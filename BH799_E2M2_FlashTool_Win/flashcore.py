#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BH799_E2M2_FlashTool_Win 低层核心 (纯标准库, Windows 版).

与 Linux 版共用: 镜像解析/校验/拼装/解码/规则文本 —— 全部是平台无关的纯 Python,
逐字复用自 ../BH799_E2M2_FlashTool/flashcore.py.

差异: Linux 的 fcntl.ioctl(NVME_IOCTL_ADMIN_CMD / SG_IO) 传输层全部移除,
改由 wintransport.py 用 Windows DeviceIoControl 提供:
  * USB 盒 (JMS583): IOCTL_SCSI_PASS_THROUGH_DIRECT + 3 步 ATA-PASS-THROUGH(0xA1)
  * 直连 NVMe     : IOCTL_STORAGE_PROTOCOL_COMMAND / IOCTL_SCSI_MINIPORT

修正三处已知错误(沿用 Linux 版):
  * 0x148 型号拼装掩码位名 (见 doc/model_name_dynamic_assembly.md §5/§6)
  * DWORD31 XOR 范围: 0x400..0x100000, 不含 80B 编程器尾; 大端 >I
  * XM 底包 1MB+80B '-Configuration-' 尾, 刷写/校验前裁掉

本模块不依赖第三方包, 可在非 Windows 机器上 import 跑离线自检.
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
import time

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

HEADER_SIZE = 1024
FLASH_SIZE = 0x100000          # 1MB SPI Flash
LOAD_BASE = 0x40000000         # body 装载 VA
SLOT_SPI = 3
CHUNK_MAX = 4096               # 固件侧单块硬限制

# 1KB 头 / 客户参数区偏移 (真值, 见 doc/model_name_dynamic_assembly.md 等)
SPI_CFG_OFF = 0x038           # dw14: XM 0x800010D8 / GD 0x00000000
CHECKSUM_OFF = 0x07C          # dw31: 0x400..0x100000 大端 u32 XOR
SMART_BLK_OFF = 0x0CD         # bit0: 0=块1(BLOCK2), 1=块3(BLOCK4)
GPIO_MODE_OFF = 0x105         # bits7:6: 0x40=UART, 0x80=LED
GPIO_LEVEL_OFF = 0x107        # bit7: 0->0x10, 1->0x30
SN_OFF, SN_LEN = 0x10C, 20
MODEL_OFF, MODEL_LEN = 0x120, 40
MASK_OFF = 0x148              # 只 1 字节 (后 3 字节为 0); 0x144 不是字段
VENDOR_OVERRIDE_OFF, VENDOR_OVERRIDE_LEN = 0x154, 8
TOOL_RECORD_OFF = 0x3E0       # 产线工具记录, 固件不读

# 客户参数区窗口 (build_image 覆盖用; 保留 base 的 DWORD0/段表/dw31/产线记录)
CFG_WINDOW = (0x020, 0x07C)
CUSTOMER_WINDOW = (0x080, TOOL_RECORD_OFF)

SLOT_NAMES = {
    1: "eMMC Boot Partition 1",
    2: "eMMC Boot Partition 2",
    3: "SPI Flash",
    4: "eMMC0 FFU",
    5: "eMMC1 FFU",
}

# 型号动态拼装掩码 (修正后位名; 来源 doc/model_name_dynamic_assembly.md §5/§6)
# 旧表 cap=0x20/fwver=0x10/pnm=0x08/mid=0x04 是错的, 勿沿用.
MASK_ROWS = [
    # bit, 名称, 段贡献, 来源, 是否运行时(镜像内不可预览)
    (0x80, "VEN",   '"BAYHUB " (7B)',     "固定 rodata",             False),
    (0x40, "OEM",   "OEM 串(≤8B)",        "头字段 [0xBC 未启用]",   False),
    (0x20, "MID",   "厂商名 + '-'",       "运行时 CID[0]/0x154 覆盖", True),
    (0x10, "PNM",   "6B 产品名 + '-'",    "运行时 CID[3..8]",        True),
    (0x08, "FWVER", "'0x'+4hex+'-'",      "运行时版本值",             True),
    (0x04, "CAP",   "数字 + 'GB '",       "运行时容量",               True),
    (0x02, "-",     "(未使用)",            "-",                        False),
    (0x01, "DISK",  '"Disk"',             "固定 rodata",             False),
]
DEFAULT_MASK_XM = 0xBC
EXAMPLE_MODEL = "BAYHUB Samsung-CKTM4R-0x0012-64GB "  # 12345/identify.bin 真机抓包, mask 0xBC

# 固件 rodata 内置的 eMMC 厂商名表 (doc/model_name_dynamic_assembly.md §2,
# 0x4001ec70-0x4001ecd8): 运行时按 CID[0] MID 查表, 命中下表即自动识别,
# 所以 MID 段 (0x20) 命中时 0x154 覆盖串应留空; 表外厂商才需自定义 0x154.
AUTO_VENDOR_NAMES = (
    "Union", "Micron", "Toshiba", "Samsung", "Hiksemi", "SanDisk",
    "Phison", "Hynix", "Foresee", "YMTC", "Ramaxel", "Biwin", "Kingston",
)

# NVMe Admin / ioctl
ADMIN_GET_LOG_PAGE = 0x02
ADMIN_IDENTIFY = 0x06
ADMIN_FW_COMMIT = 0x10
ADMIN_FW_DOWNLOAD = 0x11

# Get Log Page LIDs
LID_ERROR = 0x01
LID_SMART = 0x02
LID_FW_SLOT = 0x03
LID_HEADER = 0xC0

# JMicron JMS583 / NVMe 协议常量 (wintransport.py 复用)
SNT_JMICRON_SIGNATURE = 0x454D564E  # 'NVME' little-endian
FW_STATUS_HINTS = {
    0x107: "Invalid FW Image: 头/奇偶/长度被拒",
    0x114: "size 校验失败: 镜像字节序或长度不对",
}


# --------------------------------------------------------------------------
# 异常 / 小工具
# --------------------------------------------------------------------------

class ImageError(Exception):
    pass


class NvmeError(Exception):
    def __init__(self, msg, phase="cmd"):
        super().__init__(msg)
        self.phase = phase


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def swap32_words(data: bytes) -> bytes:
    """按 32 位字整体反序 (b0b1b2b3 -> b3b2b1b0). 读 0xC0 字反序时用."""
    if len(data) % 4:
        return data
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


def xor_words(data: bytes) -> int:
    """大端 u32 逐字 XOR. data 必须是 4 的倍数."""
    v = 0
    for (w,) in struct.iter_unpack(">I", data[:len(data) - len(data) % 4]):
        v ^= w
    return v


def set_fixed(buf: bytearray, off: int, length: int, text: str, name: str):
    """写定长 latin-1 字符串, NUL 补齐, 超长报错."""
    raw = (text or "").encode("latin-1")
    if len(raw) > length:
        raise ImageError("%s 超过 %d 字节 (实际 %d)" % (name, length, len(raw)))
    buf[off:off + length] = raw.ljust(length, b"\x00")


def describe_header_blob(raw: bytes) -> str:
    out = ["前 16 字节: %s" % raw[:16].hex()]
    for name, data in (("as-is", raw), ("swap32", swap32_words(raw))):
        w = struct.unpack(">I", data[:4])[0]
        size = w & 0xFFFFFF
        out.append("  %-6s DWORD0=0x%08X size=%d (size%%4=%d)"
                   % (name, w, size, size % 4))
    return "\n".join(out)


def decode_header_blob(raw: bytes):
    """解析 LID 0xC0 的 1KB 头. 返回 (FwImage|None, mode, normalized_bytes).

    读回可能是 32 位字反序 (le32); 两种解释都试, 成功的返回归一化大端数据.
    """
    for mode, data in (("be", raw), ("le32", swap32_words(raw))):
        try:
            img = FwImage(data, "log-0xC0")
        except ImageError:
            continue
        errs = [t for lv, t in img.header_checks() if lv == "error"]
        if not errs:
            return img, mode, data
    return None, None, raw


def mask_str(v: int) -> str:
    return "|".join(name.lower() for bit, name, *_ in MASK_ROWS
                    if name != "-" and (v & bit)) or "0"


# 运行时段的示意值 (取自 12345/identify.bin 真机抓包). 长度按这些真实长度算,
# 不用尖括号占位符算, 否则长度虚高会误报 "超长".
RUNTIME_EXAMPLE = {
    0x20: "Samsung-", 0x10: "CKTM4R-", 0x08: "0x0012-", 0x04: "64GB ",
}
RUNTIME_SEGMENT_NOTE = ("MID/PNM/FWVER/CAP 为示意值, 实际由板上 eMMC 决定, "
                        "镜像内无法预览; 0x154 为头字段, 可预览")


def assemble_model_preview(mask: int, vendor_override: str = ""):
    """按位 7->0 拼装示意串. 返回 (preview_str, length, ok).

    0x154 覆盖串用真实值; 运行时段用 RUNTIME_EXAMPLE 示意值.
    总长 >40 时固件会整体放弃拼装 (型号保持空).
    """
    parts = []
    for bit, *_ in MASK_ROWS:
        if not (mask & bit) or bit == 0x02:
            continue
        if bit == 0x80:
            parts.append("BAYHUB ")
        elif bit == 0x20:
            parts.append((vendor_override + "-") if vendor_override
                         else RUNTIME_EXAMPLE[0x20])
        elif bit in RUNTIME_EXAMPLE:
            parts.append(RUNTIME_EXAMPLE[bit])
        elif bit == 0x01:
            parts.append("Disk")
    s = "".join(parts)
    return s, len(s), len(s) <= 40


def smart_block_info(cd_byte: int):
    """0xCD bit0 -> (块名, bit, 说明)."""
    bit = cd_byte & 1
    if bit == 0:
        return ("块1 / BLOCK2", 0, "0xCD bit0=0; 中间固件 blk1 与之同源")
    return ("块3 / BLOCK4", 1, "0xCD bit0=1; 中间固件 blk3(≡blk4) 与之同源")


def gpio_mode_info(b105: int, b107: int):
    """0x105/0x107 -> dict(mode, mode_name, level_byte, caveat)."""
    m = (b105 >> 6) & 0x03
    names = {0: "其他/未定义(mode 0)", 1: "UART 115200", 2: "LED 忙闲闪烁",
             3: "其他/未定义(mode 3)"}
    level = 0x30 if (b107 & 0x80) else 0x10
    return {
        "mode": m, "mode_name": names[m], "level_byte": level,
        "caveat": ("静态成立 ≠ 真机可用: GPIO0 若物理接 LED, 切 UART 无串口输出; "
                   "FW Download/Commit 期间引脚切 MODE_SPI, 串口日志必然中断"),
    }


def decode_smart_log(raw: bytes):
    """解码 NVMe SMART/Health (LID 0x02, 512B) 标准字段."""
    if len(raw) < 192:
        return {}

    def le(off, n):
        return int.from_bytes(raw[off:off + n], "little")

    d = {
        "critical_warning": raw[0],
        "temperature_k": le(1, 2),
        "available_spare": raw[3],
        "available_spare_threshold": raw[4],
        "percentage_used": raw[5],
        "data_units_read": le(32, 16),
        "data_units_written": le(48, 16),
        "host_read_commands": le(64, 16),
        "host_write_commands": le(80, 16),
        "controller_busy_time": le(96, 16),
        "power_cycles": le(112, 16),
        "power_on_hours": le(128, 16),
        "unsafe_shutdowns": le(144, 16),
        "media_errors": le(160, 16),
        "num_err_log_entries": le(176, 16),
    }
    counters = ("data_units_read", "data_units_written", "host_read_commands",
                "host_write_commands", "controller_busy_time", "power_cycles",
                "power_on_hours", "unsafe_shutdowns")
    d["suspicious"] = any(d[k] > 0xFFFFFFFF for k in counters)
    return d


def classify_tail(data: bytes, total: int) -> str:
    tail = data[total:]
    # XM 编程器 dump: 整片 1MB 之后还有 80B '-Configuration-' 工具配置尾.
    if len(data) > FLASH_SIZE and data[FLASH_SIZE:FLASH_SIZE + 15] == b"-Configuration-":
        return ("1MB + %dB 编程器配置尾 '-Configuration-' (非固件内容, 刷写/XOR 前裁掉)"
                % (len(data) - FLASH_SIZE))
    if not tail:
        return "精确固件长度 (无尾/已裁剪)"
    if all(x in (0xFF, 0x00) for x in tail):
        return "%d 字节 0xFF/0x00 补齐 (刷写时裁掉)" % len(tail)
    return "%d 字节非空尾部数据 (刷写时裁掉)" % len(tail)


# --------------------------------------------------------------------------
# 镜像
# --------------------------------------------------------------------------

class FwImage:
    def __init__(self, data: bytes, path: str = "<memory>"):
        if len(data) < HEADER_SIZE:
            raise ImageError("文件小于 1KB, 不是固件镜像: %s" % path)
        self.data = bytes(data)
        self.path = path
        self.header = self.data[:HEADER_SIZE]
        self.dw = struct.unpack(">256I", self.header)

    # --- 头字段 ---------------------------------------------------------
    @property
    def dword0(self) -> int:
        return self.dw[0]

    @property
    def size(self) -> int:
        return self.dw[0] & 0x00FFFFFF

    @property
    def parity(self) -> int:
        return (self.dw[0] >> 24) & 0xFF

    @property
    def sections(self):
        return {"text": (self.dw[1], self.dw[2]),
                "data": (self.dw[3], self.dw[4]),
                "bss": (self.dw[5], self.dw[6])}

    @property
    def checksum(self) -> int:
        return self.dw[31]                     # >I 大端, 与 XOR 口径一致

    @property
    def slot(self) -> int:
        return (self.dw[32] >> 24) & 0x0F

    @property
    def serial(self) -> str:
        return self._cstr(self.data[SN_OFF:SN_OFF + SN_LEN])

    @property
    def model(self) -> str:
        return self._cstr(self.data[MODEL_OFF:MODEL_OFF + MODEL_LEN])

    @property
    def model_mask(self) -> int:
        return self.data[MASK_OFF]

    @property
    def download_length(self) -> int:
        return HEADER_SIZE + self.size

    # --- 客户参数 (新增) ------------------------------------------------
    @property
    def is_dynamic_model(self) -> bool:
        """0x120 首 dword 非 0 -> 静态型号; 全 0 -> 运行时动态拼装."""
        return self.dw[MODEL_OFF // 4] == 0

    @property
    def smart_block(self) -> int:
        return self.data[SMART_BLK_OFF] & 1 if len(self.data) > SMART_BLK_OFF else 0

    @property
    def spi_cfg(self) -> int:
        return self.dw[SPI_CFG_OFF // 4]

    @property
    def gpio_mode(self) -> int:
        return ((self.data[GPIO_MODE_OFF] >> 6) & 3) if len(self.data) > GPIO_MODE_OFF else 0

    @property
    def gpio_level(self) -> bool:
        return bool(self.data[GPIO_LEVEL_OFF] & 0x80) if len(self.data) > GPIO_LEVEL_OFF else False

    @property
    def vendor_override(self) -> str:
        return self._cstr(self.data[VENDOR_OVERRIDE_OFF:VENDOR_OVERRIDE_OFF + VENDOR_OVERRIDE_LEN])

    @property
    def tail_info(self) -> str:
        return classify_tail(self.data, self.download_length)

    @staticmethod
    def _cstr(b: bytes) -> str:
        return b.split(b"\x00", 1)[0].decode("latin-1")

    def version_candidates(self):
        out = []
        for m in re.finditer(rb"(?<![0-9A-Za-z])(10[0-9]{6})(?![0-9A-Za-z])", self.data):
            out.append((m.start(), m.group(1).decode()))
        return out

    # --- 校验 -----------------------------------------------------------
    def header_checks(self):
        """只校验 1KB 头本身 (不依赖 body). 也适用于 0xC0 的 1KB 回读."""
        r = []
        if self.dword0 in (0, 0xFFFFFFFF):
            r.append(("error", "DWORD0 = 0x%08X: 空片/擦除态, 不是有效镜像" % self.dword0))
            return r
        b = [(self.dword0 >> s) & 0xFF for s in (24, 16, 8, 0)]
        if b[0] ^ b[1] ^ b[2] ^ b[3] == 0xFF:
            r.append(("info", "DWORD0 奇偶校验通过 (odd, 0x%02X)" % self.parity))
        else:
            r.append(("error", "DWORD0 奇偶校验失败 (0x%02X ^ %02X ^ %02X ^ %02X != 0xFF)"
                      % tuple(b)))
        size = self.size
        if size == 0 or size > 0x1000000:
            r.append(("error", "DWORD0 长度字段异常: %d" % size))
            return r
        if size % 4:
            r.append(("error", "body 长度不是 4 的倍数"))
        if self.slot not in SLOT_NAMES:
            r.append(("error", "目标 slot = %d, 未知槽位" % self.slot))
        else:
            r.append(("info", "目标 slot = %d (%s)" % (self.slot, SLOT_NAMES[self.slot])))
        ta, da, ba = self.dw[1], self.dw[3], self.dw[5]
        if ta != LOAD_BASE:
            r.append(("warn", ".text 装载地址 0x%08X != 0x%08X" % (ta, LOAD_BASE)))
        if da != ta + self.dw[2]:
            r.append(("warn", ".data 地址 0x%08X != .text 末尾 0x%08X" % (da, ta + self.dw[2])))
        if ba != da + self.dw[4]:
            r.append(("warn", ".bss 地址 0x%08X != .data 末尾 0x%08X" % (ba, da + self.dw[4])))
        if (self.dw[5] + self.dw[6]) > 0x40028000:
            r.append(("warn", "RAM 占用超过 160KB SRAM"))
        return r

    def checks(self):
        r = list(self.header_checks())
        if any(lv == "error" for lv, _ in r):
            return r
        d = self.data
        size = self.size
        ts = self.dw[2] + self.dw[4]
        if ts != size:
            r.append(("warn", "段表 .text+.data = %d, 但 DWORD0 长度 = %d" % (ts, size)))
        else:
            r.append(("info", "段表长度与 DWORD0 一致 (%d)" % size))
        total = HEADER_SIZE + size
        if len(d) < total:
            r.append(("error", "镜像被截断: 需要 %d 字节, 实际 %d" % (total, len(d))))
            return r

        # FIX: XOR 范围 0x400..min(len,0x100000), 大端 >I; 不含 80B 编程器尾.
        end = min(len(d), FLASH_SIZE)
        end -= end % 4
        calc = xor_words(d[HEADER_SIZE:end])
        if calc == self.checksum:
            r.append(("info", "DWORD31 XOR 校验通过 (0x%08X)" % calc))
        else:
            r.append(("error", "DWORD31 XOR 校验失败: 存 0x%08X, 算 0x%08X"
                      % (self.checksum, calc)))
        if end > total:
            pad = d[total:end]
            if not all(x in (0xFF, 0x00) for x in pad):
                r.append(("warn", "填充区 [0x%X,0x%X) 非 0xFF/0x00, 固件可能拒绝"
                          % (total, end)))
        r.append(("info", "尾部: %s" % self.tail_info))
        return r

    def errors(self):
        return [t for lv, t in self.checks() if lv == "error"]

    def validate(self):
        errs = self.errors()
        if errs:
            raise ImageError("镜像校验失败:\n  - " + "\n  - ".join(errs))

    def trimmed(self) -> bytes:
        return self.data[:self.download_length]

    def with_header_from(self, donor: "FwImage", parts: str = "all") -> bytes:
        """用 donor 的客户参数/SPI 配置替换本镜像对应区域.

        保留本镜像的 DWORD0(长度+奇偶)、段表(0x04-0x1C)、DWORD31(0x7C)
        与产线记录(0x3E0-0x3FF). parts='all' 另覆盖 0x20-0x7C (含 0x38).
        """
        out = bytearray(self.trimmed())
        if parts == "all":
            out[CFG_WINDOW[0]:CFG_WINDOW[1]] = donor.data[CFG_WINDOW[0]:CFG_WINDOW[1]]
        elif parts != "customer":
            raise ValueError(parts)
        out[CUSTOMER_WINDOW[0]:CUSTOMER_WINDOW[1]] = \
            donor.data[CUSTOMER_WINDOW[0]:CUSTOMER_WINDOW[1]]
        FwImage(bytes(out)).validate()
        return bytes(out)

    def patched(self, sn=None, model=None) -> bytes:
        out = bytearray(self.trimmed())
        if sn is not None:
            set_fixed(out, SN_OFF, SN_LEN, sn, "SN")
        if model is not None:
            set_fixed(out, MODEL_OFF, MODEL_LEN, model, "Model")
        FwImage(bytes(out)).validate()
        return bytes(out)

    def padded(self, size: int) -> bytes:
        out = bytearray(self.trimmed())
        if len(out) > size:
            raise ImageError("镜像 (%d) 大于目标尺寸 (%d)" % (len(out), size))
        out.extend(b"\xFF" * (size - len(out)))
        return bytes(out)

    # --- 展示 -----------------------------------------------------------
    def report(self):
        print("=== %s ===" % self.path)
        print("  文件大小      : %d (0x%X), sha256 %s"
              % (len(self.data), len(self.data), _sha256(self.data)[:16]))
        print("  镜像 body     : %d (0x%X) -> 下载总长 %d (0x%X)"
              % (self.size, self.size, self.download_length, self.download_length))
        print("  DWORD0        : 0x%08X  奇偶 0x%02X" % (self.dword0, self.parity))
        for name in ("text", "data", "bss"):
            a, s = self.sections[name]
            print("  .%-5s        : 0x%08X + %d" % (name, a, s))
        print("  DWORD31       : 0x%08X" % self.checksum)
        print("  目标 slot     : %d (%s)" % (self.slot, SLOT_NAMES.get(self.slot, "?")))
        print("  SPI dw@0x38   : 0x%08X (%s)"
              % (self.spi_cfg, "XM25QH80B" if self.spi_cfg == 0x800010D8
                 else ("GD25Q80" if self.spi_cfg == 0 else "?")))
        blk, bit, _ = smart_block_info(self.data[SMART_BLK_OFF])
        print("  SMART 记录块  : %s (0xCD=0x%02X, bit0=%d)"
              % (blk, self.data[SMART_BLK_OFF], bit))
        print("  SN  @0x10C    : %r" % self.serial)
        print("  MN  @0x120    : %r%s" % (self.model, "  (空 -> 运行时动态拼装)"
                                         if self.is_dynamic_model else "  (静态)"))
        print("  型号掩码 0x148: 0x%02X  [%s]" % (self.model_mask, mask_str(self.model_mask)))
        print("  自定义厂商名 @0x154: %r" % self.vendor_override)
        g = gpio_mode_info(self.data[GPIO_MODE_OFF], self.data[GPIO_LEVEL_OFF])
        print("  GPIO 0x105    : 0x%02X -> %s (0x107 bit7 -> 0x%02X)"
              % (self.data[GPIO_MODE_OFF], g["mode_name"], g["level_byte"]))
        v = self.version_candidates()
        print("  版本串候选    : %s"
              % (", ".join("%r@0x%X" % (s, o) for o, s in v) if v else "未找到"))
        for lv, text in self.checks():
            tag = {"error": "错误", "warn": "警告", "info": "  ok"}[lv]
            print("  [%s] %s" % (tag, text))


def header_summary(data: bytes) -> dict:
    """解析 1KB 头为客户参数字典 (供打印/写 info.txt/导入预览共用)."""
    if len(data) < HEADER_SIZE:
        raise ImageError("头文件不足 1KB: %d B" % len(data))
    img = FwImage(data[:HEADER_SIZE], "<1KB header>")
    errs = [t for lv, t in img.header_checks() if lv == "error"]
    g = gpio_mode_info(data[GPIO_MODE_OFF], data[GPIO_LEVEL_OFF])
    blk, bit, _ = smart_block_info(data[SMART_BLK_OFF])
    return {
        "valid": not errs, "errors": errs, "dword0": img.dword0,
        "size": img.size, "slot": img.slot, "spi_cfg": img.spi_cfg,
        "checksum": img.checksum, "serial": img.serial, "model": img.model,
        "is_dynamic": img.is_dynamic_model, "mask": img.model_mask,
        "mask_str": mask_str(img.model_mask),
        "vendor_override": img.vendor_override,
        "smart_byte": data[SMART_BLK_OFF], "smart_block_name": blk,
        "smart_bit": bit, "gpio_byte": data[GPIO_MODE_OFF],
        "gpio_mode_name": g["mode_name"], "gpio_level_byte": g["level_byte"],
        "sha256": _sha256(data[:HEADER_SIZE]),
    }


def report_header(data: bytes, title: str = "客户参数区 1KB Header") -> dict:
    """打印 1KB 头摘要并返回 header_summary() 字典.

    刻意不套 FwImage.report(): 后者会因缺 body 报"截断".
    """
    s = header_summary(data)
    print("=== %s ===" % title)
    print("  长度/有效性 : %d B, %s" % (HEADER_SIZE, "头校验 OK" if s["valid"]
                                      else "头校验错误: " + "; ".join(s["errors"])))
    print("  DWORD0      : 0x%08X (body 长度 %d)" % (s["dword0"], s["size"]))
    print("  slot        : %d (%s)" % (s["slot"], SLOT_NAMES.get(s["slot"], "?")))
    print("  SPI @0x38   : 0x%08X" % s["spi_cfg"])
    print("  dw31 @0x7C  : 0x%08X" % s["checksum"])
    print("  SN   @0x10C : %r" % s["serial"])
    print("  MN   @0x120 : %r  (%s)" % (s["model"], "空 -> 动态拼装" if s["is_dynamic"]
                                       else "静态型号"))
    print("  自定义厂商名 @0x154: %r" % s["vendor_override"])
    print("  SMART 0xCD  : 0x%02X -> %s (bit0=%d)"
          % (s["smart_byte"], s["smart_block_name"], s["smart_bit"]))
    print("  GPIO 0x105  : 0x%02X -> %s (0x107 -> 0x%02X)"
          % (s["gpio_byte"], s["gpio_mode_name"], s["gpio_level_byte"]))
    print("  sha256      : %s" % s["sha256"])
    return s


# --------------------------------------------------------------------------
# 传输层见 wintransport.py (Windows DeviceIoControl).
# 以下 IdentifyInfo / 设备只读采集 / flash_image 都是传输无关的, 直接复用.
# --------------------------------------------------------------------------

class IdentifyInfo:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.vid, self.ssvid = struct.unpack_from("<HH", raw, 0)
        self.sn = raw[4:24].decode("latin-1").rstrip(" \x00")
        self.mn = raw[24:64].decode("latin-1").rstrip(" \x00")
        self.fr = raw[64:72].decode("latin-1").rstrip(" \x00")
        self.fwug = raw[319]

    def report(self, prefix="  "):
        print("%sModel    : %s" % (prefix, self.mn or "(空)"))
        print("%sSerial   : %s" % (prefix, self.sn or "(空)"))
        print("%sFirmware : %s" % (prefix, self.fr or "(空)"))
        print("%sVID/SSVID: 0x%04X / 0x%04X" % (prefix, self.vid, self.ssvid))
        print("%sFWUG     : %d" % (prefix, self.fwug))


def parse_fw_slot_log(raw: bytes):
    if len(raw) < 16:
        return None
    afi = raw[0] & 0x07
    revs = []
    for i in range(1, 8):
        revs.append(raw[i * 8:(i + 1) * 8].decode("latin-1").rstrip(" \x00"))
    return afi, revs


# --------------------------------------------------------------------------
# 设备只读采集 / 刷写驱动
# --------------------------------------------------------------------------

def read_header_1kb(dev):
    """读 LID 0xC0 的 1KB 头并归一化.

    返回 (normalized|None, raw, mode, FwImage|None). mode='be'/'le32'/None.
    """
    raw = dev.get_log(LID_HEADER, HEADER_SIZE)
    img, mode, norm = decode_header_blob(raw)
    return (norm if img else None), raw, mode, img


def probe_device(dev):
    """只读采集 Identify / SMART / 1KB 头, 逐项收集错误. 不写任何东西."""
    out = {"identify": None, "smart": None, "header_raw": None,
           "header": None, "header_mode": None, "header_img": None,
           "errors": []}
    try:
        out["identify"] = dev.identify()
    except Exception as e:                                   # noqa: BLE001
        out["errors"].append("Identify: %s" % e)
    try:
        out["smart"] = dev.get_log(LID_SMART, 512)
    except Exception as e:                                   # noqa: BLE001
        out["errors"].append("SMART(LID 0x02): %s" % e)
    try:
        norm, raw, mode, img = read_header_1kb(dev)
        out["header_raw"], out["header"] = raw, norm
        out["header_mode"], out["header_img"] = mode, img
    except Exception as e:                                   # noqa: BLE001
        out["errors"].append("Header(LID 0xC0): %s" % e)
    return out


class _FakeController:
    """自检用: 模拟控制器侧 FW Download/Commit 语义 (不做任何 ioctl)."""

    def __init__(self, flash_size=FLASH_SIZE):
        self.flash = bytearray(b"\xFF" * flash_size)
        self.staged = None
        self.stage_len = 0
        self.size = None
        self.slot = None
        self.dw0 = None
        self.committed = False
        self.calls = 0

    def fw_download(self, off, chunk):
        self.calls += 1
        if off == 0:
            dw0 = struct.unpack(">I", chunk[:4])[0]
            b = dw0.to_bytes(4, "big")
            if dw0 in (0, 0xFFFFFFFF) or (b[0] ^ b[1] ^ b[2] ^ b[3]) != 0xFF:
                raise NvmeError("check_fw_header 拒绝 (0x107)")
            self.size = dw0 & 0xFFFFFF
            self.slot = (struct.unpack(">I", chunk[128:132])[0] >> 24) & 0xF
            self.dw0 = dw0
            self.staged = bytearray(self.size + HEADER_SIZE)
            chunk = b"\x00\x00\x00\x00" + chunk[4:]   # 固件会清 DWORD0
        if self.staged is None:
            raise NvmeError("未收到首块")
        self.staged[off:off + len(chunk)] = chunk
        self.stage_len = max(self.stage_len, off + len(chunk))

    def fw_commit(self, slot, action):
        if self.staged is None:
            raise NvmeError("没有下载数据")
        if slot == 0:
            slot = self.slot
        if slot != self.slot:
            raise NvmeError("commit slot 与镜像 slot 不一致")
        if self.size + HEADER_SIZE != self.stage_len:
            raise NvmeError("size 校验失败 (0x107)")
        self.flash[0:self.stage_len] = self.staged[0:self.stage_len]
        self.flash[0:4] = struct.pack(">I", self.dw0)
        self.committed = True
        return 0


def flash_image(ctrl, img: FwImage, chunk=CHUNK_MAX, slot=None, action=1,
                progress=True, dry_run=False, host_swap32=False):
    """按 4KB 块 FW Download + FW Commit. 返回发送字节数.

    写路径原样发送 (host_swap32=False); 只有 0xC0 读路径才会字反序.
    """
    data = img.trimmed()
    slot = img.slot if slot is None else slot
    if chunk % 4 or chunk <= 0:
        raise ValueError("chunk 必须是 4 的正倍数")
    if chunk > CHUNK_MAX:
        raise ValueError("chunk 不能超过 %d (固件侧硬限制)" % CHUNK_MAX)
    total = len(data)
    if dry_run:
        return total
    t0 = time.time()
    sent = 0
    for off in range(0, total, chunk):
        part = data[off:off + chunk]
        if host_swap32:
            part = swap32_words(part)
        try:
            ctrl.fw_download(off, part)
        except NvmeError as e:
            e.phase = "download"
            e.args = ("块 0x%X/%d: %s" % (off, total, e.args[0]),)
            raise
        sent += len(part)
        if progress:
            sys.stderr.write("\r  下载 %6.2f%%  %7d/%d  0x%06X"
                             % (sent * 100.0 / total, sent, total, off))
            sys.stderr.flush()
    if progress:
        dt = max(time.time() - t0, 1e-6)
        sys.stderr.write("\r  下载 100.00%%  %7d/%d  (%.1f KiB/s)\n"
                         % (total, total, total / 1024.0 / dt))
        sys.stderr.write("  等待最后一块落盘 ...\n")
    time.sleep(0.2)
    try:
        ctrl.fw_commit(slot, action)
    except NvmeError as e:
        e.phase = "commit"
        raise
    return sent

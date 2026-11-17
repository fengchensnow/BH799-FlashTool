#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BH799_E2M2_FlashTool_Win — BH799BB eMMC→NVMe 桥片固件刷写工具 (Windows 版).

自包含: 只依赖 flashcore.py + wintransport.py + Python 3 标准库, 无第三方包.
所有相对路径 (FIRMWARE\、backup\、导出镜像) 以本文件所在目录为根.

    :: 以管理员身份运行 (刷写/设备探测需要管理员; 枚举与离线功能不需要)
    python flashtool.py                 # 交互菜单
    python flashtool.py --dry-run       # 交互菜单, 刷写只模拟不落盘
    python flashtool.py --selftest      # 离线自检 (不接触设备, 可在任意平台跑)
    python flashtool.py --enumerate     # 只看设备枚举结果

【验证边界】wintransport.py 的 DeviceIoControl 调用无法在 Linux 开发机验证;
本版已在 Linux 上验证: 全部纯逻辑 (镜像/拼装/解码/自检)、Windows 结构体 sizeof、
IOCTL 常量、协议字节构造。设备 I/O 必须在 Windows 实机先用菜单 1 (只读探测)
确认 Identify + 厂商日志 0xC0 可读, 再考虑刷写。切勿把设备层当作已验证可用。

与 Linux 版 (../BH799_E2M2_FlashTool/) 的差异只有设备枚举/传输/权限判断;
6 项菜单、拼装规则、备份头、规则文本、自检逻辑均逐字复用。

规则来源 (注释引用, 不复制文档进工具目录):
  * doc/model_name_dynamic_assembly.md §5/§6  —— 修正后的 0x148 掩码位/拼接顺序/分隔符
  * doc/gpio0_uart_led_mode.md                —— 0x105 UART/LED, 0x107 电平
  * SMART_BRIDGE_FIRMWARE.md §0/§4/§5          —— SMART 保留块 / 中间固件同源 / 断电流程
"""

from __future__ import annotations

import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import flashcore as fc
import wintransport as wt

# --------------------------------------------------------------------------
# 锚点 & 常量
# --------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent
FIRMWARE_DIR = HERE / "FIRMWARE"
BACKUP_DIR = HERE / "backup"

BASE_FILES = {
    "xm": FIRMWARE_DIR / "XM25QH80B@SOIC8.BIN",
    "gd": FIRMWARE_DIR / "GD25Q80@USON8.bin",
}
BRIDGE_FILES = {
    "blk1": FIRMWARE_DIR / "XM25QH80B_blk1_bridge.bin",
    "blk3": FIRMWARE_DIR / "XM25QH80B_blk3_bridge.bin",
}
KNOWN_SHA256 = {
    "GD25Q80@USON8.bin":
        "6723ead931913d6b06c0d697400b52d0c26011546c7a45f27e59e9084ad1abdd",
    "XM25QH80B@SOIC8.BIN":
        "a3940e3acd30c19c5716fbfa787ea24f08b907d98f1249277522fa1a858cf6b4",
    "XM25QH80B_blk1_bridge.bin":
        "bc6a30981e17484a332b8c4ae1e2588841942dd971e262ec4adecfd002dfc04d",
    "XM25QH80B_blk3_bridge.bin":
        "e998c42691e90ca4664d8498c33ef6ad22e2932b9b1f1d8340a16c63a7cef06a",
}
SPI_CFG = {"xm": 0x800010D8, "gd": 0x00000000}
SMART_BLOCKS = {1: ("块1 / BLOCK2", 0), 3: ("块3 / BLOCK4", 1)}
GPIO_MODES = {"uart": 0x40, "led": 0x80}
FIXED_DYNAMIC_MASK = 0xBC          # 菜单4 动态拼装固定掩码, 不再逐位选择
_VENDOR_LIST = " / ".join(fc.AUTO_VENDOR_NAMES)

# --------------------------------------------------------------------------
# 规则文本 (硬编码, 屏上讲清楚)
# --------------------------------------------------------------------------

RULE_IMAGE = """\
[镜像格式] 1KB 头 = 256 个大端 u32; body 从 0x400 起. 两处校验:
  * DWORD0  b0^b1^b2^b3 == 0xFF (奇偶), 低 24 位 = body 长度
  * DWORD31 @0x7C = 0x400..0x100000 大端 u32 XOR (不含 80B 编程器尾)
  客户参数区 0x000-0x3FF 不在校验范围内 -> 改 SN/型号/mask/0xCD/0x105 无需重算校验.
  XM 底包多 80B '-Configuration-' 编程器尾, 刷写/XOR 前裁掉 (trimmed).
"""

RULE_MASK = """\
[动态拼装] 仅当 0x120 Model 全 0 时生效; 按位 7->0 追加, 分隔符 '-', 总长>40 整体放弃.
  本工具固定使用掩码 0xBC = 0x80|0x20|0x10|0x08|0x04 (VEN+MID+PNM+FWVER+CAP), 不逐位选.
  位     名称    段内容                  来源
  0x80  VEN     "BAYHUB " (7B)          固定 rodata
  0x40  OEM     OEM 串 (≤8B)             头字段; 0xBC 未启用此位, 不参与拼装
  0x20  MID     eMMC 厂商名 + '-'        运行时 CID[0]; 0x154 非空时覆盖厂商名 [运行时]
  0x10  PNM     6B 产品名 + '-'          运行时 CID[3..8] [运行时]
  0x08  FWVER   '0x' + 4hex + '-'       运行时版本值 [运行时]
  0x04  CAP     数字 + 'GB '             运行时容量 [运行时]
  0x02  -       (未使用)
  0x01  DISK    "Disk"                   固定 rodata
  0x154 厂商名覆盖串: 固件能按 eMMC CID[0] MID 自动识别以下 %d 个厂商, 命中时留空即可:
    %s
  这些厂商之外的 eMMC 需自定义 0x154 覆盖串 (≤8B).
  MID/PNM/FWVER/CAP 由板上 eMMC 决定, 镜像内无法预览 (示意用真机抓包值).
  真机例 (0xBC): BAYHUB Samsung-CKTM4R-0x0012-64GB
  位名以反汇编为准 (doc/model_name_dynamic_assembly.md §5/§6); 旧资料的 cap/fwver/pnm/mid 标反了.
""" % (len(fc.AUTO_VENDOR_NAMES), _VENDOR_LIST)

RULE_GPIO = """\
[UART/LED] 0x105 bits7:6: 0x40=UART 115200 (GD 客户板), 0x80=LED 忙闲闪烁 (XM 工程板).
  0x107 bit7 -> 输出电平 0x10(0) / 0x30(1). 注意: 静态成立 ≠ 真机可用 ——
  GPIO0 若物理接的是 LED, 切 UART 不会有串口输出; FW Download/Commit 期间引脚切
  MODE_SPI, 串口日志必然中断. 该设置无需重算校验 (doc/gpio0_uart_led_mode.md).
"""

RULE_SMART = """\
[SMART] 记录是 eMMC 保留区一个 512B 块 (不在 SPI Flash, 跨刷固件保留, 无 magic/CRC).
  0xCD bit0 选块: 0=块1(BLOCK2), 1=块3(BLOCK4), 被 12 处代码读取.
  GD 把 namespace 配置结构放在块1, XM 当 SMART 记录读 -> "写入量≈容量/HostWrite 高32位异常".
  [同源规则] 清除用的中间固件必须与最终固件 0xCD 一致, 否则写地址与读地址对不上.
  三步: 刷一次中间固件 -> 完整断电再上电(512B 全0合法记录在此步写入) -> 断电刷回同源最终固件.
  在线 FW Commit 会写回 SMART 结构体, 最终固件建议用编程器整片刷.
  blk3_bridge.bin (0xCD=1) ≡ 根目录 blk4_bridge.bin, "blk3=块3=BLOCK4" 同一东西两种叫法.
"""

RULE_SAFETY = """\
[安全] 静态校验通过 ≠ 真机可用. 刷写中途失败/掉电会清 SPI DWORD0, 只能拆板用编程器恢复.
  本工具不自动串联 刷写+校验 循环, 不现场生成固件补丁 (4 个 FIRMWARE/*.bin 仅作数据文件).
"""


# --------------------------------------------------------------------------
# 状态结构
# --------------------------------------------------------------------------

@dataclass
class Disk:
    path: str
    name: str
    size_bytes: int = 0
    model: str = ""
    vendor: str = ""
    serial: str | None = None
    tran: str = ""
    subsystems: str = ""
    hotplug: bool = False
    is_usb: bool = False
    usb_vid: str = ""
    usb_pid: str = ""
    usb_driver: str = ""
    devpath: str = ""
    is_char_nvme: bool = False
    decision: str = ""            # jmicron / nvme / nvme-needs-probe / unsupported
    is_system: bool = False
    notes: str = ""


@dataclass
class AppState:
    is_admin: bool = False
    disk: Disk | None = None
    transport: str | None = None
    offline: bool = False
    probe_ok: bool = False
    snapshot: dict | None = None
    identify: bytes | None = None
    smart: bytes | None = None
    header_1kb: bytes | None = None     # 归一化 be 1024B
    header_raw: bytes | None = None      # 0xC0 原始读回
    header_mode: str | None = None      # be / le32
    dry_run: bool = False


@dataclass
class Overrides:
    sn: str | None = None
    model: str | None = None
    is_dynamic: bool = False
    mask: int | None = None
    vendor_override: str | None = None
    smart_block: int | None = None       # 1 / 3
    uart_led: int | None = None          # 0x40 / 0x80
    gpio_level: bool | None = None


# --------------------------------------------------------------------------
# 设备枚举 / 硬盘盒 / 透传决策 (Windows: \\.\PhysicalDriveN + DeviceIoControl)
# --------------------------------------------------------------------------

def list_disks() -> list[Disk]:
    """枚举 PhysicalDriveN 设备. 非 Windows 上返回 [] (离线功能仍可用)."""
    disks: list[Disk] = []
    if not wt.IS_WINDOWS:
        return disks
    for info in wt.list_disks():
        disks.append(Disk(
            path=info["path"], name=info["name"],
            size_bytes=info["size_bytes"],
            model=info["model"], vendor=info["vendor"],
            serial=info["serial"],
            tran=info["bus_name"],
            hotplug=info["is_usb"],
            is_usb=info["is_usb"],
            is_char_nvme=info["is_nvme"],       # 复用字段语义 = BusType NVMe 直连
        ))
    return disks


def _matches_jmicron(d: Disk) -> bool:
    """硬盘盒判定: BusType=Usb 即 USB 盒; BAYHUB 子串作额外佐证.

    Windows 纯 DeviceIoControl 拿不到 152d:f583 VID/PID (需 SetupAPI 读硬件 ID),
    故以总线类型为主判据, 最终仍由 confirm_passthrough 的 Identify MN 守卫把关.
    """
    return d.is_usb or "BAYHUB" in (d.vendor + d.model).upper()


def decide_transport(d: Disk):
    """USB 盒 -> JMicron SCSI 透传; NVMe 直连 -> NVMe Pass-Through; 其余拒绝."""
    if d.is_char_nvme:                          # BusType == Nvme
        d.decision = "nvme"
    elif d.is_usb and _matches_jmicron(d):
        d.decision = "jmicron"
    else:
        d.decision, d.is_system, d.notes = "unsupported", True, "非 USB 盒 / 非 NVMe 直连 (可能是系统盘)"


def _human(n: int) -> str:
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024 or u == "T":
            return "%.1f%s" % (n, u) if u != "B" else "%dB" % n
        n /= 1024.0
    return "%d" % n


def print_disk_table(disks: list[Disk]):
    print("\n=== 可选择的设备 (PhysicalDriveN) ===")
    print("  %-3s %-24s %-9s %-24s %-7s %-6s %s"
          % ("#", "路径", "容量", "型号 / 厂商", "总线", "硬盘盒", "决策"))
    for i, d in enumerate(disks, 1):
        box = "是" if d.is_usb else "否"
        dec = {"jmicron": "JMicron SCSI 透传", "nvme": "NVMe 直通",
               "unsupported": "不支持(系统盘)"}.get(d.decision, d.decision)
        print("  %-3d %-24s %-9s %-24s %-7s %-6s %s"
              % (i, d.path, _human(d.size_bytes),
                 (d.model[:12] + "/" + d.vendor[:10]).strip() or "-",
                 d.tran or "-", box, dec))
    print("  提示: Windows 版用 BusType(总线) 判硬盘盒, 最终以 Identify Model 含")
    print("        BAYHUB/E2M2 的只读守卫确认; USB VID/PID 需 SetupAPI, 本版不取.")
    print("  提示: 系统盘 (NVMe/ SATA 非 USB) 一律标记不支持, 绝不可选作刷写目标.")


def pick_disk(state: AppState, disks: list[Disk]) -> bool:
    """返回 False=用户退出; True=已选择(或离线)."""
    if not disks:
        note = ("当前非 Windows 开发机, 无法枚举设备; " if not wt.IS_WINDOWS else
                "未发现任何 PhysicalDrive; ")
        print(note + "进入离线模式 (菜单 5/6 与导出功能可用).")
        state.disk, state.offline = None, True
        return True
    print_disk_table(disks)
    while True:
        a = input("选择: 编号 / PhysicalDriveN / N / 路径 / n=离线 / 0=退出: ").strip()
        if a in ("0", "q", "quit", "exit"):
            return False
        if a.lower() == "n":
            state.disk, state.offline = None, True
            print("离线模式: 菜单 5/6 可用, 其余需先选设备.")
            return True
        d = None
        if a.isdigit():
            idx = int(a)
            if 1 <= idx <= len(disks):
                d = disks[idx - 1]
            else:                        # 允许直接输入 PhysicalDrive 编号
                for x in disks:
                    if x.name == "PhysicalDrive%d" % idx:
                        d = x
                        break
        else:
            low = a.lower()
            for x in disks:
                if low in (x.path.lower(), x.name.lower()):
                    d = x
                    break
        if d is None:
            print("无效选择, 重试.")
            continue
        if d.decision == "unsupported":
            print("该设备不支持: %s; 请改选." % d.notes)
            continue
        state.disk = d
        state.offline = False
        state.transport = "nvme" if d.is_char_nvme else "jmicron"
        state.probe_ok = False
        state.snapshot = None
        return True


def _open_dev(state: AppState):
    return wt.open_device(state.disk.path, state.transport)


def confirm_passthrough(state: AppState):
    """管理员时只读 Identify + 0xC0 冒烟测试并缓存; 校验 MN 必须是 BH799.

    这是 Windows 传输层的【只读验证前置条件】: DeviceIoControl 能否被驱动放行,
    只能在实机由这一步确认。失败则绝不进入任何刷写。
    """
    if state.disk is None:
        return
    if not state.is_admin:
        print("提示: 未以管理员运行 —— 枚举与离线功能可用, 但 Identify/Get Log/刷写")
        print("      需要管理员; 请用管理员身份重开命令提示符后运行 python flashtool.py.")
        return
    try:
        with _open_dev(state) as dev:
            snap = fc.probe_device(dev)
    except Exception as e:                                     # noqa: BLE001
        print("透传探测失败: %s" % e)
        print("  说明: Windows 设备 I/O 层未在本开发机验证; 请确认驱动/权限/通道正确,")
        print("        在实机取得只读 Identify + 0xC0 后再考虑任何刷写.")
        state.probe_ok = False
        return
    state.snapshot = snap
    state.identify = snap["identify"]
    state.smart = snap["smart"]
    state.header_1kb = snap["header"]
    state.header_raw = snap["header_raw"]
    state.header_mode = snap["header_mode"]
    # MN 守卫: 系统 NVMe SSD 也可能是 BusType=Nvme; 非 BH799 一律拒绝
    if snap["identify"]:
        idn = fc.IdentifyInfo(snap["identify"])
        mn = idn.mn.upper()
        if not ("BAYHUB" in mn or "E2M2" in mn or mn.startswith("E2M")):
            print("警告: Identify Model=%r 不像 BH799 桥片, 拒绝作为目标." % idn.mn)
            state.disk.decision, state.disk.is_system = "unsupported", True
            state.probe_ok = False
            return
    state.probe_ok = bool(snap["identify"])


# --------------------------------------------------------------------------
# 设备信息展示 (启动自动调用 + 菜单 1 同一函数)
# --------------------------------------------------------------------------

def print_smart(d: dict):
    if not d:
        print("  SMART 日志: 数据不足/不可用")
        return
    print("  --- SMART / Health (LID 0x02, 512B) ---")
    print("    Critical Warning   : 0x%02X" % d["critical_warning"])
    print("    Temperature        : %d K (%.1f C)" % (d["temperature_k"],
                                                      d["temperature_k"] - 273.15))
    print("    Available Spare   : %d%%  (threshold %d%%)"
          % (d["available_spare"], d["available_spare_threshold"]))
    print("    Percentage Used    : %d%%" % d["percentage_used"])
    print("    Data Units Read    : %d  (≈%.2f GB)"
          % (d["data_units_read"], d["data_units_read"] * 512000 / 1e9))
    print("    Data Units Written : %d  (≈%.2f GB)"
          % (d["data_units_written"], d["data_units_written"] * 512000 / 1e9))
    print("    Host Read Cmds     : %d" % d["host_read_commands"])
    print("    Host Write Cmds    : %d" % d["host_write_commands"])
    print("    Controller Busy    : %d min" % d["controller_busy_time"])
    print("    Power Cycles      : %d" % d["power_cycles"])
    print("    Power On Hours    : %d" % d["power_on_hours"])
    print("    Unsafe Shutdowns   : %d" % d["unsafe_shutdowns"])
    print("    Media Errors      : %d" % d["media_errors"])
    print("    Error Log Entries : %d" % d["num_err_log_entries"])
    if d["suspicious"]:
        print("    [警告] 计数器高 32 位非零/异常偏大: GD 板块1 存的是 namespace 配置结构, "
              "XM 当 SMART 记录读(无 magic/CRC)会产生垃圾值; 用菜单3中间固件清 0.")


def show_device_info(state: AppState):
    if state.disk is None:
        print("未选择设备 (离线模式), 无法查看设备信息.")
        return
    snap = state.snapshot
    if snap is None:
        if not state.is_admin:
            print("需要管理员权限才能读取设备信息 (Identify / Get Log).")
            return
        try:
            with _open_dev(state) as dev:
                snap = fc.probe_device(dev)
            state.snapshot = snap
        except Exception as e:                                 # noqa: BLE001
            print("读取设备信息失败: %s" % e)
            return
    print("\n=== 设备信息: %s (%s / %s) ==="
          % (state.disk.path, state.disk.decision, state.transport))
    if snap["identify"]:
        fc.IdentifyInfo(snap["identify"]).report()
    else:
        print("  Identify: 不可用")
    print_smart(fc.decode_smart_log(snap["smart"] or b""))
    if snap["header"]:
        print("  0xC0 头字序: %s (读路径可能 32 位字反序, 写路径原样发送)"
              % snap["header_mode"])
        fc.report_header(snap["header"], "设备 1KB 头 (客户参数区)")
    else:
        print("  1KB 头 (LID 0xC0): 不可用或无效")
        if snap["header_raw"]:
            print(fc.describe_header_blob(snap["header_raw"]))
    if snap["errors"]:
        print("  不可用项: %s" % "; ".join(snap["errors"]))


# --------------------------------------------------------------------------
# 拼装 / 备份头 / 导出 / 刷写守卫
# --------------------------------------------------------------------------

def build_image(base_name: str, header: bytes | None = None,
                ov: Overrides | None = None) -> bytes:
    """菜单4 唯一拼装入口. header!=None -> 覆盖客户参数区; None -> 完全沿用底包.

    三来源: 保持原盘信息 / 导入设备信息 传 header; 自定义信息传 None + Overrides.
    """
    ov = ov or Overrides()
    base_path = BASE_FILES[base_name]
    base = fc.FwImage(fc._read(str(base_path)), str(base_path))
    base.validate()
    if header is not None:
        if len(header) < fc.HEADER_SIZE:
            raise fc.ImageError("导入头不足 1KB: %d B" % len(header))
        himg, _mode, _norm = fc.decode_header_blob(header[:fc.HEADER_SIZE])
        if himg is None:
            raise fc.ImageError("导入的 1KB 头无效:\n" +
                                fc.describe_header_blob(header[:fc.HEADER_SIZE]))
        out = bytearray(base.with_header_from(himg, parts="all"))
    else:
        out = bytearray(base.trimmed())

    # 用户输入覆盖 (永远在头覆盖之后, 优先级更高)
    if ov.sn is not None:
        fc.set_fixed(out, fc.SN_OFF, fc.SN_LEN, ov.sn, "SN")
    if ov.is_dynamic:
        out[fc.MODEL_OFF:fc.MODEL_OFF + fc.MODEL_LEN] = b"\x00" * fc.MODEL_LEN
        out[fc.MASK_OFF] = (fc.DEFAULT_MASK_XM if ov.mask is None else ov.mask) & 0xFF
        if ov.vendor_override is not None:
            fc.set_fixed(out, fc.VENDOR_OVERRIDE_OFF, fc.VENDOR_OVERRIDE_LEN,
                         ov.vendor_override, "0x154")
    elif ov.model is not None:
        fc.set_fixed(out, fc.MODEL_OFF, fc.MODEL_LEN, ov.model, "Model")
    if ov.smart_block is not None:
        bit = SMART_BLOCKS[ov.smart_block][1]
        out[fc.SMART_BLK_OFF] = (out[fc.SMART_BLK_OFF] & 0xFE) | bit
    if ov.uart_led is not None:
        out[fc.GPIO_MODE_OFF] = (out[fc.GPIO_MODE_OFF] & 0x3F) | (ov.uart_led & 0xC0)
    if ov.gpio_level is not None:
        out[fc.GPIO_LEVEL_OFF] = (out[fc.GPIO_LEVEL_OFF] & 0x7F) | (0x80 if ov.gpio_level else 0)

    data = bytes(out)
    fc.FwImage(data, "<composed>").validate()
    return data


def load_header_file(path: Path) -> bytes:
    """读一个 1KB 头文件并归一化 (兼容字反序)."""
    d = Path(path).read_bytes()
    if len(d) < fc.HEADER_SIZE:
        raise fc.ImageError("头文件不足 1KB: %d B" % len(d))
    img, mode, norm = fc.decode_header_blob(d[:fc.HEADER_SIZE])
    if img is None:
        raise fc.ImageError("不是有效的 1KB 固件头:\n" +
                            fc.describe_header_blob(d[:fc.HEADER_SIZE]))
    return norm


def save_header_backup(state: AppState):
    if state.header_1kb is None:
        print("没有可用的 1KB 头 (需要管理员 + 在线设备). 无法备份.")
        return
    BACKUP_DIR.mkdir(exist_ok=True)
    idn = fc.IdentifyInfo(state.identify) if state.identify else None
    sn = (idn.sn if idn else None) or "dev"
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", sn)[:32] or "dev"
    name = "%s_%s" % (safe, datetime.now().strftime("%Y%m%d_%H%M%S"))
    hbin = BACKUP_DIR / (name + "_header.bin")
    hbin.write_bytes(state.header_1kb)
    print("已保存 %s (%d B)" % (hbin, len(state.header_1kb)))
    if state.header_mode and state.header_mode != "be" and state.header_raw:
        rbin = BACKUP_DIR / (name + "_header_raw.bin")
        rbin.write_bytes(state.header_raw)
        print("已保存 %s (原始字反序读回, %d B)" % (rbin, len(state.header_raw)))
    s = fc.header_summary(state.header_1kb)
    info = BACKUP_DIR / (name + "_info.txt")
    lines = [
        "设备      : %s" % (state.disk.path if state.disk else "?"),
        "时间      : %s" % datetime.now().isoformat(timespec="seconds"),
        "字序      : %s" % state.header_mode,
        "说明      : 客户参数区 1KB 头备份, 非整片固件; 固件 body 在线读不到, 整片备份需 SPI 编程器",
        "sha256    : %s" % s["sha256"],
        "",
        "DWORD0    : 0x%08X (body 长度 %d)" % (s["dword0"], s["size"]),
        "slot      : %d" % s["slot"],
        "SPI 0x38  : 0x%08X" % s["spi_cfg"],
        "dw31 0x7C : 0x%08X" % s["checksum"],
        "SN 0x10C  : %r" % s["serial"],
        "MN 0x120  : %r (%s)" % (s["model"], "动态拼装" if s["is_dynamic"] else "静态"),
        "mask 0x148: 0x%02X [%s]" % (s["mask"], s["mask_str"]),
        "覆盖0x154 : %r" % s["vendor_override"],
        "SMART 0xCD: 0x%02X -> %s (bit0=%d)"
        % (s["smart_byte"], s["smart_block_name"], s["smart_bit"]),
        "GPIO 0x105: 0x%02X -> %s" % (s["gpio_byte"], s["gpio_mode_name"]),
        "0x107     : -> 0x%02X" % s["gpio_level_byte"],
    ]
    info.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("已保存 %s" % info)
    fc.report_header(state.header_1kb, "已备份的客户参数区 1KB 头")
    print("注意: 这是客户参数区 1KB 头备份, 不是整片固件; 固件 body 在线读不到, "
          "整片备份需 SPI 编程器.")


def export_image(data: bytes, name: str, also_padded: bool = False) -> Path:
    p = HERE / name
    p.write_bytes(data)
    print("已导出 %s (%d B, sha256 %s)" % (p, len(data), fc._sha256(data)[:16]))
    if also_padded:
        p2 = HERE / (Path(name).stem + "_programmer_1MB.bin")
        p2.write_bytes(fc.FwImage(data, name).padded(fc.FLASH_SIZE))
        print("已导出编程器镜像 %s (1MB, 0xFF 补齐)" % p2)
    return p


def confirm(prompt: str, token: str | None = None) -> bool:
    if token:
        return input("%s\n  输入 %s 确认, 其他取消: " % (prompt, token)).strip().upper() == token.upper()
    return input("%s [y/N]: " % prompt).strip().lower() in ("y", "yes")


def _require_device(state: AppState, need_admin: bool = True):
    if state.disk is None:
        raise RuntimeError("未选择设备 (离线模式); 按 'r' 重新选择.")
    if state.disk.decision == "unsupported" or state.disk.is_system:
        raise RuntimeError("目标设备不支持刷写: %s" % (state.disk.notes or "系统盘"))
    if need_admin:
        if not state.is_admin:
            raise RuntimeError("该操作需要管理员权限 (请以管理员身份运行 python flashtool.py)")
        if not state.probe_ok:
            raise RuntimeError("透传/Identify 未确认, 拒绝操作")


def flash_bytes(state: AppState, data: bytes, label: str = "固件") -> bool:
    """刷写前风险提示 + Y 确认."""
    _require_device(state)
    img = fc.FwImage(data, "<to flash>")
    img.validate()
    print("\n待刷镜像: %s (%d B, sha256 %s)"
          % (label, len(data), fc._sha256(data)[:16]))
    print(RULE_SAFETY)
    print("  刷入 slot 3 (SPI Flash), action 1; 完成后请断电重启, 不要热插.")
    if not confirm("确认把 %s 刷入 %s?" % (label, state.disk.path), "Y"):
        print("已取消.")
        return False
    if state.dry_run:
        print("  [dry-run] 仅模拟, 未执行任何 FW Download/Commit.")
        return True
    with _open_dev(state) as dev:
        fc.flash_image(dev, img, chunk=fc.CHUNK_MAX, slot=fc.SLOT_SPI,
                       action=1, progress=True)
    print("刷写命令已下发完成. 请断开连接10s后再插入")
    return True


# --------------------------------------------------------------------------
# 动态拼装: 固定掩码 0xBC + 0x154 厂商名覆盖串
# --------------------------------------------------------------------------

def dynamic_assembly_ui() -> Overrides:
    """掩码固定 0xBC; 只问 0x154 厂商名覆盖串.

    固件能按 eMMC CID[0] MID 自动识别 fc.AUTO_VENDOR_NAMES 里的厂商, 命中时
    0x154 留空即可; 列表之外的厂商才需自定义覆盖串 (≤8B).
    """
    print("\n  固定 mask=0x%02X [%s] (0x120 清空, 运行时按位拼装)"
          % (FIXED_DYNAMIC_MASK, fc.mask_str(FIXED_DYNAMIC_MASK)))
    print("  固件可自动识别以下 %d 家 eMMC 厂商: %s"
          % (len(fc.AUTO_VENDOR_NAMES), _VENDOR_LIST))
    print("  命中这些厂商时 0x154 留空即可; 列表外的厂商才需自定义覆盖串.")
    while True:
        a = input("  0x154 厂商名覆盖串 (≤8B, 回车=留空): ").strip()
        if len(a.encode("latin-1", "replace")) > fc.VENDOR_OVERRIDE_LEN:
            print("  超过 8 字节, 请重输.")
            continue
        break
    preview, ln, ok = fc.assemble_model_preview(FIXED_DYNAMIC_MASK, a)
    print("  预览: %r   长度 %d/40  %s"
          % (preview, ln, "OK" if ok else "⚠ 超 40 字节, 固件将整体放弃拼装(型号保持空)"))
    print("  %s" % fc.RUNTIME_SEGMENT_NOTE)
    return Overrides(is_dynamic=True, mask=FIXED_DYNAMIC_MASK, vendor_override=a)


# --------------------------------------------------------------------------
# 选择辅助
# --------------------------------------------------------------------------

def _choose(prompt: str, options: dict[str, str], default: str | None = None):
    while True:
        print(prompt)
        for k, v in options.items():
            print("   %s) %s%s" % (k, v, "  [默认]" if k == default else ""))
        a = input("  > ").strip() or (default or "")
        if a in options:
            return a
        print("  无效选择: %r" % a)


def choose_smart_block() -> int:
    a = _choose("选择 SMART 槽位 (0xCD bit0):",
                {"1": "blk1 / 块1 BLOCK2 (0xCD=0)",
                 "2": "blk3 / 块3 BLOCK4 (0xCD=1)"}, "1")
    return 1 if a == "1" else 3


def choose_uart_led():
    a = _choose("选择 UART / LED (0x105):",
                {"1": "UART 115200 (0x40)", "2": "LED 忙闲闪烁 (0x80)"}, "1")
    print(RULE_GPIO)
    return GPIO_MODES["uart"] if a == "1" else GPIO_MODES["led"]


def list_bin_files() -> list[Path]:
    out = []
    for pat in ("*.bin", "*.BIN"):
        out += sorted(HERE.glob(pat))
    if FIRMWARE_DIR.is_dir():
        out += sorted(p for p in FIRMWARE_DIR.iterdir()
                      if p.is_file() and p.suffix.lower() == ".bin")
    return list(dict.fromkeys(out))


def list_header_files() -> list[Path]:
    return sorted(BACKUP_DIR.glob("*_header.bin")) if BACKUP_DIR.is_dir() else []


def select_any(include_headers: bool = False) -> Path | None:
    items: list[tuple[Path, str]] = [(p, "固件") for p in list_bin_files()]
    if include_headers:
        items += [(p, "备份头") for p in list_header_files()]
    if items:
        print("\n可选文件:")
        for i, (p, tag) in enumerate(items, 1):
            print("  %2d) [%-4s] %-40s %d B" % (i, tag, p.name, p.stat().st_size))
    else:
        print("当前目录/FIRMWARE/backup 里没有固件或备份头, 可直接输入自定义路径.")
    a = input("编号 / 自定义路径 / 回车取消: ").strip()
    if not a:
        return None
    if a.isdigit() and 1 <= int(a) <= len(items):
        return items[int(a) - 1][0]
    p = Path(a)
    if not p.is_absolute():
        p = HERE / p
    if not p.is_file():
        print("文件不存在: %s" % p)
        return None
    return p


# --------------------------------------------------------------------------
# 6 项菜单
# --------------------------------------------------------------------------

def menu_1(state: AppState):
    show_device_info(state)


def menu_2(state: AppState):
    save_header_backup(state)


def menu_3(state: AppState):
    _require_device(state)
    print("\n=== 刷入中间固件 (解决 SMART 固件数据异常 / 清 0) ===")
    for key, p in BRIDGE_FILES.items():
        if not p.is_file():
            print("  [错误] 缺少 %s" % p)
            return
        d = p.read_bytes()
        ok = fc._sha256(d) == KNOWN_SHA256[p.name]
        print("  %-5s %-34s %7d B  sha256 %s %s"
              % (key, p.name, len(d), fc._sha256(d)[:12], "OK" if ok else "不符!"))
        if not ok:
            print("  [错误] sha256 不符, 拒绝使用 (不现场生成补丁).")
            return
    print("  blk1 = 0xCD=0 / 块1(BLOCK2);  blk3 = 0xCD=1 / 块3(BLOCK4) ≡ blk4_bridge.bin")
    cur = (state.header_1kb[fc.SMART_BLK_OFF] & 1) if state.header_1kb else None
    print("  当前设备 0xCD bit0 = %s -> 建议 %s"
          % (cur, ("blk3" if cur else "blk1") if cur is not None else "(未知)"))
    key = _choose("选择中间固件:", {"1": "blk1 (0xCD=0)", "2": "blk3 (0xCD=1)"},
                  "2" if cur else "1")
    key = "blk1" if key == "1" else "blk3"
    bit = 0 if key == "blk1" else 1
    print(RULE_SMART)
    print("  [同源规则] 清除桥的 0xCD 必须等于最终固件的 0xCD; "
          "本镜像 0xCD bit0=%d -> 最终固件须用 %s." % (bit, "块1" if bit == 0 else "块3"))
    print("  三步流程: 1) 刷一次本中间固件  2) 完整断电 → 再上电一次(512B 全0合法记录在此步写入,"
          " 等几秒)  3) 断电 → 刷回同源最终固件 → 上电, SMART 从 0 正常累加.")
    print("  变砖风险: 中途失败/掉电会清 SPI DWORD0, 只能拆板用编程器恢复.")
    if not confirm("确认刷入中间固件 %s?" % BRIDGE_FILES[key].name, "Y"):
        return
    img = fc.FwImage(fc._read(str(BRIDGE_FILES[key])), str(BRIDGE_FILES[key]))
    img.validate()
    flash_bytes(state, img.trimmed(), label=BRIDGE_FILES[key].name)


def menu_4(state: AppState):
    _require_device(state)
    print("\n=== 在线刷入向导 ===")
    # 1) 底包
    a = _choose("1) 选择底包:", {"1": "XM25QH80B (工程版)", "2": "GD25Q80 (客户版)"}, "1")
    base = "xm" if a == "1" else "gd"
    ov = Overrides()
    header: bytes | None = None
    # 2) 信息来源 (三选一)
    src = _choose("2) 信息来源:",
                  {"1": "保持原盘信息 (在线设备 1KB 头)",
                   "2": "导入设备信息 (1KB 头文件, 先列出内容)",
                   "3": "自定义信息"}, "1")
    if src == "1":
        if state.header_1kb is None:
            raise RuntimeError("没有在线设备 1KB 头; 请以管理员身份运行并选设备.")
        header = state.header_1kb
        print("  将用在线设备头覆盖 0x20-0x7C 与 0x80-0x3E0 (保留底包长度/段表/校验).")
    elif src == "2":
        hdrs = list_header_files()
        if hdrs:
            print("  ./backup 里的备份头:")
            for i, p in enumerate(hdrs, 1):
                print("   %2d) %s" % (i, p.name))
        a2 = input("  编号 / 自定义路径: ").strip()
        p = None
        if a2.isdigit() and 1 <= int(a2) <= len(hdrs):
            p = hdrs[int(a2) - 1]
        elif a2:
            p = Path(a2)
            if not p.is_absolute():
                p = HERE / p
        if p is None or not p.is_file():
            print("  未提供有效头文件, 取消.")
            return
        header = load_header_file(p)
        print("  导入头内容:")
        fc.report_header(header, "导入的 1KB 头: %s" % p.name)
        if not confirm("按此头覆盖客户参数区?"):
            return
    else:
        print("  0x120 首 dword≠0 -> 原样使用 40B 型号; 全 0 -> 运行时动态拼装.")
        kind = _choose("   自定义型号方式:",
                       {"1": "自定义型号 (静态, ≤40B)", "2": "采用动态拼装"}, "2")
        if kind == "1":
            m = input("   型号 (≤40B, 回车=保持底包): ").strip()
            if m:
                ov.model = m
        else:
            ov = dynamic_assembly_ui()
        # 当前硬盘 SN: Identify Controller bytes 4:24, 回退 1KB 头 0x10C
        cur_sn = ""
        if state.identify:
            cur_sn = fc.IdentifyInfo(state.identify).sn
        if not cur_sn and state.header_1kb:
            raw_sn = state.header_1kb[fc.SN_OFF:fc.SN_OFF + fc.SN_LEN]
            cur_sn = raw_sn.split(b"\x00", 1)[0].decode("latin-1")
        if cur_sn:
            print("   当前硬盘 SN: %r" % cur_sn)
        else:
            print("   [提示] 未读到当前硬盘 SN (需管理员 + 在线设备); 回车则沿用底包 SN.")
        sn = input("   最后: 自定义 SN (≤20B, 回车=保持当前硬盘SN): ").strip()
        ov.sn = sn if sn else (cur_sn or None)
        print("  其余字段全部沿用所选底包 (0x38 等配置区不从在线设备继承).")
    # 3) SMART 槽位
    ov.smart_block = choose_smart_block()
    if ov.smart_block == 3:
        print("  说明: 只是把 0xCD 00→01, 无需重算校验; 等价于切到空的块3, "
              "不清历史. 要清历史请用菜单3的中间固件 (SMART_BRIDGE_FIRMWARE.md §5).")
    # 4) uart/led
    ov.uart_led = choose_uart_led()
    # 5) 刷入 / 导出
    act = _choose("5) 动作:", {"1": "导出 (只写文件, 不刷设备)",
                              "2": "刷入 (在线 FW Download/Commit)"}, "2")
    data = build_image(base, header=header, ov=ov)
    print("\n拼装结果:")
    fc.FwImage(data, "<composed>").report()
    if act == "1":
        name = input("  导出文件名 (回车=auto): ").strip()
        if not name:
            name = "flash_%s_%s.bin" % (base, datetime.now().strftime("%Y%m%d_%H%M%S"))
        if not name.lower().endswith(".bin"):
            name += ".bin"
        export_image(data, name, also_padded=confirm("同时导出 1MB 补齐的编程器镜像?"))
    else:
        flash_bytes(state, data, label="在线拼装镜像(%s)" % base)


def menu_5(state: AppState):
    print("\n=== 自定义刷入固件 ===")
    p = select_any(include_headers=False)
    if p is None:
        return
    data = p.read_bytes()
    img = fc.FwImage(data, str(p))
    try:
        img.validate()
    except fc.ImageError as e:
        print("镜像校验失败, 拒绝刷入:\n  %s" % e)
        return
    fc.report_header(data[:fc.HEADER_SIZE], "%s 的客户参数区" % p.name)
    img.report()
    flash_bytes(state, img.trimmed(), label=p.name)


def menu_6(state: AppState):
    print("\n=== 查看固件 / 备份信息 ===")
    p = select_any(include_headers=True)
    if p is None:
        return
    data = p.read_bytes()
    if len(data) == fc.HEADER_SIZE:
        fc.report_header(data, "1KB 备份头: %s" % p.name)
        return
    img = fc.FwImage(data, str(p))
    fc.report_header(data[:fc.HEADER_SIZE], "%s 的客户参数区" % p.name)
    img.report()


# --------------------------------------------------------------------------
# 横幅 / 菜单 / 主循环
# --------------------------------------------------------------------------

def print_banner(state: AppState):
    print("=" * 72)
    print(" BH799_E2M2_FlashTool_Win   BH799BB eMMC→NVMe 桥片固件刷写工具 (Windows)")
    print(" 目录: %s" % HERE)
    print(" 运行: %s  %s" % ("管理员" if state.is_admin else "普通用户(刷写需管理员)",
                            "[dry-run]" if state.dry_run else ""))
    print("=" * 72)


def print_rule_summaries():
    print(RULE_IMAGE)
    print(RULE_MASK)
    print(RULE_GPIO)
    print(RULE_SMART)
    print(RULE_SAFETY)


def print_menu(state: AppState):
    dev = ("%s [%s %s]" % (state.disk.path, state.disk.decision, state.transport)
           if state.disk else "离线/未选择")
    print("\n--- 当前设备: %s ---" % dev)
    print("  1) 查看设备信息        2) 备份设备信息(1KB头→./backup)")
    print("  3) 刷入中间固件        4) 在线刷入向导")
    print("  5) 自定义刷入固件      6) 查看固件/备份信息")
    print("  r) 重新选择设备        0) 退出")


def _console_setup():
    """Windows 控制台中文/符号输出: 尽力 UTF-8; 失败用 replace 兜底不中断."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv=None) -> int:
    _console_setup()
    argv = list(sys.argv[1:] if argv is None else argv)
    state = AppState(is_admin=wt.is_admin())
    state.dry_run = "--dry-run" in argv
    if "--selftest" in argv:
        return selftest()
    if "--enumerate" in argv:
        disks = list_disks()
        for d in disks:
            decide_transport(d)
        print_disk_table(disks)
        return 0

    print_banner(state)
    print_rule_summaries()
    disks = list_disks()
    for d in disks:
        decide_transport(d)
    if not pick_disk(state, disks):
        return 0
    if state.disk is not None:
        confirm_passthrough(state)
        show_device_info(state)       # 启动自动列出设备信息 ("下面的1")

    handlers = {"1": menu_1, "2": menu_2, "3": menu_3,
                "4": menu_4, "5": menu_5, "6": menu_6}
    while True:
        print_menu(state)
        c = input("选择: ").strip().lower()
        if c in ("0", "q", "quit", "exit"):
            return 0
        if c == "r":
            if not pick_disk(state, disks):
                return 0
            if state.disk is not None:
                confirm_passthrough(state)
                show_device_info(state)
            continue
        h = handlers.get(c)
        if h is None:
            print("无效选择: %r" % c)
            continue
        try:
            h(state)
        except (fc.ImageError, fc.NvmeError, OSError, ValueError, RuntimeError) as e:
            print("[错误] %s" % e)
        except KeyboardInterrupt:
            print("\n已取消当前操作.")
        except EOFError:
            return 0


# --------------------------------------------------------------------------
# 离线自检 (不接触设备, 不刷写)
# --------------------------------------------------------------------------

def selftest() -> int:
    print("=== 离线自检 (不刷写, 不接触设备) ===")
    failures = []

    def ck(cond, msg):
        if cond:
            print("  ok   %s" % msg)
        else:
            print("  FAIL %s" % msg)
            failures.append(msg)

    # 1. 四个底包精确断言
    expect = {
        "gd": (0x100000, 0x20718, 0x935F09D4, 0x00000000, 0xBD, 0, 0x40, False,
               "NA6169D003A74", "E2M2 64GB"),
        "xm": (0x100050, 0x20F20, 0xCA11DA1B, 0x800010D8, 0xBC, 0, 0x80, True,
               "29036200000000000001", ""),
        "b1": (0x100050, 0x20F20, 0xC23D858A, 0x800010D8, 0xBC, 0, 0x80, True,
               "29036200000000000001", ""),
        "b3": (0x100000, 0x20F20, 0xC23D858A, 0x800010D8, 0xBC, 1, 0x80, True,
               "29036200000000000001", ""),
    }
    for k, (ln, size, dw31, sp, mask, cd, gpio, dyn, sn, mn) in expect.items():
        p = (BASE_FILES[k] if k in ("gd", "xm") else BRIDGE_FILES["blk1" if k == "b1" else "blk3"])
        d = p.read_bytes()
        ck(len(d) == ln, "%s 长度 %#x" % (k, ln))
        ck(fc._sha256(d) == KNOWN_SHA256[p.name], "%s sha256" % k)
        img = fc.FwImage(d, p.name)
        ck(not img.errors(), "%s validate()" % k)
        ck(img.size == size and img.checksum == dw31 and img.spi_cfg == sp,
           "%s size/dw31/0x38" % k)
        ck(img.slot == fc.SLOT_SPI, "%s slot==3" % k)
        ck(d[fc.MASK_OFF] == mask and d[0x144] == 0, "%s 0x148/0x144" % k)
        ck((d[fc.SMART_BLK_OFF] & 1) == cd and d[fc.GPIO_MODE_OFF] == gpio,
           "%s 0xCD/0x105" % k)
        ck(img.is_dynamic_model == dyn and img.serial == sn and img.model == mn,
           "%s 型号/静态动态/SN" % k)

    # 2. XOR 口径: 大端 + 1MB 上限 + 80B 尾排除
    xm = BASE_FILES["xm"].read_bytes()
    ck(struct.unpack(">I", xm[0x7C:0x80])[0] == fc.xor_words(xm[0x400:0x100000]),
       "dw31 = XOR(0x400..0x100000) 大端")
    ck(fc.xor_words(xm[0x400:]) != fc.xor_words(xm[0x400:0x100000]),
       "含 80B 尾则 XOR 不同 (必须裁掉)")
    ck(fc.FwImage(xm, "xm").trimmed() == xm[:1024 + fc.FwImage(xm, "xm").size],
       "trimmed() 裁掉尾与填充")
    ck(len(fc.FwImage(xm, "xm").padded(fc.FLASH_SIZE)) == fc.FLASH_SIZE,
       "padded(1MB) 恰好 1MB")

    # 3. 掩码解析 / 逐位示意 / 预览
    ck(fc.mask_str(0xBC) == "ven|mid|pnm|fwver|cap", "mask_str(0xBC)")
    pv, ln, ok = fc.assemble_model_preview(0xBC)
    ck(pv == fc.EXAMPLE_MODEL and ln <= 40 and ok, "0xBC 预览与真机抓包一致且不超长")
    ck(FIXED_DYNAMIC_MASK == 0xBC, "菜单4 动态拼装固定掩码 = 0xBC")
    ck(len(fc.AUTO_VENDOR_NAMES) == 13
       and "Kingston" in fc.AUTO_VENDOR_NAMES and "Samsung" in fc.AUTO_VENDOR_NAMES,
       "固件可自动识别厂商表 13 家")
    ck(all(len(v.encode("latin-1")) <= fc.VENDOR_OVERRIDE_LEN
           for v in fc.AUTO_VENDOR_NAMES), "13 家厂商名均 ≤8B (可被 0x154 覆盖)")
    pv2, ln2, ok2 = fc.assemble_model_preview(0xBC, "ACME")
    ck("ACME-" in pv2 and ok2, "0x154 覆盖串在 MID 段预览中生效")

    # 4. 字序往返 (用 12345/header_raw.bin 若存在, 否则用底包头 swap)
    sample = HERE.parent / "12345" / "header_raw.bin"
    raw = sample.read_bytes()[:1024] if sample.is_file() else fc.swap32_words(xm[:1024])
    img, mode, norm = fc.decode_header_blob(raw)
    ck(img is not None and mode in ("be", "le32"), "decode_header_blob 字序自动识别")
    if img is not None:
        ck(len(norm) == 1024 and fc.decode_header_blob(norm)[1] == "be",
           "归一化后再解码为 be")
    ck(fc.decode_header_blob(xm[:1024])[1] == "be", "本来的大端头识别为 be")

    # 5. header_summary / report_header 对 1KB 头可用 (不报"截断")
    s = fc.header_summary(xm[:1024])
    ck(s["valid"] and s["mask"] == 0xBC and s["smart_bit"] == 0, "header_summary(1KB)")

    # 6. _FakeController 往返
    fake = fc._FakeController()
    n = fc.flash_image(fake, fc.FwImage(xm, "xm"), progress=False)
    ck(fake.committed and fake.flash[:n] == fc.FwImage(xm, "xm").trimmed(),
       "_FakeController 下载→提交 往返")
    try:
        fc.flash_image(fc._FakeController(), fc.FwImage(xm, "xm"),
                       chunk=8192, progress=False)
        ck(False, "chunk>4096 应抛错")
    except ValueError:
        ck(True, "chunk>4096 抛错")

    # 7. build_image 三模式矩阵
    gd_hdr = BASE_FILES["gd"].read_bytes()[:1024]
    for base in ("xm", "gd"):
        b = fc.FwImage(BASE_FILES[base].read_bytes(), base)
        # 自定义模式 (header=None): 只覆盖用户输入, 其余沿用底包
        d = build_image(base, None, Overrides(is_dynamic=True, mask=0xA4,
                                              vendor_override="VEND",
                                              sn="SN123", smart_block=3, uart_led=0x40))
        i = fc.FwImage(d, "<t>")
        ck(not i.errors(), "build_image(%s, None) validate" % base)
        ck(i.spi_cfg == b.spi_cfg and i.checksum == b.checksum and i.size == b.size,
           "自定义模式保留底包 0x38/dw31/长度")
        ck(i.serial == "SN123" and i.is_dynamic_model and i.model_mask == 0xA4,
           "自定义模式 SN/动态/mask 生效")
        ck(i.vendor_override == "VEND" and (d[fc.SMART_BLK_OFF] & 1) == 1
           and (d[fc.GPIO_MODE_OFF] >> 6) == 1,
           "自定义模式 0x154/0xCD/0x105 生效")
        # 保持/导入模式 (header 覆盖)
        d2 = build_image(base, gd_hdr, Overrides(smart_block=1))
        i2 = fc.FwImage(d2, "<t2>")
        ck(not i2.errors(), "build_image(%s, header) validate" % base)
        ck(i2.spi_cfg == 0 and i2.serial == "NA6169D003A74" and i2.model == "E2M2 64GB",
           "导入头客户参数覆盖生效, 长度/段表/校验仍归底包")
        # 4 条不变量
        for label, cond in (
            ("DWORD0", d2[:4] == BASE_FILES[base].read_bytes()[:4]),
            ("段表", d2[4:0x1C] == BASE_FILES[base].read_bytes()[4:0x1C]),
            ("dw31", d2[0x7C:0x80] == BASE_FILES[base].read_bytes()[0x7C:0x80]),
            ("产线记录", d2[0x3E0:0x400] == BASE_FILES[base].read_bytes()[0x3E0:0x400]),
        ):
            ck(cond, "不变量 %s (%s)" % (label, base))
        ck(i2.checksum == b.checksum, "checksum 不变 (%s)" % base)

    # 8. 长度上限
    try:
        build_image("xm", None, Overrides(sn="X" * 21))
        ck(False, "SN>20B 应抛错")
    except fc.ImageError:
        ck(True, "SN>20B 抛错")
    # 9. 菜单4 动态拼装: 固定掩码 0xBC + 0x154 厂商名覆盖串
    d3 = build_image("xm", None, Overrides(is_dynamic=True,
                                           mask=FIXED_DYNAMIC_MASK,
                                           vendor_override="ACME"))
    i3 = fc.FwImage(d3, "<d3>")
    ck(d3[fc.MASK_OFF] == 0xBC and i3.is_dynamic_model and i3.vendor_override == "ACME",
       "固定 0xBC + 0x154 覆盖串写入生效")
    try:
        build_image("xm", None, Overrides(is_dynamic=True,
                                          vendor_override="X" * 9))
        ck(False, "0x154>8B 应抛错")
    except fc.ImageError:
        ck(True, "0x154>8B 抛错")

    # 10. Windows 传输层: 结构体布局 / IOCTL 常量 / 协议字节 (Linux x64 可验证)
    L = wt.describe_layout()
    ck(L["ptr_size"] == 8, "wintransport 指针 8B (与 Windows x64 同对齐)")
    ck(L["STORAGE_PROPERTY_QUERY"] == 12, "STORAGE_PROPERTY_QUERY sizeof=12")
    ck(L["SCSI_PASS_THROUGH_DIRECT"] == 56, "SCSI_PASS_THROUGH_DIRECT sizeof=56")
    ck(L["SCSI_PASS_THROUGH_DIRECT.Cdb"] == 36, "SCSI_PASS_THROUGH_DIRECT.Cdb 偏移=36")
    ck(L["SRB_IO_CONTROL"] == 28, "SRB_IO_CONTROL sizeof=28")
    ck(L["SPC_HEADER_LEN"] == 80 and L["SPC_DATA_OFFSET"] == 144,
       "STORAGE_PROTOCOL_COMMAND 头/数据偏移 80/144")
    ck(wt.IOCTL_STORAGE_QUERY_PROPERTY == 0x002D1400,
       "IOCTL_STORAGE_QUERY_PROPERTY=0x2D1400")
    ck(wt.IOCTL_STORAGE_PROTOCOL_COMMAND == 0x002DD3C0,
       "IOCTL_STORAGE_PROTOCOL_COMMAND=0x2DD3C0")
    ck(wt.IOCTL_SCSI_PASS_THROUGH_DIRECT == 0x0004D014,
       "IOCTL_SCSI_PASS_THROUGH_DIRECT=0x4D014")
    ck(wt.IOCTL_SCSI_MINIPORT == 0x0004D008, "IOCTL_SCSI_MINIPORT=0x4D008")
    ck(wt.IOCTL_DISK_GET_LENGTH_INFO == 0x0007405C,
       "IOCTL_DISK_GET_LENGTH_INFO=0x7405C")
    ck(wt._cdb(0x0, 512)[:6] == bytes.fromhex("a18000000200"),
       "JMS583 CDB(0xA1,proto0,512) 逐字节")
    nb = wt._nvm_block(fc.ADMIN_IDENTIFY, cdw10=1)
    ck(nb[:4] == b"NVME" and struct.unpack_from("<I", nb, 8)[0] == 0x06
       and struct.unpack_from("<I", nb, 48)[0] == 1,
       "JMS583 NVM 命令块: 签名/opcode/CDW10")
    nc = wt._nvme_command(0x02, 0, 0x00FF00C0, 0, 0, 0, 0, 0)
    ck(nc[0] == 0x02 and struct.unpack_from("<I", nc, 40)[0] == 0x00FF00C0,
       "NVMe 64B 命令 CDW0/CDW10")
    spc = wt._spc_buffer(0x02, 0, (0, 0, 0, 0, 0, 0), data_in=1024)
    ck(len(spc) == wt.SPC_DATA_OFFSET + 1024
       and spc[wt.SPC_HEADER_LEN] == 0x02
       and struct.unpack_from("<I", spc, 36)[0] == 1024,
       "STORAGE_PROTOCOL_COMMAND 缓冲构造 (Command@80, Data@144)")
    if not wt.IS_WINDOWS:
        try:
            wt.list_disks()
            ck(False, "非 Windows 上设备枚举应明确报错")
        except fc.NvmeError:
            ck(True, "非 Windows 上设备枚举明确报错(不误连)")

    print("\n=== 结果: %d 项失败 ===" % len(failures))
    for f in failures:
        print("  - %s" % f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

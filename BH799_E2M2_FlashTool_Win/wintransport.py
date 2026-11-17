#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BH799_E2M2_FlashTool_Win 设备传输层 (Windows, 纯 ctypes + kernel32, 无第三方包).

=============================================================================
【重要 · 验证边界】
本文件的 DeviceIoControl 调用无法在 Linux 开发机上验证。能在 Linux 上验证的只有:
  * 所有 ctypes 结构体的 sizeof / 字段偏移 (Windows x64 与 Linux x64 同为 LP64/
    8 字节指针对齐, 布局一致) —— selftest 会逐项断言;
  * 协议字节构造 (JMS583 CDB / NVM 命令块 / NVMe CDW) —— selftest 逐字节比对;
  * 底层 API 常量 (CTL_CODE 计算) —— selftest 逐项断言.

而「某个 IOCTL 是否被 Windows 驱动放行、CDB 是否被原样透传、FW Download/Commit
是否真能落盘」必须在 Windows 实机上用【只读探测】确认: 运行菜单 1(查看设备信息),
确认 Identify + 厂商日志 0xC0 能读回有效 1KB 头后, 再考虑任何刷写。
本工具把「只读探测成功」(probe_ok) 作为刷写的硬性前置条件, 就是为此。
切勿把本层当作已验证可用。
=============================================================================

两条设备通道 (与 Linux 版 detect 决策一一对应):
  * USB 硬盘盒 (JMS583, BusType=Usb): WinJmicronScsi
      IOCTL_SCSI_PASS_THROUGH_DIRECT + 3 步 ATA-PASS-THROUGH(12) 0xA1,
      与 Linux SG_IO 路径逐字节同构 (CDB/NVM 命令块/回复解析完全相同)。
  * 直连 NVMe (BusType=Nvme): WinNvmeAdmin
      IOCTL_STORAGE_PROTOCOL_COMMAND + STORAGE_PROTOCOL_COMMAND(Win10+)。

对外接口与 Linux 版传输层完全一致 (flashcore 的 flash_image / probe_device /
read_header_1kb 无需改动即可复用):
  identify(cns=1) -> 4096B
  get_log(lid, size, nsid=0) -> bytes
  fw_download(byte_offset, chunk)
  fw_commit(slot, action)
  fw_slot_log() / reset() / close() / context manager
"""

from __future__ import annotations

import ctypes
import struct
import sys

import flashcore as fc

IS_WINDOWS = sys.platform == "win32"

# --------------------------------------------------------------------------
# Win32 基础常量 / CTL_CODE
# --------------------------------------------------------------------------

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080

METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 1
FILE_WRITE_ACCESS = 2

FILE_DEVICE_CONTROLLER = 0x00000004      # IOCTL_SCSI_BASE
FILE_DEVICE_MASS_STORAGE = 0x0000002D   # IOCTL_STORAGE_BASE
FILE_DEVICE_DISK = 0x00000007           # IOCTL_DISK_BASE


def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method


# 下列数值均可用 selftest 中的 test_ioctl_constants() 复算验证
IOCTL_STORAGE_QUERY_PROPERTY = CTL_CODE(
    FILE_DEVICE_MASS_STORAGE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)       # 0x002D1400
IOCTL_STORAGE_PROTOCOL_COMMAND = CTL_CODE(
    FILE_DEVICE_MASS_STORAGE, 0x04F0, METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS)                                     # 0x002DD3C0
IOCTL_SCSI_PASS_THROUGH_DIRECT = CTL_CODE(
    FILE_DEVICE_CONTROLLER, 0x0405, METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS)                                     # 0x0004D014
IOCTL_SCSI_MINIPORT = CTL_CODE(
    FILE_DEVICE_CONTROLLER, 0x0402, METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS)                                     # 0x0004D008
IOCTL_DISK_GET_LENGTH_INFO = CTL_CODE(
    FILE_DEVICE_DISK, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)             # 0x0007405C

# STORAGE_PROPERTY_QUERY / STORAGE_DEVICE_DESCRIPTOR
STORAGE_PROPERTY_ID_DeviceProperty = 0
STORAGE_QUERY_TYPE_StandardQuery = 0

# STORAGE_BUS_TYPE (winioctl.h, 枚举从 0 开始)
BUS_TYPE = {
    0: "Unknown", 1: "Scsi", 2: "Atapi", 3: "Ata", 4: "1394", 5: "Ssa",
    6: "Fibre", 7: "Usb", 8: "RAID", 9: "iScsi", 10: "Sas", 11: "Sata",
    12: "Sd", 13: "Mmc", 14: "Virtual", 15: "FileBackedVirtual",
    16: "Spaces", 17: "Nvme", 18: "SCM", 19: "Ufs",
}
BUS_TYPE_USB = 7
BUS_TYPE_NVME = 17

# SCSI_PASS_THROUGH_DIRECT.DataIn
SCSI_IOCTL_DATA_OUT = 0
SCSI_IOCTL_DATA_IN = 1
SCSI_IOCTL_DATA_UNSPECIFIED = 2

# STORAGE_PROTOCOL_COMMAND / NVMe
STORAGE_PROTOCOL_STRUCTURE_VERSION = 0x1
PROTOCOL_TYPE_NVME = 3
STORAGE_PROTOCOL_COMMAND_FLAG_ADAPTER_REQUEST = 0x80000000
STORAGE_PROTOCOL_STATUS = {
    0: "PENDING", 1: "SUCCESS", 2: "ERROR", 3: "INVALID_REQUEST",
    4: "NO_DEVICE", 5: "BUSY", 6: "DATA_OVERRUN",
    7: "INSUFFICIENT_RESOURCES", 8: "NOT_SUPPORTED",
}
# 【待实机确认】winioctl.h(用户态, 本工具用) 的 STORAGE_PROTOCOL_COMMAND 是
# Reserved1[2] -> 20 个 DWORD = 80B, Command[] 从 80 起; 而 ntddstor.h(内核态)
# 是 Reserved1[1] -> 76B。若直连 NVMe 通道 ReturnStatus 异常, 第一处要核对的就是
# SPC_HEADER_LEN(76/80) 与 Length 字段(微软文档写 sizeof(结构), 也有实现填 80)。
SPC_HEADER_LEN = 80
NVME_COMMAND_LEN = 64      # CDW0..CDW15
SPC_DATA_OFFSET = 144      # 80 + 64, 8 字节对齐 (指针要求)

SENSE_LEN = 32

# --------------------------------------------------------------------------
# ctypes 结构体 (布局可在 Linux x64 上用 ctypes.sizeof 验证)
# --------------------------------------------------------------------------


class STORAGE_PROPERTY_QUERY(ctypes.Structure):
    _fields_ = [
        ("PropertyId", ctypes.c_uint32),          # 0
        ("QueryType", ctypes.c_uint32),           # 4
        ("AdditionalParameters", ctypes.c_ubyte * 1),  # 8
    ]                                              # sizeof = 12


class SCSI_PASS_THROUGH_DIRECT(ctypes.Structure):
    """ntddscsi.h; MSVC 默认 8 字节对齐 -> x64 sizeof=56, x86=44."""
    _fields_ = [
        ("Length", ctypes.c_ushort),              # 0
        ("ScsiStatus", ctypes.c_ubyte),           # 2
        ("PathId", ctypes.c_ubyte),               # 3
        ("TargetId", ctypes.c_ubyte),             # 4
        ("Lun", ctypes.c_ubyte),                  # 5
        ("CdbLength", ctypes.c_ubyte),            # 6
        ("SenseInfoLength", ctypes.c_ubyte),      # 7
        ("DataIn", ctypes.c_ubyte),               # 8
        ("DataTransferLength", ctypes.c_uint32),  # 12
        ("TimeOutValue", ctypes.c_uint32),        # 16
        ("DataBuffer", ctypes.c_void_p),          # 24
        ("SenseInfoOffset", ctypes.c_uint32),     # 32
        ("Cdb", ctypes.c_ubyte * 16),             # 36
    ]


class SRB_IO_CONTROL(ctypes.Structure):
    """ntddscsi.h, pack(1), sizeof=28 (备用: 'NvmeMini' 直通路径)."""
    _pack_ = 1
    _fields_ = [
        ("HeaderLength", ctypes.c_uint32),
        ("Signature", ctypes.c_ubyte * 8),
        ("Timeout", ctypes.c_uint32),
        ("ControlCode", ctypes.c_uint32),
        ("ReturnCode", ctypes.c_uint32),
        ("Length", ctypes.c_uint32),
    ]


def describe_layout():
    """返回结构体布局摘要, 供 selftest 在任意平台断言."""
    return {
        "ptr_size": ctypes.sizeof(ctypes.c_void_p),
        "STORAGE_PROPERTY_QUERY": ctypes.sizeof(STORAGE_PROPERTY_QUERY),
        "SCSI_PASS_THROUGH_DIRECT": ctypes.sizeof(SCSI_PASS_THROUGH_DIRECT),
        "SCSI_PASS_THROUGH_DIRECT.Cdb": SCSI_PASS_THROUGH_DIRECT.Cdb.offset,
        "SRB_IO_CONTROL": ctypes.sizeof(SRB_IO_CONTROL),
        "SPC_HEADER_LEN": SPC_HEADER_LEN,
        "SPC_DATA_OFFSET": SPC_DATA_OFFSET,
    }


# --------------------------------------------------------------------------
# kernel32 绑定 (仅 Windows 时才真正加载, 保证本模块可在 Linux import 跑自检)
# --------------------------------------------------------------------------

_k32 = None
_shell32 = None

if IS_WINDOWS:                                                # pragma: no cover
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.restype = ctypes.c_void_p
    _k32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    _k32.DeviceIoControl.restype = ctypes.c_int  # BOOL
    _k32.DeviceIoControl.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    _k32.CloseHandle.restype = ctypes.c_int
    _k32.CloseHandle.argtypes = [ctypes.c_void_p]
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    _shell32.IsUserAnAdmin.restype = ctypes.c_int
    _shell32.IsUserAnAdmin.argtypes = []


def _require_windows():
    if not IS_WINDOWS:
        raise fc.NvmeError(
            "此操作需要 Windows (DeviceIoControl); 当前是 %s 开发机。\n"
            "  离线功能 (查看/拼装/导出/备份头/selftest) 仍可用; "
            "设备探测与刷写请在 Windows 实机以管理员身份运行。" % sys.platform)


def is_admin() -> bool:
    """是否以管理员身份运行 (替代 Linux 的 os.geteuid()==0)."""
    if not IS_WINDOWS:
        return False
    return bool(_shell32.IsUserAnAdmin())


def _open_handle(path: str, query_only: bool = False):
    """打开 \\\\.\\PhysicalDriveN; 返回句柄或 None.

    query_only=True 时 dwDesiredAccess=0 —— 仅做 IOCTL_STORAGE_QUERY_PROPERTY /
    GET_LENGTH_INFO 这类查询, 普通用户权限即可 (枚举不需要管理员).
    实际发命令 (SCSI_PASS_THROUGH_DIRECT / PROTOCOL_COMMAND 的 CTL_CODE 含
    FILE_READ_ACCESS|FILE_WRITE_ACCESS) 必须 GENERIC_READ|GENERIC_WRITE, 需管理员.
    """
    access = 0 if query_only else (GENERIC_READ | GENERIC_WRITE)
    h = _k32.CreateFileW(
        path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, None,
        OPEN_EXISTING, 0, None)
    if h is None or h == ctypes.c_void_p(-1).value:
        return None
    return h


def _close_handle(h):
    if h:
        _k32.CloseHandle(h)


def _ioctl(h, code: int, in_bytes: bytes, out_len: int) -> bytes:
    """DeviceIoControl(METHOD_BUFFERED), 独立 in/out 缓冲区, 返回 out_len 字节."""
    ib = (ctypes.c_ubyte * max(len(in_bytes), 1)).from_buffer_copy(
        in_bytes if in_bytes else b"\x00")
    ob = (ctypes.c_ubyte * max(out_len, 1))()
    returned = ctypes.c_uint32(0)
    ok = _k32.DeviceIoControl(
        h, code,
        ctypes.cast(ib, ctypes.c_void_p), len(in_bytes),
        ctypes.cast(ob, ctypes.c_void_p), out_len,
        ctypes.byref(returned), None)
    if not ok:
        raise fc.NvmeError("DeviceIoControl 0x%08X 失败 (GetLastError=%d)"
                           % (code, ctypes.get_last_error()))
    return bytes(bytearray(ob))[:out_len]


# --------------------------------------------------------------------------
# 设备枚举: IOCTL_STORAGE_QUERY_PROPERTY + IOCTL_DISK_GET_LENGTH_INFO
# --------------------------------------------------------------------------


def _cstr(buf: bytes, off: int) -> str:
    """从描述符缓冲区 off 处取 NUL 结尾的 ASCII 串."""
    if off <= 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("ascii", "replace").strip()


def _query_descriptor(h):
    """返回 (bus_type, vendor, product, serial, revision)."""
    q = STORAGE_PROPERTY_QUERY()
    q.PropertyId = STORAGE_PROPERTY_ID_DeviceProperty
    q.QueryType = STORAGE_QUERY_TYPE_StandardQuery
    raw = _ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, bytes(q), 4096)
    if len(raw) < 36:
        raise fc.NvmeError("STORAGE_DEVICE_DESCRIPTOR 过短 (%d B)" % len(raw))
    # STORAGE_DEVICE_DESCRIPTOR 字段偏移 (winioctl.h)
    vendor_off, product_off, rev_off, serial_off = struct.unpack_from("<4I", raw, 12)
    bus_type = struct.unpack_from("<I", raw, 28)[0]
    return (bus_type, _cstr(raw, vendor_off), _cstr(raw, product_off),
            _cstr(raw, serial_off), _cstr(raw, rev_off))


def _disk_length(h) -> int:
    raw = _ioctl(h, IOCTL_DISK_GET_LENGTH_INFO, b"", 8)
    return struct.unpack_from("<Q", raw, 0)[0]


def list_disks(max_index: int = 32):
    """枚举 \\\\.\\PhysicalDrive0..N, 返回磁盘信息 dict 列表.

    【说明】Windows 纯 DeviceIoControl 拿不到 USB 的 152d:f583 VID/PID
    (那需要 SetupAPI/CM_* 读硬件 ID)。因此硬盘盒判定用 BusType==Usb,
    并沿用 Linux 版相同的「Identify Model 含 BAYHUB/E2M2」只读守卫做最终确认。
    """
    _require_windows()
    disks = []
    for n in range(max_index):
        path = r"\\.\PhysicalDrive%d" % n
        h = _open_handle(path, query_only=True)
        if not h:
            continue
        try:
            try:
                bus, vendor, product, serial, rev = _query_descriptor(h)
            except fc.NvmeError:
                continue
            try:
                size = _disk_length(h)
            except fc.NvmeError:
                size = 0
        finally:
            _close_handle(h)
        disks.append({
            "path": path,
            "name": "PhysicalDrive%d" % n,
            "index": n,
            "size_bytes": size,
            "vendor": vendor,
            "model": product,
            "serial": serial or None,
            "bus_type": bus,
            "bus_name": BUS_TYPE.get(bus, "Unknown(%d)" % bus),
            "is_usb": bus == BUS_TYPE_USB,
            "is_nvme": bus == BUS_TYPE_NVME,
            # VID/PID 需 SetupAPI, 本版留空; 表格显示 "-"
            "usb_vid": "", "usb_pid": "", "usb_driver": "",
            "devpath": "",
        })
    return disks


# --------------------------------------------------------------------------
# USB 硬盘盒 (JMS583): 与 Linux SG_IO 逐字节同构的 3 步 ATA-PASS-THROUGH(12)
# --------------------------------------------------------------------------


def _cdb(proto: int, size: int = 0) -> bytes:
    """ATA PASS-THROUGH(12) CDB; 与 Linux 版 JmicronScsi._cdb 完全一致."""
    c = bytearray(12)
    c[0] = 0xA1
    c[1] = 0x80 | (proto & 0x0F)
    c[3] = (size >> 16) & 0xFF
    c[4] = (size >> 8) & 0xFF
    c[5] = size & 0xFF
    return bytes(c)


def _nvm_block(opcode, cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw14=0,
               cdw15=0, nsid=0) -> bytes:
    """512B JMicron NVM Command Block; 与 Linux 版逐字节一致."""
    b = bytearray(512)
    struct.pack_into("<I", b, 0, fc.SNT_JMICRON_SIGNATURE)
    struct.pack_into("<I", b, 8, opcode & 0xFF)
    struct.pack_into("<I", b, 12, nsid & 0xFFFFFFFF)
    for i, v in enumerate((cdw10, cdw11, cdw12, cdw13, cdw14, cdw15)):
        struct.pack_into("<I", b, 48 + 4 * i, v & 0xFFFFFFFF)
    return bytes(b)


class WinJmicronScsi:
    """USB 硬盘盒 (JMS583) -> NVMe Admin 透传.

    Windows 的 IOCTL_SCSI_PASS_THROUGH_DIRECT 与 Linux 的 SG_IO 一样能把 12B
    CDB 原样送到设备; 3 步协议/CDB/NVM 块/回复解析与 Linux 版完全相同。

    【未验证】UASP 类驱动是否放行 cdb[1]=0x80|proto 这种厂商自定义用法,
    必须在 Windows 实机用只读 Identify 确认。
    """

    def __init__(self, path: str):
        _require_windows()
        self.path = path
        self.h = _open_handle(path)
        if not self.h:
            raise fc.NvmeError(
                "打开 %s 失败; 需以管理员身份运行, 且设备存在." % path)

    def close(self):
        if self.h:
            _close_handle(self.h)
            self.h = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _spt(self, cdb: bytes, data_in: int, data: bytes, timeout_s: int) -> bytes:
        """一次 SCSI_PASS_THROUGH_DIRECT; 返回 DataBuffer 内容."""
        n = len(data)
        dbuf = (ctypes.c_ubyte * max(n, 1))()
        if n:
            ctypes.memmove(dbuf, data, n)
        sptd = SCSI_PASS_THROUGH_DIRECT()
        sz = ctypes.sizeof(SCSI_PASS_THROUGH_DIRECT)
        sptd.Length = sz
        sptd.CdbLength = len(cdb)
        sptd.SenseInfoLength = SENSE_LEN
        sptd.DataIn = data_in
        sptd.DataTransferLength = n
        sptd.TimeOutValue = timeout_s
        sptd.DataBuffer = ctypes.addressof(dbuf)
        sptd.SenseInfoOffset = sz
        for i, b in enumerate(cdb[:16]):
            sptd.Cdb[i] = b
        buf = bytes(sptd) + bytes(SENSE_LEN)
        out = _ioctl(self.h, IOCTL_SCSI_PASS_THROUGH_DIRECT, buf, len(buf))
        res = SCSI_PASS_THROUGH_DIRECT.from_buffer_copy(out[:sz])
        if res.ScsiStatus:
            sense = out[sz:sz + SENSE_LEN]
            raise fc.NvmeError("SCSI 错误: ScsiStatus=0x%02X sense=%s"
                               % (res.ScsiStatus, sense.hex()))
        return bytes(bytearray(dbuf))[:n]

    def _admin(self, opcode, cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw14=0,
               cdw15=0, nsid=0, data_in=None, data_out=None, timeout_ms=30000):
        t = max(1, timeout_ms // 1000)
        # 1) 送 NVM Command Block (data-out 512B)
        self._spt(_cdb(0x0, 512), SCSI_IOCTL_DATA_OUT,
                  _nvm_block(opcode, cdw10, cdw11, cdw12, cdw13, cdw14,
                             cdw15, nsid), t)
        got = b""
        if data_out is not None:            # 2a) 数据出
            self._spt(_cdb(0x3, len(data_out)), SCSI_IOCTL_DATA_OUT, data_out, t)
        elif data_in is not None:           # 2b) 数据入
            got = self._spt(_cdb(0x2, data_in), SCSI_IOCTL_DATA_IN,
                            b"\x00" * data_in, t)
        else:                               # 2c) 无数据
            self._spt(_cdb(0x1, 0), SCSI_IOCTL_DATA_UNSPECIFIED, b"", t)
        # 3) 取 512B reply
        reply = self._spt(_cdb(0xF, 512), SCSI_IOCTL_DATA_IN,
                          b"\x00" * 512, t)
        words = struct.unpack("<128I", reply[:512])
        if words[0] != fc.SNT_JMICRON_SIGNATURE:
            raise fc.NvmeError("不是 JMicron NVMe reply (签名字 0x%08X)" % words[0])
        status = words[5] >> 17
        if status:
            hint = fc.FW_STATUS_HINTS.get(status, "")
            raise fc.NvmeError("NVMe 命令 0x%02X 失败: status=0x%04X%s"
                               % (opcode, status,
                                  (" (" + hint + ")") if hint else ""))
        return words[2], got

    def identify(self, cns=1) -> bytes:
        _, buf = self._admin(fc.ADMIN_IDENTIFY, cdw10=cns,
                             data_in=4096, timeout_ms=10000)
        return buf

    def get_log(self, lid: int, size: int = fc.HEADER_SIZE, nsid: int = 0) -> bytes:
        numd = (size >> 2) - 1
        cdw10 = (lid & 0xFF) | ((numd & 0xFFFF) << 16)
        cdw11 = (numd >> 16) & 0xFFFF
        _, buf = self._admin(fc.ADMIN_GET_LOG_PAGE, cdw10=cdw10, cdw11=cdw11,
                             nsid=nsid, data_in=size, timeout_ms=10000)
        return buf

    def fw_download(self, byte_offset: int, chunk: bytes):
        if byte_offset % 4 or len(chunk) % 4:
            raise ValueError("FW Download 的 offset/length 必须是 4 字节对齐")
        self._admin(fc.ADMIN_FW_DOWNLOAD, cdw10=(len(chunk) >> 2) - 1,
                    cdw11=byte_offset >> 2, data_out=chunk, timeout_ms=60000)

    def fw_commit(self, slot: int, action: int):
        self._admin(fc.ADMIN_FW_COMMIT,
                    cdw10=(slot & 0x7) | ((action & 0x7) << 3),
                    timeout_ms=180000)

    def reset(self):
        raise fc.NvmeError("USB 透传没有控制器复位命令; 请拔插硬盘盒或断电重启")

    def fw_slot_log(self) -> bytes:
        return self.get_log(fc.LID_FW_SLOT, 512)


# --------------------------------------------------------------------------
# 直连 NVMe: IOCTL_STORAGE_PROTOCOL_COMMAND (Win10+, in-box stornvme.sys)
# --------------------------------------------------------------------------


def _nvme_command(opcode, nsid, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15):
    """64B NVMe 命令: CDW0[7:0]=opcode, NSID@4, CDW10..15@40..63."""
    c = bytearray(NVME_COMMAND_LEN)
    struct.pack_into("<I", c, 0, opcode & 0xFF)      # CID=0, FUSE=0
    struct.pack_into("<I", c, 4, nsid & 0xFFFFFFFF)
    for i, v in enumerate((cdw10, cdw11, cdw12, cdw13, cdw14, cdw15)):
        struct.pack_into("<I", c, 40 + 4 * i, v & 0xFFFFFFFF)
    return bytes(c)


def _spc_buffer(opcode, nsid, cdw, data_in=None, data_out=None, timeout_ms=30000):
    """构造 STORAGE_PROTOCOL_COMMAND + 64B Command + 数据缓冲区."""
    data_len = len(data_out) if data_out is not None else (data_in or 0)
    total = SPC_DATA_OFFSET + data_len
    b = bytearray(total)
    struct.pack_into("<I", b, 0, STORAGE_PROTOCOL_STRUCTURE_VERSION)  # Version
    struct.pack_into("<I", b, 4, SPC_HEADER_LEN)                       # Length
    struct.pack_into("<I", b, 8, PROTOCOL_TYPE_NVME)                    # ProtocolType
    struct.pack_into("<I", b, 12, 0)                                    # Flags (设备级)
    # 16 ReturnStatus / 20 ErrorCode: 输出, 置 0
    struct.pack_into("<I", b, 24, NVME_COMMAND_LEN)                     # CommandLength
    struct.pack_into("<I", b, 28, 0)                                    # ErrorInfoLength
    struct.pack_into("<I", b, 40, max(1, timeout_ms // 1000))          # TimeOutValue(秒)
    struct.pack_into("<I", b, 44, 0)                                    # ErrorInfoOffset
    if data_out is not None:
        struct.pack_into("<I", b, 32, len(data_out))                    # DataToDeviceTransferLength
        struct.pack_into("<I", b, 48, SPC_DATA_OFFSET)                  # DataToDeviceBufferOffset
        b[SPC_DATA_OFFSET:SPC_DATA_OFFSET + len(data_out)] = data_out
    elif data_in:
        struct.pack_into("<I", b, 36, data_in)                          # DataFromDeviceTransferLength
        struct.pack_into("<I", b, 52, SPC_DATA_OFFSET)                  # DataFromDeviceBufferOffset
    b[SPC_HEADER_LEN:SPC_HEADER_LEN + NVME_COMMAND_LEN] = _nvme_command(
        opcode, nsid, *cdw)
    return bytes(b)


class WinNvmeAdmin:
    """直连 NVMe (M.2/PCIe, BusType=Nvme) 的 admin 命令直通.

    用 IOCTL_STORAGE_PROTOCOL_COMMAND + STORAGE_PROTOCOL_COMMAND(Win10+)。

    【未验证 / 已知限制】MS 文档明确: StorNVMe.sys 会拦截 Command Effects Log
    未登记的命令; 厂商日志 0xC0、FW Download/Commit 能否放行取决于具体驱动/固件。
    必须在 Windows 实机用只读 Identify/Get Log 确认; 若不通, 请改用 USB 硬盘盒通道。
    """

    def __init__(self, path: str):
        _require_windows()
        self.path = path
        self.h = _open_handle(path)
        if not self.h:
            raise fc.NvmeError(
                "打开 %s 失败; 需以管理员身份运行, 且设备存在." % path)

    def close(self):
        if self.h:
            _close_handle(self.h)
            self.h = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _admin(self, opcode, cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw14=0,
               cdw15=0, nsid=0, data_in=None, data_out=None, timeout_ms=30000):
        cdw = (cdw10, cdw11, cdw12, cdw13, cdw14, cdw15)
        buf = _spc_buffer(opcode, nsid, cdw, data_in, data_out, timeout_ms)
        out = _ioctl(self.h, IOCTL_STORAGE_PROTOCOL_COMMAND, buf, len(buf))
        status = struct.unpack_from("<I", out, 16)[0]   # ReturnStatus
        if status != 1:  # STORAGE_PROTOCOL_STATUS_SUCCESS
            err = struct.unpack_from("<I", out, 20)[0]
            raise fc.NvmeError(
                "NVMe 命令 0x%02X 失败: ReturnStatus=%s(%d) ErrorCode=0x%08X"
                % (opcode, STORAGE_PROTOCOL_STATUS.get(status, "?"), status, err))
        if data_in:
            return 0, out[SPC_DATA_OFFSET:SPC_DATA_OFFSET + data_in]
        return 0, b""

    def identify(self, cns=1) -> bytes:
        _, buf = self._admin(fc.ADMIN_IDENTIFY, cdw10=cns,
                             data_in=4096, timeout_ms=10000)
        return buf

    def get_log(self, lid: int, size: int = fc.HEADER_SIZE, nsid: int = 0) -> bytes:
        numd = (size >> 2) - 1
        cdw10 = (lid & 0xFF) | ((numd & 0xFFFF) << 16)
        cdw11 = (numd >> 16) & 0xFFFF
        _, buf = self._admin(fc.ADMIN_GET_LOG_PAGE, cdw10=cdw10, cdw11=cdw11,
                             nsid=nsid, data_in=size, timeout_ms=10000)
        return buf

    def fw_download(self, byte_offset: int, chunk: bytes):
        if byte_offset % 4 or len(chunk) % 4:
            raise ValueError("FW Download 的 offset/length 必须是 4 字节对齐")
        self._admin(fc.ADMIN_FW_DOWNLOAD, cdw10=(len(chunk) >> 2) - 1,
                    cdw11=byte_offset >> 2, data_out=chunk, timeout_ms=60000)

    def fw_commit(self, slot: int, action: int):
        self._admin(fc.ADMIN_FW_COMMIT,
                    cdw10=(slot & 0x7) | ((action & 0x7) << 3),
                    timeout_ms=180000)

    def reset(self):
        raise fc.NvmeError("Windows 上没有通用的 NVMe 控制器复位接口; 请断电重启")

    def fw_slot_log(self) -> bytes:
        return self.get_log(fc.LID_FW_SLOT, 512)


def open_device(path: str, transport: str = "auto"):
    """按决策选传输; 与 Linux 版 open_device 同签名 (flashcore 的调用方无需改)."""
    if transport == "jmicron":
        return WinJmicronScsi(path)
    if transport == "nvme":
        return WinNvmeAdmin(path)
    # auto: 依据该 PhysicalDrive 的 BusType
    h = _open_handle(path, query_only=True)
    if not h:
        raise fc.NvmeError("无法打开 %s 判定总线类型" % path)
    try:
        bus, _, _, _, _ = _query_descriptor(h)
    finally:
        _close_handle(h)
    if bus == BUS_TYPE_NVME:
        return WinNvmeAdmin(path)
    return WinJmicronScsi(path)

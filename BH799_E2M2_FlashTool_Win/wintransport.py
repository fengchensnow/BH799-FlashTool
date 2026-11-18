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
      读 (Identify / Get Log, 含厂商 0xC0):
        IOCTL_STORAGE_QUERY_PROPERTY + STORAGE_PROTOCOL_SPECIFIC_DATA
      写 (FW Download / Commit):
        IOCTL_STORAGE_FIRMWARE_DOWNLOAD / IOCTL_STORAGE_FIRMWARE_ACTIVATE

【为什么不用 IOCTL_STORAGE_PROTOCOL_COMMAND】
  StorNVMe 只允许厂商自定义 opcode 透传; 标准 admin 命令 (Identify 0x06 /
  Get Log 0x02 / FW Download 0x11 / Commit 0x10) 会被 StorNVMe 以
  STOR_STATUS_INVALID_PARAMETER (0xC1000006) 拒绝。实测本机 (Win10 19045,
  stornvme) 厂商 opcode 能透传, 标准 opcode 全部被拒, 故改用上面两条官方通路。

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
IOCTL_STORAGE_FIRMWARE_GET_INFO = CTL_CODE(
    FILE_DEVICE_MASS_STORAGE, 0x0700, METHOD_BUFFERED, FILE_ANY_ACCESS)       # 0x002D1C00
IOCTL_STORAGE_FIRMWARE_DOWNLOAD = CTL_CODE(
    FILE_DEVICE_MASS_STORAGE, 0x0701, METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS)                                     # 0x002DDC04
IOCTL_STORAGE_FIRMWARE_ACTIVATE = CTL_CODE(
    FILE_DEVICE_MASS_STORAGE, 0x0702, METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS)                                     # 0x002DDC08
IOCTL_SCSI_PASS_THROUGH_DIRECT = CTL_CODE(
    FILE_DEVICE_CONTROLLER, 0x0405, METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS)                                     # 0x0004D014
IOCTL_SCSI_MINIPORT = CTL_CODE(
    FILE_DEVICE_CONTROLLER, 0x0402, METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS)                                     # 0x0004D008
IOCTL_DISK_GET_LENGTH_INFO = CTL_CODE(
    FILE_DEVICE_DISK, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)             # 0x0007405C
# GET_LENGTH_INFO 含 FILE_READ_ACCESS, 用 dwDesiredAccess=0 的枚举句柄会被
# I/O 管理器拒绝; 下面这个 IOCTL 是 FILE_ANY_ACCESS, 作为容量查询的 fallback.
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = CTL_CODE(
    FILE_DEVICE_DISK, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS)             # 0x000700A0
DISK_GEOMETRY_LEN = 24          # DISK_GEOMETRY 大小; DISK_GEOMETRY_EX.DiskSize 紧随其后

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

# STORAGE_PROPERTY_QUERY / STORAGE_PROTOCOL_SPECIFIC_DATA
STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY = 49   # StorageAdapterProtocolSpecificProperty
STORAGE_PROPERTY_STANDARD_QUERY = 0               # PropertyStandardQuery
PROTOCOL_TYPE_NVME = 3                            # ProtocolTypeNvme
NVME_DATA_TYPE_IDENTIFY = 1                       # NVMeDataTypeIdentify
NVME_DATA_TYPE_LOG_PAGE = 2                       # NVMeDataTypeLogPage
# 微软示例把 STORAGE_PROTOCOL_SPECIFIC_DATA 放在 AdditionalParameters (偏移 8),
# 不是 sizeof(STORAGE_PROPERTY_QUERY)=12; 实测偏移 8 可用, 12 报 ERROR_INVALID_PARAMETER.
SPD_OFFSET = 8
SPD_LEN = 40

# STORAGE_HW_FIRMWARE_DOWNLOAD / ACTIVATE
# Version 不是 sizeof: classpnp 要求 >= 0x28(40); 结构头仍是 32B, 镜像紧跟其后.
FW_DOWNLOAD_VERSION = 0x28
FW_DOWNLOAD_HDR_LEN = 32
FW_DOWNLOAD_FLAG_CONTROLLER = 0x1       # 目标为控制器; 同时使 classpnp 对齐要求降为 1
FW_DOWNLOAD_FLAG_LAST_SEGMENT = 0x2
FW_DOWNLOAD_FLAG_FIRST_SEGMENT = 0x4
FW_ACTIVATE_HDR_LEN = 16
FW_DOWNLOAD_SECTOR = 512                # 末尾短块按 512 补齐由传输层处理

# SCSI_PASS_THROUGH_DIRECT.DataIn
SCSI_IOCTL_DATA_OUT = 0
SCSI_IOCTL_DATA_IN = 1
SCSI_IOCTL_DATA_UNSPECIFIED = 2

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
        "SPD_OFFSET": SPD_OFFSET,
        "SPD_LEN": SPD_LEN,
        "FW_DOWNLOAD_HDR_LEN": FW_DOWNLOAD_HDR_LEN,
        "FW_ACTIVATE_HDR_LEN": FW_ACTIVATE_HDR_LEN,
        "DISK_GEOMETRY_LEN": DISK_GEOMETRY_LEN,
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


def _open_handle(path: str, query_only: bool = False, read_access: bool = False):
    """打开 \\\\.\\PhysicalDriveN; 返回句柄或 None.

    query_only=True   -> dwDesiredAccess=0: FILE_ANY_ACCESS 查询, 普通用户可枚举.
    read_access=True -> dwDesiredAccess=GENERIC_READ: CTL_CODE 含 FILE_READ_ACCESS
                          的 IOCTL 需要此权限 (如 IOCTL_DISK_GET_LENGTH_INFO).
    默认              -> GENERIC_READ|GENERIC_WRITE: 实际发命令, 需管理员.
    """
    if query_only:
        access = 0
    elif read_access:
        access = GENERIC_READ
    else:
        access = GENERIC_READ | GENERIC_WRITE
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
    if out_len:
        ob = (ctypes.c_ubyte * out_len)()
        ob_ptr = ctypes.cast(ob, ctypes.c_void_p)
    else:
        ob, ob_ptr = None, None
    returned = ctypes.c_uint32(0)
    ok = _k32.DeviceIoControl(
        h, code,
        ctypes.cast(ib, ctypes.c_void_p), len(in_bytes),
        ob_ptr, out_len,
        ctypes.byref(returned), None)
    if not ok:
        raise fc.NvmeError("DeviceIoControl 0x%08X 失败 (GetLastError=%d)"
                           % (code, ctypes.get_last_error()))
    return bytes(bytearray(ob))[:out_len] if ob is not None else b""


# --------------------------------------------------------------------------
# 设备枚举: IOCTL_STORAGE_QUERY_PROPERTY + 容量 (GET_LENGTH_INFO / GEOMETRY_EX)
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
    """容量字节数: GET_LENGTH_INFO -> GET_DRIVE_GEOMETRY_EX(DiskSize@24).

    任一 IOCTL 失败或返回 0 都继续尝试下一个; 全部失败抛 NvmeError,
    由 list_disks 决定提权重试 / 打印诊断, 绝不再静默当成 0 容量.
    """
    errs = []
    for code, out_len, off in (
            (IOCTL_DISK_GET_LENGTH_INFO, 8, 0),
            (IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 256, DISK_GEOMETRY_LEN)):
        try:
            raw = _ioctl(h, code, b"", out_len)
            n = struct.unpack_from("<Q", raw, off)[0]
            if n:
                return n
            errs.append("0x%08X 返回 0" % code)
        except fc.NvmeError as e:
            errs.append("0x%08X: %s" % (code, e))
    raise fc.NvmeError("容量查询失败 (%s)" % "; ".join(errs))


def _query_capacity(path: str, h) -> tuple[int, str | None]:
    """容量查询: 先枚举句柄(access=0), 失败再用 GENERIC_READ 句柄重试."""
    err1 = None
    try:
        return _disk_length(h), None
    except fc.NvmeError as e:
        err1 = str(e)
    h2 = _open_handle(path, read_access=True)
    if not h2:
        return 0, "%s; GENERIC_READ 句柄打开失败" % err1
    try:
        return _disk_length(h2), None
    except fc.NvmeError as e:
        return 0, "%s; GENERIC_READ 重试: %s" % (err1, e)
    finally:
        _close_handle(h2)


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
            size, size_err = _query_capacity(path, h)
        finally:
            _close_handle(h)
        if size_err:
            print("  [容量] %s 读取失败: %s" % (path, size_err))
        disks.append({
            "path": path,
            "name": "PhysicalDrive%d" % n,
            "index": n,
            "size_bytes": size,
            "size_error": size_err,
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
        # 与 Linux 版一致: SCSI 数据段按 512B 补齐, 但 NUMD 仍按原始 chunk 长度.
        # 末尾 800B 块不补齐时 JMS583 会拒绝 data-out.
        xfer = chunk
        if len(xfer) % FW_DOWNLOAD_SECTOR:
            xfer += b"\xFF" * (FW_DOWNLOAD_SECTOR - len(xfer) % FW_DOWNLOAD_SECTOR)
        self._admin(fc.ADMIN_FW_DOWNLOAD, cdw10=(len(chunk) >> 2) - 1,
                    cdw11=byte_offset >> 2, data_out=xfer, timeout_ms=60000)

    def fw_commit(self, slot: int, action: int):
        self._admin(fc.ADMIN_FW_COMMIT,
                    cdw10=(slot & 0x7) | ((action & 0x7) << 3),
                    timeout_ms=180000)

    def reset(self):
        raise fc.NvmeError("USB 透传没有控制器复位命令; 请拔插硬盘盒或断电重启")

    def fw_slot_log(self) -> bytes:
        return self.get_log(fc.LID_FW_SLOT, 512)


# --------------------------------------------------------------------------
# 直连 NVMe: 读走 QUERY_PROPERTY, 写走 STORAGE_FIRMWARE_* (Win10+, stornvme.sys)
# --------------------------------------------------------------------------


def _protocol_query_buffer(data_type, request_value, request_sub_value, data_len):
    """IOCTL_STORAGE_QUERY_PROPERTY 输入: STORAGE_PROPERTY_QUERY + SPD + 数据区.

    SPD 放在 AdditionalParameters (偏移 8); ProtocolDataOffset 相对 SPD 起点.
    """
    total = SPD_OFFSET + SPD_LEN + data_len
    b = bytearray(total)
    struct.pack_into("<II", b, 0, STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY,
                     STORAGE_PROPERTY_STANDARD_QUERY)
    struct.pack_into("<IIIIII", b, SPD_OFFSET, PROTOCOL_TYPE_NVME, data_type,
                     request_value, request_sub_value, SPD_LEN, data_len)
    return bytes(b)


def _fw_download_buffer(byte_offset, chunk,
                        flags=FW_DOWNLOAD_FLAG_CONTROLLER):
    """STORAGE_HW_FIRMWARE_DOWNLOAD: Version=0x28, ImageBuffer 紧跟 32B 头."""
    b = bytearray(FW_DOWNLOAD_HDR_LEN + len(chunk))
    struct.pack_into("<III", b, 0, FW_DOWNLOAD_VERSION,
                     FW_DOWNLOAD_HDR_LEN + len(chunk), flags)
    b[12] = 0                                    # Slot: Windows 只暴露 0
    struct.pack_into("<QQ", b, 16, byte_offset, len(chunk))
    b[FW_DOWNLOAD_HDR_LEN:] = chunk
    return bytes(b)


def _fw_activate_buffer():
    """STORAGE_HW_FIRMWARE_ACTIVATE: Version=16, Size=16, Flags=CONTROLLER, Slot=0.

    Flags 必须带 CONTROLLER: classpnp 对带该标志的请求走 IofCallDriver 转发给
    StorNVMe; 不带则构造 SRB (0xF3B) 走 classpnp 自己的路径, NVMe 下实测
    ACTIVATE 返回 1117 且 SPI 未被写入.
    """
    return struct.pack("<IIIB3s", FW_ACTIVATE_HDR_LEN, FW_ACTIVATE_HDR_LEN,
                       FW_DOWNLOAD_FLAG_CONTROLLER, 0, b"\x00\x00\x00")


def prepare_image_for_nvme(data: bytes) -> bytes:
    """把镜像补齐到 4096 边界, 供 Windows 官方固件 IOCTL 使用.

    classpnp/StorNVMe 要求每次 FW Download 的 BufferSize 为 4096 的倍数
    (CONTROLLER 可放宽, 但末尾短块实测不稳定), 而 BH799 固件在 commit 时
    校验「镜像头 DWORD0 长度 + 0x400 == 下载总长」. 因此末尾补 0x00 到
    4K 边界并同步改 DWORD0 (长度 + 奇偶).

    补的是 body 末尾, 即固件 RAM 布局里的 .bss 区; 启动时 .bss 本来就要
    清零, 补 0x00 与启动语义一致; 0x00 对 DWORD31 XOR 无贡献, 校验值不变
    (仍重算一次以保证自洽).
    """
    pad = (-len(data)) % 4096
    if pad == 0:
        return data
    if len(data) < fc.HEADER_SIZE:
        raise fc.ImageError("镜像小于 1KB, 无法补齐: %d B" % len(data))
    out = bytearray(data) + b"\x00" * pad
    body = len(out) - fc.HEADER_SIZE
    low3 = body.to_bytes(4, "big")[1:]                 # 低 24 位
    out[0:4] = bytes([low3[0] ^ low3[1] ^ low3[2] ^ 0xFF]) + low3
    chk = fc.xor_words(bytes(out[fc.HEADER_SIZE:fc.FLASH_SIZE]))
    out[0x7C:0x80] = chk.to_bytes(4, "big")
    return bytes(out)


class WinNvmeAdmin:
    """直连 NVMe (M.2/PCIe, BusType=Nvme).

    读: IOCTL_STORAGE_QUERY_PROPERTY (StorNVMe 官方查询接口, 支持 Identify/
        Get Log Page, 含厂商 LID 0xC0; 免管理员也可读).
    写: IOCTL_STORAGE_FIRMWARE_DOWNLOAD / _ACTIVATE (官方固件升级 IOCTL).

    IOCTL_STORAGE_PROTOCOL_COMMAND 只放行厂商自定义 opcode; 标准 admin 命令
    (0x06/0x02/0x10/0x11) 会被 StorNVMe 以 STOR_STATUS_INVALID_PARAMETER
    (0xC1000006) 拒绝, 故本通道不使用它.
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

    def _query(self, data_type, request_value, request_sub_value, data_len):
        total = SPD_OFFSET + SPD_LEN + data_len
        out = _ioctl(self.h, IOCTL_STORAGE_QUERY_PROPERTY,
                     _protocol_query_buffer(data_type, request_value,
                                            request_sub_value, data_len),
                     total)
        got_off, got_len = struct.unpack_from("<II", out, SPD_OFFSET + 16)
        start = SPD_OFFSET + got_off
        payload = out[start:start + min(got_len, data_len)]
        if len(payload) < data_len:
            raise fc.NvmeError(
                "协议查询返回不足: 需要 %d B, 实得 %d B (off=%d len=%d)"
                % (data_len, len(payload), got_off, got_len))
        return payload

    def identify(self, cns=1) -> bytes:
        return self._query(NVME_DATA_TYPE_IDENTIFY, cns, 0, 4096)

    def get_log(self, lid: int, size: int = fc.HEADER_SIZE, nsid: int = 0) -> bytes:
        return self._query(NVME_DATA_TYPE_LOG_PAGE, lid & 0xFF, nsid, size)

    def fw_download(self, byte_offset: int, chunk: bytes):
        if byte_offset % 4 or len(chunk) % 4:
            raise ValueError("FW Download 的 offset/length 必须是 4 字节对齐")
        # 末尾短块 (<4096) 带上 FIRST|LAST: classpnp 默认要求 BufferSize 按
        # ImagePayloadAlignment(4096) 对齐; CONTROLLER 可放宽, 但设备侧对短块
        # 仍会报 IO_DEVICE_ERROR, 而 FIRST|LAST 让驱动按单段处理, 实测 800B 可过.
        flags = FW_DOWNLOAD_FLAG_CONTROLLER
        if len(chunk) < fc.CHUNK_MAX:
            flags |= FW_DOWNLOAD_FLAG_FIRST_SEGMENT | FW_DOWNLOAD_FLAG_LAST_SEGMENT
        _ioctl(self.h, IOCTL_STORAGE_FIRMWARE_DOWNLOAD,
               _fw_download_buffer(byte_offset, chunk, flags), 0)

    def fw_commit(self, slot: int, action: int):
        if action != 1:
            raise fc.NvmeError("Windows 官方固件通道只支持 action=1 (替换并激活)")
        # Windows 只暴露 slot 0 (STORAGE_HW_FIRMWARE_INFO.SlotCount=1).
        # BH799 固件在 commit slot=0 时使用镜像头 DWORD32 高 4 位的槽位
        # (本项目镜像为 3=SPI Flash), 不会写错介质.
        try:
            _ioctl(self.h, IOCTL_STORAGE_FIRMWARE_ACTIVATE,
                   _fw_activate_buffer(), 0)
        except fc.NvmeError as e:
            # 1MB SPI 擦写约 2~3s, 可能超过 StorNVMe 默认 SRB 超时; 实测
            # ACTIVATE 返回 1117 后设备仍正常, 且 SPI 可能已写完.
            if "GetLastError=1117" in str(e):
                raise fc.NvmeError(
                    "ACTIVATE 返回 1117 (设备忙/超时). SPI 写入可能已完成; "
                    "不要重试. 请断电 10 秒后上电, 再用菜单 1 检查 0xC0 头.") from None
            raise

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

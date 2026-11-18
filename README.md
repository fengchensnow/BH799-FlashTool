# BH799 eMMC→NVMe 桥片固件刷写工具

针对 **BH799BB（eMMC→NVMe 桥片）**主控的SteamDeck 64G硬盘的固件刷写与设备信息工具，提供 Linux 与 Windows 两个版本。从咸鱼买的SteamDeck 64G主控板焊上颗粒但是没SMART，总觉得不爽。根据[cursorhu博客中相关的内容](https://www.cursorhu.xyz/2026/03/16/NVMe-eMMC-Bridge%E8%8A%AF%E7%89%87%E5%9B%BA%E4%BB%B6_09_Windows%E5%B9%B3%E5%8F%B0NVMe%E8%AE%BE%E5%A4%87%E5%9B%BA%E4%BB%B6%E5%8D%87%E7%BA%A7%E5%B7%A5%E5%85%B7/)，交由ai帮助完成。固件来自SteamDeck 64G和Dell/HP BH799主控硬盘。

- 纯 Python 3 标准库实现，无第三方运行时依赖
- 两个版本共用同一套镜像解析 / 拼装 / 解码逻辑，仅设备枚举与传输层不同
- 只读写 NVMe Admin 命令（Identify / Get Log Page / FW Download / FW Commit），不修改固件代码
- `FIRMWARE/` 里的 4 个 `.bin` 是**预置数据文件**，工具不现场生成补丁

> ⚠️ **刷写有风险**：中途失败或掉电会变砖，只能用 SPI 编程器恢复。刷前先用菜单 2 备份设备信息。

## 使用说明

### 从 SteamDeck 64G 硬盘升级（GD → XM）

#### 重要事情说三遍：

### 备份完重要数据再刷

### 备份完重要数据再刷

### 备份完重要数据再刷

### 仅限JMS583硬盘盒和nvme直插

懒得测跨版本刷的影响了

下载release，管理员/sudo 运行FlashTool

SteamDeck 64G 原盘出厂为 **GD 固件**。升级到 XM 固件有两条路径，二选一。不懂的地方回车就行

**路径 A — 先刷 `blk1` 中间固件，再刷回 XM（块 1，`0xCD=0`）**

1. 菜单 3 刷入 `blk1` 中间固件（`XM25QH80B_blk1_bridge.bin`）
2. **完整断电 → 再上电一次**（512B 全 0 合法记录在此步写入，不能省）
3. 断电 → 菜单 4 刷回 XM 最终固件（SMART 槽位选 `blk1`）→ 上电

原盘块 1 存的是 GD 的 namespace / 配置结构，XM 会把它当 SMART 记录解析，出现「写入量≈容量」一类的异常值；中间固件先把块 1 清成全 0 记录，最终 XM 便从 0 正常累计。中间固件与最终固件同为 `0xCD=0`，满足同源规则。

**路径 B — 直接刷 `blk3` 的 XM 固件（块 3，`0xCD=1`）**

菜单 4 选 XM 底包、SMART 槽位选 `blk3` 直接刷入即可（相当于把头 `0xCD` 一个字节置 1，客户参数区不用重算校验）。它让 XM 读空的块 3、避开块 1 的 GD 残留，**前提是块 3 当前为空**；若块 3 已被写脏，绕过去不会清掉历史，需改走路径 A。

> 注意：`blk3` 中间固件（`XM25QH80B_blk3_bridge.bin`）与「`blk3` 的 XM 最终固件」不是一回事。路径 B 直接刷最终固件，不需要先刷 bridge；bridge 只在需要把块本身清 0 时才用。

**中间固件同时就是 SMART 信息清 0 的手段**：菜单 3 的 `blk1` / `blk3` 会把当前块写成 512B 全 0 合法记录，之后计数从 0 正常累计（不是让上报恒 0）。完整机制与同源规则见 `doc/SMART_BRIDGE_FIRMWARE.md`。

### 双贴 eMMC：数据布局与硬件前提

- **数据布局**：原始 GD 固件双贴（正面 + 背部各一颗 eMMC）按 **JBOD** 组织；XM 固件双贴改用 **4M 交织**布局存储数据。两者布局不同，GD 与 XM 互刷会改变盘上数据的组织方式，升级 / 换固件前请**备份用户数据**。
- **背部加装 eMMC**：背部增加 eMMC 时需要补齐 **DCDC 与电容**；不然速率只有正面一半左右。

## 目录结构

```
.
├── BH799_E2M2_FlashTool/           Linux 版
│   ├── flashtool.py                CLI / 6 项菜单 / 镜像拼装 / 设备枚举
│   ├── flashcore.py                镜像格式、校验、传输层、日志解码
│   └── FIRMWARE/                   4 个固件底包
├── BH799_E2M2_FlashTool_Win/       Windows 版
│   ├── flashtool.py                CLI / 6 项菜单（与 Linux 版一致）
│   ├── flashcore.py                纯逻辑核心（与 Linux 版共用）
│   ├── wintransport.py             DeviceIoControl 设备层
│   └── FIRMWARE/                   同上 4 个底包
├── doc/                            固件格式与行为说明（见下方索引）
└── .gitignore
```

所有相对路径（`FIRMWARE/`、`backup/`、导出镜像）以各自工具目录为根。

## 快速开始

### Linux

```bash
cd BH799_E2M2_FlashTool
sudo python3 flashtool.py              # 交互菜单（探测/刷写需要 root）
python3 flashtool.py --enumerate       # 只看设备枚举结果（不需 root）
python3 flashtool.py --selftest        # 离线自检，不接触设备
python3 flashtool.py --dry-run         # 交互菜单，刷写只模拟不落盘
```

### Windows

以**管理员身份**打开命令提示符（探测与刷写需要管理员；枚举和离线功能不需要）：

```powershell
cd BH799_E2M2_FlashTool_Win
python flashtool.py
python flashtool.py --enumerate
python flashtool.py --selftest
```

> Windows 直连 NVMe 使用两条官方通路：读（Identify / Get Log，含厂商 `0xC0`）走
> `IOCTL_STORAGE_QUERY_PROPERTY`，写（FW Download / Commit）走
> `IOCTL_STORAGE_FIRMWARE_DOWNLOAD` / `IOCTL_STORAGE_FIRMWARE_ACTIVATE`。
> StorNVMe 只允许厂商自定义 opcode 通过 `IOCTL_STORAGE_PROTOCOL_COMMAND`，标准
> admin 命令会被拒绝（`STOR_STATUS_INVALID_PARAMETER`），本版不使用该路径。
> 固件下载的 `Version` 必须是 `0x28`，且 DOWNLOAD/ACTIVATE 都要带
> `STORAGE_HW_FIRMWARE_REQUEST_FLAG_CONTROLLER`；ACTIVATE 不带该标志会走 classpnp
> 的 SRB 路径，实测返回 1117 且 SPI 不写入。
> 直连 NVMe 刷写时，镜像会在末尾补 `0x00` 到 4096 边界（Windows 官方固件 IOCTL
> 的对齐要求；补的是 `.bss` 区，启动时本来就要清零），DWORD0 长度/奇偶同步更新。
> 该链路已在 Win10 19045 + BH799 实机验证：刷写后 `0xC0` 头 DWORD0 变为补齐后的
> 长度，SN/型号/UART/厂商覆盖串等客户参数保持不变。ACTIVATE 若仍返回 `1117`，
> **不要重试**；断电 10 秒后上电，再用菜单 1 检查 `0xC0` 头。

启动后：列出磁盘 → 选择目标 → 按传输类型决策 → 只读探测 → **自动列出设备信息** → 进入菜单。主界面按 `r` 重选设备、`0` 退出，选选项后自动清屏，任意处 Ctrl-C 优雅退出。

## 设备决策

| 传输类型 | Linux (`TRAN`) | Windows (`BusType`) | 通道 |
|---|---|---|---|
| USB 硬盘盒 | `usb` | `Usb` | JMicron SCSI / SG_IO 透传 |
| 直连 NVMe | `nvme` | `Nvme` | 读 `QUERY_PROPERTY` / 写 `FIRMWARE_*` |
| 其它 / 未知 | `sata` 等 | `Sata` 等 | 拒绝 |

Linux 版另显示 VID:PID 与驱动（`152d:f583/uas`）；Windows 纯 `DeviceIoControl` 取不到 USB VID/PID，用 `BusType=Usb` 判定硬盘盒。

## 6 项菜单

| 项 | 功能 |
|---|---|
| 1 | 查看设备信息 — Identify、FW 槽位、SMART 健康日志（LID 0x02）、1KB 客户参数区、`0xCD` SMART 块、`0x148` 掩码、`0x105` UART/LED |
| 2 | 备份设备信息 — 1KB 头存到 `./backup/`（可自定义保存名称，回车用默认 `SN_时间戳`；**不是整片固件备份**，固件 body 在线读不到） |
| 3 | 刷入中间固件 — 选 `blk1` / `blk3`，处理 SMART 数据异常或清 0；刷入时自动保留当前设备 SN/MN（含动态拼装配置） |
| 4 | 在线刷入向导 — 底包 → 信息来源 → SMART 槽位 → UART/LED → 刷入（默认）或导出 |
| 5 | 自定义刷入固件 — 列出目录内 `.bin` 或输入路径，校验后刷入 |
| 6 | 查看固件 / 备份信息 — 打印完整镜像报告或 1KB 头摘要 |

菜单 4 的信息来源三选一：**保持当前信息**（在线设备 1KB 头）、**导入备份信息**（从 `./backup/` 读 1KB 头）、**自定义信息**（静态型号 ≤40B 或动态拼装，`0x154` 覆盖串 ≤7B，自定义 SN ≤20B）。动作默认刷入，选 `1` 才是导出。

## 固件底包

两个工具目录的 `FIRMWARE/` 内容一致：

| 文件 | 大小 | 说明 |
|---|---|---|
| `GD25Q80@USON8.bin` | 1,048,576 B | GD 底包，整机客户版 |
| `XM25QH80B@SOIC8.BIN` | 1,048,656 B | XM 底包，工程版（1MB + 80B `-Configuration-` 编程器尾，刷写/校验前裁掉） |
| `XM25QH80B_blk1_bridge.bin` | 1,048,656 B | 中间固件，`0xCD=0` / 块 1 |
| `XM25QH80B_blk3_bridge.bin` | 1,048,576 B | 中间固件，`0xCD=1` / 块 3 |

程序校验这 4 个文件的 SHA-256，不符即拒绝使用。

## 规则速查

完整说明见 `doc/`。要点：

- **镜像**：1KB 头 = 256 个大端 u32；body 从 `0x400` 起映射到 `0x40000000`。DWORD0 低 24 位 = body 长度且四字节异或为 `0xFF`；DWORD31（文件 `0x7C`）= `0x400..0x100000` 大端 u32 XOR（不含 80B 尾）。客户参数区 `0x000-0x3FF` 不在校验范围内，改 SN / 型号 / 掩码 / `0xCD` / `0x105` 无需重算校验。
- **型号动态拼装**：`0x120` 全 0 时生效，固定掩码 `0xBC`；按位 7→0 追加 VEN + MID + PNM + FWVER + CAP，分隔符 `-`，总长 >40 整体放弃。位名以反汇编为准：`0x80=VEN`、`0x40=OEM`、`0x20=MID`、`0x10=PNM`、`0x08=FWVER`、`0x04=CAP`、`0x01=DISK`（这四位顺序容易记反，按名字增删字段时务必核对）。`0x144` 不是字段；`0x148` 才是掩码（XM `0xBC` / GD `0xBD`）。
- **`0x154` 覆盖串**：固件按 eMMC CID 自动识别 13 家厂商，命中时留空；表外厂商才需自定义。写入值必须自带 `-`（固件不自动补），输入 ≤7B + `-` = 8B——紧随其后的 `0x15C` 是被使用的字段，不可越界覆盖。
- **SMART**：记录是 eMMC 保留区一个 512B 块（不在 SPI Flash，跨刷固件保留，无 magic/CRC）。`0xCD` bit0 选块：0=块 1(BLOCK2)、1=块 3(BLOCK4)，被 12 处代码读取。清 0 三步：刷入**与最终固件 `0xCD` 同源**的中间固件 → 完整断电再上电（全 0 记录在此步写入）→ 断电刷回最终固件。升级时的具体路线见上文「使用说明」。
- **UART/LED**：`0x105` bits7:6 = `0x40` UART 115200 / `0x80` LED；`0x107` bit7 决定输出电平。GPIO0 物理接 LED 时切 UART 不会有串口输出。
- **eMMC 版本**：固件无版本检查，但主机数据通路只实现了 CMDQ（CMD44/45/46/47），非 CQ 通路是死代码；eMMC 5.0 卡可以初始化、可以 Identify，实际 IO 会挂死。本项目已停止固件二进制改造，需要 5.0 支持请找厂商要 non-CQ 固件或换 5.1 颗粒。

## 打包（Nuitka）

两个版本都用 `--standalone`，数据文件必须显式包含：

```bash
# Linux（需 patchelf）
python -m nuitka --standalone '--include-data-files=FIRMWARE/*=FIRMWARE/' \
  --output-dir=dist flashtool.py
```

```powershell
# Windows（需 MinGW-w64 或 MSVC；不需要 patchelf）
python -m nuitka --standalone "--include-data-files=FIRMWARE/*=FIRMWARE/" `
  --output-dir=dist flashtool.py
```

要点：

- `flashcore.py`（Windows 版还有 `wintransport.py`）由静态 `import` 自动编入，无需手动声明。
- 必须用 `--include-data-files='FIRMWARE/*=FIRMWARE/'`；`--include-data-dir` 会漏掉小写 `.bin` 文件。
- 分发时复制**整个** `dist/flashtool.dist/` 目录；`backup/` 与导出文件生成在该目录内。
- 不要用 `--onefile`：输出文件会写进临时解压目录，退出即丢。
- 打包后先跑 `flashtool.bin --selftest`（Windows 为 `flashtool.exe --selftest`）与 `--enumerate` 验证。

## 文档索引

| 文件 | 内容 |
|---|---|
| `doc/model_name_dynamic_assembly.md` | 型号动态拼装的触发条件、位掩码、拼接顺序、字段来源 |
| `doc/gpio0_uart_led_mode.md` | GPIO0 UART/LED 模式、`0x105`/`0x107`、修改前提 |
| `doc/FIRMWARE_ANALYSIS.md` | 固件镜像结构、校验、两版差异、客户参数区、在线升级路径 |
| `doc/SMART_BRIDGE_FIRMWARE.md` | SMART 持久化机制、中间固件同源规则、刷写流程 |

## 安全与状态

- 本工具不现场生成固件补丁（不改 body / 不重算校验，仅在客户参数区回写 SN/MN/mask 等字段）；`FIRMWARE/*.bin` 仅作数据文件，改动前请自行核对 SHA-256。
- 刷写中途失败 / 掉电会变砖，只能用 SPI 编程器恢复；刷前先备份设备信息。
- Windows NVMe 直连通道已在 BH799 实机验证；直连刷写会自动做 4K 末尾补齐（见上文）。
- Windows JMS583 通道与 Linux 版一致：FW Download 的 SCSI 数据段按 512B 补齐，
  NUMD 仍按原始长度，末尾 800B 块可正常下发。


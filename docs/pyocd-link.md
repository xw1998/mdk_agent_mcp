# pyOCD 链路（批次114）

pyOCD 是除 Keil（UVSOCK）与 OpenOCD 之外的**第三条调试链路**：纯 Python，进程内
`Session`，`pip install pyocd` 之后 CMSIS-DAP / J-Link / ST-Link 都能连，烧录走
CMSIS-Pack 里的 FLM 算法，不需要 Keil 安装。

## 为什么加这一层

| 链路 | 前提 | 断在哪 |
|---|---|---|
| Keil / UVSOCK | 装 Keil、uVision 开着、UVSOCK 在监听 | CI / 无界面机器、没买 Keil 的机器直接断 |
| OpenOCD（`ocd_*`） | 有发行版 + interface/target cfg | 必须独占探针并常驻外部进程，输出要按人看的文本整形 |
| pyOCD（本层） | `pip install pyocd` | 装上是可选能力；缺失时 server 照常启动 |

这不是替换前两条，而是补上「没有 Keil、又不想拉起外部进程」这一格。

## 吸收决策（对照 `docs/oss-absorption.md`）

早期结论是「以 pyocd 为核心 → 不吸收」：那时的问题是「要不要把整个调试后端换成
pyOCD」。本批改判的是另一个问题——**作为并列的第三条链路吸收**（只取 Python API
这一面，不复刻它的 CLI / commander / gdbserver 启动逻辑当主入口）。

吸收的边界：

- 取 **Python API**（`ConnectHelper` / `Session` / `Target` / `FileProgrammer` /
  `FlashEraser`），不解析 `pyocd commander` 的交互输出。
- 取**读数可校验**的能力：读到几个字节、回读是否一致，都由 API 直接给，不靠文本判断。
- `pyocd gdbserver` 只作为**可选功能**（`pyocd_gdb`），不是默认路径。

## 能力清单（15 个工具）

| 工具 | 说明 |
|---|---|
| `pyocd_list` | 列已连探针（unique_id/描述/厂商/协议）、按关键字查目标名（`targets="stm32f4"`）、报 pyocd 是否安装 |
| `pyocd_start` | 进程内开会话：`probe`(unique_id) / `target` / `frequency` / `connect_mode`(halt/pre-reset/under-reset/attach) / `pack` / `options` / `restart` |
| `pyocd_stop` | 关会话并放开探针；`resume=true` 先在关闭前让目标继续跑（默认不碰目标状态） |
| `pyocd_status` | 会话在不在、连的哪个探针、目标实时状态与停机原因、本模块登记的断点/观察点数量 |
| `pyocd_info` | 器件身份（part_number/vendor/核列表/状态/停机原因）+ 内存区域表（`memory_map`） |
| `pyocd_control` | `halt` / `resume` / `reset` / `reset_halt` / `step` / `init`，`reset_type` 支持 hardware/system/core/vectreset/sysresetreq/nsrst/emulated 等 |
| `pyocd_read_mem` | 按地址读字节：`data_hex` / `words`（按 width 解）/ `hexdump`，**自带可信度**（见下） |
| `pyocd_write_mem` | `data_hex` 或 `words`+`width`（小端）；默认写后回读比对（`verified`/`mismatch`） |
| `pyocd_reg` | 读全部/指定寄存器，写单寄存器并回读校验，`list` 列寄存器名表 |
| `pyocd_bp` | `set`（kind=auto/hw/sw）/`clear`/`list`。list 只列本模块登记过的并用 `find_breakpoint` 复核 |
| `pyocd_wp` | 观察点 `set`（read/write/read_write）/`clear`/`list`，命中后 `halt_reason=watchpoint` |
| `pyocd_flash` | `FileProgrammer` 烧录：elf/hex 自带地址，bin 必须 `base_address`；`chip_erase`=auto/chip/sector |
| `pyocd_erase` | `mode`=chip / mass / sector（sector 必须给 addresses，支持 `0x…-0x…` 区间） |
| `pyocd_gdb` | 起/停/查一个独立的 `pyocd gdbserver` 进程（要独占探针） |
| `pyocd_log` | 一站式排障：安装状态、版本、会话参数、目标状态、gdbserver 日志尾部 |

全部归入 `pyocd` 工具组，**默认收起**（与 `ocd` 组同口径），默认暴露面不变。

## 读数可信度：与 Keil 链路同一套语言

`pyocd_read_mem` / `PyOCDMemoryClient.read_mem_verified` 返回：

- `read_confidence`：`high` / `medium` / `low`
- `degenerate`：`all_zero` / `all_ff` / `repeated_word`（整帧退化）
- `reread_consistent`、`while_running`

口径：

- **目标 running 且两读不一致 → `medium`**：不断言真假——「变量本来在变」与「读被打断」
  这两种解释分不开。
- **halted 下两读不一致 → `low`**：静止状态下不一致只能是链路问题。
- **整帧退化 → `low`**，并在 `degenerate` 里写明是哪种。

条件触发（`trigger_add(kind="memory")`）复用这套读数：只看 `read_confidence == "high"`
的样本，其余记 `ambiguous`，不建基线、不判命中、不覆盖 `last_value`。

## 与其它链路的关系

- **同一根探针同一时刻只能被一个调试宿主占着**：Keil / OpenOCD / pyOCD 三者互斥。
  `pyocd_start` 连不上时第一句提示就是「别处是否占着探针」。
- 条件触发的读数源自动选路：Keil 真连着就用 Keil，否则用已开的 pyOCD 会话，两者都不在
  时回到原错误路径——**不静默改道**掩盖「在读哪块板」。

## 刻意不做（写清楚，免得后来者以为是漏了）

1. **不解析 `pyocd commander` 的交互输出**：那是给人看的，格式随版本变；走 Python API
   才能拿到「读到几个字节」这类可校验的事实。
2. **不在 import 时 import pyocd**：它要加载几百个器件定义，首次导入是秒级；而且没装
   pyocd 的机器不该因此整个 server 起不来。缺失时报 `pyocd-not-installed` + 安装提示。
3. **不做 RTT / SWO**：pyOCD 0.4x 没把这两条稳到能当 API 用；我们自己的
   `trace_buff_*` / `trace_swd_*` 已覆盖目标侧缓冲那条路。
4. **不替调用方自动 halt**：读内存前只**报告**目标状态，不悄悄停 CPU——停-读-走会改变
   被观察对象。要一致快照请显式 `pyocd_control(action="halt")`。
5. **不新增 pip 依赖到 `pyproject.toml`**：pyocd 是可选能力，惰性导入，零新增依赖。

## 实现落点

- `mdkdebug/pyocdlink.py`：`PyOCDSession`（open/close/read/write/regs/bp/wp/control/
  flash/erase/gdb）、`PyOCDMemoryClient`（条件触发适配器）、`available()`、`register()`。
- `mdkdebug/toolbox.py`：新增 `pyocd` 组（15 个）与组说明。
- `mdkdebug/annotate.py`：只读 / 会改 / 非幂等三张表归类。
- `mdkdebug/server.py`：模块注册 + `_trigger_source()` 读数源选路。

## 真机取证（2026-11-19，pyocd 0.46.1）

- 探针：`Arm DAPLink CMSIS-DAP`，`unique_id=D9763DF419A5963926F6F8EC35D93331`。
- `connect_mode="attach"` 连上（未识别具体器件时为 `part_number="CoreSightTarget"`，
  Generic —— 内置目标表里没有对应 FLM 时会这样，不是连接失败）。
- 读 CPUID `@0xE000ED00` = `71c21f41`（0x411FC271 = Cortex-M4 r0p1，即 F401 系列）。
- `halt` → `pc=0x20000000`、`sp=0x20008000`；读 `0x20000000` 4 字节；`resume` —— 全通。

## 欠账

- **reset / flash / erase 未做真机验证**：本机这块 F401 目标上是不明固件，复位或改写
  Flash 会改变现场。三个工具的错误码与参数校验有单测覆盖，但真机行为记为欠账。
- `pyocd_gdb` 未在真机上起过 gdbserver（同样因为要独占探针且会动目标）。
- 器件自动识别依赖 pyOCD 的目标表 / CMSIS-Pack；未装 pack 时只能得到 Generic 目标，
  届时需要显式 `pyocd_start(target="...", pack="...")`。

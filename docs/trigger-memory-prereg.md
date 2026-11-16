# 预注册：`trigger_add(kind="memory")` —— 内存条件触发

- 状态：**预注册（frozen），未实现**
- 写于：2026-11-16（批次113 候选，目标版本 0.2.37）
- 上游事实基线：`0.2.36`（`trigger_add/list/wait/cancel` 已发行，支持 `kind="serial"` / `"modbus"`）
- 冻结规则：本文件的**判据（§6）、否决条件（§7）、不得读成（§8）在实现开始后不得改动**。
  实施中若发现必须改，只能**追加「修订块」**，写清：触发条件（什么实测结果迫使改）、
  改前改后、以及复算依据；不得就地编辑原判据。

---

## 1. 要解决的问题

用户原话（批次112 起因）：「增加串口和modbus等条件触发的功能这样不用ai一直等待」。
现在 `serial` / `modbus` 两条通路已覆盖日志与寄存器，**还剩最常用的一条：内存**。

典型场景：

- 「等 `g_state` 变成 3」——AI 现在只能反复 `read_mem`；
- 「等 `SystemCoreClock` 变化」（时钟切换生效）；
- 「等某个计数器/水位越过阈值」；
- 「等 `svcrt_task_table[i].state` 出现 0」——数组元素。

每一次 `read_mem` 都是一轮上下文、一次 UVSOCK 往返；等到的东西又常以「还没变」告终。

## 2. 非目标（明确不做，v1）

| 不做 | 理由（写死） |
| --- | --- |
| **`on_fire="write_mem"`**（命中后自动写内存） | 写内存有副作用且写后可能被 CPU 立即覆盖（`write_mem` 自己都要靠回读 `verified` 才敢说写进去了）。要写就 `trigger_wait` 等到之后**显式**调 `write_mem`，让 AI 自己看 `verified`。登记为欠账，须新预注册。 |
| **`running="halt"` 轮询（停-读-走）** | 轮询式停机会**改变被观察对象**：每次暂停 `paused_ms` 累积，实时性敏感的条件（超时、看门狗、通信握手）会被自己的观测改掉。要一致快照就**先 `stop` 目标再登记**，或单次 `read_mem(running="halt")`。 |
| **大端（big-endian）解码** | 目标侧（Cortex-M / RISC-V 小端工具链）在本仓库全部实测样本上都是小端；加一个用不上的开关只会让参数面变宽。需要时新预注册。 |
| **表达式 / 多地址联合条件**（如 `a>1 && b<2`） | 多地址读不是原子快照，`a`、`b` 之间总有裂缝，「联合命中」会给出一个不存在的瞬间。要么读结构体一次读全（用 `addr`+`width`×`count`？也不做），要么分两个触发。 |
| **当逻辑分析仪/断点用** | 采样会漏（见 §5.4）。要精确停在某一刻用 `set_watchpoint` + `data_watchpoint`，那是另一条通路。 |

## 3. 与既有能力的分界（为什么不再造一个「等」）

| 已有 | 判什么 | 会不会漏 | 阻塞在哪 |
| --- | --- | --- | --- |
| `trace_watch`（批次75） | **事件流**（插桩/内核钩子，无损累积，可回溯 `cursor="history"`） | **不漏**（未读区不被覆盖） | 调用里长轮询 ≤60 s |
| `serial_expect` / `modbus_read` | 串口行 / 一次寄存器读 | 串口行会漏（不在监听时） | 调用里 |
| **`trigger_*`（批次112）** | 外部资源的**当前状态**（采样型） | **会漏**（采样间隔内变回去就看不到） | 后台线程，`wait` 才等 |
| **`kind="memory"`（本预注册）** | 内存里的**当前值**（采样型，且读数自带置信度） | **会漏**，且有**脏读**这个额外风险 | 后台线程 |

结论：memory 属于 `trigger_*` 家族（状态型、后台、可并发），**不并入 `trace_watch`**——
两者的漏与不漏、证据强度都不同，合成一个只会让「没命中」这句话变得不可解释。

## 4. 接口草案（参数面）

不新增工具（仍是 231 个、`serial` 组不变、默认暴露仍 42）：只是 `trigger_add` 多认一个 `kind`。

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `kind` | — | 新增 `"memory"`（与 `"serial"`/`"modbus"` 并列） |
| `addr` | 必填 | `0x…` / 十进制 / **符号名**（`g_state`、`svcrt_task_table`，走 `.axf` 符号表）。**符号在登记时解析一次**，`trigger_list` 回 `addr`（数值）+ `addr_note`（解析来源），轮询期间不再重复解析 |
| `reloc_delta` | `""` | 与 `read_mem` 同口径；**显式数字地址不受偏移** |
| `width` | `4` | 取值 1 / 2 / 4 / 8，**小端** |
| `index` | `0` | 数组元素下标，实际地址 = `addr + index*width` |
| `op` | `"change"`? → **必填** | `eq/ne/gt/ge/lt/le/change/mask_set/mask_clear`（含别名，复用批次112 的 `compare`） |
| `value` | — | `op` 需要时必填；`signed` 默认 `false`（无符号解码，超过位宽报错不截断） |
| `mask` | — | `mask_set/mask_clear` 必填 |
| `poll_ms` | **500** | 内存通路下限 **200**（`MIN_MEM_POLL_MS`），小于则报错（不静默抬到下限——「我按 50 ms 填的」和「实际 200 ms」必须让调用者知道） |
| `running` | `"live"` | 只接受 `live`；传 `halt` → 报错并指路（§2） |
| `label` / `duration_s` / `repeat` / `cooldown_s` / `max_fires` | 同批次112 | `duration_s` 默认 900 s |
| `on_fire` | 不提供 | v1 无可用值（§2）；传了 → 报错 |

预算与上限（写死）：`MAX_MEM_TRIGGERS = 4`（总数仍受 `MAX_TRIGGERS = 8` 约束，超了报错不抢占）。

## 5. 语义（四条主口径 + 一条本通路独有）

### 5.1 只认高置信样本（本通路的核心判据）

`read_mem_verified` 的返回里已经有四件证据：`read_confidence`（high/medium/low）、
`degenerate`（`all_zero`/`all_ff`/`repeated_word`）、`reread_consistent`、`while_running`。
**只有同时满足「`read_confidence=="high"` 且 `reread_consistent is not False` 且无 `degenerate`」
的样本才算样本**；其余一律记为 `ambiguous`：

- **不建基线**（`op="change"` 不会拿脏值当第一次值）；
- **不算命中**（`gt` 不会因为伪值 `0x01010101` 更大就 fire）；
- **不更新 `last_value`**（`last_value` 只放高置信样本，另设 `last_ambiguous_hex` 留证）。

这不是「保守」，是**已实测的静默错答案**：`client._degenerate_kind` 的注释写着真机实测
「目标全速运行时经 SWD 读 SRAM 的某些区段会整段重复同一个 4 字节字」，且随读推进而变——
这种值既不退化也不撕裂，任何只看比较结果的实现都会误命中。

`ambiguous` 是**读的可靠性问题**，与条件成不成立无关。所有对外的 `timed_out` / `waiting`
响应里必须同时给出 `ambiguous_count` 与 `ambiguous_rate`（最近 20 次采样）。

### 5.2 端口/链路只借不抢

memory 通路借的是 `create_server()` 建的那条 UVSOCK 连接（`UVClient` 自带 `RLock`，
并发读会被内部串行化）。**没有连上 Keil 时登记即报错**（`memory-no-client`），不挂着空等。
链接被 `reset_connection` 或编译烧录打掉 → 连续失败到上限转 `error`，给指路
（`keil_health` / `restart_keil`），**绝不假装还在等**。

### 5.3 偶发错误不杀

与批次112 同口径：单次读失败只 `errors += 1`；**连续 20 次**（`max_consecutive_errors`）
才转 `error`。`ambiguous` 单独计数（`ambiguous` 不等于 `errors`——一个是「读到了但不可信」，
一个是「没读到」）。

### 5.4 采样会漏（本通路必须写进描述层的一句话）

`op="change"` 只保证「相邻两个**高置信**采样点不同」。中途「变过去又变回来」如果发生在
`poll_ms` 之内，**看不到**。所以：

- 「没命中」≠「没发生过变化」（`trace_watch` 才敢说后者）；
- 响应里给 `sample_gap_ms`（实际采样间隔 p95），让调用者知道分辨率；
- 需要「抓到瞬时毛刺」→ 用 `set_watchpoint`（数据观察点）或 trace，不用 memory 触发。

### 5.5 一定有终点

`duration_s` 默认 900 s 到期 `expired`；`max_fires`/`cooldown_s`/`repeat` 同批次112；
进程退出 `atexit` 全停；`trigger_cancel` 立刻唤醒所有在等它的调用。

## 6. 判据（G 闸门，实现完成后逐条给数）

| 闸门 | 内容 | 通过条件 |
| --- | --- | --- |
| **G1 面** | 不新增工具；`serial` 组仍 19；注册仍 **231**、默认暴露仍 **42**、`AN.check_surface == []`；`kind` 非法值报错且列出可用值 | 三项计数与 batch112 完全一致 |
| **G2 参数与错误** | `kind="memory"` 缺 `addr` / `width=3` / `width=8` 且 `value` 超 64 位 / `poll_ms=50` / `running="halt"` / `on_fire` 非空 / `mask_set` 缺 `mask` / 符号解析失败 —— **七条各自**返回 `error_code` 与指路，**不得**退化成 `waiting` | 7/7 有明确错误码，0 条静默接受 |
| **G3 脏读免疫（核心）** | 假链路脚本化：第 1 帧回 `repeated_word` 伪值（`0x01010101…`），第 2 帧起回真值。两个用例：① `op="gt", value=100` 的地址真值为 5 → **不得在伪值上 fire**，随后真值变大时才 fire；② `op="change"` → **伪值不建基线**，真值首次出现只是建基线，第二次真值变化才 fire | 两用例全过，且 `ambiguous_count` 与 `last_ambiguous_hex` 如实记录 |
| **G4 端到端（假链路为主）** | 用假 `UVClient.read_mem_verified` 脚本：高置信样本 → 命中；连续 20 次 `ambiguous` → `error`（`error_code="memory-unstable"`）；连续 20 次读异常 → `error`；`repeat`+`cooldown_s` 命中节奏正确；`wait` 只认本次调用之后的新命中（复用批次112 的 base 计数语义） | 6 项全过 |
| **G5 成本** | `MAX_MEM_TRIGGERS=4` 同时跑、`poll_ms=500`，对照基线（同机不登记触发）测人工 `read_mem(4 B)` 的 p95 延迟 | p95 ≤ **2.0×** 基线，且期间零 `status` 错误、零 `reset_connection` |
| **G6 真机（可用则跑，不可用则如实标注欠账）** | 连着真实 Keil 会话：登记 `op="change"` 盯一个已知变量 → `write_mem` 改它 → 命中；记录 `poll_ms=500` 下的命中延迟、`ambiguous_rate`、`sample_gap_ms` | 命中成立且延迟 ≤ 1.5×`poll_ms`+50 ms；`ambiguous_rate` 如实上报（不设通过阈值，见 §7 C2） |
| **G7 文档与诚实性** | `trigger_add` 描述写明：采样会漏 / `timed_out ≠ 条件不成立` / `ambiguous` 与 `errors` 的区别；README 与 SKILL 各有一节；`trigger_list` 必带 `read_confidence`、`degenerate`、`ambiguous_count`、`sample_gap_ms` | 逐项 grep 得到 |

## 7. 可检验主张与否决条件

预注册的价值在于「先写下什么会让我认输」。

- **C1（脏读会伪命中）**：任何「只看比较结果、不看置信度」的实现，在 G3 用例①里必然在
  `0x01010101` 上 fire。**若 G3 不过 → 该实现在这一步就否决，不得发行。**
- **C2（运行态采样是否可用）**：真机全速运行时，对一个**本应不变**的静态变量连采 100 次，
  `ambiguous_rate` 若 **> 20 %** ⇒ 判 `memory_sample_unusable_while_running`：memory 触发
  **只允许在目标停止（halted）时登记**，`running=live` 且 `get_status().running==true` 时
  登记直接报错并指路「先 stop」。此判词不推翻实现，只收窄适用面。
- **C3（成本是否可接受）**：G5 若 p95 > 2.0× 基线 ⇒ 必须引入**全局读预算/错峰**
  （例如把 4 个内存触发错开到不同的 `poll_ms` 相位），做不到就把 `MAX_MEM_TRIGGERS` 降到 2，
  并在描述层写死上限数字。

**否决（kill）条件**——任一条成立则 memory kind 不落地，只留负读数：

1. G3 无法通过（做不出脏读免疫，或免疫后连真实变化也判不出 → 说明这条通路的信噪比不够）；
2. 真机上 `ambiguous_rate` **持续 > 50 %**（哪怕目标已停止），即「读到的值基本不可信」——
   此时 memory 触发等于随机数发生器，`read_mem` 单次调用仍是唯一可用的做法；
3. 实施后发现必须靠 `running="halt"` 才能拿到可用样本（即 §2 的禁区变成必需条件）——
   这会改变被观察对象，判定该能力在本基质上不成立。

## 8. 不得读成（红线）

- **「没命中」≠「没发生过」**：采样型会漏；只有 `trace_watch` 的 `coverage.complete=true`
  才配说「已录部分里没有」。
- **「读到 0」≠「变量被清零」**：`all_zero` 是脏读签名之一（批次30 口径）；memory 触发把
  这种样本记为 `ambiguous`，不参与判定。
- **`timed_out` ≠ 条件不成立**：只说明这段时间没等到。
- **`medium` 样本不是数据**，它只是一个「可能被 CPU 改写 / 可能读被打断」的上界；两者
  分不开（`read_mem_verified` 的原话），memory 触发不替调用者选一个。
- **`ambiguous` ≠ `errors`**：前者读到了但不可信，后者没读到。
- 不得把本能力当**逻辑分析仪/断点**用（瞬时毛刺会漏）；也不得用 `poll_ms` 极小 + `repeat`
  去「重建」一个事件流——那是 `trace_watch` 的活。

## 9. 实施顺序（预注册之后才允许动代码）

1. `mdkdebug/triggers.py`：`_poll_memory()` + `add_memory()`；`compare()` 复用，仅补 `signed` 解码；
   新增 `MIN_MEM_POLL_MS`、`MAX_MEM_TRIGGERS`、`MEM_DEFAULT_POLL_MS`。
2. 客户端注入：`server.create_server()` 里 `triggers.set_client_provider(_get_client)`
   （与 `builder.set_reset_connection_hook` 同一套「不反向依赖 server」的手法）。
3. `server.trigger_add`：`kind` 增加 `"memory"` 分支与 7 条参数校验。
4. `tests/test_batch113.py`：G1–G5（假链路），G6 视真机可用性。
5. README / SKILL / `trigger_add` 描述：采样会漏、`timed_out` 口径、`ambiguous` 与 `errors` 的区别。
6. 全量闸门 87 → 88 个测试文件；版本 0.2.36 → **0.2.37**（三处同步）；工具面计数不变
   （仍是 231 / 42），**但 `serial` 组描述体积会涨**，需确认 `lean` 档下 `trigger_add` 的
   关键句仍在（放描述末尾）。

## 10. 两处口径：已裁定（2026-11-16，实施前）

- **A. `poll_ms` 下限 200 ms + `MAX_MEM_TRIGGERS = 4`** → 用户裁定 **接受**（推荐项）。
  理由成立：UVSOCK 每次读是真实链路往返，运行态还要多复读一轮；4 个触发 @500 ms 实测读率
  约 24 次/秒，仍在安全区。
- **B. `op` 必填（不给默认 `change`）** → 用户裁定 **坚持必填**。

两种裁定都落在实现里：`MIN_MEM_POLL_MS=200` / `MAX_MEM_TRIGGERS=4` / `DEFAULT_MEM_POLL_MS=500`，
`add_memory()` 在 `op` 为空时抛 `memory-op-required`。

### 原始待裁定清单（保留原文，供追溯）

- **A. `poll_ms` 下限 200 ms + `MAX_MEM_TRIGGERS=4`**：是否接受？理由是 UVSOCK 每次读是
  真实链路往返（运行态还会复读一轮），比串口行匹配贵一个数量级。
- **B. `op` 是否要默认 `change`**：草案里写的是**必填**（不给默认），因为「默认 change」会让
  「我只想看现在是多少」变成一个静默跳变订阅。是否坚持必填？

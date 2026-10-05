# 工程方采纳提案（回应第三方评审 A/B）

> 对象：`docs/memory-report.html` v1.0 的两份第三方评审（`2026-10-05-memory-final-review-a.md` /
> `-b.md`）。本文做三件事：**① 事实核对（实测+源码）；② 逐条判定与修正；③ 落为 I1–I5 计划与验收**。
> 日期：2026-10-05；状态：提案（待排期）。

## 0. 结论速览

| 评审意见 | 判定 | 去向 |
|---|---|---|
| Reactor 模型（connection ≠ thread）是核心成果 | **采纳**（表述按单变量 A/B 证据） | 已在报告；措辞降调（I5） |
| 「Reactor 是唯一解」 | **不采纳该表述**（io_uring/thread-per-core/M:N 均是解） | I5 全文统一替换为「Reactor 架构以极低线程/用户态内存承载高并发」 |
| malloc_trim/回收策略是亮点 | 采纳（维持） | — |
| **FD 爆炸（8/连接）是隐患** | **采纳（最高优先）** | **I2** |
| pipe 内核内存可能吃掉数百 MB（64KB/pipe 推算） | **部分采纳：需实测**。事实修正：本项目 `F_SETPIPE_SZ=1 MiB`；页按需分配，capacity≠resident | **I1**（系统内存基准，先测再改） |
| Pipe 池化把 8 fd → 2 fd/连接 | **部分采纳（方案修正）**：pipe 是流式数据路径，**同一时刻只能服务一条连接**，池化不能降低并发峰值 fd；可行组合 = 去 socket 克隆 + pipe 懒建/空闲释放 + worker 本地复用（消 syscall）+ fd 预算回退 | **I2** |
| splice 也许是「架构税」（A/B/C/D 方案对照） | **采纳**（对照实验） | **I3**（M1 已有 splice vs copy：+38% 吞吐/−84% CPU；io_uring A/B 已否，ADR-0058） |
| 先证明系统总内存（四层模型） | **采纳（最高优先）** | **I1** |
| 72h Soak 曲线化 + bounded-memory 判据 | **采纳** | **I4** |
| worker-local pipe cache（非全局池） | 采纳（作为 I2 子项） | I2 |
| 启动水位（27MB）/churn 短命线程（42）延后 | 同意延后（ROI 低） | backlog 记录 |
| 报告措辞降调 + 加口径边界 | **采纳** | **I5** |
| 定位「predictable resource consumption」 | 采纳（对外定位语） | I5 |

## 1. 事实核对（2026-10-05 实测与源码）

**① fd 拓扑（hold 300，direct dialer，reactor；`/proc/<pid>/fd` 分类统计）**

| fd 类别 | 数量 | 每连接 | 来源（源码） |
|---|---|---|---|
| `socket:` | 1 208 | ≈4.03 | session 自身 client+upstream（`reactor.rs:104-107`）+ **`RelayHandle` 为看门狗克隆的两份 socket**（`main.rs:2526-2537`） |
| `pipe:` | 1 200 | 4.00 | 每 session 两条 pipe：c2u/u2c（`reactor.rs:1219-1230`），每条 2 端 |
| 其他（bpf map/prog/link、eventfd、日志、netns 挂载…） | ~79 | 常量 | 与连接数无关 |
| **合计** | 2 487 | **≈8.29** | 空闲 hold 亦为 8/连接；有 prelude（codec 首读）时短暂 +1 socket（`reactor.rs:1018`，首读后释放） |

**② pipe 配额**：`PIPE_SZ = 1 << 20`（1 MiB/pipe，最大 2 MiB/连接容量）；`/proc/sys/fs/pipe-max-size = 1 MiB`（设置成功）。
Pipe 缓冲**页按需分配**（有数据才占页，读空即释放），因此「64KB×端点」只能当**上界**，必须实测（见 ③）。

**③ 内核侧初测**（hold 300 空闲，slab 快照，未做基线扣除与重复）：Slab +13.9 MB、SUnreclaim +12.5 MB，
**≈46 KB/连接**（含 socket/pipe/TCP 结构等）。同口径用户态 ≈15 KB/连接（29–30.5 MB / 2000）。
→ 第一份评审的担忧方向成立，**内核侧可能大于用户态**；这直接支持 I1 先做系统内存基准。

**④ fd 上限**：8 fd/连接 → 65535 默认 limit ≈ 8 191 连接触顶（评审数字成立）。
当前 loader 未自提升 rlimit、status 也未上报 fd 统计（I2 补齐）。

**⑤ 关于「Pipe 池化降 fd」的修正**：pipe 承载在途字节流，两条并发连接的字节不能混装于同一 pipe；
因此池化只能（a）跨**先后**连接复用（消 `pipe()`/`close()` 系统调用与 slab 抖动，**不减并发峰值**），
或（b）在**空闲连接**上释放 pipe 后按需重挂（可减峰值）。二者都做，见 I2(b)(c)。

## 2. 逐条回应（含技术修正）

- **A-1/B-1（Reactor 成果）**：采纳。对外表述统一为「29 线程 / 34.8 MB 承载 10k 连接；同二进制线程模型
  对照 20 012 线程 / 527 MB」——数字是单变量 A/B 事实，保留；「唯一解/遥遥领先/顶级」等评估词不进本项目文档。
- **B-2（「唯一解」不成立）**：采纳，按上条执行。
- **A-2（64KB/pipe 推算数百 MB）**：部分采纳。修正：本项目为 1 MiB/pipe 且按需分配；「capacity≠resident」，
  以 I1 实测为准；报告不改数字，改为引用 I1 结果。
- **A-3（Pipe 池化 8→2 fd）**：部分采纳，方案按 §1⑤ 修正：**目标 10k 连接 fd 从 ~83k 压到 ≤40k**
  （splice 活跃期 6/连接；空闲期 2–4/连接），而不是把并发峰值压到 2。
- **A-4/B-8（72h soak）**：采纳（I4），判据改为曲线 + 漂移阈值。
- **A-5（启动水位/短命线程延后）**：同意延后（记录在 I 节 backlog）。
- **B-3（系统内存四层模型）**：采纳为 **P0**（I1），指标与场景按评审建议扩展（含 eBPF map/prog、sockstat、
  slabinfo 关键 cache、smaps_rollup）。
- **B-5（FD 拓扑先搞清楚）**：已完成初测（§1①），余量在 I2 做「2/连接目标」的可行性收敛。
- **B-6（转发原语对照）**：采纳（I3）。已有证据：M1 splice vs 用户态泵 = +38% 吞吐 / −84% CPU（保留 splice 默认）；
  io_uring A/B 结论「不引入」（ADR-0058，噪声内）；新增 MSG_ZEROCOPY 可行性调研与 fd 高压档权衡。
- **B-7（worker-local pipe cache）**：采纳（I2c），规避全局锁竞争。
- **B-9/B-10（定位与降调）**：采纳（I5），并作为后续对外报告的统一口径。

## 3. 计划（I1–I5）

### I1 · 系统内存基准（四层模型）——P0
- **工具**：`lab/perf/mem-system.sh`（mem.sh v2；保留 v1 口径不变以便对照）。
- **指标**：
  - userspace：`VmRSS`、`smaps_rollup`（Private_Dirty/Rss）、Threads、FD 分类计数、`malloc_info` arena；
  - kernel：`/proc/meminfo`（Slab/SReclaimable/SUnreclaim/PageTables）、`slabinfo` 关键 cache
    （`sock_inode_cache`、`kmalloc-*`、`skbuff_head_cache`、`tcp_bind_bucket`、`pipe_inode_cache`）、
    `/proc/net/sockstat{,6}`（TCP mem）、conntrack 计数；
  - eBPF：`bpftool map show` 内存合计、prog/link 数；
  - **Total = 进程增量 + kernel 归因增量**（同拓扑无实现基线扣除）。
- **场景**：连接扫描 100/500/1k/2k/5k/10k/20k（a 空闲 hold；b 稳态小流量）；UDP 20k pps；churn 10s。
- **产出**：Total/连接 曲线 + 分解表（对 dae/sing-box 至少一方同口径对照）。
- **验收**：给出 20k 连接下 sodama 的**总物理内存**与每连接分解；结论支持/否证「RSS 优势=系统优势」。
- **量级**：2–3 人日 + 机时。

### I2 · FD 架构治理——P0
- **(a) 去 `RelayHandle` socket 克隆**（−2 fd/连接）：看门狗（空闲超时/停机）改走 reactor 的
  `kill(id)`/shutdown 信号路径（已有 `kill`）；offload 链路单独保留（其需要裸 fd 语义）。
- **(b) pipe 懒建 + 空闲释放**：会话在「drain 完成且空闲 > 阈值」时关闭 pipes、置 `need_arm`，
  有数据再建（±阈值 hysteresis）；空闲 hold 目标 2–4 fd/连接。
- **(c) worker-local pipe cache**：顺序连接复用（消 syscall/减 slab 抖动），不跨 worker 共享。
- **(d) fd 预算治理**：启动自提升 `RLIMIT_NOFILE`（记入 status）；使用率 >80% 时**新连接**自动回退
  用户态 copy-pump（吞吐换可用性）；status 暴露 `fds_total/soft_limit/splice_fallbacks`。
- **验收**：hold 2000 fd/连接 ≤4（目标 6→4 活跃、2 idle）；10k 连接在默认 limit 下可跑且无 ENFILE；
  吞吐/CPU 同口径 A/B 不回退 >3%。
- **量级**：3–5 人日。

### I3 · 转发原语对照——P1
- splice(pipe) vs userspace copy vs io_uring（引用 ADR-0058 结论）vs MSG_ZEROCOPY（调研+可行性）。
- 维度：吞吐、CPU、p99、RSS、fd、**内核对端内存（接 I1 指标）**。
- **验收**：给出「fd 高压 / 低延迟 / 高吞吐」三档的选型与默认值建议。
- **量级**：2–3 人日。

### I4 · 长稳曲线化（bounded-memory）——P1
- `lab/soak/` 扩展：24/48/72h（微量 churn + 随机长连接 + 周期负载），采样 RSS/FD/Slab/SUnreclaim/
  sockstat/CPU/latency/fail，输出曲线。
- **验收**：72h 终点相对 1h 基线，RSS/FD/Slab 漂移 ≤5% 且 fail 无增长 → 允许对外使用
  `bounded-memory` 表述。
- **量级**：夹具 1 人日 + 机时。

### I5 · 报告口径与措辞——P2（与 I1 同步发布）
- `memory-report.html` v1.1：新增「口径与边界」小节（RSS-only；kernel/system 见 I1）、链接 `docs/reviews/`、
  全文去除「唯一解/遥遥领先/顶级」类措辞；数字保留（均为实测）。
- 后续对外文档统一：四层模型（Process → Kernel → Total → per-connection）与
  「predictable resource consumption」定位。
- **量级**：0.5 人日。

## 4. 不采纳 / 明确边界

- **「pipe 池化把并发峰值 fd 压到 2/连接」**：概念不成立（见 §1⑤），按 I2(b)(c) 修正目标。
- **把 64KB×pipe 推算当作既有结论**：不采纳推算，改实测（I1）。
- **启动水位 / churn 线程峰值重构**：同意延后（ROI 低），登记 backlog 备注。
- **io_uring 重新引入**：维持 ADR-0058（A/B 无收益）；仅作为 I3 对照组复测一次。

## 5. 与现有 backlog 的衔接

本提案落为 backlog 新 I 节：`I1 系统内存基准`、`I2 FD 治理`、`I3 转发原语对照`、`I4 soak 曲线化`、
`I5 报告更新`（I2 同时覆盖「O8 内存专项」的延续）。执行顺序建议：**I1 → I2 → I5 → I4 → I3**
（先拿证据、再改架构、同步口径；soak 与 I3 可并行做机时占用）。

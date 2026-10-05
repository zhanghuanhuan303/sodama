# I1 · 系统内存基准（四层模型）——数据与口径

> 对应评审提案 `2026-10-05-adoption-proposal.md` §I1。工具：`lab/perf/mem-system.sh` +
> `lab/perf/mem-analyze.py`。日期：2026-10-05；状态：已完成（扫描 100–20 000，含 dae 同口径对照）。
> 环境：Arch / 内核 6.18.54-lts / i9-9900KF（8C16T）/ 31 GB；拓扑：client ns — 网关（被测实现）—
> WAN ns（epoll echo + sing-box VLESS 服务端）。

## 0. 口径（方法学）

1. **四层模型**：Process（进程 RSS/线程/fd/smaps）→ Kernel（`/proc/meminfo` Slab/SUnreclaim、
   `/proc/slabinfo` 归因、sockstat、conntrack、bpftool map）→ **Total**（用户态 + 内核，
   对照扣除后）→ **per-connection**（÷N）。
2. **同点邻近增量**：每点先取 `pre` 快照（起压前 1 s）、`active`（连接建立后 1 s）、`after`
   （释放后 2 s）；增量一律 `active − pre`，消除多分钟扫描期的背景漂移（早期用 `N=0` 基线
   曾把系统噪声算进增量，已修正）。
3. **对照扣除**：对照组**同拓扑、同夹具、不放实现**（连接走内核直连 echo），其 within-run
   每连接增量（§3）代表夹具自身开销；实现净增 = 实现每连接 − 对照每连接（近似，上界，见局限）。
4. **夹具**：`conn_scale hold`（单进程，逐条 connect+32 B ping+回显，全部断言成功）+ WAN 侧
   `echo_server`（epoll 单线程）。**不再使用 `bench_io` 作 WAN 侧 echo**：其每连接 1~2 线程，
   1 万连接即 2 万线程（污染 `task_struct`、并触发 systemd scope `TasksMax` 15% 上限
   = 38 142，曾被误判为 sodama 线程问题）。sing-box VLESS 上游（同一进程两链路）。
5. **端口**：client/WAN 两个 netns 均放宽 `ip_local_port_range=10000-65000` + `tcp_tw_reuse=1`
   （否则 2 万连接在 WAN 侧上游拨号触发 EADDRNOTAVAIL）。
6. **复现**：
   ```bash
   cd sodama
   sudo lab/perf/mem-system.sh prepare
   sudo env POINTS="100 500 1000 2000 5000 10000 20000" HOLD_SECS=6 \
     RESULTS=/tmp/mem-system-sodama.tsv lab/perf/mem-system.sh run
   sudo env POINTS="..." RESULTS=/tmp/mem-system-ctl.tsv    lab/perf/mem-system.sh run-control
   sudo env IMPL=dae POINTS="..." RESULTS=/tmp/mem-system-dae.tsv lab/perf/mem-system.sh run
   python3 lab/perf/mem-analyze.py /tmp/mem-system-sodama.tsv /tmp/mem-system-dae.tsv \
     --control /tmp/mem-system-ctl.tsv --out-md /tmp/mem-analysis.md
   ```

## 1. 用户态（进程）——活跃 N

| 组 | N | RSS(MB) | RSS/连接(KB) | Threads | fd/连接 | priv_dirty(MB) |
|---|---|---|---|---|---|---|
| sodama | 100 | 27.4 | 280.8 | 28 | 4.87 | 20.7 |
| sodama | 500 | 27.8 | 57.0 | 28 | 4.17 | 21.0 |
| sodama | 1000 | 28.2 | 28.9 | 28 | 4.09 | 21.4 |
| sodama | 2000 | 12.1 | 6.2 | 28 | 4.04 | 5.3 |
| sodama | 5000 | 13.7 | 2.8 | 28 | 4.02 | 6.9 |
| sodama | 10000 | 16.7 | 1.7 | 28 | 4.01 | 9.9 |
| sodama | **20000** | **23.6** | **1.2** | **28** | **4.00** | **16.8** |
| dae | 100 | 55.5 | 567.9 | 22 | 2.95 | 54.9 |
| dae | 500 | 106.4 | 218.0 | 23 | 2.19 | 105.9 |
| dae | 1000 | 175.6 | 179.8 | 23 | 2.10 | 175.1 |
| dae | 2000 | 306.0 | 156.7 | 23 | 2.05 | 305.5 |
| dae | 5000 | 696.6 | 142.7 | 24 | 2.02 | 696.1 |
| dae | 10000 | 1104.6 | 113.1 | 26 | 2.01 | 1104.1 |
| dae | **20000** | **1662.0** | **85.1** | 26 | 2.00 | **1661.4** |

- sodama RSS 在 N≥2000 后由 `malloc_trim` 主动回收到 12 MB 级；**稳态净增 ≈ 0.6–0.7 KB/连接**
  （以各 run 最小 active RSS 为基线）。
- dae 用户态随连接线性：**≈ 82.7 KB/连接**净增；20 000 连接 1.66 GB。
- 线程数两者均 O(核数)（sodama 28 / dae 26）；fd/连接 sodama 4.0（2 socket + 2 pipe）、
  dae 2.0（2 socket，无 pipe）。

## 2. 内核（pre→active 增量，含夹具）

| 组 | N | ΔSlab(MB) | ΔSUnreclaim(MB) | Δsum(named cache)(MB) | Δbpf(MB) |
|---|---|---|---|---|---|
| sodama | 100 | 3.9 | 3.9 | 1.3 | 0.0 |
| sodama | 500 | 21.1 | 21.0 | 8.4 | 0.1 |
| sodama | 1000 | 47.9 | 44.2 | 18.6 | 0.3 |
| sodama | 2000 | 103.3 | 93.2 | 39.4 | 0.5 |
| sodama | 5000 | 282.4 | 244.1 | 103.5 | 1.4 |
| sodama | 10000 | 575.7 | 494.5 | 210.2 | 2.7 |
| sodama | **20000** | **1168.6** | **995.9** | **424.1** | **5.5** |
| dae | 100 | 1.6 | 1.6 | 0.8 | 0.1 |
| dae | 500 | 13.7 | 13.7 | 8.2 | 0.3 |
| dae | 1000 | 32.2 | 29.4 | 18.4 | 0.5 |
| dae | 2000 | 69.1 | 61.4 | 38.8 | 1.1 |
| dae | 5000 | 167.6 | 139.0 | 100.2 | 2.8 |
| dae | 10000 | 390.8 | 325.9 | 205.7 | 4.9 |
| dae | **20000** | **810.3** | **670.3** | **415.4** | **9.8** |

## 3. 对照组（同夹具，无实现）每连接内核开销

| N | ΔSlab/连接(KB) | ΔSUnreclaim/连接(KB) |
|---|---|---|
| 100 | -0.04 | -0.04 |
| 500 | 3.94 | 3.94 |
| 1000 | 4.64 | 4.16 |
| 2000 | 5.76 | 4.70 |
| 5000 | 6.66 | 5.20 |
| 10000 | 6.87 | 5.34 |
| 20000 | 7.12 | 5.47 |

（20 000 连接时对照自身 ~142 MB：客户端 socket + echo socket + 协议栈对象。）

## 4. 内核每连接（扣除对照夹具/内核路径后的实现净增）

| 组 | N=1000 | N=2000 | N=5000 | N=10000 | N=20000 |
|---|---|---|---|---|---|
| sodama Slab/连接(KB) | 44.4 | 47.1 | 51.2 | 52.1 | **52.7** |
| sodama SUnreclaim/连接(KB) | 41.1 | 43.0 | 44.8 | 45.3 | 45.5 |
| dae Slab/连接(KB) | 28.4 | 29.6 | 27.7 | 33.2 | **34.4** |
| dae SUnreclaim/连接(KB) | 26.0 | 26.8 | 23.3 | 28.0 | 28.9 |

**结论（对评审 A/B 的直接回应）**：① 用户态 RSS 优势 ≠ 系统优势——sodama 内核侧
≈ 46–53 KB/连接，**远大于**其用户态 ≈ 0.7–1.2 KB/连接；② 但同链路口径下 sodama 总内核
仍比 dae 低约 35%（52.7 vs 34.4 KB/连接→ 1.17 GB vs 0.81 GB @20k，差值主要来自
dae 的 per-connection Go/协议栈结构；sodama 多出的部分是 splice 的 pipe 结构）；
③ 内核侧随连接线性，属预期（每个连接 6 个 socket：client/网关入/网关出/上游入/上游出/echo）。

## 5. 20 000 连接 slab 归因（sodama，无 `/proc/<pid>/fd` 枚举注入的干净快照）

`meminfo` ΔSlab **+1168.0 MB**、ΔSUnreclaim +964.7 MB；命名 cache 合计 **+579 MB**：

| cache | Δ(MB) | 说明 |
|---|---|---|
| TCP | +284.3 | 120 k socket（6/连接）× `struct tcp_sock` ≈ 2.4 KB |
| sock_inode_cache | +94.3 | socket inode（每 socket 一个） |
| proc_inode_cache | +51.9 | sockfs/procfs 伴生 inode |
| dentry | +43.5 | 伴生目录项 |
| filp | +36.3 | 每 fd `struct file`（80 087 fd） |
| inode_cache | +23.3 | 伴生 inode |
| eventpoll_epi | +12.8 | reactor epoll 每 fd 条目 |
| kmalloc-512 | +8.5 | 协议栈小块（skb 等） |
| lsm_inode_cache / file_lock_cache / kmalloc-cg-192 / anon_vma_chain / kmalloc-cg-96 / lsm_file_cache | +4.5 ~ +7.2（各） | LSM/socket 附属 |
| **命名合计** | **≈579** | 其余（≈589 MB）为 SLUB 页账/partial slab/对齐碎片及未命名 socket 附属分配 |

释放后 3 s：TCP/sock_inode/filp **全部回落**到基线 ±1 MB，dentry/inode 大部分回收——
无结构性泄漏。

### 5.1 pipe 的关键结论（回应评审 A「64 KB×pipe 推算数百 MB」）

- 本项目 `F_SETPIPE_SZ = 1 MiB`；20 000 连接同一时刻持有 **20 000 条 pipe**（status:
  `pipe_created=20000`），容量上界 **20 GiB**；
- 实测 `slabinfo` 中 **不存在任何 pipe 命名 cache**（该内核 pipe 结构走 kmalloc/伴随分配），
  整个 hold 的 Slab 总增量为 1.17 GiB（含全部 socket 链），**远低于容量推算**；
- ⇒ **capacity ≠ resident**：pipe 缓冲页按需分配、读空即释放；以容量推算常驻内存不成立
  （以实测为准，方法学 §0）。

## 6. 已知局限

1. 对照扣除是近似：对照路径每连接 2 个 socket，实现路径 6 个 socket + pipe，
   因此「实现净增」仍含上游 sing-box 服务端 socket 的一半以上（两实现同时含，可横向对比，
   不可当纯实现值）；
2. 20 000 点建立期 6.2 s 内 `pre→active` 覆盖建连与初次搬运，稳态（空闲）数值另见 `after`；
3. 采样为进程存活期瞬时值（非峰值积分）；`task_struct` 等夹具线程项已通过 echo_server 消除；
4. 系统同机环回拓扑，无真实 NIC DMA/中断开销；
5. UDP 与 churn 的系统内存不在本文件扫描范围内：churn 稳态由 soak 曲线覆盖（35 min Slab 漂移 ≈0），UDP 路径由五方 UDP 回归覆盖（40k pkt、20k pps、0 丢包；sodama 代理路径 CPU 630 ms vs 对照 1.6–2.4 s）。

## 7. I6 增量（2026-10-05 下午，ADR-0059）

交付 I6（in-worker prelude / 启动水位 / 入口线程栈）后的复测（同夹具/同口径）：

| 指标 | I2 版本 | I6 版本 |
|---|---|---|
| 启动/空闲 RSS（mem.sh idle） | 26.7 MB | **11.1–11.7 MB**（启动完成即 `malloc_trim`） |
| `N=0` 扫描基线（mem-system） | 28.3 MB | **11.4 MB** |
| churn 线程峰值（hold 2000 + churn 10 s） | 46 | **35**（prelude 不再起线程） |
| hold 2000 / recovery RSS | 28.8 / 12.2 MB | 14.3 / 12.5 MB |
| vless splice 吞吐（4×48 MB） | 16.9 Gbps | 16.4/15.6 Gbps（噪声内） |
| 20 k 扫描活跃 RSS / fd | 23.3 MB / 4.0 per conn | 30.4 MB / 4.0 per conn |
| 内核净增（配对，20 k） | 52.7 KB/conn | 52.5 KB/conn（对照组同刻配对复现） |
| 长稳 | 35 min PASS | **60 min PASS**（RSS +3.1% / Slab −0.5% / SUnreclaim −1.4%，零失败） |

口径不变（pre→active 邻近增量、对照扣除）；I6 仅改变启动基线与 churn 线程，内核侧与每连接净增结论不受影响。

# AF_XDP 引入 sodama 的可行性研究（2026-10-14）

> 触发：72h 生产测试数据等待期间的技术预研——「AF_XDP 引入 sodama 有没有意义」。
> 方法：官方机制梳理（docs.kernel.org/networking/af_xdp）+ 目标硬件实测取证（软路由 /proc/kallsyms、网卡、
> 队列拓扑）+ 项目既有实测数据（`docs/benchmark-report.html`、`docs/memory-report-v2.html`）对照 + 生态调研。
> 密级：内部研究，结论为**否决项**（记录在案，不排期）。

---

## 0 · 一句话结论

**在当前定位（家用/小型网络代理网关）与当前硬件（4× Intel I211 / igb / 1GbE）上，AF_XDP 无可用的加速路径、
无收益场景、且否定性成本极高——不建议引入。** 若未来平台升级到 10G+ 且驱动支持 XDP 零拷贝（ixgbe/ice/mlx5/igc 等），
可重新评估；即便如此，代理场景的收益点（用户态 TCP 栈）也与 sodama 现有架构（内核 TCP + splice 零拷贝 + eBPF 分流）
互相抵消，需要重写数据面才谈得上收益。

---

## 1 · AF_XDP 是什么（机制层面）

- 定位：**包级（per-packet）高性能数据面**——通过 XDP 程序把网卡队列的帧直接重定向到用户态内存缓冲区
  （UMEM 环形队列），由用户态程序直接读写以太帧；`XDP_ZEROCOPY` 模式下驱动 DMA 直接写入用户内存，内核零拷贝。
- 关键前提（官方文档明示）：
  1. 必须有 XDP 程序在跑（`XSKMAP` + `bpf_redirect_map`）；
  2. **驱动支持程度决定性能档位**——驱动无支持时回退 `XDP_SKB`（generic，每包走 skb 分配+拷贝的慢路径，
     "A fallback mode that works for any network device"）；驱动支持时用 `XDP_DRV`（native），
     零拷贝（`XDP_ZEROCOPY`）需要驱动实现 xsk 缓冲区池（`XDP_SETUP_XSK_POOL` / `ndo_xsk_wakeup`）——
     目前仅 ixgbe/i40e/ice/mlx5/bnxt/igc 等少数驱动具备；
  3. 绑定到具体 **队列**（queue id），多队列需配合 ethtool flow steering 或 `ethtool -L combined 1`。
- 拿到帧之后呢？**用户态要自己处理**——AF_XDP 只负责"把包送到你面前"，TCP/IP 协议栈、连接状态、
  重传/窗口/拥塞控制全部自理（或引入用户态栈：smoltcp / gVisor netstack / lwIP）。
- 典型用户：Katran（Facebook L4 负载均衡）、Cloudflare 边缘 DDoS/L4 数据面、部分 5G UPF——
  共同特征：**包级转发/过滤、超高 PPS、不需要完整 TCP 语义**。

## 2 · sodama 数据面现状（对照面）

```
客户端 ──► [TC eBPF 分流（7 个 classifier，sk_assign/TPROXY）] ──► 内核 TCP/IP 栈
                                                                    │
                       reactor（epoll/splice 零拷贝，每连接 0 线程） ◄┘
                                                                    │
                                    VLESS/SS/…（rustls 加密）──► 上游节点
```

- eBPF 挂载点：TC classifier（`sodama/ebpf-rs/src/progs.rs`：lan/wan × ingress/egress + sk_assign），职责是
  **分流与透明重定向**，不是包搬运；
- 跨内核↔用户态的数据搬运：**splice 零拷贝**（明文路径 0 次用户态拷贝；M1 起 VLESS 明文 splice 落地）；
- 既有实测（同一架构、同量级硬件上已达成的数字，`docs/benchmark-report.html`）：
  - direct 24.3 Gbps（夹具上限 ~24.5 Gbps）/ p50 16 µs / CPU≈0；
  - VLESS 明文 splice 16.9 Gbps / CPU 60 ms（搬运 512 MB 口径）；VLESS+TLS 11.6–12.3 Gbps；
  - churn 26,026 conn/s（26 万条连接，fail=0）；10k 连接态 34.8 MB / 29 线程；
  - 报告一句话结论原文：**「真实上限由内核内存与 CPU（加密协议）决定，而不是线程或用户态分配器」**；
  - perf 热点分布（VLESS 明文）：`rep_movs 46.8%`（**rustls 用户态拷贝**）+ 建页 18.8% +
    `skb_splice_from_iter 8.4%`（内核 splice 管线）——**没有一项是"内核收包/软中断"**。
- 即：**瓶颈在加密与拷贝语义，不在收包路径。** AF_XDP 能省的恰恰是"收包路径"。

## 3 · 目标硬件实测取证（决定性否决）

软路由（Kwrt / x86_64 / 内核 6.12.92）：

| 项 | 实测 | 含义 |
|---|---|---|
| 网卡 | 4× Intel **I211**（igb 驱动，1GbE） | 消费级千兆；每口 RX/TX 2 队列 |
| AF_XDP socket 支持 | `dmesg: NET: Registered PF_XDP protocol family` | 内核协议族在 ✓ |
| igb 的 XSK 接入 | `/proc/kallsyms` 中 igb 仅有 `igb_xmit_xdp_ring`；**无任何 `xsk` 相关符号** | 驱动**未接入 AF_XDP 的缓冲池路径** |
| 回退档位 | 按内核文档 → `XDP_SKB`（generic） | 每包 skb 分配+拷贝，性能低于常规 socket 路径 |
| 线速上限 | 1 GbE：64B 小包理论 1.49 Mpps；1500B 满载 ≈ 82k pps | 家用实际峰值流量（<300 Mbps）≈ 25k pps 量级 |

结论：**在 I211 上 AF_XDP 连"零拷贝"的门都进不去（igb 无 ZC 支持、无 xsk pool）**，只能跑 generic 慢路径——
比 sodama 现在用的「TC 分流 + 内核 TCP + splice」**更慢**。这一条已经独立构成否决。

> 备注：Intel 新一代 I225/I226（igc 驱动）自 6.2 起有 XDP ZC 支持；若未来升级网卡（2.5GbE igc），
> AF_XDP 才具备"能用"的硬件前提——但"有意义"仍取决于第 5/6 节的瓶颈与架构判据。

## 4 · 定量：收包是瓶颈吗？

- 该设备实际负载：家庭网络峰值 ~300 Mbps；按 1500B 计 ≈ **2.5 万 pps**；即使全 64B 小包也 ≈ 0.6 Mpps,
  而 x86 单核内核网络栈（NAPI+GRO）可轻松处理 ~1 Mpps 量级、多核线性扩展——**余量 2 个数量级以上**。
- sodama 在同一架构上已经跑出 16.9 Gbps（VLESS splice）/ 26k conn/s 的实测——**远超目标硬件的物理线速**（1GbE）。
- 反证：若收包是瓶颈，perf 热点应在 `net_rx_action`/软中断；实测热点是 rustls 的 `rep_movs`。
  要提速加密路径，AF_XDP 帮不上忙（甚至因为要自己实现栈而更慢）。

## 5 · 引入 AF_XDP 需要付出什么（成本面）

代理与"包级转发"的本质差异：**代理是两个 TCP 终结点的拼接**（客户端侧 + 上游侧），
必须维护完整 TCP 语义；而 AF_XDP 只提供"帧到用户态"的搬运。

要真正用起来，必须至少选一条路：

| 路线 | 内容 | 代价 |
|---|---|---|
| A 纯 L3/L4 转发 | XDP 层直接 redirect/转发，不落地用户态 | 这就是 XDP 本身，**不需要 AF_XDP**；且功能退化为"透明桥"，代理协议（VLESS/TLS/sniff/DNS）全部失效 |
| B 用户态 TCP 栈 | AF_XDP + smoltcp/gVisor/lwIP，自管连接 | 月级工程；重写 relay/reactor/splice/DNS/sniff/分组探测；可靠性风险（重传/拥塞/SACK/TIME_WAIT 等内核十年打磨的路径要重来）；与现有 eBPF TC 分流**钩子位冲突**（XDP 在 TC 之前，分流逻辑得整体上移重写） |
| C 混合（仅特定流量走 XSK） | 例如只把 UDP/DNS 或高 PPS 流导入 XSK | sodama 的 DNS/UDP 量级微小（家用），收益 ≈ 0；复杂度照付 |

另外：即使 B 路线做完，最终收益上限仍是"把收包从内核 softirq 挪到用户态 busy-poll"——
拿 2 个核做 busy-poll 与省下的 softirq 相抵；而 sodama 的 CPU 现状是 **1–10%**，没有可省的。

## 6 · 生态对照（行业信号）

| 项目 | 收包/数据面路线 | 是否用 AF_XDP/DPDK |
|---|---|---|
| **dae**（上游） | eBPF TC/TCX + tproxy | 否 |
| **sing-box** | 内核 socket / TUN | 否 |
| **mihomo / xray / v2ray** | 内核 socket / TUN | 否 |
| Katran、Cloudflare L4、5G UPF | XDP/AF_XDP/DPDK | 是（**场景=包级转发/负载均衡**） |

**没有一个主流代理内核采用 AF_XDP**——因为代理的瓶颈模型（连接管理+加密）与 AF_XDP 的收益模型（包级 PPS）
不重叠。行业选择本身即是证据。

## 7 · 什么条件下重新评估（判据）

同时满足以下 ≥3 条再立项：

1. **硬件**：10G/25G NIC 且驱动支持 XDP ZC（ixgbe/i40e/ice/mlx5/igc）；I211/igb 永不满足；
2. **负载**：目标环境 softirq/ksoftirqd 持续饱和（>70% 单核），且实测 pps > 2–3 Mpps；
3. **业务形态**：sodama 需要变成"边缘转发/负载均衡器"（纯 L3/L4 语义），或
4. **收益可量化**：PoC 证明 AF_XDP+用户态栈的端到端（应用层吞吐/延迟）优于现架构 20%+，
   而非仅包处理微基准（微基准领先不代表端到端领先；代理的端到端里包处理占比极小）。

## 8 · 更高性价比的替代优化方向（若将来遇到数据面瓶颈）

优先级从高到低（现有架构内）：

1. **加密路径**（真正的 CPU 大头）：kTLS（已有 M2 实验 +5.6%）、AES-NI/GCM 批量、会话复用；
2. **relay 侧**：io_uring 收发批量化 / splice 池化（FD 已优化）；
3. **连接管理**：连接池/复用（上游 keep-alive），减少 conn/s 压力；
4. **XDP/TC 微调**：GRO/GSO 参数、RSS 队列绑定、TCX 挂载（已有 eBPF 基础上小步优化）；
5. 内存侧已极致（bounded：30 MB 级 / 稳定线程数），无需动。

## 9 · 记录

- 结论：**AF_XDP = 已研究 · 否决（条件性）**——写入 devlog §15；重新评估判据见 §7。
- 本次未做任何 PoC（§3 已在硬件层否决；在 I211 上跑 generic 模式的对照实验没有意义）。

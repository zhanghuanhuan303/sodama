# sodama 性能对比报告（vs dae / sing-box / v2ray）

> P33.2 · 2026-10-04 · 第二轮加深：高速 ss 上游（shadowsocks-rust）、全双工基准夹具、
> 四路对比 5 轮中位数、并发扩展、perf 热点剖面、内存/线程规模。
> 优化方向（基于本报告的实测数据）见 [`optimization-roadmap.md`](./optimization-roadmap.md)。

- **被测版本**：sodama `f10298c`+（rename 后）· dae **v2.1.1**（官方 release）·
  sing-box **1.14.2**（pacman）· v2ray **5.52.0 (V2Fly)**（pacman）
- **环境**：Intel i9-9900KF（8C/16T）· 内核 `6.18.54-2-lts` · Arch Linux ·
  全部进程在同一台机器、不同 netns
- **复现**：`sudo lab/perf/run.sh all`（`SS_UPSTREAM=ssserver ROUNDS=5`）

## 方法（v2 口径）

```text
sodama_client ns                                   sodama_wan ns
10.0.0.2 ──veth── landae(10.0.0.1)  [网关]  wan(10.9.9.1) ──veth── wanpeer(10.9.9.2…)
                      ↑ eBPF 或 tproxy                    ├─ bench_io :9999   (direct 目标)
                                                          ├─ bench_io :8080   (代理目标)
                                                          ├─ python http :8390 (健康检查)
                                                          └─ ssserver :8388   (共同上游)
```

- **direct 路径**：`client → 10.9.9.2:9999`（不经过代理，测数据面转发开销）；
- **ss 路径**：`client → 1.1.1.1:8080`，各实现经**同一个** WAN ns 内
  **shadowsocks-rust 1.25 `ssserver`**（chacha20-ietf-poly1305，`--tcp-no-delay`）
  转发；第一轮使用 python 上游，其 GIL 约 2.4 Gbps 是共同天花板（见附录 A），
  本报告全部以 ssserver 为准；
- 拦截方式各用其原生方案：sodama/dae 用 eBPF（TC），sing-box/v2ray 用
  nftables tproxy（各官方推荐部署）；
- **负载夹具（本轮加固，v2）**：`lab/bench_io` C 端点，每轮 `48MB × 4 流` 全双工
  回显 + 500 次 RTT；服务器为**全双工 echo**（预分配 ring，`BENCH_RING_MB=128`）。
  旧版单线程 `read→write` 回显在半双工下会与上游实现形成「互相等窗口」的
  环形依赖，偶发 60s 级假死（与本项目代码无关，属夹具缺陷；已修复，详见
  §夹具校准）。4 流 48MB 下夹具自身环回上限 ~24.5 Gbps、RTT ~10-11 µs；
- 预热 1 轮、取 5 轮**中位数**；CPU = 网关进程 `utime+stime` 增量（不含上游/
  夹具进程）；吞吐对比关闭半关闭（`BENCH_NOSHUT=1`，各家半关闭语义差异另有
  lab 专项覆盖）。

## 结果 A：四方对比（5 轮中位数）

| 实现 | direct | direct p50 | direct CPU | ss | ss p50 | ss CPU | RSS | 线程 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **sodama** | 24 319 Mbps | 16 µs | ~0 ms | 9 487 Mbps | 46 µs | 590 ms | **28.6 MB** | **11** |
| **dae v2.1.1** | 24 200 Mbps | 16 µs | ~0 ms | 9 357 Mbps | **43 µs** | **460 ms** | 54.2 MB | 20 |
| **sing-box 1.14.2** | 22 566 Mbps | 27 µs | 80 ms | **10 615 Mbps** | 47 µs | 500 ms | 66.8 MB | 18 |
| **v2ray 5.52.0** | 13 522 Mbps | 34 µs | 650 ms | 6 289 Mbps | 53 µs | 700 ms | 72.2 MB | 26 |

口径：吞吐 = 单工方向（每流发 48MB 并原样收回）；CPU = 该路径搬运 512MB
（256MB 上行 + 256MB 下行）的进程 CPU；RSS/线程 = 负载期间中位值。

**夹具边界**：4 流 48MB 时夹具环回自身上限 ~24.5 Gbps（§夹具校准），
因此 sodama/dae 的 direct 数字是**夹具受限**的下界，不代表数据面上限
（§结果 B 中 `64×1MB` 达 35.2 Gbps）。ss 路径（<24.5 Gbps）不受此限。

### 与第一轮（python 上游）对比

第一轮 python 上游把 ss 路径压到 0.5–2.8 Gbps（各实现一起受损）；换
ssserver 后 ss 路径的真实差距显现：sing-box 领先（10.6 Gbps），sodama 与 dae
基本持平（9.49 / 9.36），v2ray 明显落后（6.29）。sodama 的 ss CPU（590ms）比
dae/sing-box 高 18–28%，是当前最大短板——根因见 §perf 剖面（AEAD 占 ~41%、
内核拷贝 ~18%）。

## 结果 B：sodama 并发扩展（ssserver 上游）

`lab/perf/scaling.sh`，每行 = `MB×流数` 单工下行；CPU 为 sodama 进程增量。

| 路径 | 1×64MB | 2×64MB | 4×64MB | 8×64MB | 64×1MB |
|---|---:|---:|---:|---:|---:|
| direct | 8.8 Gbps | 17.5 | 24.5 | 21.9 | **35.2** |
| direct CPU | 0 ms | 0 | 0 | 0 | 0 |
| ss | 4.12 Gbps | 6.57 | 9.91 | **10.90** | 9.38 |
| ss CPU | 180 ms | 410 | 850 | 1690 | 260 |
| ss CPU/Gbps | 44 ms | 62 | 86 | **155** | 28 |
| relay（无加密） | 9.0 Gbps | 15.8 | 16.2 | 15.0 | 16.5 |
| relay CPU | 30 ms | 80 | 490 | 1100 | 110 |

- direct：0 用户态 CPU（eBPF 内核直转），64 流小包到 35.2 Gbps；4 流受夹具限。
- **ss：吞吐在 ~10.9 Gbps 饱和，4→8 流 CPU 翻倍只换 +10% 吞吐**（86→155 ms/Gbps），
  说明用户态加密环路已触及单点效率瓶颈（AEAD+拷贝+syscall，见 §perf 剖面）。
- relay（`--dialer direct` 用户态泵，无加密）：8 流 CPU 1.1s 换 15 Gbps，
  成本几乎全部是 socket 拷贝（§perf 剖面 rep_movs 49% + 建页 18.5%）。
- RSS 恒定 26.5–32.5 MB、稳态线程 11，不随流数增长（连接并发峰值见结果 C）。

## 结果 C：内存与线程规模

| 场景 | RSS | 线程 |
|---|---:|---:|
| 空闲（已加载全部 eBPF/DNS/状态面） | **27.3 MB** | **11** |
| 64 并发 ss 连接（4MB×64，9.78 Gbps） | 35.9 MB（峰值） | 100（峰值） |
| 64 流小包后（夹具串行） | 32.5 MB | 11（稳态） |

- 每并发连接 ≈ 135 KB（2 个泵线程栈 + 64KB 泵缓冲 + relay 记账）；
- 28.6 MB 中 ~19.7 MB 为匿名页、~5.1 MB 为文件页（二进制/BTF 只读），PSS 24.8 MB；
- 线程数由「每连接 1–2 个 OS 线程 + 看门狗」模型决定——连接规模上量时是
  首要风险（见优化方向 P2）。

## 结果 D：VLESS（明文 / TLS，四方对比 · 2026-10-04 加测）

上游为 WAN ns 内同一 sing-box VLESS 服务端（:8543 明文 / :8544 自签 TLS），
与 ss 同口径（48MB×4、5 轮中位；脚本 `PROXY_PROTO=vless|vless-tls run.sh all`）。
完整实测、perf 剖面与优化提案见 **[`vless-proposal.html`](./vless-proposal.html)**。

| 实现 | vless 明文 | p50 | CPU | vless-tls | p50 | CPU | RSS | 线程 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **sodama** | 12 225 Mbps | **40 µs** | 380 ms | 11 624 Mbps | **46 µs** | **420 ms** | **29.8 MB** | **11** |
| dae v2.1.1 | **12 689** | 42 µs | 410 ms | 11 453 | 55 µs | 450 ms | 59.5 MB | 20 |
| sing-box 1.14.2 | **16 588** | 42 µs | **80 ms** | **12 003** | 53 µs | 450 ms | 69.3 MB | 18 |
| v2ray 5.52.0 | 10 739 | 52 µs | 710 ms | 7 529 | 58 µs | 800 ms | 74.3 MB | 25 |

要点：① VLESS+TLS 下 sodama 综合第一梯队（吞吐 ≈ sing-box 的 97%、CPU/延迟/内存最优）；
② 明文路径落后 sing-box 是**零拷贝（splice）差距**（其 CPU 80ms vs 380ms；perf：
`rep_movs` 46.8% + 建页 18.8%）；③ **TLS（AES-NI GCM）比 ss 的 chacha20-poly1305 更快
更省**（11.6G/420ms vs 9.5G/590ms）；④ Vision-over-TLS 为待补的主流组合缺口。

### M1 落地后（2026-10-04 晚，同口径复测）

splice 零拷贝（Direct / VLESS 明文；见 `optimization-roadmap.md` O3）已上线：requests header 在
拨号时发送、响应头由 relay 首读消费，之后双向 `splice(socket→pipe→socket)`，EOF→`SHUT_WR`
半关闭与旧泵语义一致，EINVAL 自动回退，`--no-splice` 可关。

| 场景 | M1 前 | M1 后 |
|---|---:|---:|
| vless 48MB×4（5 轮中位） | 12 225 Mbps / 380 ms / p50 40µs | **16 926 Mbps / 60 ms / p50 36µs** |
| vless 8×64MB（scaling） | 11 678 Mbps / 1 100 ms | **16 177 Mbps / 190 ms** |
| relay 8×64MB（scaling） | 14 864 Mbps / 1 100 ms | **21 580 Mbps / 150 ms**（4 流 23 147） |
| vless-tls（回归） | 11 624 Mbps / 420 ms | 11 670 Mbps / 420 ms（加密路径自动跳过 splice） |
| perf 热点（vless 明文） | `rep_movs` 46.8% + 建页 18.8% | 转为内核 splice 管线（`skb_splice_from_iter` 8.4% 居首） |

证据：`splice_total=720 / fallbacks=0`（status/metrics，Prometheus 同源）；lab `verify` 9/9；
`cargo test` 236/236；eBPF `bpf_printk` 已门控（默认关：单次传输 trace 行 600+ → 0，`--ebpf-debug` 开）。

## perf 热点剖面（8×64MB，`perf record -g`）

**ss 路径（9.5 Gbps，sodama 进程 CPU 1690ms/512MB）**：

| 类别 | 占比 | 明细 |
|---|---:|---|
| AEAD（chacha20-poly1305） | **~38–41%** | chacha20 AVX2 21.3% + poly1305 AVX2 12.5% + AVX2 内联片段 ~4% |
| 内核 socket 拷贝 | ~18% | `rep_movs_alternative` 13.8%（`pump` read 6.9% + `SsReader::read_exact` 4.8% + send 2.1%） |
| 内核 skb 建页/分配 | ~5% | `clear_page_erms` 4.0% 等 |
| 用户态 libc memcpy/memmove | ~3.4% | padding/copy 路径 |
| 其余 | 分散 | TCP/BPF/调度，无单一大锁热点 |

**relay 路径（13.8 Gbps，无加密）**：

| 类别 | 占比 | 明细 |
|---|---:|---|
| 内核 socket 拷贝 | **49.4%** | `rep_movs_alternative`（recv+send 两个方向） |
| 内核 skb 建页/分配 | **18.5%** | `clear_page_erms` |
| 其余 | 分散 | TCP 栈、veth、BPF（`bpf_bprintf_prepare` 0.3–0.45%） |

**direct 路径（系统级采样）**：热点几乎全在 bench 客户端自身（`stream_main`
校验 17.8% + `stream_writer` 9.8% + 客户端内核拷贝 31%），eBPF 数据面没有出现
≥0.4% 的符号；`bpf_printk`（每报文的 `sodama0peer_ingress` / `sodama0_ingress`）
仅 0.3–0.45%，当前负载下不致命，但属纯开销，见优化方向 P3。

## 夹具校准（v2 全双工 echo 环回，WAN ns 内）

| 负载 | 吞吐 | 备注 |
|---|---:|---|
| 48MB×4 环回 | 22.7 / 24.5 / 24.8 Gbps | 3 次；客户端 pattern 填充+校验为极限 |
| 500 RTT 环回 | p50 10–11 µs | 夹具地面延迟 |
| 48MB×4 环回（旧半双工夹具） | **偶发 60s 假死** | 与上游实现形成环形依赖，已修复 |

> 教训：基准夹具必须是全双工；半双工 echo 会在多跳大缓冲管道中制造
> 「都在写、都不读」的假死，污染 ss 路径数据。`lab/bench_io.c` 已改为
> 预分配 ring 的全双工 echo，并在 400 轮混合压测中 0 失败验证。

## 分析

1. **direct（内核快路径）**：sodama 与 dae 同级（24.3/24.2 Gbps，CPU≈0，p50 16µs），
   且受夹具限制；64 流小包口径 sodama 达 35.2 Gbps。sing-box tproxy 略低
   （22.6，CPU 80ms），v2ray 用户态转发明显掉队（13.5，CPU 650ms）。
2. **ss 路径**：sing-box 10.6 G 领先；sodama 9.49 G ≈ dae 9.36 G；v2ray 6.29 G。
   sodama 的 CPU 代价最高（590ms vs 460/500），吞吐略低于 sing-box——
   **这是下一阶段优化的主战场**（AEAD 零分配 + syscall 合并 + 拷贝削减）。
3. **延迟**：direct sodama/dae 16µs（内核）；sing-box 27µs、v2ray 34µs。
   ss 路径四家 43–53µs，sodama 46µs 居中；夹具地面 10–11µs。
4. **内存**：sodama 28.6 MB，为 dae 的 53%、sing-box 的 43%、v2ray 的 40%；
   空闲 27.3 MB，64 并发连接峰值仅 +8.6 MB。
5. **规模**：ss 路径 8 流饱和 ~10.9 Gbps 且 CPU 双倍增长（用户态加密环路的
   单点效率问题）；relay 路径拷贝成本占 ~68%，零拷贝（splice）空间巨大；
   每连接 1–2 OS 线程的模型在万级连接前需要改造。

## 口径与边界（如实）

- 同一台机器、本地 veth，**不含真实公网**与远端节点；绝对数字不可外推；
- 4×48MB 的 direct 数字受夹具（客户端 pattern 校验）限制，仅用于**四方同口径
  对比**；sodama 自身能力看 `64×1MB`（35.2 Gbps）与历史 8 流 35.8 Gbps；
- ss 上游为 shadowsocks-rust（多线程 tokio），仍可能成为高并发下的共同天花板；
  四方共用同一上游，横向对比成立；
- dae 为官方 v2.1.1 release；v2ray 为 V2Fly 默认参数（未针对性能调参）；
- CPU 只统计网关进程本体，不含内核 eBPF 执行时间（TC 程序）与上游/夹具进程。

## 附录 A：第一轮（python ss 上游）数据

python 上游 GIL 约 2.4 Gbps，把 ss 路径全部压平；保留作为方法演进记录。

| 实现 | direct | ss | ss CPU |
|---|---:|---:|---:|
| sodama | 30.0 Gbps | 2.20 Gbps | 610 ms |
| dae v2.1.1 | 29.7 | 1.93 | 600 ms |
| sing-box | 26.9 | 2.73 | 480 ms |
| v2ray | 17.6 | 0.54 | 1730 ms |

## 复现

```bash
# 依赖：root；python3；ssserver（shadowsocks-rust）；sing-box/v2ray 已安装；
#       dae release 解包到 /tmp/perf，或 DAE_BIN=<path> 指定
lab/perf/run.sh build
sudo ROUNDS=5 PROXY_PROTO=vless lab/perf/run.sh all        # VLESS（默认协议）
sudo ROUNDS=5 PROXY_PROTO=ss SS_UPSTREAM=ssserver lab/perf/run.sh all   # ss 口径对照
sudo PROXY_PROTO=vless lab/perf/scaling.sh all             # 并发扩展（sodama）
sudo lab/perf/run.sh down
```

配置与脚本：`lab/perf/rules.perf.dae`、`dae.dae`、`singbox.json`、`v2ray.json`、
`run.sh`、`scaling.sh`；夹具：`lab/bench_io.c`（`BENCH_RING_MB=128`）。

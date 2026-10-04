# sodama 性能对比报告（vs dae / sing-box / v2ray）

- **日期**：2026-10-04
- **被测版本**：sodama `f10298c`（rename 后）· dae **v2.1.1**（官方 release）·
  sing-box **1.14.2**（pacman）· v2ray **5.52.0 (V2Fly)**（pacman）
- **环境**：Intel i9-9900KF（8C/16T）· 内核 `6.18.54-2-lts` · Arch Linux ·
  全部进程在不同 netns 的同一台机器上
- **复现**：`sudo lab/perf/run.sh all`（配置与负载脚本在 `lab/perf/`）

## 方法

同一 lab 拓扑、同一上游、同一负载（`lab/bench_io`，C 实现，零逐包分配）：

```text
sodama_client ns                                   sodama_wan ns
10.0.0.2 ──veth── landae(10.0.0.1)  [网关]  wan(10.9.9.1) ──veth── wanpeer(10.9.9.2…)
                      ↑ eBPF 或 tproxy                    ├─ bench_io :9999   (direct 目标)
                                                          ├─ bench_io :8080   (代理目标)
                                                          ├─ python http :8390 (健康检查)
                                                          └─ python ss  :8388 (共同上游)
```

- **direct 路径**：`client → 10.9.9.2:9999`（不经过代理，测数据面转发开销）；
- **ss 路径**：`client → 1.1.1.1:8080`，各实现经**同一个** WAN ns 内 python ss
  （chacha20-ietf-poly1305）转发；
- 拦截方式各用其原生方案：sodama/dae 用 eBPF（TC），sing-box/v2ray 用
  nftables tproxy（同为官方推荐部署）；
- 负载：每轮 `48MB × 4 流` 回显（256MB 下行 + 256MB 上行）+ `500 次 RTT`；
  预热 1 轮、取 3 轮**中位数**；CPU = 网关进程 `utime+stime` 增量；
- 吞吐对比关闭半关闭（`BENCH_NOSHUT=1`）：各家半关闭语义有差异（另有 lab 专项
  覆盖），避免混入吞吐口径。

## 结果（3 轮中位数）

| 实现 | direct 吞吐 | direct p50 | direct CPU | ss 吞吐 | ss p50 | ss CPU |
|---|---:|---:|---:|---:|---:|---:|
| **sodama** | **30.0 Gbps** | 14 µs | ~0 ms | 2.20 Gbps | 65 µs | 610 ms |
| **dae v2.1.1** | 29.7 Gbps | 13 µs | ~0 ms | 1.93 Gbps | 61 µs | 600 ms |
| **sing-box 1.14.2** | 28.0 Gbps | 22 µs | 60 ms | **2.76 Gbps** | **54 µs** | **480 ms** |
| **v2ray 5.52.0** | 18.1 Gbps | 37 µs | 510 ms | 0.54 Gbps | 67 µs | 1740 ms |

（吞吐为单工方向口径：每流发 48MB 并原样收回；CPU 为该路径搬运 512MB 的总量；
direct CPU ~0 表示零用户态参与。）

## 分析

1. **direct（内核快路径）**：sodama 与 dae 同为 eBPF 分流，direct 流量不经用户态，
   31/30 Gbps 且 CPU≈0，基本摸到 veth/内存带宽；sing-box 28 Gbps 虽走 tproxy
   用户态但环路极短，表现意外好；v2ray 18 Gbps 且每 512MB 消耗 0.5s CPU，
   用户态转发开销显著。
2. **ss 路径**：sing-box 反超（2.76 Gbps），其 Go AEAD + tproxy 环路在该场景
   最优；sodama 2.20 Gbps（Rust ss + eBPF 重定向 + relay 泵），约为 dae 的 1.14 倍；
   v2ray 0.54 Gbps，吞吐与 CPU（1.74s）都明显落后。
3. **延迟**：direct 路径 sodama/dae 13-14µs（内核转发），sing-box 22µs，
   v2ray 37µs；ss 路径四家 54-67µs，差异主要来自建连与用户态环路。
4. **CPU 效率**：ss 路径 sodama 610ms 与 dae 600ms 相当，sing-box 480ms 最优，
   v2ray 1740ms。

## 口径与边界（如实）

- 同一台机器、纯本地回环 veth，**不含真实公网**与远端节点；绝对数字不可直接
  外推到生产链路上的端到端吞吐；
- ss 上游为 python 实现（WAN ns 内），在 3 Gbps 量级可能成为天花板之一——
  四家共用同一上游，横向对比仍成立，但都会受其制约；
- sodama 的 ss 路径为「eBPF 重定向 + 用户态 relay + Rust ss」，未启用任何
  offload（ss 不支持内核拼接）；
- dae 使用官方 v2.1.1 release（与我们对照的 main@e3fee8f 并非同一版本）；
- v2ray 使用 V2Fly 5.52 默认参数（`domainStrategy: AsIs`、单线程 dispatcher），
  未做针对性能的调参。

## 复现

```bash
# 依赖：root；python3；sing-box/v2ray 已安装；dae release 解包到 /tmp/perf，
#       或 DAE_BIN=<path> 指定
lab/perf/run.sh build
sudo lab/perf/run.sh all        # 四个实现依次跑 + 汇总
sudo lab/perf/run.sh down
```

配置：`lab/perf/rules.perf.dae`（sodama）、`lab/perf/dae.dae`（dae v2）、
`lab/perf/singbox.json`、`lab/perf/v2ray.json`。

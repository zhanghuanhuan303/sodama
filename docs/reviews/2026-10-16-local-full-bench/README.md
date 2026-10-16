# 2026-10-16 本机全量强度轮 · 原始数据

本目录为本轮压测的原始 TSV 数据归档。配套报告：`docs/benchmark-report-v4.html`。

## 环境与口径

- **机器**：Arch / Linux 6.18.54-2-lts / i9-9900KF 8C16T / 31 GB（与 atlas 基准机同款）
- **网络**：wlan0 直连（不经软路由）。本目录全部数据均为 netns 本机对拍，与公网路径无关；
  真实公网口径（real.sh）需节点 URL，未在本轮采集。
- **被测构建**：sodama `main@e5db7fd`（A2 批次 5）+ 1 项未提交修复：
  `ebpf-rs/src/flow.rs` 的 `conn_save` 参数打包（修 e87ea69 引入的 7 参数 BPF 调用触发的
  验证器 `R11 is invalid` 拒载——即「补全后内核」在宿主 6.18 上原本无法加载，见报告 §5.1）。
- **对照**：dae v2.1.1（官方 dae-linux-x86_64 预编译）、sing-box 1.14.2、v2ray 5.52.0、
  mihomo 1.19.32、shadowsocks-rust ssserver 1.25.0（ss 上游；非 python GIL 上限）。
- **关键口径**：全部命令前缀 `SKIP_NET_OFFLOAD=1`。新 lab（47c603a 起）默认关闭
  dae0/dae0peer（控制面对）offload，会使**标准代理路径**吞吐减半（17.3→8.5 Gbps）；
  历史标准（M1 时代）无此动作，故为本轮统一口径。见报告 §5.2。
- **夹具**：`lab/bench_io`（48MB×4 流全双工吞吐/lat；udpblast 40000×256B）；
  `lab/scale/conn_scale`（hold/churn）；`lab/scale/echo_server`（万级连接回显）。

## 文件清单

| 文件 | 内容 |
|---|---|
| `final-vless.tsv` | 吞吐四方对拍 · VLESS 明文（5 轮 + 1 预热；direct 同轮） |
| `final-ss.tsv` | 吞吐四方对拍 · ss（chacha20-ietf-poly1305，5 轮） |
| `final-vless-tls.tsv` | 吞吐四方对拍 · VLESS+TLS（rustls，3 轮） |
| `final-scaling.tsv` | 并发扩展 1/2/4/8/64 流（direct / vless / relay 三路径） |
| `final-mem.tsv` | 五方内存五阶段（idle→load→hold 2000→churn→recovery） |
| `mem-system-control.tsv` | 系统内存四层扫描 · 对照组（无实现）100→50 000 |
| `mem-system-sodama.tsv` | 同上 · sodama |
| `mem-system-dae.tsv` | 同上 · dae v2.1.1 |
| `mem-system-singbox.tsv` | 同上 · sing-box 1.14.2 |
| `final-udp.tsv` | UDP 五方对拍（40 000×256B @20 000pps；sodama 因 A2-5 回归失败零丢包目标） |
| `soak-curve.csv` / `soak-summary.txt` | 60 分钟长稳曲线（234 点）与判据（RSS FAIL +17.6%，其余 PASS） |
| `wt-m1-ss.tsv` | ss 回归二分锚点：M1（4739410）10 轮 |
| `probe-33d884c.tsv` ~ `probe-d4ac773.tsv` | ss 回归二分中间探针（6 轮/点，见报告 §5.3） |

## 判读注意

- `*.tsv` 为 tab 分隔；吞吐行格式：`impl workload mbps p50_us p99_us cpu_ms wall_s rss_kb threads`。
- mem-system 行格式见脚本头注释（`lab/perf/mem-system.sh`），其中 `slab_subset` 列含关键 slab cache 明细。
- UDP 行的 `loss` 为绝对丢包数（40 000 口径）。

# 2026-10-17 真实 CF 边缘节点公网轮 · 原始数据

本目录为「真实订阅节点（CF 边缘 worker）」公网口径压测的原始数据归档。配套报告：
`docs/benchmark-report-v4.html` §11。

## 环境与口径

- **机器**：Arch / Linux 6.18.54-2-lts / i9-9900KF 8C16T / 31 GB；**wlan0 直连（不经软路由）**。
- **被测构建**：sodama `dev@9f1179a`（含 R11、UDP GSO、reactor 分派三项修复；`lab.sh build` +
  `lab/build-ebpf-rs.sh` 全量重建后实测）。
- **对照**：dae **v2.1.1**（官方预编译 `/tmp/perf/usr/bin/dae`）、sing-box **1.14.2**；
  另有 v2ray 5.52.0 作参考客户端（不参与对比，仅用于诊断节点/目标行为）。
- **拓扑**：client ns（`sodama_client`，10.0.0.2）→ 网关（被测实现，透明代理 tproxy/nft）
  → 宿主 wlan0 → **真实 CF 边缘节点（异机）** → 公网目标。被测实现与节点之间是真实公网链路
  （实测 RTT ≈ 180–190 ms）。
- **目标**：`https://proof.ovh.net/files/10Mb.dat`（宿主机直连 26–50 Mbps；经节点 17–20 Mbps）。
- **每轮**：client ns 内 `curl -fsS --resolve <host>:443:<pinned-ip>`（-f + 校验 HTTP 200 +
  `TARGET_EXPECT_BYTES=10485760` 短传输判失败），轮次内最多 6 次尝试（`ROUND_ATTEMPTS=6`），
  成功轮计入统计。`ROUNDS=17`，四实现（sodama / dae / singbox / direct）各 17 轮。

## 订阅与节点（凭据不入库）

- 订阅为 base64，解码后 **20 个 VLESS+WS+TLS 节点**：`host/sni = sub3.example.com`、
  `fp=chrome`、`path=/proxyip=<8 个 IP>`、端口 ∈ {2053, 2083, 2087, 2096, 8443}、
  20 个不同 CF 边缘 IP（104.26.x / 172.67.x）。
- **worker 只接受域名目标**：以 IP 为目的地的 VLESS 请求会被直接关闭（上一轮实测；本轮三方
  实现均以「嗅探 → 域名拨号」通过，日志证据见 `evidence.txt`）。
- **出口可控**：`path` 里的 `proxyip=` 列表即 worker 的出口池。默认 8 出口随机/轮转，实测
  抖动大；本轮**固定到单一实测健康出口**（203.0.113.68）后稳定复现 ~2.3 MB/s。
- 对比轮的固定后端：CF 边缘 `203.0.113.123:2053`（三方共用同一 URL——节点 URL 由
  `real.sh prepare` 固定到一个 TCP 可连后端，避免多 A 记录不可比）。

## 文件清单

| 文件 | 内容 |
|---|---|
| `real-final3.tsv` | **主数据集**：17 轮 × 4 实现；固定出口；含短传输判定+重试；7 列（含内核侧 CPU） |
| `real-final.tsv` | 次数据集（同夜第一次 17 轮）：出口池未固定、无短传输判定；5 列（仅进程口径） |
| `summary.txt` | 汇总统计（两种聚合口径 + 内核侧自助法 90% CI） |
| `evidence.txt` | 三方「域名拨号」日志证据、sing-box 1.14 源码事实、目标/节点探测记录 |

TSV 列（`real-final3.tsv`）：`impl  mbps  cpu_ms(进程)  bytes  seconds  kern_ms(轮内内核侧)  base_ms(前置 1s 空闲窗口内核侧)`

## 主数据集结果（17 轮中位 / 合计口径）

| 实现 | 交付吞吐 Mbps 中位 [min,max] | 进程 CPU ms/GB | 内核侧净 CPU ms/GB（90%CI） | 合计 ms/GB | 相对 sodama |
|---|---|---|---|---|---|
| **sodama** | **19.3** [17.5, 19.7] | **2 952** | 9 690 [4 179, 14 576] | **12 642** | base |
| dae v2.1.1 | 18.6 [17.1, 19.7] | 4 266 | 20 165 [11 371, 29 263] | 24 431 | **+93%** |
| sing-box 1.14.2 | 19.3 [16.9, 20.3] | 4 111 | 24 659 [15 528, 34 257] | 28 770 | **+128%** |
| direct（无代理基线） | 36.0 [26.0, 49.8] | 0 | 13 210 [8 253, 18 652] | 13 210 | — |

- 三方代理吞吐相当（18.6–19.3 Mbps，中位差 ≤4%）：**节点出口带宽（≈2.3–2.5 MB/s）是共同上限**，
  直连基线 36 Mbps 说明瓶颈不在本机与本地网络。
- 进程口径（`/proc/<pid>/task/*/schedstat`，ns 级、几乎无噪声）：sodama 比 dae 低 **31%**、
  比 sing-box 低 **28%**（每 GB）。
- 内核侧口径（`/proc/stat` system+irq+softirq，逐轮扣除前置 1 s 空闲基线）：sodama 点估计约为
  dae 的 **0.48×**、sing-box 的 **0.39×**；自助法 90% CI 与 dae 略有重叠，故报告以进程口径为主、
  内核口径为辅（两者排序一致）。
- 次数据集（出口未固定、条件更差）进程口径复现同一排序：sodama 2 947 / dae 4 465 / singbox 4 374 ms/GB。

## 节点侧坑与处置（影响可比性，必须在报告里读）

1. **出口池抖动 → 传输截断**：默认 8 出口路径下，v2ray 参考客户端 20 轮中 **17 轮**在 2.4–3.0 s
   被截断（`SSL routines::unexpected eof while reading`，体积 16 KB–1.5 MB）；换 CF 边缘 IP 无效，
   固定单一健康出口后降到 ~25%（残余为节点侧固有抖动）。脚本靠 `TARGET_EXPECT_BYTES` 判失败 +
   单轮最多 6 次重试消化。
2. **CacheFly 配额 403**：`cachefly.cachefly.net` 经节点可用但会返回
   `403 Access Denied`（`server: CFS 1124`、`x-cf-quota-max-delivery-conns: 500`），且宿主机直连
   不可达（无法做 direct 基线）。
3. **speed.cloudflare.com 经该 worker 不可用**：宿主机直连正常（10–11 Mbps），经节点 20 s 超时。
4. **sing-box 1.14 无法用嗅探结果回写拨号目标**（源码事实，见 `evidence.txt`）：sniff action
   已无 override 字段，1.11 起的 `sniff_override_destination` 仅遗留 no-op；本轮改用 route action
   的 `override_address`（支持域名）静态指定目标域名，并保留 sniff 规则以对齐三方工作量。

## 复现命令

```bash
# 0) 构建（含 R11/GSO/reactor 修复）
cd sodama && cargo build --release && lab/build-ebpf-rs.sh

# 1) 节点 URL：/tmp/real-node.url 一行 vless://…（默认取订阅解码后的一个节点；
#    本轮为消除出口抖动，将 path 改写为单一实测健康出口：
#    path=/proxyip=203.0.113.68）

# 2) 建拓扑 + 固定目标 IP
sudo lab/perf/real.sh prepare            # 目标默认 proof.ovh.net（见脚本头「目标选择」）

# 3) 四实现 × 17 轮（主数据集）
sudo ROUNDS=17 ROUND_ATTEMPTS=6 TARGET_EXPECT_BYTES=10485760 \
     RESULTS=/tmp/real-final3.tsv bash lab/perf/real.sh all

# 4) 清理
sudo lab/perf/real.sh down
```

单实现：`sudo ROUNDS=17 … bash lab/perf/real.sh bench sodama|dae|singbox|direct`。

## 判读注意

- `direct` 行没有代理进程，其「进程 CPU」恒为 0；它的内核侧值即纯内核转发成本，且跑在 36 Mbps
  （是代理轮的 ~1.9 倍速），**速率不同不可直接按 GB 比较**，仅作数量级参照。
- 内核侧口径为宿主整机 system+irq+softirq 增量：包含客户端 TCP、eBPF、softirq 与被测进程的
  系统调用开销，也包含少量与本测无关的后台内核活动（已按前置 1 s 基线逐轮扣除；剩余噪声体现在
  CI 宽度上）。该口径的用途是**给 sodama 的 eBPF 工作量一个上界估计**，而不是精确差值。
- 三方实现串行测量（非并行），同一时段、同一节点后端、同一出口、同一目标；测试顺序固定为
  sodama → dae → singbox → direct。cross-run 漂移由次数据集（同夜更早 17 轮）交叉验证。
- 全程 CPU governor = `powersave`（未切 performance；节点带宽是瓶颈，不受本机频率影响）。

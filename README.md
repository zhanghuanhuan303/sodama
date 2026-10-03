# dae-rust · dae 核心数据面的 Rust 重写研究

[`dae`](https://github.com/daeuniverse/dae)（Go + eBPF 的透明代理网关）核心数据面的
**Rust 重写实验工程**：可运行、可对拍、可复现，附带从源码研究到架构决策的完整文档。
*An experimental, ground-up Rust (aya-ebpf/aya) rewrite of dae's core datapath, with
byte-exact parity tests against dae's Go rule compiler and a netns test lab.*

- **数据面（eBPF）**：8 个程序（7 个 TC classifier + 1 个 `sk_skb` offload verdict）
  + 14 张 BTF map，全部为 Rust/aya-ebpf，**无 C 数据面**（P9+，ADR-0025）。
- **控制面（用户态）**：Rust + aya 加载器——`.dae` 全量配置解析与规则编译、
  透明 DNS 接管（缓存/TCP/regex/EDNS）、TCP relay / UDP NAT / TCP offload、
  协议栈 shadowsocks / trojan / vless（tcp/ws）/ vmess / tuic / hysteria2 / **anytls**（含 UDP 与会话）、
  状态面 / 热重载 / 指标导出；vless 的 **WebSocket 传输**与 **AnyTLS** 已接入真实订阅节点
  （ADR-0026 / ADR-0027）。
- **lab**：netns 拓扑（标准 + 单臂）、`verify` 9 用例、DNS / 转发面 / 协议梯 / 运维专项、
  soak、与 dae 原版 Go 规则编译器的**逐字节对拍**、真实 Go 客户端跨实现联调、
  双内核矩阵（宿主 + QEMU 第二内核）。

最新一轮完整回归（唯一 Rust 数据面，2026-10-04）：

| 项 | 结果 |
|---|---|
| `verify`（标准 / 单臂拓扑） | 9/9 · 9/9 |
| DNS 专项（domain/cache/tcp/reload/edns/regex） | 6/6 |
| 转发面专项（relay/idle/offload/lifecycle/udp） | 6/6 |
| K3 + 运维（config/status/forward/整配置热重载/ops） | 5/5 |
| 协议梯（ss/trojan/vless/vmess/tuic/hysteria2 全变体） | 15 会话、17/17 |
| 单元测试 `cargo test --release` | 73/73 |
| 规则对拍 vs dae Go 编译器 | 5/5 逐字节一致 |
| soak（tcp 60s / ss 30s / udp 30s） | 无失败轮、无泄漏 |
| 内核矩阵（6.18.54-lts 宿主 + 7.2.8 QEMU） | 9/9 · 9/9 |

## 仓库结构

```
docs/                        决策与架构文档
├── architecture-decision.html   主决策档案（自包含 HTML，可离线打开）
├── adr/                         ADR-0001..0025（背景/决策/后果/验证方式）
└── modules/                     协议字节级规格（tuic-v5 / hysteria2）

mini-dae/                    可运行工程（构建、实验、测试都在这里）
├── loader/                    Rust 用户态：加载器 / 规则编译 / DNS / relay / 协议栈 / 状态面
├── ebpf-rs/                   Rust eBPF 数据面（aya-ebpf，bpfel-unknown-none + BTF maps）
├── lab/                       netns 实验环境与全部测试脚本
│   ├── lab.sh                 拓扑 / 会话 / 9 用例 verify / 各专项
│   ├── bench.sh bench_io.c    性能剖面（六路径）
│   ├── soak.sh                长时打流 + reload/suspend 泄漏检查
│   ├── parity.sh + parity/   与 dae Go 编译器的规则编译对拍（逐字节）
│   ├── proto-check/           真实 Go 客户端 / Go 参考服务端跨实现联调
│   ├── real-node-e2e.sh       真实 vless-ws 订阅节点端到端验收（env 注入节点）
│   └── matrix.sh              内核矩阵（宿主 / QEMU 第二内核）
├── README.md                  实验手册：构建、拓扑、会话、实测输出
└── NOTES.md                   数据面/协议栈的源码级笔记（带行号与坑清单）

dae/                         上游 dae clone（不入库；对拍工具按需在仓库同级 clone，见下）
```

## 快速开始

依赖：Linux（建议内核 ≥ 5.17；≥ 6.6 走 TCX）、Rust（stable + nightly + `rust-src`）、
`bpf-linker`、`libbpf` 头文件、`ip`/`tc`/`bpftool`、python3（`cryptography`）、
gcc（仅压测夹具 `lab/bench_io.c`）。

```bash
cd mini-dae
lab/lab.sh build           # 构建 Rust 加载器 + Rust eBPF 对象（不需要 root）
sudo lab/lab.sh up         # 建 netns 拓扑并启动
sudo lab/lab.sh verify     # 9 个用例（含单写者、状态面与故障注入）
sudo lab/lab.sh down
```

详细的拓扑说明、全部会话/测试清单与实测输出见 [`mini-dae/README.md`](./mini-dae/README.md)；
数据面机制与坑清单见 [`mini-dae/NOTES.md`](./mini-dae/NOTES.md)。

## 文档

- [`docs/architecture-decision.html`](./docs/architecture-decision.html) — 主决策档案：
  上游 dae 的模块/规模分析、Rust 重写的收益与风险、部署形态（Rust worker + eBPF 分流）、
  决策点 D1–D8 与迁移路线（K0–K3、P3–P9+）。
- [`docs/adr/`](./docs/adr/) — 25 条已采纳 ADR：每个决策的背景、选项、理由、后果、
  **实测验证方式**与修订条件。重要节点：0002（eBPF 程序语言：先 C 后迁）、
  0023/0024/0025（数据面 Rust 全量迁移 → C 对象退场）。
- [`docs/modules/`](./docs/modules/) — tuic v5 / hysteria2 的字节级客户端规格。

## 上游与许可

- 本仓库是对 dae（Go + eBPF）的**学习/研究性 Rust 重写**，不是 dae 官方项目；
  许多语义、map 布局与协议实现以 dae 源码为参照（逐项记录在文档与注释中）。
- 许可证：**AGPL-3.0-only**（见 [`LICENSE`](./LICENSE)），与上游 dae 一致。
- 上游代码不随本仓库分发：`dae/` 与 `mini-dae/lab/parity/dae-work/` 均在
  `.gitignore` 中。需要运行规则对拍/跨实现联调时，把 dae clone 到本仓库同级目录：

  ```bash
  git clone https://github.com/daeuniverse/dae dae
  cd mini-dae && lab/parity.sh          # 逐字节对拍 dae 的 Go 规则编译器
  ```

- 唯一保留的 C 源文件是压测服务端夹具 `mini-dae/lab/bench_io.c`（不属于数据面）。
- 第三方商标与项目名称归其各自所有者；本仓库与 daeuniverse 无隶属关系。

# 安全工程提案 · 攻击面治理与排期

- 版本：v0.1 · 2026-10-11（评审意见回应稿，**待采纳**）
- 来源：评审意见（2026-10-11）——① fuzz 目标与特权内核加载 CI 不应停在 G 类「中」优先级，
  应与 A 类同级；② 代理内核是攻击面最密集的软件类别之一（TLS/REALITY/SS 解析、DNS 报文、
  订阅拉取），而它已在接管全屋流量；③ nightly 工具链 + bpf-linker 的供应链脆弱性全文未讨论。
- 基线：`main@0bcadc6`（第二阶段 §11.7 修复批次后；72h 生产测试进行中）
- 纪律：与既有文档相同——「已具备」逐条附代码/CI 锚点；「缺口」不遮掩；每个动作有验收标准。
- 与 72h 生产测试的关系：**互不干扰**。本提案全部工作在开发机 / CI 进行，不触碰正在跑测试的软路由。

## 0 · 结论速览

| 评审意见 | 判定 | 落点 |
|---|---|---|
| fuzz 与特权内核加载 CI 提到 A 类同级 | **采纳**（并扩展） | 新设 **S 类（安全工程）**，与 A 类同优先级；S1 = fuzz（3 目标 → **≥8 目标**）；S2 = 特权加载 CI（含 G6 前置） |
| 攻击面密集（协议解析/DNS/订阅） | 采纳 | §1 给出**完整攻击面清单**（9 类输入 × 解析器 × 现有防线） |
| nightly + bpf-linker 供应链未讨论 | **采纳**（缺口证实） | S3：工具链仓库级钉死、bpf-linker 版本断言、cargo-deny、产物哈希（§2 列出 6 项缺口） |
| （扩展）根进程崩溃面与默认暴露面 | 提案新增 | S4：panic 边界、面板默认鉴权（当前**空 token = 放行**）、状态 socket 权限 |

总投入估算：**≈9–13 人日 + 机时**（不含 fuzz 挖出缺陷的修复池 ≈2–3 人日）。排期见 §4。

## 1 · 威胁模型与攻击面（现状取证）

### 1.1 信任边界

| 边界 | 事实 | 锚点 |
|---|---|---|
| 进程权限 | loader 以 **root/特权**运行；Capability 最小集 `CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN`（OpenWrt 上直接 root） | `install/sodama.service` |
| 单进程 | 引擎是单进程：**崩溃/挂起 = 全屋断网**（可用性攻击面）；`Restart=on-failure`（3 s）仅部分兜底 | 同上 |
| 内核写入 | eBPF 对象由 root 在**运行期**从磁盘加载（`--ebpf /usr/lib/sodama/sodama-ebpf`），无完整性校验 | 同上 / SC4 |
| 内存安全 | Rust 主干消除多数内存类漏洞；但 unsafe 面、依赖与**逻辑解析**仍在，且以 root 运行 | — |
| 上游不可信（有事实依据） | §10：机场端点轮换入口、按 UA 变化内容；§11：上游/链路把截断正文交给引擎。**「节点/端点不可信」不是假设，是已发生的事实** | devlog §10/§11 |

### 1.2 输入面清单（触达者 → 解析器 → 现有防线）

| # | 输入 | 触达者 | 主要解析代码（行数） | 现有防线 |
|---|---|---|---|---|
| 1 | ClientHello / QUIC Initial（嗅探） | **LAN 内任意设备** | `sniffer.rs` 667 · `tls13.rs` 1836 · `quicsniff.rs` 378 | 解析失败即放弃嗅探（回默认路径）；**无 fuzz** |
| 2 | DNS 查询 / 上游应答（明文/DoT/DoH/DoQ） | LAN 设备 + 任意上游 | `dns.rs` 2018 · `dnsroute.rs` 1286 · `dnsup.rs` 942 | UDP 尺寸钳制（512/EDNS）、缓存 1024 条 + TTL 帽（`dns.rs:265,522-524`）；**无 fuzz** |
| 3 | 节点回包帧（12 家族） | **代理节点**（可能被劫持/恶意） | `vless` 552 · `vmess` 1153 · `vision` 846 · `anytls` 966 · `tuic` 831 · `hysteria2` 1137 · `ss` 1792 · `ssr_cipher` 536 · `shadowtls` 858 · `reality` 617 · `ws` 693 | 跨实现逐字节对拍（Vision↔Xray、shadow-tls 三版）——**只覆盖正确帧**；无 fuzz |
| 4 | h2 帧（HPACK / Huffman） | 上游（DoH-h2 等） | `hpack.rs` 369 · `huffman_table.rs` | 无专项；**无 fuzz** |
| 5 | 订阅正文 / 规则集文本 | 订阅端点（第三方）；明文 http 可 MITM | `subscribe.rs` 726 · `ruleset.rs` 498 · `rules.rs` 1701 | 8 MiB 上限、重定向 ≤ 3、Content-Length 精确校验（§11.7）、TLS=webpki 根（`subscribe.rs:5`）；**无 fuzz** |
| 6 | geodata `.dat`（社区下载） | 分发方 | `geodata.rs` 751（手写 varint / length-delimited） | 显式截断/溢出错误（`geodata.rs:93-96,117,158`）；**无 fuzz** |
| 7 | `.dae` 配置 | 用户 / 面板写入路径 | `config.rs` 2430（+`rules.rs`） | validate 护栏、权限校验（`mode & 0o037 == 0`）、行级诊断；**无 fuzz** |
| 8 | 面板 HTTP API | **LAN（默认绑定 `0.0.0.0:8080`；HTTPS `0.0.0.0:8443` 自签名）** | `panel/backend/src/main.rs:186,208` | token（Bearer / `?token=` / Cookie 会话）；**空 token = 放行**（`main.rs:314-343`） |
| 9 | 状态面 unix socket | 本机 | `status.rs` | 默认 `/tmp/sodama-status.sock`（部署建议 `/run` + 0750，见 service 注释） |

### 1.3 结论

loader ≈44.4k 行中，解析/协议族代码 **>15k 行**；上表 9 类输入里，**LAN 设备（#1/#2/#8）
与上游（#2/#3/#4/#5）两条通道不需要任何预先信任即可触达解析器**。现有防线集中在「正确输入的
跨实现一致性」；对**畸形/恶意输入**的系统性覆盖是空的——这正是 fuzz 的职责，也是把 G3/G4
提级、并把清单从 3 个目标扩展到 ≥8 个的依据（§3 S1）。

现有质量资产（公正记录，fuzz 是补盲区而非替代）：268→274+ 单测、lab `verify`/专项、
跨实现逐字节对拍、QEMU 双内核矩阵、第三方评审。

## 2 · 供应链现状与缺口

### 2.1 现行锚点（先记录做对的部分）

- CI 固定组合：`nightly-2026-09-29` + `bpf-linker 0.11.1`（LLVM 23），升级规程写在注释里
  （`.github/workflows/ci.yml:23-28`）；构建 `--locked`（`ci.yml:93,104,109`）。
- `Cargo.lock` 入库两份（`sodama/`、`sodama/ebpf-rs/`）；CI 缓存按锁文件哈希。
- 订阅拉取 TLS 走既有的 webpki 根校验路径（`subscribe.rs:5` 注释：订阅站证书需公开可信）。
- CI 只做「编译 + 单测」是**明示的边界**而非疏忽（`ci.yml:1-5`）——本提案的 S2 就是补上另一半。

### 2.2 缺口（逐条带证据）

| # | 缺口 | 证据 | 风险 |
|---|---|---|---|
| SC1 | **仓库级无工具链钉死**：无 `rust-toolchain.toml`；本地 `cargo +nightly` 跟随最新 nightly，与 CI 钉住的日期可漂移 | `find rust-toolchain*` 无命中；`lab/build-ebpf-rs.sh` 只检查「存在 nightly」 | 「本地可复现」≠「仓库可复现」；eBPF 对象行为随工具链漂移 |
| SC2 | **bpf-linker 本地无版本断言**：脚本只检查存在性（`command -v`），版本靠文档口传（NOTES §11.13） | `lab/build-ebpf-rs.sh:23` | bpf-linker 的输出**将在 ring-0 执行**——链上最「动内核」的一环靠约定而非机制 |
| SC3 | **无依赖漏洞审计**：无 `deny.toml`/`audit.toml`，CI 无 cargo-audit/deny（advisory 无法主动触达） | 仓库无配置文件；`ci.yml` 仅 build+test | 与 A8（SBOM/许可证审计）天然合并，一次做两件事 |
| SC4 | **构建产物无哈希记录**：root 运行期从磁盘加载 eBPF 对象，无完整性校验 | `install/sodama.service`（`--ebpf` 路径） | 磁盘/部署链路被篡改时无感 |
| SC5 | CI actions 按 tag 固定（`checkout@v4`/`cache@v4`） | `ci.yml:37,48,59` | 低；私有仓库单维护者，记录在案（P2） |
| SC6 | 本地构建经 USTC/Tuna 镜像（NOTES §11.13） | — | 无法消除，如实登记为边界 |

**为什么供应链在本项目要单列**：这条件链的终端产物是在 ring-0 执行、由 root 装载的 eBPF 对象。
verifier 是**运行时**防线（已有）；构建链的可复现性与完整性（SC1–SC4）是零。两者缺一不可。

## 3 · 提案（S0–S5）

### S0 · 前置校准（0.5 人日）

- 在 `main` 上实测一次 `lab.sh build && sudo lab.sh up && verify`，校准 **G6 记载冲突**
  （backlog 记「O8 期间 6 项断言失败」，10-06 回归表记 9/9）：结论要么修复夹具/断言，
  要么收窄 verify 口径并注明——**这是 S2 的前置**（特权 CI 需要一个可信的验收对象）。
- 记录当前解析类单测的 crash 基线（fuzz 出 crash 时用于区分回归/新发现）。

### S1 · Fuzz 基建与目标（P0 · 3.5–5 人日 + 机时）

**基建**：`sodama/fuzz/`（cargo-fuzz，libFuzzer；不进发布路径，独立于主 workspace 的依赖树）；
corpus 目录入库（小体积种子）；`lab/fuzz/README.md` 记录运行方式与 crash 处理流程。

**目标清单**（验收对齐 backlog G3「≥3 个」并提高）：

| 优先 | 目标 | 输入 | 触及面 |
|---|---|---|---|
| P0 | `fuzz_dae_parse` | `.dae` 文本 | config.rs + include 展开 + rules.rs 入口 |
| P0 | `fuzz_dns_packet` | 报文（请求/应答/EDNS+ECS/TC/畸形压缩指针） | dns.rs / dnsroute.rs |
| P0 | `fuzz_client_hello` | TLS CH 字节流（含分片/截断/诡异扩展顺序） | sniffer.rs / tls13.rs |
| P0 | `fuzz_subscribe_body` | HTTP 响应 + 正文 + 链接/Base64 | subscribe.rs |
| P1 | `fuzz_vmess_frame` | VMess 请求/响应帧 | vmess.rs（节点侧） |
| P1 | `fuzz_hpack_huffman` | HPACK 块 / Huffman 位流 | hpack.rs / huffman_table.rs |
| P1 | `fuzz_vision_ws_frame` | Vision/WS 帧 | vision.rs / ws.rs |
| P1 | `fuzz_geodata_dat` | `.dat` 字节流 | geodata.rs |
| P2 | `fuzz_ruleset_text` | 规则集文本 | rules.rs / ruleset.rs |

**CI 接入**（与底层承载无关，两项都要）：
- PR 门禁：P0 四项各 60–120 s（超时即红，不改名不跳过）；
- 夜间任务：全量目标各 10–30 min——**与 G5（夜间 soak）合并为一个 nightly job**，一次基建两处收益。

**验收**：① ≥8 目标跑通且进夜间；② 每目标累计 ≥24 h 无 crash 方可标「稳」；
③ 每个 crash 走**三连**：最小化种子入 corpus → 回归单测 → 修复（禁止只修不测）；
④ crash 修复池 2–3 人日（预期会挖出 5–20 个小型解析缺陷——挖不出才说明目标写错了）。

### S2 · 特权内核加载 CI（P0 · 1.5–2.5 人日，另 + G6 修复 0.5–1 人日）

**方案选型**（backlog G4 原文要求「self-hosted runner 或 QEMU 中跑 verify 子集」）：

| 方案 | 落地时间 | 隔离 | 关键约束 |
|---|---|---|---|
| **A · QEMU(TCG) 跑 verify，直接进 GitHub Actions** | 1.5–2.5 人日 | 好（VM 内） | 复用 `matrix.sh vm` 的 initramfs+9p 路线；TCG 较慢（先测基线耗时）；内核镜像来源需固化（Arch 镜像下载或 artifacts） |
| B · self-hosted runner（本机） | 0.5–1 人日 | **差** | 本机存有软路由凭据（`lab/prod/health-track.sh` 默认 `root@192.0.2.10`）——CI 逃逸 → 路由器失守；不可接受，除非 runner 放进专用 VM（即退化回 A + 托管） |
| C · GitHub-hosted + KVM 嵌套 | — | — | 标准 runner 无 `/dev/kvm`，不可行 |

**建议：方案 A**。把 `matrix.sh vm` 参数化（headless、超时、结果断言 → `MATRIX-RESULT=PASS`），
CI 里新增 job：构建 → 起 QEMU → 对象加载冒烟（`bpftool prog show` 断言）→ verify 子集
（≥ proxy/direct/block/fault 四项；时间允许则全量 9 项）。触发：main push 后 + 夜间；
失败告警（红 + 通知渠道）。

**验收**：① CI 出现「QEMU verify 子集 PASS」工件；② eBPF 对象「能被内核加载」有日志证据；
③ 失败时能在 CI 页面直接看到 verify 输出；④ 文档（`ci.yml` 注释或 `docs/deploy.md` 增节）。

### S3 · 供应链加固（P0 前半 + P1 后半 · 2–3 人日）

| # | 动作 | 验收 |
|---|---|---|
| S3.1 | **仓库级钉死数据面工具链**：`sodama/ebpf-rs/rust-toolchain.toml`（`nightly-2026-09-29` + `rust-src`）；构建脚本不再用裸 `+nightly`；loader 保持 stable | 新 clone 直接 `lab/build-ebpf-rs.sh` 与 CI 用同一组合；升级 = 显式提交（含对象哈希对比） |
| S3.2 | **bpf-linker 版本断言**：脚本与 CI 校验 `bpf-linker --version` == 0.11.1（env 可覆盖），失败给出安装命令；把已验证组合（nightly 日期/bpf-linker/LLVM 23）连同二进制 SHA256 记入 NOTES | 版本不符即构建失败（不再靠口传） |
| S3.3 | **cargo-deny**（advisories + licenses + bans + sources）入 CI（**与 A8 合并**：许可证审计 + SBOM 一次做完）；advisory 每日检查 | `cargo deny check` 绿；advisory 命中时有处理记录 |
| S3.4 | **产物哈希**：CI 与本地构建输出 eBPF 对象 SHA256（job summary / 日志）；部署脚本安装前比对；可选：loader 启动时把对象哈希写 status 面 | 部署链路出现「哈希一致」证据 |
| S3.5 | （P2）CI actions 按 commit SHA 固定；镜像链路（SC6）在 NOTES 记录为边界 | — |

### S4 · 根进程健壮性与默认面收紧（P1 · 1–2 人日）

- **panic 边界**：现状 `catch_unwind` 仅 2 处（`main.rs:6408,6475`）。以 S1 结果驱动，
  补关键网络入口线程的 panic 边界（DNS/订阅/探测/嗅探已有各自经验），目标：
  **任何网络输入都不置主进程于死地**；对「解析 panic 逃逸」逐条加回归单测。
- **面板默认鉴权**：当前「未设 token = 放行 + 默认 `0.0.0.0:8080`」——建议绑定非 loopback 且
  token 为空时**启动拒绝或强告警**（fail-closed）；`panel.conf` 模板与文档把 token 标注为必填。
- **状态面 socket**：默认 `/tmp/sodama-status.sock` → 建议 `/run/sodama/status.sock` + 0600/0750
  （service 注释已有做法，改为文档推荐默认）。
- **尺寸/分配上限盘点**：订阅 8 MiB 与 DNS 缓存上限已有；其余解析路径（帧长度字段驱动的分配）
  的上限随 fuzz 结论补齐。

### S5 · 固化（P1 · 0.5 人日）

- 本提案 §1/§2 固化为 **ADR-0064《安全工程与威胁模型》**（背景/决定/后果/验证方式）；
- **backlog 重分类落地**（见附录 A，批准后并入 `docs/backlog.md`）；
- README/Atlas 相应位置补一条指针（「安全工程」成为与 A 类并列的叙事，不是隐藏条目）。

## 4 · 排期（与 A 类同优先级；建议插在 A 类中低项之前）

| 日 | 事项 | 里程碑 |
|---|---|---|
| D1 | S3.1 + S3.2（工具链钉死、版本断言）· S0 校准（verify 实测） | — |
| D2–D3 | S1 基建（fuzz crate / harness 模板 / CI 骨架 + corpus 起步） | — |
| D4–D6 | S1 前 4 目标 + PR 门禁 | **M1：fuzz 门禁上线** |
| D7–D9 | S2（QEMU verify 进 CI；视 S0 结论修 G6） | **M2：特权 CI 绿** |
| D10–D12 | S1 余下目标 + 夜间全量（与 G5 合流） | — |
| D13–D14 | S3.3（cargo-deny）· S4 首轮 · S5（ADR + backlog 重分类） | **M3：供应链 + 文档收口** |
| D15–D16 | 缓冲：fuzz crash 修复池 | — |

排序理由：A 类是「从可运行到可分发」（增长收益），S 类是「从可分发到可信任」（风险削减）。
在「已接管全屋流量 + 72h 生产测试进行中」的事实下，S 类的期望损失削减高于 A 类中低项
（shell 补全、PKGBUILD 等可以等）。A 类中 A8（许可证/SBOM）与 S3.3 合并执行。

## 5 · 成本与风险

- **成本**：≈9–13 人日 + 机时（夜间 fuzz/CI；QEMU TCG 的时间预算在 S2 内实测）。
- **风险 1**：fuzz 必然挖出缺陷（这是目的）——修复池 2–3 人日已列，挖不出反而要检查目标质量。
- **风险 2**：QEMU TCG 在 CI 上的耗时不确定——S2 第一步先测「boot + 单用例」基线。
- **风险 3**：自托管 runner 的托管责任（凭据暴露）——方案 A 已规避；若后续改用 runner，
  必须放进专用 VM 且与生产凭据隔离。
- **边界（明确不做）**：代码签名/远程证明（对单维护者研究项目属过度工程，记录边界）；
  OSS-Fuzz 上游托管（调研项，不承诺）；seccomp 白名单（P2 调研，不排期）。

## 附录 A · backlog 重分类建议（批准后并入）

- 新设 **S. 安全工程（与 A 类同级，最高）**；原 G 类如下调整：
  - G3（fuzz）→ **S1**（验收升级为 ≥8 目标 + 夜间 + crash 三连）；
  - G4（特权内核加载 CI）→ **S2**（补「G6 校准/修复」前置）；
  - G5（夜间 soak）→ 与 **S1 夜间任务合并**为一个 nightly job；
  - G6（verify 探针陈旧）→ 保留在 G，但标注为 S2 前置；S0 给出实测结论。
- 新增条目：**S3.1–S3.5**（供应链，见上表）· **S4**（panic 边界 / 面板默认鉴权 / socket 权限 /
  尺寸上限盘点）· **S5**（ADR-0064 + 本文归档 + README/Atlas 指针）。

## 附录 B · 证据锚点索引（本次取证的坐标）

| 主题 | 锚点 |
|---|---|
| CI 范围与工具链钉死 | `.github/workflows/ci.yml:1-5,23-28,93,104,109` |
| 本地构建脚本（仅存在性检查） | `sodama/lab/build-ebpf-rs.sh`（nightly 检查 L16-21、bpf-linker L23） |
| 特权与最小 capability 集 | `install/sodama.service`（AmbientCapabilities / ExecReload / RuntimeDirectory 注释） |
| 面板绑定与鉴权 | `panel/backend/src/main.rs:186,208,314-343` |
| 订阅拉取防线 | `sodama/loader/src/subscribe.rs:5,25,26,156,288` |
| DNS 尺寸/缓存上限 | `sodama/loader/src/dns.rs:265-271,522-524` |
| geodata 解析错误处理 | `sodama/loader/src/geodata.rs:93-96,117,158` |
| panic 边界现状 | `sodama/loader/src/main.rs:6408,6475`（全仓库 `catch_unwind` 仅此 2 处） |
| 解析器规模 | `wc -l sodama/loader/src/*.rs`（全文合计 ≈44.4k 行；§1.2 表内逐文件行数） |
| backlog 原文 | `docs/backlog.md` G3/G4/G5/G6 行（L88-91）与 A8（L33） |
| 上游不可信事实 | `docs/phase2-devlog.md` §10（端点轮换/内容变化）、§11（截断正文） |
| 已验证工具链组合 | `sodama/NOTES.md` §11.13/§11.33（nightly-2026-09-29 + bpf-linker 0.11.1 + LLVM 23） |

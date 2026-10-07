# 后续版本 Backlog（本版不做）

本文件把「已知但明确不在当前版本内」的事项集中登记，供后续版本规划。原则：
**如实**（不把未做写成已做）、**有验收条件**（每条给出可判定的完成标准）、
**与 ADR/parity 互链**（决策理由见 ADR；覆盖度口径见 `parity-status.md`）。

当前状态（main@a00d74a；ADR-0058；单测 257/257；架构档案 HTML v2.43 / VLESS 提案 v1.9）：
核心数据面复现（K0–K3）、分流主链路、DNS 子系统、出站 12 家族 + shadow-tls 插件、
真网关可用、规则编译逐字节对拍、M1–M4 性能项（O3/O4/O5/O9）与 O6/O7/O8、
G1 同机 + 真实节点口径均已交付。以下为余项。

## 已具备的工程化资产（对照基线）

| 资产 | 现状 |
|---|---|
| 构建 | `cargo build --release` + `lab/build-ebpf-rs.sh`（nightly 固定日期 + bpf-linker 0.11.1） |
| CI | `.github/workflows/ci.yml`：eBPF 对象构建 + loader 编译/单测（无特权内核加载） |
| 部署 | `install/install.sh`（--dry-run/--uninstall）+ `install/sodama.service`（capability 最小集 + ExecReload）+ `docs/deploy.md` |
| 实验 | lab.sh（netns/verify/专项）、gateway.sh（真网关一键 + 启动自检回滚）、bench/soak/matrix/parity |
| 文档 | ADR-0001..0056 + parity-status.md + HTML 决策档案 + NOTES §11.x + 协议模块规格 `docs/modules/` |

## A. 工程化与发布（打包，最高优先级）

| # | 事项 | 动机 / 对照 | 验收标准 |
|---|---|---|---|
| A1 | **Docker 镜像** | dae 有 `Dockerfile` + `docker-compose.yml`；容器是主要分发方式之一 | 多阶段构建（builder 固定 nightly+bpf-linker；runtime 含 loader/eBPF 对象/示例配置）；`docker run --privileged --network host` 冒烟通过并写入 README |
| A2 | **发行包（tarball）** | dae 有 release 工件（多架构） | tag 产出 `sodama-<ver>-x86_64.tar.zst`：loader、`ebpf-rs.o`、systemd、install.sh、示例配置、README/LICENSE；解包后 `install.sh` 可装可卸 |
| A3 | **发行 CI** | dae 有 release/prerelease/daily-build 工作流 | tag `v*` 触发：构建 → 冒烟（容器内 `--version`/单测）→ 上传 release 工件 + SHA256SUMS；失败不产出 |
| A4 | **版本与 CHANGELOG** | 当前 Cargo 0.1.0、无 CHANGELOG | `--version` 输出语义化版本 + git sha；CHANGELOG 从提交生成；README 顶部版本徽章 |
| A5 | **shell 补全** | dae 有 `install/shell-completion/`（bash/zsh/fish） | 补全 CLI 全部参数（`--config/--dialer/--subscribe/--listen-socks/...`）；安装脚本可选部署 |
| A6 | **Makefile / 任务入口** | dae 有 Makefile（build/test/release 单入口） | `make build / test / lab / install / release` 目标；与新贡献者文档一致 |
| A7 | **发行包体系** | 本机 Arch；dae 上游有 AUR/发行版打包路径 | 至少 `PKGBUILD`（本机可 `makepkg` 构建安装）；deb 可选 |
| A8 | **许可证一致性审计** | `LICENSE`=AGPL-3.0，但部分源码头为 `SPDX GPL-2.0`（不一致）；依赖需 SBOM | 全部源码/配置文件头统一为 AGPL-3.0-only（或逐文件说明例外）；`cargo deny`/SBOM 跑通并记录第三方许可证清单 |
| A9 | **install.sh 升级/回滚** | 当前只有装/卸 | `--upgrade`：保留上一版二进制，systemd 启动失败自动回滚；dry-run 覆盖新路径 |
| A10 | **容器/内核兼容性矩阵文档** | eBPF 对内核/BTF/CAP 有要求 | ✅ 已完成：`docs/openwrt.md` §2 给出 kernel fragment（**NAMESPACES/NET_NS 是硬前提，官方镜像默认未开**——已用 QEMU 实测确认）与逐项排障；`docs/deploy.md` 含容器 capability 清单 |
| A11 | **OpenWrt 支持（P0）** | ✅ 应用侧已完成（2026-10-05）：musl 静态交叉构建（x86_64 7.2MB / aarch64 6.3MB / armv7 6.2MB，`lab/build-openwrt.sh`，zig+cargo-zigbuild）；`install/openwrt/` ipk 包（预编译产物 + procd + uci + 数据面对 helper）；内核 fragment 与文档 `docs/openwrt.md`。代码侧仅一处 musl 适配（`MSG_WAITFORONE` 类型；`malloc_trim` 已有 cfg 门控）。官方镜像 QEMU 冒烟跑通 ipk/二进制并实测确认**官方内核缺 CONFIG_NAMESPACES**；⏸️ **暂停**（按用户指示移到后续）：自编内核镜像上的完整 eBPF 冒烟（cmake 3.30.5 bootstrap 宿主补丁已定位，构建目录 <openwrt-build-dir> 保留） | 后续：应用 cmake 补丁 → 自编镜像跑通完整冒烟；aarch64 真机验证；SDK 一键出 ipk |

## B. 出站协议余项（如实边界）

| # | 事项 | 现状/依据 | 验收标准 |
|---|---|---|---|
| B1 | 其余 SIP003 插件：simple-obfs（http/tls）、v2ray-plugin（ws/tls） | 解析即报错（ADR-0055 边界） | 与 Go/参考服务端跨实现用例（对照 `ss` 插件链） |
| B2 | SSR 完整形态：`auth_aes128_md5/sha1`、`auth_sha1_v4`、`auth_chain_a/b`、`obfs_*` 全家族 + UDP | origin+plain 子集（ADR-0054 边界） | 每个 proto/obfs 至少 1 条黄金向量 + 1 个跨实现 lab 用例 |
| B3 | ECH（hysteria2） | 已评估为边界（ADR-0056）；前置：rustls/quinn 提供 ECH 或可插拔 TLS + HPKE 依赖 | 与 ot/quic-go ECH 服务端夹具互操作 |
| B4 | rustls 路径 uTLS（naive h2/h3、DoH h2/h3 等指纹） | P24 边界（ADR-0048） | 与自实现 CH 同款的指纹对齐测试 |
| B5 | ML-DSA / gecko（hysteria2 混淆/后量子） | hy2 v0 边界（ADR-0020） | 与 Go 客户端参数级互通 |

## C. eBPF 数据面（对标 dae ≈65%）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| C1 | L2/桥接程序族（TC L2 变体） | 8 程序（7×TC + sk_skb） | 桥接拓扑 lab 用例 |
| C2 | cgroup 钩子（connect/bind/sendmsg…） | **6/6 已挂载**（sock_create/release、connect4/6、sendmsg4/6；P17b）——用于 pname 采集与 `pname()` 规则（WAN egress 新连接，见 `status` hooks）；bind 与 sock_addr 重定向用例未做 | 至少 connect/bind 两钩子的 sock_addr 重定向用例 |
| C3 | ringbuf 事件通道 | 用 printk 调试 | 高频事件可采样上报，替代 printk |
| C4 | XDP 可选路径调研 | 未做 | 调研报告（收益/兼容性）即可 |

## D. 配置系统（≈65%）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| D1 | `include` 展开 | ✅ 已完成（代码已实现：入口目录相对路径约束 + 循环检测 `circular include is not allowed` + 对照 `config_merger.go` dfsMerge 语义；2026-10-08 文档滞后修正） | — |
| D2 | 全局健康检查参数全量（间隔/容忍度/策略） | 子集 | 配置→健康循环行为的一对一测试 |
| D3 | `config_merger` deferred 项收尾 | 显式列出 | deferred 列表清零或标注永久不做 |
| D4 | 组级 override 细节（组级 dialer 参数覆盖） | 余项 | lab 双组覆盖用例 |

## E. 转发面（≈78%）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| E1 | UDP endpoint pool / full-cone NAT（网关侧 UDP 代理） | 协议侧可用、网关默认 UDP 直连 | full-cone 行为测试（外部多映射） |
| E2 | backlog fuse / 连接计费 | 未做 | 压测下 fuse 生效 + 计费可导出 |
| E3 | offload 完整形态（fuse 失效路径与统计） | 生命周期/回收已交付（O4/O8：每 offload 连接 0 线程、200 条 fds 回收全过、可观测计数）；余 fuse 失效路径（依赖 E2） | 失效全路径与计数可观测 |

## F. 嗅探 / IPv6

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| F1 | QUIC 观测 → 域名拨号（UDP dial_mode/punt） | 仅观测 | UDP 域名拨号 + punt 用例 |
| F2 | ICMPv6 error 转发 | 未做 | netns 用例 |
| F3 | IPv6 分片补全 | 非首片跳过 | 分片重组/转发用例 |

## G. 性能与质量

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| G1 | 与 Go 版**同机对拍** + **异机/公网口径**（六路径基准） | **已完成**：P33.2 四方对比（direct/ss，ssserver 上游 + 全双工夹具 + 5 次中位数；并发扩展/内存/线程/perf 剖面齐备；`docs/benchmark-report.html` §3）——sodama 与 dae 同机同拓扑；UDP 四方对拍补齐（`lab/perf/udp.sh`：20k pps 0 丢包，sodama CPU 630 ms/40k 包 vs dae 2140 / sing-box 1580 / v2ray 1780；O7）；ss 方法 A/B（chacha vs aes-256-gcm）已做（O6）；**真实节点/公网口径（2026-10-05）**：`lab/perf/real.sh` 三方共用同一节点 + 固定后端 IP（VLESS-REALITY+Vision，v2ray skip）、8 MiB×17 轮：客户端 CPU_ms/GB sodama **6 233** vs dae 8 820（-29%）/ sing-box 8 557（-27%）；同后端轮 4 987 vs 8 613 / 10 290（见 roadmap P5） | 同机 + 异机口径均无回退；余：kTLS 目标异机重测（G2） |
| G2 | 生产级优化（THP/连接池/看门狗内存上限） | **M1+M2+M4+O8 已交付**：splice 零拷贝（Direct/VLESS 明文/kTLS 成功的 TLS，`--no-splice` 可关；vless 12.2→16.9 Gbps / CPU 380→60 ms；relay 8 流 15→21.6 Gbps） + eBPF printk 门控 + **kTLS 内核 TLS 实验（`--ktls`：TLS 48MB×4 11.67→12.32 Gbps、memcpy 29.4%→1.6%、TX+RX+splice 全链路，默认关）** + **M4 epoll worker 池：10k 连接 28 线程 / 32.1 MB、fail=0、风暴 25 606/s；stage 2 codec 全协议面（VLESS 全组合含 reality/vision/ws、Trojan、vmess、ss/ssr/anytls）vless-tls 2 000 连接 27 线程 / 61 MB（线程模型 4 011 / 222 MB）；offload 看门狗单线程化（每 offload 连接 0 线程）；io_uring A/B 结论不引入；`SODAMA_NO_REACTOR=1` / `SODAMA_REACTOR_CODEC=0` 可关（ADR-0058）**；**O8 缓冲池/回收：按字节封顶 8MB 池 + UDP 槽按需增长 + SIGTERM 有界优雅退出（50 在途整机 462ms、无 tc 残留）+ 30s malloc_trim（churn 300 条 RSS 无增长）**；方向与待办（ss 路径 O1/O2 按用户方向暂缓——以 VLESS 为基准；kTLS 异机复测）在 `docs/optimization-roadmap.md`（O1–O10） | 各优化项有开关与压测数据；M2 对账：memcpy ✓；≥13 Gbps/≤1000 ms 受本机夹具（≈12.5 Gbps 封顶）与内核密码引擎速度限制，待异机口径重测；M4：✅ 10k 连接 28 线程 / 32.1 MB、fail=0；stage 2 验收：ss/ssr/ss2022/anytls 均逐连接确认 codec 投递、offload 200 条 0 线程回收全过；O8：churn/退出均有界 |
| G3 | fuzz（`.dae` 解析 / DNS 报文 / CH 解析） | 未做 | 至少 3 个 fuzz target 跑通 |
| G6 | `lab.sh verify` 探针陈旧 | `test_proxy`/`test_host_proxy`/`test_reload`/`test_rebind`/`test_fault_*` 断言 回包含 `orig_dst=`，但仓库内无任何夹具产生该字段（历史遗留）；O8 期间实测 6 项因断言失败 | 修复夹具或断言（使 verify 回到 9/9）；在此之前专项用例（test-ss/vless/offload/udp）为准 |
| G4 | 特权内核加载类 CI | CI 只编译+单测 | self-hosted runner 或 QEMU 中跑 verify 子集 |
| G5 | 长稳 soak 纳入 CI（夜间） | 手动 | 夜间任务 + 失败告警 |

## H. 文档

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| H1 | 顶层 `README.md` 状态区重写 | 数字停留在 P5 时期（121/121、ADR-0031 等），与当前（257 单测、ADR-0058、G1 真实节点数据）脱节 | 状态表与实际一致；仓库结构/快速开始重写 |
| H2 | 用户手册（配置参考 + Go dae → sodama 迁移指南） | 散在 README/NOTES | 独立章节：逐项差异表（配置/CLI/部署） |
| H3 | 基准报告 | bench.sh 有输出 | `docs/bench.md` 固化方法与结果 |

## I. 资源/系统内存专项（第三方评审采纳，2026-10-05）

来源：`docs/reviews/2026-10-05-memory-final-review-{a,b}.md` 与工程方提案
`docs/reviews/2026-10-05-adoption-proposal.md`。

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| I1 | **系统内存基准（四层模型）** | ✅ 已完成（2026-10-05）：扫描 100–20 000 + 与 dae 同口径对照；数据/口径见 `docs/reviews/2026-10-05-i1-system-memory-data.md`（工具 `lab/perf/mem-system.sh` + `mem-analyze.py`） | 实测结论：sodama 用户态稳态净增 ≈0.6–0.7 KB/连接、内核侧 ≈46–53 KB/连接（含共享链路；dae ≈34 KB/连接）；RSS 优势 ≠ 系统优势，已在 v2 报告成文 |
| I2 | **FD 架构治理** | ✅ 已完成（2026-10-05）：去 RelayHandle 克隆；pipe 懒建/空闲释放（`SODAMA_PIPE_IDLE_MS`）；worker-local pipe cache；`raise_nofile_limit` + status `fds_used/fds_soft_limit/splice_fd_budget/pipe_*` + ≥80% 新连接回退 copy-pump。实测 hold 20 000：fd/连接 **4.0**（2 socket + 2 pipe，建立峰值无额外瞬态）；空闲回落 ≈3.1；pipe_created/reused/released 计数工作 | 验收达成：活跃 ≤4/连接；20 k 在默认/自提升 limit 下可跑；同口径吞吐/CPU 不回退（splice 仍 +31%/−80% vs copy） |
| I3 | **转发原语对照** | ✅ 已完成（2026-10-05）：见 `docs/reviews/2026-10-05-i3-forwarding-primitives.md`；io_uring 复测维持不引入（ADR-0058）；MSG_ZEROCOPY 调研结论「不适用本数据面、记录边界」 | 三档选型（吞吐/fd 高压/低时延）已定：默认 splice；fd≥80% 自动降级 copy pump；低时延无回退 |
| I4 | **长稳曲线化（bounded-memory）** | ✅ 短时完成（2026-10-05）：`lab/perf/soak-curve.sh`（轻负载 hold 200 + 微量 churn + 周期负载 + 15 s 采样→CSV）；35 min（I2 版本）与 **60 min（I6 最终版本）** 两轮：RSS +3.1%、Slab −0.5%、SUnreclaim −1.4%、fd 无增长、RTT p50 34–93 µs / p99 229–904 µs、零失败 → 短时判据 PASS；曲线入 v2.1 报告 | 72 h 为机时型任务：脚本/判据/采样就绪（`SOAK_SECS=259200`），完成且漂移 ≤5%、失败不增长后方可对外使用「bounded-memory」 |
| I5 | **报告口径与措辞** | ✅ 已完成（2026-10-05，2026-10-06 合并为 `docs/benchmark-report.html`）：四层模型 + 专业排版 + 图表；全文去「唯一解/遥遥领先/顶级」，统一「极低用户态内存承载高并发 / predictable resource consumption」；口径与边界、评审回应矩阵成章 | v1 保留存档并链到 v2；后续对外统一 v2 口径 |

执行顺序建议：**I1 → I2 → I5 → I4 → I3**（先拿证据、再改架构、同步口径；soak 与 I3 可并行）。

## 明确不在范围（永久）

- **daed Web UI / GraphQL / 鉴权**：daemon 是独立项目，sodama 只做本体 + 状态面；
- **与 dae 二进制/配置 100% 兼容**：本项目定位研究性复现，配置语义对齐即可（ADR-0005/0011）；
- **Windows/macOS**：数据面依赖 Linux eBPF，不做跨平台。

## 使用方式

- 规划下一版时，从 A 类（工程化/发布）开始——它是「从可运行到可分发」的最后一段；
- 协议类（B）与数据面类（C）按需穿插；
- 每完成一项，同步 `parity-status.md` 覆盖度数字与证据锚点，并在 CHANGELOG 记录。

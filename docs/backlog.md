# 后续版本 Backlog（本版不做）

本文件把「已知但明确不在当前版本内」的事项集中登记，供后续版本规划。原则：
**如实**（不把未做写成已做）、**有验收条件**（每条给出可判定的完成标准）、
**与 ADR/parity 互链**（决策理由见 ADR；覆盖度口径见 `parity-status.md`）。

当前版本（v2.9 / HTML v2.40，main@93a2816）的范围：核心数据面复现（K0–K3）、
分流主链路、DNS 子系统、出站 12 家族 + shadow-tls 插件、真网关可用、
规则编译逐字节对拍。以下为余项。

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
| A10 | **容器/内核兼容性矩阵文档** | eBPF 对内核/BTF/CAP 有要求 | `docs/deploy.md` 增加：支持内核下限、BTF 要求、容器所需 capability、常见失败排查 |

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
| C2 | cgroup 钩子（connect/bind/sendmsg…） | 未做 | 至少 connect/bind 两钩子的 sock_addr 重定向用例 |
| C3 | ringbuf 事件通道 | 用 printk 调试 | 高频事件可采样上报，替代 printk |
| C4 | XDP 可选路径调研 | 未做 | 调研报告（收益/兼容性）即可 |

## D. 配置系统（≈65%）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| D1 | `include` 展开 | deferred | 与 dae 相同语义（相对路径/循环检测）+ 解析测试 |
| D2 | 全局健康检查参数全量（间隔/容忍度/策略） | 子集 | 配置→健康循环行为的一对一测试 |
| D3 | `config_merger` deferred 项收尾 | 显式列出 | deferred 列表清零或标注永久不做 |
| D4 | 组级 override 细节（组级 dialer 参数覆盖） | 余项 | lab 双组覆盖用例 |

## E. 转发面（≈78%）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| E1 | UDP endpoint pool / full-cone NAT（网关侧 UDP 代理） | 协议侧可用、网关默认 UDP 直连 | full-cone 行为测试（外部多映射） |
| E2 | backlog fuse / 连接计费 | 未做 | 压测下 fuse 生效 + 计费可导出 |
| E3 | offload 完整形态（fuse 失效路径与统计） | 最小实现 | 失效全路径与计数可观测 |

## F. 嗅探 / IPv6

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| F1 | QUIC 观测 → 域名拨号（UDP dial_mode/punt） | 仅观测 | UDP 域名拨号 + punt 用例 |
| F2 | ICMPv6 error 转发 | 未做 | netns 用例 |
| F3 | IPv6 分片补全 | 非首片跳过 | 分片重组/转发用例 |

## G. 性能与质量

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| G1 | 与 Go 版**同机对拍**（六路径基准） | **大部分完成**：P33.2 四方对比（direct/ss，ssserver 上游 + 全双工夹具 + 5 次中位数；并发扩展/内存/线程/perf 剖面齐备；`docs/perf-report.md`）——sodama 与 dae 同机同拓扑；余 relay/offload/UDP 同机对拍 | 补齐 relay/offload/UDP 路径对拍 + 误差说明 |
| G2 | 生产级优化（THP/连接池/看门狗内存上限） | **方向已定**：基于 P33.2 剖面产出 `docs/optimization-roadmap.md`（O1–O8：AEAD 零分配 / syscall 合并 / splice 零拷贝 / worker 池 / printk 门控 / AES-GCM / UDP 批量 / 缓冲池），待实施 | 各优化项有开关与压测数据（基准：ss 8 流 ≥12 Gbps / ≤110 ms·Gbps⁻¹；relay ≥22 Gbps） |
| G3 | fuzz（`.dae` 解析 / DNS 报文 / CH 解析） | 未做 | 至少 3 个 fuzz target 跑通 |
| G4 | 特权内核加载类 CI | CI 只编译+单测 | self-hosted runner 或 QEMU 中跑 verify 子集 |
| G5 | 长稳 soak 纳入 CI（夜间） | 手动 | 夜间任务 + 失败告警 |

## H. 文档

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| H1 | 顶层 `README.md` 状态区重写 | 数字停留在 P5 时期（121/121、ADR-0031 等），与当前（236 单测、ADR-0056）脱节 | 状态表与实际一致；仓库结构/快速开始重写 |
| H2 | 用户手册（配置参考 + Go dae → sodama 迁移指南） | 散在 README/NOTES | 独立章节：逐项差异表（配置/CLI/部署） |
| H3 | 基准报告 | bench.sh 有输出 | `docs/bench.md` 固化方法与结果 |

## 明确不在范围（永久）

- **daed Web UI / GraphQL / 鉴权**：daemon 是独立项目，sodama 只做本体 + 状态面；
- **与 dae 二进制/配置 100% 兼容**：本项目定位研究性复现，配置语义对齐即可（ADR-0005/0011）；
- **Windows/macOS**：数据面依赖 Linux eBPF，不做跨平台。

## 使用方式

- 规划下一版时，从 A 类（工程化/发布）开始——它是「从可运行到可分发」的最后一段；
- 协议类（B）与数据面类（C）按需穿插；
- 每完成一项，同步 `parity-status.md` 覆盖度数字与证据锚点，并在 CHANGELOG 记录。

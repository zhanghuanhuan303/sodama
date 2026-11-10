# 后续版本 Backlog（本版不做）

本文件把「已知但明确不在当前版本内」的事项集中登记，供后续版本规划。原则：
**如实**（不把未做写成已做）、**有验收条件**（每条给出可判定的完成标准）、
**与 ADR/parity 互链**（决策理由见 ADR；覆盖度口径见 `parity-status.md`）。

当前状态（dev@v1.0.0 发布打包（AUR 双包 + release tarball）；ADR-0069；单测 350 + ebpf-logic 3；ATLAS v2.3（重写版）；devlog §26；决策档案 HTML v2.46 / VLESS 提案 v1.9）：
核心数据面复现（K0–K3）、分流主链路、DNS 子系统、出站 12 家族 + shadow-tls 插件、
真网关可用、规则编译逐字节对拍、M1–M4 性能项（O3/O4/O5/O9）与 O6/O7/O8、
G1 同机 + 真实节点口径均已交付。以下为余项。

## 已具备的工程化资产（对照基线）

| 资产 | 现状 |
|---|---|
| 构建 | `cargo build --release` + `lab/build-ebpf-rs.sh`（nightly 固定日期 + bpf-linker 0.11.1） |
| CI | `.github/workflows/ci.yml`：eBPF 对象构建 + loader 编译/单测 + **lint 门禁（v1.4：fmt --check + clippy -D warnings）**（无特权内核加载） |
| 部署 | `install/install.sh`（--dry-run/--uninstall）+ `install/sodama.service`（capability 最小集 + ExecReload；**v1.5：Type=notify + `sd_notify`、`ExecStartPre` validate 门禁、StartLimit 300×5s、`OOMScoreAdjust=-100`、Timeout 120s/30s**）+ `docs/deploy.md` |
| 实验 | lab.sh（netns/verify/专项）、gateway.sh（真网关一键 + 启动自检回滚）、bench/soak/matrix/parity |
| 文档 | ADR-0001..0069 + parity-status.md + ATLAS HTML v1.8 + NOTES §11.x + 协议模块规格 `docs/modules/` + 配置参考 `docs/config-reference.md`（生成器 + drift 单测；v1.5 随 global 生效面重生成） |

## A. 工程化与发布（打包，最高优先级）

| # | 事项 | 动机 / 对照 | 验收标准 |
|---|---|---|---|
| A1 | **Docker 镜像** | dae 有 `Dockerfile` + `docker-compose.yml`；容器是主要分发方式之一 | 多阶段构建（builder 固定 nightly+bpf-linker；runtime 含 loader/eBPF 对象/示例配置）；`docker run --privileged --network host` 冒烟通过并写入 README |
| A2 | **发行包（tarball）** | dae 有 release 工件（多架构） | tag 产出 `sodama-<ver>-x86_64.tar.zst`：loader、`ebpf-rs.o`、systemd、install.sh、示例配置、README/LICENSE；解包后 `install.sh` 可装可卸 |
| A3 | **发行 CI** | dae 有 release/prerelease/daily-build 工作流 | tag `v*` 触发：构建 → 冒烟（容器内 `--version`/单测）→ 上传 release 工件 + SHA256SUMS；失败不产出 |
| A4 | **版本与 CHANGELOG** | `--version` ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：三行输出（版本 + git sha（build.rs 注入，无 git 回落 unknown）/ 运行时 + 平台 / 许可），子命令分派前处理、无需 root，`version` 子命令同义；余：CHANGELOG 从提交生成、README 顶部版本徽章 | `--version` 输出语义化版本 + git sha；CHANGELOG 从提交生成；README 顶部版本徽章 |
| A5 | **shell 补全** | ✅ **已完成（2026-10-16，v1.4，ADR-0068）**：`sodama completion bash\|zsh\|fish`（脚本内嵌，零外部文件依赖）+ 预生成副本 `install/shell-completion/sodama.{bash,zsh,fish}`（与生成器一致性由单测锁定）+ `install/install.sh` 部署（补全目录自动探测） | 补全覆盖 CLI 顶层子命令与常用参数；bash/zsh/fish 三份可用 |
| A6 | **Makefile / 任务入口** | dae 有 Makefile（build/test/release 单入口） | `make build / test / lab / install / release` 目标；与新贡献者文档一致 |
| A7 | **发行包体系** | 本机 Arch；dae 上游有 AUR/发行版打包路径 | ✅ **已完成（2026-10-24，v1.0.0，devlog §26）**：AUR 双包 `packaging/aur/sodama`（源码，git tag；nightly+bpf-linker+wasm-pack 前置检查）与 `sodama-bin`（预编译 tarball，本地 `makepkg` 实测 5.8 MB）；`packaging/make-release.sh` 生成 musl 静态发布包（引擎+面板+systemd+配置+补全+文档，5.6 MB）；Arch 资产 `packaging/arch/`（`Type=notify` 单元 + 幂等 datapath + 面板单元 + 0640 样例）；使用说明 `docs/arch-linux.md`；两包 `!strip` 保护 eBPF `.symtab`/`.BTF` | ✅ 已达（本地构建/安装校验通过；AUR push 与 GitHub Release 上传归用户） |
| A8 | **许可证一致性审计** | 🟡 公开版已把源码头统一为 `AGPL-3.0-only`；依赖 SBOM/第三方清单见 `THIRD_PARTY_LICENSES.md`，`cargo deny` 待 CI 接入 | 全部源码/配置文件头统一为 AGPL-3.0-only；`cargo deny`/SBOM 跑通并记录第三方许可证清单 |
| A9 | **install.sh 升级/回滚** | 当前只有装/卸 | `--upgrade`：保留上一版二进制，systemd 启动失败自动回滚；dry-run 覆盖新路径 |
| A10 | **容器/内核兼容性矩阵文档** | eBPF 对内核/BTF/CAP 有要求 | ✅ 已完成：`docs/openwrt.md` §2 给出 kernel fragment（**NAMESPACES/NET_NS 是硬前提，官方镜像默认未开**——已用 QEMU 实测确认）与逐项排障；`docs/deploy.md` 含容器 capability 清单 |
| A11 | **OpenWrt 支持（P0）** | ✅ 应用侧已完成（2026-10-05）：musl 静态交叉构建（x86_64 7.2MB / aarch64 6.3MB / armv7 6.2MB，`lab/build-openwrt.sh`，zig+cargo-zigbuild）；`install/openwrt/` ipk 包（预编译产物 + procd + uci + 数据面对 helper）；内核 fragment 与文档 `docs/openwrt.md`。代码侧仅一处 musl 适配（`MSG_WAITFORONE` 类型；`malloc_trim` 已有 cfg 门控）。官方镜像 QEMU 冒烟跑通 ipk/二进制并实测确认**官方内核缺 CONFIG_NAMESPACES**；⏸️ **暂停**（按用户指示移到后续）：自编内核镜像上的完整 eBPF 冒烟（cmake 3.30.5 bootstrap 宿主补丁已定位，构建目录 <openwrt-build-dir> 保留） | 后续：应用 cmake 补丁 → 自编镜像跑通完整冒烟；aarch64 真机验证；SDK 一键出 ipk |
| A12 | **CLI 取证与日志（v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：`export outline`（`key_docs()` 同源机器可读 schema）；`sysdump --out *.tar.gz`（自实现 ustar + stored gzip：status/路由/网卡/sysctl/nft/iptables 现场，`--json` 保留旧形态）；日志轮转三参（`--logfile`/`--logfile-maxsize`/`--logfile-maxbackups`，产物 `<log>.<N>.gz`）+ `log_level`（0=off..4=debug，非法回落 info）；`trace` 见 C5 | ✅ `tar xzf` 实测可解；轮转/级别有单测 |
| A13 | **systemd 单元强化（v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：`Type=notify` + `sd_notify`（READY/RELOADING/STOPPING；无 `NOTIFY_SOCKET` 时 no-op）、`ExecStartPre=sodama validate` 门禁、`StartLimitIntervalSec=300`/`StartLimitBurst=5`、`OOMScoreAdjust=-100`、`Restart=on-abnormal`、`TimeoutStartSec=120`/`TimeoutStopSec=30`、`LimitNPROC=4096` | 实机验证需 systemd 环境（开发机以命令行/VM 跑，如实登记） |

## B. 出站协议余项（如实边界）

| # | 事项 | 现状/依据 | 验收标准 |
|---|---|---|---|
| B1 | 其余 SIP003 插件：simple-obfs（http/tls）、v2ray-plugin（ws/tls） | 解析即报错（ADR-0055 边界） | 与 Go/参考服务端跨实现用例（对照 `ss` 插件链） |
| B2 | SSR 完整形态：`auth_aes128_md5/sha1`、`auth_sha1_v4`、`auth_chain_a/b`、`obfs_*` 全家族 + UDP | origin+plain 子集（ADR-0054 边界） | 每个 proto/obfs 至少 1 条黄金向量 + 1 个跨实现 lab 用例 |
| B3 | ECH（hysteria2） | 已评估为边界（ADR-0056）；前置：rustls/quinn 提供 ECH 或可插拔 TLS + HPKE 依赖 | 与 ot/quic-go ECH 服务端夹具互操作 |
| B4 | rustls 路径 uTLS（naive h2/h3、DoH h2/h3 等指纹） | P24 边界（ADR-0048） | 与自实现 CH 同款的指纹对齐测试 |
| B5 | ML-DSA / gecko（hysteria2 混淆/后量子） | hy2 v0 边界（ADR-0020） | 与 Go 客户端参数级互通 |

## C. eBPF 数据面（对标 dae ≈85%，2026-10-16 数据面对标批次后）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| C1 | L2/桥接程序族（TC L2 变体） | ✅ **已完成（ADR-0065 + ADR-0067）**：5 个 `*_l3` 程序 + `--link-hdr auto\|l2\|l3`（按 arphrd 自动判定）+ **`lan_egress` 角色（L2/L3，LAN 接口 ingress+egress 双钩子，反向 conntrack 刷新；2026-10-16）**；共 **14 个 TC 程序（7 角色 ×2）** + sk_skb offload | ✅ 内核级已实测（QEMU 7.2.8：`l3-attach`/`l3` 入门禁；`lan_egress` 由 `test-gaps` 断言 hooks） |
| C2 | cgroup 钩子（connect/bind/sendmsg…） | **6/6 已挂载**（sock_create/release、connect4/6、sendmsg4/6；P17b）——用于 pname 采集与 `pname()` 规则（WAN egress 新连接，见 `status` hooks）；bind 与 sock_addr 重定向用例未做 | 至少 connect/bind 两钩子的 sock_addr 重定向用例 |
| C3 | ringbuf 事件通道 | ✅ **已完成（2026-10-16，ADR-0065）**：`event_ringbuf`（256KiB）+ `SodaEvent` 72B（对照 `struct dae_event`）+ 5 类事件（blocked/溢出×2/rebind/redirect 失败）+ 1s/键限速 + 丢弃计数；热路径 printk 退出（保留 `--ebpf-debug` 门控）；loader 常驻消费线程（1 条/秒/类型日志限速）+ status `events` + 9 个 metrics；**并批次交付 `skb_send_sock` 记账**（fentry→kprobe 回退 + 用户态 BTF 解析替代 CO-RE + `offload_sent` 键摘除时回收） | 高频事件可采样上报（已具备）；待生产回验：`status.events`/`offload_sent.*` 随流量增长且 `dropped_kernel` 有界 |
| C4 | XDP 可选路径调研 | ✅ **已完成（2026-10-16）**：调研结论沿用 devlog §15（AF_XDP/数据面搬 XDP 否决），按 backlog 建议落**最小计量探针** `sodama_xdp_observe`（`--xdp <iface>` 可选挂载，恒 `XDP_PASS`、只计数不干预；status `xdp` + 2 个 metrics） | 调研报告（收益/兼容性）已具备；待实测：软路由网卡上的 native/generic 可用性与计数准确性 |
| C5 | `trace` 判决事件与内核侧过滤 | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：新 map `trace_filter_map`（`SodaTraceFilter`：协议/端口/IP 版本/drop-only 位图，内核侧先裁）+ 新事件 `SODAMA_EVENT_TRACE`（判决在 `SodaEvent.pad[0]`；block/direct/存活门禁/redirect 4 判决点）；CLI 侧再按条件过滤（同语义，单测锁定）；daemon 落盘 `/run/sodama-trace.log`（不可写退 `/tmp`） | ✅ 单测 + 矩阵运行；边界：复用常驻事件通道（非独立 tracepoint 程序），高频判决下事件环可能丢尾帧（偏离 1） |

## D. 配置系统（≈65%）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| D1 | `include` 展开 | ✅ 已完成（代码已实现：入口目录相对路径约束 + 循环检测 `circular include is not allowed` + 对照 `config_merger.go` dfsMerge 语义；2026-10-08 文档滞后修正） | — |
| D2 | 全局健康检查参数全量（间隔/容忍度/策略） | 子集 | 配置→健康循环行为的一对一测试 |
| D3 | `config_merger` deferred 项收尾 | 显式列出 | deferred 列表清零或标注永久不做 |
| D4 | 组级 override 细节（组级 dialer 参数覆盖） | 余项 | lab 双组覆盖用例 |
| D5 | **global 生效面收口（v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：27 → **36** 生效（不生效 18 → 9，余项启动显式告警）——`log_level`（0=off..4=debug，非法回落 info）、`so_mark_from_dae`（含数据面 `dae_socket` 读 config_map）、`mptcp`（内核不支持回落 TCP）、`allow_insecure` 全局默认、`udphop_interval` 全局、`fallback_resolver`（bootstrap → fallback → 系统解析链）、`disable_thp`（仅本进程）、`disable_waiting_network` + 启动等待网络（默认开、30s 上限、超时只告警）、`auto_config_kernel_parameter`（写 sysctl 并登记期望值，被改回即纠正）、`tls_fragment*`（仅自实现 TLS 路径）、`utls_imitate`/`tls_implementation`（chrome 口径）、`pprof_port`（127.0.0.1 诊断端口）、`bandwidth_max_tx/rx`（令牌桶；限额时 relay 新连接走拷贝泵） | 配置→行为有一对一单测/实测；边界见 ADR-0069 偏离清单 |

## E. 转发面（≈78%）

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| E1 | UDP endpoint pool / full-cone NAT（网关侧 UDP 代理） | ✅ **已完成（2026-10-16，v1.4，ADR-0068）**：full-cone 端点池（同一客户端 src 多目标复用 1 出口端点，回包按上游真实来源注入）+ 分类 TTL（DNS 17s / QUIC·域名 300s / 代理地板 300s）+ 负缓存 + 1s janitor；内核级 `test-udp-cone`（双目标 4 报文复用 1 端点）；前置事实仍成立：网关侧全链真机验证（2026-10-08） | ✅ 已达（`test-udp-cone`）；边界：full-cone 仅直连型出口，代理型仍 dest-affine（ADR-0068 偏离 1） |
| E2 | backlog fuse / 连接计费 | **fuse 已交付（ADR-0067，2026-10-16）**：`tcp_offload_pause` + 两阶段 drain/lift + 用户态泵 + `SODAMA_FUSE_MAX_BACKLOG`；余：连接计费未做 | 压测下 fuse 生效（真实触发留生产观测；判定逻辑单测锁定）+ 计费可导出 |
| E3 | offload 完整形态（fuse 失效路径与统计） | **fuse 已交付（ADR-0067）**：生命周期/回收（O4/O8）+ pause engage/lift/失败计数（`status.offload_fuse`）+ 注册时清残留 | ✅ 失效全路径与计数可观测（无失败残留由 `test-fuse` 断言） |
| E4 | **UDP GSO（`UDP_SEGMENT` 聚合发送，v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：`send_gso_udp` 按 `UDP_SEGMENT` cmsg 发送（≤64 段；EMGSIZE/EINVAL/EOPNOTSUPP 回落逐包）；status 增 `gso_sends/gso_datagrams/gso_unsupported` | ✅ 计数可观测；回落路径不重试不丢包 |
| E5 | **带宽限额 `bandwidth_max_tx/rx`（v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：进程级令牌桶（`100`=100 Mbit/s、`10mbps`/`1g`/`8192b` 口径），reload 可 `set_rate` 热更新；限额生效时 relay 新连接走拷贝泵（splice 在用户态不可节流） | ✅ 单测（`rate_limiter_throttles_small_writes`）；边界：已建立 splice 连接不受 reload 后新限额影响（偏离 3） |
| E6 | **代次排空预算（drain，v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：`reload/suspend --drain=N` 等旧代在飞会话自然排空预算（超预算不强制关闭，如实回报余量与耗时；对照 dae `control_plane_drain.go`） | ✅ 语义有实测（如实回报）；强制路径仍为 `--abort`（A1，ADR-0068） |

## F. 嗅探 / IPv6

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| F1 | QUIC 观测 → 域名拨号（UDP dial_mode/punt） | 仅观测 | UDP 域名拨号 + punt 用例 |
| F2 | ICMPv6 error 转发 | 未做 | netns 用例 |
| F3 | IPv6 分片补全 | 非首片跳过 | 分片重组/转发用例 |
| F4 | **`real_domain_runtime`（域名确认集，v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：确认集（FIFO 8192 + 负缓存 300s + 近似单飞）+ `dns.rs::has_fresh_any_scope`（不限定 ECS 作用域，对照 dae `HasDnsKnowledge`）；`dial_mode=domain` 时 DNS 已知域名交节点远端解析；status `real_domain` 段 | ✅ 3 单测；单飞为近似（偏离 9） |

## G. 性能与质量

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| G1 | 与 Go 版**同机对拍** + **异机/公网口径**（六路径基准） | **已完成**：P33.2 四方对比（direct/ss，ssserver 上游 + 全双工夹具 + 5 次中位数；并发扩展/内存/线程/perf 剖面齐备；`docs/benchmark-report.html` §3）——sodama 与 dae 同机同拓扑；UDP 四方对拍补齐（`lab/perf/udp.sh`：20k pps 0 丢包，sodama CPU 630 ms/40k 包 vs dae 2140 / sing-box 1580 / v2ray 1780；O7）；ss 方法 A/B（chacha vs aes-256-gcm）已做（O6）；**真实节点/公网口径（2026-10-05）**：`lab/perf/real.sh` 三方共用同一节点 + 固定后端 IP（VLESS-REALITY+Vision，v2ray skip）、8 MiB×17 轮：客户端 CPU_ms/GB sodama **6 233** vs dae 8 820（-29%）/ sing-box 8 557（-27%）；同后端轮 4 987 vs 8 613 / 10 290（见 roadmap P5） | 同机 + 异机口径均无回退；余：kTLS 目标异机重测（G2） |
| G2 | 生产级优化（THP/连接池/看门狗内存上限） | **M1+M2+M4+O8 已交付**：splice 零拷贝（Direct/VLESS 明文/kTLS 成功的 TLS，`--no-splice` 可关；vless 12.2→16.9 Gbps / CPU 380→60 ms；relay 8 流 15→21.6 Gbps） + eBPF printk 门控 + **kTLS 内核 TLS 实验（`--ktls`：TLS 48MB×4 11.67→12.32 Gbps、memcpy 29.4%→1.6%、TX+RX+splice 全链路，默认关）** + **M4 epoll worker 池：10k 连接 28 线程 / 32.1 MB、fail=0、风暴 25 606/s；stage 2 codec 全协议面（VLESS 全组合含 reality/vision/ws、Trojan、vmess、ss/ssr/anytls）vless-tls 2 000 连接 27 线程 / 61 MB（线程模型 4 011 / 222 MB）；offload 看门狗单线程化（每 offload 连接 0 线程）；io_uring A/B 结论不引入；`SODAMA_NO_REACTOR=1` / `SODAMA_REACTOR_CODEC=0` 可关（ADR-0058）**；**O8 缓冲池/回收：按字节封顶 8MB 池 + UDP 槽按需增长 + SIGTERM 有界优雅退出（50 在途整机 462ms、无 tc 残留）+ 30s malloc_trim（churn 300 条 RSS 无增长）**；方向与待办（ss 路径 O1/O2 按用户方向暂缓——以 VLESS 为基准；kTLS 异机复测）在 `docs/optimization-roadmap.md`（O1–O10） | 各优化项有开关与压测数据；M2 对账：memcpy ✓；≥13 Gbps/≤1000 ms 受本机夹具（≈12.5 Gbps 封顶）与内核密码引擎速度限制，待异机口径重测；M4：✅ 10k 连接 28 线程 / 32.1 MB、fail=0；stage 2 验收：ss/ssr/ss2022/anytls 均逐连接确认 codec 投递、offload 200 条 0 线程回收全过；O8：churn/退出均有界 |
| G3 | fuzz（`.dae` 解析 / DNS 报文 / CH 解析） | ✅ **已完成（2026-10-16，v1.4，ADR-0068，确定性形态）**：`loader/src/fuzz_smoke.rs`（固定种子 xorshift 变异器 + 真实语料种子；覆盖 .dae 配置含 include / DNS 报文 / 出站链接全家族 / 订阅含 SIP008 / TLS CH / QUIC Initial / HPACK-QPACK；`SODAMA_FUZZ_ITERS` 可调，默认 4000 轮 ≈1-2s）；不走 libFuzzer（不可复现工具链） | ✅ 已达（2 项测试常态运行；口径为确定性变异测试） |
| G6 | `lab.sh verify` 探针陈旧 | `test_proxy`/`test_host_proxy`/`test_reload`/`test_rebind`/`test_fault_*` 断言 回包含 `orig_dst=`，但仓库内无任何夹具产生该字段（历史遗留）；O8 期间实测 6 项因断言失败 | 修复夹具或断言（使 verify 回到 9/9）；在此之前专项用例（test-ss/vless/offload/udp）为准 |
| G4 | 特权内核加载类 CI | CI 只编译+单测 | self-hosted runner 或 QEMU 中跑 verify 子集 |
| G5 | 长稳 soak 纳入 CI（夜间） | 手动 | 夜间任务 + 失败告警 |
| G7 | **运行时观测基线（v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：1h 流量历史（1s 采样 → status `traffic` 段 + 2 个 metrics；对照 dae `runtime_stats.go`，1s 粒度较 dae 250ms 更粗）；告警节流 `AlertPacer`（首次必发 + 冷却窗口 + 累计观察次数；接入 redirect_track/conn_state 容量告警）；`pprof_port` 诊断端口（`/` 文本、`/json`；非 Go pprof 火焰图——偏离 5） | ✅ 可经 status/metrics 取数 |
| G8 | **lab 与内核级用例（v1.5）** | ✅ **已完成（2026-10-16，v1.5，ADR-0069）**：钩子生命周期用例 `lab.sh test-hooks`（reload 切代前后钩子集合逐项不变——把 ADR-0065「形态消解」结论变断言）；lab 基建修复：就绪等待 20s→50s（适配 30s 网络等待）、`--config` 权限幂等 0640、配置加载失败带首条诊断详情；单测 329 → **346 + 3（ebpf-logic）**；矩阵 `verify 12/12 + cap 12/12` | ✅ 已达（cap 新增 `test-hooks`） |

## H. 文档

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| H1 | 顶层 `README.md` 状态区重写 | 数字停留在 P5 时期（121/121、ADR-0031 等），与当前（257 单测、ADR-0058、G1 真实节点数据）脱节 | 状态表与实际一致；仓库结构/快速开始重写 |
| H2 | 用户手册（配置参考 + Go dae → sodama 迁移指南） | 配置参考 ✅ **已生成（v1.4，ADR-0068）**：`docs/config-reference.md`（由 `sodama config-doc` 从 `key_docs()` 生成 + drift 单测锁定）；迁移指南仍散在 README/deploy | 迁移指南单独立文：逐项差异表（配置/CLI/部署） |
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

## J. 面板能力面（2026-10-17 用户点名；高优先级）

来源：生产面板 v2.0 部署与引擎 A2/修复轮后的能力差清点。主题：**引擎已具备、但面板尚未呈现的能力**。

| # | 事项 | 现状 | 验收标准 |
|---|---|---|---|
| J1 | **UDP 走向可视化** | 状态面/面板只见计数，不区分走向 | 呈现哪类流量走代理 UDP、哪些 direct 回退、`raw_udp` 回退原因；可下钻 |
| J2 | **组级 `udp_check_dns` 探测结果** | 未呈现 | 组级探测结果可见，并与节点 UDP 能力联动提示 |
| J3 | **UDP NAT 未启用时的显式说明** | 无 | 生产未启用 UDP NAT 时面板显式标注（避免「UDP 计数恒 0」被误读为故障） |
| J4 | **UDP 相关旋钮「改了就生效」回执** | 无 | UDP 旋钮保存后回执当前生效值（含 `gso_*` 计数联动） |
| J5 | `export outline` schema 浏览 | 无 | 面板可浏览导出的 outline/schema |
| J6 | `dns-bench` 一键入口 | 无 | 面板可触发 DNS 基准并展示结果 |
| J7 | `status.events` 事件流可视 | 无 | 事件流列表（时间 / 类型 / 详情），可过滤 |
| J8 | `xdp` / `offload_fuse` / `offload_sent` 明细视图 | 无 | 数据面卡片展示该三项明细 |
| J9 | Prometheus 端点导出 | 无 | 面板可导出 / 展示 `/metrics` 抓取入口 |
| J10 | `pprof_port` 链接 | 无 | 面板提供诊断端口直达链接 |
| J11 | 日志轮转三参 | 无 | 面板可配置 / 展示日志轮转三参数 |
| J12 | 订阅缓存命中 / 失败负缓存生效面标注 | 无 | 面板标注订阅缓存命中率与负缓存生效状态 |

执行顺序建议：**J 类（用户点名，面板能力面）优先于 A 类打包**；I 类已完成（I1 → I2 → I5 → I4 → I3）。

## 明确不在范围（永久）

- **daed Web UI / GraphQL / 鉴权**：daemon 是独立项目，sodama 只做本体 + 状态面；
- **与 dae 二进制/配置 100% 兼容**：本项目定位研究性复现，配置语义对齐即可（ADR-0005/0011）；
- **Windows/macOS**：数据面依赖 Linux eBPF，不做跨平台。

## 使用方式

- 规划下一版时，从 A 类（工程化/发布）开始——它是「从可运行到可分发」的最后一段；
- 协议类（B）与数据面类（C）按需穿插；
- 每完成一项，同步 `parity-status.md` 覆盖度数字与证据锚点，并在 CHANGELOG 记录。

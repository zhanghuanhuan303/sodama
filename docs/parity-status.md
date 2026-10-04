# 对标进度：dae（Go）↔ sodama（全 Rust）

- **版本**：v2.13 · 2026-10-05（M3 Vision-over-TLS：tls/reality 外层 + 双向 XTLS DIRECT、ws/wss 逐字节、真订阅 e2e；ADR-0057）
- **口径**：「覆盖度」= 该域**功能点覆盖**的粗估（我方可用 ÷ dae 等价能力），
  **不是代码行数、不是性能等价**；数字是判断值，逐行给出证据出处。
  按口径分两档汇总：主链路（日常代理网关）与 dae 全功能面。
- **证据来源**：本仓库 `sodama/` 实测（ADR/NOTES/README）、
  上游 clone `dae/`（`main@e3fee8f`）源码清点、真实订阅节点实测。

## 表 A · 分域对照

| # | 域 | dae（Go 原版） | sodama（全 Rust） | 覆盖度 | 关键差异 / 证据 |
|---|---|---|---|---|---|
| 1 | **eBPF 数据面（程序/hook）** | 23 程序（13×TC L2/L3 变体 + `sk_skb` offload + 5×cgroup + kprobe/fentry）、24 map、4,403 行 C（HTML §2.1） | 8 程序（7×TC 含单臂 dual-role + `sk_skb` offload）、14 map（BTF）、~1.1k 行 Rust；**cgroup2 钩子 6/6 已挂载（pname 采集，P17b）** | **≈65%** | 主路径语义逐一对齐；余：L2/桥接变体、kprobe/fentry、ringbuf。优势：C 已退役（ADR-0025）、TCX 退出即摘钩 |
| 2 | **分流主链路** | tproxy/direct/block、控制面 DNS override、五钩子角色、conn_state、双 epoch 热重载、redirect_track 单写者 | 同上全有 | **≈95%** | K0–K3 九用例 ×2 拓扑全过；`verify` 9/9（ADR-0009/0010，NOTES §11.16） |
| 3 | **规则引擎** | dip/sip/dport/sport/l4proto/ipversion/dscp/mac/pname/domain/geoip/geosite/fallback + not/and + mark/must + sub/subnode | dae 现有函数集全覆盖（geoip/geosite 自 `.dat` 编译期展开，含 attr/ext；pname 走 cgroup2 采集；domain 走 DNS 位图 + 预计算索引）；`sub/subnode` 本版 dae 无此函数 | **≈95%** | **编译产物与 dae 逐字节对拍 5/5**（ADR-0010/0033）；真实 `.dat` 计数与上游清点一致（geoip:cn 15,357 / geosite:cn 6,623）；余项：geosite 负载未纳入对拍、流式解析、pname 用 comm 非 argv basename（CO-RE）；geodata 搜索目录已含 XDG（P18e） |
| 4 | **配置系统** | 全量 `.dae`（global/dns/routing/group/subscription/node/include）全部生效 | 全量解析 + schema 校验 + 行级诊断；生效 routing 子集 + dns.upstream + **config 的 subscription/node/group 运行时**（ADR-0031）；deferred 项显式列出 | **≈65%** | 解析面与 `config_merger/parser` 语义逐条对齐；执行面为子集，deferred 不静默丢（ADR-0011）；缺 include 展开/全局健康参数全量、多组分派 |
| 5 | **DNS 子系统** | 透明 UDP/TCP、缓存、EDNS、regex、DoT/DoH/DoQ/H3 上游、`dns.routing` 请求/应答分流、ECS、嗅探 punt | 透明 UDP/TCP（含 **UDP6 接管**）、正负缓存 TTL（**optimistic cache + RFC 8767 后台刷新单飞** + **fixed_domain_ttl** + **ipversion_prefer**）、域位图、regex、EDNS/截断、reload 重投影、TCP keep-alive、**DoT/DoH(h2,h1,h3)/DoQ 上游**、**多上游 + `dns.routing`**、**bootstrap_resolver**、ECS 注入/**响应回填/ecs_cache**、`qname(file:)`/`sip()`/`pname()`（sodama 扩展） | **≈97%** | ADR-0034–0040/0047/0050/0052/0053；余 H3 推送/动态表等细节不涉；ECS 为 sodama 扩展（dae 无） |
| 6 | **出站协议栈** | ss（含 2022/插件/shadowtls）、ssr、trojan、vmess、vless、tuic、hysteria2、juicity、naive、http、socks5、anytls | ss classic + **ss2022**、**ssr（origin+plain + 流密码，TCP）**、**shadow-tls 插件（v1/v2/v3 + ss classic）**、trojan、vmess、vless(tcp/ws/**reality+vision**/**tls+vision（M3 双向 XTLS DIRECT）**)、tuic v5（**0-RTT 尝试**）、hy2、**juicity v0（QUIC + exporter 认证 + trojan 风格元数据，TCP+UDP）**、anytls、socks5、http、**naive（HTTP/2 与 HTTP/3 CONNECT + Basic）**、direct；**REALITY ClientHello 对齐 uTLS Chrome-120** | **≈86%**（家族）· **≈99%**（主流可用性） | ADR-0016–0020/0026/0027/0041/0042/0048–0051/0054/0055/0057；**12 家族全有**；**Vision 组合齐（tls/reality/ws/wss，lab 逐字节 + 真订阅 48 节点 e2e）**；**48 条真机 REALITY 全健康**；余 simple-obfs/v2ray-plugin 等其余 SIP003 插件、SSR `auth_*`/`obfs_*` 与 UDP、rustls 路径 uTLS；**ECH：已评估边界（ADR-0056，`ech=` 显式报错不静默）**；naive 边界：Basic 依赖外层 TLS |
| 7 | **转发面** | relay（并发上限/backlog fuse/计费）、UDP endpoint pool（full-cone）、offload 完整 | relay（SO_MARK/半关闭/janitor/**`--max-conns` 并发上限 + `limit_rejected` 指标**）、UDP NAT（ss/vless/vmess/tuic/hy2 协议侧可用；网关策略默认 UDP 直连）、offload 最小实现 | **≈78%** | 512KB 逐字节、UDP 会话复用、offload 用户态零字节均实测（ADR-0015/0022）；并发上限已补（P18e，ADR-0042）；缺 backlog fuse/计费 |
| 8 | **多节点·订阅·健康检查** | subscription + node + group（min/max/random/fixed）+ alive set + 间隔/容忍度 + 延迟策略 + sticky IP 等 | `--subscribe`/config 订阅（HTTP(S)/file）、group filter/policy、经节点健康探测（TCP+UDP）、拨号失败切换、SIGHUP 订阅热更新、按规则分派不同组、**代理域名粘滞 IP（3 次失败作废 + reload 重置）** | **≈85%** | ADR-0031/0042/0043/0047；lab 双组交叉 + 真机 66/66；余组级 override 细节 |
| 9 | **嗅探与域名策略（dial_mode）** | 内核侧 TLS/HTTP/QUIC 嗅探 → `domain/domain+` 拨号、sniff-punt | 用户态嗅探（TLS SNI / HTTP Host / h2c / QUIC Initial SNI）+ `dial_mode` 远端解析 + **sniff-punt（嗅探域在 relay 侧重判规则：direct/block/组重选）** | **≈90%** | ADR-0030/0044/0045；余 QUIC 观测→拨号、UDP punt |
| 10 | **IPv6** | 数据面 + 规则 + 协议全支持 | **TCP+UDP 全链**：v6 解析/tproxy（key 2）/UDP（key 3）/全部协议 v6 目标（含 ss UDP ATYP=4）/v6 direct/**DNS over UDP6 接管**/v6 嗅探；余 ICMPv6/分片 | **≈95%** | ADR-0032/0046；lab `test-v6` 四段全过（TCP、direct、UDP 2/2 跨实现、v6 DNS 源地址正确） |
| 11 | **部署自动化** | netns 自动搭建（移网卡/sysctl/tproxy 规则，`netns_utils.go`）、systemd（`install/dae.service`）、Docker、发行包、shell 补全 | `lab.sh` / `gateway.sh` 脚本级一键；**systemd unit（`install/sodama.service`，capability 最小集 + SIGHUP ExecReload）+ `install/install.sh`（--dry-run/--uninstall）+ `docs/deploy.md`（P18e）**；**OpenWrt：musl 静态交叉构建（x86_64/aarch64/armv7）+ prebuilt ipk 包（procd/uci/数据面对 helper）+ 内核 fragment 与 QEMU 冒烟（`install/openwrt/`、`lab/build-openwrt.sh`、`lab/openwrt-smoke.sh`、`docs/openwrt.md`）**；无 Docker/发行包/shell 补全 | **≈70%** | 真网关一键脚本体验接近（ADR-0029）；ADR-0042；余：Docker/发行包/shell 补全、OpenWrt 真机验证 |
| 12 | **运维面** | 主线较弱（daed 独立项目提供 GraphQL/Web UI） | SIGHUP/USR2、状态 socket（status/rules/config/maps/metrics/reload/suspend/resume）、Prometheus、sysdump/trace、日志轮转 | **≈90%** | 相对 dae 主线领先；daed 的 UI/鉴权不在范围（ADR-0021） |
| 13 | **质量工程** | Go 单测 244 文件/3.9 万行 + CI（bpf-test/build/docker/go-test…）+ fuzz | **240 单测** + verify 9×2 拓扑 + 专项用例（嗅探 punt/UDP v6/DoH-h2/DNS 选项/ECS 回填+刷新/QUIC 嗅探/分组/订阅/naive h2+h3/juicity/ssr/shadow-tls v1-v3/**Vision XTLS DIRECT 状态机**…） + **`lab/vision` Xray 夹具四模式逐字节** + 对拍 5 逐字节 + QEMU 双内核矩阵 + soak + 六路径基准 + `dns-bench` + REALITY e2e + RFC 9001/9000 黄金向量 + CI | **≈84%** | ADR-0010/0022/0025/0042–0057；CI 缺特权内核加载类测试 |
| 14 | **性能** | 生产级优化（THP/内存上限/连接池/看门狗） | 六路径基准（direct 31Gbps / relay 24.7 / offload 14.6 / ss 2.5）+ **同机四方对比（P33.2，5 次中位）：direct 24.3 / dae 24.2 / sing-box 22.6 / v2ray 13.5 Gbps（4×48MB 受夹具限制），ss 9.49 / 9.36 / **10.6** / 6.29 Gbps；RSS 28.6 vs 54.2/66.8/72.2 MB；64 流 direct 35.2 Gbps** + **VLESS 四方（明文/TLS）与 M1 零拷贝（splice 落地：vless 明文 12.2→16.9 Gbps、CPU 380→60 ms；relay 8 流 15→21.6 Gbps；perf 拷贝/建页消失；`--no-splice` 可关）** + **M2 kTLS（实验）：TLS 48MB×4 11.67→12.32 Gbps / CPU 420→400 ms；memcpy 29.4%→1.6%（达标）；TX+RX 解密错误 0、splice 4/4；8 流受同机夹具（≈12.5 Gbps）与内核 AES-GCM 速度（2.89 GB/s）限制** + **M4 epoll worker 池（ADR-0058）：10k 连接 28 线程 / 32.1 MB、fail=0、风暴 25 606/s；stage 2 codec 全协议面已交付（VLESS 全组合含 reality/vision/ws、Trojan、vmess、ss/ssr/anytls）：vless-tls 2 000 连接 27 线程 / 61 MB（线程模型 4 011 / 222 MB）、vision 夹具四模式逐字节、吞吐 A/B +5~25%；offload 看门狗单线程化——每 offload 连接 0 线程（200 条实测 28→28 线程）且生命周期回收全过；io_uring A/B 结论为不引入（交叉配对中位 8.18 vs 8.11 GB/s，噪声内）；O6：AEAD 方法实测定调（16KB 块 chacha 1.73 vs aes-gcm 1.57 GB/s，保留 chacha、vmess auto→chacha、组内同分优先 chacha）；O7：UDP recvmmsg/sendmmsg + 16 分片会话表 + 4–8MB 转发缓冲，20k pps 0 丢包 CPU 630 ms/40k 包（dae 2140 / sing-box 1580 / v2ray 1780），四方对拍 `lab/perf/udp.sh`；O8：缓冲池（按字节封顶 8MB）+ UDP 槽按需增长 + 有界优雅退出（50 在途连接整机 462ms、无 TC 残留）+ 30s `malloc_trim`（churn 300 条 RSS 无增长），并修复 ss 帧边界 EOF 误报截断；`SODAMA_NO_REACTOR=1` / `SODAMA_REACTOR_CODEC=0` / `SODAMA_UDP_BATCH=0` 可关**；**G1 真实节点/公网口径（2026-10-05）**：sodama/dae/sing-box 共用同一真实 VLESS-REALITY 节点与固定后端、8 MiB×17 轮，客户端 CPU_ms/GB **6 233 vs 8 820 / 8 557**（同后端轮 4 987 vs 8 613 / 10 290），节点限速为共同上限（宿主直连 ≈20.5 Mbps，v2ray 无 REALITY skip）；并发扩展/perf 剖面/优化方向见 `docs/perf-report.md`、`docs/optimization-roadmap.md`、`docs/vless-proposal.html` | **≈85%** | 同机同拓扑同上游（ssserver/sing-box vless）+ 全双工夹具 + 异机真实节点；余：kTLS 目标异机重测、relay/offload/UDP 同机对拍、UDP 批量化（O7） |
| 15 | **真实订阅生态** | 全原生 | 订阅#1（50×vless-ws）✅；订阅#2：anytls ✅、**REALITY+Vision ✅（自实现 TLS 1.3，ADR-0041）** | **≈85%** | ADR-0026/0027/0028/0041；边界外协议可桥接过渡 |

## 表 B · 汇总

| 口径 | 完成度 | 说明 |
|---|---|---|
| 研究目标（可行性验证） | **100%** | aya 全栈可行、规则逐字节对拍、C 数据面退役、真实节点浏览器可用——结论闭环 |
| 核心主链路（分流/规则/DNS（含 DoT/DoH h2+h3）/主流协议/转发/运维） | **≈93%** | 日常「tproxy 网关 + 主流节点」已可用；P21–P31 补齐嗅探 punt/粘滞 IP/DoH/DNS 选项（含 ECS 回填与后台刷新）/UDP v6/Chrome-120/naive/HTTP-3/juicity/SSR/shadow-tls；232 单测 + lab 专项全绿 + 真机自检 66/66 |
| dae 全功能面（嗅探/多节点/geo/IPv6/安全 DNS/系统集成） | **≈83%（±5%）** | 结构性缺口（P19–P31）收官；IPv6（TCP+UDP）≈95%、规则≈95%、DNS≈97%、嗅探≈90%、协议家族≈85%（12 家族全有 + shadow-tls 插件；余其余 SIP003 插件/ECH 细项） |

## Top 缺口（按优先级）

1. ~~嗅探 + dial_mode（远端域名解析）~~ **已完成（P14，ADR-0030）**；**QUIC SNI（P20，ADR-0044）**；~~sniff-punt~~ **已完成（P21，ADR-0045）**——余：UDP（QUIC）域名拨号/punt；
2. ~~多节点/订阅/组 + 健康检查~~ **已完成（P15/P18e/P19）**；~~sticky IP~~ **已完成（P23，ADR-0047）**——余：组级 override 细节；
3. ~~IPv6 数据面~~ **TCP（P16，ADR-0032）/UDP（P22，ADR-0046）均已完成**；余：ICMPv6/分片；
4. ~~geoip/geosite/pname~~ **已完成（P17，ADR-0033）**；余项：geosite 对拍覆盖、pname argv basename（CO-RE）、geodata 流式解析；
5. ~~DoH/DoQ + `dns.routing`~~ **已完成（P18a/b/c）**；~~DoH h2/H3、optimistic cache（含 **RFC 8767 后台刷新**）/`fixed_domain_ttl`/`ipversion_prefer`/bootstrap_resolver~~ **全部完成（P23/P26/P29，ADR-0047/0050/0053）**；~~ECS 注入/响应回填/ecs_cache~~ **已完成（P18/P28，ADR-0038/0052，sodama 扩展，dae 无）**——DNS 域闭环；
6. ~~协议细节：REALITY/Vision/uTLS~~ **REALITY+Vision（P18d）、ss2022/http（P18e）**；**uTLS Chrome-120 对齐 + Vision 上行 splice + TUIC 0-RTT 已完成（P24，ADR-0048）**；~~naive（HTTP/2 CONNECT）~~ **已完成（P25，ADR-0049）**；~~naive H3/`naive+quic`~~ **已完成（P26，ADR-0050）**；~~juicity~~ **已完成（P27，ADR-0051）**；~~ssr~~ **已完成（P30，ADR-0054，origin+plain 子集）**；~~插件/shadowtls~~ **已完成（P31，ADR-0055，v1/v2/v3 + ss classic；附带修复 CH 严格解析兼容性）**；ECH **已评估为边界（P32，ADR-0056：rustls/quinn 无客户端 ECH，`ech=` 显式报错不静默）**；余：simple-obfs/v2ray-plugin 等其余 SIP003 插件、SSR `auth_*`/`obfs_*` 与 UDP、rustls 路径 uTLS、ML-DSA/gecko；
7. ~~systemd/打包/daed~~ **systemd/安装脚本/CI 已完成（P18e，ADR-0042）**；余 Docker/发行包/shell 补全；daed（Web UI）不在范围；
8. offload 完整形态（fuse/计费）；~~relay 并发上限~~ **已完成（P18e，`--max-conns`，ADR-0042）**。

## 优势项（相对 dae 主线）

- **全栈 Rust**：数据面（aya-ebpf/BTF）已退役 C（ADR-0025），协议栈纯 Rust 跨实现验收；
- **规则编译逐字节对拍**：与 dae Go 编译器 5/5 一致，作为回归护栏（ADR-0010）；
- **用户态嗅探零数据面改动**：MSG_PEEK 只读采集（不消费字节）+ 逐协议域名编码对齐（ADR-0030）；
- **TCX 生命周期**：进程退出即摘钩，回滚天然安全；
- **状态面/可观测**：JSON socket + Prometheus + sysdump/trace（dae 主线没有，daed 才有 Web UI）；
- **单臂 dual-role 程序**、`--lan none` 一键真网关（ADR-0029）、本地 SOCKS5 入口（ADR-0028）；
- **IPv6 TCP 全链**（P16，ADR-0032）：v4-mapped 统一五元组 + sockmap key 2 + 协议目标 v6 编码 + v6 嗅探，真机实测通过；
- **规则语言与 dae 对齐**（P17，ADR-0033）：`.dat` 编译期展开（attr/ext、2M LPT 容量）、cgroup2 pname 采集；对拍 5/5 逐字节（含 geoip/pname）；
- **DNS 安全上游与分流**（P18a/b/c，ADR-0034/0035/0036）：DoT/DoH/DoQ 纯 Rust（rustls + quinn），真实公网三者验证；多上游 + `dns.routing` 请求/应答分流（asis 回原目的、应答重查、路由先于缓存 + 作用域化缓存键）；URL/路由热切换；
- **DNS 面鲁棒性**（P18b）：上游锁中毒恢复 + 单查询 panic 隔离，单次异常不再杀死 DNS 线程；
- **DNS 实用化**（ADR-0037/0038/0039/0040）：自定义名单文件（`qname(file:)`）+ `upstream_hits` 分流观测 + ECS 注入（`ecs=auto`）+ 客户端网段路由（`sip()` 请求/应答双侧）+ 进程名过滤（`pname()`，cgroup2→WAN egress→控制面 raw 反查 + GC）+ `dns-bench` 并发/多轮 p95；真网关国内→DoH+ECS/其余→DoH 实测、名单热加载即生效；
- **REALITY + Vision 自实现**（P18d，ADR-0041）：零新运行时依赖（`ring`/`x25519-dalek`/`ml-kem`）自写最小 TLS 1.3（Chrome 形状 ClientHello + X25519MLKEM768 + session_id 密封 + 证书 HMAC 绑定）+ Vision 帧层与下行 splice；订阅#2 66/66 节点入组，真机 HTTP/HTTPS 实测；
- **协议家族与运维面收尾**（P18e，ADR-0042）：SS2022（SIP022 三方法，BLAKE3 子密钥，与 shadowsocks-rust 跨实现）+ HTTP CONNECT 出站（与独立 Python 代理跨实现）；**订阅热更新**（SIGHUP 重拉 → 成员整体替换 + 同名继承健康，拨号热路径零锁竞争）；relay 并发上限（`--max-conns` + `limit_rejected` 指标）；组 UDP DNS 健康检查（`udp_check_dns`，失败回退 TCP）；eBPF 分片处理（v4 非首片跳过 / v6 分片头）；geodata XDG；嗅探 h2c（最小 HPACK）+ QUIC Initial 识别统计；
- **工程化闭环**（P18e，ADR-0042）：GitHub Actions CI（loader 构建/单测/eBPF 对象，固定 nightly-2026-09-29 + bpf-linker 0.11.1 + LLVM 23）、systemd unit（capability 最小集 + `ExecReload`）+ `install.sh`（dry-run/uninstall）+ `docs/deploy.md`；
- **多组分派 + 启动健壮性**（P19，ADR-0043）：规则按组名选组（组索引 = config 顺序，数据面 outbound 经 `conn_state` 回读，eBPF 零改动）；**启动期 DNS 自我阻塞修复**（initial reload 不再重拉订阅）+ 单上游失败不拖垮上游集 + DoQ 改 IP 字面量 + 健康并发 24 + `gateway.sh up` 启动自检（就绪才返回，失败自动回滚直连）；
- **嗅探组合收齐**（P20，ADR-0044）：用户态解 **QUIC Initial**（RFC 9001 固定盐 HKDF + 头部保护 + AES-GCM + CRYPTO→ClientHello）取 SNI——TLS/HTTP/h2c/QUIC 四类域名嗅探全有；RFC A.1/A.2 黄金向量 + 真实 quinn 首包 + lab Python 跨实现；`sniffing.quic_sni` 观测；
- **UDP v6 全链**（P22，ADR-0046）：sockmap key 3 + `IPV6_TRANSPARENT`/`RECVORIGDSTADDR` 透明监听 + v6 DNS 接管 + ss UDP v6 目标，lab 跨实现断言；
- **DoH over HTTP/2**（P23，ADR-0047）：自实现最小 h2 客户端（HPACK/流控/ALPN 门控；H1-only 服务端零额外连接），Go 标准库参考服务端跨实现；同批交付 sticky IP/bootstrap_resolver/DNS 三选项；
- **REALITY 指纹对齐**（P24，ADR-0048）：ClientHello 对 uTLS HelloChrome_120 逐项（签名算法/版本/ALPS/GREASE-ECH/Boring padding），真机 48 条 REALITY 全健康；Vision 上行 splice + TUIC 0-RTT；
- **naive 出站**（P25，ADR-0049）：复用 DoH 的最小 h2 客户端实现 HTTP/2 CONNECT + Basic 认证隧道（HPACK 编码 + 双向流控窗口更新 + 半关闭 END_STREAM），Go 标准库服务端跨实现（交互零延迟 + 512KB 逐字节）；H3 形态（`naive+quic://`）显式报错不静默；
- **HTTP/3 双项**（P26，ADR-0050）：`h3client` 最小 HTTP/3（控制流 + SETTINGS + QPACK 静态编解码 + DATA 帧 + CONNECT 隧道读写半），DoH 上游新增 `h3://`（连接复用 + 失败重建）、`naive+quic://`（ALPN=h3 CONNECT）；quic-go fork 离线夹具跨实现（h3 512KB 双向 + 连接复用断言）；varint 抽 `quicvarint` 共享（RFC 9000 §A.1 向量）；
- **juicity v0 出站**（P27，ADR-0051）：quinn + TLS exporter 认证（保持打开的认证单向流）+ trojan 风格元数据（IPv4/IPv6/域名）；TCP 每连接一条流、UDP 每 NAT 会话一条流（`[元数据][len u16][载荷]` 双工帧）；Go/quic-go 参考服务端跨实现（TCP 512KB + UDP 3/3）；
- **ECS 回填/ecs_cache**（P28，ADR-0052）：解析上游应答的 ECS 回显（RFC 7871 scope），按回填 scope 作用域化缓存 + 阶梯查找（请求前缀 → 本机 /32 → 更宽 /20//16//12//8//0），只向宽复用；状态面 `dns.ecs.echo/scope`；lab scope=0 与 /16 复用断言；
- **optimistic 后台刷新**（P29，ADR-0053）：stale 命中后单飞异步重查（失败保留旧条目、负应答取代过期正值、保留原查询 ECS 语义）；状态面 `dns.refresh.*`；lab「上游恰好 1 次刷新」断言；
- **SSR 出站（origin+plain）**（P30，ADR-0054）：流密码层（aes-*-cfb/ctr、chacha20-ietf、rc4-md5(-6)；EVP_BytesToKey(MD5) 派生；CFB/CTR 自实现保流状态）+ 连接层（IV/首段目标地址/URL-safe base64 链接解析）；`auth_*`/`obfs_*` 与 UDP 显式报错不静默；Go/outbound 夹具跨实现（交互 + 512KB）——出站 12 家族全有；
- **shadow-tls 插件（v1/v2/v3）**（P31，ADR-0055）：v1（rustls TLS1.2 + 裸隧道）/v2（首帧 HMAC-SHA1 前缀 + 应用密钥甄别票据）/v3（CH session_id HMAC + 握手期 relay 帧反变换 + 链式 MAC）；`CertPolicy::WebPki`（rustls-webpki 链+主机名+CV 验签）；`ss://…?plugin=shadow-tls;…`（ss classic；ss2022/UDP 显式报错）；Go/sing-shadowtls 夹具三版跨实现；**附带修复 TLS1.3 CH 的 supported_versions u8 与 GREASE 碰撞**（严格解析器兼容性，REALITY 路径同受益）；
- **嗅探组合收齐 + 重判**（P20/P21，ADR-0044/0045）：QUIC Initial 解密取 SNI + 用户态规则 VM 重放（域/LPM/not/AND/OR/must，与数据面逐条对齐）——嗅探四类 + punt 三路径（direct/block/组重选）均有 lab 交叉证据；
- **连接规模（M4，ADR-0058）**：epoll worker 池（16 worker，stage 1 splice + stage 2 codec：VLESS 全组合含 reality/vision/ws、Trojan、vmess）——hold 10k 连接 = 28 线程 / 32.1 MB（线程模型 20 011 线程 / 763 MB）、fail=0、建立 4 717/s；风暴 25 606 连接/s（线程模型 20 860/s）；同二进制 A/B 吞吐无回退（vless 64×1 MB +19%，relay 64×1 MB 37.9 vs 13.6 Gbps）；vless-tls 2 000 长连接 = 27 线程 / 61 MB（线程模型 4 011 / 222 MB）；vision 夹具 tls/reality/ws/wss 四模式逐字节；`SODAMA_NO_REACTOR=1` / `SODAMA_REACTOR_CODEC=0` 可关；
- **工程化验收**：QEMU 双内核矩阵、soak 三模式、六路径基准、协议三方交叉（Go 客户端/Python+Go 参考服务端）。

## 后续版本 Backlog（本版不做）

余项（协议/数据面/配置/转发/性能/文档）与**工程化打包**全量清单见 [`docs/backlog.md`](./backlog.md)：
A 类为工程化与发布（Docker 镜像/发行包/发行 CI/版本与 CHANGELOG/shell 补全/
Makefile/发行版打包/许可证一致性审计/升级回滚/内核兼容矩阵），B–H 为协议与数据面余项
（simple-obfs+v2ray-plugin、SSR auth_*/obfs_* 与 UDP、ECH 前置条件、eBPF L2/cgroup/ringbuf、
include 展开、UDP endpoint pool、fuzz、同机对拍、顶层 README 重写等）。
当前版本口径：A–H 均**不在本版范围**（含 ECH 边界，ADR-0056）；完成时同步本表与 CHANGELOG。

## 维护说明

- 每完成一个阶段（P14+），更新受影响行的「sodama」「覆盖度」「证据」三列，并在文首版本行记录日期；
- 覆盖度是**判断值**：若某域完成度大幅变化，必须在证据列给出新的实测/文档锚点，不允许只改数字；
- 与 `docs/adr/` 的关系：ADR 记录「为什么这么做」，本表记录「做到了哪里」；
  两处不一致时以 ADR + NOTES 实测为准，本表先改。

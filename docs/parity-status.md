# 对标进度：dae（Go）↔ mini-dae（全 Rust）

- **版本**：v2.1 · 2026-10-04（P20 QUIC Initial SNI 嗅探：用户态解 Initial 取 ClientHello SNI；嗅探组合收齐）
- **口径**：「覆盖度」= 该域**功能点覆盖**的粗估（我方可用 ÷ dae 等价能力），
  **不是代码行数、不是性能等价**；数字是判断值，逐行给出证据出处。
  按口径分两档汇总：主链路（日常代理网关）与 dae 全功能面。
- **证据来源**：本仓库 `mini-dae/` 实测（ADR/NOTES/README）、
  上游 clone `dae/`（`main@e3fee8f`）源码清点、真实订阅节点实测。

## 表 A · 分域对照

| # | 域 | dae（Go 原版） | mini-dae（全 Rust） | 覆盖度 | 关键差异 / 证据 |
|---|---|---|---|---|---|
| 1 | **eBPF 数据面（程序/hook）** | 23 程序（13×TC L2/L3 变体 + `sk_skb` offload + 5×cgroup + kprobe/fentry）、24 map、4,403 行 C（HTML §2.1） | 8 程序（7×TC 含单臂 dual-role + `sk_skb` offload）、14 map（BTF）、~1.1k 行 Rust | **≈65%** | 主路径语义逐一对齐；缺 L2/桥接变体、cgroup 钩子、ringbuf。优势：C 已退役（ADR-0025）、TCX 退出即摘钩 |
| 2 | **分流主链路** | tproxy/direct/block、控制面 DNS override、五钩子角色、conn_state、双 epoch 热重载、redirect_track 单写者 | 同上全有 | **≈95%** | K0–K3 九用例 ×2 拓扑全过；`verify` 9/9（ADR-0009/0010，NOTES §11.16） |
| 3 | **规则引擎** | dip/sip/dport/sport/l4proto/ipversion/dscp/mac/pname/domain/geoip/geosite/fallback + not/and + mark/must + sub/subnode | dae 现有函数集全覆盖（geoip/geosite 自 `.dat` 编译期展开，含 attr/ext；pname 走 cgroup2 采集；domain 走 DNS 位图 + 预计算索引）；`sub/subnode` 本版 dae 无此函数 | **≈95%** | **编译产物与 dae 逐字节对拍 5/5**（ADR-0010/0033）；真实 `.dat` 计数与上游清点一致（geoip:cn 15,357 / geosite:cn 6,623）；余项：geosite 负载未纳入对拍、流式解析、pname 用 comm 非 argv basename（CO-RE）；geodata 搜索目录已含 XDG（P18e） |
| 4 | **配置系统** | 全量 `.dae`（global/dns/routing/group/subscription/node/include）全部生效 | 全量解析 + schema 校验 + 行级诊断；生效 routing 子集 + dns.upstream + **config 的 subscription/node/group 运行时**（ADR-0031）；deferred 项显式列出 | **≈65%** | 解析面与 `config_merger/parser` 语义逐条对齐；执行面为子集，deferred 不静默丢（ADR-0011）；缺 include 展开/全局健康参数全量、多组分派 |
| 5 | **DNS 子系统** | 透明 UDP/TCP、缓存、EDNS、regex、DoT/DoH/DoQ/H3 上游、`dns.routing` 请求/应答分流、ECS、嗅探 punt | 透明 UDP/TCP、正负缓存 TTL、域位图、regex、EDNS/截断、reload 重投影、TCP keep-alive、**DoT/DoH/DoQ 上游**、**多上游 + `dns.routing`（reject/asis/tag、应答重查≤3）** + URL/路由热切换 + **自定义名单 `qname(file:)` / `upstream_hits` / ECS 注入 `ecs=auto` / 客户端网段 `sip()`（mini 扩展）** | **≈88%** | 明文 DNS + 安全上游（ADR-0034/0035）+ 请求/应答分流（ADR-0036/0037/0038，lab 全矩阵 + 真机分流/名单热加载/ECS 实测）；余 DoH h2/h3、上游 ECS 回填/ecs_cache、optimistic cache、`ipversion_prefer`、bootstrap_resolver、嗅探 punt |
| 6 | **出站协议栈** | ss（含 2022/插件/shadowtls）、ssr、trojan、vmess、vless、tuic、hysteria2、juicity、naive、http、socks5、anytls | ss classic + **ss2022（SIP022 三方法）**、trojan(TCP)、vmess(AEAD aid=0)、vless(tcp/ws/**reality+vision**)、tuic v5、hy2(+obfs/Brutal 近似/udphop)、anytls、socks5、**http（CONNECT）**、direct（TCP 目标已支持域名，逐协议 ATYP 对齐） | **≈70%**（家族）· **≈95%**（主流可用性） | 主流 9 协议全覆盖且纯 Rust 跨实现验收（ADR-0016–0020/0026/0027/0042）；域名目标编码见 ADR-0030；**REALITY+Vision 自实现 TLS 1.3+ML-KEM（ADR-0041）**；**ss2022 与 shadowsocks-rust ssserver 跨实现、http 与独立 Python CONNECT 代理跨实现（ADR-0042）**；缺 ssr/juicity/naive、插件/shadowtls、逐字节 uTLS 指纹（仅 chrome 形状近似）、上行 splice/ECH/ML-DSA、gecko |
| 7 | **转发面** | relay（并发上限/backlog fuse/计费）、UDP endpoint pool（full-cone）、offload 完整 | relay（SO_MARK/半关闭/janitor/**`--max-conns` 并发上限 + `limit_rejected` 指标**）、UDP NAT（ss/vless/vmess/tuic/hy2 协议侧可用；网关策略默认 UDP 直连）、offload 最小实现 | **≈78%** | 512KB 逐字节、UDP 会话复用、offload 用户态零字节均实测（ADR-0015/0022）；并发上限已补（P18e，ADR-0042）；缺 backlog fuse/计费 |
| 8 | **多节点·订阅·健康检查** | subscription + node + group（min/max/random/fixed）+ alive set + 间隔/容忍度 + 延迟策略 + sticky IP 等 | `--subscribe`/config 订阅（HTTP(S)/file；base64/明文；逐行容错）；group filter（name/keyword/regex/subtag/!）、policy（min/min_moving_avg/min_avg10/random/fixed）、经节点健康探测（TCP + 可选 UDP，并发 24；last/EMA/hist10、tolerance 标死）、拨号失败切换、SIGHUP 订阅热更新（成员热替换 + 健康继承）、**按规则分派不同组（P19：组索引 direct=0/block=1/用户组 2 起，数据面 outbound 经 conn_state 回读选组）** | **≈80%** | ADR-0031/0042/0043、NOTES §11.22/§11.33/§11.34；lab 双组双 ss 服务端交叉验证 + 真机 66/66 alive；缺 sticky IP |
| 9 | **嗅探与域名策略（dial_mode）** | 内核侧 TLS/HTTP/QUIC 嗅探 → `domain/domain+` 拨号（**远端解析，绕 DNS 污染**）、sniff-punt | 用户态嗅探（TLS SNI / HTTP Host / h2c：preface + 最小 HPACK / **QUIC Initial SNI（RFC 9001 解密，ADR-0044）**，MSG_PEEK 不消费；UDP 侧新会话观测 + `sniffing.quic_sni`）；`dial_mode ip/domain/domain+`，命中即域名交节点；**无** sniff-punt | **≈75%** | ADR-0030/0042/0044、NOTES §11.21/§11.35；QUIC 仅 v1 首包、观测不拨号（UDP 域名拨号未做）；`domain` 等价 dae `domain+` 的“总是使用”行为（无 DNS 缓存门槛） |
| 10 | **IPv6** | 数据面 + 规则 + 协议全支持 | TCP 全链：v6 解析/tproxy（sockmap key 2）/全部协议 v6 目标编码/v6 direct/v6 嗅探远端解析/AAAA 入域位图；**UDP v6（含 DNS over UDP6）与 ICMPv6/分片未做** | **≈80%**（TCP） | ADR-0032、NOTES §11.23；lab `test-v6` 3 断言全过（tproxy→ss(ATYP=4)→v6 echo；v6 direct）；真机网关 v6：嗅探 `[2001::1]→RELAY 远端解析` 204、字面量 `[2606:4700:4700::1111]` 200；静态 fe80 邻居不可省（NA 被 dae0peer_ingress 丢弃，上游同样要求） |
| 11 | **部署自动化** | netns 自动搭建（移网卡/sysctl/tproxy 规则，`netns_utils.go`）、systemd（`install/dae.service`）、Docker、发行包、shell 补全 | `lab.sh` / `gateway.sh` 脚本级一键；**systemd unit（`install/dae-mini.service`，capability 最小集 + SIGHUP ExecReload）+ `install/install.sh`（--dry-run/--uninstall）+ `docs/deploy.md`（P18e）**；无打包/发行包 | **≈65%** | 真网关一键脚本体验接近（ADR-0029）；ADR-0042；缺 Docker/发行包/shell 补全 |
| 12 | **运维面** | 主线较弱（daed 独立项目提供 GraphQL/Web UI） | SIGHUP/USR2、状态 socket（status/rules/config/maps/metrics/reload/suspend/resume）、Prometheus、sysdump/trace、日志轮转 | **≈90%** | 相对 dae 主线领先；daed 的 UI/鉴权不在范围（ADR-0021） |
| 13 | **质量工程** | Go 单测 244 文件/3.9 万行 + CI（bpf-test/build/docker/go-test…）+ fuzz | **181 单测** + verify 9×2 拓扑 + 6 专项 + 协议梯 17+ + 对拍 5 逐字节 + QEMU 双内核矩阵 + soak + 六路径基准 + `dns-bench` + REALITY e2e + RFC 9001 黄金向量 + **GitHub Actions CI（构建/单测/eBPF 对象，固定 nightly+bpf-linker，P18e）** | **≈80%** | 方法学密度高、绝对规模小（ADR-0010/0022/0025/0042/0043/0044）；CI 缺特权内核加载类测试 |
| 14 | **性能** | 生产级优化（THP/内存上限/连接池/看门狗） | 六路径基准：direct 31Gbps / relay 24.7Gbps / offload 14.6Gbps / ss 2.5Gbps | **≈55%** | 有数据、缺与 Go 版同机对拍（如实，ADR-0022） |
| 15 | **真实订阅生态** | 全原生 | 订阅#1（50×vless-ws）✅；订阅#2：anytls ✅、**REALITY+Vision ✅（自实现 TLS 1.3，ADR-0041）** | **≈85%** | ADR-0026/0027/0028/0041；边界外协议可桥接过渡 |

## 表 B · 汇总

| 口径 | 完成度 | 说明 |
|---|---|---|
| 研究目标（可行性验证） | **100%** | aya 全栈可行、规则逐字节对拍、C 数据面退役、真实节点浏览器可用——结论闭环 |
| 核心主链路（分流/规则/DNS（含 DoT/DoH）/主流协议/转发/运维） | **≈88%** | 日常「tproxy 网关 + 主流节点」已可用（P13 真网关实测 204 / YouTube 200；P14 嗅探远端解析实测 hits 10/10；P15 订阅组真机 66/66 alive；P18a 真实公网 DoT/DoH 解析实测；P18d REALITY/Vision 66/66；P19 多组分派 lab 交叉 + 真机回归） |
| dae 全功能面（嗅探/多节点/geo/IPv6/安全 DNS/系统集成） | **≈75%（±5%）** | 结构性缺口已收官（P19 多组分派；P20 嗅探四类域名收齐）；IPv6（TCP 全链）≈80%、规则语言（geo/pname）≈95%、DNS（安全上游+分流）≈88%、协议家族≈70% |

## Top 缺口（按优先级）

1. ~~嗅探 + dial_mode（远端域名解析）~~ **已完成（P14，ADR-0030）**；**QUIC SNI 已完成（P20，ADR-0044）**；余项：sniff-punt（按嗅探域名重判路由）；
2. ~~多节点/订阅/组 + 健康检查~~ **已完成（P15，ADR-0031）**；**订阅热更新与 udp_check 已完成（P18e，ADR-0042）**；**按规则分派不同组已完成（P19，ADR-0043）**——数据面结构性缺口收官；余项：sticky IP；
3. ~~IPv6 数据面~~ **已完成（P16，ADR-0032，TCP 全链）**；余项：UDP v6（含 DNS over UDP6 接管，需 sockmap key 3）、ICMPv6/分片（v4 非首片跳过 + v6 分片头已处理，P18e）；
4. ~~geoip/geosite/pname~~ **已完成（P17，ADR-0033）**；余项：geosite 对拍覆盖、pname argv basename（CO-RE）、geodata 流式解析（XDG 已完成，P18e）；
5. ~~DoH/DoQ + `dns.routing`~~ **已完成（P18a/b/c，ADR-0034/0035/0036）**；余项：DoH h2/h3、ECS、optimistic cache/`fixed_domain_ttl`/`ipversion_prefer`、`bootstrap_resolver`、嗅探 punt；
6. ~~协议细节：REALITY/Vision/uTLS~~ **REALITY+Vision 已完成（P18d，ADR-0041）**；~~ss2022/http~~ **已完成（P18e，ADR-0042）**；余项：逐字节 uTLS 指纹（当前 chrome 形状近似）、上行 splice/ECH/ML-DSA、插件/shadowtls、juicity/naive/ssr、gecko、tuic 0-RTT；
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
- **工程化验收**：QEMU 双内核矩阵、soak 三模式、六路径基准、协议三方交叉（Go 客户端/Python+Go 参考服务端）。

## 维护说明

- 每完成一个阶段（P14+），更新受影响行的「mini-dae」「覆盖度」「证据」三列，并在文首版本行记录日期；
- 覆盖度是**判断值**：若某域完成度大幅变化，必须在证据列给出新的实测/文档锚点，不允许只改数字；
- 与 `docs/adr/` 的关系：ADR 记录「为什么这么做」，本表记录「做到了哪里」；
  两处不一致时以 ADR + NOTES 实测为准，本表先改。

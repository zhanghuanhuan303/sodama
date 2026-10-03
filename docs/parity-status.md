# 对标进度：dae（Go）↔ mini-dae（全 Rust）

- **版本**：v1.1 · 2026-10-04（P13 网关 + P14 嗅探/远端解析后清点）
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
| 3 | **规则引擎** | dip/sip/dport/sport/l4proto/ipversion/dscp/mac/pname/domain/geoip/geosite/fallback + not/and + mark/must + sub/subnode | 除 pname/geo/subnode 外全有；domain 走 DNS 位图 + regex | **≈75%** | **编译产物与 dae 逐字节对拍 5/5**（ADR-0010）；缺 geo 数据、进程名、subnode |
| 4 | **配置系统** | 全量 `.dae`（global/dns/routing/group/subscription/node/include）全部生效 | 全量解析 + schema 校验 + 行级诊断；生效 routing 子集 + dns.upstream；group/node/subscription 仅解析（无运行时） | **≈60%** | 解析面与 `config_merger/parser` 语义逐条对齐；执行面为子集，deferred 显式列出不静默丢（ADR-0011） |
| 5 | **DNS 子系统** | 透明 UDP/TCP、缓存、EDNS、regex、DoT/DoH/DoQ/H3 上游、`dns.routing` 请求/应答分流、ECS、嗅探 punt | 透明 UDP/TCP、正负缓存 TTL、域位图、regex、EDNS/截断、reload 重投影、TCP keep-alive | **≈55%** | 明文 DNS 全对齐（6 专项，ADR-0012/0013/0014）；安全上游与请求分流缺 |
| 6 | **出站协议栈** | ss（含 2022/插件/shadowtls）、ssr、trojan、vmess、vless、tuic、hysteria2、juicity、naive、http、socks5、anytls | ss classic、trojan(TCP)、vmess(AEAD aid=0)、vless(tcp/ws)、tuic v5、hy2(+obfs/Brutal 近似/udphop)、anytls、socks5、direct（TCP 目标已支持域名，逐协议 ATYP 对齐） | **≈60%**（家族）· **≈85%**（主流可用性） | 主流 7 协议全覆盖且纯 Rust 跨实现验收（ADR-0016–0020/0026/0027）；域名目标编码见 ADR-0030；缺 ss2022/ssr/juicity/naive/http、REALITY/Vision/uTLS、gecko |
| 7 | **转发面** | relay（并发上限/backlog fuse/计费）、UDP endpoint pool（full-cone）、offload 完整 | relay（SO_MARK/半关闭/janitor）、UDP NAT（ss/vless/vmess/tuic/hy2 协议侧可用；网关策略默认 UDP 直连）、offload 最小实现 | **≈75%** | 512KB 逐字节、UDP 会话复用、offload 用户态零字节均实测（ADR-0015/0022）；缺 fuse/计费/并发上限 |
| 8 | **多节点·订阅·健康检查** | subscription + group（min/max/random）+ alive set + 延迟探测 + sticky IP + 故障恢复 | 单 `--dialer URL`；group 名仅解析映射 | **≈10%** | **最大生态缺口** |
| 9 | **嗅探与域名策略（dial_mode）** | 内核侧 TLS/HTTP/QUIC 嗅探 → `domain/domain+` 拨号（**远端解析，绕 DNS 污染**）、sniff-punt | 用户态嗅探（TLS SNI / HTTP Host，MSG_PEEK 不消费）+ `dial_mode ip/domain/domain+`，命中即域名交节点；**无** QUIC/UDP 嗅探与 sniff-punt | **≈55%** | ADR-0030、NOTES §11.21；`domain` 等价 dae `domain+` 的“总是使用”行为（无 DNS 缓存门槛）；h2c 不做 |
| 10 | **IPv6** | 数据面 + 规则 + 协议全支持 | 仅 IPv4（显式边界） | **≈5%** | `--no-ipv6` 只是规避不是支持 |
| 11 | **部署自动化** | netns 自动搭建（移网卡/sysctl/tproxy 规则，`netns_utils.go`）、systemd（`install/dae.service`）、Docker、发行包、shell 补全 | `lab.sh` / `gateway.sh` 脚本级一键；无 systemd/打包 | **≈40%** | 真网关一键脚本体验接近（ADR-0029），自动化深度不同（脚本代劳，安全性更高） |
| 12 | **运维面** | 主线较弱（daed 独立项目提供 GraphQL/Web UI） | SIGHUP/USR2、状态 socket（status/rules/config/maps/metrics/reload/suspend/resume）、Prometheus、sysdump/trace、日志轮转 | **≈90%** | 相对 dae 主线领先；daed 的 UI/鉴权不在范围（ADR-0021） |
| 13 | **质量工程** | Go 单测 244 文件/3.9 万行 + CI（bpf-test/build/docker/go-test…）+ fuzz | 95 单测 + verify 9×2 拓扑 + 6 专项 + 协议梯 17 + 对拍 5 逐字节 + QEMU 双内核矩阵 + soak + 六路径基准；无 CI | **≈70%** | 方法学密度高、绝对规模小（ADR-0010/0022/0025） |
| 14 | **性能** | 生产级优化（THP/内存上限/连接池/看门狗） | 六路径基准：direct 31Gbps / relay 24.7Gbps / offload 14.6Gbps / ss 2.5Gbps | **≈55%** | 有数据、缺与 Go 版同机对拍（如实，ADR-0022） |
| 15 | **真实订阅生态** | 全原生 | 订阅#1（50×vless-ws）✅；订阅#2：anytls ✅、REALITY+Vision ❌（SOCKS5 桥接兜底） | **≈70%** | ADR-0026/0027/0028；边界外协议可桥接过渡 |

## 表 B · 汇总

| 口径 | 完成度 | 说明 |
|---|---|---|
| 研究目标（可行性验证） | **100%** | aya 全栈可行、规则逐字节对拍、C 数据面退役、真实节点浏览器可用——结论闭环 |
| 核心主链路（分流/规则/明文 DNS/主流协议/转发/运维） | **≈80–85%** | 日常「tproxy 网关 + 主流节点」已可用（P13 真网关实测 204 / YouTube 200；P14 嗅探远端解析实测 hits 10/10） |
| dae 全功能面（嗅探/多节点/geo/IPv6/安全 DNS/系统集成） | **≈60%（±5%）** | 差距集中在结构性 4–5 项，非零散细节 |

## Top 缺口（按优先级）

1. ~~嗅探 + dial_mode（远端域名解析）~~ **已完成（P14，ADR-0030）**；余项：QUIC/UDP 与 h2c 嗅探、sniff-punt（按嗅探域名重判路由）；
2. **多节点/订阅/组 + 健康检查**：从「研究品」到「日用品」的门槛；
3. **IPv6 数据面**；
4. **geoip/geosite/pname**；
5. **DoH/DoQ + `dns.routing`**；
6. 协议细节：REALITY/Vision/uTLS、ss2022/插件、juicity/naive/ssr、gecko、tuic 0-RTT；
7. **systemd/打包/daed**；
8. offload 完整形态（fuse/计费）与 relay 并发上限。

## 优势项（相对 dae 主线）

- **全栈 Rust**：数据面（aya-ebpf/BTF）已退役 C（ADR-0025），协议栈纯 Rust 跨实现验收；
- **规则编译逐字节对拍**：与 dae Go 编译器 5/5 一致，作为回归护栏（ADR-0010）；
- **用户态嗅探零数据面改动**：MSG_PEEK 只读采集（不消费字节）+ 逐协议域名编码对齐（ADR-0030）；
- **TCX 生命周期**：进程退出即摘钩，回滚天然安全；
- **状态面/可观测**：JSON socket + Prometheus + sysdump/trace（dae 主线没有，daed 才有 Web UI）；
- **单臂 dual-role 程序**、`--lan none` 一键真网关（ADR-0029）、本地 SOCKS5 入口（ADR-0028）；
- **工程化验收**：QEMU 双内核矩阵、soak 三模式、六路径基准、协议三方交叉（Go 客户端/Python+Go 参考服务端）。

## 维护说明

- 每完成一个阶段（P14+），更新受影响行的「mini-dae」「覆盖度」「证据」三列，并在文首版本行记录日期；
- 覆盖度是**判断值**：若某域完成度大幅变化，必须在证据列给出新的实测/文档锚点，不允许只改数字；
- 与 `docs/adr/` 的关系：ADR 记录「为什么这么做」，本表记录「做到了哪里」；
  两处不一致时以 ADR + NOTES 实测为准，本表先改。

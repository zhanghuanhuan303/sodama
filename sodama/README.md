# sodama：dae 核心数据面的最小复现（K0–K3 + P3a/b + P4 + P5 协议梯 + P6 运维面 + P7 收敛 + P8/P9 数据面 Rust 化，P9+ 移除 C 数据面）

用 **Rust/aya-ebpf（数据面）+ Rust/aya（控制面加载器）** 复现 dae 的核心机制，并附带一套可跑的
netns 实验环境。**K0–K3、P3a（DNS 接管/域位图）、P3b-1（缓存/TCP DNS）、P3b-2a
（domain(regex:)/EDNS）、P4（TCP relay / UDP NAT / TCP offload）、P5-G1（shadowsocks +
trojan）、P5-G2（vless + vmess AEAD）、P5-G3a（tuic v5 / QUIC）、P5-G3b（hysteria2 /
QUIC + 最小 HTTP/3 认证）、P5-G3b+（salamander 混淆 / Brutal 近似 / udphop）、
P18a–e（DoT/DoH、DoQ、`dns.routing`、ECS/sip、pname、REALITY+Vision、SS2022/http、热更新、CI/systemd）、
P19（多组分派 + 启动健壮性）、
P20（QUIC Initial SNI 嗅探）、P21（sniff-punt）、P22（UDP over IPv6 全链）、
P23（sticky IP / DoH h2 / bootstrap / DNS 选项）、P24（uTLS Chrome-120 / Vision splice / TUIC 0-RTT）、
P25（naive / HTTP-2 CONNECT）、P26（HTTP/3：DoH h3 / naive+quic）、P27（juicity v0）、
P28（ECS 回填 / ecs_cache）、P29（optimistic 后台刷新）、P30（SSR origin+plain）、
P31（shadow-tls v1/v2/v3，ss 插件）、P32（ECH 边界：已评估不实现）、
P33（运行时参数热更新 + `--watch-config` 配置热驱动）、
P34（多订阅按声明顺序回退 + 默认配置目录 `~/.config/sodama`）、
P35（inotify 毫秒级热驱动 + 配置即唯一事实来源 + 无 home 兜底）、
P36（用户分流名单 + 标准格式规则集（URL 自动更新）+ 订阅置顶的可读配置）与
P6（suspend/reload/metrics/sysdump/日志轮转/整配置热重载）已完成**；P9+ 已删除 C 数据面，
`ebpf-rs` 的 Rust 对象是**唯一数据面**（ADR-0025）。

- **规则 VM**：`bpf_loop` 扫 `match_set` 数组，复刻 dae 的粘性 OR / AND 编码
- **LPM array-of-maps**：`dip`/`sip`/`mac` 集合折叠进内层 LPM trie
- **双 epoch 槽热重载**：SIGHUP → 写非活跃槽 → 切 `active_routing_epoch_map`，不重挂钩子
- **conn_state 缓存**：新连接跑 VM，非 SYN 直接用缓存判决（热重载不影响在途连接）
- **钩子角色**：LAN ingress / WAN egress / WAN ingress / dae0 ingress / dae0peer ingress
  + **单臂 dual-role**（同一接口同时挂 `sodama_wan_lan_ingress` / `sodama_lan_wan_egress`）
- **redirect_track 单写者**：同发布者续租、竞争发布者 2s 窗口内拒绝改绑（计数）、
  陈旧窗口允许改绑；回程续租受 `reply_publisher_matches` 约束
- 分流：`direct / block / proxy / must_rules / 控制面`，规则按顺序优先匹配
- 重定向：改目的 MAC、写 `skb->cb`、`bpf_redirect` 进 dae0
- 透明代理：dae0peer 上 `bpf_sk_assign` 交给 tproxy socket（accept 保持原始目的地址）
- 回程：dae0 ingress 查 `redirect_track`，还原 MAC 后送回原接口（`from_wan` 时 `BPF_F_INGRESS`）
- Real Direct：direct 判决直接 `TC_ACT_OK`，由内核三层转发
- **K3 生态接入**：`--config <file.dae>` 全量配置解析（词法/语法/include/schema，诊断带
  文件:行号）、`validate`/`export-config`/`extract-routing` 子命令、只读状态面
  （`--status-socket`，Unix socket JSON）、可选过渡一跳（`--forward socks5://…`）；
  无法编译的规则（geoip/pname 等）显式列入 deferred，绝不静默丢弃
- **P3a DNS 接管**：透明 UDP DNS 监听（`IP_TRANSPARENT` + `IP_ORIGDSTADDR`）→ 上游 →
  解析 A 记录 → 按 `domain(suffix/full/keyword:)` 计算位图 → 写 `domain_routing_map`，
  内核按位图匹配（`route_match_domain_set`）；`domain(regex:)` 整条规则显式 deferred
- **P3b-1 DNS 缓存 + TCP DNS**：正/负缓存（负缓存按 RFC 2308 用 SOA 寿命）、命中回填
  ID/question 并按已过秒数递减 TTL；TCP DNS 2 字节分帧、keep-alive，与 UDP 共用缓存；
  缓存命中也会重发域位图，SIGHUP 后从缓存重建新槽位图（对照 dae `reconcileCurrentBpfProjections`）
- **P3b-2a regex 域规则 + EDNS**：`domain(regex:)` 编译期编译（非法正则硬失败），对
  小写化 qname 非锚定匹配（模式保持原大小写）；EDNS 的 DO 位入缓存键、带 options 的
  查询不缓存；UDP 应答按客户端公布尺寸截断（TC=1），缓存/TCP 保留完整应答
- **P4 转发面**：TCP relay（`--dialer direct|socks5://…|ss://…|trojan://…|vless://…|vmess://…`，
  host ns 拨号 + `SO_MARK` 防自环 + 双向泵送/半关闭 + janitor）；UDP NAT（按 (client, orig_dst)
  会话，回包源地址保持原始目的地址）；TCP offload（`fast_sock` + `sk_skb` 内核对拼，最小实现：
  无 fuse/计费；**对标批起有内核路径字节计量**：`skb_send_sock` 的 fentry/kprobe 探针 + 键摘除时回收，
  `status.offload_sent.{reclaimed_bytes,kernel_bytes}`）
- **P5-G1 原生协议栈**：shadowsocks classic AEAD（SIP004；TCP 分块 0x3FFF + UDP 包；
  `aes-256-gcm` / `chacha20-ietf-poly1305`）与 trojan（rustls 0.23 + CONNECT 头）；
  **协议与 offload 互斥**（AEAD/TLS 帧不交给内核拼接，带 `--offload` 也 `offloaded_total=0`）；
  UDP 仅在 ss 支持，其余协议显式计入 `udp_nat.direct_fallback`；验收对端是
  `lab/ss_server.py` / `lab/trojan_server.py`（独立实现，不复用 Rust 代码）
- **P5-G2 协议栈**：vless（TCP+UDP，tls/none，**tcp/ws 传输**，UUID5 回退）与 vmess AEAD（aid=0，嵌套 HMAC KDF、
  AES-ECB auth id、SHAKE128 分块/填充、终止块；TCP+UDP，tls 可选）；共享 `tls.rs`（rustls）；
  **三方交叉验收**：Rust 客户端 ↔ 独立 Python 服务端（lab e2e）与**真实 Go 客户端**
  （dae 依赖的 outbound fork）↔ 同一 Python 服务端（`lab/proto-check/`）；UDP 会话拨号
  不再持 NAT 表锁（首包仍在 dns_loop 同步拨，边界见 ADR-0017）
- **P10 vless WebSocket（真实订阅节点接入）**：RFC6455 客户端传输（HTTP Upgrade + 掩码帧，
  拆半、ping→pong、close→EOF）；`type=ws` + `host`/`path` 参数；与参照客户端（v2ray）同目标对拍，
  gateway e2e（client ns → tproxy → vless-ws → 真实节点 → gstatic 204）见 `lab/real-node-e2e.sh`
  与 ADR-0026（grpc/h2/指纹仍不做）
- **P11 AnyTLS（真实订阅节点接入）**：anytls-go 协议 v2 客户端（sha256 认证 + 帧 +
  默认 paddingScheme 逐字节对齐 + UpdatePaddingScheme 即时生效）；单 Stream；
  跨实现测试对 sing-box 服务端，真实节点 e2e gstatic 204（ADR-0027）；
  同批：`--dial-timeout`（默认 5s）可配，lab 用 `USE_DIAL_TIMEOUT` 透传
- **P12 本地 SOCKS5 入口（浏览器验收）**：`--listen-socks 127.0.0.1:11080 --dialer anytls://…`
  ——不加载 eBPF、不需 root，浏览器直接指 socks5 即可走真实节点（ADR-0028）；
  DNS 本地解析为 v1 边界；`resolve()` 已改为优先 IPv4（双栈节点域名踩坑）
- **P13 真网关模式（host gateway）**：`--lan none` + `lab/gateway.sh`——物理网卡不移动，
  只挂 wan egress/ingress 钩子接管**宿主自身流量**（浏览器零配置）；规则纪律：
  DNS `direct(must)` 置顶、禁用任何 `sip()`（宿主机源地址即私网）、QUIC 阻断回落 TCP；
  一键 up/down/status/test，一键回滚无残留（ADR-0029、NOTES §11.20）；
  **接口选择（ADR-0066）**：`--lan`/`--wan` 支持 glob pattern与 `auto`（= 默认路由接口），配置键
  `lan_interface`/`wan_interface` 同语义（CLI 优先）；懒绑定——启动无匹配不报错，接口出现后 1s 内自动补挂、消失后清理
- **P14 用户态嗅探 + dial_mode（远端域名解析）**：TLS ClientHello SNI / HTTP/1.x Host/CONNECT
  嗅探（`MSG_PEEK` 只读采集不消费，超时默认 100ms 回退 IP）；`--dial-mode ip|domain|domain+`
  命中即交域名给节点远端解析（绕 DNS 污染）；目标地址类型化（vless/vmess 0x02、tuic 0x00、
  ss/socks5/trojan/anytls 0x03、hy2 字符串、direct 本地解析）；SOCKS 入口同享；
  状态面 `sniffing` 计数（ADR-0030、NOTES §11.21）
- **P15 订阅 / 节点组 / 健康检查（多节点选路）**：`--subscribe <url>`（可重复）/`--group <name>`，
  config `subscription/node/group` 生效；极小 HTTP(S) 订阅拉取（3 跳重定向/chunked/webpki/
  **优先 IPv4**/marked socket、**`http-file://`/`https-file://` = 拉取+磁盘回退，dae 风格**）
  + base64/明文解码 + 逐行容错；filter（name 精确/keyword:/regex:/
  subtag/`!`，行内 AND / 行间 OR）；policy（min/min_moving_avg/min_avg10/random/fixed(i)/
  `fixed('节点名')`——**名字点名**：订阅刷新重排成员索引后仍指向同一节点，
  改名/下线则自动兑底；reload 时 policy 与成员/filter 一起热应用）；
  经节点健康探测（last/EMA/hist10，tolerance 标死）+ 拨号失败自动切换；状态面 `group`
  （ADR-0031、NOTES §11.22；**优雅空闲**：探测节奏由「有人查状态面（20s 内）」与
  「有活跃连接/30s 内有转发」决定，两者皆无时指数退避 30→60→120→240→480→`probe_idle_cap`
  （默认 600s，`0` = 不退避），退避中每秒检查一次可被立刻叫醒；状态面 `probe_interval_secs`/
  `probe_active`，节奏变化写日志；**P34**：多来源按声明顺序回退——pacman 镜像风格，alive 中
  rank 最小者（活动层）独占出口，全部标死才切下一源，`subscription_failover: false` = 池化；
  状态面 `active_tag`；来源顺序 = node → CLI --subscribe → config subscription；默认配置目录
  `~/.config/sodama/config.dae`，相对订阅路径按配置目录解析、`subN.url` 单行 URL 文件
  自动按 URL 抓取，ADR-0061、NOTES §11.49）
- **P16 IPv6 数据面（TCP 全链）**：五元组统一 16 字节（v4-mapped + `is_v6`）；`parse_v6`
  （跳扩展头、分片放行）+ `IPV6_TRANSPARENT` 双监听（sockmap key 2）；规则 v6 前缀、
  协议目标 v6 编码（ss 0x04/vray 0x03/tuic 0x02/hy2 `[v6]:port`）、v6 嗅探远端解析、
  AAAA 入域位图；控制对 fe80 静态邻居（动态 NDP 会被 dae0peer_ingress 丢弃）；
  lab `v6-up`/`test-v6`；真机网关 v6 域名/字面量均实测通过（ADR-0032、NOTES §11.23）
- **P17 geoip/geosite/pname（规则语言收尾）**：v2ray `.dat` 手工 protobuf 读取（无新依赖），
  `dip(geoip:cn)`/`domain(geosite:cn[@attr])`/`ext:file:code` 编译期展开（类型映射与 dae 一致），
  搜索目录含 `DAE_LOCATION_ASSET`/`--geodata-dir`；LPM 内层容量 2,048,000（对齐 dae）；
  domain 匹配预计算索引 + 前导点语义；pname 走 6 个 cgroup2 钩子（sock_create/release、
  connect4/6、sendmsg4/6）采集 comm → `cookie_pid_map`，TC 仅 WAN egress 新连接反查，
  16B 定长匹配；状态面/metrics 新增 pname 面；对拍 5/5 逐字节（含 geoip/pname）
  （ADR-0033、NOTES §11.24）
- **P18a DNS 安全上游（DoT/DoH）**：`dnsup` 上游抽象 + 五种 scheme（udp/tcp/tcp+udp/tls/https），
  默认端口/path 与 dae 对齐；`tcp+udp` 回正为 UDP 优先、TC/失败才 TCP（客户端协议不再
  决定上游传输）；DoT/DoH 持久连接（**P23 起 DoH 按 ALPN 优先 HTTP/2**，自实现最小
  h2 客户端；H1-only 服务端同连接走 HTTP/1.1，含 chunked），
  失败丢弃重连一次；`--dns-upstream` 接完整 URL，reload 按 URL 热切换；状态面
  `dns.upstream_url`/`upstream_scheme`；lab 自签 DoT/DoH 夹具 + 连接复用断言，
  真实公网 AliDNS DoT/DoH 实测（ADR-0034、NOTES §11.25）
- **P18b DoQ（DNS over QUIC）**：quinn 连接复用 + 每查询一条双向流，ID 置 0/恢复、
  写完 FIN 后才读、取消码 0x3（RFC 9250）；锁中毒恢复 + 单查询 panic 隔离（DNS 线程不再被单次异常杀死）；
  quic-go 参考服务端交叉验证 + AliDNS 真实 DoQ（ADR-0035、NOTES §11.26）
- **P18c `dns.routing` 请求/应答分流 + 多上游**：`dns.upstream { tag: url }` 全部生效；
  请求 `qname/qtype` → `reject`（空应答）/`asis`（回客户端原目的，UDP/TCP 透明套接字原地址）/tag；
  应答 `qname/qtype/upstream/ip`（含 geoip）→ `accept`/`reject`（清空 answer）/换上游重查（≤3）；
  路由先于缓存 + 按上游作用域缓存键；dae 链编码与默认 fallback（asis/accept）对齐；
  `dns.routing` 热重载；lab 双假上游 + asis 夹具全矩阵（ADR-0036、NOTES §11.27）
- **P18c 实用化：`qname(file:)` 自定义名单 + 分流观测**（sodama 扩展）：文本名单文件
  （每行一条、`#` 注释、默认 suffix、行首 `full:/keyword:/regex:`、相对路径按规则文件目录、
  缺失硬失败）；`dns.routing.upstream_hits` per-tag 计数；真网关默认
  国内域→本地明文 / 其余→DoH / 名单+geosite 广告域→reject（ADR-0037、NOTES §11.28）
- **P18c 实用化：ECS 注入 + `sip()` 客户端网段路由**（sodama 扩展）：上游 URL
  `ecs=auto|<CIDR>`（v4 /24、v6 /56，已带 OPT 透传，缓存按子网分域）；请求函数
  `sip(...)`（CIDR/geoip/ext，可与 qname/qtype 同链）；真网关国内域走 DoH+ECS
  （ADR-0038、NOTES §11.29）
- **P18c 实用化：应答侧 `sip()` + `dns-bench`**（sodama 扩展）：应答路由可按客户端
  来源过滤；`dns-bench` 子命令（用户态 + marked socket，同域名跨上游
  min/avg/p50/TTL 对比，`--client` 供 ECS）；真机 router↔DoH↔DoH+ECS A/B
  （ADR-0039、NOTES §11.30）
- **P18c 实用化：DNS `pname()` + bench 并发/多轮**（sodama 扩展）：WAN egress 按 DNS
  流（UDP/TCP SYN）写 `dns_sender_pname_map`，控制面 raw 反查 + 120s 陈旧判定 +
  60s GC；`dns.routing` 请求/应答双侧支持 `pname(...)`（无进程信息不命中）；
  `dns-bench --rounds/--concurrency` + p95（ADR-0040、NOTES §11.31）
- **P18d REALITY + Vision（自实现 TLS 1.3）**：零新运行时依赖新增
  `tls13.rs`（Chrome 形状 ClientHello + X25519MLKEM768 hybrid + 记录层
  AES-GCM/ChaCha + `raw_read` 直通）、`reality.rs`（authKey/session_id 密封/
  证书 HMAC-SHA512+ed25519 绑定）、`vision.rs`（帧层 + 下行 splice）；
  `vless://…security=reality…flow=xtls-rprx-vision` 直接解析入组；
  订阅#2 66/66 节点入组，真机 HTTP/HTTPS 实测（ADR-0041、NOTES §11.32）
- **P18e 批量收尾（协议/组/数据面/工程化）**：SS2022（SIP022 三方法，BLAKE3
  子密钥，跨实现 shadowsocks-rust）+ HTTP CONNECT 出站；**SIGHUP 订阅热更新**
  （重拉订阅 → 成员整体替换 + 同名继承健康，失败保留旧成员）；`--max-conns`
  并发上限 + `limit_rejected`；组 `udp_check_dns`（UDP DNS 探测优先、失败回退 TCP）；
  eBPF **分片处理**（v4 非首片跳过 / v6 分片头）；geodata **XDG** 搜索目录；
  嗅探 **h2c**（preface + 最小 HPACK `:authority`）+ QUIC Initial 识别统计；
  **GitHub Actions CI**（loader 构建/单测/eBPF 对象，固定 nightly + bpf-linker）+
  **systemd unit + install.sh（--dry-run/--uninstall）+ `docs/deploy.md`**；
  lab 新增 `ss2022-up`/`http-up`/`sub-reload-up` 三用例（ADR-0042、NOTES §11.33）
- **P19 多组分派（规则按组名选组）+ 启动健壮性**：组索引 = config `group` 段顺序
  （direct=0/block=1/用户组 `GROUP_INDEX_BASE=2` 起；未定义组名回退 proxy）；
  **eBPF 零改动**——outbound u8 本就在 `conn_state_map`，relay/UDP 每连接按 5 元组
  raw 回读选组（查不到回退默认组）；`GROUP_SET` 存全部组（空组也注册保索引），
  SIGHUP 逐组热替换；**启动期 DNS 自我阻塞修复**（initial reload 不再重拉订阅，
  详见 NOTES §11.34——重启后必现的启动断网根因）；单上游失败不拖垮上游集；
  健康并发 8→24；**`gateway.sh up` 启动自检 + 失败自动回滚直连**（`--wait/--no-wait`）；
  lab `groups-up`/`test-groups` 双组双 ss 交叉验证（ADR-0043、NOTES §11.34）
- **P20 QUIC Initial SNI 嗅探**：用户态解 QUIC v1 Initial（RFC 9001 固定盐 HKDF →
  `client in`/`quic key/iv/hp`（`tls13 ` 前缀标签）→ 头部保护 AES-ECB → AES-128-GCM →
  CRYPTO/PADDING → 与 TLS 共用的 ClientHello 解析取 SNI）；`udp_nat_handle` 新会话接入，
  命中记 `sniffing.quic_sni` + 日志；仅 v1 首包、单包、观测不拨号（边界如实）；
  验证：RFC 9001 A.1 密钥向量 + A.2 官方向量包（SNI=example.com）黄金用例 + 真实
  quinn 栈环回首包 + lab `quic_probe.py`（Python 独立实现）`test-quic-sniff`
  （ADR-0044、NOTES §11.35）
- **P21 sniff-punt（嗅探域名在 relay 侧重判）**：`--sniff-punt`（CLI >
  `global.auto_sniff_punt`）；`rules::punt_match` 用户态重放规则 VM（域集合/LPM/not/
  logical OR-AND/must，dport=53→控制面）——`direct`=直连原始 IP、`block`=关连接、
  用户组=换组拨号；状态面 `sniffing.punt_*`；lab `sniff-punt-up`/`test-sniff-punt`
  （双组双 ss 三路径交叉；ADR-0045、NOTES §11.36）
- **P22 UDP over IPv6 全链**：`SockMap<4>`（key 3 = v6 UDP）+ `IPV6_TRANSPARENT`/
  `V6ONLY`/`IPV6_RECVORIGDSTADDR` 透明监听 + 第二个 dns_loop；v6 DNS 接管
  （回包源=原始目的）；ss UDP v6 目标 ATYP=0x04；lab `test-v6` 四段（TCP/direct/
  UDP 2/2 跨实现/v6 DNS；ADR-0046、NOTES §11.37）
- **P23 sticky IP + DoH h2 + bootstrap + DNS 选项**：代理域名粘滞 IP（连续 3 败作废/
  成功清零/reload 重置）；DoH 优先 HTTP/2（自实现最小 h2 客户端；ALPN 门控——
  H1-only 服务端零额外连接，握手失败回退）；`global.bootstrap_resolver`（上游/订阅
  域名自举，A+AAAA、TC→TCP）；DNS `optimistic_cache`（stale 供应 + TTL 上限）/
  `fixed_domain_ttl`/`ipversion_prefer`；lab `doh-h2-up`/`dnsopts-up`（ADR-0047、
  NOTES §11.38）
- **P24 协议细项**：REALITY ClientHello 对齐 uTLS Chrome-120（签名算法/版本/
  ALPS/GREASE-ECH/Boring padding）；Vision 上行 splice（回归测试固化）；TUIC 0-RTT
  （无票据/被拒无痛回退）；显式边界（当时）：ECH、rustls
  路径 uTLS（juicity/naive/ssr 已由 P25–P27、P30 补齐，shadow-tls 由 P31 补齐；ADR-0048、NOTES §11.39）
- **P25 naive（HTTP/2 CONNECT 出站）**：复用 DoH 的 `h2client` 帧层新增 CONNECT 隧道
  （HPACK `:method`/`:authority` + `connect_tunnel` reader 线程 + 双向流控 +
  `END_STREAM` 半关闭 + 两半 drop 关底层）；`naive+https://`/`naive://`（Basic）,
  `naive+quic://`（H3）显式未实现；`tls::connect_alpn` 必须协商 h2；lab 新增
  Go 标准库参考服务端 + `naive-up`/`test-naive`（交互零延迟 + 512KB 逐字节；
  ADR-0049、NOTES §11.40）
- **P26 HTTP/3（DoH h3 + naive+quic）**：`h3client` 最小 HTTP/3（控制流+SETTINGS、
  `request()`、`connect_tunnel()`（RFC 9114 §4.4 DATA 帧）、`H3TunnelReader/Writer`）；
  DNS 上游 `h3://`（ALPN=h3、连接复用、失败重建）；`naive+quic://`（QUIC；socket=None）；
  varint 抽 `quicvarint` 共享；lab quic-go 离线夹具 `naive-h3-up`/`test-naive-h3`
  与 `doh-h3-up`/`test-doh-h3`（连接复用断言；ADR-0050、NOTES §11.41）
- **P27 juicity v0（QUIC）**：`juicity.rs`（TLS exporter 认证（保持打开的 50B 认证流）+
  trojan 风格元数据；TCP 每连接一条双向流、UDP 每 NAT 会话一条双向流
  `[元数据][len u16][载荷]`）；链接 `juicity://uuid:password@host:port?sni=…`；
  lab Go/quic-go 夹具 `juicity-up`/`test-juicity` 与 `juicity-udp-up`/`test-juicity-udp`
  （ADR-0051、NOTES §11.42）
- **P28 ECS 回填 / ecs_cache**：解析上游应答 ECS 回显（RFC 7871 scope）并按回填 scope
  作用域化缓存；`ecs_scope_ladder` 阶梯查找（请求前缀 → 本机 /32 → 更宽 /20/16/12/8/0，
  只向宽复用）；状态面 `dns.ecs.echo/scope`；lab `ecscache-up`/`test-ecs-cache`
  （scope=0 全局与 /16 跨子网复用；ADR-0052、NOTES §11.43）
- **P29 optimistic 后台刷新（RFC 8767）**：stale 命中后单飞异步重查（失败保留旧条目；
  负应答取代过期正值；保留原查询 ECS 语义）；状态面 `dns.refresh.*`；lab
  `test-dns-options` 断言上游恰好 1 次刷新（ADR-0053、NOTES §11.44）
- **P30 SSR（origin+plain）**：`ssr_cipher.rs` 流密码层（aes-*-cfb/ctr、chacha20-ietf、
  rc4-md5(-6)；EVP_BytesToKey(MD5) 派生；CFB/CTR 自实现保流状态）+ `ssr.rs` 连接层
  （IV/首段目标地址/URL-safe base64 链接解析；`auth_*`/`obfs_*` 与 UDP 显式报错）；
  lab Go/outbound 夹具 `ssr-up`/`test-ssr`（交互 + 512KB 逐字节；ADR-0054、NOTES §11.45）
- **P31 shadow-tls（v1/v2/v3，ss 插件）**：`shadowtls.rs`（v1 rustls TLS1.2 裸隧道 /
  v2 首帧 HMAC-SHA1 前缀 + 应用密钥甄别票据 / v3 CH session_id HMAC + 握手期
  relay 帧反变换 + 链式 MAC）；证书默认 WebPKI（`CertPolicy::WebPki`）；
  `ss://…?plugin=shadow-tls;…`（ss classic；ss2022/UDP 显式报错）；lab Go/
  sing-shadowtls 夹具 `shadowtls-up`/`test-shadowtls` 三版（交互 + 512KB；
  ADR-0055、NOTES §11.46）；附带修复 TLS1.3 CH 严格解析兼容性
- **P32 ECH 边界（已评估，不实现）**：dae 生态 ECH 仅 hy2 `?ech=`（ot/quic-go
  fork）；rustls/quinn 无客户端 ECH → `ech=` 解析即显式报错不静默（单测锁定；
  ADR-0056、NOTES §11.47）
- **P5-G3a QUIC（tuic v5）**：惰性 tokio 运行时 + quinn（阻塞 relay 用 block_on 桥接）；
  认证 token = TLS exporter（label=uuid 裸字节、context=password）；TCP 每条中继一条 QUIC
  双向流，UDP 走 QUIC DATAGRAM（含分片/重组）；上游 socket 用自建 `Endpoint` 打 `SO_MARK`；
  跨实现对端是 `lab/proto-check/tuic-server`（Go/quic-go 独立实现，先构建）
- **P5-G3b+ hysteria2 能力补齐**：`salamander` 混淆（逐 datagram BLAKE2b XOR，`quicsock::ObfsSocket`）；
  **Brutal 近似**（认证后按 `min(server_rx, client_tx)` 定固定窗口，丢包不收缩；`brutal.rs`；
  如实标注：quinn pacer 使速率约 +25%，bbr3 以 BBR 近似）；**udphop**（端口并集、5s 起跳、
  跳时换新本地 socket 并对 quinn 谎报逻辑地址；`HopSocket`）；链接支持
  `obfs=salamander&obfs-password=…`、`cc_override=bbr|brutal|bbr3`、端口并集自动生效；
  服务端侧 `hy2-server -obfs-password/-hop-ports` 同步支持（见 ADR-0020）
- **P36 用户分流名单 + 标准格式规则集（类 Clash/sing-box）**：config `rule_set { tag: 'url|路径' }`
  ——自动识别 **Clash rule-provider YAML**（`payload:` 下 DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD/
  DOMAIN-REGEX；classical 三列同解析）、**sing-box rule-set JSON v1**、**纯文本域名列表**
  （`#` 注释；`full:`/`suffix:`/`keyword:`/`regex:` 前缀；裸条目=suffix）；非域名条目
  （IP-CIDR 等）计数上报（`status.rule_sets[].ignored`）；远程 URL **自动下载 + 本地缓存**
  （`rule_set_cache_dir`，按 `rule_set_update_interval` 刷新，0=每次 reload；失败回退旧缓存，
  无缓存硬失败）；路由用 `domain(ruleset: tag)` 引用（空名单=永不匹配哨兵，不会打断 reload）。
  **用户名单文件** `rules/user_{proxy,direct}.txt`：强制走代理 / 强制直连（eBPF real-direct），
  **加入 inotify 监听——编辑名单文件即毫秒级生效**；配置模板重排为 i3wm 风格（订阅置顶）
  （ADR-0063、NOTES §11.51）
- **P6 运维面**：信号面 `SIGHUP=reload` / `SIGUSR2=suspend`（eBPF `control_flags_map` →
  no-load/fail-open，reload 恢复）；状态面从只读扩展为 `status/rules/config/maps/metrics/
  reload/suspend/resume`（控制命令仍经主循环串行执行）；CLI 新增 `reload/suspend/resume/
  metrics/sysdump/trace`；`--log-file` + SIGHUP reopen（轮转友好）；`--config` 整配置热重载
  （失败不切槽 = 回滚，DNS 上游热切换；**P33**：reload/SIGHUP 同时热更新运行参数
  ——relay/udp idle、dial_timeout、max_conns、dial_mode、sniffing_timeout、sniff-punt，
  优先级 CLI 显式值 > config global > 现值）；**配置热驱动（P33/P35）**：`--watch-config <秒>`
  或 config `global { watch_config: 10 }`——inotify 目录事件驱动（毫秒级 + 100ms 去抖，事件名
  过滤 + 快照复核；<秒> = 无 inotify 时的兜底扫描），变更自动 `reload-fast`（订阅节点走
  `sub_cache_ttl` 缓存，默认 1800s；失败源负缓存 `sub_fail_ttl` 默认 600s——未变源不打
  订阅服务器；手动 reload/SIGHUP 仍强制重拉）；坏配置保留旧槽/旧参数；
  状态面 `config_watch {transport, debounce_ms, ...}`；`metrics` 输出 Prometheus 文本（daed GraphQL 不做，
  见 ADR-0021）
- **P7 收敛**：C 基准端点（`lab/bench_io.c` + `lab/bench.sh`）六路径剖面（口径如实：perf 不可用，
  墙钟 + 状态面 counters + `/proc` CPU/RSS）；**offload 生命周期修复**（半关闭超时 10s 兜底、
  fast_sock 键注销、注册前排空接收队列；回归 `test-offload-lifecycle`）；TCP_NODELAY
  令 ss 小包 p50 43.3ms→55µs；`lab/soak.sh` 三模式（reload/suspend 循环）；静态发布
  `lab/build-static.sh`（glibc crt-static static-pie + Alpine 冒烟）（见 ADR-0022）
- **P8 数据面 Rust 迁移（起步，历史）**：唯一还未 Rust 化的核心——eBPF 程序本体——开始迁移。
  工具链：nightly + rust-src（Tuna 镜像）+ `bpf-linker 0.11.1` + crates USTC 源替换；
  `ebpf-rs/`（aya-ebpf 0.2，no_std，`bpfel-unknown-none` + `-Z build-std=core`）；
  垂直切片 = **offload verdict**（当时 `--ebpf-offload <rust.o>` 双对象共存；该机制已在 P9+
  随 C 对象一并移除）（见 ADR-0023、NOTES §11.13）
- **P9 数据面全量 Rust 化（完成）**：7 个 TC classifier + 规则 VM + offload verdict 全部移植到
  aya-ebpf（BTF maps，含 map-in-map 的 LPM 内层模板），**8 程序/14 map 单对象**，与 C 同名同型，
  loader 零分支；全量回归（verify/DNS/协议梯/运维/soak）在 Rust 数据面上通过；唯一路线调整：
  `bpf_loop` 因 aya-obj 的 PSEUDO_FUNC relocation 缺口改用有界循环（规则 ≤64，语义等价）
  （见 ADR-0024、NOTES §11.14；**2026-10-16 已改回 `bpf_loop`**——aya-obj 0.3.0 已支持
  PSEUDO_FUNC 重定位，规则容量对齐 dae 1024，见下「能力缺口批次」与 ADR-0066）
- **P9+ 移除 C 数据面（完成）**：删 `ebpf/sodama.c` 与全部 `USE_EBPF_*` 回退分支
  （loader 去掉 `--ebpf-offload`；lab/bench 删 `offload-rs`/`rs-up`/`rs-dual-up` 入口）；
  `lab/lab.sh build` 只构建 Rust 对象；复跑：标准/单臂 verify 均 9/9、DNS/转发面/协议栈抽查、
  `cargo test` 73/73、offload 基准 12.4Gbps/19µs（见 ADR-0025、NOTES §11.15）
- **数据面对标批次（完成，2026-10-16）**：补齐 `docs/backlog.md` C1/C3/C4——
  **L3 链路头变体**（5 个 `*_l3` 程序 + `--link-hdr auto|l2|l3`，按 `/sys/class/net/<if>/type`
  自动判定，对照 dae `linkHdrLen()`；L3 送控制面 `bpf_skb_change_head(+14)` 补以太头，
  回程按 `l3_ifindex_map` **不写 MAC、不手工剥头，直接 `bpf_redirect` 回原接口**——
  实测手工 `adjust_room(-14)` 会多剥 14B，与 dae 多留 14B 一样是错形态，两条都避开）；
  **ringbuf 事件通道**（`event_ringbuf` + `SodaEvent` 72B + 5 类事件 + 1s/键限速 + 丢弃计数，
  替代热路径 printk；`status.events` + 事件日志限速 1 条/秒/类型）；
  **`skb_send_sock` 记账**（fentry→kprobe 回退；用户态 BTF 解析（`loader/src/btfoff.rs`）
  写 `sk_buff` 字段偏移替代 CO-RE；`offload_guard` 过滤 + `offload_sent` 累加 + 键摘除时回收）；
  **XDP 计量探针**（`--xdp <iface>` 可选，恒 `XDP_PASS`、只计数不干预）。
  实测：22 程序/22 map、`cargo test` 302/302、musl x86_64 交叉构建通过（`sodama 7.7M · sodama-ebpf 772K`）；
  **内核级已实测**（QEMU 内核矩阵 `lab/matrix.sh vm`，内核 7.2.8，宿主用户即可）：`verify` **12/12 全绿**
  （原 9 项 + `l3-attach` + `l3` + `xdp`）、fentry 挂载成功（偏移由运行内核 BTF 解出）、记账
  `kernel_bytes`/`reclaimed_bytes` 实测增长与释出、**L3 端到端过关**（ipip 隧道：小连接分流 + 512KB 逐字节回显；
  同批修掉回程多剥 14B、回显夹具 8 次读上限、`net_offload.py` 指针段错误三处缺陷）；
  **未过/待办**：offload 用例的 QEMU 既有抖动（随宿主状态大幅波动，基线同环境亦失败，待查注册交接竞态）、
  生产 6.12 回验（见 ADR-0065、devlog §19）
  （数据面调试开关：`SODAMA_NO_OFFLOAD_ACCOUNT=1` 跳过记账探针挂载，供 A/B 与隔离排障）
- **能力缺口批次 #1–#4（完成，2026-10-16）**：按 `docs/capability-gap-review.md`「日常网关影响」
  top 4 逐项落地（ADR-0066、devlog §20）——
  **① `must_<组名>` 糖**（≡ `<组名>(must)`，含 fallback 展开；顺带修 `--config` 路径
  丢 `(must)`/`(mark: 0x…)` 参数的静默丢语义；投递侧成套：`conn_save` 只在非 UDP-53
  或 must 时存，TCP-53/`dns_loop` 交付分支按 conn_state 的 must 位分流——must 的 DNS
  走普通代理流，不劫持）；
  **② 订阅 `http(s)-file://`**（dae 风格 scheme；磁盘回退沿用 `sub-cache/<tag>.bin`，
  与 dae `persist.d` 同口径：先解析成功再落盘，失败回退）；
  **③ 接口懒绑定/热插拔**（`loader/src/ifwatch.rs`：`path.Match` 风格 glob +
  `wan_interface: auto`→默认路由接口 + 1s 轮询；启动按 pattern 挂载，运行中自动补挂/清理，含 L3 记账；
  偏离 dae 的 netlink 订阅）；
  **④ `match_set` 容量 64 → 1024**（= dae 默认；有界循环实测上限仅 ~217，改内核 `bpf_loop`；
  domain 位图 word/bit 改 loader 预计算写进 `match_set.value[0..2]`，跨规则拼接处重定位）。
  实测：`cargo test` **308/308**；内核级 QEMU 7.2.8 **`verify` 12/12 + 新增 cap 阶段 5/5**
  （`test-must` / `test-sub-file` / `test-hotplug` / `test-rules-cap`（71 match_set + 高位命中）/
  `test-domain`），汇总行 `verify=PASS cap=PASS`（lab 另修一个 VM 环境缺口：最小 initramfs 根 ns
  `lo` 默认 down → `lab.sh up()` 幂等拉起 + 假上游存活检查）
- **eBPF 余项批次（完成，2026-10-16）**：按 `docs/capability-gap-review.md` §3 数据的全部余项
  收官（ADR-0067、devlog §21；本批后 §3 判定 24 行全部「已完成」）——
  **① `lan_egress` 角色**（`sodama_lan_egress{,_l3}`；LAN 接口 ingress+egress 双钩子，反向 conntrack 刷新）；
  **② 出口连通性判定**（`outbound_connectivity_map` 1536 + `outbound_is_alive` 三处判定 +
  BLOCKED_ALIVE（限速键 = outbound）+ 控制面 2s 健康投影（`dial_mode=ip` 且策略非 random/fixed
  且组非空）；组标死 → 新连接被数据面阻断）；
  **③ offload 背压 fuse**（`tcp_offload_pause` + 两阶段 drain/lift + 用户态泵 + `SODAMA_FUSE_MAX_BACKLOG`）；
  **④ 首包 handoff**（`routing_handoff_map` + 控制面兑底读取 conn_state → handoff）；
  **⑤ stats/事件键域对齐 dae**（stats 0..12 + 限速键 0..261 + 6 新计数键 + LAN TCP fail-closed）；
  **⑥ `conn_state_map` pinning 与容量可配**（`/sys/fs/bpf/sodama` 冷启动全表迁移 +
  `bpf_conn_state_map_size`（默认 262144 = dae 默认，启动生效））；
  **⑦ 纯 SYN 重绑**（同代拒改/异代重路由，事件 5/9；`datapath_generation` reload 递增）。
  实测：`cargo test` **310/310**；内核级 QEMU 7.2.8 **`verify` 12/12 + cap 阶段 9/9**
  （新增 `test-gaps` / `test-alive` / `test-fuse` / `test-pinning`）；
  **栈预算教训**：新增写入把 `split_flow` 链路 combined stack 推过 512（verifier 实测 528）→
  事件/conn_state/handoff 三结构全部移入 per-CPU scratch + 四函数改子程序帧（详见 ADR-0067）

原理与 dae 源码对照见 [NOTES.md](./NOTES.md)。

## 目录

```
ebpf-rs/src/         Rust/aya-ebpf 数据面（唯一）：14 个 TC 程序（7 角色 × L2/L3）+ 6 个 cgroup 程序
                     （P17b pname 采集）+ sk_skb offload（含背压 fuse）+ fentry/kprobe 记账 + xdp 计量
                     + 规则 VM + conn_state（+pinning 迁移）+ 出口连通性 + handoff + 单写者；
                     BTF maps（含 map-in-map 与 3 张 per-CPU scratch）
loader/src/main.rs   Rust + aya：加载、挂钩子、setns、tproxy/UDP socket、规则下发/热重载、
                     relay/Dialer、UDP NAT、offload 注册、janitor、只读状态面、DNS 线程、
                     接口懒绑定/热插拔（启动 specs → `IfWatch` → 主循环每 1s 补挂/清理）
loader/src/rules.rs  迷你规则解析 + 编译（match_set 编码 + LPM trie + regex 编译 + dump/对拍；P19 组名→outbound 索引；容量 1024；domain 位下标预计算进 value[0..2]）
loader/src/target.rs P14：拨号目标类型（IPv4/IPv6/域名）+ 逐协议编码（vless/vmess/tuic/RFC1928/字符串；v6 形式见 P16）
loader/src/quicsniff.rs P20：QUIC Initial SNI 嗅探（RFC 9001 解密：固定盐 HKDF + 头部保护 + AES-128-GCM + CRYPTO→ClientHello）
loader/src/sniffer.rs P14/P18e/P20：TLS SNI / HTTP Host / h2c（preface + 最小 HPACK :authority）嗅探（纯解析函数 + MSG_PEEK 采集循环；P20 起 ClientHello 解析与 QUIC 共用）
loader/src/subscribe.rs P15：订阅拉取（HTTP(S)/file、**`http(s)-file://`（dae 风格 scheme，ADR-0066）**、重定向/chunked/base64）+ 链接解析 + 磁盘缓存/回退（`sub-cache/<tag>.bin`）
loader/src/ifwatch.rs 接口懒绑定/热插拔（ADR-0066）：`path.Match` 风格 glob + `auto`→默认路由接口 + 1s 轮询（/sys/class/net）+ 启动/运行中挂载去重
loader/src/group.rs   P15/P18e：节点组 filter/policy/健康探测/失败切换（GroupRuntime）；P18e 成员热替换（replace_members 健康继承）+ udp_check_dns
loader/src/geodata.rs P17a：v2ray .dat 读取（手写 protobuf）+ geoip/geosite 展开/搜索目录（含 XDG）/缓存
loader/src/config.rs 全量 .dae 解析（词法/语法、include 合并、schema 校验、deferred 提取；P19 已定义组名在 routing 提取中直通）
loader/src/status.rs 状态面（Unix socket：status/rules/config/maps/metrics + reload/suspend/resume 控制命令）
loader/src/socks5.rs 最小 SOCKS5 客户端（relay 的一种 dialer，握手 + CONNECT）
loader/src/outbound.rs 拨号器梯度：direct / socks5 / shadowsocks(含 2022) / trojan / vless / vmess / tuic /
                     hysteria2 / http(CONNECT)；URL 解析、标记 socket、ReadHalf/WriteHalf、UDP relay、offload/UDP 能力判定
loader/src/ss.rs    shadowsocks classic AEAD（SIP004）+ SS2022（SIP022：BLAKE3 子密钥,
                   TCP 随机 salt / UDP session+packet id；读写两半）
loader/src/tls.rs   共享 TLS 层（rustls：握手 + 读路径 pending/抽干不变量，ALPN）
loader/src/trojan.rs trojan（TLS + CONNECT 头；仅 TCP；无 close_notify 半关闭）
loader/src/vless.rs vless（TCP/UDP，tls/none/reality，tcp/ws 传输，addons flow=xtls-rprx-vision，响应头惰性解析）
loader/src/tls13.rs P18d：最小 TLS 1.3 客户端（Chrome 形状 CH + X25519MLKEM768 + 记录层 AES-GCM/ChaCha + raw_read 直通）
loader/src/reality.rs P18d：REALITY 客户端（authKey HKDF、session_id AES-GCM 密封、证书 HMAC-SHA512/ed25519 绑定）
loader/src/vision.rs P18d：xtls-rprx-vision 帧层（UUID/cmd/len/pad、长填充、下行 splice 裸读）
loader/src/ws.rs    VLESS over WebSocket：RFC6455 客户端传输（Upgrade 握手 + 掩码帧，可拆半）
loader/src/anytls.rs AnyTLS 客户端（anytls-go v2：sha256 认证 + 帧 + paddingScheme，单 Stream）
loader/src/vmess.rs vmess AEAD（嵌套 HMAC KDF、auth id、SHAKE128 分块/填充、终止块）
loader/src/tuic.rs tuic v5（QUIC：exporter 认证、双向流、DATAGRAM 分片/重组、连接复用）
loader/src/quicsock.rs QUIC socket 中间件：salamander 混淆（ObfsSocket）+ udphop（HopSocket）
loader/src/brutal.rs Brutal 近似拥塞控制（hybrid：inner BBR + 认证后速率目标）
loader/src/hysteria2.rs hysteria2（QUIC：h3 认证、0x401 TCP 流帧、SessionID DATAGRAM 分片/重组）
loader/src/hpack.rs HPACK Huffman 解码 + QPACK 静态表编解码（h3 认证用）
loader/src/huffman_table.rs 生成表：HPACK Huffman 256 项 + QPACK 静态表 99 项
loader/src/dns.rs    DNS wire 解析/构造、域名匹配（suffix/full/keyword/regex）、位图计算、正负缓存
loader/src/dnsup.rs  P18a/b DNS 上游抽象/传输：udp/tcp/tcp+udp/tls(DoT)/https(DoH)/quic(DoQ)，持久连接 + 失败重连；URL 参数 sni/insecure/ecs（ECS 注入模式）
loader/src/dnsroute.rs  P18c dns.routing：请求/应答分流编译与匹配（qname/qtype/sip/upstream/ip；reject/asis/accept/tag 重查；qname(file:) 自定义名单；应答侧 sip 来源过滤）
lab/real-user.dae    真实用户风格配置（0640；含可编译规则与 deferred 示例）
lab/socks5_echo.py   最小 SOCKS5 后端（socks5 dialer 对端，从 host ns 可达）
lab/ss_server.py     P5-G1：独立实现的 shadowsocks 服务端（Python cryptography，TCP+UDP）
lab/trojan_server.py P5-G1：独立实现的 trojan 服务端（stdlib ssl）
lab/vless_server.py  P5-G2：独立实现的 vless 服务端（stdlib + 可选 ssl，TCP+UDP）
lab/vmess_server.py  P5-G2：独立实现的 vmess AEAD 服务端（cryptography，TCP+UDP）
lab/proto-check/     P5-G2/G3：Go 侧交叉验证（outbound 客户端 ↔ Python 服务端；tuic-server；hy2-server）
lab/proto-check/tuic-server  P5-G3a：Go/quic-go 独立实现的 TUIC v5 参考服务端（需构建）
lab/proto-check/hy2-server   P5-G3b：Go/http3 独立实现的 hysteria2 参考服务端（需构建）
lab/proto-check/build-tuic-server.sh  构建 tuic 服务端（用 parity 的 dae-work + module 缓存）
lab/proto-check/build-hy2-server.sh   构建 hysteria2 服务端（同上）
lab/gen-huffman-table.py  从 Go module 缓存机械提取 HPACK/QPACK 表，生成 Rust 常量
lab/gen-certs.sh     生成 trojan/vless/vmess 测试自签证书（lab/certs/，10 年）
lab/ss_local_probe.py     P5-G1：不依赖 netns 的 ss 协议层本地复现器（对本地 echo）
lab/trojan_local_probe.py P5-G1：不依赖 netns 的 trojan 协议层本地复现器
lab/udp_mark_probe.py lab 调试工具：marked UDP 的 connect vs sendto 在 tproxy 下的行为差异
lab/fake_dns.py      假 DNS 上游（A 记录应答，UDP+TCP；big.test 供截断测试）
lab/dns_probe.py     透明 DNS 探针（UDP/TCP/--edns，打印 rcode/tc/ttl/answer）
lab/dns_transport_server.py  P18a DoT/DoH 上游服务端（自签证书，转发到假 UDP DNS；tls|https 两模式）
lab/proto-check/doq-server  P18b DoQ 参考服务端（Go/quic-go，独立实现；`build-doq-server.sh` 构建）
lab/stream_probe.py  relay 大流量探针（发 N KB 并逐字节校验回显）
lab/udp_probe.py     UDP NAT 探针（多报文 + 应答来源校验）
lab/rules.dae        实验规则（dae `.dae` 语法子集）
lab/rules.reload.dae 热重载用的规则集（8080 由 proxy 改为 block）
lab/ops-reload.dae   P6：整配置热重载模板（会话复制到 /tmp，测试运行中改写 routing/dns）
lab/rules.fault.dae  reload 打流用的规则集（8080 判决不变，加一条无关规则）
lab/rules.dns.dae    P3a 域分流规则（proxy.test / direct.test 的 domain 规则 + fallback）
lab/dnsroute.dae     P18c dns.routing 夹具（双上游 up1/up2 + 请求/应答规则；asis 实验中）
lab/rules.regex.dae  P3b-2a regex 域分流规则（api[0-9]+.regex.test 命中）
lab/rules.udp.dae    P4b UDP NAT 规则（所有 UDP:9998 判 proxy，验证 mark 防自环）
lab/lab.sh           建/拆 netns 拓扑（标准 + 单臂）、跑测试、热重载、故障注入
lab/gateway.sh       P13：真网关模式一键脚本（up/down/status/test/watchdog/--dry-run；宿主流量透明接管；P15 支持 --subscribe/--group；P18c 支持 --config/--dns/--geodata-dir；P19 启动自检 + 失败自动回滚，--wait/--no-wait；I7 节点看护 + 持久日志）
lab/quic_probe.py     P20：QUIC Initial 探针（Python 独立实现 RFC 9001 加密，造带 SNI 的 1200B 首包）
lab/sub_server.py    P15：订阅服务器夹具（GET /sub 返回指定文件内容；P18e 起按请求重读）
lab/http_connect_server.py P18e：独立实现的 HTTP CONNECT 代理（可选 Basic；ss/代理跨实现验证用）
lab/rules.gateway.dae P13：网关模式规则（DNS must 置顶、无私网 sip、QUIC block、fallback proxy）
lab/gateway.dae      P18c：网关模式配置（同规则的 routing + DNS 进控制面 → 国内走本地明文/其余 DoH + 广告拦截）
lab/blocklist.txt    P18c：自定义 DNS 拦截名单（qname(file:) 读取；默认全部注释）
ebpf-rs/             P9：完整 Rust 数据面（12 TC（6 角色×L2/L3）+ offload verdict + 规则 VM；BTF maps；
                     不属主 workspace，构建：lab/build-ebpf-rs.sh，产物 target/bpfel-unknown-none/release/）
lab/wan_echo.py      WAN 侧 echo（9999/8080 TCP；8082 纯回显；9998 UDP）
lab/client_probe.py  客户端探针
lab/hold_conn.py     长连接探针（验证 conn_state 缓存跨热重载）
lab/rebind_probe.py  单写者探针（信号文件驱动的三段式长连接）
lab/rebind_tool.py   redirect_track / sodama_stats_map 的 bpftool JSON 读写工具
lab/parity.sh        规则编译对拍（dae 原版 Go 编译器 vs sodama 编译器）
lab/parity/          Go 侧对拍工具（dae 源码副本 + stub 构建的测试用例）
lab/matrix.sh        K2 内核矩阵（run 当前内核 / vm 用 QEMU 引导第二个内核）
lab/vm-init.sh       QEMU 内的验证入口（矩阵用）
lab/matrix/SUMMARY.md 矩阵执行结果与未覆盖项
```

## 依赖

- Linux 内核 ≥ 5.17（`bpf_loop` 路由扫描；aya 在内核 ≥ 6.6 时走 TCX）
- Rust（cargo）与 nightly + rust-src + `bpf-linker`（编 eBPF 数据面，`lab/build-ebpf-rs.sh`）；
  libbpf 头文件（`/usr/include/bpf`）、`ip`/`tc`/`bpftool`、python3、gcc（仅 P7 基准端点 `bench_io.c`）
- root 权限（加载 eBPF、建 netns）；对拍与矩阵的 VM 无需 root
- QUIC 交叉验证（P5-G3a/G3b）：Go 工具链 + module 缓存
- （可选）sing-box：anytls 跨实现测试靶子（`cargo test` 缺失时自动跳过）
  （`lab/proto-check/build-tuic-server.sh` / `build-hy2-server.sh`）
- （可选）shadowsocks-rust（`ssserver`，P18e ss2022 跨实现对端，`pacman -S shadowsocks-rust`）

## 部署（P18e）

系统级安装：`install/install.sh`（二进制 → `/usr/local/bin`、unit → 系统 unit 目录、
配置与 geodata 示例；支持 `--dry-run` 与 `--uninstall`）；unit 文件
`install/sodama.service`（capability 最小集、SIGHUP `ExecReload`）——详细步骤与
真网关模式配合见 [`docs/deploy.md`](../docs/deploy.md)。CI（GitHub Actions）覆盖
loader 构建、`cargo test --release` 与 eBPF 对象构建（`.github/workflows/ci.yml`，
固定 nightly-2026-09-29 + bpf-linker 0.11.1；fmt/clippy 刻意不入 CI，见文件内注释）。

**并发上限与 RLIMIT_NOFILE（I2）**：转发每连接约 4 fd（2 socket + 活跃时 2 pipe），
所以 fd 上限就是并发天花板。引擎启动时把 soft 提到 hard；**以 root（CAP_SYS_RESOURCE）
运行时同时抬高 hard** 到 `min(/proc/sys/fs/nr_open, 262144)`。OpenWrt/procd 默认
hard=4096（≈1000 连接）——不抬 hard 会把并发卡在四位数；抬后上限约 6.5 万连接，
实际瓶颈转移到内核 socket 内存与 CPU。状态面 `relay.fds_soft_limit` 可核对生效值。

## 快速开始

```bash
lab/lab.sh build           # 编译（不需要 root）
sudo lab/lab.sh up         # 标准拓扑 + 启动 sodama（带只读状态面 socket）
sudo lab/lab.sh verify     # 9 个用例（含状态面与故障注入；fault-kill 最后会杀掉加载器）
sudo lab/lab.sh down

sudo lab/lab.sh dual-up    # 单臂拓扑（bridge + 单接口路由器）
sudo lab/lab.sh verify     # 同一套用例在单臂拓扑上重跑

# K3：配置工具（不加载 eBPF、不需要 root）
target/release/sodama validate <config.dae>        # 解析 + schema 校验 + 可编译性
target/release/sodama export-config <config.dae>   # 合并后的配置（JSON）
target/release/sodama extract-routing <config.dae> # 数据面可编译的规则（deferred 到 stderr）
target/release/sodama sub-parse <url|path> [--tag <t>] [--json] [--limit <n>] [--timeout <s>]
                                                   # 只读：拉订阅→解码→逐行解析（控制面板导入预览用）
target/release/sodama status [--socket <path>] [--cmd status|rules|config|maps] [--json]

sudo lab/lab.sh config-up  # 用 lab/real-user.dae 启动（K3；该文件需 chmod 640，loader 会校验权限）
sudo lab/lab.sh test-config # 全量解析 + 子集编译 + deferred 上报
sudo lab/lab.sh test-status # 只读状态面
sudo lab/lab.sh forward-up  # 标准拓扑 + SOCKS5 过渡一跳（K3）
sudo lab/lab.sh test-forward # orig_dst 一跳保留

sudo lab/lab.sh dns-up      # 标准拓扑 + DNS 接管（P3a，假上游）
sudo lab/lab.sh test-domain # DNS → 域位图 → domain 规则分流
sudo lab/lab.sh test-dns-cache  # P3b-1：正/负缓存 + TTL 递减
sudo lab/lab.sh test-dns-tcp    # P3b-1：TCP DNS 分帧 + 缓存
sudo lab/lab.sh test-dns-reload # P3b-1：reload 后用缓存重建新槽位图
sudo lab/lab.sh test-dns-edns   # P3b-2a：UDP 截断/EDNS 尺寸/TCP 完整应答

sudo lab/lab.sh regex-up    # P3b-2a：regex 域分流会话
sudo lab/lab.sh test-domain-regex # regex 命中走 tproxy、不命中直转

sudo lab/lab.sh relay-up    # P4a：TCP relay（--dialer direct，短 idle 便于测回收）
sudo lab/lab.sh test-relay       # 真实转发 + 512KB 完整性
sudo lab/lab.sh test-relay-idle  # relay janitor 回收空闲连接
sudo lab/lab.sh offload-up  # P4c：relay + TCP offload（fast_sock/sk_skb）
sudo lab/lab.sh test-relay-offload # 内核拼接证据（用户态零字节）
sudo lab/lab.sh udp-up      # P4b：UDP NAT 会话
sudo lab/lab.sh test-udp-relay   # UDP 真实转发 + 会话复用
sudo lab/lab.sh test-udp-idle    # UDP 会话回收

lab/gen-certs.sh            # P5-G1：生成 trojan 自签证书（首次跑 trojan-up 前）
sudo lab/lab.sh ss-up       # P5-G1：shadowsocks 会话（chacha20-ietf-poly1305，带 --offload 验证互斥）
sudo lab/lab.sh test-ss          # 跨实现 TCP 512KB + 用户态 AEAD + offloaded=0
sudo lab/lab.sh ss-udp-up   # P5-G1：shadowsocks UDP 会话（rules.udp.dae）
sudo lab/lab.sh test-ss-udp      # ss UDP 3/3 + sessions_proxied=1 / direct_fallback=0
sudo lab/lab.sh trojan-up   # P5-G1：trojan（TLS）会话
sudo lab/lab.sh test-trojan      # 跨实现 TCP 512KB + CONNECT 日志 + offloaded=0
python3 lab/ss_local_probe.py     # P5-G1：协议层本地复现（不需要 root/netns）
python3 lab/trojan_local_probe.py # P5-G1：同上（trojan）

sudo lab/lab.sh vless-up    # P5-G2：vless（明文 TCP）+ offload 互斥
sudo lab/lab.sh vless-tls-up     # P5-G2：vless + security=tls（自签）
sudo lab/lab.sh vless-udp-up     # P5-G2：vless UDP（rules.udp.dae）
sudo lab/lab.sh test-vless / test-vless-udp
sudo lab/lab.sh vmess-up    # P5-G2：vmess（chacha20-poly1305）+ offload 互斥
sudo lab/lab.sh vmess-tls-up     # P5-G2：vmess（aes-128-gcm + TLS）
sudo lab/lab.sh vmess-udp-up     # P5-G2：vmess UDP
sudo lab/lab.sh test-vmess / test-vmess-udp

lab/proto-check/build-tuic-server.sh   # P5-G3a：构建 TUIC 参考服务端（Go/quic-go）
lab/proto-check/build-hy2-server.sh    # P5-G3b：构建 hysteria2 参考服务端（Go/http3）
sudo lab/lab.sh tuic-up     # P5-G3a：tuic v5（QUIC）会话 + offload 互斥
sudo lab/lab.sh test-tuic        # 512KB + QUIC 流 + Go 服务端日志
sudo lab/lab.sh tuic-udp-up # P5-G3a：tuic UDP（QUIC DATAGRAM）
sudo lab/lab.sh test-tuic-udp    # 3/3 + 分片/重组
sudo lab/lab.sh hy2-up      # P5-G3b：hysteria2（h3 认证 + QUIC）会话 + offload 互斥
sudo lab/lab.sh test-hy2         # 512KB + 0x401 流帧 + Go/http3 服务端日志
sudo lab/lab.sh hy2-udp-up  # P5-G3b：hysteria2 UDP（QUIC DATAGRAM）
sudo lab/lab.sh test-hy2-udp     # 3/3 + SessionID 分片/重组
sudo lab/lab.sh hy2-obfs-up # P5-G3b+：salamander 混淆（TCP）+ offload 互斥
sudo lab/lab.sh test-hy2-obfs    # 512KB + 服务端 salamander 日志
sudo lab/lab.sh hy2-obfs-udp-up  # P5-G3b+：salamander + UDP
sudo lab/lab.sh test-hy2-obfs-udp # 3/3
sudo lab/lab.sh hy2-brutal-up    # P5-G3b+：cc_override=brutal + 带宽声明
sudo lab/lab.sh test-hy2-brutal  # 512KB（Brutal 近似路径）
sudo lab/lab.sh hy2-hop-up  # P5-G3b+：udphop（端口并集 + 5s 跳端口 + 多端口 mux）
sudo lab/lab.sh test-hy2-hop     # 两轮 512KB 跨跳存活
lab/proto-check/build-naive-server.sh  # P25：构建 naive 参考服务端（Go 标准库 h2）
sudo lab/lab.sh naive-up    # P25：naive（HTTP/2 CONNECT + Basic）会话 + offload 互斥
sudo lab/lab.sh test-naive       # 交互零延迟 + 512KB 双向流控 + 服务端 proto=HTTP/2.0
lab/proto-check/build-naive-h3-server.sh  # P26：构建 naive h3 参考服务端（Go/quic-go http3）
lab/proto-check/build-doh-h3-server.sh    # P26：构建 DoH h3 参考服务端（Go/quic-go http3）
sudo lab/lab.sh naive-h3-up # P26：naive（HTTP/3 CONNECT + Basic）会话
sudo lab/lab.sh test-naive-h3    # 交互零延迟 + 512KB 双向 + 服务端 proto=HTTP/3.0
sudo lab/lab.sh doh-h3-up   # P26：DoH over HTTP/3（上游 h3://）
sudo lab/lab.sh test-doh-h3      # 两查询复用一条 QUIC 连接（服务端 new-conn 计数断言）
lab/proto-check/build-juicity-server.sh  # P27：构建 juicity 参考服务端（Go/quic-go）
sudo lab/lab.sh juicity-up  # P27：juicity v0（QUIC）TCP 会话 + offload 互斥
sudo lab/lab.sh test-juicity     # 交互 + 512KB 双向 + 服务端 target 日志
sudo lab/lab.sh juicity-udp-up   # P27：juicity UDP（每 NAT 会话一条双向流）
sudo lab/lab.sh test-juicity-udp # 3/3 + 服务端 UDP 会话 target 日志
sudo lab/lab.sh ecscache-up # P28：ECS 回填 / ecs_cache（上游 ecs=auto）
sudo lab/lab.sh test-ecs-cache   # scope=0 全局与 /16 跨子网复用（上游增量恰好 1 次）
lab/proto-check/build-ssr-server.sh  # P30：构建 SSR 参考服务端（Go；origin+plain）
sudo lab/lab.sh ssr-up   # P30：SSR（shadowsocksr-stream；origin+plain）会话 + offload 互斥
sudo lab/lab.sh test-ssr         # 交互 + 512KB 双向 + 服务端 target 日志
lab/proto-check/build-shadowtls-server.sh  # P31：构建 shadow-tls 参考服务端（Go/sing-shadowtls）
sudo lab/lab.sh shadowtls-up     # P31：shadow-tls v3（ss 插件）会话
sudo lab/lab.sh test-shadowtls   # 交互 + 512KB + STLS handler 交接 + ss 后端 target
sudo lab/lab.sh shadowtls-v2-up  # P31：shadow-tls v2（首帧 HMAC）
sudo lab/lab.sh test-shadowtls-v2
sudo lab/lab.sh shadowtls-v1-up  # P31：shadow-tls v1（TLS1.2 裸隧道）
sudo lab/lab.sh test-shadowtls-v1
# P12：本地 SOCKS5 入口（浏览器验收；不加载 eBPF、不需 root）：
# target/release/sodama --listen-socks 127.0.0.1:11080 --dialer 'anytls://…' --dial-timeout 15
# 浏览器：SOCKS5 127.0.0.1:11080（Firefox 勾“SOCKS v5 时代理 DNS”）；停止：pkill -f listen-socks
# P13：真网关模式（宿主流量透明接管；浏览器零配置）——需 root：
#   sudo lab/gateway.sh up                      # 默认接口 = 默认路由网卡（如 wlan0）
#   lab/gateway.sh test                         # 204 / 出口 IP（代理路径）/ DNS 快检
#   sudo lab/gateway.sh down                    # 停止并恢复（幂等；同时停掉看护）
#   sudo lab/gateway.sh up --dry-run            # 只预览命令，零副作用
#
# I7 节点看护（默认开启，--no-watchdog 关）：每 15s 经代理路径探测三目标
# （gstatic / cp.cloudflare / bing，wget 走 fallback→proxy，≥2 成即通）；连续 4 次失败
# → SIGHUP 热刷新订阅组，仍失败 → 自动 down 回退直连（fail-open）+ 桌面通知。
# 日志持久化：/var/log/sodama-gateway.log（SODAMA_GW_LOG 可改；重启后可回溯）。
# 实测（故障演练：SIGSTOP loader 模拟假死）：默认参数 ~2–3 分钟自动切回直连。
#   （P16 起 IPv6 TCP 也会被透明代理；--no-ipv6 仍可临时关闭网卡 IPv6，down 时恢复）
# P18c：真网关 + 加密 DNS（宿主机 DNS 进控制面 → DoH/DoQ + dns.routing 广告拦截）：
#   sudo lab/gateway.sh up --config lab/gateway.dae --geodata-dir /usr/share/v2ray \
#        --subscribe /tmp/sodama-sub.url
#   --config <file.dae> 用配置模式（含 dns.upstream/dns.routing；少了 --rules 的简易格式）
#   --dns <URL>         显式指定控制面上游（https://… / quic://… / tls://…）
#   --geodata-dir <dir> 指向 v2ray .dat（geosite 规则编译期展开用）
# P10：真实节点端到端（节点 URL 只经环境变量传入，不落盘）：
#   REAL_NODE_URL='vless://…type=ws…' 或 'anytls://…' 或 'socks5://…'（桥接） \
#     sudo lab/real-node-e2e.sh    # client ns → tproxy → relay → 真实节点 → gstatic 204
# 慢节点首连可调：USE_DIAL_TIMEOUT=15 sudo -E lab/real-node-e2e.sh
# P14：嗅探 + 远端解析（域名交节点）：DIAL_MODE=domain sudo -E lab/real-node-e2e.sh
# P15：订阅 + 节点组（两个 ss 后端；kill A 验证健康标死与 failover）：
sudo lab/lab.sh subscribe-up && sudo lab/lab.sh test-subscribe
# 真机订阅：sudo lab/gateway.sh up --subscribe /tmp/sodama-sub.url [--group proxy]
# P16：IPv6（tproxy v6 → relay → ss(ATYP=4)、v6 direct 对照）：
sudo lab/lab.sh v6-up && sudo lab/lab.sh test-v6
# P17a：geoip/geosite（小型 .dat 夹具 + 假 DNS；geoip 集合内直连/集合外代理，geosite 位图代理）：
sudo lab/lab.sh geo-up && sudo lab/lab.sh test-geo
# P17b：pname（cgroup2 采集；python3 命中直连、curl 不命中走 fallback 代理）：
sudo lab/lab.sh pname-up && sudo lab/lab.sh test-pname
# P18a：DoT/DoH 上游（自签证书夹具 + 假 DNS；断言连接复用与传输路径）
sudo lab/lab.sh dot-up && sudo lab/lab.sh test-dot     # tls://（2 查询复用 1 条 TLS 连接）
sudo lab/lab.sh doh-up && sudo lab/lab.sh test-doh     # https://（keep-alive 复用，path=/dns-query）
sudo lab/lab.sh dns-udp-up && sudo lab/lab.sh test-dns-udp    # 显式 udp://（仅 UDP）
sudo lab/lab.sh dns-tcpup-up && sudo lab/lab.sh test-dns-tcpup # 显式 tcp://（仅 TCP）
# P18b：DoQ（先构建 Go/quic-go 参考服务端；断言连接复用与 ID 0/恢复）
lab/proto-check/build-doq-server.sh
sudo lab/lab.sh doq-up && sudo lab/lab.sh test-doq
# P18c：dns.routing 请求/应答分流（双假上游 + asis 回原目的 + 热重载）
sudo lab/lab.sh dnsroute-up && sudo lab/lab.sh test-dnsroute
# P18c+：上游 A/B 对比（用户态；需 root 因为 marked socket；不加载 eBPF）
sudo target/release/sodama dns-bench --config lab/gateway.dae \
  --names www.taobao.com,www.google.com --tags router,alidns_ecs,alidns --runs 5 --client 192.0.2.254
# P18c++：并发/多轮 + p95；`--rounds R --concurrency C`（总样本 runs×R）
sudo target/release/sodama dns-bench --config lab/gateway.dae \
  --names www.taobao.com --tags alidns,alidns_ecs,router --runs 10 --rounds 2 --concurrency 4 --client 192.0.2.254
# P18d：REALITY + Vision（自实现 TLS 1.3；ignored e2e，需本机 sing-box）
#   本机参考服务端 128KB 往返：
#   cargo test --release -- --ignored e2e_reality_vision
#   真实节点（不接管系统网络；HTTP/HTTPS，HTTPS 会触发下行 splice）：
#   NODE='vless://…security=reality…flow=xtls-rprx-vision' \
#     SODAMA_DAE_E2E_URL="$NODE" SODAMA_DAE_E2E_TARGET=example.com:80 \
#     cargo test --release -- --ignored e2e_reality_vision
#   SODAMA_DAE_E2E_URL="$NODE" SODAMA_DAE_E2E_HTTPS=www.gstatic.com cargo test --release -- --ignored e2e_reality_vision
#   loader 本地 SOCKS（root，SO_MARK 生效）定向验证节点：
#   sudo target/release/sodama --listen-socks 127.0.0.1:1083 --dialer "$NODE"
#   curl -x socks5h://127.0.0.1:1083 http://example.com/
sudo lab/lab.sh ops-up      # P6：运维面会话（--log-file + 状态面控制命令）
sudo lab/lab.sh test-ops         # suspend(fail-open)/reload/metrics/sysdump/日志轮转
sudo lab/lab.sh ops-reload-up    # P6：整配置热重载会话（/tmp 配置副本 + 假 DNS）
sudo lab/lab.sh test-config-reload # 规则变更生效/坏配置回滚/DNS 上游热切换
# 运维 CLI（对运行中的实例）：
target/release/sodama reload|suspend|resume [--socket <path>]
target/release/sodama metrics [--socket <path>]
target/release/sodama sysdump [--socket <path>] [--out <file>]
target/release/sodama trace [--seconds N]
# P33/P35：配置热驱动（inotify 事件驱动，毫秒级 + 100ms 去抖；<秒> = 兜底扫描；见 ADR-0060/0062）
#   config `global { watch_config: 10 }`（或 --watch-config 10）；变更自动 fast reload
#   （订阅节点缓存 sub_cache_ttl，默认 1800s；失败源负缓存 sub_fail_ttl 默认 600s）——改配置保存即生效，
#   未变源 0 请求（P37；手动 reload/SIGHUP 仍强制重拉）
target/release/sodama reload --socket /tmp/sodama-status.sock   # 手动线：等价 SIGHUP（同步等结果，强制重拉订阅）
sudo env USE_CONFIG=/tmp/sodama-watch.dae USE_WATCH_CONFIG=2 USE_DIALER=direct lab/lab.sh up  # lab 自动线
# P34/P35：多订阅顺序回退（pacman 风格）与默认配置发现（ADR-0061）
#   config `subscription { 主: 'url1'; 备: 'url2' }`：声明顺序 = 优先级，首个有活节点的源生效；
#   `global { subscription_failover: false }` 关回退（池化）
#   默认配置候选：$XDG_CONFIG_HOME/sodama/config.dae → ~/.config/sodama/config.dae
#   → /etc/sodama/config.dae（无 home 的软路由/OpenWrt 可用系统目录）
# P35：行为参数全部写进 config（唯一事实来源）：dial_mode/dial_timeout/sniffing_timeout/
#   watch_config/sub_cache_ttl/sub_fail_ttl/geodata_dir/log_file/status_socket/…；命令行仅进程级参数与调试覆盖
sudo lab/lab.sh sub-order-up && sudo lab/lab.sh test-sub-order   # 顺序回退 + 重排 2s 内生效（inotify+缓存）端到端
# P36：用户分流名单 + 标准格式规则集（独立文件/URL 自动更新，ADR-0063）
#   config `rule_set { tag: 'url|路径' }` → routing `domain(ruleset: tag) -> proxy|direct`
#   纯文本名单（编辑即热生效）；Clash YAML / sing-box JSON 自动识别；远程按
#   rule_set_update_interval 刷新（0=每次 reload）；status.rule_sets 可查计数
sudo lab/lab.sh ruleset-up && sudo lab/lab.sh test-ruleset  # 三格式 + URL 刷新 + 未知集硬失败
# 真网关用户名单（编辑保存即生效）：~/.config/sodama/rules/user_{proxy,direct}.txt
# 真网关零行为参数启动（只读 config）：sudo lab/gateway.sh up
# P7 工具链：
lab/bench.sh build                 # 编译 C 基准端点（gcc）
lab/bench.sh all                   # 六路径性能表（root；自动起/停会话：direct relay offload ss udp-direct udp-nat）
lab/soak.sh run 60 tcp             # 60s soak（另有 ss/udp 模式）
lab/build-static.sh                # 静态二进制（SMOKE_ALPINE=1 加 Alpine 冒烟）
# P8/P9 数据面（Rust/aya-ebpf，唯一数据面；C 对象已移除，见 ADR-0025）：
lab/build-ebpf-rs.sh               # 编译 Rust 数据面对象（需 nightly + bpf-linker；lab.sh build 已含）
sudo lab/lab.sh up                 # up/dual-up 直接加载 Rust 对象（无数据面分支）
lab/proto-check/run.sh vless     # P5-G2：真实 Go 客户端 ↔ Python 服务端（TCP+UDP）
lab/proto-check/run.sh vmess     # 同上；vmess tls 也可
sudo lab/lab.sh down

lab/parity.sh              # 规则编译对拍（dae Go vs sodama Rust）
lab/matrix.sh run          # 当前内核矩阵（root）
lab/matrix.sh vm           # QEMU 引导第二个内核跑矩阵（普通用户）
```

单独跑：

```bash
sudo lab/lab.sh test-proxy       # 1.1.1.1:8080   -> 规则 1 -> tproxy
sudo lab/lab.sh test-direct      # 10.9.10.2:9999 -> 规则 2（LPM 集合第二前缀）-> 内核直转
sudo lab/lab.sh test-block       # 1.1.1.1:8081   -> 规则 3（!dport && sip）-> 丢弃
sudo lab/lab.sh test-host-proxy  # 宿主机自身流量 -> wan_egress + from_wan 回程
sudo lab/lab.sh test-reload      # 长连接跨热重载 + 新连接走新规则
sudo lab/lab.sh test-rebind      # redirect_track 单写者（竞争发布者 / 陈旧窗口）
sudo lab/lab.sh test-fault-reload # 故障注入：reload 中打流
sudo lab/lab.sh test-fault-kill  # 故障注入：kill -9 后 TCX 自动摘钩 + fail-open（破坏性）
```

## 规则语法（dae `.dae` 的子集）

```
# dip/sip/mac 是集合（折叠成一个 LPM trie）；dport/sport/dscp 每个参数一个 match_set（OR）
dip(1.1.1.1/32) && dport(8080) -> proxy
dip(10.9.9.0/24, 10.9.10.0/24) && dport(9999) -> direct
!dport(9999) && sip(10.0.0.0/24) -> block
l4proto(udp) && dport(443) -> proxy(must)
l4proto(tcp) && dport(443) -> direct(mark: 0x800, must)
mac('00:11:22:33:44:55') -> direct
l4proto(tcp) && dport(443) && domain(suffix: example.com) -> proxy
domain(regex: '^api[0-9]+\\.example\\.com$') && dport(9999) -> proxy
fallback -> direct
```

- 支持函数：`dip sip mac l4proto ipversion dport sport dscp domain pname fallback`
  （P17 起 dae 现有 routing 函数全覆盖；`geoip:`/`geosite:`/`ext:` 为参数 key，编译期展开）
- `domain` 支持 `suffix:` / `full:` / `keyword:` / `regex:` 四种 key，带 key 参数需与 DNS 接管配合（P3a）
- `regex:` 在规则编译期编译（非法正则硬失败）；匹配小写化 qname、模式保持原大小写（与 dae 一致）
- 运算符：`!`（取反）、`&&`（连接函数）；函数内逗号 = OR
- outbound：`direct / block / proxy / must_rules`，参数 `mark: 0xNNN`、`must`；
  **`must_<组名>` 前缀糖 ≡ `<组名>(must)`**（dae 同形；未定义组仍回退 proxy 但 must 语义不丢，ADR-0066）
- 未支持：无（dae 现有 routing 函数全覆盖）；`geoip` 的 `inverse_match` 是硬错误（dae 同）；
  pname 用 comm 而非 argv basename（见 ADR-0033）

**编码与 dae 完全一致**（`component/routing/matcher_builder.go:60-73`）：
整条规则最后一个 match_set 拿真实 outbound；同一函数内非最后一个 match_set 用
`LogicalOr(0xFE)`（粘性 OR：命中后跳过后续同组条件）；非最后一个函数的收尾 match_set
用 `LogicalAnd(0xFF)`。

## 实测结果

同一套 9 用例在标准拓扑与单臂拓扑上各跑一遍，**全部通过**：

```
proxy     : PASS     # LAN 客户端 -> tproxy，orig_dst=1.1.1.1:8080
direct    : PASS     # LPM 集合第二个前缀 10.9.10.2 -> 内核直转
block/not : PASS     # !dport && sip -> 丢弃，未进入用户态
host/wan  : PASS     # 宿主机自身流量（wan_egress + from_wan 回程）
reload    : PASS     # 在途连接保持旧判决，新连接按新规则处理
rebind    : PASS     # 单写者：竞争发布者被拒 + 陈旧窗口恢复
status    : PASS     # 只读状态面：JSON 可用、未知命令被拒绝
fault/reload: PASS   # 10 轮 SIGHUP + 打流，连接全部成功、无热重载失败
fault/kill : PASS    # kill -9 后 TCX 自动摘钩，流量回落为内核直转（fail-open）
```

P3a DNS 域分流（`lab.sh dns-up && lab.sh test-domain`）：

```
answer=10.9.10.3 / answer=10.9.10.4         # DNS 经 sodama 转发到假上游
sodama tproxy: orig_dst=10.9.10.3:9999    # proxy.test 的 IP → domain 规则命中 → tproxy
wan-echo-ok data=ping                       # direct.test 的 IP → 内核直转
dns: queries=2 published_ips=2 domain_routing_entries=2
PASS: 域位图端到端（DNS 接管 → 位图 → domain 规则分流）
```

P3b-1 DNS 缓存与 TCP DNS（同一会话内）：

```
$ lab/lab.sh test-dns-cache
answer=10.9.10.9  ttl=30        # cache.test 首次：上行假上游
answer=10.9.10.9  ttl=29        # 第二次：命中缓存，TTL 递减；上游只收到 1 次
ancount=0                       # nx.test（NODATA）负缓存，两次查询上行 1 次
dns cache: hits=2 misses=4 entries=4 expired=0
PASS: DNS 缓存（命中不重查上游、TTL 递减、负缓存）

$ lab/lab.sh test-dns-tcp
proto=tcp                       # 2 字节长度前缀分帧
answer=10.9.10.6                # tcp.test；第二次命中缓存，假上游 QUERY-TCP 只 1 次
dns tcp: queries=2 responses=2 cache_hits=3
PASS: TCP DNS（2 字节分帧、可缓存、无 unsupported 计数）

$ lab/lab.sh test-dns-reload
domain_routing: slot=0 的 10.9.10.3 位图已重建   # SIGHUP 后用缓存重投影
sodama tproxy: orig_dst=10.9.10.3:9999        # 不再查 DNS，新槽位图仍生效
PASS: reload 后缓存重投影，新槽域位图端到端生效
```

P3b-2a regex 域分流与 EDNS（`regex-up` / `dns-up` 会话）：

```
$ lab/lab.sh regex-up && lab/lab.sh test-domain-regex
answer=10.9.10.21               # api1.regex.test 命中 regex 规则
sodama tproxy: orig_dst=10.9.10.21:9999
wan-echo-ok data=ping           # web.regex.test 不命中 → 内核直转
dns regex: domain_sets=1 bitmap_matched=1 domain_routing=1
PASS: domain(regex:) 命中走 tproxy、不命中直转

$ lab/lab.sh test-dns-edns
rcode=0 / tc=1 / ancount=0      # 无 EDNS（512）：big.test 大应答被截断
rcode=0 / tc=0 / ancount=60     # --edns 4096：完整 60 条 A（缓存命中）
tc=1                            # 再查一次无 EDNS：仍按客户端尺寸截断
ancount=60                      # --tcp：完整应答；假上游 QUERY big.test 只 1 次
PASS: EDNS 尺寸、UDP 截断（TC=1 + 清空 answer）、TCP 完整应答
```

P4 转发面（`relay-up` / `offload-up` / `udp-up` 会话）：

```
$ lab/lab.sh relay-up && lab/lab.sh test-relay
wan-echo-ok data=ping               # 经 relay 到真实 WAN 目标
stream-ok bytes=524288 prefix=...   # 512KB 随机数据逐字节一致
relay: conns_total=2 bytes_up=524299 bytes_down=524333 dial_errors=0
PASS: relay 真实转发（512KB 完整性）+ 状态面

$ lab/lab.sh test-relay-idle
after-idle: closed                  # --relay-idle-timeout 2s，janitor 强制回收
relay evicted: 1
PASS: relay janitor 回收空闲连接

$ lab/lab.sh offload-up && lab/lab.sh test-relay-offload
stream-ok bytes=524288              # 全程内核拼接
offload: offloaded=2 failures=0 userspace_bytes=0 verdicts=42 redirects=42
PASS: TCP offload（512KB 走内核拼接，用户态字节数远小于总传输）

$ lab/lab.sh udp-up && lab/lab.sh test-udp-relay
reply=udp-echo-ok data=ping0 from=2.2.2.2:9998
summary=3/3
udp nat: sessions=1/1 bytes_up=15 bytes_down=66
PASS: UDP NAT（真实转发、3 报文复用 1 会话、回包源地址正确）
```

P5-G1 协议栈（`ss-up` / `trojan-up` / `ss-udp-up` 会话；对端是独立 Python 服务端）：

```console
$ lab/lab.sh ss-up && lab/lab.sh test-ss
wan-echo-ok data=ping
stream-ok bytes=524288 prefix=wan-echo-ok data=start
ss tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0
PASS: shadowsocks TCP（独立 Python 服务端 + 用户态 AEAD + offload 互斥）
# 独立服务端日志：TCP target=1.1.1.1:8080

$ lab/lab.sh trojan-up && lab/lab.sh test-trojan
stream-ok bytes=524288 prefix=wan-echo-ok data=start
trojan tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0
PASS: trojan TCP（独立 Python 服务端 + TLS/CONNECT + offload 互斥）
# 独立服务端日志：CONNECT target=1.1.1.1:8080

$ lab/lab.sh ss-udp-up && lab/lab.sh test-ss-udp
summary=3/3
ss udp: sessions=1/1 proxied=1 fallback=0 bytes_up=180 bytes_down=66
PASS: shadowsocks UDP（独立 Python 服务端 + 会话计数）
```

P5-G2 协议栈（vless/vmess；对端同样是独立 Python 服务端）：

```console
$ lab/lab.sh vless-up && lab/lab.sh test-vless        # 明文 TCP
$ lab/lab.sh vless-tls-up && lab/lab.sh test-vless    # security=tls
stream-ok bytes=524288 prefix=wan-echo-ok data=start
vless tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0
PASS: vless TCP（独立 Python 服务端 + 用户态帧式封装 + offload 互斥）

$ lab/lab.sh vless-udp-up && lab/lab.sh test-vless-udp
summary=3/3
vless udp: sessions=1/1 proxied=1 fallback=0
PASS: vless UDP（独立 Python 服务端 + 帧式封装）

$ lab/lab.sh vmess-up && lab/lab.sh test-vmess        # chacha20-poly1305
$ lab/lab.sh vmess-tls-up && lab/lab.sh test-vmess    # aes-128-gcm + TLS
stream-ok bytes=524288 prefix=wan-echo-ok data=start
vmess tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0
PASS: vmess TCP（独立 Python 服务端 + AEAD 分块 + offload 互斥）

$ lab/lab.sh vmess-udp-up && lab/lab.sh test-vmess-udp
summary=3/3
vmess udp: sessions=1/1 proxied=1 fallback=0
PASS: vmess UDP（独立 Python 服务端 + 数据报分块）

$ lab/proto-check/run.sh vmess tls                    # 真实 Go 客户端
ok  github.com/daeuniverse/dae/protocheck
PROTO-CHECK vmess/tls: PASS
```

P5-G3a QUIC（tuic v5；对端是 Go/quic-go 独立参考服务端）：

```console
$ lab/lab.sh tuic-up && lab/lab.sh test-tuic
wan-echo-ok data=ping
stream-ok bytes=524288 prefix=wan-echo-ok data=start
tuic tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0
PASS: tuic v5 TCP（Go/quic-go 参考服务端 + QUIC 流 + offload 互斥）
# 参考服务端日志：TCP target=1.1.1.1:8080

$ lab/lab.sh tuic-udp-up && lab/lab.sh test-tuic-udp
summary=3/3
tuic udp: sessions=1/1 proxied=1 fallback=0
PASS: tuic v5 UDP（QUIC DATAGRAM + 分片重组）
# 参考服务端日志：UDP target=2.2.2.2:9998
```

P5-G3b QUIC（hysteria2；对端是 Go/http3 独立参考服务端，含 h3 认证）：

```console
$ lab/lab.sh hy2-up && lab/lab.sh test-hy2
wan-echo-ok data=ping
stream-ok bytes=524288 prefix=wan-echo-ok data=start
hy2 tcp: conns=2 bytes_up=524299 bytes_down=524333 offloaded=0
PASS: hysteria2 TCP（Go/http3 参考服务端 + QUIC 流 + HTTP/3 认证）
# 参考服务端日志：AUTH-OK / TCP target=1.1.1.1:8080

$ lab/lab.sh hy2-udp-up && lab/lab.sh test-hy2-udp
summary=3/3
hy2 udp: sessions=1/1 proxied=1 fallback=0
PASS: hysteria2 UDP（QUIC DATAGRAM + 分片重组）
# 参考服务端日志：UDP target=2.2.2.2:9998
```

P5-G3b+（hysteria2 能力补齐；对端仍是 Go 参考服务端，新增混淆/多端口）：

```console
$ lab/lab.sh hy2-obfs-up && lab/lab.sh test-hy2-obfs
wan-echo-ok data=ping
stream-ok bytes=524288 prefix=wan-echo-ok data=start
hy2 obfs tcp: conns=2 bytes_up=524299 bytes_down=524333
PASS: hysteria2 + salamander（跨实现，服务端日志确认混淆开启）
$ lab/lab.sh test-hy2-brutal
stream-ok bytes=524288 prefix=wan-echo-ok data=start
hy2 brutal tcp: conns=1 bytes_up=524294
PASS: hysteria2 cc_override=brutal（固定窗口近似，流量正确）
$ lab/lab.sh hy2-hop-up && lab/lab.sh test-hy2-hop
stream-ok bytes=524288 prefix=wan-echo-ok data=start
stream-ok bytes=524288 prefix=wan-echo-ok data=start
hy2 hop tcp: conns=2 bytes_up=1048588（跨 1 次跳端口）
PASS: hysteria2 udphop（5s 跳端口，QUIC 连接跨跳存活）
```

P6 运维面（`ops-up` / `ops-reload-up` 会话）：

```console
$ lab/lab.sh ops-up && lab/lab.sh test-ops
ops: suspended=true（no-load）
ops: reload ok, match_sets=9 slot=0
ops: reload 后 suspended=false, reload.ok=true
ops: metrics 文本导出正常（42 行）
ops: sysdump 可解析（keys=config,generated_at_sec,maps,rules,status,system）
ops: 日志轮转OK（旧 -> /tmp/sodama-ops.log.1，新文件含重载记录）
PASS: 运维面（suspend/reload/metrics/sysdump/轮转）

$ lab/lab.sh ops-reload-up && lab/lab.sh test-config-reload
config-reload: 规则变更生效 slot=0
config-reload: 损坏配置 reload 失败（rollback）: 解析配置失败:
config-reload: 失败后旧规则保留（8080 仍直连）
config-reload: DNS 上游已切换 -> 127.0.0.1:59999
config-reload: 上游切回 5353，解析恢复
PASS: 整配置热重载（变更生效 / 失败回滚 / DNS 上游热切换）
```

标准拓扑钩子（K1）：

```
attached sodama_lan_ingress      to landae (Ingress)
attached sodama_wan_egress       to wan    (Egress)
attached sodama_wan_ingress      to wan    (Ingress)
attached sodama0_ingress     to dae0   (Ingress)
attached sodama0peer_ingress to dae0peer (Ingress，在 daens)
```

单臂拓扑钩子（两个合用程序）：

```
single(9) tcx/ingress sodama_wan_lan_ingress
single(9) tcx/egress  sodama_lan_wan_egress
dae0(11) tcx/ingress  sodama0_ingress
```

规则 dump（节选，编码与 dae 一致）：

```
compiled 9 match_sets, 3 lpm tries
[ 0] type=IpSet        not=0 outbound=0xff mark=0x0   must=0 lpm_index=0
[ 1] type=Port         not=0 outbound=0x02 mark=0x0   must=0 port=8080-8080
[ 4] type=Port         not=1 outbound=0xff mark=0x0   must=0 port=9999-9999
[ 6] type=L4Proto      not=0 outbound=0xff mark=0x800 must=1 mask=0x1
lpm[0]: 1.1.1.1/32   lpm[2]: 10.9.9.0/24, 10.9.10.0/24   lpm[5]: 10.0.0.0/24
```

热重载证据（`test-reload`）：

```
reply1: sodama tproxy: orig_dst=1.1.1.1:8080 peer=10.0.0.2:57854
one
reply2: sodama tproxy: orig_dst=1.1.1.1:8080 peer=10.0.0.2:57854
two
PASS: 在途连接保持旧判决，新连接按新规则处理
[sodama] rules reloaded: 9 match_sets -> slot 1 (was 0)
bpf_trace_printk: sodama: cached outbound=0x2 dport=8080
```

单写者证据（`test-rebind`）：把 redirect_track 条目伪造成竞争发布者（新鲜），
在途连接的下一个包触发发布时被拒；把条目改为陈旧后允许改绑，回程恢复：

```
PASS 1/2: 竞争发布者被拒（rebind_rejected 120 → 125，绑定保持）
-- 探针输出 --
local=10.0.0.2:41324
echo1: sodama tproxy: orig_dst=1.1.1.1:8080 peer=10.0.0.2:41324
one
echo2: (no echo)          # 绑定被劫持期间回程送到错误 MAC
echo3: sodama tproxy: orig_dst=1.1.1.1:8080 peer=10.0.0.2:41324
two                       # 陈旧窗口改绑后，重传与新数据都恢复
three
PASS 2/2: 陈旧窗口允许改绑，回程路径恢复（echo3 到达）
```

规则编译对拍（`lab/parity.sh`，dae 原版 Go 编译器 vs sodama Rust 编译器）：

```
PARITY rules.dae: PASS（9 行，逐字节一致）
PARITY rules.reload.dae: PASS（9 行，逐字节一致）
```

内核矩阵（`lab/matrix.sh`，详见 [lab/matrix/SUMMARY.md](./lab/matrix/SUMMARY.md)）：

```
MATRIX-RESULT kernel=6.18.54-2-lts verify=PASS   # 宿主内核
MATRIX-RESULT kernel=7.2.8-arch1-2 verify=PASS   # QEMU 引导的第二内核
```

K3（全量配置解析 + 状态面 + 过渡一跳）：

```console
$ target/release/sodama validate lab/real-user.dae
sections: global / subscription / node / group / dns / routing
OK: schema 校验通过
routing: 6 条可编译, 1 条 deferred
  deferred lab/real-user.dae:65: dip(geoip: cn) -> direct — 带 key 的参数（如 geoip:cn）需要 geodata/域名数据，数据面暂未接入

# dae 官方 example.dae（chmod 640 后）：schema 通过；6 条规则 -> 1 可编译 / 5 deferred（pname/IPv6/geoip/geosite）

$ lab/lab.sh config-up && lab/lab.sh test-config && lab/lab.sh test-status
config: supported=6 deferred=1 fallback=proxy
PASS: 全量配置解析、子集编译、deferred 显式上报
status: rules=12 conn_state=2 hooks=5 rebind_rejected=0
PASS: 只读状态面可用，且拒绝非查询命令

$ lab/lab.sh dns-up && lab/lab.sh test-domain
answer=10.9.10.3 / answer=10.9.10.4
sodama tproxy: orig_dst=10.9.10.3:9999    # proxy.test → domain 规则
wan-echo-ok data=ping                       # direct.test → 内核直转
dns: queries=2 published_ips=2 domain_routing_entries=2
PASS: 域位图端到端（DNS 接管 → 位图 → domain 规则分流）

$ lab/lab.sh forward-up && lab/lab.sh test-forward
--- 客户端收到 ---
socks5-backend: target=1.1.1.1:8080
PASS: orig_dst 经 SOCKS5 一跳完整保留
```

外层 map 结构（`bpftool map dump name lpm_array_map`）：

```
key: 00 00 00 00  inner_map_id: 148     # match_set[0] 的 1.1.1.1/32
key: 02 00 00 00  inner_map_id: 149     # match_set[2] 的两个 /24
key: 05 00 00 00  inner_map_id: 150     # match_set[5] 的 10.0.0.0/24
```

P7（剖面 / soak / 静态发布；口径：perf 不可用，墙钟 + counters + `/proc`）：

```console
$ lab/bench.sh all
路径          吞吐Mbps  p50µs  p99µs  丢包   cpu_ms  ms/GB  rss_kB  up_MB  down_MB  offload  conns
direct         31116.6     10     25     -     0.0      -   24672    0.0      0.0        0      0
relay          24713.2     17    142     -   120.0  447.0   26976  128.0    128.0        0      5
offload        14564.8     23    107     -   230.0      -   27124    0.8      0.1        5      5
ss              2497.0     55    213     -   340.0 1266.6   26188  128.0    128.0        0      5
udp-direct        16.9      8     22 11262     0.0      -   25596    0.0      0.0        0      0
udp-nat           16.7     15     68 11248   100.0      -   24024    0.0      0.0        0      0
# direct=内核直转基线；relay=用户态泵；offload=内核对拼（用户态≈零，吞吐低于 relay 如实记录）；
# ss=协议栈；UDP 的 blast 列被端点丢包主导，只作相对参考（RTT 列为准）

$ lab/soak.sh run 60 tcp
iter 870: ok=1 rss=25776kB fds=36 active=0 fast_sock=0 udp_active=0
PASS: soak 60s（tcp）无失败轮、无泄漏（RSS +368kB，fd +0，...）
# 60s 含 435 次 reload + 290 次 suspend/resume；ss 30s +440kB；udp 的 RSS 增长为 glibc
# arena 保留（MALLOC_ARENA_MAX=1 下 +7.9MB），fd 回基线，脚本注明并放宽到 48MB

$ lab/build-static.sh
-- file --  ... static-pie linked ...   -- ldd --  statically linked
$ SMOKE_ALPINE=1 lab/build-static.sh
OK: schema 校验通过 / routing: 6 条可编译, 1 条 deferred   # redis:7-alpine 内
```

P8（数据面 Rust 迁移起步：offload 垂直切片；历史——双对象机制已随 C 对象移除，环境细节见 NOTES §11.13 / ADR-0023）：

```console
$ lab/build-ebpf-rs.sh
== cargo +nightly: ebpf-rs（bpfel-unknown-none / build-std=core）==
    Finished `release` profile [optimized] target(s)
-rw-r--r-- 2184 .../ebpf-rs/target/bpfel-unknown-none/release/sodama-ebpf（当时的切片对象）
```

P9/P9+（数据面全量 Rust 化 → 移除 C 数据面；下列全量回归在唯一 Rust 对象上完成）：

```console
$ lab/lab.sh build && sudo lab/lab.sh up && sudo lab/lab.sh verify
== cargo +nightly: Rust eBPF 对象（唯一数据面）==
proxy/direct/block/host/reload/rebind/status/fault: 9×PASS（标准拓扑）
# 单臂：sudo lab/lab.sh dual-up && sudo lab/lab.sh verify → 同样 9/9
$ cargo test --release
73 passed; 0 failed
$ sudo lab/bench.sh run offload
RESULT offload tcp_mbps=12437.0 lat_p50_us=19 ... offloaded=5 conns=5
$ sudo lab/bench.sh all
路径          吞吐Mbps  p50µs  p99µs  丢包   cpu_ms  ms/GB  rss_kB  up_MB  down_MB  offload  conns
direct         30634.7     10    188     -    10.0      -   24072    0.0      0.0        0      0
relay          23779.6     18    169     -    90.0  335.3   25844  128.0    128.0        0      5
offload         7503.2     24     80     -   240.0      -   26460    3.3      2.2        5      5
ss              2451.8     59    115     -   350.0 1303.8   26452  128.0    128.0        0      5
udp-direct        16.7      8     25 11262     0.0      -   24484    0.0      0.0        0      0
udp-nat           16.7     16     79 11220    90.0      -   25076    0.0      0.0        0      0
# 对照 P7 C 时代：direct 31117/10、relay 24713/17、offload 14565/23、ss 2497/55；
# offload 单次方差大（同对象另有 12437/19µs 与 8286/30µs 两次单跑），量级同档；
# UDP blast 丢包与 C 同数值（11262/11248，端点主导，只作相对参考）
# 数据面即 Rust（日志 loading .../sodama-ebpf）；USE_EBPF_* 分支已删
```

P9+ 完整性回归（2026-10-04，全部在唯一 Rust 对象上；详见 NOTES §11.16）：

```console
# 功能全量：DNS 6/6 · 转发面 6/6 · K3/运维 5/5 · 协议梯 15 会话 17/17（含 vless/vmess TLS 变体）
$ lab/parity.sh lab/rules.udp.dae lab/rules.fault.dae lab/rules.bench.dae
PARITY rules.udp.dae / rules.fault.dae / rules.bench.dae: PASS（逐字节一致）
$ lab/proto-check/run.sh vmess && lab/proto-check/run.sh vmess tls && lab/proto-check/run.sh vless
PROTO-CHECK vmess/none、vmess/tls、vless/none: PASS   # vless/tls 为 P5 已知 Go 客户端 allowInsecure 偏差
$ lab/soak.sh run 60 tcp && lab/soak.sh run 30 ss && lab/soak.sh run 30 udp
PASS: soak tcp 968 轮 RSS +316kB/fd +0 · ss 365 轮 +664kB/fd +0 · udp +32.9MB（arena 保留）
$ lab/matrix.sh run && lab/matrix.sh vm
MATRIX-RESULT kernel=6.18.54-2-lts verify=PASS
MATRIX-RESULT kernel=7.2.8-arch1-2 verify=PASS
# 边界：对拍不覆盖 domain 规则集（Go dump 工具限制）；<5.17/<6.6 内核未真机验证
```

## 与 dae 的对照

| sodama | dae |
|---|---|
| `sodama_route` / `sodama_route_loop_cb` / `route_eval_match` / `route_finalize_match` | `route`(:1944) / `route_loop_cb`(:1891) / `route_eval_match`(:1708) / `route_finalize_match`(:1821) |
| `routing_map` / `routing_meta_map` / `lpm_array_map` | 同名（:355 / :363 / :314） |
| `match_set` / `lpm_key` 布局与枚举值 | 同名（:337 / :298）；枚举取 `common/consts/ebpf_sync_defs.h` |
| `SodaMatchSet` 的 outbound 编码（OR/AND/Direct/Block/ControlPlane） | `common/consts/ebpf_generated.go` |
| `sodama_lan_ingress` | `tproxy_lan_ingress_role`（:2900） |
| `sodama0peer_ingress` / `sodama0_ingress` | `tproxy_dae0peer_ingress`（:3870）/ `tproxy_dae0_ingress`（:4030） |
| `sodama_wan_egress` / `sodama_wan_ingress` | `do_tproxy_wan_egress`（:3787）/ `do_tproxy_wan_ingress`（:3329） |
| `sodama_wan_lan_ingress` / `sodama_lan_wan_egress` | `do_tproxy_wan_lan_ingress`（:3370）/ `do_tproxy_lan_wan_egress`（:3841） |
| 双 epoch 槽 + `active_routing_epoch_map` | `tproxy.c:71/371`；热重载不重挂钩子 |
| `conn_state` 缓存与非 SYN 直读 | `conn_state_map`（:504）、`mark_tcp_seen`（:2735） |
| `sodama_conn_lookup` 的到期判定 | `udp_conn_state_expired`（:2337） |
| janitor 清理 | `control/conn_state_janitor.go` |
| `sodama_publish_redirect_track` 单写者 | `publish_redirect_track_for_packet`（:2196），陈旧窗口 `REDIRECT_REBIND_STALE_NS_FALLBACK`（:85） |
| `reply_publisher_matches` 续租约束 | 同名（:4000/4045-4055） |
| `sodama_stats_map`（rebind 拒绝 / update 失败计数） | `bpf_stats_map`（:539）的子集 |
| `config_map` | `struct dae_param`（:214）+ `dae_ifindex_map`（:241） |
| `lab/rules.dae` + `rules.rs` | `.dae` 路由规则 + `routing_matcher_builder.go`（子集，已逐字节对拍） |
| `lab.sh` / `gateway.sh` 里 daens 的路由 | `control/netns_utils.go:871 setupIPv4Datapath` / `setupIPv6Datapath`（P16；含静态 fe80 邻居） |
| `lab.sh` 里 fwmark/local 规则 | `control/netns_utils.go:560 setupRoutingPolicy`（同 `tproxy.c:2904` 注释） |
| `config.rs` 全量解析 + include + schema | `pkg/config_parser` + `config/config_merger.go` + `config/parser.go`（错误语义已对齐） |
| `sodama_route_match_domain_set` / `domain_routing_map` / `rules.rs` 的 domain 编译 | `route_match_domain_set`（`tproxy.c:1673`）/ `domain_routing_map`（:388）/ `routing_matcher_builder.go addDomain`（:375） |
| `loader/src/dns.rs` + `dns_loop`（透明 UDP 接管） | `control/control_plane.go` + `dnsmasq`/DNS 向上游转发链（P3a 为最小形态） |
| 只读状态面（Unix socket JSON） | ——（dae 无对应形态；daed GraphQL 不在本范围） |
| `--dialer socks5://…`（过渡一跳；`--forward` 旧写法） | 过渡形态（ADR-0011/0015） |
| `loader/src/ss.rs`（classic AEAD，TCP/UDP） | `component/outbound/shadowsocks`（dae 走 Go 库；sodama 为纯 Rust SIP004） |
| `loader/src/trojan.rs`（rustls + CONNECT） | `component/outbound/trojan` + `daeuniverse/outbound`（同上，纯 Rust） |
| `loader/src/vless.rs` / `vmess.rs` | `protocol/vless` / `protocol/vmess`（olicesx/outbound；wire 规格从该实现读出，见 ADR-0017） |
| `lab/proto-check/`（Go 客户端 ↔ Python 服务端） | 用 dae 自己依赖的 outbound 客户端做生态兼容交叉验证 |
| `loader/src/tuic.rs`（tokio/quinn） | `protocol/tuic`（olicesx/outbound，quic-go；wire 规格见 `docs/modules/tuic-v5-client-spec.md`） |
| `lab/proto-check/tuic-server`（Go/quic-go） | 独立的 TUIC v5 服务端实现，做跨实现验收 |
| `loader/src/hysteria2.rs` / `hpack.rs`（tokio/quinn + 手写 h3） | `protocol/hysteria2`（olicesx/outbound，quic-go + http3）；Brutal/salamander 已在 P5-G3b+ 补齐（见 ADR-0020） |
| `lab/proto-check/hy2-server`（Go/http3） | 独立的 hysteria2 服务端实现，做跨实现验收 |
| `Outbound::supports_offload()` / `supports_udp()` | dae 的协议能力描述（sodama 把互斥/回退写成显式判定 + 计数） |

## 尚未复现（后续）

数据面：DNS 嗅探 punt（`ROUTE_STATE_DNS_QUERY` 强制控制面路径）、事件 ringbuf、
IPv6 剩余项（UDP v6/DNS over UDP6 接管、ICMPv6/分片）；P17 剩余：pname argv basename（CO-RE）、
geodata XDG 搜索目录/流式解析、geosite 负载入对拍。
转发面：offload 的 backlog fuse / tcp_info 精确计费 / SK_PASS 用户态回退协调（ADR-0022 已补：
（ADR-0022 已补：半关闭超时看门狗、fast_sock 键注销、注册前排空队列；已 offload 的连接可回收）；UDP 跨目标
full-cone；嗅探的剩余形态（QUIC/UDP 域名拨号；TLS/HTTP1/h2c/QUIC-SNI + sniff-punt 已做，见 ADR-0030/0044/0045）；relay 并发上限。
节点生态剩余（ADR-0031）：按规则分派不同组（数据面 outbound id）、订阅热更新（update_interval）、
`add_latency`/`region`/`udp_check_dns`/多 check URL、gzip 压缩订阅。
协议栈（P5-G3b+ 后的剩余）：hysteria2 的 gecko 混淆、pinSHA256/ECH/自定义 CA、QPACK 动态表
（当前只支持静态表）；udphop 只支持链接扩展 interval（dae 是全局配置）；Brutal 是近似
（无 pacer 直接控制，见 ADR-0020）；vmess aid≠0/CFB/packetaddr、vless vision/XUDP/reality、
uTLS 指纹；tuic 的 0-RTT/连接迁移/`udp_relay_mode=quic`/重连状态机、多用户配置与密码表。
运维面（P6 后的剩余）：daed GraphQL/鉴权 API、`suspend --abort`、systemd/打包集成、
日志分级与多后端、OTLP 等其他导出格式（见 ADR-0021）。
DNS 侧的 P3b-2 剩余：DoH/DoQ、嗅探 punt、`dns.routing` 请求/应答分流、ECS 等 options
分区缓存、乐观缓存。
另有未覆盖的内核路径：<6.6 的 netlink 附加、<5.17 的加载失败诊断
（见 `lab/matrix/SUMMARY.md`）。

状态面为查询 + 控制（status/rules/config/maps/metrics/reload/suspend/resume），无 daed
兼容 API 与鉴权（ADR-0021）；拨号器从 host ns 拨号（不再是 daens）；SOCKS5 只支持无认证
CONNECT；ss 不支持插件与 2022 版；trojan 不支持 UDP 与域名目标。

## 容易踩的坑（都是实测踩出来的）

1. **tproxy 回包路由**：回包源地址是原始目的地址（非本机地址），daens 里光有
   `default dev dae0peer` 会 `Network is unreachable`。必须照 dae 配：
   dae0peer 地址 `169.254.0.11/32` + 默认路由 `via 169.254.0.1` +
   静态邻居（`169.254.0.1` → dae0 的 MAC）+ `accept_local=1`。
2. **换 netns 后不要信 `/sys/class/net`**：sysfs 视图跟随挂载点而不是当前 netns
   （`ip netns exec` 会帮你重挂，直接 `setns` 不会）。取 MAC 用
   `SIOCGIFHWADDR` 或 netlink。
3. **BPF map 名在内核里截断到 15 字符**：`domain_routing_map` 实际叫
   `domain_routing_`，`bpftool map dump name domain_routing_map` 会报
   `can't parse name`——按 `bpftool map list` 拿到的 id dump，或直接用截断名
   （aya 按 ELF 名解析，不受影响）。
4. **relay/上游 socket 必须打 `SO_MARK`（0x233）**：数据面 `sodama_wan_egress` /
   `sodama_lan_ingress` 见到 mark 直接放行；否则 host ns 出去的目标连接（或 DNS 上游、
   UDP NAT 上行）会被自己的规则再抓一次，形成回环。`rules.udp.dae` 用「所有 UDP:9998
   都判 proxy」正面验证了这一点。
5. **offload 的两个实现坑**：① `skb->remote_ip4/local_ip4` 在 sk_skb 上下文是主机字节
   序，写进 `__be32` 后内存里是「IP 字节按序」，Rust 侧构造 sockhash 键要用
   `from_ne_bytes`（端口用 `to_be()`）；② psock 接管后用户态 `read` 会返回 EAGAIN，
   泵必须当「驻留重试」而不是断连，否则会拆掉正在被内核拼接的连接。另：sockhash 无法
   用 bpftool 枚举（`map dump` 显示 0 条），观测靠 verdict/redirect 计数与用户态字节数。
6. **ss/trojan 的对端也要打 `SO_MARK`**：`ss_server.py` / `trojan_server.py` 从 host ns
   连真实目标，若不打标会被 sodama 的 `wan_egress` 二次捕获——表现为 RELAY 连接
   疯狂新建、客户端超时。
7. **ss 单块明文上限 0x3FFF**：TCP 两端都要按上限切块；服务端把一次 `recv(65536)` 的
   整块加密会直接超出 2 字节长度字段（实踩：`struct.error: 'H' format requires
   0 <= number <= 65535`）。
8. **rustls 的明文缓冲默认只有 16KB**（`DEFAULT_RECEIVED_PLAINTEXT_LIMIT`）：TLS 读
   路径必须保证「两次 `read_tls` 之间先抽干 `reader()` 明文」，否则大流量下 deframer
   缓冲打满、`read_tls` 报错被当成致命错误拆连接（实测 512KB 必现）。`tls.rs` 用
   pending 密文缓冲 + 一次喂一块解决（trojan/vless/vmess 共用）。
9. **lab 里 UDP 回包源地址不是 orig_dst**：tproxy 会把回包源恢复成 `10.9.9.2`，Python
   服务端用 `connect()` 的 UDP socket 会按对端过滤丢包——用 `sendto/recvfrom`；
   `lab/udp_mark_probe.py` 可复现两种写法差异（ss 服务端一直是非 connect 写法，所以
   G1 没暴露）。
10. **vmess 块解析的顺序与状态**：SHAKE128 先抽 padding 再抽 mask；解析出的块头
    （size/padding）必须跨「数据没到齐」的调用保留，否则长度解释错位（大流量必现）。
    终止块要连同其 tag+padding 一起消费，保持流位置精确。
11. **Go 客户端链接层的两个已知偏差**：`vless://` 忽略 `allowInsecure`（自签 TLS 会
    x509 失败）、`vmess://` 忽略 `scy`（恒用 aes-128-gcm）；proto-check 因此对 vless
    只测明文、vmess 测 none/tls+aes，Rust 侧仍支持 chacha 与 TLS（lab e2e 覆盖）。
12. **QUIC 的 datagram 能力必须双向显式开启**：quinn 侧要设 `datagram_receive_buffer_size`
    （它决定对外广播的 `max_datagram_frame_size`），否则 Go 参考服务端回包直接报
    `DATAGRAM frame too large`；服务端回包也要按 `DatagramTooLargeError.MaxDataLen` 分片。
13. **Go 参考服务端的日志 fd 是启动时打开的**：lab 测试里要截断（`:`>`）而不是 `rm`，
    否则日志写入未链接的 inode，路径上永远看不到。
14. **SO_MARK 三处实现都要 best-effort**（Rust/Go/Python）：非 root 时降级告警，
    否则本机 `cargo test` 的跨实现单测会因 EPERM 全挂（lab 以 root 运行，不受影响）。
15. **QPACK 的 “literal name” 形式里 bit3 也是 H 标志**（`001N Hxxx`）：quic-go 用它编码
    不在静态表中的名字（`hysteria-udp` 等，HPACK Huffman）；只按 3 位前缀读裸名字会直接
    UTF-8 失败（实踩：`非 UTF-8 名字: invalid utf-8 sequence of 1 bytes from index 0`）。
16. **hysteria2 服务端的 HTTP/3 层绝不能声明 `H3_DATAGRAM`**（`EnableDatagrams: false`，
    只开 QUIC 层 datagram）：quic-go 的 h3 客户端一看到就会启动 receiveDatagrams 循环，
    把 UDP relay 的裸 datagram 吃掉。
17. **quinn endpoint driver 不会自动轮询新 socket**（udphop 的致命坑）：`poll_recv` 返回 Pending
    后，driver 只等**已注册的 waker**——跳端口新建的 socket 永远不会被读到（症状：一跳之后
    完全收不到回包，直到 idle 超时）。修法：保存驱动传入的 recv waker，新增 socket 后主动
    `wake()`，driver 会重新对全部 socket 注册（`quicsock.rs::recv_waker`）。
18. **udphop 的 5s 最小间隔是可用性边界**：300ms 快速跳端口实测会因服务端地址在多个旧四元组
    间回退而失速（QUIC 重传风暴）；5s 间隔下连接跨跳存活（Go 侧同样强制 ≥5s）。
19. **状态面客户端要读到 EOF**：`metrics` 是多行 Prometheus 文本，按行读只会拿到第一行
    （P6 实测：metrics 只输出 `# TYPE sodama_uptime_seconds`）。
20. **0640 配置权限校验对测试夹具同样生效**：`--config` 会拒绝 0644 文件；lab 把模板复制到
    /tmp 后必须 `chmod 640`（每次 `sed -i` 后重建文件时也要）。
21. **offload 下不要用用户态向对端传播 FIN**：RDHUP 时时仍有排队数据在重定向路径上，
    `shutdown(SHUT_WR)` 会截断它们（C 基准实测 32MB 流只剩 0.3–17MB）。用“两侧 RDHUP
    干净退出 / 单侧 10s 超时强制关闭”的看门狗（dae `relayHalfCloseTimeout` 同义）。
22. **不要给 `sk_skb` verdict 加 `skb->len==0 → SK_PASS` 特殊分支**：实测会让 psock 吃掉 EOF
    并停滞在途数据（10s 只走 MB 级）；保持与 dae 相同，不特殊处理。
23. **FIN 重定向尝试留下的 `POLLERR` 是常态**：传输中按它 force-close 会切断全部在途数据；
    只有“无 RDHUP 的 ERR/HUP”才当错误。
24. **sockmap 条目持有 socket 引用，必须注销**：offload 连接终结后不删 `fast_sock` 键，
    socket 与 map 条目一起泄漏（soak 直接涨 fd）；状态面 `maps.fast_sock` 因 map 已被
    `take_map` 移出 `Ebpf`，计数要从 `RELAY_OFFLOAD` 里取。
25. **Nagle + 延迟 ACK 能藏出 40ms**：ss/trojan 等“帧头 + 载荷”多次小写会中招（ss ping-pong
    p50=43.3ms）；出站 `marked_tcp_connect` 与 tproxy accept 都要 `TCP_NODELAY`。
26. **metrics 客户端要读到 EOF，调用方也别提前关管道**：`metrics | awk '… exit'` 会给客户端
    EPIPE panic；先完整取回输出再过滤。
27. **udp soak 的 RSS 增长先看是不是 glibc arena 保留**：会话/线程 churn 下默认可攀到
    +30MB，`MALLOC_ARENA_MAX=1` 降到 +7.9MB 且 fd 回基线；不要把它误当逻辑泄漏。
28. **`verify` 的 rebind 对时序敏感**：并行跑其他负载时出现过一次抖动（单跑必过）；
    回归应串行执行。
29. **WS 握手响应头要按“扫描进度”搜索，不能每轮从尾回退 3 字节**：`\r\n\r\n`
    可能跨两次 read 到达；首版实现因此在真实节点上报“握手响应中途关闭”（ADR-0026）。
30. **验收真实节点先跟参照客户端对拍**：节点对目标可达性自身有策略（实测部分目标被
    节点侧黑洞，v2ray 与 sodama 失败模式一致）；否则会把节点问题误判为实现 bug。
31. **AnyTLS 首包必须 Settings+SYN+PSH(目标) 一次写**：目标地址在首条 PSH 里（不在 SYN），
    pkt1 的 padding 只作用于这一批；拆开写会与真实客户端特征不一致。
32. **AnyTLS pkt1 的尾部 waste 帧长度随机**：mock/测试里读尾帧要用短超时探测，
    不能无条件 read；另 UpdatePaddingScheme 只影响**下一次写**（已用定长 scheme 钉住）。
33. **真网关规则不能有 `sip(...)`**：宿主机模式的流量源地址就是本机私网地址，
    `sip(192.168.0.0/16) -> direct` 会把全部出站 TCP 判成直连（症状：TCP 被墙/超时，
    而 DNS 因数据面 DNS override 仍进控制面，很容易误判“已跑通”）。见 `lab/rules.gateway.dae` 头部。
34. **网关模式 DNS 直连要 `direct(must)` 且置顶**：`route.rs` 对任何命中的非 must 规则会自动把
    53 端口改送控制面 DNS 模块；且缺省上游 `8.8.8.8:53` 在受限网络不可达。
35. **真网关不必移动网卡**：`--lan none --wan wlan0` 即可（复用 `test-host-proxy` 路径）；
    移动网卡会闪断且惊扰 NetworkManager。status/日志输出对 `--dialer`（含凭据）要 redact。
36. **dial_mode 嗅探是 MSG_PEEK（只读）**：不消费字节才能不破坏后续泵；嗅探失败/超时必须回退 IP。
    `domain` 只在客户端首包是 TLS/HTTP/1.x 时命中（h2c/QUIC/二进制协议一律 IP）；
    客户端给域名的 SOCKS 入口在 domain 模式下不做本地解析，直交节点。
37. **健康探测的 dial 失败也必须记账**：`probe` 里拨号失败曾走 `?` 提前返回、不计入失败，
    后果是死节点永远不被标死（lab 回归：kill A 后 alive 仍 2/2；修复后 4s 内标死）。
    另：订阅 URL 主机双栈时也会 AAAA 优先，拉取路径已改为**优先 IPv4**（同 P12 的 resolve 修订）。

## Rust 化的边界

- 控制面/加载器：aya 已验证可用（本项目即是），TCX 让生命周期管理比 netlink 干净。
- map-in-map：aya 0.14 支持 `ArrayOfMaps` + 独立创建 `LpmTrie` 后 `set()` 插入；
  内层 map 的属性必须与外层对象 BTF 模板一致（type/flags/key/value/max_entries）。
- **eBPF 程序本身：已完成全量 Rust 化（P9，ADR-0024），且 C 对象已移除（P9+，ADR-0025）**——
  `ebpf-rs/`（nightly + `-Z build-std=core` 构建 `bpfel-unknown-none`，bpf-linker + BTF）
  是唯一数据面；两个边界：① `bpf_loop` 不可用（aya-obj 的 PSEUDO_FUNC relocation 缺口），
  规则 VM 用有界循环；② 仍需 `debug = 2` 才能让 bpf-linker 产出 `.BTF`。
  需要 C 对照时从 `dae/` 重建 C 对象并临时切换 `--ebpf`（调试手段，非常规路径）。
- **真实订阅形态（2026-10-04 普查/更新；2026-10-08 修订）**：主流节点形态与我们的实现状态——
  vless-ws ✅（ADR-0026）、**anytls ✅**（ADR-0027，单 Stream、无 UDP/会话复用）、
  **vless+REALITY+Vision ✅**（P18d/P24，ADR-0041/0048；自实现最小 TLS 1.3 +
  ClientHello 对 uTLS Chrome-120 逐项对齐，真机 48 条 REALITY 全健康）——本行原为
  历史边界描述，已于 2026-10-08 修正。边界外协议过渡期可用 SOCKS5 桥接：
  `--dialer socks5://127.0.0.1:<sing-box/mihomo 的 socks 端口>`（所有协议立即可用）。

分域覆盖度对照（与 dae 原版逐项对标，含 Top 缺口与优先级）见
[`docs/parity-status.md`](../docs/parity-status.md)（主文档 HTML 第 10 节同源）。

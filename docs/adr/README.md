# 架构决策记录（ADR）

## 这是什么

每一条无法从代码本身推断、且会影响后续大量实现的决策，在这里留一份记录：背景、选项、决定、后果、验证方式。目的是**半年后回看时，知道当时为什么这么定，以及什么条件下应该推翻它**。

主文档：[`../architecture-decision.html`](../architecture-decision.html)（决策点 D1–D8 的交互卡片）。

## 状态机

| 状态 | 含义 |
|---|---|
| 提议 | 已写出，未拍板 |
| **已采纳** | 当前工作基线，实现应对齐 |
| 被取代 | 由更新的 ADR 取代（保留原文，标出取代者） |
| 废弃 | 不再适用（例如上游能力变化），保留原文 |

修订规则：**不修改已采纳 ADR 的结论**，而是新写一条 `ADR-XXXX` 取代它，并在两条之间互链。

## 编号与命名

`ADR-NNNN-短横线小写标题.md`，四位递增，永不复用。

## 索引

| 编号 | 标题 | 状态 | 对应决策点 |
|---|---|---|---|
| [0001](./ADR-0001-scope-and-fidelity.md) | 目标定位：生产质量、分批交付 | 已采纳 | D1 |
| [0002](./ADR-0002-ebpf-program-language.md) | eBPF 程序语言：先 C 后迁 | 已采纳 | D2 |
| [0003](./ADR-0003-userspace-runtime.md) | 用户态运行时：tokio 起步 | 已采纳 | D3 |
| [0004](./ADR-0004-outbound-protocol-strategy.md) | outbound 协议栈：Dialer trait + 梯度推进 | 已采纳 | D4 |
| [0005](./ADR-0005-config-compatibility.md) | 配置：100% 兼容 .dae，语法收回仓库 | 已采纳 | D5 |
| [0006](./ADR-0006-delivery-scope.md) | 交付范围：只做 dae 本体 | 已采纳 | D6 |
| [0007](./ADR-0007-priority-order.md) | 优先级：配置 + 路由先行 | **被 0009 取代** | D7 |
| [0008](./ADR-0008-deployment-model.md) | 部署形态：常驻进程 + eBPF 分流，不接管 direct | 已采纳 | D8 |
| [0009](./ADR-0009-kernel-track-first.md) | 优先级（取代 0007）：先做内核切片（K 轨道） | 已采纳 | D7 |
| [0010](./ADR-0010-k2-parity-and-matrix.md) | K2 交付边界：对拍口径与内核矩阵覆盖 | 已采纳 | —（K2 执行） |
| [0011](./ADR-0011-k3-scope-and-boundaries.md) | K3 范围与边界：全量解析、子集编译、只读状态面、过渡一跳 | 已采纳 | —（K3 执行） |
| [0012](./ADR-0012-p3a-dns-and-domain-bitmap.md) | P3a 范围与边界：透明 UDP DNS 接管 + 域位图，domain 规则转可编译 | 已采纳 | —（P3a 执行） |
| [0013](./ADR-0013-p3b1-dns-cache-and-tcp.md) | P3b-1 范围与边界：DNS 正/负缓存（TTL 递减）+ TCP DNS | 已采纳 | —（P3b-1 执行；修订 0012 的缓存/TCP 边界） |
| [0014](./ADR-0014-p3b2a-regex-and-edns.md) | P3b-2a 范围与边界：`domain(regex:)` + EDNS（DO 键/UDP 截断） | 已采纳 | —（P3b-2a 执行；细化 0013 的 EDNS/TTL 边界） |
| [0015](./ADR-0015-p4-forwarding-plane.md) | P4 范围与边界：TCP relay（dialer）、UDP NAT 会话、TCP offload 最小实现 | 已采纳 | —（P4 执行；`--forward` 升级为 dialer） |
| [0016](./ADR-0016-p5-g1-protocol-stack.md) | P5 G1 范围与边界：shadowsocks classic AEAD + trojan（跨实现验收、协议/offload 互斥） | 已采纳 | —（P5-G1 执行；接 ADR-0004 的协议梯度） |
| [0017](./ADR-0017-p5-g2-vless-vmess.md) | P5 G2 范围与边界：vless（TCP/UDP）+ vmess（AEAD，aid=0）；三方交叉验收 | 已采纳 | —（P5-G2 执行；UDP 会话拨号不再持锁） |
| [0018](./ADR-0018-p5-g3-quic-tuic.md) | P5 G3 范围与边界：tuic v5（QUIC，TCP+UDP）落地；hysteria2 归 G3b | 已采纳 | —（P5-G3a 执行；引入 tokio/quinn 运行时） |
| [0019](./ADR-0019-p5-g3b-hysteria2.md) | P5 G3b 执行：hysteria2（QUIC + 最小 HTTP/3 认证；Brutal/混淆不做） | 已采纳 | —（P5-G3b 执行；HPACK Huffman/QPACK 共享件） |
| [0020](./ADR-0020-p5-g3bplus-hysteria2-extras.md) | P5 G3b+ 执行：salamander 混淆、Brutal 近似、udphop（取代 0019 的三项边界） | 已采纳 | —（P5-G3b+ 执行；异步 socket 中间件） |
| [0021](./ADR-0021-p6-ops-surface.md) | P6 运维面：信号/控制命令、指标导出、日志轮转、整配置热重载（回滚 + DNS 上游切换） | 已采纳 | —（P6 执行；状态面由只读扩展为可控） |
| [0022](./ADR-0022-p7-convergence.md) | P7 收敛：剖面口径（无 perf）、offload 生命周期修复、soak、静态发布（crt-static） | 已采纳 | —（P7 执行；补强 0015 的 offload 边界） |
| [0023](./ADR-0023-p8-dataplane-rust-migration.md) | P8 数据面 Rust 迁移（起步）：offload 垂直切片、双对象共存、guard 镜像、镜像工具链 | 已采纳 | —（P8 执行；启动 0002 的“后迁”） |
| [0024](./ADR-0024-p9-dataplane-full-rust.md) | P9 数据面全量 Rust 化：8 程序/14 map 全量移植、默认切换（USE_EBPF_C 回退）、有界循环替代 bpf_loop | 已采纳 | —（P9 执行；取代 0023 的迁移路线部分） |
| [0025](./ADR-0025-remove-c-datapath.md) | 移除 C 数据面：单一 Rust 对象、删除 USE_EBPF_* 分支与 offload 双对象，回退即重建 | 已采纳 | —（0002 收尾；接 0024 默认切换） |
| [0026](./ADR-0026-vless-ws-transport.md) | VLESS WebSocket 传输：接入真实订阅节点（type=ws + host/path，参考对拍验收） | 已采纳 | —（P10 执行；扩展 0017 的 vless 传输边界） |
| [0027](./ADR-0027-anytls-client.md) | AnyTLS 客户端：anytls-go v2 子集（paddingScheme 逐字节对齐、单 Stream）+ `--dial-timeout` | 已采纳 | —（P11 执行；第二个真实订阅） |
| [0028](./ADR-0028-socks-inbound.md) | 本地 SOCKS5 入口（`--listen-socks`）：零 root、零 eBPF，浏览器直接验收真实节点；resolve 优先 IPv4 | 已采纳 | —（P12 执行） |
| [0029](./ADR-0029-host-gateway-mode.md) | 真网关模式（host gateway）：`--lan none` + `lab/gateway.sh`，宿主流量透明接管；DNS `direct(must)`、禁 `sip` 规则、QUIC 阻断 | 已采纳 | —（P13 执行） |
| [0030](./ADR-0030-sniffing-dial-mode.md) | 用户态嗅探 + dial_mode：TLS SNI/HTTP Host（MSG_PEEK）→ 域名交节点远端解析；Target 类型化（逐协议域名 ATYP） | 已采纳 | —（P14 执行） |
| [0031](./ADR-0031-subscription-groups.md) | 订阅 / 节点组 / 健康检查：filter + policy（min/min_moving_avg/min_avg10/random/fixed）+ 探测标死 + 拨号失败切换；数据面仍单代理槽 | 已采纳 | —（P15 执行） |
| [0032](./ADR-0032-p16-ipv6-dataplane.md) | IPv6 数据面（TCP 全链）：16B 统一五元组 + sockmap key 2 + IPV6_TRANSPARENT 双监听 + 协议目标 v6 编码 + 静态 fe80 邻居（NDP 陷阱）；UDP v6/ICMPv6 未做 | 已采纳 | —（P16 执行；对标表缺口 #3） |
| [0033](./ADR-0033-p17-geodata-pname.md) | P17 规则语言收尾：v2ray `.dat` 的 geoip/geosite 编译期展开（attr/ext/搜索目录/2M LPM）+ pname（cgroup2 六钩子 + cookie_pid_map + WAN egress 16B 匹配）；comm vs argv 差异如实 | 已采纳 | —（P17 执行；对标表缺口 #4） |
| [0034](./ADR-0034-p18a-dot-doh-upstream.md) | P18a DNS 安全上游：dnsup 上游抽象 + DoT/DoH 持久连接传输（HTTP/1.1）、`tcp+udp` 语义对齐（UDP 优先 TC 回退，客户端协议不再决定上游）、URL 热切换与状态面；DoQ/H3/`dns.routing` 留下一步 | 已采纳 | —（P18a 执行；对标表缺口 #5） |
| [0035](./ADR-0035-p18b-doq.md) | P18b DoQ（RFC 9250）：quinn 连接复用 + 每查询一条双向流、ID 置 0/恢复、FIN 后读、取消码 0x3；锁中毒恢复 + 单查询 panic 隔离；quic-go 参考服务端交叉验证 + AliDNS 真实 DoQ | 已采纳 | —（P18b 执行；对标表缺口 #5） |
| [0036](./ADR-0036-p18c-dns-routing.md) | P18c `dns.routing` 请求/应答分流 + 多上游：qname/qtype→reject/asis/tag（asis 回客户端原目的，UDP/TCP 两路径）、应答 qname/qtype/upstream/ip→accept/reject/换上游重查（深度 3）；路由先于缓存 + 按上游作用域缓存；dae 链编码/默认 fallback 对齐；sub/node/subnode 以 note 跳过 | 已采纳 | —（P18c 执行；对标表缺口 #5 收尾） |
| [0037](./ADR-0037-dns-file-blocklist.md) | `qname(file:)` 自定义域名名单（mini 扩展：文本名单、默认 suffix、full:/keyword:/regex: 前缀、相对路径按规则文件目录、缺失硬失败）+ `upstream_hits` 分流命中观测；真网关默认国内→本地明文/其余→DoH/名单拦截 | 已采纳 | —（P18c 实用化扩展） |
| [0038](./ADR-0038-dns-ecs-sip.md) | DNS 精细策略（mini 扩展）：上游 URL `ecs=auto|<CIDR>` 注入 ECS（客户端子网，v4/24 v6/56，已带 OPT 透传，缓存按子网分域）+ 请求函数 `sip(...)` 客户端网段路由；真网关国内域 DoH+ECS | 已采纳 | —（P18c 实用化扩展二） |
| [0039](./ADR-0039-dns-response-sip-bench.md) | 应答侧 `sip(...)`（按客户端来源过滤应答）+ `dns-bench` 子命令（用户态、marked socket、同域名跨上游 min/avg/p50/TTL 对比）；真机 router↔DoH↔DoH+ECS A/B | 已采纳 | —（P18c 实用化扩展三） |

## 新增一条 ADR

1. 从上面的编号继续（不要复用）；
2. 至少包含：背景、决策、理由、后果（正/负）、验证方式、相关链接；
3. 若决策被验证/推翻，新写一条并互链，不删旧条。

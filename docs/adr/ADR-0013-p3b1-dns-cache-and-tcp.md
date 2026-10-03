# ADR-0013：P3b-1 范围与边界——DNS 正/负缓存（TTL 递减）+ TCP DNS

- **状态**：已采纳（2026-10-03）
- **对应**：ADR-0009 的 P3（DNS）第二阶段（P3b-1）；修订 ADR-0012 中「无缓存、无 TCP DNS」的边界
- **相关**：ADR-0012（P3a 基础）、ADR-0011（只读状态面/过渡一跳）

## 背景

ADR-0012 给 P3a 划的边界是「只做 UDP、不做缓存/TCP DNS/DoH/DoQ/regex/嗅探 punt」，并把
P3b 的修订条件写了进去。P3b-1 要做前两项（缓存与 TCP DNS）——这也是日常 DNS 流量里最
常见的两个形态：应用先查 UDP、截断或长应答走 TCP。缓存一旦引入，若语义不明确就会出现
比「没有缓存」更难查的行为差异：

1. 命中时的 TTL 该不该递减、question 大小写要不要回填（0x20 随机化）？
2. 负应答（NXDOMAIN/NODATA）缓多久？
3. 热重载后，缓存命中的域名还会不会写进新 epoch 的域位图？（不写 = domain 规则
   在 reload 后静默失效）

TCP DNS 则涉及一个实现事实：accept 发生在 daens，而上游连接必须从 host ns 发出，
否则上游查询会被自己的钩子二次捕获。

## 决策

1. **缓存 key 与寿命**：key =（小写 qname, qtype, qclass）。正缓存寿命 = answer 段最小
   TTL；负缓存（rcode=3 或 NOERROR 且 answer 为空）= `min(SOA.TTL, SOA.MINIMUM)`
   （RFC 2308），无 SOA 时用默认 30s。寿命上限 3600s（到期重查；客户端可见 TTL 仍按
   原值递减）。寿命为 0、TC=1、SERVFAIL/REFUSED 等一律不入缓存。
2. **命中语义**：改写事务 ID 为客户端查询的 ID；若 question 段长度一致且忽略大小写相等，
   按客户端原文回填 question（兼容 0x20 随机化）；answer/authority 段 TTL 按已过秒数
   递减；**additional 段与 OPT 的 TTL 字段不动**（OPT 的 TTL 是扩展 rcode/flags）。
3. **容量与淘汰**：最多 1024 条；插入前先清扫过期条目，仍满则淘汰最旧条目；状态面暴露
   `cache_entries/hits/misses/inserts/evictions/expired`。
4. **命中也要重发域位图**：位图写入是幂等 OR；命中路径同样走 `publish_live`。热重载切换
   epoch 后，主循环用缓存快照重投影新槽（`reconcile_domain_bits`，对照 dae
   `dns_controller_bpf.go reconcileCurrentBpfProjections`）——保证「reload 后客户端不再
   查 DNS，domain 规则仍然有效」。
5. **TCP DNS**：落在 tproxy 的 :53 连接由 accept 线程（daens）经 mpsc 转交给 host ns 的
   `tcp_dns_loop`；上游 TCP 连接在 host ns 建立（走宿主路由，不经自己的钩子）。
   2 字节长度前缀分帧，一条连接可连续处理多条查询（keep-alive），读写超时 5s；
   UDP/TCP 共用同一份缓存与位图发布路径。TCP DNS 优先于 `--forward` 过渡一跳处理
   （DNS 是本地引擎，不交给 SOCKS5 后端）。
6. **状态面**：`dns` 段新增 `tcp_queries/tcp_responses/tcp_unsupported` 与缓存六项；
   `tcp_unsupported` 语义收窄为「TCP DNS 连接无法转交（处理线程未启动/通道关闭）」。
7. **边界（属 P3b-2 或更后）**：DoH/DoQ、`domain(regex:)`、嗅探 punt（`ROUTE_STATE_DNS_QUERY`
   控制面强制）、`dns.routing` 请求/应答分流、EDNS 参数区分（缓存不区分客户端 EDNS
   大小/选项，上游应答原样回给客户端）、乐观/陈旧缓存与预取。AAAA 仍只计数不落位图。
8. **验收口径**：`test-dns-cache`（命中不重查上游、TTL 递减、NODATA 负缓存）、
   `test-dns-tcp`（分帧、缓存、unsupported=0）、`test-dns-reload`（SIGHUP 后新槽位图
   重建且端到端生效）+ 缓存单测；原有 9 用例回归不受影响。

## 理由

- 按 dae 的语义对齐（命中返回剩余寿命、reload 重投影），保证将来对拍时缓存不成为
  行为漂移来源；这两点都有 dae 源码对照（`dns_cache.go`、`dns_controller_bpf.go`）。
- TCP DNS 的「连接转交 + host ns 上游」复用了 P3a 已验证的 netns 事实，不需要在
  daens 里再打一条出向路径，也不引入新配置键。
- 显式列出「不缓存什么」「不动哪些 TTL 字段」，把最容易出错的协议细节固定为契约。

## 后果

- 正面：UDP/TCP 两种 DNS 形态闭环；缓存显著减少上游流量（lab 用假上游计数验证）；
  reload 后 domain 规则不因缓存而失效；状态面让缓存行为可观测。
- 负面/代价：位图发布频率随命中上升（每次命中一次 channel 消息 + map RMW），
  当前规则规模下可忽略，规则数很大时需改为脏标记/批量（记入 P7 优化清单）；
  缓存不区分 EDNS 参数，极端客户端（超小 UDP buffer + 大应答）可能收到超预期报文，
  真实部署需在 P3b-2 一并处理 EDNS 拆分/截断。
- 风险：负缓存默认 30s 可能让上游的短时故障/域名新增延迟可见；可用 `--dns-upstream`
  与状态面观察，必要时按配置暴露 TTL 参数（未做）。

## 验证方式（实测）

- `cargo test --release`：23/23（P3b-1 新增 6 个缓存单测：命中改 ID/递减 TTL、最小 TTL
  过期、SOA 负缓存、SERVFAIL/TC 不入缓存、question 大小写回填、OPT 不动）。
- `lab.sh dns-up && test-dns-cache`：`cache.test` 两次查询上游只 1 次、TTL 30→29；
  `nx.test`（NODATA）两次查询上游只 1 次；状态面 `hits=2 misses=4 entries=4`。
- `lab.sh dns-up && test-dns-tcp`：`--tcp` 两次查询，假上游 `QUERY-TCP` 只 1 次，
  `tcp_queries=2 tcp_responses=2 tcp_unsupported=0`。
- `lab.sh dns-up && test-dns-reload`：SIGHUP 后 active_slot 1→0，bpftool 可见新槽
  `10.9.10.3` 位图重建，且不再查 DNS 直接连 `10.9.10.3:9999` 仍命中 tproxy。
- 回归：标准拓扑 verify 9/9、`config-up + test-config + test-status`、
  `forward-up + test-forward`、`lab/parity.sh` 均通过。

## 修订条件

P3b-2 落地（DoH/DoQ、regex 域规则、嗅探 punt、`dns.routing` 分流、EDNS 区分、
乐观/陈旧缓存）时，新写 ADR 修订本条对边界（第 7 条）的描述；若缓存策略需要暴露配置项
（TTL 上限/负缓存时长/容量），另条记录键名与默认值。位图发布的批量化若在 P7 落地，
需重新评估第 4 条的频率假设。

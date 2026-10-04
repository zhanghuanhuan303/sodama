# dae 核心数据面笔记（eBPF 分流 / tproxy / 回程还原）

这份笔记基于本仓库 clone 的 `dae`（`main` @ `e3fee8f`，tag `nightly`），
行号均指 `dae/control/kern/tproxy.c`（4403 行），除非另注。
所有机制都在本目录的 mini-dae 里被复现并实测（见 README）。

## 0. 一句话概括

dae 在报文进入 TCP/IP 栈之前，用 tc eBPF 程序分流：

- `direct`：不动报文，交给内核三层路由（Real Direct，不经用户态）；
- `proxy`：改写目的 MAC、在 `skb->cb` 里打标记，`bpf_redirect` 进
  `dae0`/`dae0peer` 这对虚拟设备，在 dae netns 里 `bpf_sk_assign` 交付给
  tproxy socket；回程按 `redirect_track` 还原 MAC 后送回原接口。

## 1. 钩子布局

程序入口与其挂载位置（Go 侧：`control/control_plane_core_bind.go`、
`control/bpf_stub.go`）：

| eBPF 程序 | 挂载点 | 作用 |
|---|---|---|
| `tproxy_lan_ingress_*` | LAN 接口 ingress（host ns） | LAN 客户端流量的**分流点**（`tproxy_lan_ingress_role`, 2900） |
| `tproxy_lan_egress_*` | LAN 接口 egress | 反方向 conntrack 刷新（`do_tproxy_lan_egress`, 2802）、丢 NDP redirect |
| `tproxy_wan_egress_*` | WAN 接口 egress | 出 WAN 流量的分流点：本机进程流量 + 转发流量（3455/3632） |
| `tproxy_wan_ingress_*` | WAN 接口 ingress | 回包、unsolicited UDP（3329） |
| `tproxy_lan_wan_egress_*` / `wan_lan_ingress_*` | 单臂接口（dual-role） | 同一接口既是 LAN 又是 WAN |
| `tproxy_dae0peer_ingress` | daens 内 dae0peer ingress | 透明代理交付（3870） |
| `tproxy_dae0_ingress` | host ns 内 dae0 ingress | 回程还原 + 重定向回原接口（4030） |
| `cgroup/{sock_create,sock_release}` | cgroup | 进程归因（cookie→pid/pname）（4200/4208） |
| `cgroup/{connect4,6,sendmsg4,6}` | cgroup | 本机 socket 的直连/嗅探决策（4221-4242） |
| `sk_skb/tcp_offload_redirect` | sockmap | 全内核 TCP 转发（绕过用户态）（4264） |
| `fentry|kprobe/skb_send_sock` | 内核函数 | offload 记账（4389） |

## 2. 分流：一台用 `bpf_loop` 跑的布尔表达式虚拟机

用户态（`control/routing_matcher_builder.go`）把 `.dae` 规则编译成 `match_set`
数组，数据面只做"查表 + 求值"。

`struct match_set`（337）：

```c
union { __u32 index; struct port_range port_range; enum L4ProtoType l4proto_type;
        enum IpVersionType ip_version; __u32 pname[4]; __u8 dscp; };
__u8 not;            // 子规则取反
enum MatchType type; // Mac/IpSet/SourceIpSet/Port/SourcePort/L4Proto/IpVersion/DomainSet/ProcessName/Dscp/Fallback
__u8 outbound;       // 0..252，或 OUTBOUND_LOGICAL_OR / OUTBOUND_MUST_RULES 等控制值
__u8 must;           // must_* 规则
__u32 mark;          // 命中后写入 skb->mark
```

三种匹配资源：

1. **LPM trie 数组** `lpm_array_map`（314）：`BPF_MAP_TYPE_ARRAY_OF_MAPS`，
   每个 `match_set.index` 对应一个 LPM trie（`unused_lpm_type`, 306），
   支持 IP 集 / MAC / 源 IP 的最长前缀匹配（`route_match_lpm`, 1634）。
   规则里的 `index` 由用户态按 match_set 槽位分配（`epoch*MAX_MATCH_SET_LEN + index`）。
2. **Domain 位图** `domain_routing_map`（388）：key 是 `(epoch_slot, 目的 IPv4/IPv6)`，
   value 是 `MAX_MATCH_SET_LEN/32` 个 u32 的位图——第 i 位表示"第 i 条规则是
   domain 规则且该域命中"。用户态在 DNS 应答时按 IP 写入位图；
   数据面查一次代表 32 条规则的 word（`route_match_domain_set`, 1673）。
   这就是"DNS 关联域名"落到数据面的形态。
3. **常量比较**：端口区间、L4 协议掩码、IP 版本、DSCP、进程名（`equal16`）。

求值循环：

```c
ret = bpf_loop(active_rules_len, route_loop_cb, &loop_ctx, 0);   // 2019
```

`route_loop_cb`（1891）逐条取 `routing_map[slot*MAX + i]`，跳过"已判死"的规则，
`route_eval_match`（1708）做单条匹配，`route_finalize_match`（1821）处理
子规则边界（`OUTBOUND_LOGICAL_OR`）、取反、`must` 继承，并在规则尾部产出结果。

结果打包（1876/2022）：

```
bit  0..7   outbound id（0=direct, 1=block, 2..252=用户组, 253..255=控制值）
bit  8..39  mark
bit 40      must
bit 41..42  routing epoch slot（+1 编码）
```

两个 epoch 槽（`ROUTING_EPOCH_SLOT_NUM=2`, 71）用于**热重载**：用户态先往另一个
槽写新规则集，再切 `active_routing_epoch_map`（371），数据面读槽无锁切换。

内核门槛：`bpf_loop` 需要 **5.17+**（`docs/en/how-it-works.md:42`），
所以 dae 的硬性要求是 5.17。

## 3. 判决 → 动作

- `OUTBOUND_DIRECT`：`skb->mark = mark; return TC_ACT_OK`（2955）——报文沿
  正常内核路由转发，完全不进用户态。这是 README 里 "Real Direct" 的实现。
- `OUTBOUND_BLOCK`：`TC_ACT_SHOT`（2959）。
- 其它（代理组）：`redirect_lan_packet_to_control_plane`（2860）：

  1. **改目的 MAC 为 `dae0peer_mac`**（`rewrite_packet_for_control_plane`, 2252）：
     报文要穿过 dae0→dae0peer 这层 veth/netkit，目的 MAC 必须是对端设备的 MAC
     （netkit 还会有 MAC 过滤）。L3-only 的报文先 `bpf_skb_change_head` 补以太头。
  2. **记回程绑定**（`publish_redirect_track_for_packet`, 2196）：
     `redirect_track[forward 五元组] = {ifindex, smac, dmac}`。单写者语义 +
     2s 陈旧窗口，防止伪造者抢走别人连接的回程（2177 的注释写得很清楚）。
  3. **打 cb 标记**：`skb->cb[0] = TPROXY_MARK (0x8000000)`，`cb[1] = l4proto`（2875）。
  4. **`bpf_redirect(dae0_ifindex, 0)`**（2073）。内核含 CVE-2025-37959 修复时
     （mainline ≥ 6.14.7）对 **ingress** 方向改用 `bpf_redirect_peer`（省一次软转发）。

## 4. 透明代理交付（dae0peer_ingress, 3870）

```c
if (skb->cb[0] != TPROXY_MARK) return TC_ACT_SHOT;  // 防乱入
skb->mark = TPROXY_MARK;
bpf_skb_change_type(skb, PACKET_HOST);
if (l4proto == TCP && !SYN) return TC_ACT_OK;       // 已建立 TCP 不做 assign
ret = bpf_sk_assign(skb, listener);                 // SYN/UDP 才 assign
```

- listener 来自 `listen_socket_map`（119，SOCKMAP，key：0=TCP4 / 1=UDP / 2=TCP6），
  由用户态在 daens 里创建（IP_TRANSPARENT + bind tproxy_port）后放入。
- `bpf_sk_assign`（`assign_listener`, 2040）让 accept 出来的 socket
  **保持原始目的地址**，这就是 tproxy 语义。
- 已建立 TCP 靠 daens 里的路由策略本地投递（2904 的注释）：
  ```
  ip rule add fwmark 0x8000000/0x8000000 table 2023
  ip route add local default dev lo table 2023
  ```
  （Go 侧：`control/netns_utils.go:560 setupRoutingPolicy`）

### 4.1 回程能发出去，靠的是 daens 里一整套配置（重要！）

`control/netns_utils.go:871 setupIPv4Datapath`：

```
ip addr  add 169.254.0.11/32 dev dae0peer          # 让 L3 头成立
ip route add 169.254.0.1/32 dev dae0peer scope link
ip route add default via 169.254.0.1 dev dae0peer   # 注意是 via 网关
ip neigh add 169.254.0.1 lladdr <dae0 的 MAC> dev dae0peer nud permanent
sysctl net.ipv4.conf.dae0peer.accept_local=1        # 防 martian source 丢包（:863）
```

tproxy socket 的回包源地址是**原始目的地址**（非本机地址）。我们实测：
只配 `default dev dae0peer`（无网关）时，`ip route get` 直接
`Network is unreachable`，SYN-ACK 发不出去；换成 dae 这套
（169.254.0.11 + via 169.254.0.1 + 静态邻居 + accept_local）后回程立刻通。
mini-dae 的 lab.sh 完整照抄了这套。

### 4.2 用户态自己的 socket 要打 mark

`struct dae_param.dae_socket_mark`（224-227）与 `bpf_sock_is_dae_socket`（465）：
dae 的 socket 带 `SO_MARK`（配置项 `so_mark_from_dae`），数据面据此识别
"这是 dae 自己的流量"，避免自捕获（尤其 UDP）和 NAT-loopback 误判。
顺带一个内核行为值得记住：`inet_request_mark()` 在 listener 的 `sk_mark==0`
且 `net.ipv4.tcp_fwmark_accept=1` 时会让新连接继承 SYN 的 `skb->mark`——
那会把 `TPROXY_MARK` 带进回包，命中上面的 fwmark 规则被本地吞掉。
给控制面 socket 设非零 `SO_MARK` 是一条稳妥的隔离线。

## 5. 回程还原（dae0_ingress, 4030）

```c
load_redirect_tuple(skb, &redirect_tuple);        // 3989：IPv4 归一化成 mapped-IPv6
entry = bpf_map_lookup_elem(&redirect_track, &redirect_tuple);  // 反向 tuple
if (!entry) return TC_ACT_OK;
if (reply_publisher_matches(skb, entry))          // 只有绑定所有者能续租
        entry->last_seen_ns = bpf_ktime_get_ns();
bpf_skb_store_bytes(skb, h_source, entry->dmac, 6, 0);  // 换回"网关"MAC
bpf_skb_store_bytes(skb, h_dest,   entry->smac, 6, 0);  // 换回客户端 MAC
flags = entry->from_wan ? BPF_F_INGRESS : 0;
bpf_redirect(entry->ifindex, flags);               // 4068
```

即：回包从 daens 的 proxy socket 出来，穿过 dae0peer→dae0，在 dae0 ingress
被换回客户端认识的 MAC，再注入原接口（`from_wan` 时用 `BPF_F_INGRESS` 从
ingress 队列进，否则走 egress 直接发给 LAN 客户端）。用户态 janitor 负责
过期清理（`control/datapath_janitor.go`）。

## 6. 状态机与缓存

`conn_state_map`（504）里同时承载 conntrack 与路由缓存：

- TCP：`mark_tcp_seen`（2735 起）维护 SYN/FIN/RST 生命周期，
  缓存的决定直接复用（`tcp_state->meta.data.has_routing`），
  避免每包都跑规则虚拟机（2944-2964）。
- UDP：`mark_udp_seen*`（2316）带 300s backstop（2323），
  DNS（53）走短生命周期特判（`is_short_lived_udp_traffic`, 2310）。
- 反向包刷新：`tproxy_lan_egress_refresh`（2770）只刷新状态、不重定向。
- 路由元数据打包在 `union routing_meta`（420）里，与状态同拍发布
  （`publish_routing_meta`, 444，注释讨论了内存序的取舍）。

## 7. 进程归因（`pname()` 分流）

- `cgroup/sock_create`（4200）时把 `cookie → {pid, pname}` 写进 `cookie_pid_map`（411）。
- pname 不是简单的 `bpf_get_current_comm`：`get_pid_pname`（4098）用
  `BPF_CORE_READ(task, mm, arg_start)` 读 **argv**，再用 `bpf_loop` 找到
  可执行文件名——这样能区分 `docker-proxy` 这类被 comm 截断/同名的进程。
- 分流时用 socket cookie 反查 pname，与 `match_set.pname` 比较（1790）。
  这比 Clash 扫 `/proc` 快几个数量级（`docs/en/how-it-works.md:22-28`）。

## 8. 为什么还需要用户态：DNS 关联与嗅探 punt

- domain 规则命中与否取决于 `domain_routing_map` 位图，位图由用户态在
  DNS 应答经过 dae 时写入。DNS 不经 dae 则 domain 分流失效。
- 位图没有该 IP 时，数据面把首个报文连同 `routing_handoff_map`（289）
  交给用户态（punt），用户态用 TLS/HTTP/QUIC 嗅探（`component/sniffing`）
  得到域名后决定，再回注。sniffing 的超时/负缓存策略见
  `docs/en/how-it-works.md:45-84`。

## 9. TCP offload：连 relay 也搬进内核

- `fast_sock`（SOCKHASH, 255）存一对 socket；
  `sk_skb/tcp_offload_redirect`（4264）作为 stream verdict 程序在两 socket 间
  直接搬数据，用户态 relay 完全退场。
- `tcp_offload_pause`（269）是背压保险丝：暂停期间数据交给用户态转发，
  等内核排空重试队列再恢复，避免删 sockmap 导致丢包。
- `tcp_offload_sent_account`（4389）用 fentry/kprobe 做字节记账，
  与 `tcp_info` 的 receive 增量对比推算堆积。

## 10. 内核要求汇总

| 能力 | 要求 |
|---|---|
| `bpf_loop`（规则遍历、argv 解析） | Linux 5.17+ |
| `bpf_sk_assign` | Linux 5.7+（dae 被 5.17 门槛覆盖） |
| `bpf_redirect_peer` | 需 CVE-2025-37959 修复（mainline ≥ 6.14.7），否则自动退回 `bpf_redirect` |
| dae0/dae0peer 设备 | netkit（新内核）或 veth |

## 11. mini-dae 复现范围

当前状态（**K0–K3 + P3（a/b-1/b-2a）+ P4 + P5-G1/G2/G3a/G3b/G3b+ + P6 已完成**；九用例 × 两拓扑 × 两内核实测通过，
DNS、转发面、协议栈与运维面另跑专项；offload 为最小实现，边界见 ADR-0015/0016/0017/0018/0019/0020/0021）：

| dae | mini-dae | 状态 |
|---|---|---|
| 规则 VM（`bpf_loop` + match_set + 粘性 OR/AND） | `mini_route` / `mini_route_loop_cb` / `route_eval_match` / `route_finalize_match` | ✅ 已实现 |
| `routing_map` / `routing_meta_map` / `lpm_array_map` | 同名 + 内层 LPM trie（map-in-map） | ✅ 已实现 |
| 枚举与 outbound 编码 | 取 dae 的 `ebpf_sync_defs.h` / `ebpf_generated.go` 原值 | ✅ 已对齐 |
| `dip/sip/mac/l4proto/ipversion/dport/sport/dscp/fallback` | `loader/src/rules.rs` | ✅ 已实现 |
| LAN ingress 分流 → 重定向 | `mini_lan_ingress` | ✅ 已实现 |
| WAN egress 分流（本机进程 + 转发流量） | `mini_wan_egress` | ✅ 已实现（K1） |
| WAN ingress 回包刷新 | `mini_wan_ingress` | ✅ 已实现（K1） |
| 改 MAC + cb + redirect_track | 同名逻辑 | ✅ 已实现（单写者见下一行） |
| dae0peer_ingress + sk_assign | 同名 | ✅ 已实现 |
| dae0_ingress 回程还原 | 同名 | ✅ 已实现（`from_wan` 的 `BPF_F_INGRESS` 已实测） |
| conn_state（TCP 状态机 / UDP 超时） | `mini_conn_state` / `mini_conn_lookup` / `mini_conn_save` | ✅ 已实现（K1） |
| 双 epoch 槽热重载 | `active_routing_epoch_map` 同构（SIGHUP 触发） | ✅ 已实现（K1） |
| janitor 过期清理 | 用户态 janitor 线程 | ✅ 已实现（K1） |
| 域位图（DNS 应答 → `domain_routing_map`） | `mini_route_match_domain_set` + `loader/src/dns.rs` | ✅ 已实现（P3a，仅 IPv4 A 记录） |
| `domain(suffix/full/keyword/regex:)` 规则 | `loader/src/rules.rs` 编译成 match_set（regex 在编译期编译；位下标 = 数组位置） | ✅ 已实现（P3a/P3b-2a） |
| DNS 接管（透明 UDP → 上游 → 回包） | `dns_loop`（`IP_TRANSPARENT` + `IP_ORIGDSTADDR`，配套回包 socket） | ✅ 已实现（P3a，仅 UDP） |
| DNS 缓存（正/负、TTL 递减、命中回填 ID/question） | `loader/src/dns.rs` 的 `DnsCache` | ✅ 已实现（P3b-1） |
| TCP DNS（落到 tproxy 的 :53） | `tcp_dns_loop` / `handle_tcp_dns_conn`（daens→host ns 转交） | ✅ 已实现（P3b-1，2 字节分帧/keep-alive） |
| reload 后用缓存重建域位图 | `reconcile_domain_bits`（对照 dae `reconcileCurrentBpfProjections`） | ✅ 已实现（P3b-1） |
| EDNS：DO 位缓存键 / options 不缓存 / UDP 按客户端尺寸截断 | `query_edns` / `client_udp_size` / `truncate_for_udp` | ✅ 已实现（P3b-2a） |
| DNS 嗅探 punt（`ROUTE_STATE_DNS_QUERY` 控制面强制） | —— | ❌ 未实现（P3a 走常规规则命中 tproxy，非该路径） |
| DoH / DoQ / `dns.routing` 请求应答分流 / ECS 分区缓存 / 乐观缓存 | —— | ❌ 未实现（P3b-2 剩余；AAAA 只计数、不落位图） |
| 进程名（cgroup cookie）匹配 | —— | ❌ 未实现 |
| IPv6 路径 | —— | ❌ 未实现（当前只做 IPv4） |
| 单臂（dual-role）的合并程序 | `mini_wan_lan_ingress` / `mini_lan_wan_egress` | ✅ 已实现 |
| `redirect_track` 单写者/陈旧窗口防抢注 | `mini_publish_redirect_track` + `reply_publisher_matches` | ✅ 已实现 |
| 简单计数 map（rebind 拒绝等） | `mini_stats_map` | ✅ 已实现 |
| 全量 `.dae` 解析（include/schema/诊断） | `loader/src/config.rs` | ✅ 已实现（K3） |
| 只读状态面（Unix socket JSON） | `loader/src/status.rs` | ✅ 已实现（K3；P6 起含控制命令 reload/suspend/resume 与 metrics） |
| suspend（no-load/fail-open） | `mini_suspended()` + `control_flags_map`（C）+ SIGUSR2/状态面命令 | ✅ 已实现（P6；对照 dae suspend） |
| 统计导出（Prometheus 文本） / sysdump / trace | `metrics`/`sysdump`/`trace` 子命令 | ✅ 已实现（P6；daed GraphQL 不做，见 ADR-0021） |
| 日志文件与轮转（SIGHUP reopen） | `--log-file` + `log()` sink | ✅ 已实现（P6） |
| 整配置热重载（回滚 + DNS 上游热切换） | `do_reload` + `UPSTREAM_ADDR` 热更新 | ✅ 已实现（P6；失败不切槽） |
| TCP relay + Dialer（direct / socks5 / ss / trojan / vless / vmess / tuic / hysteria2） | `handle_relay_conn` + `outbound.rs`（host ns 线程池；tuic/hysteria2 走 QUIC） | ✅ 已实现（P4a 基座 + P5-G1/G2/G3a/G3b 协议梯） |
| relay 空闲回收（janitor） | `relay_janitor_loop`（`--relay-idle-timeout`） | ✅ 已实现（P4a） |
| UDP NAT（非 DNS 的代理 UDP） | `dns_loop` 分流 + `udp_nat_handle` 会话表 | ✅ 已实现（P4b，按 (client,orig_dst) 会话） |
| UDP 会话空闲回收 | `udp_nat_janitor_loop`（`--udp-idle-timeout`） | ✅ 已实现（P4b） |
| TCP offload（sockmap/sk_skb 内核对拼） | `fast_sock` + `mini_tcp_offload` + `try_offload` | ✅ 最小实现（P4c；无 fuse/计费/回收，见 ADR-0015） |
| 控制面自身 socket 防自环（SO_MARK） | `marked_tcp_connect` / `new_marked_udp` + C 侧 mark 跳过 | ✅ 已实现（P4a；协议栈/独立服务端同样打标） |
| shadowsocks classic AEAD（TCP 分块 + UDP 包，SIP004） | `loader/src/ss.rs` + `Outbound::Shadowsocks` | ✅ 已实现（P5-G1；aes-256-gcm / chacha20-ietf-poly1305） |
| trojan（TLS + CONNECT 头，rustls 0.23） | `loader/src/trojan.rs` + `Outbound::Trojan` | ✅ 已实现（P5-G1；仅 TCP/IPv4/无 close_notify 半关闭） |
| 协议/offload 互斥（AEAD/TLS 不交给内核拼接） | `Outbound::supports_offload()`（仅 direct/socks5） | ✅ 已实现（P5-G1；带 `--offload` 也 `offloaded_total=0`） |
| UDP 代理能力与显式回退 | `supports_udp()`（G1 仅 ss）+ `udp_nat.direct_fallback` 计数 | ✅ 已实现（P5-G1） |
| 协议 URL 解析（`ss://` SIP002/旧式 base64、`trojan://` query） | `outbound.rs::parse`（插件/非法参数硬失败） | ✅ 已实现（P5-G1） |
| vless（TCP/UDP，tls/none，UUID5 回退） | `loader/src/vless.rs` + `Outbound::Vless` | ✅ 已实现（P5-G2） |
| vmess AEAD（aid=0，嵌套 HMAC KDF、SHAKE128 分块、终止块） | `loader/src/vmess.rs` + `Outbound::Vmess` | ✅ 已实现（P5-G2；tcp/net，scy=auto|aes|chacha） |
| 共享 TLS 层（rustls 读路径不变量；ALPN） | `loader/src/tls.rs`（trojan/vless/vmess 共用） | ✅ 已实现（P5-G2 抽取；G1 行为不变） |
| UDP over stream 会话（vless 帧 / vmess 块） | `UdpRelay::Stream`（Mutex 读写半 + pending 缓冲） | ✅ 已实现（P5-G2；每数据报一帧/块） |
| 生态交叉验证（真实 Go 客户端 ↔ Python 服务端） | `lab/proto-check/`（parity 的 dae-work + outbound client） | ✅ 已实现（P5-G2；vless/vmess TCP+UDP） |
| tuic v5（QUIC：认证 exporter token、流式 TCP、DATAGRAM UDP + 分片） | `loader/src/tuic.rs` + `Outbound::Tuic`（tokio/quinn） | ✅ 已实现（P5-G3a；native 模式，连接复用，无重连状态机） |
| QUIC 参考对端（Go/quic-go 独立实现） | `lab/proto-check/tuic-server` + `build-tuic-server.sh` | ✅ 已实现（P5-G3a；本地跨实现单测 + lab e2e） |
| hysteria2（HTTP/3 认证 + 0x401 TCP + DATAGRAM UDP） | `loader/src/hysteria2.rs` + `hpack.rs` + `huffman_table.rs` + `Outbound::Hysteria2` | ✅ 已实现（P5-G3b） |
| salamander 混淆 / udphop / Brutal 近似（QUIC socket 中间件） | `loader/src/quicsock.rs`（Obfs/Hop）+ `brutal.rs`（HybridController） | ✅ 已实现（P5-G3b+；Brutal 为近似、gecko 不做，见 ADR-0020） |
| HPACK Huffman 解码 + QPACK 静态表编解码（h3 认证） | `hpack.rs` / `huffman_table.rs`（表由 `lab/gen-huffman-table.py` 从 Go 源码生成） | ✅ 已实现（P5-G3b；RFC 7541 官方向量验证） |
| hysteria2 参考对端（Go/http3 独立实现） | `lab/proto-check/hy2-server` + `build-hy2-server.sh` | ✅ 已实现（P5-G3b；本地跨实现单测 + lab e2e） |
| vmess aid≠0/CFB、packetaddr、vless vision/XUDP/reality、uTLS 指纹 | —— | ❌ 未实现（G3+，见 ADR-0017） |
| VMess / VLESS / SOCKS5-UDP / ss 2022 / uTLS 指纹 / obfs-ws | —— | ❌ 未实现（G2+，见 ADR-0016） |
| hysteria2 pinSHA256/ECH/自定义 CA、gecko 混淆 | —— | ❌ 未实现（见 ADR-0020） |
| 事件 ringbuf | —— | ❌ 未实现 |
| UDP full-cone NAT 语义 | `udp_nat_handle`（每目标一个上游 socket；回包不校验来源） | ⚠️ 部分（P4b；非跨目标 full-cone，边界见 ADR-0015） |

### 11.1 K0–K3 已验收的行为

- 三路径包级 e2e：proxy（`orig_dst=1.1.1.1:8080`）、direct（LPM 集合的**第二个**前缀
  `10.9.10.2:9999`，用于证明 OR 折叠真的写进了同一个 trie）、block（`!dport && sip`
  → 丢弃，未进入用户态）；
- 本机流量与 WAN 回程：宿主机自身进程的流量走 `wan_egress` 分流，回包经
  `dae0_ingress` 以 `BPF_F_INGRESS` 注入（trace 里 `ingress=1`），LAN 客户端回包走
  egress（`ingress=0`）——两个分支都实测；
- 热重载：SIGHUP 写非活跃槽再切 `active_routing_epoch_map`；在途连接保持旧判决
  （数据面打 `cached outbound=0x2`，未重跑 VM），新连接走新规则；
- conn_state 缓存：非 SYN 的后续报文直接读缓存判决，TCP/UDP 各带过期时间，反向包
  只刷新状态不重定向；
- 编译器与 DNS/协议单测共 53 个全过：前者覆盖 `&&` 编码、标量函数 OR 展开、`!` + fallback、
  `mark/must`、跨规则 LPM 下标重定位、regex 编译（含非法正则硬失败）；DNS 覆盖 wire
  查询解析（压缩指针、CNAME、AAAA 计数）与 A 应答构造、域名匹配（suffix 点边界 / full /
  keyword / regex 大小写语义）、位图计算，以及 P3b-1/P3b-2a 的缓存与 EDNS（命中改 ID/
  回填 question/递减 TTL、最小 TTL 过期、SOA 负缓存、SERVFAIL/TC 不入缓存、OPT 不动但
  additional 递减、DO 位键分离、options 不缓存、UDP 截断）；协议侧覆盖
  `evp_bytes_to_key`/ss 回环、trojan 口令向量、vless UUID/请求头/UDP 帧、vmess KDF 参考
  向量/auth id CRC/chunk 回环与逐字节分片，以及 vless↔Python 服务端的 UDP 回环；
- `bpftool map dump name lpm_array_map` 可见 3 个内层 trie（inner_map_id）；
- 实验设计上的一个取巧：`lab/rules.dae` 的 **fallback 故意设成 proxy**，这样规则一旦漏判，
  测试会看到 tproxy 回包而直接报错（比默默直连更容易发现问题）；
- 单臂双角色：`--dual single` 在同一接口挂 `mini_wan_lan_ingress` + `mini_lan_wan_egress`
  （对照 dae 合用程序：解析一次、wan/lan 角色顺序执行），八用例全通过；
- 单写者：竞争发布者在 2s 窗口内被拒并计数（`mini_stats_map[0]`），绑定保持；条目陈旧
  后允许改绑、回程恢复（`test-rebind` 的 echo2 断 / echo3 恢复证据）；
- 故障注入：kill -9 后 TCX 钩子自动摘除、流量回落为内核直转（fail-open，WAN echo 应答）；
  10 轮 SIGHUP + 持续打流全部成功、无「热重载失败」；
- 规则编译对拍：`lab/parity.sh` 对两份规则集与 dae 原版 Go 编译器（stub 构建驱动真实
  builder）输出逐字节一致；口径与边界见 ADR-0010；
- 内核矩阵：宿主 6.18.54-lts 与 QEMU 引导的 7.2.8 上，同一份对象/加载器均 8/8
  （5.17/6.1/6.6 本环境无镜像，未执行——见 `lab/matrix/SUMMARY.md`）；
- K3 全量解析：`lab/real-user.dae` 与 dae 官方 `example.dae` 均 schema 通过；
  routing 逐条翻译，未实现能力（geoip/pname/geosite 等）显式进 deferred（带文件:行号
  与原因），可编译子集（含 domain 全四种 key）在数据面生效；
- K3 只读状态面：`status` 返回 rules/conn_state/hooks/active_slot/stats/config 摘要，
  未知命令被拒绝；请求经主循环串行处理（服务线程不碰 map）；
- K3 过渡一跳：`--forward socks5://…` 下客户端收到
  `socks5-backend: target=1.1.1.1:8080`，orig_dst 一跳保留（对照 ADR-0011）。

### 11.2 P3a（DNS 接管 + 域位图）已验收的行为

- DNS wire：透明 UDP 监听（`IP_TRANSPARENT` + `IP_ORIGDSTADDR` cmsg），转发到上游
  （默认 `8.8.8.8:53`，可 `--dns-upstream` / 配置 `dns.upstream` 覆盖）后**用绑定原始
  目的地址的独立 socket 回包**——这是 tproxy 语义的固有要求，直接用监听 socket 回包
  会以错误源地址发出；
- 域位图：解析应答中的 A 记录 → 对每条 `domain(...)` 规则做 suffix（点边界）/full/
  keyword 匹配 → 得到位图 → 经 `MainMsg::DnsPublish` 交主循环写 `domain_routing_map`
  （key=`{slot, ipv4-mapped}`，与 dae `domain_routing_map` 同构；C 侧匹配对照
  `tproxy.c:1673-1706` 的 word 缓存实现）；
- 端到端证据（`lab.sh dns-up && lab.sh test-domain`）：`proxy.test` 的 A 记录经 dae
  转发后命中 domain 规则 → tproxy（`orig_dst=10.9.10.3:9999`）；`direct.test` 的 A 记录
  未命中 → 内核直转（`wan-echo-ok`）；状态面 `dns: queries=2 published_ips=2
  domain_routing_entries=2`；
- 生命周期：`reload`（SIGHUP）时同时清理 `domain_routing_map` 的非活跃槽；
- 边界：只处理 UDP DNS；AAAA 只计数不落位图（见 ADR-0012；缓存与 TCP 的边界由 ADR-0013
  修订，`domain(regex:)` 与 EDNS 的边界由 ADR-0014 修订）。

### 11.3 P3b-1（DNS 缓存 + TCP DNS）已验收的行为

- 缓存（`loader/src/dns.rs`）：key =（小写 qname, qtype, qclass）；正缓存寿命 = answer 段
  最小 TTL，负缓存（NXDOMAIN/NODATA）= `min(SOA.TTL, SOA.MINIMUM)`（RFC 2308，无 SOA
  用 30s 默认）；上限 1024 条（先清扫过期，再淘汰最旧）、寿命上限 3600s；TC=1 与
  SERVFAIL/REFUSED 不入缓存；命中时改事务 ID、按客户端大小写回填 question（0x20 兼容）、
  answer/authority 的 TTL 按已过秒数递减（当时实现为 additional 与 OPT 不动，P3b-2a 起
  additional 普通 RR 也递减、仅 OPT 不动——见 §11.4）；
- 缓存命中也要重发域位图（幂等 OR），SIGHUP 切换 epoch 后主循环用缓存快照重投影
  （`reconcile_domain_bits`，对照 dae `dns_controller_bpf.go reconcileCurrentBpfProjections`）——
  即「reload 后客户端不再查 DNS，domain 规则仍然有效」；
- TCP DNS：落在 tproxy 的 :53 连接由 accept 线程（daens）经 mpsc 转交给 host ns 的
  `tcp_dns_loop`（上游 TCP 连接在 host ns 建立，不经自己的钩子）；2 字节长度前缀分帧，
  一条连接可连续处理多条查询（keep-alive），读写超时 5s；与 UDP 共用缓存与位图路径；
- 实测证据（`lab.sh dns-up` + 四个专项）：
  - `test-dns-cache`：`cache.test` 第二次查询命中缓存（TTL 30 → 29，上游只收到 1 次）、
    `nx.test`（NODATA）两次查询上游只收到 1 次，状态面 `hits=2 misses=4 entries=4`；
  - `test-dns-tcp`：`--tcp` 探针两次查询 `tcp.test`，上游 `QUERY-TCP` 只 1 次，
    `tcp_queries=2 tcp_responses=2 tcp_unsupported=0`；
  - `test-dns-reload`：先解析 `proxy.test`，SIGHUP 后 active_slot 1→0，bpftool 可见新槽
    `10.9.10.3` 位图的 `match_set[1]` 位已重建，且不再查 DNS 直接连 `10.9.10.3:9999`
    仍命中 tproxy；
- 边界（P3b-2 剩余）：DoH/DoQ、嗅探 punt（`ROUTE_STATE_DNS_QUERY`）、`dns.routing`
  请求/应答分流、ECS 等 options 的分区缓存、乐观/陈旧缓存。

### 11.4 P3b-2a（domain(regex:) + EDNS）已验收的行为

- regex 域规则（对照 dae `ahocorasick_slimtrie.go:137-143`）：模式在规则编译期编译
  （Rust `regex` 1.x，RE2 语法系）；对**小写化、去尾点**的 qname 做非锚定匹配，模式保持
  原大小写（大写模式永不命中——与 dae 一致）；非法正则是硬失败（不是 deferred）；
- EDNS：`query_edns` 解析 OPT（size/DO/options）；DO 位入缓存键；带 options（ECS 等）
  的查询不入缓存也不命中；发给客户端的 UDP 应答按客户端尺寸截断（无 EDNS=512，有
  EDNS=公布值下限 512）——清空 answer/authority/additional、置 TC=1、保留 question，
  尺寸允许时保留 OPT；缓存与位图始终用完整应答，TCP 不截断；
- 对照 dae `setRecordTTL` 的细化：命中时 additional 段的普通 RR 也递减 TTL，仅 OPT
  的 TTL 字段不动（ADR-0013 第 2 条收窄，见 ADR-0014）；
- 实测证据：`test-domain-regex`（api1.regex.test 命中走 tproxy、web.regex.test 直转）、
  `test-dns-edns`（no-EDNS → `tc=1 ancount=0`；`--edns 4096` → `tc=0 ancount=60`；
  缓存命中仍按尺寸截断；TCP 完整；假上游只收到 1 次 big.test 查询）；

### 11.5 P4（转发面）已验收的行为

- **TCP relay（P4a）**：`--dialer direct|socks5://host:port`（`--forward` 是后者旧写法）；
  accept 在 daens，连接经 mpsc 转交 host ns relay 线程池；上游 socket 打
  `SO_MARK=0x233`，C 侧 `mini_lan_ingress`/`mini_wan_egress` 对带 mark 的包直接放行
  （对照 dae `is_dae_socket`）——这是「出口从 host ns 发出不重新被自己抓」的关键；
  双向泵送 + 半关闭，bytes/active 入状态面，janitor 按 `--relay-idle-timeout`（默认 300s）
  回收空闲连接；
- 实测：`test-relay` 经真实 WAN 目标回显 512KB 逐字节一致
  （`bytes_up=524299 bytes_down=524333 dial_errors=0`）；`test-relay-idle` 空闲 2s 后被
  janitor 回收（客户端读到 EOF/复位，`evicted>=1`）；`test-forward` 现在走 relay+socks5
  dialer（后端从 host ns 可达，orig_dst 保留）；
- **UDP NAT（P4b）**：透明 UDP 监听按原始目的端口分流（53 → DNS 引擎，其余 → NAT 会话）；
  会话键 =（client, orig_dst），每会话一个 host ns 上游 socket（mark + 2s 读超时）与一个
  绑定 orig_dst 的回包 socket；上游回包由 reader 线程直接发客户端；janitor 按
  `--udp-idle-timeout`（默认 60s）回收；
- 实测：`test-udp-relay` 3 报文复用 1 会话、回包源=2.2.2.2:9998、`errors=0`；
  `test-udp-idle` 空闲回收（`evicted>=1 active=0`）；数据面 mark 跳过同一用例验证
  （rules.udp.dae 把所有 UDP:9998 判 proxy，上游不被二次捕获）；
- **TCP offload（P4c，最小实现）**：`fast_sock` SOCKHASH + `sk_skb/stream_verdict`
  程序 `mini_tcp_offload`；键 =「对端收到报文时的四元组」（每个 socket 以 peer 元组入
  map）；verdict 按 skb 自身元组查 peer 后 egress 重定向（flags=0），未命中 SK_PASS；
- 实测与两个实现级发现：`test-relay-offload` 512KB 流的
  `userspace_bytes=0 verdicts=42 redirects=42`（完全内核拼接）；
  1）`skb->remote_ip4/local_ip4` 在此上下文是主机字节序（写进 `__be32` 字段后内存里是
  「IP 字节按序」），Rust 侧要用 `from_ne_bytes` 构造键；
  2）psock 接管后用户态 `read` 返回 EAGAIN，用户态泵必须把它当「驻留重试」而不是断连，
  否则会把正在被内核拼接的连接拆掉；注册前已入队的数据仍由泵排空，顺序不变；
- 边界：offload 无 backlog fuse / tcp_info 精确计费（见 ADR-0015）；半关闭计时与连接回收
  在 P7 补齐：看门狗（两侧 RDHUP 干净退出 / 单侧 10s 强制关闭）+ fast_sock 键注销 +
  注册前排空接收队列（见 §11.12 与 ADR-0022）；sockhash 无法用 bpftool 枚举（`map dump`
  显示 0 条），观测靠 verdict/redirect 计数与 `maps.fast_sock`（P7 新增）。

### 11.6 P5-G1（原生协议栈：shadowsocks + trojan）已验收的行为

- **拨号器梯度**：`--dialer direct|socks5://…|ss://…|trojan://…`；ss 支持 SIP002
  `ss://<method>:<password>@host:port` 与旧式 `ss://base64(method:password)@host:port`
  （带 `plugin=` 直接拒绝）；trojan 支持 `trojan://pass@host:port?sni=…&allowInsecure=1`；
  状态面 `dialer` 字段回显归一化后的名字（`ss://<method>@host:port` / `trojan://host:port`）；
- **shadowsocks classic AEAD（SIP004）**：密钥 `evp_bytes_to_key`（MD5，无盐）→ HKDF-SHA1
  （`info="ss-subkey"`，salt 每方向独立）；TCP `[salt][AEAD(len2)][AEAD(payload)]`（LE nonce），
  单块明文上限 0x3FFF；UDP 每包独立 salt + nonce0，载荷 = SOCKS5 地址头 + 数据；
  不做 SIP022；
- **trojan**：rustls 0.23（ring provider；`allowInsecure=1` 用 NoVerify，默认 webpki 根）；
  `hex(SHA224(password))+CRLF` + CONNECT(0x01)+IPv4+PORT+CRLF；不做 UDP ASSOCIATE、
  域名目标、close_notify 半关闭；
- **协议 / offload 互斥（显式）**：`supports_offload()` 仅 direct/socks5 为真；ss/trojan
  会话即使带 `--offload` 也不注册 fast_sock——AEAD/TLS 帧交给内核拼接会绕过封装，
  测试正面断言 `offload_enabled=true && offloaded_total=0 && 用户态字节数 ≥ 512KB`；
- **UDP 回退显式化**：G1 仅 ss 声明 `supports_udp()`；其他协议在有 dialer 时计入
  `udp_nat.direct_fallback`（测试要求 ss 会话下 `sessions_proxied>=1 && direct_fallback==0`）；
- **跨实现验收**：`lab/ss_server.py`（Python cryptography）与 `lab/trojan_server.py`
  （stdlib ssl）是独立对端，不复用 Rust 代码；两者上游 socket 都打 `SO_MARK`（防自环）；
  另有 `lab/ss_local_probe.py` / `lab/trojan_local_probe.py` 本地复现器（不依赖 netns）；
- **实测**：`test-ss` / `test-trojan` 512KB 逐字节一致（`bytes_up=524299 bytes_down=524333
  dial_errors=0 offloaded=0`），独立服务端日志各见目标行；`test-ss-udp` 3/3、回包源 =
  `2.2.2.2:9998`、`sessions=1/1 proxied=1 fallback=0`；
- **三个实现级发现（已修）**：
  1. Python 对端把上游 `recv(65536)` 的整块当一块加密，超出 ss 的单块上限（`!H`）——
     服务端必须按 0x3FFF 切块；Rust 读写两端本来就按上限切；
  2. 独立服务端的上游 socket 必须打 `SO_MARK`，否则从 host ns 出站会被 mini-dae 的
     `wan_egress` 二次捕获成环（表现为 RELAY 风暴、客户端超时）；
  3. **rustls 的明文缓冲默认只有 16KB**：TLS 读路径必须保证「两次 `read_tls` 之间先抽干
     `reader()` 明文」；否则大流量下 deframer/明文缓冲打满，`read_tls` 报错被当成致命
     错误拆连接（实测 512KB 必现）。修法：pending 密文缓冲 + 一次喂一块后回到循环顶部
     抽明文（`trojan.rs::TrojanReader`）。

### 11.7 P5-G2（vless + vmess AEAD）已验收的行为

- **拨号器梯度**：`--dialer direct|socks5://…|ss://…|trojan://…|vless://…|vmess://base64(JSON)`；
  vless 的 `type/headerType/security/flow` 与 vmess 的 `aid/net/type/scy/tls/fp` 都按 ADR-0017
  的子集硬校验（不支持就报错，不静默降级）；
- **vless**：请求头 `[ver][uuid16][addonLen][cmd][port][ATYP+ADDR]`；响应头惰性解析；
  UDP 帧 `[BE16 len][payload]`；UUID 支持标准格式与 Xray 兼容的 UUID5 回退；
- **vmess**：AEAD 请求头（嵌套 HMAC KDF、AES-ECB auth id + CRC32、eAuthID 作 AAD、connNonce）；
  响应头由 `SHA256(bodyKey/IV)` 派生；数据块 `BE16(size^mask)‖AEAD‖padding`，SHAKE128
  **先抽 padding 再抽 mask**，nonce `BE16(counter)‖IV[2:12]`，TCP 用终止块表半关闭；
  UDP 一个数据报一个块；chacha 会话密钥 = `md5(k)‖md5(md5(k))`；
- **共享 TLS 层**：`tls.rs` 抽出 G1 验证过的 rustls 读路径（pending 密文 + 抽干明文不变量），
  trojan 改用后行为不变（回归已证）；
- **UDP 会话拨号不再持锁**：`udp_nat_handle` 快路径持锁查表、慢路径锁外拨号、插入时去重；
  遗留边界：新会话首包仍在 `dns_loop` 线程同步拨号（TLS 一个 RTT，待异步化）；
- **三方交叉验收**（
  1. Rust 客户端 ↔ 独立 Python 服务端：lab e2e（TCP 512KB/UDP 3/3/offload 互斥）；
  2. **真实 Go 客户端**（parity 的 `dae-work` + olicesx/outbound v2ray dialer）↔ 同一
     Python 服务端：`lab/proto-check/run.sh {vless,vmess[,tls]}` TCP+UDP echo 全过；
  3. 本地 Rust↔Python 单测（vless UDP 回环）把协议问题从拓扑问题剔离；
- **四个实现级发现**：
  1. lab 拓扑里目标回包源地址会被 tproxy 恢复成 `10.9.9.2`（非 orig_dst），Python 服务端
     用 `connect()` 的 UDP socket 会按对端过滤丢包——改用 `sendto/recvfrom`（ss 服务端一直
     是这个写法，所以没暴露）；可用 `lab/udp_mark_probe.py` 复现两种写法差异；
  2. VMess 块解析的 padding/mask 抽取顺序（先 padding 后 mask）与半帧状态保留是硬要求，
     否则大流量下长度解释错位；
  3. rustls 的 16KB 明文缓冲不变量在抽取 `tls.rs` 时原样保留（G1 的坑，见 §11.6）；
  4. Go 客户端链接层两个已知偏差：`vless://` 忽略 `allowInsecure`（自签 TLS 会 x509，
     proto-check 因此只做明文）、`vmess://` 忽略 `scy`（恒用 aes-128-gcm）——Rust 侧仍按
     链接语义支持 chacha/TLS，由 lab e2e 覆盖。

### 11.8 P5-G3a（tuic v5 / QUIC）已验收的行为

- **运行时**：惰性全局 tokio（2 worker）+ quinn（`runtime-tokio`/`rustls-ring`，关 default
  特性以避开未缓存的 `rustls-platform-verifier`）；阻塞 relay 线程用 `block_on` 桥接；
  rustls 配置从 `tls.rs` 复用（NoVerify/webpki + ALPN）；
- **认证**：单向流 `[05][00][uuid16][token32]`，token = TLS exporter（label=uuid 裸字节，
  context=password）；失败只能表现为连接被 `0xfffffff1` 关闭（v5 无认证响应）；
- **TCP**：每条 relay 连接一条双向流 `[05][01][ATYP+ADDR+PORT]` 后裸字节；半关闭=FIN；
  目标不可达=服务端 Cancel（无状态帧）；
- **UDP**：QUIC DATAGRAM `[05][02][assoc][pkt][frag_total][frag_id][size][ADDR|0xff][data]`；
  超 `max_datagram_size()` 分片（单片 1452，首片带地址）；接收接 PKT_ID 重组（单候选、30s）；
- **SO_MARK**：quinn 自建 socket 无法打标 → `Endpoint::new` 传入自己 bind+mark 的 UdpSocket；
  三处（Rust/Go/Python）对非 root 统一降级告警；
- **接口**：`DialedStream.socket` / `RelayHandle.upstream` 改 `Option<TcpStream>`（QUIC 无 TCP）；
  offload 仍只 direct/socks5；
- **实测**：本地跨实现单测（TCP 256KB+FIN 透传；UDP 小包+3000B 分片往返）、lab
  `test-tuic`（512KB、`offloaded=0`）、`test-tuic-udp`（3/3、`proxied=1 fallback=0`）；
- **两个实现级发现**：
  1. Go 参考服务端回包也要分片：大回包直接 `SendDatagram` 会报 `DATAGRAM frame too large`，
     应按 `DatagramTooLargeError.MaxDataLen` 计算分片预算（与客户端同规则）；
  2. Go 服务端的日志文件是启动时一次性打开的 fd，测试里不能 `rm` 后期待日志重现——
     要截断（`:`>` 文件`）而不是删除；
  3. quinn 侧必须显式开 `datagram_receive_buffer_size`（决定对外广播的
     `max_datagram_frame_size`），否则回包方向直接被对端判为过大。

### 11.9 P5-G3b（hysteria2 / QUIC + HTTP/3）已验收的行为

- **HPACK/QPACK 底座**：`huffman_table.rs` 由 `lab/gen-huffman-table.py` 从本机 Go module 缓存机械提取
  （HPACK 表 = `golang.org/x/net/http2/hpack`；QPACK 静态表 = `olicesx/qpack`，99 项）；`hpack.rs`
  实现 Huffman 解码（树构建 + RFC 7541 §5.2 padding 校验 + EOS 拒绝）与 QPACK「静态索引/name-ref/
  literal」编解码，RFC 7541 附录 C.4 官方向量覆盖；
- **认证（h3）**：control 单向流 `[00][SETTINGS 04 00]` 保持打开；请求块 QPACK（非 Huffman 编码侧）+
  FIN；`:status 233` = 成功；读 `Hysteria-UDP` / `Hysteria-CC-RX`；`hysteria-padding` 256..2048 随机；
  失败返回错误（不 panic）；
- **TCP**：首帧 `0x401 | addrLen | host:port | padLen | pad(64..511)`，之后裸字节；拨号期读服务端响应
  （非 FastOpen，便于错误上报）；半关闭 = QUIC FIN；
- **UDP**：QUIC DATAGRAM `[SessionID u32][PacketID u16][FragID u8][FragCount u8][varint addr][data]`；
  每 NAT 会话一个 SessionID；单包 PacketID=0/FragID=0/FragCount=1；超预算按 1200（上限 1452）分片
  （随机 PacketID，每片带地址）；接收单候选重组（30s 过期），`Hysteria-UDP != true` 时 `connect_udp` 报 Unsupported；
- **链接**：`hysteria2://` / `hy2://`；auth = userinfo；`sni`（空回退主机名）、`insecure`（Go ParseBool）、
  `upmbps`/`downmbps`（Mbps×1e6/8；downmbps → `Hysteria-CC-RX`，0 = 服务端测速）、`maxTx`/`maxRx`（成对生效）；
- **边界（如实标注）**：Brutal CC 未做（用 quinn 自带 CC）、salamander/gecko 混淆未做（`obfs=` 配置期报错）、
  `pinSHA256`/`ech`/`ca` 未做（配置期报错）、不做 udphop/0-RTT/连接迁移；
- **实测**：本地跨实现单测（TCP 256KB+FIN 透传；UDP 小包+3000B 强制分片）、lab
  `test-hy2`（512KB、`offloaded=0`、`dial_errors=0`）、`test-hy2-udp`（3/3、`proxied=1 fallback=0`）；
- **三个实现级发现**：
  1. QPACK 的「literal name」形式里 bit3 也是 H 标志（`001N Hxxx`），quic-go 正是用它编码
     不在静态表中的名字（`hysteria-udp` 等）——只按 3 位前缀读裸名字会直接 UTF-8 失败；
  2. 服务端 HTTP/3 层绝不能声明 `H3_DATAGRAM`（只开 QUIC 层 datagram），否则 quic-go 的 h3
     客户端会启动 receiveDatagrams 循环把裸 datagram 吃掉；
  3. `close_reason()` 判活 + 一个 dialer 一条连接复用对 hysteria2 同样成立（与 tuic 同构）；
     h3 认证失败必须以「客户端错误」返回，不能 panic（服务端 401 是正常路径）。

### 11.10 P5-G3b+（salamander / Brutal 近似 / udphop）已验收的行为

- **salamander**（`quicsock::ObfsSocket`，`blake2 0.10`）：逐 datagram `[8B salt][payload XOR key]`，
  `key = BLAKE2b-256(PSK||salt)`（32B keystream 循环）；PSK<4B 拒绝；收侧 ≤8B 丢弃；
  跨实现用 Go 生成的 key 向量钉死算法；不实现 gecko（解析期报错）；
- **Brutal 近似**（`brutal.rs`）：HybridController = inner quinn BBR + 共享 `Arc<AtomicU64>` 速率目标；
  认证后按 Go `resolveCongestion` 语义算 `min(server_rx, client_tx)`，目标>0 时
  `window=max(2mtu, rate×srtt)`、丢包不收缩；`cc_override=bbr|brutal|bbr3`（bbr3→BBR 近似，
  cubic/new_reno 按 Go 拒绝）；**如实标注**：quinn pacer 把实际速率放大约 25%；
- **udphop**（`quicsock::HopSocket`）：端口并集（`all`/范围/合并）→ 每 interval（默认 30s，链接扩展
  `udphop-interval`，最小 5s）随机换目标+新本地 socket，旧 socket 宽限一个 interval；对 quinn
  谎报逻辑地址（否则客户端 migration 丢包）；服务端（quic-go fork）自动迁移；
- **参考对端**：`hy2-server -obfs-password`（用 outbound 的 `obfs` 包）与 `-hop-ports`（多 socket mux，
  回复走「该客户端最后一次来包的 socket」）；
- **实测**：cargo 跨实现 3 项（obfs TCP+UDP、Brutal 256KB×2、hop 11s 跨 2 跳）+ lab 四会话
  `test-hy2-obfs`（512KB）/`test-hy2-obfs-udp`（3/3）/`test-hy2-brutal`（512KB）/`test-hy2-hop`
  （两轮 512KB 跨 5s 跳端口）；
- **两个实现级发现**：
  1. **quinn endpoint driver 不会自动发现新 socket**：`poll_recv` 返回 Pending 后它只等已注册的 waker，
     跳端口新建的 socket 永远不会被轮询（表现为：前半段正常、一跳就完全收不到回包，直到 idle 超时）。
     修法：HopSocket 保存驱动传入的 recv waker，新增 socket 后主动 `wake()`，驱动重新对全部 socket 注册；
  2. **GO 侧 min hop interval = 5s 不是保守，而是可用性边界**：300ms 跳端口实测会失速
     （服务端地址在多个旧四元组间回退，QUIC 重传风暴），5s 间隔下连接跨跳存活。

### 11.11 P6（运维面）已验收的行为

- **信号**：SIGHUP = reload（重编译/切槽 + 清 suspend + reopen 日志）；SIGUSR2 = suspend；
- **suspend**：eBPF `control_flags_map`（ARRAY u32×1）bit0；5 个分流入口读到即 `TC_ACT_OK`
  （no-load / fail-open，内核直转）；实测 suspend 后客户端探测从 tproxy 变为真实回显；
- **状态面**（不再只读）：`status|rules|config|maps|metrics|reload|suspend|resume`；
  控制命令仍经 mpsc 交主循环串行执行（与 `DnsPublish` 同一队列）；
- **CLI**：`reload`/`suspend`/`resume`/`metrics`/`sysdump`/`trace`；
  `sysdump` 输出 status+rules+config+maps+系统网络信息（`ip -j`）的单 JSON；
- **metrics**：Prometheus 文本（`mini_dae_*`，含 relay/udp_nat/dns/maps/stats/suspended/reload）；
- **日志**：`--log-file` + SIGHUP reopen（`mv` 后新文件重建，实测含重载记录）；
- **整配置热重载**：`--config` 重跑 include/parse/schema/子集编译；编译失败不切槽（回滚）；
  `dns.upstream` 重载后热切换（DNS 线程每查询读当前值；`--dns-upstream` 优先）；
- **实测**：`test-ops`（suspend fail-open / reload 恢复+切槽 / metrics 42 行 / sysdump 六键 /
  日志轮转）与 `test-config-reload`（改规则生效 / 坏配置回滚 / 上游 5353→59999→5353）；
- **两个实现级发现**：
  1. 状态面客户端必须**读到 EOF**：metrics 是多行文本，按行读取只会拿到第一行；
  2. 配置文件的 0640 权限校验对测试夹具同样生效（/tmp 副本要 `chmod 640`）。

### 11.12 P7（收敛：剖面 / offload 生命周期 / soak / 静态发布）已验收的行为

（完整口径与取舍见 ADR-0022；本节只记录可复现的行为与数字。）

- **剖面口径（如实）**：`perf` 不可用（`perf_event_paranoid=2` 且无 perf 二进制）——
  指标 = 墙钟吞吐 + 状态面 counters + `/proc/<pid>` CPU/RSS；工具：`lab/bench_io.c`（C 端点）
  + `lab/bench.sh`（六路径：direct/relay/offload/ss/udp-direct/udp-nat）；direct 基线用
  `bench-up` 会话（`rules.bench.dae`）；
- **基线数字**（16 核 / veth / 单次取数）：direct 31Gbps·p50 10µs；relay 24.7Gbps·17µs·
  447ms/GB；offload 14.6Gbps·23µs（用户态≈零，但**吞吐低于 relay**，未追因，如实记录）；
  ss 2.5Gbps·55µs·1267ms/GB；UDP RTT：direct 8µs vs NAT 15µs；
- **offload 生命周期修复**（P4c 最小实现 ⇒ 对齐 dae 会话层语义）：看门狗 `poll(RDHUP)`——
  两侧 RDHUP 干净退出，单侧 >10s（dae `relayHalfCloseTimeout`）强制关闭两侧；连接终结后
  **删除 fast_sock 键**（sockmap 条目持 socket 引用，不删会胀 fd/RSS）；注册前**排空接收队列**
  （防用户态泵与内核重定向双路径）；新增回归 `test-offload-lifecycle`（断言 `active=0`、
  `fast_sock=0`，状态面 maps 新增该计数——注意 offload 启用后 map 已被 `take_map` 移出
  `Ebpf`，计数要从 `RELAY_OFFLOAD` 取）；
- **三个反直觉的坑**：
  1. 用户态在 RDHUP 时向对端传播 FIN 会截断重定向队列里的在途数据（32MB 只剩 0.3–17MB）——
     不传播，靠超时兜底；
  2. 给 `sk_skb` verdict 加 `skb->len==0 → SK_PASS` 反而让 psock 吃掉 EOF 并停滞数据（10s 只走
     MB 级）——保持与 dae 相同，不特殊处理；
  3. FIN 重定向尝试会在源 socket 留下 `POLLERR`（常态）；传输中按它 force-close 会切断全部
     在途数据；
- **优化（先测后改）**：出站 TCP（`marked_tcp_connect`）与 tproxy accept 全部 `TCP_NODELAY`
  ⇒ ss 小包 p50 **43.3ms → 55µs**（帧头+载荷多次小写撞 Nagle+延迟 ACK）；relay 保持 ~17µs；
  bench 的 `metric()` 必须先读完整 metrics（`awk exit` 关管道会让客户端 EPIPE panic）；
- **soak**（`lab/soak.sh`，默认 60s）：tcp 60s = 870 轮 + 435 reload + 290 suspend/resume，
  RSS +368kB、fd +0；ss 30s +440kB；udp 30s 的 RSS +30.9MB 是 glibc 多线程 arena 保留
  （`MALLOC_ARENA_MAX=1` 下 60s 仅 +7.9MB，fd 回基线），脚本对 udp 放宽到 48MB 并注明；
- **静态发布**：`lab/build-static.sh` = glibc `crt-static` static-pie（`ldd: statically linked`）
  + `redis:7-alpine` 冒烟（`validate` 6 可编译/1 deferred）；musl target 因 ring 缺
  `x86_64-linux-musl-gcc` 未直构（源码两处 libc 类型差异已改 `as _`：`SIOCGIFHWADDR` ioctl
  签名、`msg_controllen` glibc=usize/musl=u32）；
- **回归**：`cargo test` 73/73、标准/单臂 verify 9/9、DNS 六专项、转发面六专项（含新
  `test-offload-lifecycle`）、G1/G2/G3a/G3b 全套、`test-ops`/`test-config-reload`、
  `lab/parity.sh`、`lab/proto-check`；**verify 的 rebind 对时序敏感**：并行负载下出现过一次
  抖动（复跑通过），回归应串行跑。

### 11.13 P8（数据面 Rust 迁移起步：工具链 + offload 垂直切片）

> 迁移期历史：本节的双对象共存与 `--ebpf-offload` 已在 P9+（§11.15，ADR-0025）移除——
> 保留本节以记录工具链与 guard 镜像的由来。

- **工具链（本机存档）**：
  - nightly + rust-src：官方源被 TLS 拦；镜像均可用（Tuna/USTC/Aliyun/rsproxy）。安装：
    `RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup RUSTUP_UPDATE_ROOT=https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup rustup toolchain install nightly --profile minimal --component rust-src`；
  - crates：`~/.cargo/config.toml` 源替换到 USTC
    `sparse+https://mirrors.ustc.edu.cn/crates.io-index/`。**坑：Tuna 的 index `config.json`
    里 dl 仍指向被拦的 static.crates.io**——必须选 dl 也镜像的源（USTC/rsproxy 实测可下
    crate）；
  - `bpf-linker 0.11.1` 本机已在 `~/.cargo/bin`（PATH 需自行加）。
- **crate**：`ebpf-rs/`（不进主 workspace）——aya-ebpf 0.2.1、`no_std`、
  `.cargo/config.toml`：`[build] target=bpfel-unknown-none`、`[unstable] build-std=["core"]`、
  `linker=bpf-linker`、`rustflags=["-C","link-arg=--btf"]`；构建 `lab/build-ebpf-rs.sh`
  （对象约 2.1KB，含 `sk_skb/stream_verdict` 与 `maps` 段）。
- **loader 接入**：`--ebpf-offload <rust.o>`（需 `--offload`）：Rust 对象提供
  `fast_sock`/`offload_guard`/`mini_stats_map` 与 `mini_tcp_offload`；C 对象其余程序不动；
  状态面 counters 合并（Rust 的 2/3 覆盖 C 的 redirects/verdicts）。
- **两个坑**：
  1. aya-ebpf 0.2 没有公开的 SockHash lookup，而 `bpf_sk_redirect_hash` 未命中会丢包——
     用 `offload_guard`（HASH）镜像做预检；注册顺序必须 **fast_sock 先、guard 后**，
     回收相反（否则 guard 命中而 fast_sock 缺失的窗口会丢包）；
  2. `skb.remote_port()` 返回原始 u32：LE 下要和 C 一样 `>> 16`（高 16 位是网络序端口），
     `local_port()` 要 `to_be()`。
- **实测**：`offload-rs-up` + `test-relay-offload`/`test-offload-lifecycle` 通过；
  C 路线同名用例与 `ss-up`（协议/offload 互斥）复测通过；`cargo test --release` 73/73；
  bench：offload-rs 11.3Gbps·p50 19µs vs C 同轮 8.9Gbps·p29µs（单次方差大，量级一致）。

### 11.14 P9（数据面全量 Rust 化）已验收的行为

（决策与取舍见 ADR-0024；ADR-0023 的迁移路线部分被它取代，guard 镜像仍保留。）

- **单对象全量**：`ebpf-rs/` 现在= 7 个 TC classifier（lan/wan/dual/dae0peer/dae0）+ offload verdict
  + 14 张 map；名字/类型/容量/section 与 C 逐一对齐，loader 零分支——`--ebpf <rust.o>`；
  **P9+ 起 Rust 对象是唯一数据面**（C 对象与 `USE_EBPF_C` 回退已删，见 §11.15/ADR-0025）；
- **BTF maps**：`#[btf_map]`（含 `ArrayOfMaps<LpmTrie<[u8;16],u32,1024>,128>` 内层模板、
  `domain_routing_map` 的 `BPF_F_NO_PREALLOC`）；**必须 `debug = 2`**（bpf-linker `--btf` 从
  DWARF 生成 `.BTF`，否则 aya 报 `no BTF parsed for object`）；
- **规则 VM 用有界循环替代 `bpf_loop`**：aya-obj 对函数指针的 `R_BPF_64_64` relocation 未产出内核要的
  `BPF_PSEUDO_FUNC`（verifier：`callback function not static`）；规则上限 64 已先验证明，内核 ≥5.3
  的 bounded loop 语义等价（上游 aya-obj 修复后可评估换回，见 ADR-0024 修订条件）；
- **移植要点**：解析全走 `ctx.load::<T>()`；`skb->mark/ifindex` 走原始指针；MAC 改写用
  `ctx.store::<[u8;6]>`；`bpf_skb_change_type`/`bpf_redirect(BPF_F_INGRESS)` 同 C；
  dae0peer 的 `listen_socket_map`→`bpf_sk_assign` 用原始 `bpf_map_lookup_elem`（aya-ebpf 的 SockMap
  只暴露 SK_LOOKUP 方法）；
- **本次抓到的一个移植 Bug（值得记）**：TCP 位段在 LE u16 里 flags 在**高字节**
  （fin=bit8/syn=bit9/rst=bit10/ack=bit12），按低字节位算会把所有 SYN 当“无状态非 SYN”放行
  （症状：direct/block 过而 proxy 全挂）；已由 verify 钉住；
- **实测（全量回归都在 Rust 数据面上）**：标准 verify 9/9、单臂 8/9（rebind 首轮 flake，单跑过）；
  DNS 六专项；转发面六专项（含 offload 生命周期）；G1/G2/G3 全部（ss/trojan/vless/vmess/
  tuic/hysteria2 含 obfs/brutal/hop）；test-ops/test-config-reload；soak 30s tcp（450 轮，
  RSS +372kB、fd +0）；`cargo test` 73/73；
- **性能（单次取数）**：direct 30.4Gbps/10µs、relay 20.4Gbps/18µs、offload 11.9Gbps/21µs（C）
  vs offload-rs 10.8Gbps/19µs——与 C 同级；

### 11.15 P9+（移除 C 数据面）已验收的行为

（决策与取舍见 ADR-0025；本节记录清理后复跑的实测边界。）

- **清理范围**：删 `ebpf/mini_dae.c`（整个 `ebpf/` 目录）与 `build/mini_dae.o`（含残留 `.tmp`）；
  loader 删 `--ebpf-offload`、`static OFFLOAD_EBPF` 与 offload 计数回退分支（offload 计数与
  数据面同属 `mini_stats_map` 索引 2/3）；lab 删 `USE_EBPF_RS`/`USE_EBPF_C`/`USE_OFFLOAD_RS`
  分支与 `offload-rs-up`/`rs-up`/`rs-dual-up` 会话；bench 删 `offload-rs` 路径；
  `lab/lab.sh build` 只构建 Rust 对象（工具链缺失即失败，不再静默跳过）；
- **残留检查**：`grep -rn "mini_dae\.c\|mini_dae\.o\|USE_EBPF\|USE_OFFLOAD_RS\|offload-rs\|ebpf-offload"`
  在 `lab/`、`loader/src/`、`ebpf-rs/src/` 零命中；`lab/lab.sh rs-up`/`offload-rs-up` 退出码 2（usage）；
- **复跑（唯一 Rust 对象）**：标准 verify 9/9、单臂 verify 9/9（本次串行无 flake）；
  `test-domain`（DNS）、`test-forward`（转发面）、`test-ss`（协议栈）抽查全 PASS；
  `cargo test --release` 73/73；`lab/bench.sh run offload` 12.4Gbps / p50 19µs；
- **六路径基准（`lab/bench.sh all`，单次取数；对照 P7 C 时代表）**：direct 30635Mbps/10µs（C 31117/10）、
  relay 23780/18µs（C 24713/17）、offload 7503/24µs（C 14565/23；同对象三次单跑 12437/19µs、
  8286/30µs——**单次方差大**，与 C 同为量级）、ss 2452/59µs（C 2497/55）；UDP blast 丢包
  11262/11220（C 同数值 11262/11248，端点丢包主导，只作相对参考）；
- **回退方式**：需 C 对照时从 `dae/` 重建 C 对象并临时切换 `--ebpf`（调试手段，非常规路径）。

### 11.16 P9+ 完整性回归（唯一 Rust 对象，2026-10-04 全量复跑）

删除 C 后把“只在抽查过”的层面全部在最终对象上重跑（P1 功能全量 → P2 联调/对拍 →
P4 稳定性 → P3 内核矩阵）：

- **功能全量（P1，全 PASS）**：标准/单臂 verify 9/9（前节已记）；DNS 6/6
  （domain/cache/tcp/reload/edns + regex）；转发面 6/6（relay/idle/offload/lifecycle/udp-relay/udp-idle）；
  K3/运维 5/5（config/status/forward/ops-reload 整配置/ops）；协议梯 **15 个会话、17/17 端到端**
  （ss、ss-udp、trojan、vless 与 vless-tls、vless-udp、vmess 与 vmess-tls、vmess-udp、tuic、tuic-udp、
  hy2、hy2-udp、hy2-obfs、hy2-obfs-udp、hy2-brutal、hy2-hop）；`cargo test` 73/73；
  六路径基准见前节；
- **P2 联调/对拍**：`lab/parity.sh` 在 IP 规则集上 **5/5 逐字节一致**
  （rules.dae / rules.reload.dae / rules.udp.dae / rules.fault.dae / rules.bench.dae；
  rules.dns/regex 因 Go 侧 dump 工具 `unhandled match type 0` 不在对拍范围内——K2 既有限制，
  非 Rust 侧偏差）；`lab/proto-check/run.sh`：vmess/none、vmess/tls、vless/none **3/4 PASS**；
  **vless/tls FAIL 为已知偏差**（P5 已记录：Go 客户端链接层忽略 `allowInsecure`，
  自签证书必 x509；Rust 侧 vless TLS 由 lab e2e `vless-tls-up` 覆盖并通过）；
- **P4 稳定性（`lab/soak.sh`，全 PASS）**：tcp 60s（968 轮：每 2 轮 reload、每 3 轮 suspend/resume）
  RSS +316kB、fd +0；ss 30s（365 轮）RSS +664kB、fd +0；udp 30s RSS +32.9MB（glibc arena
  保留，脚本按 48MB 阀值判定）fd±1；均 active=0/fast_sock=0/udp_active=0；
- **P3 内核矩阵（`lab/matrix.sh`）**：宿主 6.18.54-2-lts 9/9、QEMU 第二内核 7.2.8-arch1-2
  9/9（两内核均 MATRIX-RESULT verify=PASS）；日志见 `lab/matrix/out/`，汇总同步
  `lab/matrix/SUMMARY.md`（含 out/ 目录 root 属主坑）。
- **完整性边界（如实）**：本回归覆盖 mini-dae 声明范围（ADR-0006/0011），**不等于 full dae**
  ——geoip/pname/CO-RE 等仍显式 deferred；<5.17/<6.6 内核行为未真机验证（见 SUMMARY）。

### 11.17 P10（vless WebSocket 传输 / 真实订阅节点）已验收的行为

（决策与取舍见 ADR-0026；脚本 `lab/real-node-e2e.sh`；探针 `real_vless_ws_probe`。）

- **触发**：用真实订阅（50 节点，全部 vless+ws+tls+CF CDN）检验生态兼容性，
  原 vless 客户端只做 tcp、解析期即拒绝——属于“接入原有生态”的硬缺口；
- **实现**：`loader/src/ws.rs`（RFC6455 客户端传输）——
  - 握手：`GET {path}` + `Host/Sec-WebSocket-Key/Version`，校 101 与
    `Sec-WebSocket-Accept`（SHA1+GUID）；握手残留字节存读半 pending 不丢帧；
  - 读半流式（remaining 计数、不缓存整帧）、续帧当字节流、ping→pong（写路径捎带）、close→EOF；
  - 写半每次 write 一帧（掩码、FIN=1）；传输选择在 `parse_vless`：
    `type=ws` + `host`/`path`（缺省 host=sni、path=/）；grpc/h2 仍拒绝；
- **实测坑（值得记）**：
  1. 响应头搜索不能每轮都从 `buf.len()-3` 重新开始——分隔符可跨两次 read，
     必须记录上次扫描进度（首次实现漏掉 `\r\n\r\n` → “握手响应中途关闭”）；
  2. 掩码是客户端→服务端**强制**；服务端帧带 mask 应报错；
  3. 真实节点对**目标可达性自身有策略**：同一节点 v2ray 5.52 与 mini-dae 在
     `1.1.1.1`/`1.0.0.1`/`www.cloudflare.com` 上同样失败（节点侧黑洞）、gstatic/ipify 正常
     ——验收必须带“参照客户端同目标对拍”，否则会把节点问题误判为实现 bug；
  4. 环境坑：本机容器内 root 覆盖宿主用户属主的 0640 文件会被拒（capability 映射），
     lab 脚本生成规则文件先 `rm -f` 再写；
- **验收**：`cargo test --release` 80/80（+1 ignored）；标准 verify 9/9；vless tcp/tls/udp 专项全过；
  `lab/real-node-e2e.sh`（环境变量注入节点）：client ns → tproxy → vless-ws →
  真实节点 → gstatic **204**，relay up 1981B/down 4713B、dial_errors=0；拨号探针 API 级直连同样通过。
- **真实订阅形态普查（第二份订阅，2026-10-04）**：48×vless（`security=reality` +
  `flow=xtls-rprx-vision`，带 pbk/sid/spx）+ 18×anytls——两者都在当前边界外
  （解析期显式拒绝，已用测试钉住：`parse_vless_rejects_reality/vision`、
  `parse_rejects_anytls_scheme`）。参照验证：**sing-box 1.14**（REALITY 与 anytls 各取一节点）
  均 **204**，订阅本身可用；v2ray 5.52 对 REALITY+Vision 支持不全（同目标失败）。
  **桥接通路（不改代码即可用）**：`--dialer socks5://127.0.0.1:10883` 指向本机 sing-box
  （出站 = 真实节点），gateway e2e gstatic **204** 实测通过；注意慢节点首连可能 >5s
  （relay 拨号硬编码 5s 超时，会 dial_errors=1，重试即过——后续可加 `--dial-timeout`）。

### 11.18 P11（AnyTLS 客户端 / --dial-timeout）已验收的行为

（决策与取舍见 ADR-0027；脚本 `lab/real-node-e2e.sh`（REAL_NODE_URL）；探针 `real_anytls_probe`。）

- **触发**：第二订阅 18×anytls；把 §11.17 普查里的边界外协议变成原生支持；
- **实现**（`loader/src/anytls.rs`）：认证 `sha256(password)+padding0(30B)`；帧
  `[cmd][sid BE32][len BE16][data]`；首包批 Settings+SYN+PSH(SocksAddr) 计 pkt1；
  读路径处理 Update/Settings/SYNACK/Heart/Waste/Alert；paddingScheme 默认值与
  anytls-go 逐字节一致（md5 `75cff2ad89aadf5e257059ee571ebe11`），区间随机 + `c` 检查符；
- **实现坑（值得记）**：
  1. 首包必须是 **Settings + SYN + PSH(目标地址)** 一次写（地址不在 SYN data 里），
     否则 pkt1 padding 与真实客户端对不上；
  2. pkt1 的尾部 waste 帧**长度随机**（100-400），mock 测试要短超时探测尾帧，
     不能无条件 read；
  3. 自读缓冲（pending）拼接时要按 `out[off..]` 偏移读底层，否则短读会覆写头部；
- **附带**：`--dial-timeout <s>`（默认 5）与 lab `USE_DIAL_TIMEOUT` 透传；
  真实节点慢首连（>5s）曾触发默认超时重试；
- **验收**：`cargo test` 89/89（+2 ignored）；sing-box 服务端跨实现回环；
  `REAL_NODE_URL=anytls://… lab/real-node-e2e.sh`：真实节点 gstatic **204**，
  relay up 1981B/down 4713B、dial_errors=0；标准 verify 9/9。

### 11.19 P12（本地 SOCKS5 入口 / 浏览器验收）已验收的行为

（决策与取舍见 ADR-0028；实现 `loader/src/socksin.rs` + `main.rs` 的 socks 模式。）

- **入口**：`--listen-socks <addr> --dialer <anytls|vless|…>`：不加载 eBPF、不需 root；
  CONNECT、无认证；IPv4/域名目标（域名本地解析）；UDP/BIND/IPv6 显式拒绝；
- **实现要点**：hello→request 解析纯函数（可测）；拨号成功后才回 `REP_SUCCEEDED`；
  进长连接前**清掉握手超时**（否则浏览器空闲连接 10s 被误断）；泵直接复用 relay `pump`；
- **实测坑**：节点域名双栈时 `getaddrinfo` 可能 AAAA 优先 → “只有 IPv4”误拒；
  `resolve()` 改为优先 IPv4（v6-only 才回落）；
- **验收**：`cargo test` 95/95；真机跑订阅#2 anytls 节点：gstatic 204（域名/本地两种
  socks 形态）、YouTube 200（relay down 918KB）；日志 `/tmp/mini-dae-socks.log`。

### 11.20 P13（真网关模式 / host gateway）已验收的行为

（决策与取舍见 ADR-0029；实现 = loader `--lan none` + `lab/gateway.sh` + `lab/rules.gateway.dae`。）

- **入口**：`sudo lab/gateway.sh up [--iface wlan0] [--node /tmp/mini-dae-node.url]`；
  `down`/`status`/`test`/`--dry-run`；节点 URL 仅从文件/参数读取（不入库）。
- **拓扑**：物理网卡留在宿主 netns（只挂 wan egress/ingress）；控制面对 netns `gwdae` +
  veth `dae0gw/dae0gwpeer`（169.254.0.11/32、静态邻居 169.254.0.1、`fwmark 0x8000000 → table 2023`，与 lab 拓扑一致）。
- **数据面路径**（与 lab `test-host-proxy` 同源）：wlan0 egress 判 proxy → 改 dst MAC 为 dae0peer MAC +
  `redirect_track(smac,dmac,from_wan=1,ifindex=wlan0)` → redirect dae0 → dae0peer ingress
  `bpf_sk_assign` → tproxy（daens）→ relay 在 host ns 拨号（`SO_MARK=0x233` 跳过钩子）→
  回程 dae0 ingress 还原 MAC + `BPF_F_INGRESS` 注回 wlan0（`progs.rs` `mini_dae0_ingress` L132-196）。
- **实测坑 1（最重要）**：网关规则里不能写任何 `sip(...)`——宿主机流量源地址就是本机私网地址，
  `sip(192.168.0.0/16) -> direct` 会把全部出站 TCP 判直连（症状：TCP 直连被墙/超时，
  而 DNS 因数据面 DNS override 仍进控制面，容易误判「链路已通」）。
- **实测坑 2**：DNS(53) 想直连必须 `direct(must)` 且排在私网 `dip` 规则之前——`route.rs:146`
  对任何命中的非 must 规则会强制 `CONTROL_PLANE`（送 DNS 模块）；而缺省上游 `8.8.8.8:53`
  在受限网络不可达。
- **实测坑 3**：状态输出不要回显进程 argv 里的 `--dialer`（含节点凭据）；脚本 status 已 redact。
- **验收**（本机 Arch / 6.18.54-lts / wlan0 192.0.2.254 / anytls 真实节点）：
  钩子 4 个（`mini_wan_egress@wlan0`、`mini_wan_ingress@wlan0`、`mini_dae0_ingress@dae0gw`、
  `mini_dae0peer_ingress@dae0gwpeer`）、规则 15 条 match_set；`generate_204` **204**、
  YouTube **200**、出口 IP 为节点侧（203.0.113.45）；relay `conns_total=4 / active=1 / dial_errors=0`、
  下行 931KB；`down` 后 `bpftool net show dev wlan0` 无钩子、直连 baidu 200；二次 `up` 幂等；
  `--dry-run` 零副作用。
- **边界**：IPv6 不代理（`--no-ipv6` 可临时关网卡 v6）；UDP 不代理（QUIC 显式 block，引导浏览器回落 TCP）；
  无 systemd 常驻/崩溃自愈（未做，重启后需重新 up）；Docker/容器流量同样经 wlan0 被接管。

### 11.21 P14（用户态嗅探 / dial_mode 远端域名解析）已验收的行为

（决策与取舍、与 dae 的差异见 ADR-0030；实现 `loader/src/target.rs` +
`loader/src/sniffer.rs` + `main.rs` 的 relay/accepted 路径。）

- **入口**：`--dial-mode ip|domain|domain+`（`domain++` 为兼容别名；CLI > config
  `global.dial_mode` > 默认 `ip`）、`--sniffing-timeout-ms`（默认 100）；
  `gateway.sh` 默认 `domain`；lab 透传 `USE_DIAL_MODE`/`USE_SNIFF_TIMEOUT`；
  `real-node-e2e.sh` 接受 `DIAL_MODE=` 环境变量。
- **实现要点**：
  - `target::Target`（Ip/Domain）+ 逐协议域名编码：RFC1928 风格 0x03（ss/socks5/
    trojan/anytls）、vless/vmess 0x02、tuic v5 0x00、hysteria2 字符串；direct 本地解析；
  - `sniffer::sniff`（纯函数，可测）：TLS ClientHello SNI + HTTP/1.x Host / CONNECT；
  - relay accept 后 `MSG_PEEK` 只读采集（**不消费字节**，泵语义不变），超时回退 IP；
  - SOCKS5 入口：客户端给域名且 dial_mode != ip 时不做本地解析，域名直交节点。
- **可观测**：状态面 `sniffing`（dial_mode / timeout_ms / attempts / hits / misses）。
- **实测**：`cargo test --release` **108/108**（嗅探 8 + 目标 4 + vless 域名头 1 等）；
  `DIAL_MODE=domain REAL_NODE_URL=anytls://… sudo lab/real-node-e2e.sh` →
  日志 `sniff 203.0.113.34:443 → www.gstatic.com（域名交节点远端解析）`、**204**、
  relay `dial_errors=0`；真机网关（wlan0 + anytls 节点）：`sniffing: attempts=10 hits=10
  misses=0`、gstatic **204** / YouTube **200** / 出口 IP=节点侧。
- **边界（如实）**：只做 TCP 嗅探；HTTP/2 明文（h2c）已在 P18e 补上；
  ClientHello 只看首 record（超时回退 IP）；**sniff-punt 已于 P21 补齐（ADR-0045，见 §11.36）**；
  `domain` 即「命中即用域名」（等价 dae `domain+` 的“总是使用”行为，dae 的
  `domain` 带 DNS 缓存/后台探测门槛，未实现）；UDP 目标仍为 IP。

### 11.22 P15（订阅 / 节点组 / 健康检查）已验收的行为

（决策与边界见 ADR-0031；实现 `loader/src/subscribe.rs` + `loader/src/group.rs` +
`config.rs` 提取 + `main.rs` 接线；lab 夹具 `lab/sub_server.py`。）

- **入口**：`--subscribe <url>`（可重复）/ `--group <name>`；config `subscription/node/group` 生效；
  `gateway.sh --subscribe/--group`；活动组选择：`--group` > 组名 `proxy` > 唯一/第一个；
  无 config 组时默认单组 `proxy`（全部节点）。
- **实现要点**：
  - 订阅：HTTP/1.0 GET（3 跳重定向/chunked/webpki TLS/`marked_tcp_connect`/**优先 IPv4**）；
    base64（std/url-safe/no-pad）或明文；逐行链接解析，不支持的行逐条报告（REALITY 等）；
  - filter：`name(精确/keyword:/regex:)`、`subtag`、`!`、行内 AND、多行 OR、空=全部；
  - policy：`min` / `min_moving_avg`（EMA）/ `min_avg10` / `random` / `fixed(i)`；
  - 健康：经节点连接 check 目标（默认 cp.cloudflare.com:80）计 last/EMA/hist10，
    失败按 tolerance 标死；拨号失败自动切换（最多 3 名）；UDP 选支持成员。
- **实测**：`cargo test` **121/121**；lab `subscribe-up` + `test-subscribe`：
  拉取/组构建/首探成功 → kill A 后 4s 标死（interval 1s/tolerance 1）→ failover 经 B 成功；
  真机订阅#2：48×REALITY 逐行跳过 + 18×anytls 入组，`alive 18/18`、EMA 最快 SG 287ms、
  204/YouTube 200、dials=5 failovers=0。
- **边界（如实）**：数据面仍把全部用户组映射 proxy（按规则分派不同组需要数据面携带
  outbound id，未做）；订阅仅启动时拉取（无 update_interval 热更新）；gzip 订阅报错；
  `add_latency`/`region`/多 check URL/`udp_check_dns` 未实现；check 判定 = 拨号 + 任意响应。

### 11.23 P16（IPv6 数据面，TCP 全链）已验收的行为

（决策与边界见 ADR-0032；实现分散在 `ebpf-rs/{common,parse,route,flow,progs,offload}.rs`、
`loader/src/{main,target,outbound,socksin,rules,config,dns}.rs`；lab 夹具 `rules.v6.dae` +
`wan_echo.py`/`ss_server.py` 双栈。）

- **统一元组**：`MiniTuple` 16 字节地址（v4-mapped）+ `is_v6`，eBPF 与 loader 镜像同步
  （40 字节）；`conn_state_map`/`redirect_track`/`fast_sock` 行 key 全量跟随；
  loader 侧 `addr16()`/`mini_tuple_of()`/`tuple_hex()` 支持 v6，状态面 `tuple_hex` 输出不变形状。
- **解析**：`parse_v6`（固定头 + 跳过 hop-by-hop/routing/dest-opts ≤ 4 个；分片返回 None
  走原路径）+ `parse_ip` 统一入口；四个解析函数 `#[inline(always)]`——**别删**：verifier 会报
  `cannot return stack pointer to the caller`（嵌套调用返回 16B 结构体触发 sret 真调用）。
- **交付**：`cb[3]` 携带 v6 标志；sockmap key = `(tcp?0:1) + (v6?2:0)`；loader 建
  `[::]:port`（`IPV6_TRANSPARENT`+`V6ONLY`+`SO_MARK`）注册 key 2（失败降级仅 v4，日志明示）。
- **控制对（最大坑）**：必须照抄上游 `setupIPv6Datapath`：host 侧 `fe80::ecee:eeff:feee:eeee/128
  dev dae0 scope link nodad` + `net.ipv6.conf.dae0.forwarding=1`；daens 侧默认路由 + **静态永久邻居
  `fe80::ecee... lladdr <dae0 MAC>`** + `fwmark→2023/local default`。
  若只配路由不写静态邻居：daens 发 NS、host 回 NA，而 NA 进 daens 会被 `dae0peer_ingress`
  的 `cb[0] != TPROXY_MARK → SHOT` 丢弃（上游 C 同样如此），邻居停在 INCOMPLETE，
  tproxy 的 SYN-ACK 永远发不出去——现象是 `ss` 里 SYN-RECV、用户态 accept 永不返回，
  极易误诊为 listener/sk_assign 问题（实际 sk_assign 的 ftrace 是成功的）。
- **规则**：LPM 键 16B，v4 前缀 +96；`dip/sip` 接受 v6 CIDR；手写 mini 规则 v6 前缀
  必须加引号（`dip('2001:db8:aa::1/128')`），`.dae` 提取器自动加。
- **协议目标**：RFC1928 0x04 / v2ray 0x03 / tuic 0x02 / hy2 `[v6]:port` 字符串；
  `marked_tcp_connect` v6（sockaddr 走 `[u8;128]` 栈缓冲 + `copy_nonoverlapping`，
  注意 `transmute_copy` 不能放大）；SOCKS5 入口接受 ATYP=6；DNS AAAA 同时发布域位图。
- **lab 夹具**：`v6-up`/`test-v6`；拓扑加 LAN/WAN/假公网 v6（`2001:db8:1::/64`、`2001:db8:9::/64`、
  `2001:db8:aa::1/128`），`wan_echo.py` 双栈（v6 socket 必须 `V6ONLY`，否则抢 v4 的 0.0.0.0 绑定）；
  `ss_server.py` 出站 `dial_tcp` 按目标选 family（ATYP=4 支持）。
- **实测**：`cargo test` **122/122**；lab `test-v6` 3 断言全过；回归 `verify` **9/9**、
  DNS **6/6**、订阅组 **3/3**；规则对拍 `parity.sh` **3/3 逐字节一致**（新增
  `rules.v6.dae`：与 dae Go 编译器编译出的 16B LPM 键完全一致）；真机网关 v6：嗅探
  `[2001::1]:443 → www.google.com` `RELAY（远端解析）` 204、字面量 `[2606:4700:4700::1111]:443` 200
  （节点侧 v6 出口可用）。
- **测试基建经验（多实例 + 宿主环境）**：
  - lab 与真网关同时跑时 **map 名字重复**：按名字 `bpftool map list | head -1` 会拿到另一个实例
    （rebind/DNS 位图测试都中过），已新增 `lab/map_id.py`（loader pid 的 `fdinfo` → `map_id`
    ∩ `bpftool map list`）并在 `rebind_tool.py` 复用；内核还会把 map 名截断到 15 字符，匹配要截断。
  - `rebind` 测试时序：2s 陈旧窗口内必须先 dump 绑定（否则 TCP 重传在窗口外合法改绑，必误报），
    stats 放到窗口过后再读（保证两次读取间无新增拒绝）；工具解析要快（早期逐 fd 调 `map show`
    十六个子进程直接吃满窗口）。
  - 宿主 Docker 会把 `FORWARD` 策略设为 DROP：内核直转/故障 fail-open 用例需要按接口
    精确放行（lab `forward_allow/forward_disallow` 在 up/cleanup 成对增删，不碰全局策略）。
  - `test-reload` 会用 reload 变体覆盖 `lab/rules.dae`，早期失败路径不恢复会造成后续 `up`
    加载错规则（症状：代理全挂）；已加 `trap ... EXIT` 恢复。
- **边界（如实）**：**UDP v6 已于 P22 补齐（ADR-0046，§11.37：sockmap key 3 + v6 透明监听 + DNS over UDP6 接管）**；
  余 ICMPv6/分片不处理；UDP relay 目标仍是 `SocketAddr`（UDP 域名拨号未做）；控制对用 veth
  （上游新版 netkit）但配方等价；解析不处理 fragment 头。

### 11.24 P17（geoip/geosite 展开 + pname）已验收的行为

（决策与边界见 ADR-0033；实现 `loader/src/geodata.rs`、`ebpf-rs/src/cgroup.rs`；
夹具 `lab/gen-geo-dat.py`、`lab/rules.geo.dae`、`lab/rules.geoip.dae`、`lab/rules.pname.dae`。）

**A. geoip/geosite（P17a）**

- 读取：手写极简 protobuf（varint + length-delimited；无新依赖）扫 `GeoIPList/GeoSiteList`；
  code 大小写不敏感；`code@attr` 按 `Domain.attribute.key` 过滤；`ext:file[:code]`
  文件名缺 `.dat` 自动补；`inverse_match` 硬错误；`--geodata-dir` > `$DAE_LOCATION_ASSET`
  > 配置目录 > `/etc/dae` > share/dae；懒加载 + (文件,code) 缓存（无 geo 规则不碰磁盘）。
- 展开：`dip(geoip:…)`→裸前缀（v4-mapped+96；**排序+去重**后再入 LPM，对齐 dae
  MergeAndSort/Deduplicate）；`domain(geosite:…)`→域名参数（Plain→keyword、
  RootDomain→suffix、Full→full、Regex→regex），首次出现顺序分组、组内去重；
  展开会写 `geoexp:` 日志（reload 时）。
- 容量：`lpm_array_map` 内层模板 1024 → **2,048,000**（= dae `tproxy.c:75`；
  NO_PREALLOC 不预分配内存）；loader 侧同为 2,048,000 并有超限预检。
- 匹配：domain 走编译期索引（suffix/full Hash 集合；qname 枚举点后缀 O(labels)；
  **支持前导点**：`.example.com` 只匹配子域）；keyword/regex 仍线性。
- `.dae` 语法两处放宽（对拍需要）：值允许 `file:code` 多段冒号；词内 `!` 当普通字符
  （`geolocation-!cn`）——只在“前一个字符是裸词字符”时并词。另解禁 `ipversion(6)`。
- 真实数据清点（`--compile-dump` + `/usr/share/v2ray/*.dat`）：geoip:cn **15,357** 前缀、
  geosite:cn **6,576 suffix + 44 full + 3 regex**、`geolocation-!cn` **25,024** 域，
  ~40ms/集合；与上游清点数值一致（数据版本差异 ±几项）。
- 对拍：Go harness 改用 `assets.NewLocationFinder`；`parity.sh` 生成夹具并 export
  `DAE_LOCATION_ASSET`；`rules.geoip.dae`（CN v4+v6 / US）**逐字节一致**。

**B. pname（P17b）**

- eBPF（`cgroup.rs`）：6 钩子 `cgroup/sock_create|sock_release|connect4|connect6|sendmsg4|sendmsg6`
  全部返回 1；`bpf_get_socket_cookie(ctx)` → `cookie_pid_map`（HASH+NO_PREALLOC，65536；
  `{pname[16],pid,pad,last_seen}`）；已存在只刷新 last_seen，release 删除；
  pname 取 `bpf_get_current_comm`。
- TC（`flow.rs`/`route.rs`）：仅 `is_wan && new_flow` 反查 cookie → `MiniRouteCtx.pname`；
  match 类型 **8**（= dae ProcessName），值区即 16B pname（dae match_set union 同布局）；
  `is_wan && 16B 相等`；命中计数 `mini_stats_map[4]`（数组 4→5）。
- 控制面：多值 OR + NOT；>16B 截断并记 note（dae 记日志）；挂载失败只告警（
  `pname: cgroup2 钩子 x/6`）；状态面 `pname{driver,enabled,hooks,map_entries,hits}`、
  metrics `mini_dae_pname_{hooks,map_entries,hits}`。
- 实测：`cargo test` **131/131**；对拍 `rules.pname.dae` 逐字节（含多值排序/NOT）；
  lab `pname-up`+`test-pname`：python3 命中直连（WAN echo）、curl 不命中走 fallback
  代理（tproxy 回显）、`cookie_pid_map` 可见 `python3`（活连接；关闭即被 release 清掉）、
  状态面 hooks=6/hits≥1；真机网关重启后 cgroup2 **6/6** 挂载、v4 204/v6 200 不回归。
- **踩坑**：
  - 对拍发现 dae `MergeAndSortRulesOptimizer` 对非 ip/sip 函数参数按 **(key,val) 字符串序**
    重排（`pname(wget,bash)` → `bash,wget`；dport 多值同）——已对齐，否则 pname 对拍必
    失败（match_set 下标不同）。
  - cgroup attach 需要 root + cgroup2 挂载；容器里 cgroup namespace 会改变可见层级；
    attach 失败是**静默降级**，排障先看 `status .pname.hooks`。
  - tproxy 回显不是 HTTP 响应，curl≥8 默认拒 HTTP/0.9：测试用 `curl --http0.9`。
  - pname 来源差异（comm vs argv basename）与 geosite 未入对拍写在 ADR-0033。

### 11.25 P18a（DoT/DoH 上游 + 上游抽象）已验收的行为

（决策与边界见 ADR-0034；实现 `loader/src/dnsup.rs` + `main.rs` 接入；夹具
`lab/dns_transport_server.py`、假 DNS 新增夹具名、会话 `dot-up`/`doh-up`/
`dns-udp-up`/`dns-tcpup-up`。）

- 上游对象：`UpstreamSpec{scheme,host,port,path,sni,insecure}` + `parse()`
  （`[v6]`、`?sni=`、`?insecure=1`）；默认端口/默认 path 与 dae 逐项对齐
  （tcp/udp 53；tls/quic 853；https/h3 443 + `/dns-query`）；`h3://` 显式报错。
- 传输：`udp`（marked socket、锁内串行、按 DNS ID 跳杂包）；`tcp`（每查询一条
  2B 分帧）；`tcp+udp` = **UDP 优先，TC/失败才 TCP**；`tls`（DoT）= 持久连接
  （30s 空闲重建、失败丢弃重连一次）+ 2B 分帧；`https`（DoH）= 持久连接 +
  HTTP/1.1 POST `application/dns-message`（Content-Length/chunked）。
- 接入：全局 `UPSTREAM: Mutex<Option<Arc<Upstream>>>`；客户端侧枚举改名
  `ClientProto{Udp,Tcp}`，**不再决定上游传输**（修正旧行为：TCP 客户端 →
  tcp+udp 上游现在也走 UDP 优先）；`resolve_dns` 统一 `exchange()`；
  `--dns-upstream` 接受完整 URL；reload 时按 URL 重建 Upstream 热切换；
  状态面新增 `dns.upstream_url`/`dns.upstream_scheme`（`dns.upstream` 仍为
  解析后地址串，兼容旧脚本）。
- lab 夹具：`dns_transport_server.py`（tls/https 两模式，自签证书转发到假 UDP
  DNS；日志 `TLS-CONN/TLS-QUERY/…`、`DOH-CONN/DOH-QUERY <path> …`）；
  假 DNS 新增 `dot/dot2/doh/doh2/udpup/tcpup.test`。
- 实测：`cargo test` **135/135**（dnsup 4 单测）；lab `test-dot`（2 次查询复用
  1 条 TLS 连接、scheme=tls）、`test-doh`（keep-alive 复用、path=/dns-query）、
  `test-dns-udp`（仅 UDP 上行）、`test-dns-tcpup`（仅 TCP 上行）；明文回归
  `test-dns-cache`/`test-dns-tcp`（已改断言：客户端 TCP → 上游 UDP 优先）/
  `test-dns-edns` 全过；`test-config-reload`（上游 URL 热切换）全过；
  `verify` 9/9；`parity.sh` 5/5。
- 真实公网：`https://223.5.5.5/dns-query?sni=dns.alidns.com` 与
  `tls://223.5.5.5?sni=dns.alidns.com` 在 lab 拓扑内解析 `www.baidu.com`/
  `www.qq.com` 成功（证书校验通过、`upstream_errors=0`）。
- **踩坑/边界**：
  - DoH 用 HTTP/1.1（RFC 8484 名义要求 h2/h3；公共 DoH 实测兼容）；h2 需
    HPACK **编码**侧（现有 hpack.rs 只有解码 + QPACK 静态表），列入修订条件。
  - 上游域名用系统解析器解析**一次**（无 `global.bootstrap_resolver`）；
    IP 字面量 + `?sni=` 完全规避（已实测）。
  - DoT/DoH 持锁串行：单 dns_loop 线程下无争用；线程池化时需去锁重构。
  - DoQ（P18b）、`dns.routing`（P18c）未做（对标表缺口 #5 余项）。

### 11.26 P18b（DoQ，RFC 9250）已验收的行为

（决策与边界见 ADR-0035；实现 `loader/src/dnsup.rs` 的 `exchange_quic`；夹具
`lab/proto-check/doq-server`（Go/quic-go）+ `build-doq-server.sh`；会话 `doq-up`+`test-doq`。）

- 传输：quinn 0.11 + `tuic::runtime()`；ALPN `doq`；keep_alive 5s、idle 60s；
  marked UDP socket；`Endpoint::new` 必须在 `runtime().block_on` 内（否则
  "there is no reactor running" panic）；连接 `Mutex<Option<QuicConn>>` 复用，
  陈旧/已关/失败时丢弃重建（重试一次）。
- RFC 9250：线上 DNS ID 置 0、应答恢复客户端 ID；每查询一条双向流；
  2 字节长度分帧；**查询写完 FIN 后才读**；读完应答 `stop(0x3)` 释放流槽。
- 健壮性（本次踩坑）：三把锁中毒恢复（`into_inner()`，丢弃旧连接重建）；
  `dns_loop`/`handle_tcp_dns_conn` 单查询 `catch_unwind` 隔离——此前一次
  quinn panic 会杀死 DNS 线程、透明 DNS 永久失效（实测碰到并修复）。
- 实测：`cargo test` **136/136**（含 ID 置零/恢复单测）；lab `test-doq`：
  quic-go 服务端交叉验证（doq.test/doq2.test 两次查询复用 **1 条** QUIC 连接、
  状态面 scheme=quic）；真实公网 `quic://dns.alidns.com` 解析 www.baidu.com/
  www.qq.com 成功（upstream_errors=0）；`test-dot` 回归通过。
- 边界：AdGuard 的 UDP 853/784/8853 在本机网络被阻断（openssl -quic 同样超时），
  非实现问题；无 0-RTT、无连接池（锁内串行）。

### 11.27 P18c（`dns.routing` 请求/应答分流 + 多上游）已验收的行为

（决策与边界见 ADR-0036；实现 `loader/src/dnsroute.rs` + `main.rs` 的 UpstreamSet/
Selected/应答重查循环；夹具 `lab/dnsroute.dae`、假 DNS 支持 bind 地址与第二实例。）

- 上游：`dns.upstream { tag: url }` 全部生效（tag 引用编译期校验，未知 tag 硬失败）；
  CLI `--dns-upstream` → 单 tag `default`（覆盖一切）；无 `dns.routing` 段时保持
  legacy 单上游（不改变既有行为）。
- 请求：`qname`（suffix/full/keyword/regex/geosite/ext，裸值默认 suffix）、`qtype`
  （常用类型名表 + 数字）；出口 `reject`（空应答 NOERROR，不缓存）/`asis`（marked UDP
  回客户端原目的；UDP 路径取 IP_ORIGDSTADDR，TCP 路径取透明套接字 local_addr）/tag；
  默认 fallback `asis`；**路由先于缓存**。
- 应答：`qname`/`qtype`/`upstream`（按名字）/`ip`（裸 CIDR/geoip/ext，运行时前缀
  匹配）；出口 `accept`/`reject`（`dns::strip_answers` 清空 answer 后**入缓存**）/
  tag（换上游重查，深度上限 3 = 最多 2 次重查）；默认 fallback `accept`。
- 缓存：键加**作用域**（`tag|<tag>|<url>` / `asis|<addr>` / `legacy|<url>`），
  同 name 不同上游不串答（对照 dae responseCacheKey）。
- `dnsroute` 编译：逐行复刻 dae 链编码（函数末 And、多值中间 Or、行末 Tail；`!`
  作用于整个函数）；geosite/geoip 编译期展开；`sub/node/subnode` 跳过并记 note。
- 状态面：`dns.upstreams{tag→url}`、`dns.routing{request_rules,response_rules,
  request_fallback,response_fallback,rejects,response_rejects,relookups,notes}`。
- 实测：`cargo test` **141/141**（dnsroute 5 项）；lab `test-dnsroute`：reject 空应
  答且上游未见/`qtype(https)` reject/`suffix: via2.test`→up2（日志区分）/缓存作用域
  （up2 仅 1 上行）/fallback→up1/应答 `ip` reject 清空 answer/应答 `ip`→up2 重查/
  `asis` UDP+TCP 回 10.9.9.2:53（WAN ns 假 DNS）/热重载 fallback 切换 + status 计数；
  回归：`verify` 9/9、明文 DNS 三连、`test-config-reload`、`test-dot`、`parity 5/5`。
- 边界：DoH h2/h3、ECS、optimistic cache、`fixed_domain_ttl`、`ipversion_prefer`、
  `bootstrap_resolver`、嗅探 punt **已于 P21/P23 补齐（ADR-0045/0047，§11.36/§11.38）**；`upstream(...)` 按名字比较（不复刻 dae 的
  数值巧合）；`ip()` 线性匹配（dae 用 trie）。
- **自定义名单与分流观测（ADR-0037，mini 扩展）**：`qname(file: 'x.txt')`——每行一条、
  空行/`#` 注释、默认 suffix、行首 `full:/keyword:/regex:` 覆盖、相对路径按规则文件
  目录解析、文件缺失/空域名硬失败；`dns.routing.upstream_hits{tag|asis|legacy|reject}`
  计数。真网关默认：广告数据集 + 用户名单 → reject，`geosite:cn` → 本地明文 router，
  其余 → DoH（实测 `{alidns: 92, router: 13}`）；名单热加载实测（加 `example.com`
  → reload → 空应答；移除 → reload → 恢复）。
- **真机网关实测**（`lab/gateway.dae`，`--config` + `--geodata-dir /usr/share/v2ray`）：
  去掉 `dport(53) -> direct(must)` 后，宿主机 DNS 进控制面 → DoH
  （`https://223.5.5.5/dns-query?sni=dns.alidns.com`）：123 查询 0 错误、
  `getent` 正常；`qname(geosite:category-ads-all) -> reject`（911 域）
  doubleclick.net / adservice.google.com 空应答（rejects=4）；热重载 fallback
  切到 `quic://dns.alidns.com` 后 23ms 解析（DoQ 真机可用）再切回；代理路径
  204 / YouTube 200 / 嗅探+远端解析正常。CLI `--dns-upstream` 现在作为 tag
  `default` 与配置 tags 共存（同名时 CLI 优先），`--config`+`--dns` 不再打断
  路由 tag 引用。

### 11.28 `qname(file:)` 自定义名单 + `upstream_hits`（真网关实用化）

（决策与边界见 ADR-0037；实现 `dnsroute.rs` 的 `resolve_relative`/`parse_domain_file`
与 `main.rs` 的 `DNS_TAG_HITS`；夹具 `lab/blocklist.test.txt`、`lab/blocklist.txt`。）

- `qname(file: '<路径>')`（请求/应答均可）：每行一条；空行/`#`（含行内）注释；
  默认 suffix；行首 `full:/keyword:/regex:` 覆盖类型；相对路径按**规则所在文件**
  目录解析（`Loc.file` → `cfg.files`）；文件缺失/行无域名 = 编译硬失败；空名单合法；
  notes 记 `→ N 条域名`。
- `dns.routing.upstream_hits`：请求选路计数（`tag|asis|legacy|reject`），状态面可见。
- 真网关（`lab/gateway.dae`）：`category-ads-all` + 用户名单 → reject；
  `geosite:cn` → `router`（192.0.2.1:53 明文）；fallback `alidns`（DoH）。
- 实测：`cargo test` **143/143**；lab `test-dnsroute`（名单 suffix/full/注释/
  不上行 + 5 条请求规则 + upstream_hits 断言）；真机：3 条请求规则、105 查询
  0 错误、`upstream_hits {alidns: 92, router: 13}`；名单热加载：加 `example.com`
  → reload → 拦截（rejects+2）→ 移除 → reload → 恢复。

### 11.29 上游 ECS 注入 + 客户端网段路由（真网关精细策略）

（决策与边界见 ADR-0038；实现 `dns.rs::add_ecs/ecs_auto_prefix`、`dnsup.rs` 的
`ecs=` 解析与 `EcsMode`、`dnsroute.rs` 的 `sip`、`main.rs` 的 client/ECS 转发；
夹具 `fake_dns.py` 的 ECS 日志、`lab/dnsroute.dae`/`lab/gateway.dae`。）

- ECS（mini 扩展，上游 URL 参数）：`ecs=auto`（发起方归整 v4 /24、v6 /56）或
  `ecs=<IP>/<prefix>`；发送前尾插 OPT + ECS option 8（地址按前缀截断、
  RDLEN/option-length 分列）；客户端已带 OPT 时透传不注入；注入时缓存作用域
  追加 `|ecs=<前缀>`；应答重查也按新上游重新注入。
- `sip(...)`（mini 扩展，请求函数）：值与 `ip()` 同（CIDR/geoip/ext，支持 `!`）；
  与 qname/qtype 同链；无客户端信息时不命中（`!sip` 命中）；UDP 取 recvmsg
  源地址、TCP 取 peer_addr。
- 真网关：`alidns_ecs: 'https://223.5.5.5/dns-query?sni=dns.alidns.com&ecs=auto'`，
  `qname(geosite:cn) -> alidns_ecs`（router 保留一键可切）。
- 实测：`cargo test` **145/145**（ECS 编码/截断/已带 OPT、`ecs=` 解析、
  `sip` 正/反例）；lab `test-dnsroute`：假上游收到 `ecs=1/24/10.0.0`（客户端
  10.0.0.2）、`qname && sip(10.0.0.0/24)` 命中 up2，7/3 规则矩阵 +
  `upstream_hits` 全断言；真机：`upstream_hits {alidns: 78, alidns_ecs: 8}`、
  86 查询 0 错误。

### 11.30 应答侧 `sip()` + `dns-bench`（上游 A/B 工具）

（决策与边界见 ADR-0039；实现 `dnsroute.rs` 的 `RespKind::Sip`/
`response_select_for`、`main.rs` 的 `run_dns_bench`、`dns.rs` 的
`build_query/first_answer_ttl`。）

- 应答侧 `sip(...)`：与请求侧同义（CIDR/geoip/ext、`!`、同链）；客户端地址由
  main 透传（UDP recvmsg 源地址 / TCP peer_addr）；无来源不命中。
- `dns-bench`（需 root，marked socket 不被网关自身接管）：
  `mini-dae dns-bench --config <file.dae> --names a,b [--tags …] [--runs N]
  [--client <IP>]`，复用生产 `UpstreamSet`（`build_upstream_set_core`），
  输出 ok/min/avg/p50/ancount/TTL；`--client` 供 `ecs=auto`。
- 实测：`cargo test` **146/146**；lab `test-dnsroute` 7/5 规则矩阵全过
  （resp_rejects=2）；真机 A/B（runs=5，client=192.0.2.254）：
  taobao 1.31 / 7.43 / 7.45ms，baidu 1.32 / 7.37 / 7.24ms，
  google 1.32 / 7.25 / 6.81ms（router / DoH / DoH+ECS，均 5/5）；
  ECS 与普通 DoH 的应答 TTL 不同（上游视角随子网变化）。

### 11.31 DNS `pname()` + `dns-bench` 并发/多轮（ADR-0040）

（实现：`ebpf-rs/src/flow.rs` 写 `dns_sender_pname_map`；`loader/src/main.rs`
`lookup_dns_pname`/`dns_pname_gc_loop`/`bpf_map_op_raw`；`dnsroute.rs` 的
`ReqKind::Pname`/`RespKind::Pname`；bench 的 `bench_one`/`pct`。）

- 采集：WAN egress 对 DNS 流（UDP 任意包 / TCP SYN）写入
  `{sip(16B v4-mapped), h_sport(主机序 u16)} → {pname[16], ts_ns}`；
  **教训**：`MiniTuple.sport` 是网络序原始值（报文直接装入），首版按主机序
  当键导致永不命中——写侧改用 `pkt.h_sport`。
- 反查：DNS 线程 dup map fd，raw `BPF_MAP_LOOKUP_ELEM`；条目 >120s 视为陈旧；
  另有 60s 周期 GC 线程（`BPF_MAP_GET_NEXT_KEY/DELETE_ELEM`）避免端口轮换
  耗尽 4096 槽位。
- 规则：请求/应答 `pname(...)`（等值、多值 OR、`!`；无进程信息不命中）。
- bench：`--rounds R --concurrency C`（总样本 runs×R，scoped 线程并发）+ p95。
- 实测：`cargo test` **154/154**；真网关临时规则
  `qname(full: example.com) && pname(python3) -> reject`：python3 空应答、
  getent 正常、TCP DNS 同样命中；移除后恢复。bench（runs=10×rounds=2×
  concurrency=4，client=192.0.2.254）：taobao DoH p50 9.2/p95 124.8ms、
  DoH+ECS 8.2/109.8ms、UDP 1.4/24.8ms；google 类似。

### 11.32 REALITY + Vision（自实现 TLS 1.3，ADR-0041）

（实现：`loader/src/tls13.rs`、`reality.rs`、`vision.rs`；接入
`outbound.rs` 的 `parse_vless`/`Outbound::Vless{reality,flow}` 与 `vless.rs`
addons flow。）

- **tls13.rs**：最小 TLS 1.3 客户端（rustls 换不动的四个点：自定义
  session_id/key_share、取 ECDHE 私钥、按记录粒度直通、证书钩子）。
  Chrome 形状 CH（GREASE/16 套件/ALPN）；key share 含 X25519 与
  X25519MLKEM768（`ml-kem`，REALITY 服务端现在强制要求）；套件
  AES-128/256-GCM 与 ChaCha；Finished/KeyUpdate/alert；`raw_read` 开关。
- **reality.rs**：authKey = HKDF-SHA256(X25519(clientEph, srvStaticPub),
  salt=random[:20], info="REALITY")；session_id 明文前 16B（`[1,8,10,0]` +
  unix + sid8）用 AES-256-GCM 密封（nonce=random[20:32]，AD=session_id
  置零的完整 CH）回填 offset 39；叶证书签名域 == HMAC-SHA512(authKey,
  SPKI ed25519 公钥) 才认可（否则判“被转发到真站”）；极简 DER 解析。
- **vision.rs**：帧 `[UUID?][cmd][len u16BE][pad u16BE][content][padding]`；
  首帧长填充（<900B 垫到 ~900B+）；非 TLS 发 0x01 后直通；下行收到 0x02
  切裸读（记录层多读字节移交）；上行不 splice（只 0x00/0x01，服务端兼容）。
- **互操作踩坑**（对拍 OpenSSL/utls/真站所得）：key_share 的 GREASE 组
  必须同时在 supported_groups（否则 OpenSSL `illegal_parameter`）；GREASE
  share 数据不可为空（utls 拒）；compress_certificate 用 `[02 00 02]`。
- **实测修复**：握手循环「读 socket 后必须 `continue` 回到顶部重判记录完整性」；
  首版读半片后直接 `take_record().expect`，真机健康探测（真实网络分片）即
  panic（group 探针线程传播）；已改为先 continue、缺记录时返回错误而非 panic，
  并留 `hs_io_take_record_partial` 回归单测。
- 实测：`cargo test` **154/154**；ignored e2e：本机 sing-box（REALITY+Vision）
  echo 128KB 往返逐字节一致；本 TLS13 直握 microsoft/openssl；真实订阅节点
  HTTP 200、HTTPS（内层 TLS1.3 触发下行 splice）成功；网关订阅#2
  **66/66 入组** + `gateway.sh test` PASS + curl http/https 正常；lab verify
  9/9 无回归。

### 11.33 P18e 批量收尾（SS2022/http/热更新/并发上限/分片/XDG/嗅探/CI，ADR-0042）

（实现：`loader/src/ss.rs`、`outbound.rs`、`group.rs`、`sniffer.rs`、`geodata.rs`、
`main.rs`；`ebpf-rs/src/parse.rs`；`.github/workflows/ci.yml`、`install/`、`docs/deploy.md`；
lab 夹具 `http_connect_server.py` + `sub_server.py` 每次重读。）

- **SS2022（SIP022）**：`2022-blake3-aes-128-gcm/-aes-256-gcm/-chacha20-poly1305`；
  URI 的 password 是 PSK 标准 base64（**严禁** EVP_BytesToKey，长度硬校验）；
  子密钥 `BLAKE3 derive_key("shadowsocks 2022 session subkey", PSK||salt)`；
  TCP 随机 salt + 长度域独立 AEAD 块 + 首块 timestamp（容差 30s）；UDP
  `session_id(8B)+packet_id(8B)`、每会话重放窗口上限 32；跨实现对端：
  **shadowsocks-rust ssserver**（pacman 安装，`--outbound-fwmark 563` 防自环）。
- **HTTP CONNECT 出站**：`http://[user:pass@]host:port`；读响应头到 `\r\n\r\n`、
  非 200 报错、Basic 认证；`supports_udp()==false`（UDP 调用方直连回退）。
- **订阅热更新**：`GroupRuntime.inner: RwLock<Arc<GroupInner>>`（成员+健康同锁）；
  `replace_members` 按 **name+tag** 继承 health（alive/last/EMA/hist），
  返回（新成员数, 继承数）；拨号/探测持 Arc 快照零锁竞争；
  `do_reload` 成功路径调 `reload_group_members`（重拉订阅→按活动组名回查 filter→替换）；
  无节点/替换后为空 → 保留旧成员。日志：`订阅热更新：N 成员（继承 M 健康），组 X`。
- **并发上限**：`--max-conns N`（0=不限）+ `limit_rejected`（状态面 + Prometheus
  `mini_dae_relay_limit_rejected`）；超限即关连接。
- **udp_check_dns**：组级 > 全局，取第一个、构建期解析（失败禁用并告警）；
  支持 UDP 的成员优先 UDP DNS 探测（最小 A 查询，等应答；3s 读/5s 拨号），
  失败回退 TCP；探测记账统一 `record_probe`。
- **eBPF 分片**（对照 `tproxy.c:1131/1214`）：v4 `frag_off & 0x1fff != 0` 跳过；
  v6 分片扩展头（0x2c）非首片跳过、首片 +8B 继续。**改完已重建对象**（build-ebpf-rs.sh）。
- **h2c**：`PRI * HTTP/2.0` preface + 跳 SETTINGS，首个 HEADERS 帧走最小 HPACK
  （61 项静态表、前缀整数、Huffman 复用 `hpack.rs`）取 `:authority`；
  动态表引用/CONTINUATION/无 END_HEADERS → No（回退 IP）。
- **QUIC**：仅 Initial 识别统计（新 UDP 会话首包长头 && ≥1200B）→ `sniffing.quic_initial`；
  SNI 需解 Initial 加密，本阶段不做（如实）。
- **geodata XDG**：搜索目录加 `$XDG_DATA_HOME/dae` / `~/.local/share/dae` /
  `$XDG_DATA_DIRS/*/dae`（config 目录之后、系统目录之前）。
- **工程化**：GitHub Actions（固定 nightly-2026-09-29 + bpf-linker 0.11.1 + LLVM23；
  loader 构建/单测/eBPF 对象校验；fmt/clippy 刻意不入 CI）、`install/dae-mini.service`（capability 最小集 + `ExecReload`
  SIGHUP）、`install/install.sh`（`--dry-run`/`--uninstall`）、`docs/deploy.md`。
- lab 新命令：`ss2022-up`/`test-ss2022`、`http-up`/`test-http`、`sub-reload-up`/`test-sub-reload`；
  `sub_server.py` 改为按请求重读文件。

### 11.34 P19（多组分派 + 启动期 DNS 自我阻塞修复，ADR-0043）

（实现：`rules.rs`/`config.rs`/`main.rs`/`group.rs`；`lab/gateway.sh`；`lab/gateway.dae`。
真机两次「重启后断网」的根因排查也在此。）

- **多组分派**：组索引 = config `group` 段顺序（direct=0 / block=1 / 用户组
  `GROUP_INDEX_BASE=2` 起）；规则编译期 `resolve_outbound_id` 解析组名→索引
  （未定义回退 proxy，兼容 K3）；`extract_routing` 已定义组名**直通**（不再改写为 proxy）。
  eBPF **零改动**（outbound u8 本来就在 `conn_state_map`）；relay/UDP 每连接按
  5 元组 raw lookup（dup fd）回读 → `by_outbound` 选组，查不到/非用户组回退默认组；
  `GROUP_SET`（RwLock）存全部组 + 默认组（`--group` > proxy > 第一个）；空组也注册
  （保索引稳定）；SIGHUP 逐组 `replace_members`（组集合变更时重建，不继承健康）。
- **踩坑（重要）**：`do_reload(startup=true)` **不得**做需要网络/DNS 的事。启动顺序是
  「挂钩子 → initial do_reload → spawn dns_loop/relay」；其间宿主 DNS 已被拦截但无人
  应答。P18e 的 `reload_group_members` 在启动期重拉订阅解析 66 个节点域名 →
  getaddrinfo 超时卡死主线程（日志停在「解析失败」后再无一行）→ 钩子空挂 = 断网。
  以前 systemd-resolved 缓存有结果时侥幸通过，**重启后缓存为空必现**。修复：startup
  跳过订阅重拉（`build_groups` 刚拉过）；SIGHUP 路径正常热更新。
- **单上游不再拖垮全量**：`build_upstream_set_core` 逐条构造，失败条目跳过 + 告警，
  其余照常生效；legacy = 第一个可用上游；CLI `--dns-upstream` 仍硬错误。
  `gateway.dae` 的 `ali_quic` 改 `quic://223.5.5.5?sni=dns.alidns.com`（同 DoH：
  IP 字面量 + SNI，不依赖自身解析）。
- **启动窗口**：健康探测并发 8→24（66 节点首轮收敛 ~70s→~20s）；`gateway.sh up`
  增加**启动自检**（组内任一成员探测成功 + wget 204；`--wait <秒>`/`--no-wait`/
  `GATEWAY_WAIT_SECS`），超时**自动 down 回滚直连**——up 要么返回可用代理，要么回滚。
- 实测：`cargo test` **176/176**；lab `groups-up`/`test-groups`（8080→node-a /
  8082→node-b 双 ss 服务端日志交叉 + SIGHUP 复测）、`verify` 9/9、订阅/热更新/
  config/dnsroute 回归全过；真机启动自检通过、`gateway.sh test` PASS（204 / 出口 IP /
  DNS ok）、SIGHUP「组 proxy 66 成员（继承 44 健康）」、66/66 alive、0 panic。

### 11.35 P20（QUIC Initial SNI 嗅探，ADR-0044）

（实现：`loader/src/quicsniff.rs`；`sniffer.rs` 抽出 `parse_client_hello_body` 共用；
`main.rs` UDP 新会话接入 + `sniffing.quic_sni`；lab `quic_probe.py` + `test-quic-sniff`。）

- **解密链**（RFC 9001，纯用户态、零新依赖）：固定盐 HKDF-SHA256 → `client in` →
  `quic key/iv/hp`（标签带 `tls13 ` 前缀）→ 头部保护（sample=pn+4 处 16B，AES-ECB 掩码，
  首字节低 4 位出 pn_len）→ AAD=去保护头、AES-128-GCM → CRYPTO(0x06)/PADDING 帧 →
  handshake → 共用 ClientHello 解析取 SNI。
- **接入**：`udp_nat_handle` 新会话慢路径（长头 + ≥1200B）：先计 `quic_initial`，
  命中记 `sniffing.quic_sni` + 日志 `quic sniff … → …（SNI，Initial 解密）`。
- **边界（如实）**：v1 首包、单包（CH 跨包→No）；仅观测不拨号（UDP 域名拨号未做）。
- **测试学**：RFC 9001 A.1 密钥向量 + A.2 官方包（SNI=example.com）黄金用例；
  **真实 quinn 栈**环回口首包跨实现；lab Python 按 RFC 独立造包。
  注意：`quinn::Endpoint::connect` 必须在 tokio 上下文里调（否则 driver spawn panic）；
  测试收尾（drop connecting / close endpoint）也回到运行时上下文。
- 实测：`cargo test` **181/181**；lab `test-quic-sniff` PASS（initial=1 sni=1）、
  `test-udp-relay`（改为前后增量断言，+1 会话）、`test-udp-idle`、`verify` 9/9 全过。

## 12. 用 Rust 重写这套东西的可行性

已验证（本仓库 mini-dae，实测跑通）：

- **加载器/控制面**：aya 0.14 完全能替代 `cilium/ebpf` + bpf2go。
  `Ebpf::load` → `SchedClassifier::attach(TCX)` → `SockMap::set` →
  `Array/HashMap/LPM` 写 map，语义一一对应；TCX 在内核 ≥ 6.6 时自动启用，
  进程退出即摘钩子（比 netlink 模式干净）。
- **规则编译器**：与 dae 原版 Go 编译器（`dae_stub_ebpf` 构建驱动真实
  `RoutingMatcherBuilder`）对同一规则集输出**逐字节一致**；见 `lab/parity/`。
- **内核矩阵**：`lab/matrix.sh` 一条命令在任意内核上重跑全套用例；QEMU +
  virtio-9p 引导第二内核（7.2.8）已实测 8/8。
- **配置栈**：全量 `.dae` 解析（include/schema/行级诊断）在 Rust 侧完整实现，
  与 dae 的 `config_merger.go`/`parser.go` 语义逐条对齐；数据面只吃子集，
  未实现能力显式 deferred（这正是 P3/P5 的待办清单）。
- **DNS 接管**：Rust 侧的 DNS wire 解析/构造、域名匹配（含 regex）、位图计算与应答
  缓存全部单测覆盖，透明 UDP/TCP 收发（含回包源地址绑定、分帧、daens→host ns 连接转交、
  EDNS 尺寸与截断）已在实测中验证；继续做 DoH/DoQ/嗅探 punt 只是在同一模块上加功能，
  不构成架构风险。
- **转发面**：TCP relay/UDP NAT/offload 在 Rust 侧闭环：host ns 拨号 + `SO_MARK` 防
  自环、每连接/每会话线程模型（阻塞 IO + janitor 回收）、`SockHash`/`SkSkb` 注册；
  实测「512KB 流用户态零字节」证明内核拼接可用。dae 的 backlog fuse/计费/看门狗是
  工程细节，不是可行性问题。
- **协议栈**：shadowsocks classic AEAD（TCP/UDP）与 trojan（rustls TLS）已在 Rust 侧
  与独立 Python 实现对端互通（512KB 逐字节一致），vless 与 vmess AEAD（嵌套 KDF/SHAKE128
  分块）同样通过 Python 对端与真实 Go 客户端三方交叉；tuic v5 则用「Go/quic-go 独立参考
  服务端」补齐 QUIC 路径（TCP 流 + DATAGRAM 分片/重组）。证明纯 Rust 实现 dae 的协议
  梯度可行；rustls 的缓冲语义（16KB 明文上限）与 QUIC 的能力协商是两轮最贵的坑，
  已写成不变量/边界。hysteria2 也已在 Rust 侧闭环：最小 HTTP/3 认证（QPACK 编解码，
  其中 Huffman 解码直接决定能否读 quic-go 的响应头）与 Go/http3 独立参考服务端跨实现验收；
  Brutal/salamander 已在 P5-G3b+ 补齐（Brutal 为近似、gecko 不做，见 ADR-0020 与 §11.10），
  udphop/0-RTT/连接迁移的边界同文标注。
- **netns 切换**：`setns(CLONE_NEWNET)` 逐线程生效，和 dae 用
  `vishvananda/netns` 的做法等价；注意 **sysfs 视图跟挂载点走**，
  换 netns 后用 `/sys/class/net` 读 MAC 会读错/读不到，用
  `SIOCGIFHWADDR`（或 netlink）才对。

已全部完成（P9，见 §11.14 与 ADR-0024；C 数据面已在 P9+ 移除，见 §11.15 与 ADR-0025）：

- **eBPF 程序本身用 Rust（aya-ebpf）**：8 个程序与 14 张 map 全部移植完成并通过全量回归；
  唯一未按原路走通的点是 `bpf_loop` 的函数指针 relocation（改用有界循环，语义等价）；
  CO-RE / pname 等 full dae 能力仍不在 mini 范围内（与 C 时期相同）。
  迁移时要额外处理：verifier 对 `bpf_loop` 回调状态机、
  `__sk_buff` 字段读写、CO-RE 读 `task_struct.mm.arg_start` 的表达差异。
- 判断：**数据面与控制面已全 Rust**（单一 aya-ebpf 对象 + aya 加载器）；此前"C 数据面 + Rust 控制面"
  的过渡拆分已于 P9+ 退场——把「cb 标记、MAC 改写、sk_assign、回程路由配方」一并搬迁后，
  行为对齐且回归同口径通过，mini-dae 已经把这条路径跑通并收尾。

### 11.36 P21（sniff-punt：嗅探域名在 relay 侧重判，ADR-0045）已验收的行为

- `--sniff-punt`（或 config `global.auto_sniff_punt: true`；CLI 优先）。生效前提：
  `dial_mode domain/domain+`（不嗅探无域可判，启动日志明确提示）；默认关。
- 重判 VM：`rules::punt_match(PuntCtx{domain,dip,sip,dport,sport,l4proto})` 逐条对照
  `ebpf-rs/src/route.rs`：域位图→`dns::domain_set_matches`（suffix/full/keyword/regex）、
  dip/sip→`lpm_tries`（v4-mapped）、`not`/logical OR(0xFE)/AND(0xFF)/must、dport=53→
  `ControlPlane`；mac/dscp/pname 用户态不可得按不命中（LAN 转发 `is_wan=0`，pname 恒不中）。
- relay 行为：`direct`=直连原始目的 IP（不经组、不本地解析 SNI）、`block`=关连接、
  用户组=换组拨号；NoMatch/无组映射=保持数据面决策；日志 `punt <域>（<orig>）→ …`，
  状态面 `sniffing.punt_enabled/attempts/direct/block/group/keep`。
- 实测：单测 5 项（含 `!domain`+AND 传播与 sticky-OR）；lab `sniff-punt-up`+
  `test-sniff-punt`：direct 不经 ss（仅健康检查目标）、full 域重判到 alt 组（ss-B 日志
  `TCP target=1.1.1.1:8080`、ss-A 无）、block 关连接——三路径计数与日志双证。

### 11.37 P22（UDP over IPv6 全链，ADR-0046）已验收的行为

- eBPF：`listen_socket_map` 3→4 槽（key 3 = IPv6 UDP；progs.rs 的 `(tcp?0:1)+(v6?2:0)` 早已算好）。
- loader：UDP socket 家族化（`sockaddr_any_of`/`sockaddr_to_std` v6）、
  `make_transparent_udp6`（`IPV6_V6ONLY`+`IPV6_RECVORIGDSTADDR`+bind `[::]`）、
  `recv_with_orig_dst` 解 `IPV6_ORIGDSTADDR` cmsg、回包 socket 按族绑定；
  key 3 注册后起第二个 `dns_loop`（host ns）；失败降级仅 v4（日志）。
- 协议：ss UDP v6 目标 ATYP=0x04；`new_marked_udp_for(peer)` 按族建 socket（direct UDP 回退同样吃 v6）。
- 实测：lab `v6-up`+`test-v6`：v6 UDP 2/2 回显 + ss 日志 `UDP target=2001:db8:aa::1:9998`；
  v6 DNS（`[2001:db8:aa::1]:53`）rcode=0/answer=10.9.10.35/回包源=原始目的/假上游恰 1 次；
  TCP 两段回归全过；`udp-up` 用例（v4）回归 PASS。

### 11.38 P23（sticky IP / DoH h2 / bootstrap / DNS 选项，ADR-0047）已验收的行为

- sticky：`resolve` 粘滞 + `note_dial`（连续 3 败作废/成功清零）+ reload `reset`；
  接入 `dial_tcp/dial_udp` 的 `server_addr()` 反馈（协议实现零改动）。
- DoH h2：`h2client`（前言/SETTINGS/PING/HEADERS+HPACK/DATA 流控/CONTINUATION/GOAWAY/RST，
  `:status` 解析含 Huffman 值）；`tls::connect_alpn` 暴露协商结果——ALPN=h2 才发前言，
  H1-only 服务端同连接直走 HTTP/1.1（lab DOH-CONN=1 为证）；ALPN=h2 但握手失败→
  标 `h2_broken` 回退 H1。
- bootstrap：`global.bootstrap_resolver`（逗号分隔；未配置=不启用）；A+AAAA、TC=1 走 TCP、
  SO_MARK；接入 DNS 上游主机名与订阅 URL；启动/reload 热更新。
- DNS 选项：optimistic cache（stale 供应 + TTL 压到上限，`sweep_expired` 尊重窗口）、
  `fixed_domain_ttl`（缓存寿命覆盖；校验放行子段）、`ipversion_prefer`（`has_fresh`→非首选族空 NOERROR）；
  状态面新增 5 个字段。
- 实测：单测 sticky 6/bootstrap 3/h2client 4/dns 3；lab `test-doh-h2`（Go 标准库仅收 h2）、
  `test-doh`（H1 回退 1 连接）、`test-dns-options`（首查 TTL=30；2s 后 stale TTL=7 且不重查；
  AAAA 过滤；仅 AAAA 域不受影响）。

### 11.39 P24（uTLS Chrome-120 / Vision splice / TUIC 0-RTT，ADR-0048）已验收的行为

- ClientHello（仅 REALITY 自实现 TLS 1.3 路径）对齐 uTLS `HelloChrome_120`：签名算法 8 项
  集合与顺序、`supported_versions`=GREASE+1.3+1.2、ALPS(0x4469)、GREASE-ECH（随机
  config_id/enc、payload 144/176/208/240）、Boring padding（(0xff,0x200) 垫到 0x200）。
- Vision 上行 splice 确认：过滤窗口/非 TLS 帧发 CMD_END 后裸写 TLS 应用数据（新回归测试
  `writer_splices_after_filter_window`）；注释已修正。
- TUIC 0-RTT：`into_0rtt()` 早数据发认证+首流；无票据/被拒回退 1-RTT（lab Go 服务端
  场景验证回退无回归）。
- 真机：新二进制重启网关自检通过；订阅含 48 条 REALITY 的组 66/66 alive、代理 204、0 panic。
- 显式边界（本轮不做）：ECH（rustls 无客户端 ECH）、shadow-tls 插件（依赖 fork rustls
  暴露 TLS randoms）、juicity/naive/ssr、rustls 路径 uTLS 逐字节（rustls 不暴露 CH 构造）。

### 11.40 P25（naive h2 CONNECT，ADR-0049）已验收的行为

- `h2client.rs` 抽帧层（`write_frame_raw`/`read_frame_raw`/`strip_padding_io`）后新增
  **HTTP/2 CONNECT 隧道**：`H2Conn::next_stream` + 对端 `SETTINGS_INITIAL_WINDOW_SIZE`（id=4）
  解析；`encode_connect_headers`（HPACK：`:method` 静态名 2 + literal "CONNECT"、`:authority`
  静态名 1、额外头用名字字面量）；`connect_tunnel` reader 线程（DATA→`VecDeque` 并回
  `WINDOW_UPDATE`、对端窗口更新唤醒写者、SETTINGS/PING/RST/GOAWAY 处理）。
- `TunnelReader`/`TunnelWriter`：写侧双向流控（连接级+流级 `wait_window`）、
  `MAX_DATA_FRAME=16384`、`end_stream()` 幂等（半关闭必须发 END_STREAM，否则服务端读不到
  EOF 不回包）、两半都 drop 时 shutdown 底层 TCP 唤醒 reader 线程。
- `outbound::Naive`：`naive+https://`/`naive://` 解析（userinfo 用 `rsplit_once('@')` 兼容
  密码含 `@`）、Basic=`base64(user:pass)`、`tls::connect_alpn` 必须协商 h2（不降级 H1）；
  `naive+quic://`（H3）显式报错不静默。
- lab：Go 标准库参考服务端（`lab/proto-check/naive-server/`）——CONNECT 直挂 Handler
  （经 ServeMux 会 404：CONNECT 的 URL.Path 为空）、出口 socket SO_MARK=0x233 防数据面
  二次接管、上行→客户端逐块 Flush；`test-naive`：交互零延迟（`RECV 0.00`）+ 512KB 逐字节
  （`stream-ok bytes=524288`）+ 服务端日志 `proto=HTTP/2.0` + `offloaded_total=0`（h2 隧道
  不可内核拼接，符合预期）。
- 实测：`cargo test --release` **204/204**（新增 `connect_headers_encode` 字节级、
  `parse_naive_url`）；回归 `verify` 9/9 + `test-sniff-punt`/`test-v6`/`test-doh-h2`/
  `test-dns-options`/`test-tuic` 全 PASS；真机网关 66/66 alive、generate_204→204、0 panic。
- 边界：仅 h2（无 H3/QUIC 形态）、不做跨目标连接池（每客户端连接一条底层 h2 连接）、
  Basic 凭据仅 base64（安全性依赖外层 TLS；`insecure=1` 时有 MITM 风险）、服务端兼容性
  未做矩阵穷举（按 RFC 9113 CONNECT 语义实现，已过 Go 标准库 `net/http` h2）。

### 11.41 P26（HTTP/3：DoH h3 + naive+quic，ADR-0050）已验收的行为

- `h3client.rs`（最小 HTTP/3，与 h2client 对称）：控制流 type 0x00 + 空 SETTINGS（保持
  打开）；`request()`：HEADERS + QPACK + DATA + FIN，读 HEADERS（`:status`）/DATA 直到
  流 FIN；`connect_tunnel()`：CONNECT（`:method`/`:authority`，无 `:scheme`/`:path`）→
  2xx 后返回读写半；隧道数据走 **DATA 帧**（RFC 9114 §4.4），写侧 ≤16KB/帧，
  `end_stream()` 幂等发 FIN；`H3Shared` 同时持有控制流与 endpoint 句柄（两半存活期间
  连接不被驱动回收）。
- `quicvarint.rs`：hysteria2 的 varint 四函数抽成公共模块（RFC 9000 §A.1 五组官方向量
  测试），hy2 与 h3 共用。
- DNS 上游实装 `h3://`（/`http3://`，默认 443、path=/dns-query）：ALPN=h3、5s
  keep-alive/60s 空闲重建、一次失败重建重试、POST application/dns-message。
- `naive+quic://`：`Outbound::Naive { h3: bool }`；QUIC endpoint 带 SO_MARK、ALPN=h3；
  CONNECT 携 Basic；`socket=None`（QUIC 不与 offload 搭配）。
- 踩坑（已修）：tokio **嵌套运行时**——`h3_conn()` 在 `block_on` 内又调 `H3Conn::new`
  的 `block_on` → “Cannot start a runtime from within a runtime” panic；拆成两段调用。
- lab：quic-go fork 离线夹具 `naive-h3-server`/`doh-h3-server`（dae-work 模块图，
  GOPROXY=off）+ `naive-h3-up`/`test-naive-h3`（交互零延迟 + 512KB 双向 + 服务端
  `proto=HTTP/3.0` + `offloaded_total=0`）与 `doh-h3-up`/`test-doh-h3`（两查询各答对、
  `H3 request proto=HTTP/3.0` 恰 2 次、**新建连接恰 1 条**）；`fake_dns` 增
  doh3.test→10.9.10.39 / doh4.test→10.9.10.40。
- 实测：`cargo test --release` **208/208**；lab 两项 PASS；回归 `verify` 9/9 +
  `test-doh-h2`/`test-doh`/`test-doq`/`test-naive`/`test-tuic`/`test-hy2` 全 PASS；
  真机网关 66/66、generate_204→204、0 panic。
- 边界：QPACK 只解静态表/字面量（引用动态表报错；不广告动态表容量、不开 QPACK
  encoder/decoder 流）；无 0-RTT/服务端推送/GOAWAY 重试；`https://` 仍优先 h2，
  H3 需显式 `h3://`。

### 11.42 P27（juicity v0，ADR-0051）已验收的行为

- `juicity.rs`：一个 dialer 复用一条 QUIC 连接（失效重建）；认证单向流
  `[00][00][uuid16][token32]`（token = TLS exporter，label=uuid 裸字节、context=password）
  **保持打开**（不 FIN）；TCP 每连接一条双向流，拨号即写 `[01][TYPE ADDR PORT]`
  （trojan 风格：1/4/3/2，复用 `Target::encode_socks_addr_port`），`shutdown_write`=FIN；
  UDP 每 NAT 会话一条双向流：流首 `[03][会话元数据]`，每帧 `[目标元数据][len u16][payload]`，
  回包跳过来源元数据；读超时机制同 tuic UDP（阻塞 `recv` + `set_read_timeout`）。
- 链接：`juicity://uuid:password@host:port?sni=…&allow_insecure=1`（uuid 严格 32 hex；
  `congestion_control`/`cwnd`/`pinned_certchain_sha256` 忽略，边界见 ADR-0051）。
- lab：Go/quic-go 夹具 `lab/proto-check/juicity-server`（自上游 e2e 服务端移植；协议常量
  就地重述；上游 TCP/UDP socket 打 SO_MARK）+ `juicity-up`/`test-juicity`（TCP：交互 +
  512KB 双向 + `JUICITY tcp target=…` + offloaded=0）与 `juicity-udp-up`/`test-juicity-udp`
  （3/3 + `JUICITY udp session target=…` + `sessions_proxied≥1`/`direct_fallback=0`）。
- 跨实现踩坑：夹具 UDP socket 必须绑 `0.0.0.0:0`（绑 127.0.0.1 时 `sendto` 非回环地址
  EINVAL）；与 naive 夹具同源的 SO_MARK 坑同样适用。
- 实测：`cargo test --release` **215/215**；lab 四项（juicity TCP/UDP + naïve-
  系列回归）全 PASS；真机网关 66/66、generate_204→204、0 panic。
- 边界：不做 full-cone underlay（`IV||PSK` + chacha20-poly1305 包加密的
  `TransportPacketConn`）、0-RTT、本地 CC 参数（均见 ADR-0051）。

### 11.43 P28（ECS 回填 / ecs_cache，ADR-0052）已验收的行为

- `dns::parse_ecs_echo`：从应答 OPT RR（复用 `parse_rrs`）解 ECS option 8 的
  FAMILY/SOURCE-PREFIX/SCOPE-PREFIX/ADDRESS；`dns::truncate_prefix` 与
  `dns::ecs_scope_ladder`（v4：请求前缀 → 本机 /32 → /20/16/12/8/0；
  v6：→ /128 → /48/32/0）构成作用域阶梯。
- `DnsCache::answer_from_cache_ecs`：候选键逐个 `get_scoped`（命中/乐观 stale/过期移除
  逻辑抽自旧单键路径），全 miss 只计一次；`answer_from_cache_scoped` 语义不变。
- 解析路径：`ecs=auto` 现在把**客户端完整地址**交给 `add_ecs`（它自己按前缀截断写线上）——
  此前 `ecs_auto_prefix` 先截断会让 /32 回填键变成整个 /24 共享（已修）；应答带 ECS
  回显时按 `truncate(回显地址, scope)` 入缓存（scope=0 → `0.0.0.0/0` / `::/0` 全局键），
  无回显回退请求前缀；状态面新增 `dns.ecs.echo`/`dns.ecs.scope`。
- lab：`lab/ecscache.dae`（上游 `udp://…?ecs=auto`）+ fake_dns 的 `ECS_ECHO` 表
  （`ecs0.test` scope=0、`ecs16.test` scope=16，回显地址/source 照抄客户端请求）+
  `ecscache-up`/`test-ecs-cache`：两域各两次查询，假上游各只收到 1 次（第二次命中
  回填键）；状态面 `echo>=2`、`scope=="10.0.0.0/16"`。
- 单测：`parse_ecs_echo`（v4 scope=0/16、无 OPT/非法输入）、`ecs_scope_ladder`
  （v4/v6 顺序与截断）、缓存集成三例（/16 跨 /24 命中、不同 /16 不命中；/0 全局；
  /32 仅本机命中；自带 OPT 不入缓存）。
- 实测：`cargo test --release` **215/215**；lab `test-ecs-cache` PASS；回归 `verify` 9/9 +
  `test-dns-cache`/`test-dns-options`/`test-dnsroute` 全 PASS；真机网关重启自检 + 66/66 + 0 panic。
- 边界：不做乐观预取/后台刷新；客户端自带 OPT（含 ECS）仍透传且不入缓存（既有语义）；
  阶梯只覆盖规范前缀，非规范回显 scope（如 /22）按 miss 保守处理。

### 11.44 P29（optimistic cache 后台刷新，ADR-0053）已验收的行为

- `dns.rs`：`DnsCache` 增 `refreshing: HashSet<String>`（key = 命中的作用域键 +
  qname + qtype + 上游 URL）+ `begin_refresh`/`end_refresh`/`refreshing_len`
  （单飞）；`answer_from_cache_ecs_full` 返回 `CacheHit{resp, stale, scope}`；
  `remove_scoped` 精确删键；`is_negative_response`（NXDOMAIN / 空 NOERROR /
  有 A / SERVFAIL 四态）。
- `main.rs`：stale 命中→照常回客户端→单飞 spawn 刷新线程（同一 `query_send` 含
  ECS；失败保留旧条目；成功按 `ecs_effective_scope` 入缓存；负答不可缓存时
  取代过期正值）；状态面 `dns.refresh.{spawned,coalesced,err,inflight}`。
- 实测：`cargo test --release` **217/217**；lab `test-dns-options`：stale TTL=7 后
  假上游在 3s 内恰好收到 1 次刷新（共 2 次，单飞）；状态面 spawned≥1、err=0。
- 边界：刷新不做应答路由重查（用原上游结果）；刷新线程与主路径共享全局缓存锁
  （短临界区）。

### 11.45 P30（SSR origin+plain，ADR-0054）已验收的行为

- `ssr_cipher.rs`：流密码层对齐 Go `ciphers/stream_cipher.go`——方法 aes-128/192/256-cfb、
  aes-128/192/256-ctr、chacha20-ietf、rc4-md5、rc4-md5-6；key 用 EVP_BytesToKey(MD5，无盐)
  派生（`d_i = MD5(d_{i-1} || password)`）；CFB-128/CTR 在 AES 块加密上自实现、跨调用
  保持流状态；`rc4-md5(-6)` 为 RC4(MD5(key||iv))；`chacha20-ietf` 用 RustCrypto
  `chacha20`；`init_encrypt()` 首调用生成随机 IV，连接内复用。
- `ssr.rs`：`ssr://` 链接解析（外层 base64 或内层明文均可；password 字段 URL-safe
  base64；格式 `server:port:proto:method:obfs:pwd`）；连接层 origin proto + plain obfs：
  首写 `[IV][E(目标地址||载荷)]`、首读先取对端 IV；`proto`/`obfs` 非 origin/plain
  解析即报错（不静默降级）；无插件。
- `outbound.rs`：`Outbound::Ssr`（name/server_addr/dial_tcp）+ `parse()` 支持 `ssr://`
  （先剥 `#fragment`）。
- lab：`lab/proto-check/ssr-server`（从 olicesx/outbound 移植的 Go 参考服务端；
  上游 socket 打 `SO_MARK=0x233`）；`ssr-up`/`test-ssr`：交互 + 512KB 逐字节 +
  服务端 `SSR connect target=` 日志 + 状态面（conns>=2、dial_errors=0、
  bytes_up/down>=512KiB、offloaded=0）。
- 实测：`cargo test` **225/225**（ssr_cipher 5 例（含 Go 黄金向量）+ ssr 3 例）；
  lab `test-ssr` PASS；回归 `verify` 9/9 + `test-juicity`/`test-tuic`/`test-dns-options`
  PASS；真机网关 down→up 自检通过 + `gateway.sh test`（出口 IP + DNS 快检）+
  日志 0 panic。
- 边界：`auth_*`（auth_aes128_md5/sha1、auth_sha1_v4、auth_chain_a/b）与 `obfs_*`
  （http_simple/http_post/random_head/tls1.2_ticket_auth）及 UDP 未做——
  解析即显式报错；SSR 连接不可与 TCP offload 拼接。

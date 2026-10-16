//! 数据面公共常量与结构（与 loader 侧的镜像定义逐字节一致）。

#![allow(dead_code)]

pub const TPROXY_MARK: u32 = 0x800_0000;
pub const SODAMA_DAE_SOCKET_MARK: u32 = 0x233;
pub const SODAMA_PACKET_HOST: u32 = 0;
pub const SODAMA_PACKET_OTHERHOST: u32 = 3;
pub const AF_INET: u32 = 2;

/// 可编译 match_set 上限（= dae `Makefile:14` 的 `MAX_MATCH_SET_LEN ?= 1024`；
/// `routing_map`/`lpm_array_map`/`domain_routing_map` 位图容量均由此推导）。
/// 数据面扫描为有界循环（`while i < rules_len`，`rules_len` 由本常量经 map 元数据限界）。
pub const SODAMA_MAX_MATCH_SET_LEN: u32 = 1024;
pub const SODAMA_EPOCH_SLOT_NUM: u32 = 2;
pub const SODAMA_EPOCH_SLOT_RESULT_SHIFT: u64 = 41;
pub const SODAMA_RESULT_MARK_SHIFT: u64 = 8;
pub const SODAMA_RESULT_MUST_SHIFT: u64 = 40;

pub const SODAMA_TCP_CONN_TIMEOUT_NS: u64 = 300_000_000_000;
pub const SODAMA_UDP_CONN_TIMEOUT_NS: u64 = 60_000_000_000;
pub const SODAMA_REDIRECT_REBIND_STALE_NS: u64 = 2_000_000_000;

pub const SODAMA_OUTBOUND_DIRECT: u8 = 0x00;
pub const SODAMA_OUTBOUND_BLOCK: u8 = 0x01;
pub const SODAMA_OUTBOUND_MUST_RULES: u8 = 0xFC;
pub const SODAMA_OUTBOUND_CONTROL_PLANE: u8 = 0xFD;
pub const SODAMA_OUTBOUND_LOGICAL_OR: u8 = 0xFE;
pub const SODAMA_OUTBOUND_LOGICAL_MASK: u8 = 0xFE;

pub const SODAMA_MATCH_DOMAIN_SET: u8 = 0;
pub const SODAMA_MATCH_IP_SET: u8 = 1;
pub const SODAMA_MATCH_SOURCE_IP_SET: u8 = 2;
pub const SODAMA_MATCH_PORT: u8 = 3;
pub const SODAMA_MATCH_SOURCE_PORT: u8 = 4;
pub const SODAMA_MATCH_L4_PROTO: u8 = 5;
pub const SODAMA_MATCH_IP_VERSION: u8 = 6;
pub const SODAMA_MATCH_MAC: u8 = 7;
/// P17b：pname（= dae `MatchType_Pname`；进程名 16 字节精确比较）
pub const SODAMA_MATCH_PNAME: u8 = 8;
pub const SODAMA_MATCH_DSCP: u8 = 9;
pub const SODAMA_MATCH_FALLBACK: u8 = 10;

pub const SODAMA_L4_TCP: u32 = 1;
pub const SODAMA_L4_UDP: u32 = 2;
pub const SODAMA_IPV4: u32 = 1;
pub const SODAMA_IPV6: u32 = 2;
pub const SODAMA_IPV6_BYTE_LENGTH: u8 = 16;

pub const SODAMA_STATE_BAD_RULE: u8 = 1 << 0;
pub const SODAMA_STATE_GOOD_SUBRULE: u8 = 1 << 1;
pub const SODAMA_STATE_MUST: u8 = 1 << 2;
pub const SODAMA_STATE_DNS_QUERY: u8 = 1 << 3;

pub const SODAMA_FLAG_SUSPEND: u32 = 1;
/// M1：热路径调试打印门控（默认关；loader `--ebpf-debug` 置位）。
pub const SODAMA_FLAG_DEBUG: u32 = 2;
/// A2 #3：trace 过滤器 map 的尺寸（单元素；loader 写，热路径读）。
pub const SODAMA_TRACE_FILTER_SIZE: u32 = 1;

pub const SODAMA_STAT_UDP_CONN_OVERFLOW: u32 = 0;
pub const SODAMA_STAT_TCP_CONN_OVERFLOW: u32 = 1;
/// redirect_track 因表满拒写（对照 dae `BPF_STATS_REDIRECT_OVERFLOW`）。
pub const SODAMA_STAT_REDIRECT_OVERFLOW: u32 = 2;
pub const SODAMA_STAT_REDIRECT_UPDATE_FAILED: u32 = 3;
/// 回程绑定被竞争发布者拒改（新鲜期内；对照 dae `BPF_STATS_REDIRECT_REBIND_REJECTED`）。
pub const SODAMA_STAT_REDIRECT_REBIND_REJECTED: u32 = 4;
/// 纯 SYN 被拒改活跃流的缓存路由（同代次；对照 dae `BPF_STATS_SYN_REBIND_REJECTED`）。
pub const SODAMA_STAT_SYN_REBIND_REJECTED: u32 = 5;
/// 无任何缓存路由的已建立 TCP 直通（重启后的存量流；对照 dae
/// `BPF_STATS_STATELESS_TCP_PASSTHROUGH`，仅计数不告警）。
pub const SODAMA_STAT_STATELESS_TCP_PASSTHROUGH: u32 = 6;
/// 非首分片直通（对照 dae `BPF_STATS_FRAG_TAIL_PASSED`）。
pub const SODAMA_STAT_FRAG_TAIL_PASSED: u32 = 7;
/// IP 头解析成功但 L4 非 TCP/UDP（对照 dae `BPF_STATS_PARSE_UNSUPPORTED_L4`）。
pub const SODAMA_STAT_PARSE_UNSUPPORTED_L4: u32 = 8;
/// WAN-ingress 无主 UDP（正向状态缺失；照 dae `BPF_STATS_UNSOLICITED_UDP_SEEN`，
/// 仅计数：状态仍创建（is_wan_ingress_direction 标记保留）。
pub const SODAMA_STAT_UNSOLICITED_UDP_SEEN: u32 = 9;
/// 对照 dae `BPF_STATS_SOCKMARK_FALLBACK`。sodama 无 so_mark 注入（mark 校验走
/// 专用 socket 标记位），此键保留占位以对齐 dae 键域，恒 0。
pub const SODAMA_STAT_SOCKMARK_FALLBACK: u32 = 10;
/// C3：事件无法入 ringbuf（满）被丢弃的次数（对照 dae `BPF_STATS_EVENT_DROP`）。
pub const SODAMA_STAT_EVENT_DROPS: u32 = 11;
/// 纯 SYN 的缓存路由属旧代次：删条目重路由（对照 dae
/// `BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE`）。
pub const SODAMA_STAT_REBIND_REROUTED: u32 = 12;
pub const SODAMA_STAT_OFFLOAD_REDIRECTS: u32 = 13;
pub const SODAMA_STAT_OFFLOAD_VERDICTS: u32 = 14;
pub const SODAMA_STAT_PNAME_HITS: u32 = 15;
/// 对标批：fentry/kprobe `skb_send_sock` 记录的 offload 推送字节总数（按 CPU 分桶）。
pub const SODAMA_STAT_OFFLOAD_SENT_BYTES: u32 = 16;
/// 对标批：`offload_sent` 记账写入失败（表满）次数——记账丢失必须可数。
pub const SODAMA_STAT_ACCOUNT_DROPS: u32 = 17;
/// 对标批：`skb_send_sock` 探针被调用次数。**诊断用**：`0` = 钩子没落在内核推流路径上
/// （符号被 LTO 内联 / 该内核走别的推流函数）——后两个键与它一起定位 0 字节问题。
pub const SODAMA_STAT_PROBE_CALLS: u32 = 18;
/// 对标批：探针读 `sk_buff` 字段/重建四元组失败次数（偏移不符、边界不合法）。
pub const SODAMA_STAT_PROBE_PARSE_FAIL: u32 = 19;
/// 对标批：探针解析出四元组但被 `offload_guard` 过滤的次数（键与注册侧不一致）。
pub const SODAMA_STAT_PROBE_GUARD_MISS: u32 = 20;
/// sodama 自有：offload verdict 因背压 fuse 暂停而改走 SK_PASS 的包数
/// （对照 dae `tcp_offload_pause` 语义，dae 无对应计数键；fuse 可测性所需）。
pub const SODAMA_STAT_OFFLOAD_PAUSE_PASSES: u32 = 21;
/// `sodama_stats_map` 容量：0..=12 对齐 dae `enum bpf_stats_key` 键域，
/// 13..=20 为 sodama 自有键（offload/探针），留余量。
pub const SODAMA_STAT_MAP_SIZE: u32 = 24;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_HLEN: u32 = 14;

/// IPv4 地址 → v4-mapped 16 字节形式（网络序字节；LPM/元组统一用 16 字节地址）。
pub fn v4_mapped_bytes(addr: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&addr.to_ne_bytes());
    out
}

/* errno（负值，与 C 的返回一致） */
pub const EPERM: i64 = -1;
pub const ENOEXEC: i64 = -8;
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaConfig {
    pub tproxy_port: u32,
    pub dae0_ifindex: u32,
    /// 数据面代次（u16）：loader 每次**重载**递增、启动随机非 0；写入 conn_state 与
    /// routing_handoff 条目，纯 SYN 按「代次 + epoch 槽是否仍匹配」决定拒改（同代）
    /// 还是重路由（异代）。对照 dae `PARAM.datapath_generation`（`nextDatapathGeneration`，
    /// `control/datapath_generation.go:20-27`）；sodama 无 reload 代次交接，
    /// 语义对齐在「同 4 元组纯 SYN」判定上。
    pub datapath_generation: u16,
    pub dae0peer_mac: [u8; 6],
    /// A2 #6：控制面自身 socket 的 SO_MARK（`so_mark_from_dae`，默认
    /// `SODAMA_DAE_SOCKET_MARK`；数据面按它跳过自环）。
    pub so_mark: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SodaLpmKey {
    pub prefixlen: u32,
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaPortRange {
    pub start: u16,
    pub end: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SodaMatchUnion {
    pub value: [u8; 16],
    pub index: u32,
    pub port: SodaPortRange,
    pub l4proto_mask: u32,
    pub ipversion_mask: u32,
    pub dscp: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaMatchSet {
    pub u: SodaMatchUnion,
    pub not: u8,
    pub type_: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SodaRouteCtx {
    pub l4proto_mask: u32,
    pub ipversion_mask: u32,
    pub h_sport: u16,
    pub h_dport: u16,
    pub dscp: u8,
    pub is_wan: u8,
    pub state: u8,
    pub routing_epoch_slot: u8,
    pub domain_word_idx: u32,
    pub domain_word_bits: u32,
    pub domain_word_cached: u8,
    pub pad_domain: [u8; 3],
    /// P17b：本次报文的进程名（仅 WAN egress 新连接由 cookie_pid_map 反查；
    /// 其它路径全 0 → `pname()` 正规则不命中，与 dae 语义一致）
    pub pname: [u8; 16],
    pub result: i64,
    pub lpm_saddr: SodaLpmKey,
    pub lpm_daddr: SodaLpmKey,
    pub lpm_mac: SodaLpmKey,
}

#[repr(C)]
pub struct SodaRouteLoopCtx {
    pub work: *mut SodaRouteCtx,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SodaTuple {
    /// 统一 16 字节地址：IPv4 为 v4-mapped（::ffff:a.b.c.d），IPv6 为原始 16 字节。
    pub sip: [u8; 16],
    pub dip: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub l4proto: u8,
    /// 0=IPv4 / 1=IPv6（用于 sockmap key 选路与会话一致性）
    pub is_v6: u8,
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaConnState {
    pub last_seen_ns: u64,
    pub mark: u32,
    pub outbound: u8,
    pub must: u8,
    pub has_routing: u8,
    pub l4proto: u8,
    pub is_wan_ingress_direction: u8,
    /// 写入路由时的 epoch 槽编码（slot+1；0 = 未取到）；与 `datapath_generation`
    /// 一起供「纯 SYN 重绑」判定（对照 dae `conn_state.routing_epoch_slot` /
    /// `conn_state.datapath_generation`，`tproxy.c:3110-3124`）。
    pub routing_epoch_slot: u8,
    pub pad: [u8; 2],
    pub datapath_generation: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaRedirectEntry {
    pub ifindex: u32,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub from_wan: u8,
    pub pad: [u8; 3],
    pub last_seen_ns: u64,
}

/// P17b：pname 采集（cgroup 钩子写入，TC 侧按 socket cookie 反查）。
/// 对照 dae `struct pid_pname`（tproxy.c:403-417）：pname 16 字节（含 NUL）、
/// pid（tgid）、last_seen_ns。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaPidPname {
    pub pname: [u8; 16],
    pub pid: u32,
    pub pad: [u8; 4],
    pub last_seen_ns: u64,
}

/// P18c+：DNS 发送方键（client 地址 16B + 源端口；TC WAN egress 新 UDP DNS 流写入，
/// 控制面按 (client addr, sport) 反查，供 `dns.routing` 的 `pname()` 匹配）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaDnsSenderKey {
    pub addr: [u8; 16],
    pub port: u16,
    pub pad: u16,
}

/// P18c+：DNS 发送方进程名（与 SodaPidPname 同的 16B pname；`ts_ns` 供控制面判陈旧）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaDnsSenderPname {
    pub pname: [u8; 16],
    pub pad: u16,
    pub _pad2: [u8; 6],
    pub ts_ns: u64,
}

/// A2 #3：trace 过滤器（单元素结构；loader 的 `trace` 子命令写，热路径按字段匹配
/// ——内核侧过滤，对照 dae trace 的过滤语义；洪泛时不会把无关报文灌进 ringbuf）。
pub const SODAMA_TRACE_L4_ANY: u32 = 0;
pub const SODAMA_TRACE_IPVER_ANY: u32 = 0;
pub const SODAMA_TRACE_IPVER_V4: u32 = 1;
pub const SODAMA_TRACE_IPVER_V6: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SodaTraceFilter {
    /// 0 = 关闭（默认）；非 0 = 开启。
    pub enabled: u32,
    /// 0 = 不限；否则要求 `l4proto` 匹配（6=TCP / 17=UDP）。
    pub l4proto: u32,
    /// 0 = 不限；否则要求 sport 或 dport 匹配（host 序）。
    pub port: u32,
    /// 0 = 不限；`SODAMA_TRACE_IPVER_*`。
    pub ipver: u32,
    /// 0 = 全部判决；非 0 = 仅 SHOT（drop-only，对照 dae `--drop-only`）。
    pub drop_only: u32,
}

/// 事件类型（对照 dae `enum dae_event_type` 的编号）。
pub const SODAMA_EVENT_BLOCKED: u32 = 0;
pub const SODAMA_EVENT_UDP_CONN_OVERFLOW: u32 = 1;
pub const SODAMA_EVENT_TCP_CONN_OVERFLOW: u32 = 2;
/// 出口不存活导致的阻断（每 outbound 1s 限速；对照 dae `DAE_EVENT_BLOCKED_ALIVE`）。
pub const SODAMA_EVENT_BLOCKED_ALIVE: u32 = 3;
pub const SODAMA_EVENT_REDIRECT_REBIND_REJECTED: u32 = 4;
/// 纯 SYN 被拒改活跃流的缓存路由（同代次；对照 dae `DAE_EVENT_SYN_REBIND_REJECTED`）。
pub const SODAMA_EVENT_SYN_REBIND_REJECTED: u32 = 5;
/// 6/7 在 dae 侧为「保留、永不发出」（计数替代：STATELESS_TCP_PASSTHROUGH /
/// FRAG_TAIL_PASSED），编号不占用。
pub const SODAMA_EVENT_REDIRECT_UPDATE_FAILED: u32 = 8;
/// 纯 SYN 的缓存路由属旧代次：删条目重路由（对照 dae `DAE_EVENT_SYN_REBIND_REROUTED`）。
pub const SODAMA_EVENT_SYN_REBIND_REROUTED: u32 = 9;
/// A2 #3：trace 事件（sodama 自有，dae 无此事件——dae 的 trace 是独立 eBPF 程序）。
/// 携带完整五元组 + 判决（判决编码在 `SodaEvent.pad[0]`，见 `SODAMA_VERDICT_*`），
/// 由 loader 的 `trace` 子命令按秒开启，写 trace 文件供 CLI 过滤。
pub const SODAMA_EVENT_TRACE: u32 = 10;
/// trace 事件的判决编码（写入 `SodaEvent.pad[0]`）。
pub const SODAMA_VERDICT_OK: u8 = 0;
pub const SODAMA_VERDICT_SHOT: u8 = 1;
pub const SODAMA_VERDICT_REDIR: u8 = 2;

/// 事件限速键（0..=255 = per-outbound，供 BLOCKED_ALIVE 用；256+ 保留键域，
/// 对照 dae `control/event_rate_contract.go`：256 blocked / 257 redirect_rebind /
/// 258 overflow / 259 syn_rebind / 260 stateless_tcp / 261 frag_tail）。
pub const SODAMA_EVENT_RATE_BLOCKED: u32 = 256;
pub const SODAMA_EVENT_RATE_REDIRECT_REBIND: u32 = 257;
pub const SODAMA_EVENT_RATE_OVERFLOW: u32 = 258;
pub const SODAMA_EVENT_RATE_SYN_REBIND: u32 = 259;
pub const SODAMA_EVENT_RATE_STATELESS_TCP: u32 = 260;
pub const SODAMA_EVENT_RATE_FRAG_TAIL: u32 = 261;
/// 事件限速键域上界（含；容量 = MAX+1 = 262）。
pub const SODAMA_EVENT_RATE_KEY_MAX: u32 = SODAMA_EVENT_RATE_FRAG_TAIL;
/// 限速窗口：每键每窗口最多一条（对照 dae `EVENT_RATE.window_ns` = 1s）。
pub const SODAMA_EVENT_RATE_WINDOW_NS: u64 = 1_000_000_000;

/// `event_rate_map` 容量（键 0..=261）：0..=255 为 per-outbound（BLOCKED_ALIVE），
/// 256+ 为保留键。
pub const SODAMA_EVENT_RATE_MAP_SIZE: u32 = SODAMA_EVENT_RATE_KEY_MAX + 1;

/// 出口连通性表（Array；键 = outbound*6 + domain*2 + ipversion，容量对齐 dae
/// `outbound_connectivity_map` 的 1536 = 256 outbounds × 3 domains × 2 ipversions）。
/// domain：0=TCP、1=DNS UDP、2=data UDP；ipversion：0=IPv4、1=IPv6。
pub const SODAMA_CONNECTIVITY_MAP_SIZE: u32 = 1536;
pub const SODAMA_CONNECTIVITY_PER_OUTBOUND: u32 = 6;
pub const SODAMA_CONNECTIVITY_DOMAIN_TCP: u32 = 0;
pub const SODAMA_CONNECTIVITY_DOMAIN_DNS_UDP: u32 = 1;
pub const SODAMA_CONNECTIVITY_DOMAIN_DATA_UDP: u32 = 2;

/// `tcp_offload_pause` 背压 fuse 表容量（键 = fast_sock 键；键在 = 暂停内核拼接）。
pub const SODAMA_OFFLOAD_PAUSE_MAP_SIZE: u32 = 8192;
/// `routing_handoff_map` 容量（与 dae `MAX_ROUTING_HANDOFF_NUM` 同）。
pub const SODAMA_ROUTING_HANDOFF_MAP_SIZE: u32 = 65536;

/// C3：数据面事件（72 字节，字段布局对照 dae `struct dae_event`；
/// `pid/pname` 暂置 0——sodama 的 pname 采集在 cgroup 钩子，TC 路径不可得）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaEvent {
    pub timestamp: u64,
    pub type_: u32,
    pub pid: u32,
    pub pname: [u8; 16],
    pub outbound: u8,
    pub l4proto: u8,
    pub pad: [u8; 2],
    pub sip: [u8; 16],
    pub dip: [u8; 16],
    pub sport: u16,
    pub dport: u16,
}

/// 对标批：fentry/kprobe 记账所需的 `struct sk_buff` 字段偏移（字节）。
/// loader 在加载时从 `/sys/kernel/btf/vmlinux` 解出真实偏移后写入——aya-ebpf 不提供
/// CO-RE field access，故用「用户态 BTF 解析 + map 传参」替代 `BPF_CORE_READ_INTO`
/// （dae 用的是 clang CO-RE，见 `include/tcp_offload.h:tcp_offload_skb_key`）。
pub struct SodaTraceParam {
    pub network_header: u32,
    pub transport_header: u32,
    pub tail: u32,
    pub head: u32,
}

/// C4：XDP 计量探针的计数键（per-CPU array）。
pub const SODAMA_XDP_PACKETS: u32 = 0;
pub const SODAMA_XDP_BYTES: u32 = 1;
pub const SODAMA_XDP_IPV4: u32 = 2;
pub const SODAMA_XDP_IPV6: u32 = 3;
pub const SODAMA_XDP_OTHER: u32 = 4;
pub const SODAMA_XDP_MAP_SIZE: u32 = 8;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SodaRoutingHandoffEntry {
    pub last_seen_ns: u64,
    /// 路由结果位编码（与 `route.rs` 返回的 result 同布局：低 8 位 outbound，
    /// bit 8..39 mark，bit 40 must，bit 41..42 epoch 槽编码）。
    pub result: u64,
    pub datapath_generation: u16,
    pub dscp: u8,
    pub pad: u8,
    pub mac: [u8; 6],
}

/// handoff 条目有效期（控制面读取时的陈旧判定；dae 无显式 TTL，
/// 靠 conn_state 优先 + reload 换代自然失效——sodama 取 30s 与 TCP 短命流量语义相合）。
pub const SODAMA_HANDOFF_TTL_NS: u64 = 30_000_000_000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaDomainRouting {
    /// 位图字数 = MAX_MATCH_SET_LEN/32（1024 → 32；= dae `tproxy.c:380`）。
    pub bitmap: [u32; (SODAMA_MAX_MATCH_SET_LEN / 32) as usize],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SodaRoutingEpochIp {
    pub slot: u32,
    pub addr: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SodaParseResult {
    pub tuples: SodaTuple,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub l4proto: u8,
    pub new_flow: u8,
    pub is_v4: u8,
    pub dscp: u8,
    pub h_sport: u16,
    pub h_dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpHdr {
    pub vihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Ipv6Hdr {
    /// version(4) + traffic class(8) + flow label(20)，NBO
    pub vtc_flow: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_flags: u16,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

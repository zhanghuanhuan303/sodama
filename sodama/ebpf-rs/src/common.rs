//! 数据面公共常量与结构（与 loader 侧的镜像定义逐字节一致）。

#![allow(dead_code)]

pub const TPROXY_MARK: u32 = 0x800_0000;
pub const SODAMA_DAE_SOCKET_MARK: u32 = 0x233;
pub const SODAMA_PACKET_HOST: u32 = 0;
pub const SODAMA_PACKET_OTHERHOST: u32 = 3;
pub const AF_INET: u32 = 2;

pub const SODAMA_MAX_MATCH_SET_LEN: u32 = 64;
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

pub const SODAMA_STAT_REBIND_REJECTED: u32 = 0;
pub const SODAMA_STAT_REDIRECT_UPDATE_FAILED: u32 = 1;
pub const SODAMA_STAT_OFFLOAD_REDIRECTS: u32 = 2;
pub const SODAMA_STAT_OFFLOAD_VERDICTS: u32 = 3;
pub const SODAMA_STAT_PNAME_HITS: u32 = 4;
/// C3：事件无法入 ringbuf（满）被丢弃的次数（对照 dae `BPF_STATS_EVENT_DROP`）。
pub const SODAMA_STAT_EVENT_DROPS: u32 = 5;
/// 对标批：fentry/kprobe `skb_send_sock` 记录的 offload 推送字节总数（按 CPU 分桶）。
pub const SODAMA_STAT_OFFLOAD_SENT_BYTES: u32 = 6;
/// 对标批：conn_state_map 写入失败（表满）次数（对照 dae `BPF_STATS_UDP/TCP_CONN_OVERFLOW`
/// 的合并计数；sodama 不拆分 TCP/UDP 两个键，事件里按 l4proto 区分）。
pub const SODAMA_STAT_CONN_OVERFLOW: u32 = 7;
/// 对标批：`offload_sent` 记账写入失败（表满）次数——记账丢失必须可数。
pub const SODAMA_STAT_ACCOUNT_DROPS: u32 = 8;
/// `sodama_stats_map` 容量（已用键 0..=8，留余量给后续批次）。
pub const SODAMA_STAT_MAP_SIZE: u32 = 16;

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
    pub dae0peer_mac: [u8; 6],
    pub pad: [u8; 2],
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
    pub pad: [u8; 3],
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

/// 事件类型（对照 dae `enum dae_event_type` 的编号；仅实现子集，未实现的编号保留不占用）。
/// 未实现：3=BLOCKED_ALIVE（sodama 数据面无 outbound 存活态）、5=SYN_REBIND_REJECTED、
/// 6/7/9（dae 侧为保留/计数替代或数据面代次概念）。
pub const SODAMA_EVENT_BLOCKED: u32 = 0;
pub const SODAMA_EVENT_UDP_CONN_OVERFLOW: u32 = 1;
pub const SODAMA_EVENT_TCP_CONN_OVERFLOW: u32 = 2;
pub const SODAMA_EVENT_REDIRECT_REBIND_REJECTED: u32 = 4;
pub const SODAMA_EVENT_REDIRECT_UPDATE_FAILED: u32 = 8;

/// 事件限速键（对照 dae `EVENT_RATE.{blocked,redirect_rebind,overflow}_key`；
/// 0..=255 保留给 per-outbound 事件，sodama 暂未实现 BLOCKED_ALIVE）。
pub const SODAMA_EVENT_RATE_BLOCKED: u32 = 256;
pub const SODAMA_EVENT_RATE_REDIRECT_REBIND: u32 = 257;
pub const SODAMA_EVENT_RATE_OVERFLOW: u32 = 258;
/// 事件限速键域大小（含 0..=258）。
pub const SODAMA_EVENT_RATE_KEY_MAX: u32 = 258;
/// 限速窗口：每键每窗口最多一条（对照 dae `EVENT_RATE.window_ns` = 1s）。
pub const SODAMA_EVENT_RATE_WINDOW_NS: u64 = 1_000_000_000;

/// `event_rate_map` 容量（键 0..=258）。
pub const SODAMA_EVENT_RATE_MAP_SIZE: u32 = SODAMA_EVENT_RATE_KEY_MAX + 1;

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
#[derive(Clone, Copy)]
pub struct SodaDomainRouting {
    pub bitmap: [u32; 2],
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

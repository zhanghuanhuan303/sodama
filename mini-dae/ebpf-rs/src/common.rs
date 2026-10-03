//! 数据面公共常量与结构（与 loader 侧的镜像定义逐字节一致）。

#![allow(dead_code)]

pub const TPROXY_MARK: u32 = 0x800_0000;
pub const MINI_DAE_SOCKET_MARK: u32 = 0x233;
pub const MINI_PACKET_HOST: u32 = 0;
pub const MINI_PACKET_OTHERHOST: u32 = 3;
pub const AF_INET: u32 = 2;

pub const MINI_MAX_MATCH_SET_LEN: u32 = 64;
pub const MINI_EPOCH_SLOT_NUM: u32 = 2;
pub const MINI_EPOCH_SLOT_RESULT_SHIFT: u64 = 41;
pub const MINI_RESULT_MARK_SHIFT: u64 = 8;
pub const MINI_RESULT_MUST_SHIFT: u64 = 40;

pub const MINI_TCP_CONN_TIMEOUT_NS: u64 = 300_000_000_000;
pub const MINI_UDP_CONN_TIMEOUT_NS: u64 = 60_000_000_000;
pub const MINI_REDIRECT_REBIND_STALE_NS: u64 = 2_000_000_000;

pub const MINI_OUTBOUND_DIRECT: u8 = 0x00;
pub const MINI_OUTBOUND_BLOCK: u8 = 0x01;
pub const MINI_OUTBOUND_MUST_RULES: u8 = 0xFC;
pub const MINI_OUTBOUND_CONTROL_PLANE: u8 = 0xFD;
pub const MINI_OUTBOUND_LOGICAL_OR: u8 = 0xFE;
pub const MINI_OUTBOUND_LOGICAL_MASK: u8 = 0xFE;

pub const MINI_MATCH_DOMAIN_SET: u8 = 0;
pub const MINI_MATCH_IP_SET: u8 = 1;
pub const MINI_MATCH_SOURCE_IP_SET: u8 = 2;
pub const MINI_MATCH_PORT: u8 = 3;
pub const MINI_MATCH_SOURCE_PORT: u8 = 4;
pub const MINI_MATCH_L4_PROTO: u8 = 5;
pub const MINI_MATCH_IP_VERSION: u8 = 6;
pub const MINI_MATCH_MAC: u8 = 7;
/// P17b：pname（= dae `MatchType_Pname`；进程名 16 字节精确比较）
pub const MINI_MATCH_PNAME: u8 = 8;
pub const MINI_MATCH_DSCP: u8 = 9;
pub const MINI_MATCH_FALLBACK: u8 = 10;

pub const MINI_L4_TCP: u32 = 1;
pub const MINI_L4_UDP: u32 = 2;
pub const MINI_IPV4: u32 = 1;
pub const MINI_IPV6: u32 = 2;
pub const MINI_IPV6_BYTE_LENGTH: u8 = 16;

pub const MINI_STATE_BAD_RULE: u8 = 1 << 0;
pub const MINI_STATE_GOOD_SUBRULE: u8 = 1 << 1;
pub const MINI_STATE_MUST: u8 = 1 << 2;
pub const MINI_STATE_DNS_QUERY: u8 = 1 << 3;

pub const MINI_FLAG_SUSPEND: u32 = 1;

pub const MINI_STAT_REBIND_REJECTED: u32 = 0;
pub const MINI_STAT_REDIRECT_UPDATE_FAILED: u32 = 1;
pub const MINI_STAT_OFFLOAD_REDIRECTS: u32 = 2;
pub const MINI_STAT_OFFLOAD_VERDICTS: u32 = 3;
pub const MINI_STAT_PNAME_HITS: u32 = 4;

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
pub struct MiniConfig {
    pub tproxy_port: u32,
    pub dae0_ifindex: u32,
    pub dae0peer_mac: [u8; 6],
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MiniLpmKey {
    pub prefixlen: u32,
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MiniPortRange {
    pub start: u16,
    pub end: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union MiniMatchUnion {
    pub value: [u8; 16],
    pub index: u32,
    pub port: MiniPortRange,
    pub l4proto_mask: u32,
    pub ipversion_mask: u32,
    pub dscp: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MiniMatchSet {
    pub u: MiniMatchUnion,
    pub not: u8,
    pub type_: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MiniRouteCtx {
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
    pub lpm_saddr: MiniLpmKey,
    pub lpm_daddr: MiniLpmKey,
    pub lpm_mac: MiniLpmKey,
}

#[repr(C)]
pub struct MiniRouteLoopCtx {
    pub work: *mut MiniRouteCtx,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MiniTuple {
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
pub struct MiniConnState {
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
pub struct MiniRedirectEntry {
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
pub struct MiniPidPname {
    pub pname: [u8; 16],
    pub pid: u32,
    pub pad: [u8; 4],
    pub last_seen_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MiniDomainRouting {
    pub bitmap: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MiniRoutingEpochIp {
    pub slot: u32,
    pub addr: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MiniParseResult {
    pub tuples: MiniTuple,
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

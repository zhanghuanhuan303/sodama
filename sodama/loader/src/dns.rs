// SPDX-License-Identifier: GPL-2.0
//! DNS 处理（P3a 基础 + P3b-1 缓存/TCP）。
//!
//! 范围：`解析请求 → （缓存命中则回包）／转发上游 → 从应答中取 A 记录 →
//! 按 domain 规则计算位图 → 写缓存`。缓存语义：
//! - key =（小写 qname, qtype, qclass）；
//! - 正缓存寿命 = answer 段最小 TTL；负缓存（NXDOMAIN / NODATA）= SOA 的
//!   `min(SOA.TTL, SOA.MINIMUM)`，无 SOA 时用默认值；
//! - 命中时改写事务 ID、按客户端大小写回填 question、按已过秒数递减 TTL
//!   （additional 段与 OPT 不动）；
//! - TC=1、SERVFAIL/REFUSED 等 rcode 不入缓存。
//!
//! 对照 dae：位图语义（bit i = 第 i 个 match_set 命中该 IP）来自
//! `control/routing_matcher_builder.go addDomain` 与 `tproxy.c route_match_domain_set`；
//! 命中时按剩余寿命递减 TTL 对照 dae `dns_cache.go`（“a cache hit the remaining
//! lifetime of the entry”）；负缓存寿命对照 RFC 2308。
//!
//! 仍未做（P3b-2 剩余）：DoH/DoQ、嗅探 punt（`ROUTE_STATE_DNS_QUERY`）、
//! `dns.routing` 请求/应答分流、除 DO 外的 EDNS options（带 options 的查询不缓存，
//! 但也不会按 ECS 等选项分开解析）。见 ADR-0014。

pub use crate::rules::DomainSetSpec;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

// ---------------------------------------------------------------- DNS wire

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(off)?, *buf.get(off + 1)?]))
}

/// 写大端 u16（单测与假上游构包用）。
#[allow(dead_code)]
fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// 读取（可能被压缩指针引用的）域名；返回 (小写去尾点名称, 下一字节偏移)。
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut off = start;
    let mut next = None;
    let mut hops = 0usize;
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            off += 1;
            if next.is_none() {
                next = Some(off);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *buf.get(off + 1)? as usize;
            if next.is_none() {
                next = Some(off + 2);
            }
            hops += 1;
            if hops > 16 {
                return None; // 防御压缩环
            }
            off = ptr;
            continue;
        }
        let label = buf.get(off + 1..off + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        off += 1 + len;
    }
    Some((labels.join(".").to_lowercase(), next?))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// 解析查询报文（只要求 header + 第一个 question）。
pub fn parse_query(buf: &[u8]) -> Option<Question> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = read_u16(buf, 4)?;
    if qdcount == 0 {
        return None;
    }
    let (qname, off) = read_name(buf, 12)?;
    let qtype = read_u16(buf, off)?;
    let qclass = read_u16(buf, off + 2)?;
    Some(Question {
        qname,
        qtype,
        qclass,
    })
}

/// question 段结束（answer 段开始）的字节偏移。
pub fn questions_end(buf: &[u8]) -> Option<usize> {
    let qdcount = read_u16(buf, 4)?;
    let mut off = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(buf, off)?;
        off = next.checked_add(4)?;
    }
    (off <= buf.len()).then_some(off)
}

// ---------------------------------------------------------------- RR 遍历

pub const SEC_ANSWER: u8 = 0;
pub const SEC_AUTHORITY: u8 = 1;
pub const SEC_ADDITIONAL: u8 = 2;
/// OPT 伪记录（RFC 6891）：TTL 字段是扩展 rcode/flags，不是寿命。
pub const RR_OPT: u16 = 41;

#[derive(Debug, Clone, Copy)]
pub struct Rr {
    pub section: u8,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    /// RR 名起始偏移（截断时原样搬移 OPT 用）
    pub name_off: usize,
    /// TTL 字段在报文中的偏移（递减改写用）。
    pub ttl_off: usize,
    pub rdata_off: usize,
    pub rdlen: usize,
}

/// 遍历 question 之后的所有 RR。任何一段不完整就返回 `None`（用于“不缓存坏包”）。
pub fn parse_rrs(buf: &[u8]) -> Option<Vec<Rr>> {
    let qd = read_u16(buf, 4)? as usize;
    let an = read_u16(buf, 6)? as usize;
    let ns = read_u16(buf, 8)? as usize;
    let ar = read_u16(buf, 10)? as usize;
    let mut off = 12;
    for _ in 0..qd {
        let (_, next) = read_name(buf, off)?;
        off = next.checked_add(4)?;
    }
    let mut out = Vec::with_capacity(an + ns + ar);
    for (section, count) in [(SEC_ANSWER, an), (SEC_AUTHORITY, ns), (SEC_ADDITIONAL, ar)] {
        for _ in 0..count {
            let name_off = off;
            let (_, next) = read_name(buf, off)?;
            let rtype = read_u16(buf, next)?;
            let rclass = read_u16(buf, next + 2)?;
            let ttl = u32::from_be_bytes([
                *buf.get(next + 4)?,
                *buf.get(next + 5)?,
                *buf.get(next + 6)?,
                *buf.get(next + 7)?,
            ]);
            let rdlen = read_u16(buf, next + 8)? as usize;
            let rdata_off = next + 10;
            if rdata_off.checked_add(rdlen)? > buf.len() {
                return None;
            }
            out.push(Rr {
                section,
                rtype,
                rclass,
                ttl,
                name_off,
                ttl_off: next + 4,
                rdata_off,
                rdlen,
            });
            off = rdata_off + rdlen;
        }
    }
    Some(out)
}

/// 从应答报文中取出 A 记录 IPv4 地址（跳过 CNAME 等；AAAA 忽略并计数）。
pub fn answer_a_records(buf: &[u8]) -> (Vec<[u8; 4]>, usize) {
    let (a, aaaa) = answer_a_and_aaaa_records(buf);
    (a, aaaa.len())
}

/// 取应答中的 A 与 AAAA 地址（跳过 CNAME 等；供域位图发布）。
pub fn answer_a_and_aaaa_records(buf: &[u8]) -> (Vec<[u8; 4]>, Vec<[u8; 16]>) {
    let mut out = Vec::new();
    let mut v6 = Vec::new();
    let Some(rrs) = parse_rrs(buf) else {
        return (out, v6);
    };
    for rr in rrs.iter().filter(|r| r.section == SEC_ANSWER) {
        if rr.rclass != 1 {
            continue;
        }
        if rr.rtype == 1 && rr.rdlen == 4 {
            if let Some(b) = buf.get(rr.rdata_off..rr.rdata_off + 4) {
                out.push([b[0], b[1], b[2], b[3]]);
            }
        } else if rr.rtype == 28 && rr.rdlen == 16 {
            if let Some(b) = buf.get(rr.rdata_off..rr.rdata_off + 16) {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                v6.push(a);
            }
        }
    }
    (out, v6)
}

/// 构造一个 A 记录应答（供单测与假上游使用；保留问题段）。
#[allow(dead_code)]
pub fn build_a_response(query: &[u8], addrs: &[[u8; 4]], ttl: u32) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut out = query.to_vec();
    out[2] |= 0x80; // QR=1, 保留 RD
    out[7] = out[7].wrapping_add(0); // 保持原 ancount 前先清零
                                     // ANCOUNT = addrs.len()，NS/AR = 0
    let n = addrs.len() as u16;
    out[6..8].copy_from_slice(&n.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    for a in addrs {
        put_u16(&mut out, 0xc00c); // 指向 question 的 qname
        put_u16(&mut out, 1); // A
        put_u16(&mut out, 1); // IN
        out.extend_from_slice(&ttl.to_be_bytes());
        put_u16(&mut out, 4);
        out.extend_from_slice(a);
    }
    Some(out)
}

// ---------------------------------------------------------------- EDNS

/// 查询中的 EDNS(0) 信息（OPT 伪记录，RFC 6891）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EdnsInfo {
    pub present: bool,
    /// 客户端公布的 UDP 载荷尺寸（OPT class）。
    pub udp_size: u16,
    /// DO 位（OPT TTL 的 0x8000）——DNSSEC OK，影响上游应答内容，必须入缓存键。
    pub do_bit: bool,
    /// OPT rdata 非空（ECS 等选项）；这类查询不缓存也不命中缓存。
    pub has_options: bool,
}

pub fn query_edns(buf: &[u8]) -> EdnsInfo {
    let mut info = EdnsInfo::default();
    let Some(rrs) = parse_rrs(buf) else {
        return info;
    };
    if let Some(opt) = rrs
        .iter()
        .find(|r| r.section == SEC_ADDITIONAL && r.rtype == RR_OPT)
    {
        info.present = true;
        info.udp_size = opt.rclass;
        info.do_bit = opt.ttl & 0x8000 != 0;
        info.has_options = opt.rdlen > 0;
    }
    info
}

/// 客户端可接受的 UDP 应答尺寸：无 EDNS = 512（RFC 1035），有 EDNS = 公布值（下限 512）。
pub fn client_udp_size(query: &[u8]) -> usize {
    let e = query_edns(query);
    if !e.present {
        512
    } else {
        e.udp_size.max(512) as usize
    }
}

/// 首条 A/AAAA 应答的 TTL（工具展示用；无则 None）。
pub fn first_answer_ttl(resp: &[u8]) -> Option<u32> {
    for rr in parse_rrs(resp)? {
        if rr.section == SEC_ANSWER && (rr.rtype == 1 || rr.rtype == 28) {
            return Some(rr.ttl);
        }
    }
    None
}

/// 构造一个最小查询报文（工具/测试用：单 question、RD=1、无 EDNS）。
pub fn build_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

/// 自动 ECS 前缀（RFC 7871 常见实践）：v4 /24、v6 /56（本机/客户端地址归整）。
pub fn ecs_auto_prefix(client: IpAddr) -> (IpAddr, u8) {
    match client {
        IpAddr::V4(a) => {
            let o = a.octets();
            (IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], 0)), 24)
        }
        IpAddr::V6(a) => {
            let mut o = a.octets();
            for b in o.iter_mut().skip(7) {
                *b = 0;
            }
            (IpAddr::V6(std::net::Ipv6Addr::from(o)), 56)
        }
    }
}

/// 给查询追加 EDNS Client Subnet 选项（RFC 7871）：尾插一个 OPT RR（UDP 尺寸 4096），
/// RDATA 为 ECS（family/source-prefix/scope=0/地址截断到前缀字节）。
/// 查询已带 OPT 时返回 `None`（不改客户端自己的 EDNS，ECS 交由客户端/上游协商）。
pub fn add_ecs(query: &[u8], prefix: (IpAddr, u8)) -> Option<Vec<u8>> {
    if query.len() < 12 || query_edns(query).present {
        return None;
    }
    let (ip, plen) = prefix;
    let (family, addr): (u16, Vec<u8>) = match ip {
        IpAddr::V4(a) => (1, a.octets().to_vec()),
        IpAddr::V6(a) => (2, a.octets().to_vec()),
    };
    let max = if family == 1 { 32 } else { 128 };
    if plen == 0 || plen > max {
        return None;
    }
    let nbytes = (plen as usize).div_ceil(8);
    let mut addr = addr[..nbytes].to_vec();
    let rem = plen as usize % 8;
    if rem != 0 {
        if let Some(last) = addr.last_mut() {
            *last &= 0xFFu8 << (8 - rem);
        }
    }
    // ECS option data = FAMILY(2) + SOURCE-PREFIX(1) + SCOPE(1) + ADDRESS；
    // OPT RDATA = OPTION-CODE(2) + OPTION-LENGTH(2) + ECS option data。
    let opt_data_len = 4 + addr.len();
    let rdata_len = 4 + opt_data_len;
    let mut out = Vec::with_capacity(query.len() + 11 + rdata_len);
    out.extend_from_slice(query);
    let arcount = u16::from_be_bytes([query[10], query[11]]).saturating_add(1);
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    out.push(0); // root name
    out.extend_from_slice(&RR_OPT.to_be_bytes());
    out.extend_from_slice(&4096u16.to_be_bytes()); // class = UDP payload size
    out.extend_from_slice(&0u32.to_be_bytes()); // ext-rcode/flags
    out.extend_from_slice(&(rdata_len as u16).to_be_bytes()); // RDLEN
    out.extend_from_slice(&8u16.to_be_bytes()); // OPTION-CODE = ECS
    out.extend_from_slice(&(opt_data_len as u16).to_be_bytes()); // OPTION-LENGTH
    out.extend_from_slice(&family.to_be_bytes());
    out.push(plen);
    out.push(0); // SCOPE PREFIX-LENGTH（请求端置 0）
    out.extend_from_slice(&addr);
    Some(out)
}

// ---------------------------------------------------------------- P28 ECS 回填

/// 上游应答中的 ECS 回显（RFC 7871 §7.3：FAMILY/SOURCE-PREFIX/SCOPE/ADDRESS）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcsEcho {
    /// 1 = IPv4，2 = IPv6
    pub family: u16,
    /// OPTION-DATA 里的地址（客户端子网回显）
    pub src: IpAddr,
    pub src_prefix: u8,
    /// 上游声明的作用域前缀（0 = 全局）
    pub scope_prefix: u8,
}

/// 从上游应答的 OPT RR 里解出 ECS 回显；没有/非法 → None。
pub fn parse_ecs_echo(resp: &[u8]) -> Option<EcsEcho> {
    let opt = parse_rrs(resp)?.into_iter().find(|r| r.rtype == RR_OPT)?;
    let rd = resp.get(opt.rdata_off..opt.rdata_off.checked_add(opt.rdlen)?)?;
    let mut pos = 0usize;
    while pos + 4 <= rd.len() {
        let code = u16::from_be_bytes([rd[pos], rd[pos + 1]]);
        let len = u16::from_be_bytes([rd[pos + 2], rd[pos + 3]]) as usize;
        pos += 4;
        let data = rd.get(pos..pos.checked_add(len)?)?;
        if code == 8 {
            if data.len() < 4 {
                return None;
            }
            let family = u16::from_be_bytes([data[0], data[1]]);
            let src_prefix = data[2];
            let scope_prefix = data[3];
            let max = match family {
                1 => 32u8,
                2 => 128u8,
                _ => return None,
            };
            if src_prefix > max || scope_prefix > max {
                return None;
            }
            let nbytes = (src_prefix as usize).div_ceil(8);
            let addr = data.get(4..4 + nbytes)?;
            let src = match family {
                1 => {
                    let mut o = [0u8; 4];
                    o[..nbytes.min(4)].copy_from_slice(&addr[..nbytes.min(4)]);
                    IpAddr::V4(std::net::Ipv4Addr::from(o))
                }
                _ => {
                    let mut o = [0u8; 16];
                    o[..nbytes.min(16)].copy_from_slice(&addr[..nbytes.min(16)]);
                    IpAddr::V6(std::net::Ipv6Addr::from(o))
                }
            };
            return Some(EcsEcho {
                family,
                src,
                src_prefix,
                scope_prefix,
            });
        }
        pos += len;
    }
    None
}

/// 地址按前缀截断（主机位清零）。
pub fn truncate_prefix(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let p = prefix.min(32) as u32;
            let masked = if p == 0 {
                0
            } else {
                u32::from(v4) & (!0u32 << (32 - p))
            };
            IpAddr::V4(masked.into())
        }
        IpAddr::V6(v6) => {
            let p = prefix.min(128) as u32;
            let raw = u128::from(v6);
            let masked = if p == 0 {
                0
            } else {
                raw & (!0u128 << (128 - p))
            };
            IpAddr::V6(masked.into())
        }
    }
}

/// P28：ECS 作用域候选阶梯（从请求前缀到更宽 scope，再到本机前缀）：
/// - 请求前缀（注入时用的 /24 或 /56，等值命中）；
/// - 本机前缀（/32、/128；上游回填 scope=32 时同一客户端仍能命中）；
/// - 更粗规范前缀（命中上游回填的较宽 scope，如 /16、/0 全局）。
/// 只会“向宽”复用（候选前缀 ⊆ 条目 scope），不会把窄答案给宽网段。
pub fn ecs_scope_ladder(ip: IpAddr, prefix: u8) -> Vec<(IpAddr, u8)> {
    let host = if ip.is_ipv4() { 32 } else { 128 };
    let mut out: Vec<(IpAddr, u8)> = Vec::new();
    let push = |out: &mut Vec<(IpAddr, u8)>, p: u8| {
        let p = p.min(host);
        let t = truncate_prefix(ip, p);
        if !out.iter().any(|(a, b)| *a == t && *b == p) {
            out.push((t, p));
        }
    };
    push(&mut out, prefix);
    push(&mut out, host);
    let coarser: &[u8] = if ip.is_ipv4() {
        &[24, 20, 16, 12, 8, 0]
    } else {
        &[56, 48, 32, 0]
    };
    for &p in coarser {
        if p < prefix {
            push(&mut out, p);
        }
    }
    out
}

/// UDP 截断：超过客户端公布尺寸时丢弃 answer/authority/additional、置 TC=1；
/// 若原应答带 OPT 则保留（EDNS 客户端期望看到 OPT）。逐跳 IP 分片不属于本层，
/// 交给内核（本地回包 MTU 足够）。
pub fn truncate_for_udp(response: &[u8], max_size: usize) -> Vec<u8> {
    if response.len() <= max_size {
        return response.to_vec();
    }
    let Some(qend) = questions_end(response) else {
        return response.to_vec();
    };
    let mut out = Vec::with_capacity(max_size + 16);
    out.extend_from_slice(&response[..12]);
    out[2] |= 0x02; // TC=1
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&response[12..qend]);
    if let Some(rrs) = parse_rrs(response) {
        if let Some(opt) = rrs.iter().find(|r| r.rtype == RR_OPT) {
            let end = opt.rdata_off + opt.rdlen;
            let opt_len = end.saturating_sub(opt.name_off);
            if end <= response.len() && out.len() + opt_len <= max_size {
                out.extend_from_slice(&response[opt.name_off..end]);
                out[10..12].copy_from_slice(&1u16.to_be_bytes());
            }
        }
    }
    out
}

// ---------------------------------------------------------------- 缓存

pub const DNS_CACHE_MAX_ENTRIES: usize = 1024;
/// 缓存寿命上限（秒）；超过则提前过期重查（客户端可见 TTL 仍从原值递减）。
pub const DNS_CACHE_MAX_TTL: u32 = 3600;
/// 负缓存（NXDOMAIN / NODATA）无 SOA 时的默认寿命。
pub const DNS_CACHE_NEGATIVE_DEFAULT_TTL: u32 = 30;
// ---------------------------------------------------------------- 缓存

/// P18c：请求路由 reject 的空应答（NOERROR + 回显 question；对照 dae
/// `sendRejectWithResponseWriter_`：RcodeSuccess、无 answer）。
/// 保持 RD 位，置 QR/RA；不携带 EDNS OPT（dae 的空应答同样不附）。
pub fn empty_noerror(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let qdcount = read_u16(query, 4).unwrap_or(0);
    if qdcount == 0 {
        return Vec::new();
    }
    let Some(qend) = questions_end(query) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(12 + (qend - 12));
    out.extend_from_slice(&query[..12]);
    out[2] |= 0x80; // QR=1
    out[2] &= !0x02; // TC=0
    out[3] = 0x80 | (query[3] & 0x01); // RA=1，保留 RD
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..qend]);
    out
}

/// P38：构造 SERVFAIL 应答（保留 question；QR=1，RCODE=2）——
/// `dns.bind` 查询失败/超时的兑底应答（对照 dae `dns_listener` 的 SERVFAIL 行为）。
pub fn servfail(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let qdcount = read_u16(query, 4).unwrap_or(0);
    if qdcount == 0 {
        return Vec::new();
    }
    let Some(qend) = questions_end(query) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(12 + (qend - 12));
    out.extend_from_slice(&query[..12]);
    out[2] |= 0x80; // QR=1
    out[2] &= !0x02; // TC=0
    out[3] = 0x80 | 0x02 | (query[3] & 0x01); // RA=1，RCODE=SERVFAIL(2)
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..qend]);
    out
}

/// P18c：应答路由 reject——删掉 answer 段（对照 dae `respMsg.Answer = nil`），
/// 保留 question 与其余段（authority/additional）及头部 flag/rcode。
pub fn strip_answers(response: &[u8]) -> Vec<u8> {
    let Some(qend) = questions_end(response) else {
        return response.to_vec();
    };
    let Some(rrs) = parse_rrs(response) else {
        return response.to_vec();
    };
    // answer 段里最后一条 RR 的结束位置（无 answer 则即 question 结束）
    let mut answer_end = qend;
    let mut ancount = 0u16;
    for rr in &rrs {
        if rr.section == SEC_ANSWER {
            answer_end = rr.rdata_off + rr.rdlen;
            ancount += 1;
        }
    }
    if ancount == 0 {
        return response.to_vec();
    }
    let mut out = Vec::with_capacity(response.len());
    out.extend_from_slice(&response[..12]);
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&response[12..qend]);
    // 跳过 answer 段；authority/additional 原样保留
    if answer_end <= response.len() {
        out.extend_from_slice(&response[answer_end..]);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
    /// DNSSEC OK：影响上游是否附带 RRSIG，对照 dae 的 EDNS 元数据保留。
    do_bit: bool,
    /// P18c：请求路由作用域（上游 tag|url / asis 地址 / legacy）；
    /// 同 name 走不同上游不得共享缓存（对照 dae responseCacheKey 含 upstreamIndex）。
    scope: String,
}

struct CacheEntry {
    response: Vec<u8>,
    /// 应答中 question 段结束位置（命中时按客户端 question 回填）。
    question_end: usize,
    stored: Instant,
    ttl: u32,
}

/// 上游应答缓存（对照 dae `dns_cache.go` 的最小语义：正/负缓存 + 命中时按剩余寿命递减 TTL）。
/// P23：新增 optimistic_cache（过期条目在窗口内继续以 stale TTL 供应）。
pub struct DnsCache {
    map: HashMap<CacheKey, CacheEntry>,
    /// P29：后台刷新单飞（cache key 字符串 → 正在刷新；da 同源的 CAS 语义，粒度更细）。
    refreshing: std::collections::HashSet<String>,
    /// optimistic cache（dae 默认 true）：过期后仍可供应（见 stale_reply_ttl）。
    pub optimistic: bool,
    /// 超过到期后仍可供应的窗口秒数（0 = 不限）。
    pub optimistic_ttl: u32,
    /// stale 应答中记录 TTL 的上限（对照 dae `optimistic_stale_reply_ttl`）。
    pub stale_reply_ttl: u32,
    pub hits: u64,
    pub misses: u64,
    pub expired: u64,
    pub inserts: u64,
    pub evictions: u64,
    /// P23：命中过期但被 optimistic 供应（stale）的次数。
    pub stale_hits: u64,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            refreshing: std::collections::HashSet::new(),
            optimistic: true,
            optimistic_ttl: 60,
            stale_reply_ttl: 30,
            hits: 0,
            misses: 0,
            expired: 0,
            inserts: 0,
            evictions: 0,
            stale_hits: 0,
        }
    }
}

/// P29：负应答判定（RFC 2308，对照 dae `isNegativeResponse`）——NXDOMAIN，或
/// NOERROR 且 answer 里无 qtype 记录也无 CNAME（有 CNAME 视为别名链，不取代正值）。
pub fn is_negative_response(resp: &[u8], qtype: u16) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    if rcode == 3 {
        return true;
    }
    if rcode != 0 {
        return false;
    }
    match parse_rrs(resp) {
        Some(rrs) => rrs
            .iter()
            .filter(|r| r.section == SEC_ANSWER)
            .all(|r| r.rtype != qtype && r.rtype != 5),
        None => false,
    }
}

/// P29：缓存命中信息（stale 标志 + 命中的作用域键，供 RFC 8767 刷新单飞）。
pub struct CacheHit {
    pub resp: Vec<u8>,
    pub stale: bool,
    pub scope: String,
}

impl DnsCache {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// P29：尝试开始一次后台刷新（单飞）；返回 true = 本次由调用方负责刷新。
    pub fn begin_refresh(&mut self, key: &str) -> bool {
        self.refreshing.insert(key.to_string())
    }

    /// P29：刷新结束（无论成败，必须调用）。
    pub fn end_refresh(&mut self, key: &str) {
        self.refreshing.remove(key);
    }

    /// P29：在飞刷新数（状态面）。
    pub fn refreshing_len(&self) -> usize {
        self.refreshing.len()
    }

    /// P29：精确删除一个作用域键（后台刷新得到负应答时取代过期正值）。
    pub fn remove_scoped(&mut self, q: &Question, do_bit: bool, scope: &str) -> bool {
        self.map
            .remove(&CacheKey {
                qname: q.qname.clone(),
                qtype: q.qtype,
                qclass: q.qclass,
                do_bit,
                scope: scope.to_string(),
            })
            .is_some()
    }

    /// 命中则返回给客户端的应答（改 ID、回填 question、递减 TTL）；否则计 miss 并返回 None。
    /// 带 EDNS options（非 DO）的查询不命中（ECS 等选项会改变上游应答）。
    /// 兼容签名（无作用域；测试用）。生产走 `answer_from_cache_scoped`。
    #[allow(dead_code)]
    pub fn answer_from_cache(
        &mut self,
        query: &[u8],
        q: &Question,
        edns: &EdnsInfo,
        now: Instant,
    ) -> Option<Vec<u8>> {
        self.answer_from_cache_scoped(query, q, edns, "", now)
    }

    pub fn answer_from_cache_scoped(
        &mut self,
        query: &[u8],
        q: &Question,
        edns: &EdnsInfo,
        scope: &str,
        now: Instant,
    ) -> Option<Vec<u8>> {
        if edns.has_options {
            self.misses += 1;
            return None;
        }
        let key = CacheKey {
            qname: q.qname.clone(),
            qtype: q.qtype,
            qclass: q.qclass,
            do_bit: edns.do_bit,
            scope: scope.to_string(),
        };
        if let Some(resp) = self.get_scoped(&key, query, now) {
            return Some(resp.0);
        }
        self.misses += 1;
        None
    }

    /// P28：ECS 作用域化查找——按 `ecs_scope_ladder` 从请求前缀依次尝试
    /// 本机前缀与更宽 scope（上游回填的 scope 键），命中即返回；全部未命中计一次 miss。
    /// （单元测试用；生产路径走 `answer_from_cache_ecs_full`。）
    #[allow(dead_code)]
    pub fn answer_from_cache_ecs(
        &mut self,
        query: &[u8],
        q: &Question,
        edns: &EdnsInfo,
        base_scope: &str,
        ecs: Option<(IpAddr, u8)>,
        now: Instant,
    ) -> Option<Vec<u8>> {
        self.answer_from_cache_ecs_full(query, q, edns, base_scope, ecs, now)
            .map(|h| h.resp)
    }

    /// P29：同 `answer_from_cache_ecs`，额外报告 stale 标志与命中的作用域键
    /// （供 RFC 8767 后台刷新单飞与负应答取代）。
    pub fn answer_from_cache_ecs_full(
        &mut self,
        query: &[u8],
        q: &Question,
        edns: &EdnsInfo,
        base_scope: &str,
        ecs: Option<(IpAddr, u8)>,
        now: Instant,
    ) -> Option<CacheHit> {
        if edns.has_options {
            self.misses += 1;
            return None;
        }
        let mut candidates: Vec<String> = Vec::new();
        match ecs {
            Some((ip, p)) => {
                for (a, pl) in ecs_scope_ladder(ip, p) {
                    candidates.push(format!("{base_scope}|ecs={a}/{pl}"));
                }
            }
            None => candidates.push(base_scope.to_string()),
        }
        for scope in candidates {
            let key = CacheKey {
                qname: q.qname.clone(),
                qtype: q.qtype,
                qclass: q.qclass,
                do_bit: edns.do_bit,
                scope: scope.clone(),
            };
            if let Some((resp, stale)) = self.get_scoped(&key, query, now) {
                return Some(CacheHit { resp, stale, scope });
            }
        }
        self.misses += 1;
        None
    }

    /// 单键命中（不改 miss 计数）：`(应答, 是否 stale)`；过期且超窗则移除。
    fn get_scoped(
        &mut self,
        key: &CacheKey,
        query: &[u8],
        now: Instant,
    ) -> Option<(Vec<u8>, bool)> {
        let e = self.map.get(key)?;
        let elapsed = now.saturating_duration_since(e.stored).as_secs() as u32;
        if elapsed >= e.ttl {
            // P23：optimistic cache——过期但在窗口内则继续供应（TTL 压到
            // stale_reply_ttl 上限），并在后台/下次查询时刷新。
            if self.optimistic
                && (self.optimistic_ttl == 0 || elapsed < e.ttl.saturating_add(self.optimistic_ttl))
            {
                self.stale_hits += 1;
                self.hits += 1;
                return Some((
                    prepare_cached_stale(&e.response, e.question_end, query, self.stale_reply_ttl),
                    true,
                ));
            }
            self.map.remove(key);
            self.expired += 1;
            return None;
        }
        self.hits += 1;
        Some((
            prepare_cached(&e.response, e.question_end, query, elapsed),
            false,
        ))
    }

    /// P23：作用域内某 (qname, qtype) 是否有未过期的缓存（ipversion_prefer 用）。
    pub fn has_fresh(&self, qname: &str, qtype: u16, scope: &str, now: Instant) -> bool {
        let qname = normalize(qname);
        [false, true].iter().any(|do_bit| {
            let key = CacheKey {
                qname: qname.clone(),
                qtype,
                qclass: 1,
                do_bit: *do_bit,
                scope: scope.to_string(),
            };
            self.map
                .get(&key)
                .is_some_and(|e| (now.saturating_duration_since(e.stored).as_secs() as u32) < e.ttl)
        })
    }

    /// P23：配置（启动/reload 时应用；对照 dae dns.optimistic_cache 系列）。
    pub fn set_options(&mut self, optimistic: bool, optimistic_ttl: u32, stale_reply_ttl: u32) {
        self.optimistic = optimistic;
        self.optimistic_ttl = optimistic_ttl;
        self.stale_reply_ttl = stale_reply_ttl;
    }

    /// 按语义入缓存；返回是否已缓存。带 EDNS options 的查询不入缓存。
    /// 兼容签名（无作用域；测试用）。生产走 `insert_scoped`。
    #[allow(dead_code)]
    pub fn insert(&mut self, q: &Question, edns: &EdnsInfo, response: &[u8], now: Instant) -> bool {
        self.insert_scoped(q, edns, "", response, now)
    }

    pub fn insert_scoped(
        &mut self,
        q: &Question,
        edns: &EdnsInfo,
        scope: &str,
        response: &[u8],
        now: Instant,
    ) -> bool {
        self.insert_scoped_with_fixed(q, edns, scope, response, now, None)
    }

    /// P23：带 fixed_domain_ttl 的插入。`fixed_ttl=Some(t)` 时缓存寿命固定为 t 秒
    /// （0 = 立即过期；配合 optimistic 可供 stale），对照 dae `fixedTtlDeadlineFunc`。
    pub fn insert_scoped_with_fixed(
        &mut self,
        q: &Question,
        edns: &EdnsInfo,
        scope: &str,
        response: &[u8],
        now: Instant,
        fixed_ttl: Option<u32>,
    ) -> bool {
        if edns.has_options {
            return false;
        }
        let Some(mut entry) = build_entry(response, now, fixed_ttl.is_some()) else {
            return false;
        };
        if let Some(t) = fixed_ttl {
            entry.ttl = t.min(DNS_CACHE_MAX_TTL);
        } else if entry.ttl == 0 {
            return false;
        }
        let key = CacheKey {
            qname: q.qname.clone(),
            qtype: q.qtype,
            qclass: q.qclass,
            do_bit: edns.do_bit,
            scope: scope.to_string(),
        };
        // P38：替换语义（含存在时仅计数）用 entry 一次性完成（clippy::map_entry）。
        let replace_existing = self.map.contains_key(&key);
        if !replace_existing {
            self.sweep_expired(now);
            if self.map.len() >= DNS_CACHE_MAX_ENTRIES {
                if let Some(k) = self
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.stored)
                    .map(|(k, _)| k.clone())
                {
                    self.map.remove(&k);
                    self.evictions += 1;
                }
            }
        }
        self.map.insert(key, entry);
        self.inserts += 1;
        true
    }

    fn sweep_expired(&mut self, now: Instant) {
        let optimistic = self.optimistic;
        let o_ttl = self.optimistic_ttl;
        let dead: Vec<CacheKey> = self
            .map
            .iter()
            .filter(|(_, e)| {
                let elapsed = now.saturating_duration_since(e.stored).as_secs() as u32;
                elapsed >= e.ttl
                    && !(optimistic && (o_ttl == 0 || elapsed < e.ttl.saturating_add(o_ttl)))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            self.map.remove(&k);
            self.expired += 1;
        }
    }

    /// 供 reload 后重建域位图：当前所有 (question, response) 快照。
    pub fn snapshot(&self) -> Vec<(Question, Vec<u8>)> {
        self.map
            .iter()
            .map(|(k, e)| {
                (
                    Question {
                        qname: k.qname.clone(),
                        qtype: k.qtype,
                        qclass: k.qclass,
                    },
                    e.response.clone(),
                )
            })
            .collect()
    }
}

/// 判断一个应答能否入缓存，并计算缓存寿命。`allow_zero_ttl` 供 fixed_domain_ttl=0
/// 的“立即过期”条目使用（P23）。
fn build_entry(response: &[u8], now: Instant, allow_zero_ttl: bool) -> Option<CacheEntry> {
    if response.len() < 12 || response[2] & 0x02 != 0 {
        return None; // 截断（TC）不入缓存
    }
    let rcode = response[3] & 0x0f;
    if rcode != 0 && rcode != 3 {
        return None; // SERVFAIL/REFUSED 等不缓存（含 dae 也不缓存的瞬时失败）
    }
    let rrs = parse_rrs(response)?;
    let question_end = questions_end(response)?;
    let has_answer = rrs.iter().any(|r| r.section == SEC_ANSWER);
    let ttl = if rcode == 3 || !has_answer {
        soa_min_ttl(response, &rrs).unwrap_or(DNS_CACHE_NEGATIVE_DEFAULT_TTL)
    } else {
        rrs.iter()
            .filter(|r| r.section == SEC_ANSWER)
            .map(|r| r.ttl)
            .min()?
    };
    if ttl == 0 && !allow_zero_ttl {
        return None;
    }
    Some(CacheEntry {
        response: response.to_vec(),
        question_end,
        stored: now,
        ttl: ttl.min(DNS_CACHE_MAX_TTL),
    })
}

/// 负缓存寿命 = min(SOA.TTL, SOA.MINIMUM)（RFC 2308）。
fn soa_min_ttl(buf: &[u8], rrs: &[Rr]) -> Option<u32> {
    let rr = rrs
        .iter()
        .find(|r| r.section == SEC_AUTHORITY && r.rtype == 6 && r.rclass == 1)?;
    let (_, off) = read_name(buf, rr.rdata_off)?;
    let (_, off) = read_name(buf, off)?;
    let min_off = off.checked_add(4 * 4)?;
    if min_off + 4 > rr.rdata_off + rr.rdlen {
        return None;
    }
    let min = u32::from_be_bytes([
        *buf.get(min_off)?,
        *buf.get(min_off + 1)?,
        *buf.get(min_off + 2)?,
        *buf.get(min_off + 3)?,
    ]);
    Some(rr.ttl.min(min))
}

/// 构造命中应答：ID 用客户端查询、question 按客户端原样回填（大小写敏感），
/// answer/authority/additional 的 TTL 递减 `elapsed` 秒（OPT 的 TTL 字段是
/// 扩展 rcode/flags，不动——对照 dae `setRecordTTL`）。
fn prepare_cached(cached: &[u8], cached_qend: usize, query: &[u8], elapsed: u32) -> Vec<u8> {
    let mut out = cached.to_vec();
    if query.len() >= 12 && out.len() >= 12 {
        out[0..2].copy_from_slice(&query[0..2]);
    }
    if let Some(qend) = questions_end(query) {
        let qlen = qend.saturating_sub(12);
        let clen = cached_qend.saturating_sub(12);
        if qlen > 0
            && qlen == clen
            && out.len() >= cached_qend
            && query[12..qend].eq_ignore_ascii_case(&cached[12..cached_qend])
        {
            out[12..cached_qend].copy_from_slice(&query[12..qend]);
        }
    }
    if elapsed > 0 {
        if let Some(rrs) = parse_rrs(&out) {
            for rr in rrs {
                if rr.rtype != RR_OPT {
                    let new = rr.ttl.saturating_sub(elapsed);
                    out[rr.ttl_off..rr.ttl_off + 4].copy_from_slice(&new.to_be_bytes());
                }
            }
        }
    }
    out
}

/// P23：stale 应答（optimistic cache）——ID/question 回填同上，但记录 TTL 统一压到
/// `stale_reply_ttl`（对照 dae `optimistic_stale_reply_ttl`）。
fn prepare_cached_stale(
    cached: &[u8],
    cached_qend: usize,
    query: &[u8],
    stale_reply_ttl: u32,
) -> Vec<u8> {
    let mut out = cached.to_vec();
    if query.len() >= 12 && out.len() >= 12 {
        out[0..2].copy_from_slice(&query[0..2]);
    }
    if let Some(qend) = questions_end(query) {
        let qlen = qend.saturating_sub(12);
        let clen = cached_qend.saturating_sub(12);
        if qlen > 0
            && qlen == clen
            && out.len() >= cached_qend
            && query[12..qend].eq_ignore_ascii_case(&cached[12..cached_qend])
        {
            out[12..cached_qend].copy_from_slice(&query[12..qend]);
        }
    }
    if let Some(rrs) = parse_rrs(&out) {
        for rr in rrs {
            if rr.rtype != RR_OPT {
                out[rr.ttl_off..rr.ttl_off + 4].copy_from_slice(&stale_reply_ttl.to_be_bytes());
            }
        }
    }
    out
}

// ---------------------------------------------------------------- 域名匹配

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// 对照 dae 的 RoutingDomainKey 语义（语义参考 + 单测用；生产匹配走
/// `domain_set_matches` 的预计算索引）。
#[cfg(test)]
pub fn domain_match(key: &str, pattern: &str, qname: &str) -> bool {
    let q = normalize(qname);
    let p = normalize(pattern);
    if p.is_empty() || q.is_empty() {
        return false;
    }
    match key {
        "full" => q == p,
        "keyword" => q.contains(&p),
        "suffix" => {
            // P17a：前导点 = 只匹配子域（对照 dae ahocorasick_slimtrie 语义）；
            // 无前导点 = 裸域 + 子域。
            if let Some(sub) = p.strip_prefix('.') {
                !sub.is_empty() && q.ends_with(&format!(".{sub}"))
            } else {
                q == p || q.ends_with(&format!(".{p}"))
            }
        }
        // regex 无编译后形式，不在此函数里静默按 suffix 处理
        _ => false,
    }
}

/// 一个 domain 集合是否命中 qname（regex 用编译好的模式；对照 dae：qname 小写化、
/// regex 模式保持原大小写、非锚定匹配）。suffix/full 走编译期索引（O(labels)/O(1)），
/// keyword 仍线性扫描（数据量通常小）。
pub fn domain_set_matches(spec: &DomainSetSpec, qname: &str) -> bool {
    let q = normalize(qname);
    if q.is_empty() {
        return false;
    }
    match spec.key.as_str() {
        "suffix" => {
            if spec.index.suffix.contains(&q) {
                return true;
            }
            // 枚举 q 的每个「点后缀」（不含 q 自身——sub-only 模式不匹配裸域）。
            for (i, b) in q.as_bytes().iter().enumerate() {
                if *b == b'.' {
                    let s = &q[i + 1..];
                    if s.is_empty() {
                        break;
                    }
                    if spec.index.suffix.contains(s) || spec.index.suffix_sub_only.contains(s) {
                        return true;
                    }
                }
            }
            false
        }
        "full" => spec.index.full.contains(&q),
        "keyword" => spec.domains.iter().any(|pat| {
            let p = normalize(pat);
            !p.is_empty() && q.contains(&p)
        }),
        "regex" => spec.regexes.iter().any(|r| r.is_match(&q)),
        _ => false,
    }
}

/// 计算一个报文应写入的位图（按 MAX_MATCH_SET_LEN/32 个 word）。
/// 返回 (words, 命中的 domain 规则数)。
pub fn matched_bitmap(sets: &[DomainSetSpec], qname: &str) -> (Vec<u32>, usize) {
    let words = (crate::rules::MAX_MATCH_SET_LEN as usize).div_ceil(32);
    let mut bits = vec![0u32; words];
    let mut hits = 0usize;
    for spec in sets {
        if domain_set_matches(spec, qname) {
            let idx = spec.match_set_index as usize;
            bits[idx / 32] |= 1 << (idx % 32);
            hits += 1;
        }
    }
    (bits, hits)
}

/// IPv4 → 与数据面 lpm_key/位图 key 一致的 16 字节「IPv4-mapped」形式。
pub fn map_v4(ip: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&ip);
    out
}

// ---------------------------------------------------------------- 测试

// ---------------------------------------------------------------- 测试

/// P18c：供其它模块单测构造应答的最小助手。
#[cfg(test)]
pub mod tests_support {
    pub fn a_response(name: &str, octets: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        // answer
        let mut resp = q.clone();
        resp[2] |= 0x80;
        resp[6..8].copy_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&octets);
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn no_edns() -> EdnsInfo {
        EdnsInfo::default()
    }

    /// 在查询尾部追加一个 OPT（rdlen=0）供 EDNS 解析测试用。
    fn query_with_edns(name: &str, qtype: u16, size: u16, do_bit: bool) -> Vec<u8> {
        let mut q = query(name, qtype);
        q[10..12].copy_from_slice(&1u16.to_be_bytes()); // arcount=1
        q.push(0);
        put_u16(&mut q, RR_OPT);
        put_u16(&mut q, size);
        q.extend_from_slice(&(if do_bit { 0x8000u32 } else { 0u32 }).to_be_bytes());
        put_u16(&mut q, 0);
        q
    }

    #[test]
    fn servfail_echoes_question_and_sets_rcode() {
        let q = query("sf.test", 1);
        let r = servfail(&q);
        assert!(r.len() > 12);
        assert_eq!(r[0..2], q[0..2]); // ID 保留
        assert_eq!(r[2] & 0x80, 0x80); // QR=1
        assert_eq!(r[2] & 0x01, 0x01); // RD 保留
        assert_eq!(r[3] & 0x0f, 0x02); // RCODE=SERVFAIL
        assert_eq!(r[6..8], [0, 0]); // ANCOUNT=0
        assert_eq!(&r[12..], &q[12..]); // question 原样回显
                                        // 畸形/无 question：返回空（调用方跳过发送）
        assert!(servfail(&[0u8; 4]).is_empty());
        let mut noq = q.clone();
        noq[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert!(servfail(&noq).is_empty());
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        put_u16(&mut q, qtype);
        put_u16(&mut q, 1);
        q
    }

    #[test]
    fn parses_query_and_answer() {
        let q = query("Proxy.Test", 1);
        let qq = parse_query(&q).unwrap();
        assert_eq!(qq.qname, "proxy.test");
        assert_eq!(qq.qtype, 1);
        assert_eq!(qq.qclass, 1);

        let resp = build_a_response(&q, &[[10, 9, 10, 3], [10, 9, 10, 4]], 30).unwrap();
        assert_eq!(read_u16(&resp, 6), Some(2));
        let (addrs, aaaa) = answer_a_records(&resp);
        assert_eq!(addrs, vec![[10, 9, 10, 3], [10, 9, 10, 4]]);
        assert_eq!(aaaa, 0);
    }

    #[test]
    fn answer_with_compression_and_aaaa() {
        // question: a.test A；answer1: CNAME（压缩指针）→ cname；answer2: A 1.2.3.4
        let q = query("a.test", 1);
        let mut resp = q.clone();
        resp[2] |= 0x80;
        resp[6..8].copy_from_slice(&2u16.to_be_bytes());
        // answer1: name=ptr 0x0c, type CNAME(5), class 1, ttl 30, rdlen=7, rdata="cname" 0
        resp.extend_from_slice(&[0xc0, 0x0c]);
        put_u16(&mut resp, 5);
        put_u16(&mut resp, 1);
        resp.extend_from_slice(&30u32.to_be_bytes());
        put_u16(&mut resp, 7);
        resp.extend_from_slice(&[5, b'c', b'n', b'a', b'm', b'e', 0]);
        // answer2: name=ptr, A, IN, ttl, 4, 1.2.3.4
        resp.extend_from_slice(&[0xc0, 0x0c]);
        put_u16(&mut resp, 1);
        put_u16(&mut resp, 1);
        resp.extend_from_slice(&30u32.to_be_bytes());
        put_u16(&mut resp, 4);
        resp.extend_from_slice(&[1, 2, 3, 4]);
        let (addrs, aaaa) = answer_a_records(&resp);
        assert_eq!(addrs, vec![[1, 2, 3, 4]]);
        assert_eq!(aaaa, 0);
    }

    #[test]
    fn domain_matching_semantics() {
        assert!(domain_match("suffix", "proxy.test", "proxy.test"));
        assert!(domain_match("suffix", "proxy.test", "a.proxy.test"));
        assert!(domain_match("suffix", "proxy.test", "a.proxy.test."));
        assert!(!domain_match("suffix", "proxy.test", "notproxy.test"));
        assert!(!domain_match("suffix", "proxy.test", "proxy.test.evil"));
        // P17a：前导点 = 只匹配子域
        assert!(!domain_match("suffix", ".proxy.test", "proxy.test"));
        assert!(domain_match("suffix", ".proxy.test", "a.proxy.test"));
        assert!(domain_match("full", "direct.test", "direct.test"));
        assert!(!domain_match("full", "direct.test", "x.direct.test"));
        assert!(domain_match("keyword", "kw", "www.kw.example"));
    }

    #[test]
    fn domain_set_index_semantics() {
        let mk = |key: &str, doms: &[&str]| {
            DomainSetSpec::build(
                0,
                key,
                &doms.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
            .unwrap()
        };
        let suf = mk("suffix", &["proxy.test", ".sub.test"]);
        assert!(domain_set_matches(&suf, "proxy.test"));
        assert!(domain_set_matches(&suf, "A.Proxy.Test."));
        assert!(!domain_set_matches(&suf, "notproxy.test"));
        assert!(!domain_set_matches(&suf, "proxy.test.evil"));
        assert!(!domain_set_matches(&suf, "sub.test"));
        assert!(domain_set_matches(&suf, "x.sub.test"));
        let full = mk("full", &["full.test"]);
        assert!(domain_set_matches(&full, "full.test"));
        assert!(!domain_set_matches(&full, "x.full.test"));
        let kw = mk("keyword", &["kw"]);
        assert!(domain_set_matches(&kw, "www.KW.example"));
        assert!(!domain_set_matches(&kw, "nope.example"));
    }

    #[test]
    fn bitmap_bits_follow_match_set_index() {
        let sets = vec![
            DomainSetSpec::build(0, "suffix", &["proxy.test".into()]).unwrap(),
            DomainSetSpec::build(33, "keyword", &["kw".into()]).unwrap(),
        ];
        let (bits, hits) = matched_bitmap(&sets, "a.proxy.test");
        assert_eq!(hits, 1);
        assert_eq!(bits[0], 1);
        assert_eq!(bits[1], 0);
        let (bits2, hits2) = matched_bitmap(&sets, "x.kw.y");
        assert_eq!(hits2, 1);
        assert_eq!(bits2[0], 0);
        assert_eq!(bits2[1], 1 << 1);
        let (bits3, _) = matched_bitmap(&sets, "none.test");
        assert!(bits3.iter().all(|w| *w == 0));
    }

    #[test]
    fn v4_mapping_matches_dataplane_layout() {
        let m = map_v4([10, 9, 10, 3]);
        assert_eq!(&m[10..12], &[0xff, 0xff]);
        assert_eq!(&m[12..16], &[10, 9, 10, 3]);
    }

    // ------------------------------------------------------------ 缓存

    #[test]
    fn cache_hit_rewrites_id_and_decrements_ttl() {
        let q1 = query("cache.test", 1);
        let mut q2 = q1.clone();
        q2[0] = 0xab;
        q2[1] = 0xcd;
        let resp = build_a_response(&q1, &[[10, 9, 10, 9]], 30).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        assert!(c.insert(&parse_query(&q1).unwrap(), &no_edns(), &resp, t0));
        assert_eq!(c.len(), 1);

        let hit = c
            .answer_from_cache(
                &q2,
                &parse_query(&q2).unwrap(),
                &no_edns(),
                t0 + Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(&hit[0..2], &[0xab, 0xcd]);
        let a = parse_rrs(&hit)
            .unwrap()
            .into_iter()
            .find(|r| r.section == SEC_ANSWER && r.rtype == 1)
            .unwrap();
        assert_eq!(a.ttl, 25);
        assert_eq!(c.hits, 1);
        assert_eq!(c.misses, 0);
    }

    #[test]
    fn cache_expires_on_min_ttl() {
        let q = query("expire.test", 1);
        let resp = build_a_response(&q, &[[1, 2, 3, 4]], 10).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        c.set_options(false, 60, 30); // P23：本用例验证非 optimistic 的过期行为
        assert!(c.insert(&parse_query(&q).unwrap(), &no_edns(), &resp, t0));
        assert!(c
            .answer_from_cache(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                t0 + Duration::from_secs(10)
            )
            .is_none());
        assert_eq!(c.expired, 1);
        assert_eq!(c.misses, 1);
        assert_eq!(c.len(), 0);
    }

    // ---- P23：optimistic cache / fixed_domain_ttl / has_fresh ----

    #[test]
    fn optimistic_serves_stale_with_bounded_ttl() {
        let q = query("stale.test", 1);
        let resp = build_a_response(&q, &[[10, 9, 10, 71]], 10).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default(); // optimistic=true / ttl=60 / stale=30
        assert!(c.insert(&parse_query(&q).unwrap(), &no_edns(), &resp, t0));
        let hit = c
            .answer_from_cache_scoped(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                "",
                t0 + Duration::from_secs(15),
            )
            .unwrap();
        let a = parse_rrs(&hit)
            .unwrap()
            .into_iter()
            .find(|r| r.section == SEC_ANSWER && r.rtype == 1)
            .unwrap();
        assert_eq!(a.ttl, 30); // 过期应答的 TTL 上限 = optimistic_stale_reply_ttl
        assert_eq!(c.stale_hits, 1);
        assert_eq!(c.expired, 0);
        // 超出 optimistic 窗口（10 + 60）→ miss 并清出
        assert!(c
            .answer_from_cache_scoped(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                "",
                t0 + Duration::from_secs(75),
            )
            .is_none());
        assert_eq!(c.expired, 1);
    }

    #[test]
    fn fixed_domain_ttl_zero_expires_immediately_but_serves_stale() {
        let q = query("fixed.test", 1);
        let resp = build_a_response(&q, &[[1, 2, 3, 4]], 300).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        assert!(c.insert_scoped_with_fixed(
            &parse_query(&q).unwrap(),
            &no_edns(),
            "",
            &resp,
            t0,
            Some(0)
        ));
        // 立即过期，但 optimistic 窗口内仍可供应（dae：fixed 0 + optimistic 默认开）
        assert!(c
            .answer_from_cache_scoped(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                "",
                t0 + Duration::from_secs(1),
            )
            .is_some());
        assert_eq!(c.stale_hits, 1);
        // 关 optimistic → 立即 miss
        let mut c2 = DnsCache::default();
        c2.set_options(false, 60, 30);
        assert!(c2.insert_scoped_with_fixed(
            &parse_query(&q).unwrap(),
            &no_edns(),
            "",
            &resp,
            t0,
            Some(0)
        ));
        assert!(c2
            .answer_from_cache_scoped(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                "",
                t0 + Duration::from_secs(1),
            )
            .is_none());
    }

    #[test]
    fn has_fresh_tracks_expiry_and_type() {
        let q = query("fresh.test", 1);
        let resp = build_a_response(&q, &[[1, 2, 3, 4]], 10).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        assert!(c.insert(&parse_query(&q).unwrap(), &no_edns(), &resp, t0));
        assert!(c.has_fresh("fresh.test", 1, "", t0 + Duration::from_secs(5)));
        assert!(!c.has_fresh("fresh.test", 1, "", t0 + Duration::from_secs(11)));
        assert!(!c.has_fresh("fresh.test", 28, "", t0 + Duration::from_secs(5)));
    }

    #[test]
    fn negative_nodata_uses_soa_minimum_and_decrements() {
        // NODATA：rcode=0、ancount=0、authority 一条 SOA（TTL 20 / MINIMUM 60）→ 寿命 20
        let q = query("neg.test", 1);
        let mut resp = q.clone();
        resp[2] |= 0x80;
        resp[6..8].copy_from_slice(&0u16.to_be_bytes());
        resp[8..10].copy_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&[0xc0, 0x0c]);
        put_u16(&mut resp, 6);
        put_u16(&mut resp, 1);
        resp.extend_from_slice(&20u32.to_be_bytes());
        let mut rdata: Vec<u8> = Vec::new();
        for _ in 0..2 {
            rdata.extend_from_slice(&[2, b'n', b's', 4, b't', b'e', b's', b't', 0]);
        }
        rdata.extend_from_slice(&1u32.to_be_bytes());
        rdata.extend_from_slice(&2u32.to_be_bytes());
        rdata.extend_from_slice(&3u32.to_be_bytes());
        rdata.extend_from_slice(&4u32.to_be_bytes());
        rdata.extend_from_slice(&60u32.to_be_bytes());
        put_u16(&mut resp, rdata.len() as u16);
        resp.extend_from_slice(&rdata);

        assert_eq!(soa_min_ttl(&resp, &parse_rrs(&resp).unwrap()), Some(20));
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        c.set_options(false, 60, 30); // P23：验证非 optimistic 的过期语义
        assert!(c.insert(&parse_query(&q).unwrap(), &no_edns(), &resp, t0));
        let hit = c
            .answer_from_cache(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                t0 + Duration::from_secs(3),
            )
            .unwrap();
        let soa = parse_rrs(&hit)
            .unwrap()
            .into_iter()
            .find(|r| r.rtype == 6)
            .unwrap();
        assert_eq!(soa.ttl, 17);
        assert_eq!(&hit[hit.len() - 4..], &60u32.to_be_bytes());
        assert!(c
            .answer_from_cache(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                t0 + Duration::from_secs(21)
            )
            .is_none());
    }

    #[test]
    fn ecs_injection_shape_and_auto_prefix() {
        let q = query("ecs.test", 1);
        assert!(!query_edns(&q).present);
        let (ip, plen) = ecs_auto_prefix("192.0.2.254".parse().unwrap());
        assert_eq!(plen, 24);
        let out = add_ecs(&q, (ip, plen)).unwrap();
        // OPT 固定 11B + RDATA（option-code/len 4B + ECS 4B + 3 字节地址）
        assert_eq!(out.len(), q.len() + 11 + 8 + 3);
        let e = query_edns(&out);
        assert!(e.present && e.has_options);
        // 尾部结构：family=1, prefix=24, scope=0, addr=192.0.2.0
        assert_eq!(&out[out.len() - 7..], &[0, 1, 24, 0, 192, 168, 5]);
        // 已带 OPT 的查询不动
        let q2 = {
            let mut x = q.clone();
            x[10..12].copy_from_slice(&1u16.to_be_bytes());
            x.push(0);
            put_u16(&mut x, RR_OPT);
            put_u16(&mut x, 512);
            x.extend_from_slice(&0u32.to_be_bytes());
            put_u16(&mut x, 0);
            x
        };
        assert!(add_ecs(&q2, (ip, plen)).is_none());
        // RDATA 与 RDLEN 一致（parse_rrs 能完整遍历）
        let parsed = parse_rrs(&out).unwrap();
        let opt = parsed.iter().find(|r| r.rtype == RR_OPT).unwrap();
        assert_eq!(opt.rdlen, 11);
        assert_eq!(opt.rdata_off + opt.rdlen, out.len());
        // v6 → /56，地址截断到 7 字节
        let (ip6, plen6) = ecs_auto_prefix("2001:db8:1:2:3:4:5:6".parse().unwrap());
        assert_eq!(plen6, 56);
        let out6 = add_ecs(&q, (ip6, plen6)).unwrap();
        assert_eq!(out6.len(), q.len() + 11 + 8 + 7);
    }

    #[test]
    fn no_cache_for_servfail_or_truncated() {
        let q = query("s.test", 1);
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        let mut fail = build_a_response(&q, &[[1, 2, 3, 4]], 30).unwrap();
        fail[3] = (fail[3] & 0xf0) | 2; // SERVFAIL
        assert!(!c.insert(&parse_query(&q).unwrap(), &no_edns(), &fail, t0));
        let mut trunc = build_a_response(&q, &[[1, 2, 3, 4]], 30).unwrap();
        trunc[2] |= 0x02; // TC
        assert!(!c.insert(&parse_query(&q).unwrap(), &no_edns(), &trunc, t0));
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn cache_hit_preserves_client_question_case() {
        let q_lower = query("case.test", 1);
        let resp = build_a_response(&q_lower, &[[9, 9, 9, 9]], 30).unwrap();
        let q_upper = query("CASE.Test", 1);
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        assert!(c.insert(&parse_query(&q_lower).unwrap(), &no_edns(), &resp, t0));
        let hit = c
            .answer_from_cache(&q_upper, &parse_query(&q_upper).unwrap(), &no_edns(), t0)
            .unwrap();
        let qend = questions_end(&q_upper).unwrap();
        assert_eq!(&hit[12..qend], &q_upper[12..qend]);
    }

    #[test]
    fn cache_hit_leaves_opt_untouched() {
        let q = query("opt.test", 1);
        let mut resp = build_a_response(&q, &[[1, 1, 1, 1]], 30).unwrap();
        resp[10..12].copy_from_slice(&1u16.to_be_bytes()); // arcount=1
        resp.push(0);
        put_u16(&mut resp, RR_OPT);
        put_u16(&mut resp, 4096);
        resp.extend_from_slice(&0x0000_8000u32.to_be_bytes());
        put_u16(&mut resp, 0);
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        assert!(c.insert(&parse_query(&q).unwrap(), &no_edns(), &resp, t0));
        let hit = c
            .answer_from_cache(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                t0 + Duration::from_secs(7),
            )
            .unwrap();
        let opt = parse_rrs(&hit)
            .unwrap()
            .into_iter()
            .find(|r| r.rtype == RR_OPT)
            .unwrap();
        assert_eq!(opt.ttl, 0x8000);
        let a = parse_rrs(&hit)
            .unwrap()
            .into_iter()
            .find(|r| r.rtype == 1)
            .unwrap();
        assert_eq!(a.ttl, 23);
    }

    // ------------------------------------------------------------ EDNS / regex

    #[test]
    fn regex_domain_set_matches_lowercased_qname() {
        // 对照 dae：qname 小写、模式保持原大小写、非锚定匹配
        let spec = DomainSetSpec::build(5, "regex", &[r"^api[0-9]+\.regex\.test$".into()]).unwrap();
        let sets = vec![spec];
        let (bits, hits) = matched_bitmap(&sets, "API1.Regex.Test.");
        assert_eq!(hits, 1);
        assert_eq!(bits[0], 1 << 5);
        let (bits2, hits2) = matched_bitmap(&sets, "web.regex.test");
        assert_eq!(hits2, 0);
        assert!(bits2.iter().all(|w| *w == 0));
        // 大写模式不会命中（qname 已小写化，对照 dae 行为）
        let upper = DomainSetSpec::build(0, "regex", &["API".into()]).unwrap();
        let (_, hits3) = matched_bitmap(&[upper], "api.test");
        assert_eq!(hits3, 0);
    }

    #[test]
    fn edns_parsing_and_udp_size() {
        let plain = query("e.test", 1);
        assert_eq!(query_edns(&plain), EdnsInfo::default());
        assert_eq!(client_udp_size(&plain), 512);

        let e = query_with_edns("e.test", 1, 4096, true);
        let info = query_edns(&e);
        assert!(info.present && info.udp_size == 4096 && info.do_bit && !info.has_options);
        assert_eq!(client_udp_size(&e), 4096);

        // 公布尺寸小于 512 时按下限 512 处理
        let small = query_with_edns("e.test", 1, 128, false);
        assert_eq!(client_udp_size(&small), 512);
    }

    fn big_answer(n: usize) -> (Vec<u8>, Vec<u8>) {
        let q = query_with_edns("big.test", 1, 1232, false);
        let addrs: Vec<[u8; 4]> = (0..n).map(|i| [10, 9, 10, (100 + i) as u8]).collect();
        let mut resp = build_a_response(&q, &addrs, 30).unwrap();
        // 假上游 echo 客户端的 OPT
        resp[10..12].copy_from_slice(&1u16.to_be_bytes());
        resp.push(0);
        put_u16(&mut resp, RR_OPT);
        put_u16(&mut resp, 1232);
        resp.extend_from_slice(&0u32.to_be_bytes());
        put_u16(&mut resp, 0);
        (q, resp)
    }

    #[test]
    fn truncate_for_udp_sets_tc_and_keeps_opt() {
        let (q, resp) = big_answer(60);
        assert!(resp.len() > 512);
        let short = truncate_for_udp(&resp, 512);
        assert!(short.len() <= 512);
        assert_eq!(short[2] & 0x02, 0x02, "TC 应置位");
        assert_eq!(read_u16(&short, 6), Some(0), "answer 段应清空");
        // question 完整保留
        let qend = questions_end(&q).unwrap();
        assert_eq!(&short[12..qend], &q[12..qend]);
        // OPT 保留（问句带 EDNS）
        let opt = parse_rrs(&short)
            .unwrap()
            .into_iter()
            .find(|r| r.rtype == RR_OPT);
        assert!(opt.is_some(), "截断后应保留 OPT");
        assert_eq!(read_u16(&short, 10), Some(1), "arcount 应为 1（仅 OPT）");

        // 尺寸足够时原样返回
        let full = truncate_for_udp(&resp, 4096);
        assert_eq!(full.len(), resp.len());
        assert_eq!(full[2] & 0x02, 0);
    }

    #[test]
    fn cache_key_separates_do_bit_and_skips_edns_options() {
        let q = query("do.test", 1);
        let resp = build_a_response(&q, &[[1, 2, 3, 4]], 30).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        let do_edns = EdnsInfo {
            present: true,
            udp_size: 1232,
            do_bit: true,
            has_options: false,
        };
        assert!(c.insert(&parse_query(&q).unwrap(), &do_edns, &resp, t0));
        // 无 DO 的查询不能命中带 DO 的条目
        assert!(c
            .answer_from_cache(&q, &parse_query(&q).unwrap(), &no_edns(), t0)
            .is_none());
        assert!(c
            .answer_from_cache(&q, &parse_query(&q).unwrap(), &do_edns, t0)
            .is_some());

        // 带 EDNS options（ECS 等）：不入缓存、不命中
        let opt_edns = EdnsInfo {
            present: true,
            udp_size: 1232,
            do_bit: false,
            has_options: true,
        };
        assert!(!c.insert(&parse_query(&q).unwrap(), &opt_edns, &resp, t0));
        assert!(c
            .answer_from_cache(&q, &parse_query(&q).unwrap(), &opt_edns, t0)
            .is_none());
    }

    #[test]
    fn cache_hit_ages_additional_records_but_not_opt() {
        let q = query("extra.test", 1);
        let mut resp = build_a_response(&q, &[[1, 1, 1, 1]], 30).unwrap();
        resp[10..12].copy_from_slice(&2u16.to_be_bytes()); // arcount=2
                                                           // OPT
        resp.push(0);
        put_u16(&mut resp, RR_OPT);
        put_u16(&mut resp, 4096);
        resp.extend_from_slice(&0u32.to_be_bytes());
        put_u16(&mut resp, 0);
        // 普通 additional RR：TXT，ttl 30
        resp.push(0);
        put_u16(&mut resp, 16);
        put_u16(&mut resp, 1);
        resp.extend_from_slice(&30u32.to_be_bytes());
        put_u16(&mut resp, 2);
        resp.extend_from_slice(&[1, b'x']);
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        assert!(c.insert(&parse_query(&q).unwrap(), &no_edns(), &resp, t0));
        let hit = c
            .answer_from_cache(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                t0 + Duration::from_secs(5),
            )
            .unwrap();
        let rrs = parse_rrs(&hit).unwrap();
        let txt = rrs.iter().find(|r| r.rtype == 16).unwrap();
        assert_eq!(txt.ttl, 25, "普通 additional RR 应递减（对照 dae）");
        let opt = rrs.iter().find(|r| r.rtype == RR_OPT).unwrap();
        assert_eq!(opt.ttl, 0, "OPT 的 TTL 字段不动");
    }

    #[test]
    fn refresh_single_flight() {
        let mut c = DnsCache::default();
        assert!(c.begin_refresh("k"));
        assert!(!c.begin_refresh("k"), "同 key 在飞时应合并");
        assert_eq!(c.refreshing_len(), 1);
        c.end_refresh("k");
        assert!(c.begin_refresh("k"), "结束后可再次发起");
    }

    #[test]
    fn negative_response_classification() {
        let q = query("neg.test", 1);
        // NXDOMAIN（rcode=3）
        let mut nx = build_a_response(&q, &[], 30).unwrap();
        nx[3] = (nx[3] & 0xF0) | 3;
        assert!(is_negative_response(&nx, 1));
        // NOERROR 无 A 也无 CNAME
        let empty = build_a_response(&q, &[], 30).unwrap();
        assert!(is_negative_response(&empty, 1));
        // 有 A → 非负
        let pos = build_a_response(&q, &[[1, 2, 3, 4]], 30).unwrap();
        assert!(!is_negative_response(&pos, 1));
        // SERVFAIL 不当作负答（不能取代旧正值）
        let mut fail = build_a_response(&q, &[[1, 2, 3, 4]], 30).unwrap();
        fail[3] = (fail[3] & 0xF0) | 2;
        assert!(!is_negative_response(&fail, 1));
    }

    // ------------------------------------------------ P28：ECS 回填 / ecs_cache

    /// 构一个带 ECS 回显 OPT 的应答（QR=1，附一条 A）。
    fn build_a_response_ecs(q: &[u8], addr: [u8; 4], src_prefix: u8, scope_prefix: u8) -> Vec<u8> {
        let resp = build_a_response(q, &[addr], 30).unwrap();
        let mut resp = resp;
        // 追加 OPT RR：RDATA = ECS option（带 scope 回显）
        let mut opt_data = Vec::new();
        opt_data.extend_from_slice(&1u16.to_be_bytes()); // family v4
        opt_data.push(src_prefix);
        opt_data.push(scope_prefix);
        let nbytes = (src_prefix as usize).div_ceil(8);
        opt_data.extend_from_slice(&addr[..nbytes]);
        let rdlen = 4 + opt_data.len();
        let ar = u16::from_be_bytes([resp[10], resp[11]]) + 1;
        resp[10..12].copy_from_slice(&ar.to_be_bytes());
        resp.push(0);
        resp.extend_from_slice(&RR_OPT.to_be_bytes());
        resp.extend_from_slice(&4096u16.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&(rdlen as u16).to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.extend_from_slice(&(opt_data.len() as u16).to_be_bytes());
        resp.extend_from_slice(&opt_data);
        resp
    }

    #[test]
    fn parse_ecs_echo_variants() {
        let q = query("echo.test", 1);
        let resp = build_a_response_ecs(&q, [10, 1, 2, 0], 24, 0);
        let e = parse_ecs_echo(&resp).unwrap();
        assert_eq!(e.family, 1);
        assert_eq!(e.src.to_string(), "10.1.2.0");
        assert_eq!((e.src_prefix, e.scope_prefix), (24, 0));
        let resp = build_a_response_ecs(&q, [10, 1, 0, 0], 16, 16);
        let e = parse_ecs_echo(&resp).unwrap();
        assert_eq!(
            (e.src.to_string().as_str(), e.scope_prefix),
            ("10.1.0.0", 16)
        );
        // 无 OPT → None；普通应答不报错
        let plain = build_a_response(&q, &[[1, 2, 3, 4]], 30).unwrap();
        assert!(parse_ecs_echo(&plain).is_none());
        assert!(parse_ecs_echo(&q).is_none());
    }

    #[test]
    fn ecs_scope_ladder_order_and_truncation() {
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let ladder = ecs_scope_ladder(ip, 24);
        assert_eq!(
            ladder,
            vec![
                ("10.1.2.0".parse().unwrap(), 24),
                ("10.1.2.3".parse().unwrap(), 32),
                ("10.1.0.0".parse().unwrap(), 20),
                ("10.1.0.0".parse().unwrap(), 16),
                ("10.0.0.0".parse().unwrap(), 12),
                ("10.0.0.0".parse().unwrap(), 8),
                ("0.0.0.0".parse().unwrap(), 0),
            ]
        );
        let v6: IpAddr = "2001:db8:1:2::5".parse().unwrap();
        let ladder6 = ecs_scope_ladder(v6, 56);
        assert_eq!(ladder6[0], ("2001:db8:1::".parse().unwrap(), 56));
        assert_eq!(ladder6[1], (v6, 128));
        assert!(ladder6.contains(&("2001:db8::".parse().unwrap(), 32)));
        assert_eq!(ladder6.last().unwrap().1, 0);
    }

    #[test]
    fn ecs_cache_reuses_echoed_broader_scope() {
        let q = query("share.test", 1);
        let resp = build_a_response(&q, &[[7, 7, 7, 7]], 30).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        // 上游声明 scope=/16（地址截断到 /16）→ 按回填键插入
        assert!(c.insert_scoped(
            &parse_query(&q).unwrap(),
            &no_edns(),
            "legacy|up|ecs=10.1.0.0/16",
            &resp,
            t0
        ));
        // 同 /16 内另一个 /24 的客户端（请求前缀 /24）命中
        let hit = c.answer_from_cache_ecs(
            &q,
            &parse_query(&q).unwrap(),
            &no_edns(),
            "legacy|up",
            Some(("10.1.9.9".parse().unwrap(), 24)),
            t0 + Duration::from_secs(5),
        );
        assert!(hit.is_some());
        // 不同 /16 的客户端不命中
        assert!(c
            .answer_from_cache_ecs(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                "legacy|up",
                Some(("10.2.9.9".parse().unwrap(), 24)),
                t0 + Duration::from_secs(5),
            )
            .is_none());
    }

    #[test]
    fn ecs_cache_global_scope_zero_and_host_prefix() {
        let q = query("global.test", 1);
        let resp = build_a_response(&q, &[[8, 8, 8, 8]], 30).unwrap();
        let t0 = Instant::now();
        let mut c = DnsCache::default();
        // scope=0（全局）→ 任何子网（含本机 /32 候选）都能命中
        assert!(c.insert_scoped(
            &parse_query(&q).unwrap(),
            &no_edns(),
            "legacy|up|ecs=0.0.0.0/0",
            &resp,
            t0
        ));
        assert!(c
            .answer_from_cache_ecs(
                &q,
                &parse_query(&q).unwrap(),
                &no_edns(),
                "legacy|up",
                Some(("192.0.2.254".parse().unwrap(), 24)),
                t0 + Duration::from_secs(1),
            )
            .is_some());
        // scope=32（仅本机）→ 同一客户端的 /32 候选命中；别的客户端不命中
        let q2 = query("narrow.test", 1);
        let resp2 = build_a_response(&q2, &[[9, 9, 9, 9]], 30).unwrap();
        assert!(c.insert_scoped(
            &parse_query(&q2).unwrap(),
            &no_edns(),
            "legacy|up|ecs=10.9.9.9/32",
            &resp2,
            t0
        ));
        assert!(c
            .answer_from_cache_ecs(
                &q2,
                &parse_query(&q2).unwrap(),
                &no_edns(),
                "legacy|up",
                Some(("10.9.9.9".parse().unwrap(), 24)),
                t0 + Duration::from_secs(1),
            )
            .is_some());
        assert!(c
            .answer_from_cache_ecs(
                &q2,
                &parse_query(&q2).unwrap(),
                &no_edns(),
                "legacy|up",
                Some(("10.9.9.10".parse().unwrap(), 24)),
                t0 + Duration::from_secs(1),
            )
            .is_none());
        // 带 EDNS options（客户端自带 ECS）不进缓存（既有语义）
        let opt = EdnsInfo {
            present: true,
            udp_size: 1232,
            do_bit: false,
            has_options: true,
        };
        assert!(c
            .answer_from_cache_ecs(
                &q,
                &parse_query(&q).unwrap(),
                &opt,
                "legacy|up",
                Some(("192.0.2.254".parse().unwrap(), 24)),
                t0 + Duration::from_secs(1),
            )
            .is_none());
    }
}

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

use crate::rules::DomainSetSpec;
use std::collections::HashMap;
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
            let ptr = (((len & 0x3f) as usize) << 8) | *buf.get(off + 1)? as usize;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
    /// DNSSEC OK：影响上游是否附带 RRSIG，对照 dae 的 EDNS 元数据保留。
    do_bit: bool,
}

struct CacheEntry {
    response: Vec<u8>,
    /// 应答中 question 段结束位置（命中时按客户端 question 回填）。
    question_end: usize,
    stored: Instant,
    ttl: u32,
}

/// 上游应答缓存（对照 dae `dns_cache.go` 的最小语义：正/负缓存 + 命中时按剩余寿命递减 TTL）。
#[derive(Default)]
pub struct DnsCache {
    map: HashMap<CacheKey, CacheEntry>,
    pub hits: u64,
    pub misses: u64,
    pub expired: u64,
    pub inserts: u64,
    pub evictions: u64,
}

impl DnsCache {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// 命中则返回给客户端的应答（改 ID、回填 question、递减 TTL）；否则计 miss 并返回 None。
    /// 带 EDNS options（非 DO）的查询不命中（ECS 等选项会改变上游应答）。
    pub fn answer_from_cache(
        &mut self,
        query: &[u8],
        q: &Question,
        edns: &EdnsInfo,
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
        };
        let Some(e) = self.map.get(&key) else {
            self.misses += 1;
            return None;
        };
        let elapsed = now.saturating_duration_since(e.stored).as_secs() as u32;
        if elapsed >= e.ttl {
            self.map.remove(&key);
            self.expired += 1;
            self.misses += 1;
            return None;
        }
        self.hits += 1;
        Some(prepare_cached(&e.response, e.question_end, query, elapsed))
    }

    /// 按语义入缓存；返回是否已缓存。带 EDNS options 的查询不入缓存。
    pub fn insert(&mut self, q: &Question, edns: &EdnsInfo, response: &[u8], now: Instant) -> bool {
        if edns.has_options {
            return false;
        }
        let Some(entry) = build_entry(response, now) else {
            return false;
        };
        let key = CacheKey {
            qname: q.qname.clone(),
            qtype: q.qtype,
            qclass: q.qclass,
            do_bit: edns.do_bit,
        };
        if self.map.contains_key(&key) {
            self.map.insert(key, entry);
            self.inserts += 1;
            return true;
        }
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
        self.map.insert(key, entry);
        self.inserts += 1;
        true
    }

    fn sweep_expired(&mut self, now: Instant) {
        let dead: Vec<CacheKey> = self
            .map
            .iter()
            .filter(|(_, e)| now.saturating_duration_since(e.stored).as_secs() as u32 >= e.ttl)
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

/// 判断一个应答能否入缓存，并计算缓存寿命。
fn build_entry(response: &[u8], now: Instant) -> Option<CacheEntry> {
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
    if ttl == 0 {
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

// ---------------------------------------------------------------- 域名匹配

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// 对照 dae 的 RoutingDomainKey 语义。regex 需要编译后的 `Regex`，本函数只处理
/// 字符串匹配种类（regex 请走 `matched_bitmap` / `domain_set_matches`）。
pub fn domain_match(key: &str, pattern: &str, qname: &str) -> bool {
    let q = normalize(qname);
    let p = normalize(pattern);
    if p.is_empty() || q.is_empty() {
        return false;
    }
    match key {
        "full" => q == p,
        "keyword" => q.contains(&p),
        "suffix" => q == p || q.ends_with(&format!(".{p}")),
        // regex 无编译后形式，不在此函数里静默按 suffix 处理
        _ => false,
    }
}

/// 一个 domain 集合是否命中 qname（regex 用编译好的模式；对照 dae：qname 小写化、
/// regex 模式保持原大小写、非锚定匹配）。
pub fn domain_set_matches(spec: &DomainSetSpec, qname: &str) -> bool {
    if spec.key == "regex" {
        let q = normalize(qname);
        !q.is_empty() && spec.regexes.iter().any(|r| r.is_match(&q))
    } else {
        spec.domains
            .iter()
            .any(|pat| domain_match(&spec.key, pat, qname))
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

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
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
        assert!(domain_match("full", "direct.test", "direct.test"));
        assert!(!domain_match("full", "direct.test", "x.direct.test"));
        assert!(domain_match("keyword", "kw", "www.kw.example"));
    }

    #[test]
    fn bitmap_bits_follow_match_set_index() {
        let sets = vec![
            DomainSetSpec {
                match_set_index: 0,
                key: "suffix".into(),
                domains: vec!["proxy.test".into()],
                regexes: vec![],
            },
            DomainSetSpec {
                match_set_index: 33,
                key: "keyword".into(),
                domains: vec!["kw".into()],
                regexes: vec![],
            },
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
        let spec = DomainSetSpec {
            match_set_index: 5,
            key: "regex".into(),
            domains: vec![r"^api[0-9]+\.regex\.test$".into()],
            regexes: vec![Regex::new(r"^api[0-9]+\.regex\.test$").unwrap()],
        };
        let sets = vec![spec];
        let (bits, hits) = matched_bitmap(&sets, "API1.Regex.Test.");
        assert_eq!(hits, 1);
        assert_eq!(bits[0], 1 << 5);
        let (bits2, hits2) = matched_bitmap(&sets, "web.regex.test");
        assert_eq!(hits2, 0);
        assert!(bits2.iter().all(|w| *w == 0));
        // 大写模式不会命中（qname 已小写化，对照 dae 行为）
        let upper = DomainSetSpec {
            match_set_index: 0,
            key: "regex".into(),
            domains: vec!["API".into()],
            regexes: vec![Regex::new("API").unwrap()],
        };
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
}

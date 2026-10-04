// SPDX-License-Identifier: GPL-2.0
//! mini-dae 的路由规则：解析 + 编译。
//!
//! 语法是 dae `.dae` 路由规则的一个子集（每条规则一行）：
//!
//! ```text
//! dip(1.1.1.1/32, 10.9.9.0/24) && dport(8080) -> proxy
//! !dport(9999) && sip(10.0.0.0/24) -> direct
//! l4proto(udp) && dport(443) -> proxy(must)
//! mac('00:11:22:33:44:55') -> direct
//! fallback -> direct
//! ```
//!
//! 与 dae 的语义对齐（对照 `component/routing/matcher_builder.go:44-101` 与
//! `control/routing_matcher_builder.go`）：
//!
//! - `&&` 连接函数（dae 的 `AndFunctions`）；函数内部的多个参数是 **OR**；
//! - 集合类函数（`dip`/`sip`/`mac`）折叠成**一个** match_set（一个 LPM trie）；
//!   `l4proto`/`ipversion` 折叠成一个掩码 match_set；
//!   标量类函数（`dport`/`sport`/`dscp`）展开成**多个** match_set（OR）；
//! - outbound 编码（= dae `ebpf_generated.go`）：
//!   非最后一个 match_set 用 `LogicalOr(0xFE)`（粘性 OR），
//!   非最后一个函数的最后一个 match_set 用 `LogicalAnd(0xFF)`，
//!   整条规则的最后一个 match_set 用真实 outbound。
//!
//! 未实现的 dae 能力（会显式报错，而不是静默忽略）：`pname()` 进程名、outbound 组名映射。
//! domain 的 suffix/full/keyword/regex 四种 key 均已支持（regex 在前编译期编译，匹配发生在
//! 用户态，见 ADR-0014）。P17a 起 `dip(geoip:…)`/`dip(ext:…)` 与 `domain(geosite:…)`/
//! `domain(ext:…)` 在编译期展开（`geodata.rs`，对照 dae `DatReaderOptimizer`）。

use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::geodata::{self, Geodata};

/// 与 `ebpf-rs/src/common.rs` 的 `MINI_MAX_MATCH_SET_LEN` 保持一致。
pub const MAX_MATCH_SET_LEN: u32 = 64;

/// 与 `ebpf-rs/src/maps.rs` 的内层 LPM 模板一致（map-in-map 的 template 匹配要求）。
/// P17a：对齐 dae `tproxy.c:75` 的 `max_entries=2,048,000`（`geoip:cn` ≈15k、
/// `geoip:us` ≈293k；NO_PREALLOC 下容量只是上限，内存随实际插入增长）。
pub const LPM_MAX_ENTRIES: u32 = 2_048_000;
/// LPM trie 必须用 BPF_F_NO_PREALLOC。
pub const BPF_F_NO_PREALLOC: u32 = 1;

// ---- match 类型（= dae common/consts/ebpf_sync_defs.h） ----
pub const MATCH_DOMAIN_SET: u8 = 0;
pub const MATCH_IP_SET: u8 = 1;
pub const MATCH_SOURCE_IP_SET: u8 = 2;
pub const MATCH_PORT: u8 = 3;
pub const MATCH_SOURCE_PORT: u8 = 4;
pub const MATCH_L4_PROTO: u8 = 5;
pub const MATCH_IP_VERSION: u8 = 6;
pub const MATCH_MAC: u8 = 7;
/// P17b：pname（= dae `MatchType_Pname`，值区存 16 字节进程名，NUL 补全）
pub const MATCH_PNAME: u8 = 8;
pub const MATCH_DSCP: u8 = 9;
pub const MATCH_FALLBACK: u8 = 10;

// ---- outbound 编码（= dae common/consts/ebpf_generated.go） ----
pub const OUTBOUND_DIRECT: u8 = 0x00;
pub const OUTBOUND_BLOCK: u8 = 0x01;
/// P19：用户组 outbound 索引基址（direct=0 / block=1，用户组 2、3、… 至 0xFB）。
pub const GROUP_INDEX_BASE: u8 = 2;
/// 兼容旧名：无组映射时的隐式 proxy 组索引。
pub const OUTBOUND_PROXY: u8 = GROUP_INDEX_BASE;
pub const OUTBOUND_MUST_RULES: u8 = 0xFC;
pub const OUTBOUND_LOGICAL_OR: u8 = 0xFE;
pub const OUTBOUND_LOGICAL_AND: u8 = 0xFF;

/// 与 C 侧 `struct mini_match_set` 完全同位（24 字节）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MatchSet {
    /// union：LPM 下标 / 端口范围 / 掩码 / dscp
    pub value: [u8; 16],
    pub not: u8,
    pub type_: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

unsafe impl aya::Pod for MatchSet {}

impl MatchSet {
    pub fn lpm_index(&self) -> u32 {
        u32::from_ne_bytes(self.value[0..4].try_into().unwrap())
    }
    pub fn port_range(&self) -> (u16, u16) {
        (
            u16::from_ne_bytes(self.value[0..2].try_into().unwrap()),
            u16::from_ne_bytes(self.value[2..4].try_into().unwrap()),
        )
    }
    pub fn mask(&self) -> u32 {
        u32::from_ne_bytes(self.value[0..4].try_into().unwrap())
    }
    pub fn dscp(&self) -> u8 {
        self.value[0]
    }
}

#[derive(Debug, Clone)]
pub struct DomainSetSpec {
    /// 位图位下标 = match_set 在数组中的位置（对照 dae simulatedDomainSet.RuleIndex）
    pub match_set_index: u32,
    /// suffix / full / keyword / regex（对照 dae RoutingDomainKey）
    pub key: String,
    pub domains: Vec<String>,
    /// key=regex 时在编译期编译好的模式（对照 dae `regexp.Compile`；编译错误是硬失败）
    pub regexes: Vec<Regex>,
    /// P17a：预计算匹配索引（suffix/full 哈希 + 前导点语义；keyword/regex 留存待扫）
    pub index: DomainIndex,
}

/// 域名集合的预计算索引。语义对照 dae `ahocorasick_slimtrie.go`：
/// - suffix 无前导点：匹配裸域与子域；带前导点（`.example.com`）：只匹配子域；
/// - full：全等；keyword：子串；regex：编译后的模式。
/// 大小写：qname 与模式均小写化后匹配（与 dae 一致）。
#[derive(Debug, Clone, Default)]
pub struct DomainIndex {
    /// 无前导点 suffix（apex + sub）
    pub suffix: HashSet<String>,
    /// 带前导点 suffix（sub only）
    pub suffix_sub_only: HashSet<String>,
    pub full: HashSet<String>,
}

impl DomainSetSpec {
    /// 构建一个 domain 集合（regex 编译 + 索引）。编译错误 → 整条规则硬失败。
    pub fn build(match_set_index: u32, key: &str, domains: &[String]) -> Result<Self, String> {
        let regexes = if key == "regex" {
            domains
                .iter()
                .map(|pat| {
                    Regex::new(pat).map_err(|e| format!("domain(regex: {pat}) 编译失败: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let mut index = DomainIndex::default();
        match key {
            "suffix" => {
                for d in domains {
                    let d = d.trim_end_matches('.').to_ascii_lowercase();
                    if d.is_empty() {
                        continue;
                    }
                    if let Some(sub) = d.strip_prefix('.') {
                        if !sub.is_empty() {
                            index.suffix_sub_only.insert(sub.to_string());
                        }
                    } else {
                        index.suffix.insert(d);
                    }
                }
            }
            "full" => {
                for d in domains {
                    let d = d.trim_end_matches('.').to_ascii_lowercase();
                    if !d.is_empty() {
                        index.full.insert(d);
                    }
                }
            }
            _ => {}
        }
        Ok(Self {
            match_set_index,
            key: key.to_string(),
            domains: domains.to_vec(),
            regexes,
            index,
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct CompiledRules {
    pub sets: Vec<MatchSet>,
    /// match_set 下标 -> 该 match_set 的 LPM 前缀（prefixlen, 16 字节键）
    pub lpm_tries: BTreeMap<u32, Vec<(u32, [u8; 16])>>,
    /// domain 规则（用户态 DNS 应答经过时据此写域位图）
    pub domain_sets: Vec<DomainSetSpec>,
    /// P17a：编译期展开说明（geoip/geosite/ext 展宽了多少条），供日志/状态面
    pub notes: Vec<String>,
}

// ------------------------------------------------------------------
// 词法 / 语法
// ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Quoted(String),
    Not,
    And,
    Arrow,
    Comma,
    LParen,
    RParen,
    Colon,
}

fn lex(line: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = line.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            ' ' | '\t' | '\r' => i += 1,
            '#' => break,
            '!' => {
                out.push(Tok::Not);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            ':' => {
                out.push(Tok::Colon);
                i += 1;
            }
            '\'' => {
                let mut j = i + 1;
                let mut s = String::new();
                while j < b.len() && b[j] != '\'' {
                    s.push(b[j]);
                    j += 1;
                }
                if j >= b.len() {
                    return Err(format!("未闭合的引号: {line}"));
                }
                out.push(Tok::Quoted(s));
                i = j + 1;
            }
            '-' if b.get(i + 1) == Some(&'>') => {
                out.push(Tok::Arrow);
                i += 2;
            }
            '&' if b.get(i + 1) == Some(&'&') => {
                out.push(Tok::And);
                i += 2;
            }
            _ => {
                // word：允许 IPv4/CIDR/端口范围/十六进制等。
                // 注意 ':' 恒为独立 token（所以 MAC 必须像 dae 文档那样写成 mac('aa:bb:...')）。
                let mut j = i;
                let mut s = String::new();
                while j < b.len() {
                    let ch = b[j];
                    if ch.is_alphanumeric() || "._/%*~-".contains(ch) {
                        s.push(ch);
                        j += 1;
                    } else {
                        break;
                    }
                }
                if s.is_empty() {
                    return Err(format!("无法解析的字符 '{c}': {line}"));
                }
                out.push(Tok::Word(s));
                i = j;
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct Arg {
    /// None = 无 key 参数
    key: Option<String>,
    val: String,
}

impl Arg {
    fn bare(val: String) -> Self {
        Self { key: None, val }
    }
    fn display(&self) -> String {
        match &self.key {
            Some(k) => format!("{k}:{}", self.val),
            None => self.val.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct Func {
    name: String,
    not: bool,
    args: Vec<Arg>,
}

/// 仅接受无 key 参数的函数（dip/sip/mac/l4proto/…；domain 例外）。
fn bare_values(f: &Func) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for a in &f.args {
        if a.key.is_some() {
            return Err(format!(
                "函数 {} 不支持带 key 参数（{}）",
                f.name,
                a.display()
            ));
        }
        out.push(a.val.clone());
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct Outbound {
    id: u8,
    mark: u32,
    must: bool,
    /// P19：原始组名（built-in 外由 `resolve_outbound_id` 查组索引）。
    name: String,
}

#[derive(Debug, Clone)]
struct Rule {
    funcs: Vec<Func>,
    outbound: Outbound,
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn expect(&mut self, t: &Tok, what: &str) -> Result<(), String> {
        match self.next() {
            Some(x) if &x == t => Ok(()),
            other => Err(format!("期望 {what}，得到 {other:?}")),
        }
    }
    fn word(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w),
            Some(Tok::Quoted(w)) => Ok(w),
            other => Err(format!("期望标识/取值，得到 {other:?}")),
        }
    }

    fn parse_func(&mut self) -> Result<Func, String> {
        // 注意先 peek 再消费：不能无条件 next()，否则会把函数名吞掉。
        let not = if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            true
        } else {
            false
        };
        let name = self.word()?;
        let mut args = Vec::new();
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.next();
            if !matches!(self.peek(), Some(Tok::RParen)) {
                loop {
                    // 允许 key: value（domain 的分组靠它；dip 的 geoip/ext 也用它），
                    // 并允许第二段冒号（ext:file:code → key=ext, val=file:code）。
                    let first = self.word()?;
                    let arg = if matches!(self.peek(), Some(Tok::Colon)) {
                        self.next();
                        let mut v = self.word()?;
                        while matches!(self.peek(), Some(Tok::Colon)) {
                            self.next();
                            v.push(':');
                            v.push_str(&self.word()?);
                        }
                        Arg {
                            key: Some(first),
                            val: v,
                        }
                    } else {
                        Arg::bare(first)
                    };
                    args.push(arg);
                    match self.next() {
                        Some(Tok::Comma) => continue,
                        Some(Tok::RParen) => break,
                        other => return Err(format!("函数参数后应为 ',' 或 ')'，得到 {other:?}")),
                    }
                }
            } else {
                self.next(); // RParen
            }
        }
        Ok(Func { name, not, args })
    }

    fn parse_outbound(&mut self) -> Result<Outbound, String> {
        let name = self.word()?;
        let mut mark = 0u32;
        let mut must = false;
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.next();
            if !matches!(self.peek(), Some(Tok::RParen)) {
                loop {
                    let w = self.word()?;
                    if matches!(self.peek(), Some(Tok::Colon)) {
                        self.next();
                        let v = self.word()?;
                        match w.as_str() {
                            "mark" => {
                                let s = v.trim_start_matches("0x");
                                mark = u32::from_str_radix(s, 16)
                                    .map_err(|e| format!("mark 解析失败 {v}: {e}"))?;
                            }
                            other => return Err(format!("不认识的 outbound 参数: {other}")),
                        }
                    } else if w == "must" {
                        must = true;
                    } else {
                        return Err(format!("不认识的 outbound 参数: {w}"));
                    }
                    match self.next() {
                        Some(Tok::Comma) => continue,
                        Some(Tok::RParen) => break,
                        other => {
                            return Err(format!("outbound 参数后应为 ',' 或 ')'，得到 {other:?}"))
                        }
                    }
                }
            } else {
                self.next();
            }
        }
        let id = match name.as_str() {
            "direct" => OUTBOUND_DIRECT,
            "block" => OUTBOUND_BLOCK,
            "must_rules" => OUTBOUND_MUST_RULES,
            // P19：其余是用户组名；真实索引由 compile 阶段的 groups 映射解析。
            _ => OUTBOUND_PROXY,
        };
        Ok(Outbound {
            id,
            mark,
            must,
            name,
        })
    }

    fn parse_rule(&mut self) -> Result<Rule, String> {
        let mut funcs = vec![self.parse_func()?];
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            funcs.push(self.parse_func()?);
        }
        self.expect(&Tok::Arrow, "->")?;
        let outbound = self.parse_outbound()?;
        if self.pos != self.toks.len() {
            return Err(format!("规则尾部有多余内容: {:?}", &self.toks[self.pos..]));
        }
        Ok(Rule { funcs, outbound })
    }
}

// ------------------------------------------------------------------
// 编译
// ------------------------------------------------------------------

/// 单个函数展开出的「半成品」match_set（outbound 尚未分配）。
#[derive(Debug, Clone, Default)]
struct Partial {
    type_: u8,
    value: [u8; 16],
    lpm: Option<Vec<(u32, [u8; 16])>>,
    /// 该函数携带的 not（dae: 函数的 Not 会打到它生成的每个 match_set 上）
    not: bool,
    /// domain 规则：(key, 域名列表)，仅 MATCH_DOMAIN_SET 使用
    domain: Option<(String, Vec<String>)>,
    /// 人类可读描述，用于后续错误/报告（当前未消费）
    #[allow(dead_code)]
    desc: String,
}

/// 前缀解析：IPv4（v4-mapped，前缀 +96）或 IPv6（原始 16 字节，0..=128）。
fn parse_ip_prefix(s: &str) -> Result<(u32, [u8; 16]), String> {
    let (addr_s, plen_s) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    if let Ok(v4) = addr_s.parse::<Ipv4Addr>() {
        let plen: u32 = match plen_s {
            Some(p) => p.parse().map_err(|_| format!("前缀长度非法: {s}"))?,
            None => 32,
        };
        if plen > 32 {
            return Err(format!("IPv4 前缀长度越界: {s}"));
        }
        let mut data = [0u8; 16];
        data[10] = 0xff;
        data[11] = 0xff;
        data[12..16].copy_from_slice(&v4.octets());
        return Ok((96 + plen, data));
    }
    if let Ok(v6) = addr_s.parse::<std::net::Ipv6Addr>() {
        let plen: u32 = match plen_s {
            Some(p) => p.parse().map_err(|_| format!("前缀长度非法: {s}"))?,
            None => 128,
        };
        if plen > 128 {
            return Err(format!("IPv6 前缀长度越界: {s}"));
        }
        return Ok((plen, v6.octets()));
    }
    Err(format!("前缀非法（不是 IPv4/IPv6 CIDR）: {s}"))
}

fn parse_mac(s: &str) -> Result<[u8; 16], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("MAC 需要 6 段: {s}"));
    }
    let mut data = [0u8; 16];
    for (i, p) in parts.iter().enumerate() {
        data[10 + i] = u8::from_str_radix(p, 16).map_err(|_| format!("MAC 段非法: {s}"))?;
    }
    Ok(data)
}

/// geodata CIDR → LPM 键（v4 → v4-mapped + 96，与 `parse_ip_prefix` 同规）。
fn prefix_from_cidr(c: &geodata::Cidr) -> Result<(u32, [u8; 16]), String> {
    let mut data = [0u8; 16];
    match c.ip.len() {
        4 => {
            if c.plen > 32 {
                return Err(format!("geoip v4 前缀长度越界: /{}", c.plen));
            }
            data[10] = 0xff;
            data[11] = 0xff;
            data[12..16].copy_from_slice(&c.ip);
            Ok((96 + c.plen, data))
        }
        16 => {
            if c.plen > 128 {
                return Err(format!("geoip v6 前缀长度越界: /{}", c.plen));
            }
            data.copy_from_slice(&c.ip);
            Ok((c.plen, data))
        }
        n => Err(format!("geoip CIDR ip 长度非法（{n} 字节）")),
    }
}

fn require_geo<'a>(geo: Option<&'a Geodata>, what: &str) -> Result<&'a Geodata, String> {
    geo.ok_or_else(|| {
        format!("{what} 需要 geodata 文件（用 --geodata-dir 或 DAE_LOCATION_ASSET 指定目录）")
    })
}

/// domain 分组：保持首次出现的 key 顺序，去重完全相同的 (key, value)。
fn group_put(
    order: &mut Vec<String>,
    grouped: &mut BTreeMap<String, Vec<String>>,
    seen: &mut HashSet<(String, String)>,
    key: &str,
    val: String,
) {
    if !seen.insert((key.to_string(), val.clone())) {
        return;
    }
    if !grouped.contains_key(key) {
        order.push(key.to_string());
    }
    grouped.entry(key.to_string()).or_default().push(val);
}

fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    match s.split_once('-') {
        Some((a, b)) => {
            let a: u16 = a.parse().map_err(|_| format!("端口非法: {s}"))?;
            let b: u16 = b.parse().map_err(|_| format!("端口非法: {s}"))?;
            if a > b {
                return Err(format!("端口区间倒置: {s}"));
            }
            Ok((a, b))
        }
        None => {
            let p: u16 = s.parse().map_err(|_| format!("端口非法: {s}"))?;
            Ok((p, p))
        }
    }
}

fn expand_func(
    f: &Func,
    geo: Option<&Geodata>,
    notes: &mut Vec<String>,
) -> Result<Vec<Partial>, String> {
    if f.args.is_empty() && f.name != "fallback" {
        return Err(format!("函数 {} 需要至少一个参数", f.name));
    }
    let not = f.not;
    match f.name.as_str() {
        // 集合类：折叠成一个 match_set（一个 LPM trie / 一个掩码）
        "dip" | "sip" => {
            let (type_, name) = if f.name == "dip" {
                (MATCH_IP_SET, "dip")
            } else {
                (MATCH_SOURCE_IP_SET, "sip")
            };
            let mut prefixes = Vec::new();
            for a in &f.args {
                match a.key.as_deref() {
                    None => prefixes.push(parse_ip_prefix(&a.val)?),
                    Some("geoip") => {
                        let geo = require_geo(geo, &format!("{name}(geoip:{})", a.val))?;
                        let hit = geo.geoip_code(&a.val)?;
                        notes.push(format!("{name}(geoip:{}) → {} 条前缀", a.val, hit.0.len()));
                        for c in hit.0.iter() {
                            prefixes.push(prefix_from_cidr(c)?);
                        }
                    }
                    Some("ext") => {
                        let (file, code) = geodata::split_ext(&a.val)?;
                        let geo = require_geo(geo, &format!("{name}(ext:{})", a.val))?;
                        let hit = geo.geoip_ext(file, code)?;
                        notes.push(format!("{name}(ext:{}) → {} 条前缀", a.val, hit.0.len()));
                        for c in hit.0.iter() {
                            prefixes.push(prefix_from_cidr(c)?);
                        }
                    }
                    Some(other) => {
                        return Err(format!(
                            "{name}(…) 不认识的 key: {other}（可用 geoip/ext 或裸 CIDR）"
                        ))
                    }
                }
            }
            if prefixes.is_empty() {
                return Err(format!("{name}(…) 展开为空"));
            }
            Ok(vec![Partial {
                type_,
                value: [0u8; 16],
                lpm: Some(prefixes),
                not,
                domain: None,
                desc: format!("{name}({} 项)", f.args.len()),
            }])
        }
        "mac" => {
            let vals = bare_values(f)?;
            let mut prefixes = Vec::new();
            for a in &vals {
                prefixes.push((128u32, parse_mac(a)?));
            }
            Ok(vec![Partial {
                type_: MATCH_MAC,
                value: [0u8; 16],
                lpm: Some(prefixes),
                not,
                domain: None,
                desc: format!("mac({})", vals.join(",")),
            }])
        }
        // P17b：进程名。16 字节定长（含 NUL 补全），超长截断（dae 同：日志提醒后截断）；
        // 多参数 = OR（每个值一个 match_set，与 dport 同形）。匹配只在 WAN egress
        // 新连接（本机发起的流量），语义见 route.rs。
        "pname" => {
            // dae 对非 ip/sip 函数参数按字符串序排序；多值 = OR，顺序影响 match_set 下标。
            let mut vals: Vec<String> = f
                .args
                .iter()
                .map(|a| {
                    if a.key.is_some() {
                        return Err(format!("pname 不支持带 key 参数（{}）", a.display()));
                    }
                    Ok(a.val.clone())
                })
                .collect::<Result<Vec<_>, String>>()?;
            vals.sort();
            let mut out = Vec::new();
            for v in &vals {
                let raw = v.as_bytes();
                if raw.is_empty() {
                    return Err("pname(...) 参数为空".into());
                }
                if raw.contains(&0) {
                    return Err("pname(...) 不能包含 NUL".into());
                }
                let mut value = [0u8; 16];
                let n = raw.len().min(16);
                value[..n].copy_from_slice(&raw[..n]);
                if raw.len() > 16 {
                    notes.push(format!(
                        "pname({}) 超过 16 字节，截断为 {}",
                        v,
                        String::from_utf8_lossy(&raw[..n])
                    ));
                }
                out.push(Partial {
                    type_: MATCH_PNAME,
                    value,
                    lpm: None,
                    not,
                    domain: None,
                    desc: format!("pname({v})"),
                });
            }
            Ok(out)
        }
        "l4proto" => {
            let vals = bare_values(f)?;
            let mut mask = 0u32;
            for a in &vals {
                mask |= match a.as_str() {
                    "tcp" => 1,
                    "udp" => 2,
                    "tcp_udp" => 3,
                    other => return Err(format!("l4proto 只支持 tcp/udp/tcp_udp: {other}")),
                };
            }
            let mut p = Partial {
                type_: MATCH_L4_PROTO,
                value: [0u8; 16],
                lpm: None,
                not,
                domain: None,
                desc: format!("l4proto({})", vals.join(",")),
            };
            p.value[0..4].copy_from_slice(&mask.to_ne_bytes());
            Ok(vec![p])
        }
        "ipversion" => {
            let vals = bare_values(f)?;
            let mut mask = 0u32;
            for a in &vals {
                mask |= match a.as_str() {
                    "4" => 1,
                    "6" => 2,
                    other => return Err(format!("ipversion 只支持 4/6: {other}")),
                };
            }
            let mut p = Partial {
                type_: MATCH_IP_VERSION,
                value: [0u8; 16],
                lpm: None,
                not,
                domain: None,
                desc: format!("ipversion({})", vals.join(",")),
            };
            p.value[0..4].copy_from_slice(&mask.to_ne_bytes());
            Ok(vec![p])
        }
        // domain：每个 key 一组域名 → 各自一个 match_set（同函数内 OR）。
        // 无 key 视为 suffix（dae 文档：No key indicates suffix）。匹配发生在
        // 用户态 DNS 应答经过时（写域位图），数据面只读位图。
        // P17a：`geosite:code[@attr]` 与 `ext:file:code` 在编译期展开为域名参数。
        "domain" => {
            if f.args.is_empty() {
                return Err("domain(...) 需要至少一个参数".into());
            }
            let mut order: Vec<String> = Vec::new();
            let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let mut seen: HashSet<(String, String)> = HashSet::new();
            for a in &f.args {
                match a.key.as_deref() {
                    None => group_put(&mut order, &mut grouped, &mut seen, "suffix", a.val.clone()),
                    Some(k @ ("suffix" | "full" | "keyword" | "regex")) => {
                        group_put(&mut order, &mut grouped, &mut seen, k, a.val.clone())
                    }
                    Some("geosite") => {
                        let geo = require_geo(geo, &format!("domain(geosite:{})", a.val))?;
                        let hit = geo.geosite_code(&a.val)?;
                        notes.push(format!("domain(geosite:{}) → {} 条域名", a.val, hit.len()));
                        for e in hit.iter() {
                            group_put(
                                &mut order,
                                &mut grouped,
                                &mut seen,
                                e.dtype.routing_key(),
                                e.value.clone(),
                            );
                        }
                    }
                    Some("ext") => {
                        let (file, code) = geodata::split_ext(&a.val)?;
                        let geo = require_geo(geo, &format!("domain(ext:{})", a.val))?;
                        let hit = geo.geosite_ext(file, code)?;
                        notes.push(format!("domain(ext:{}) → {} 条域名", a.val, hit.len()));
                        for e in hit.iter() {
                            group_put(
                                &mut order,
                                &mut grouped,
                                &mut seen,
                                e.dtype.routing_key(),
                                e.value.clone(),
                            );
                        }
                    }
                    Some(other) => {
                        return Err(format!(
                            "domain(…) 不认识的 key: {other}（可用 suffix/full/keyword/regex/geosite/ext）"
                        ))
                    }
                }
            }
            let mut out = Vec::new();
            for key in order {
                let doms = grouped.remove(&key).unwrap_or_default();
                if doms.is_empty() {
                    continue;
                }
                out.push(Partial {
                    type_: MATCH_DOMAIN_SET,
                    value: [0u8; 16],
                    lpm: None,
                    not,
                    domain: Some((key.clone(), doms.clone())),
                    desc: format!("domain({key}: {} 条)", doms.len()),
                });
            }
            if out.is_empty() {
                return Err("domain(...) 展开为空".into());
            }
            Ok(out)
        }
        // 标量类：每个参数一个 match_set（OR）
        "dport" | "sport" => {
            let type_ = if f.name == "dport" {
                MATCH_PORT
            } else {
                MATCH_SOURCE_PORT
            };
            let mut vals = bare_values(f)?;
            // 对照 dae MergeAndSortRulesOptimizer：非 ip/sip 函数的参数按 (key, val)
            // 排序（字符串序；dae 的 val 是字符串，保持逐字节一致）。
            vals.sort();
            let mut out = Vec::new();
            for a in &vals {
                let (start, end) = parse_port_range(a)?;
                let mut p = Partial {
                    type_,
                    value: [0u8; 16],
                    lpm: None,
                    not,
                    domain: None,
                    desc: format!("{}({a})", f.name),
                };
                p.value[0..2].copy_from_slice(&start.to_ne_bytes());
                p.value[2..4].copy_from_slice(&end.to_ne_bytes());
                out.push(p);
            }
            Ok(out)
        }
        "dscp" => {
            let mut vals = bare_values(f)?;
            vals.sort(); // 同 dport：dae 对非 ip/sip 参数按字符串序排序
            let mut out = Vec::new();
            for a in &vals {
                let v: u8 = a.parse().map_err(|_| format!("dscp 非法: {a}"))?;
                let mut p = Partial {
                    type_: MATCH_DSCP,
                    value: [0u8; 16],
                    lpm: None,
                    not,
                    domain: None,
                    desc: format!("dscp({a})"),
                };
                p.value[0] = v;
                out.push(p);
            }
            Ok(out)
        }
        "fallback" => Ok(vec![Partial {
            type_: MATCH_FALLBACK,
            value: [0u8; 16],
            lpm: None,
            not,
            domain: None,
            desc: "fallback".into(),
        }]),
        other => Err(format!(
            "mini-dae 不支持的函数: {other}（目前支持 domain/dip/sip/mac/l4proto/ipversion/dport/sport/dscp/pname/fallback）"
        )),
    }
}

/// P19：组名 → outbound 索引。built-in：direct=0 / block=1 / must_rules=0xFC；
/// 用户组：`groups` 映射（config `group` 顺序，从 `GROUP_INDEX_BASE` 起）。
/// 未知名回退：同名不存在时用 "proxy"（若也未定义则最小索引/隐式 2）——与 K3 时代
/// “其余组名都映射到唯一用户组”的行为兼容。
fn resolve_outbound_id(name: &str, builtin: u8, groups: &HashMap<String, u8>) -> u8 {
    match name {
        "direct" | "block" | "must_rules" => builtin,
        _ => groups
            .get(name)
            .or_else(|| groups.get("proxy"))
            .or_else(|| groups.values().min())
            .copied()
            .unwrap_or(OUTBOUND_PROXY),
    }
}

fn compile_rule(
    rule: &Rule,
    geo: Option<&Geodata>,
    notes: &mut Vec<String>,
    groups: &HashMap<String, u8>,
) -> Result<CompiledRules, String> {
    // 第一遍：展开成扁平的 match_set 列表（记录所属函数与函数内位置）
    let mut flat: Vec<(Partial, usize, usize)> = Vec::new();
    let mut func_lens: Vec<usize> = Vec::new();
    for (fi, f) in rule.funcs.iter().enumerate() {
        let partials = expand_func(f, geo, notes)?;
        func_lens.push(partials.len());
        for (pi, p) in partials.into_iter().enumerate() {
            flat.push((p, fi, pi));
        }
    }
    if flat.len() > MAX_MATCH_SET_LEN as usize {
        return Err(format!(
            "规则编译出 {} 个 match_set，超过上限 {MAX_MATCH_SET_LEN}",
            flat.len()
        ));
    }

    // 第二遍：分配 outbound（= dae matcher_builder.go:60-73 的编码）
    let outbound_id = resolve_outbound_id(&rule.outbound.name, rule.outbound.id, groups);
    let mut sets = Vec::with_capacity(flat.len());
    let mut lpm_tries = BTreeMap::new();
    let mut domain_sets = Vec::new();
    let last = flat.len() - 1;
    for (i, (p, fi, pi)) in flat.iter().enumerate() {
        let outbound = if i == last {
            outbound_id
        } else if *pi == func_lens[*fi] - 1 {
            OUTBOUND_LOGICAL_AND
        } else {
            OUTBOUND_LOGICAL_OR
        };
        let index = sets.len() as u32;
        let mut value = p.value;
        if let Some(prefixes) = &p.lpm {
            value[0..4].copy_from_slice(&index.to_ne_bytes());
            // P17a：排序 + 去重（与 dae MergeAndSort/Deduplicate 后的集合一致；
            // 对拍输出本就要排序，提前做还让写入顺序确定）。
            let mut sorted = prefixes.clone();
            sorted.sort();
            sorted.dedup();
            if sorted.len() > LPM_MAX_ENTRIES as usize {
                return Err(format!(
                    "LPM 集合超过上限 {LPM_MAX_ENTRIES}（/{} 条）",
                    sorted.len()
                ));
            }
            lpm_tries.insert(index, sorted);
        }
        if let Some((key, domains)) = &p.domain {
            // domain 位图的位下标 = match_set 在数组中的位置（对照 dae addDomain：
            // Value 不写下标，位下标就是 appendRule 的位置）。
            // 对照 dae ahocorasick_slimtrie.go:137-143：regex 在编译期编译，
            // 编译错误使整条规则编译失败（硬失败，不静默降级）。
            domain_sets.push(DomainSetSpec::build(index, key, domains)?);
        }
        sets.push(MatchSet {
            value,
            not: p.not as u8,
            type_: p.type_,
            outbound,
            must: rule.outbound.must as u8,
            mark: rule.outbound.mark,
        });
    }
    Ok(CompiledRules {
        sets,
        lpm_tries,
        domain_sets,
        notes: Vec::new(),
    })
}

/// 解析整个规则文件（每条规则一行，# 注释）。无 geodata 的入口（单测用）。
#[cfg(test)]
pub fn parse_and_compile(text: &str) -> Result<CompiledRules, String> {
    parse_and_compile_with_groups(text, None, &HashMap::new())
}

/// P17a：带 geodata 的编译入口（`dip(geoip:…)`/`domain(geosite:…)` 展开）。
/// 组名按空映射解析（全部回退隐式 proxy）——单测入口；生产路径用
/// `parse_and_compile_with_groups`。
#[cfg(test)]
pub fn parse_and_compile_with_geo(
    text: &str,
    geo: Option<&Geodata>,
) -> Result<CompiledRules, String> {
    parse_and_compile_with_groups(text, geo, &HashMap::new())
}

/// P19：带组名映射的编译入口。`groups` = 组名 → outbound 索引
/// （config `group` 段顺序，从 `GROUP_INDEX_BASE` 起）。
pub fn parse_and_compile_with_groups(
    text: &str,
    geo: Option<&Geodata>,
    groups: &HashMap<String, u8>,
) -> Result<CompiledRules, String> {
    let mut all = CompiledRules::default();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let toks = lex(line).map_err(|e| format!("第 {} 行: {e}", lineno + 1))?;
        let mut parser = Parser { toks, pos: 0 };
        let rule = parser
            .parse_rule()
            .map_err(|e| format!("第 {} 行: {e}", lineno + 1))?;
        let mut rule_notes = Vec::new();
        let compiled = compile_rule(&rule, geo, &mut rule_notes, groups)
            .map_err(|e| format!("第 {} 行: {e}", lineno + 1))?;
        all.notes.extend(rule_notes);

        let base = all.sets.len() as u32;
        if base + compiled.sets.len() as u32 > MAX_MATCH_SET_LEN {
            return Err(format!(
                "规则总数超过上限 {MAX_MATCH_SET_LEN}（第 {} 行）",
                lineno + 1
            ));
        }

        // LPM trie 下标从「规则内下标」重定位到「全局下标」
        let lpm_local: Vec<u32> = compiled.lpm_tries.keys().copied().collect();
        let reloc: Vec<(u32, u32)> = lpm_local.iter().map(|l| (*l, base + *l)).collect();
        for (local, abs) in &reloc {
            if let Some(prefixes) = compiled.lpm_tries.get(local) {
                all.lpm_tries.insert(*abs, prefixes.clone());
            }
        }
        for s in compiled.sets {
            all.sets.push(s);
        }
        for mut spec in compiled.domain_sets {
            spec.match_set_index += base;
            all.domain_sets.push(spec);
        }
        for (_local, abs) in reloc {
            let bytes = abs.to_ne_bytes();
            all.sets[abs as usize].value[0..4].copy_from_slice(&bytes);
        }
    }
    if all.sets.is_empty() {
        return Err("规则为空：至少需要一条规则（例如 `fallback -> direct`）".into());
    }
    Ok(all)
}

pub fn type_name(t: u8) -> &'static str {
    match t {
        MATCH_DOMAIN_SET => "DomainSet",
        MATCH_IP_SET => "IpSet",
        MATCH_SOURCE_IP_SET => "SourceIpSet",
        MATCH_PORT => "Port",
        MATCH_SOURCE_PORT => "SourcePort",
        MATCH_L4_PROTO => "L4Proto",
        MATCH_IP_VERSION => "IpVersion",
        MATCH_MAC => "Mac",
        MATCH_PNAME => "Pname",
        MATCH_DSCP => "Dscp",
        MATCH_FALLBACK => "Fallback",
        _ => "Unknown",
    }
}

fn fmt_pname(value: &[u8; 16]) -> String {
    let end = value.iter().position(|b| *b == 0).unwrap_or(16);
    String::from_utf8_lossy(&value[..end]).into_owned()
}

fn fmt_lpm_key(data: &[u8; 16], plen: u32) -> String {
    if data[10] == 0xff && data[11] == 0xff {
        let addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let v4plen = plen.saturating_sub(96);
        format!("{addr}/{v4plen}")
    } else {
        let addr = std::net::Ipv6Addr::from(*data);
        format!("{addr}/{plen}")
    }
}

/// 对拍用的前缀渲染：v4 为 `a.b.c.d/<plen-96>`，其它为 `xx:..:xx/<plen>`。
/// 必须与 lab/parity（dae Go 侧）的格式完全一致。
fn fmt_prefix_parity(data: &[u8; 16], plen: u32) -> String {
    if data[10] == 0xff && data[11] == 0xff {
        let addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        format!("{addr}/{}", plen.saturating_sub(96))
    } else {
        let addr = std::net::Ipv6Addr::from(*data);
        format!("{addr}/{plen}")
    }
}

impl CompiledRules {
    pub fn dump(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "rules: {} match_sets", self.sets.len());
        for (i, m) in self.sets.iter().enumerate() {
            let _ = write!(
                s,
                "[{i:2}] type={:<12} not={} outbound=0x{:02x} mark=0x{:x} must={}",
                type_name(m.type_),
                m.not,
                m.outbound,
                m.mark,
                m.must
            );
            match m.type_ {
                MATCH_DOMAIN_SET => {
                    if let Some(spec) = self
                        .domain_sets
                        .iter()
                        .find(|d| d.match_set_index == i as u32)
                    {
                        let _ = write!(s, " domains={}:{}", spec.key, spec.domains.join(","));
                    }
                }
                MATCH_IP_SET | MATCH_SOURCE_IP_SET | MATCH_MAC => {
                    let _ = write!(s, " lpm_index={}", m.lpm_index());
                }
                MATCH_PORT | MATCH_SOURCE_PORT => {
                    let (a, b) = m.port_range();
                    let _ = write!(s, " port={a}-{b}");
                }
                MATCH_L4_PROTO | MATCH_IP_VERSION => {
                    let _ = write!(s, " mask=0x{:x}", m.mask());
                }
                MATCH_DSCP => {
                    let _ = write!(s, " dscp={}", m.dscp());
                }
                MATCH_PNAME => {
                    let _ = write!(s, " pname={}", fmt_pname(&m.value));
                }
                _ => {}
            }
            let _ = writeln!(s);
        }
        for (idx, prefixes) in &self.lpm_tries {
            let _ = writeln!(s, "lpm[{idx}]: {} prefixes", prefixes.len());
            for (plen, data) in prefixes {
                let _ = writeln!(s, "    {}", fmt_lpm_key(data, *plen));
            }
        }
        s
    }

    /// 对拍格式（lab/parity）：LPM 前缀内联进槽位行，无表头；
    /// 与 dae 原版 Go 编译器（lab/parity/run.sh）的输出逐字节可比。
    pub fn dump_parity(&self) -> String {
        let mut s = String::new();
        for (i, m) in self.sets.iter().enumerate() {
            let _ = write!(
                s,
                "slot {i} type={} not={} outbound=0x{:02x} mark=0x{:x} must={}",
                type_name(m.type_),
                m.not,
                m.outbound,
                m.mark,
                m.must
            );
            match m.type_ {
                MATCH_DOMAIN_SET => {
                    if let Some(spec) = self
                        .domain_sets
                        .iter()
                        .find(|d| d.match_set_index == i as u32)
                    {
                        let _ = write!(s, " domains={}:{}", spec.key, spec.domains.join(","));
                    }
                }
                MATCH_IP_SET | MATCH_SOURCE_IP_SET | MATCH_MAC => {
                    let mut prefixes: Vec<(u32, [u8; 16])> = self
                        .lpm_tries
                        .get(&m.lpm_index())
                        .cloned()
                        .unwrap_or_default();
                    prefixes.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                    let rendered: Vec<String> = prefixes
                        .iter()
                        .map(|(plen, data)| fmt_prefix_parity(data, *plen))
                        .collect();
                    let _ = write!(s, " prefixes={}", rendered.join(","));
                }
                MATCH_PORT | MATCH_SOURCE_PORT => {
                    let (a, b) = m.port_range();
                    let _ = write!(s, " port={a}-{b}");
                }
                MATCH_L4_PROTO | MATCH_IP_VERSION => {
                    let _ = write!(s, " mask=0x{:x}", m.mask());
                }
                MATCH_DSCP => {
                    let _ = write!(s, " dscp={}", m.dscp());
                }
                MATCH_PNAME => {
                    let _ = write!(s, " pname={}", fmt_pname(&m.value));
                }
                _ => {}
            }
            let _ = writeln!(s);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_or_encoding_matches_dae() {
        // dip(a, b) && dport(8080) -> proxy
        // 期望：dip 折叠成 1 个 match_set（And），dport 展开成 1 个（真实 outbound）
        let c = parse_and_compile("dip(1.1.1.1/32, 10.9.9.0/24) && dport(8080) -> proxy").unwrap();
        assert_eq!(c.sets.len(), 2);
        assert_eq!(c.sets[0].type_, MATCH_IP_SET);
        assert_eq!(c.sets[0].outbound, OUTBOUND_LOGICAL_AND);
        assert_eq!(c.sets[1].outbound, OUTBOUND_PROXY);
        assert_eq!(c.lpm_tries[&0].len(), 2);
    }

    #[test]
    fn scalar_function_expands_with_sticky_or() {
        // dport(80, 443, 8080) -> proxy：3 个 match_set，前两个 LogicalOr
        let c = parse_and_compile("dport(80, 443, 8080) -> proxy").unwrap();
        assert_eq!(c.sets.len(), 3);
        assert_eq!(c.sets[0].outbound, OUTBOUND_LOGICAL_OR);
        assert_eq!(c.sets[1].outbound, OUTBOUND_LOGICAL_OR);
        assert_eq!(c.sets[2].outbound, OUTBOUND_PROXY);
    }

    #[test]
    fn not_and_fallback() {
        let c = parse_and_compile("!dport(9999) && fallback -> direct").unwrap();
        assert_eq!(c.sets.len(), 2);
        assert_eq!(c.sets[0].not, 1);
        assert_eq!(c.sets[0].outbound, OUTBOUND_LOGICAL_AND);
        assert_eq!(c.sets[1].type_, MATCH_FALLBACK);
        assert_eq!(c.sets[1].outbound, OUTBOUND_DIRECT);
    }

    #[test]
    fn named_groups_resolve_to_indices() {
        // P19：组名 → outbound 索引（config 顺序，从 GROUP_INDEX_BASE 起）
        let mut groups = HashMap::new();
        groups.insert("proxy".to_string(), GROUP_INDEX_BASE);
        groups.insert("alt".to_string(), GROUP_INDEX_BASE + 1);
        let c = parse_and_compile_with_groups(
            "dport(8080) -> proxy\ndport(8082) -> alt\nfallback -> direct",
            None,
            &groups,
        )
        .unwrap();
        assert_eq!(c.sets[0].outbound, GROUP_INDEX_BASE);
        assert_eq!(c.sets[1].outbound, GROUP_INDEX_BASE + 1);
        assert_eq!(c.sets[2].outbound, OUTBOUND_DIRECT);
        // 未知名回退 proxy 组（不静默直连）
        let c = parse_and_compile_with_groups("dport(1) -> typo", None, &groups).unwrap();
        assert_eq!(c.sets[0].outbound, GROUP_INDEX_BASE);
    }

    #[test]
    fn mark_and_must() {
        let c = parse_and_compile("dport(443) -> direct(mark: 0x800, must)").unwrap();
        assert_eq!(c.sets[0].mark, 0x800);
        assert_eq!(c.sets[0].must, 1);
    }

    #[test]
    fn domain_rules_compile_to_bitmap_sets() {
        // domain 每个 key 一组 → 各自一个 match_set；位下标 = 数组位置
        let c = parse_and_compile(
            "domain(suffix: 'proxy.test', keyword: 'kw') && dport(9999) -> proxy",
        )
        .unwrap();
        assert_eq!(c.sets.len(), 3, "{:#?}", c.sets);
        assert_eq!(c.sets[0].type_, MATCH_DOMAIN_SET);
        assert_eq!(c.sets[0].outbound, OUTBOUND_LOGICAL_OR);
        assert_eq!(c.sets[1].outbound, OUTBOUND_LOGICAL_AND);
        assert_eq!(c.sets[2].outbound, OUTBOUND_PROXY);
        assert!(c.sets[0].value.iter().all(|b| *b == 0));
        assert_eq!(c.domain_sets.len(), 2);
        assert_eq!(c.domain_sets[0].match_set_index, 0);
        assert_eq!(c.domain_sets[0].key, "suffix");
        assert_eq!(c.domain_sets[0].domains, vec!["proxy.test"]);
        assert_eq!(c.domain_sets[1].key, "keyword");
        // 无 key 默认 suffix
        let c2 = parse_and_compile("domain('direct.test') -> direct").unwrap();
        assert_eq!(c2.domain_sets[0].key, "suffix");
        // 位下标随全局重定位
        let c3 = parse_and_compile("dport(80) -> direct\ndomain(full: 'x.test') -> proxy").unwrap();
        assert_eq!(c3.domain_sets[0].match_set_index, 1);
        // regex 在编译期编译，可编译成域位图（对照 dae regexp.Compile）
        let c4 =
            parse_and_compile("domain(regex: '^api[0-9]+\\\\.regex\\\\.test$') -> proxy").unwrap();
        assert_eq!(c4.domain_sets.len(), 1);
        assert_eq!(c4.domain_sets[0].key, "regex");
        assert_eq!(c4.domain_sets[0].regexes.len(), 1);
        // 非法 regex 是硬失败（不静默丢规则）
        let err = parse_and_compile("domain(regex: '([') -> proxy").unwrap_err();
        assert!(err.contains("regex"), "{err}");
    }

    #[test]
    fn multi_rule_lpm_index_relocation() {
        let c = parse_and_compile(
            "dip(1.1.1.1/32) -> proxy\nsip(10.0.0.0/24) -> direct\nfallback -> direct",
        )
        .unwrap();
        assert_eq!(c.sets.len(), 3);
        assert_eq!(c.sets[0].lpm_index(), 0);
        assert_eq!(c.sets[1].lpm_index(), 1);
        assert_eq!(c.lpm_tries[&0].len(), 1);
        assert_eq!(c.lpm_tries[&1].len(), 1);
    }

    #[test]
    fn pname_compile_forms() {
        // 单值 / 多值 OR（字符串序：bash < wget）/ NOT
        let c = parse_and_compile(
            "pname(curl) -> direct\npname(wget, bash) -> block\n!pname(sshd) && dport(22) -> direct\nfallback -> direct\n",
        )
        .unwrap();
        assert_eq!(c.sets[0].type_, MATCH_PNAME);
        assert_eq!(c.sets[0].not, 0);
        assert_eq!(&c.sets[0].value[..4], b"curl");
        assert_eq!(c.sets[0].outbound, OUTBOUND_DIRECT); // 单 match_set = 整条规则最后一个
        assert_eq!(&c.sets[1].value[..4], b"bash");
        assert_eq!(&c.sets[2].value[..4], b"wget");
        assert_eq!(c.sets[3].type_, MATCH_PNAME);
        assert_eq!(c.sets[3].not, 1);
        assert_eq!(&c.sets[3].value[..4], b"sshd");
        assert_eq!(c.sets[3].outbound, OUTBOUND_LOGICAL_AND); // 后面还有 dport
                                                              // NUL 补全
        assert_eq!(c.sets[0].value[4], 0);
        // 16 字节截断（dae 同：trim 后使用）
        let t =
            parse_and_compile("pname(0123456789abcdefGH) -> direct\nfallback -> direct\n").unwrap();
        assert_eq!(&t.sets[0].value, b"0123456789abcdef");
        assert!(t.notes.iter().any(|n| n.contains("截断")));
        // 带 key / 空值是错误
        assert!(parse_and_compile("pname(x: curl) -> direct\nfallback -> direct\n").is_err());
        assert!(parse_and_compile("pname() -> direct\nfallback -> direct\n").is_err());
    }
}

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
//! 未实现的 dae 能力（会显式报错，而不是静默忽略）：`pname()` 进程名、IPv6 前缀、
//! outbound 组名映射。domain 的 suffix/full/keyword/regex 四种 key 均已支持
//! （regex 在前编译期编译，匹配发生用户态，见 ADR-0014）。

use regex::Regex;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

/// 与 `ebpf-rs/src/common.rs` 的 `MINI_MAX_MATCH_SET_LEN` 保持一致。
pub const MAX_MATCH_SET_LEN: u32 = 64;

/// 与 `ebpf-rs/src/maps.rs` 的内层 LPM 模板一致（map-in-map 的 template 匹配要求）。
pub const LPM_MAX_ENTRIES: u32 = 1024;
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
pub const MATCH_DSCP: u8 = 9;
pub const MATCH_FALLBACK: u8 = 10;

// ---- outbound 编码（= dae common/consts/ebpf_generated.go） ----
pub const OUTBOUND_DIRECT: u8 = 0x00;
pub const OUTBOUND_BLOCK: u8 = 0x01;
/// mini-dae 只有一个用户组；其它组名都映射到它。
pub const OUTBOUND_PROXY: u8 = 0x02;
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
}

#[derive(Debug, Default, Clone)]
pub struct CompiledRules {
    pub sets: Vec<MatchSet>,
    /// match_set 下标 -> 该 match_set 的 LPM 前缀（prefixlen, 16 字节键）
    pub lpm_tries: BTreeMap<u32, Vec<(u32, [u8; 16])>>,
    /// domain 规则（用户态 DNS 应答经过时据此写域位图）
    pub domain_sets: Vec<DomainSetSpec>,
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
    /// 原始组名，仅用于后续日志/报告（当前未消费）
    #[allow(dead_code)]
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
                    // 允许 key: value（domain 的分组靠它；其它函数会拒绝带 key）
                    let first = self.word()?;
                    let arg = if matches!(self.peek(), Some(Tok::Colon)) {
                        self.next();
                        let v = self.word()?;
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
            // 其余组名都映射到 mini-dae 唯一的用户组
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

fn parse_v4_prefix(s: &str) -> Result<(u32, [u8; 16]), String> {
    let (addr_s, plen_s) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let v4: Ipv4Addr = addr_s.parse().map_err(|_| {
        format!("mini-dae 目前只支持 IPv4 前缀（{s} 不是合法 IPv4；IPv6 待 K0 下一步）")
    })?;
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
    Ok((96 + plen, data))
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

fn expand_func(f: &Func) -> Result<Vec<Partial>, String> {
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
            let vals = bare_values(f)?;
            let mut prefixes = Vec::new();
            for a in &vals {
                prefixes.push(parse_v4_prefix(a)?);
            }
            Ok(vec![Partial {
                type_,
                value: [0u8; 16],
                lpm: Some(prefixes),
                not,
                domain: None,
                desc: format!("{name}({})", vals.join(",")),
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
        "domain" => {
            if f.args.is_empty() {
                return Err("domain(...) 需要至少一个参数".into());
            }
            let mut order: Vec<String> = Vec::new();
            let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for a in &f.args {
                let key = a.key.clone().unwrap_or_else(|| "suffix".into());
                match key.as_str() {
                    "suffix" | "full" | "keyword" | "regex" => {}
                    other => return Err(format!("domain 不认识的 key: {other}")),
                }
                if !grouped.contains_key(&key) {
                    order.push(key.clone());
                }
                grouped.entry(key).or_default().push(a.val.clone());
            }
            let mut out = Vec::new();
            for key in order {
                let doms = grouped.remove(&key).unwrap_or_default();
                out.push(Partial {
                    type_: MATCH_DOMAIN_SET,
                    value: [0u8; 16],
                    lpm: None,
                    not,
                    domain: Some((key.clone(), doms.clone())),
                    desc: format!("domain({key}:{})", doms.join(",")),
                });
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
            let vals = bare_values(f)?;
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
            let vals = bare_values(f)?;
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
            "mini-dae 不支持的函数: {other}（目前支持 domain/dip/sip/mac/l4proto/ipversion/dport/sport/dscp/fallback）"
        )),
    }
}

fn compile_rule(rule: &Rule) -> Result<CompiledRules, String> {
    // 第一遍：展开成扁平的 match_set 列表（记录所属函数与函数内位置）
    let mut flat: Vec<(Partial, usize, usize)> = Vec::new();
    let mut func_lens: Vec<usize> = Vec::new();
    for (fi, f) in rule.funcs.iter().enumerate() {
        let partials = expand_func(f)?;
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
    let mut sets = Vec::with_capacity(flat.len());
    let mut lpm_tries = BTreeMap::new();
    let mut domain_sets = Vec::new();
    let last = flat.len() - 1;
    for (i, (p, fi, pi)) in flat.iter().enumerate() {
        let outbound = if i == last {
            rule.outbound.id
        } else if *pi == func_lens[*fi] - 1 {
            OUTBOUND_LOGICAL_AND
        } else {
            OUTBOUND_LOGICAL_OR
        };
        let index = sets.len() as u32;
        let mut value = p.value;
        if let Some(prefixes) = &p.lpm {
            value[0..4].copy_from_slice(&index.to_ne_bytes());
            lpm_tries.insert(index, prefixes.clone());
        }
        if let Some((key, domains)) = &p.domain {
            // domain 位图的位下标 = match_set 在数组中的位置（对照 dae addDomain：
            // Value 不写下标，位下标就是 appendRule 的位置）。
            // 对照 dae ahocorasick_slimtrie.go:137-143：regex 在编译期编译，
            // 编译错误使整条规则编译失败（硬失败，不静默降级）。
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
            domain_sets.push(DomainSetSpec {
                match_set_index: index,
                key: key.clone(),
                domains: domains.clone(),
                regexes,
            });
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
    })
}

/// 解析整个规则文件（每条规则一行，# 注释）。
pub fn parse_and_compile(text: &str) -> Result<CompiledRules, String> {
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
        let compiled = compile_rule(&rule).map_err(|e| format!("第 {} 行: {e}", lineno + 1))?;

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
        MATCH_DSCP => "Dscp",
        MATCH_FALLBACK => "Fallback",
        _ => "Unknown",
    }
}

fn fmt_lpm_key(data: &[u8; 16], plen: u32) -> String {
    if data[10] == 0xff && data[11] == 0xff {
        let addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let v4plen = plen.saturating_sub(96);
        format!("{addr}/{v4plen}")
    } else {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} plen={plen}",
            data[10], data[11], data[12], data[13], data[14], data[15]
        )
    }
}

/// 对拍用的前缀渲染：v4 为 `a.b.c.d/<plen-96>`，其它为 `xx:..:xx/<plen>`。
/// 必须与 lab/parity（dae Go 侧）的格式完全一致。
fn fmt_prefix_parity(data: &[u8; 16], plen: u32) -> String {
    if data[10] == 0xff && data[11] == 0xff {
        let addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        format!("{addr}/{}", plen.saturating_sub(96))
    } else {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}/{plen}",
            data[10], data[11], data[12], data[13], data[14], data[15]
        )
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
}

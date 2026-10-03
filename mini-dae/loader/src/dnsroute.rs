// SPDX-License-Identifier: GPL-2.0
//! P18c：`dns.routing` 请求/应答分流（对照 dae `component/dns/request_routing.go`
//! 与 `response_routing.go` 的 Match 语义与链编码）。
//!
//! 语义要点（与 dae 对齐）：
//! - 规则自顶向下；同一行内 `&&` 用「subrule」编码：函数非末尾项带 `And` 链标记、
//!   末尾项带真实出口；多值函数（如 `qtype(a, aaaa)`、`upstream(up1, up2)`）拆成多个
//!   带 `Or` 链标记的项，语义 = OR；`!` 作用于整个函数；
//! - 请求出口：`reject`（空应答 NOERROR）、`asis`（发往客户端原始目的地址，仅 UDP）、
//!   或 `dns.upstream` 定义的 tag；默认 fallback = `asis`（dae 默认，仅当存在
//!   `dns.routing` 段时启用；无该段时沿用 legacy 单上游）；
//! - 应答出口：`accept`、`reject`（去掉 answer 段）、或 tag（换上游重查，
//!   深度上限 3，对照 dae `MaxDnsLookupDepth = 3`）；默认 fallback = `accept`；
//! - 请求函数：`qname`（suffix/full/keyword/regex/geosite/ext；裸值默认 suffix）、
//!   `qtype`；应答函数另加 `upstream`、`ip`（裸 CIDR / geoip / ext）。
//!
//! 与 dae 的差异（如实）：
//! - `sub/node/subnode`（只影响 dae 自身订阅/节点查询）不适用——mini 无此类内部查询；
//!   含它们的规则被跳过并记 note（不参与普通查询匹配，与 dae 的语义效果一致）；
//! - 应答 `upstream(...)` 按**名字**比较（asis/reject/tag）；dae 数值比较下
//!   `upstream(reject)` 会碰巧命中 asis，属上游数值复用，mini 不做这种巧合；
//! - `ip(geoip:…)` 运行时线性前缀匹配（应答 IP 数很少）；dae 用 128 位 trie。

use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::{Config, Function, Item, Param, Rule};
use crate::dns::{self, DomainSetSpec, Question};
use crate::geodata::{self, Cidr};

/// 请求出口选择。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReqOut {
    Reject,
    AsIs,
    Tag(String),
}

/// 应答出口选择。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespOut {
    Accept,
    Reject,
    Tag(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    /// 多值/多函数链接（LogicalOr）
    Or,
    /// 函数末尾但行未结束（LogicalAnd）
    And,
    /// 行末尾（真实出口）
    Tail,
}

#[derive(Debug, Clone)]
enum ReqKind {
    QName(usize),
    QType(u16),
    /// 客户端源地址（mini 扩展；无客户端信息时不命中）
    Sip(usize),
}

#[derive(Debug, Clone)]
struct ReqEntry {
    kind: ReqKind,
    not: bool,
    chain: Chain,
}

#[derive(Debug, Clone)]
enum RespKind {
    QName(usize),
    QType(u16),
    /// 客户端源地址（mini 扩展；无客户端信息时不命中）
    Sip(usize),
    /// 按名字比较请求阶段选中的上游（tag / asis / reject）
    Upstream(ReqOut),
    Ip(usize),
}

#[derive(Debug, Clone)]
struct RespEntry {
    kind: RespKind,
    not: bool,
    chain: Chain,
}

pub struct DnsRouter {
    req: Vec<ReqEntry>,
    req_domains: Vec<DomainSetSpec>,
    req_ips: Vec<Vec<Cidr>>,
    req_out: Vec<ReqOut>, // 与 req 等长；仅 Tail 项有效
    pub req_fallback: ReqOut,
    pub request_rule_lines: usize,

    resp: Vec<RespEntry>,
    resp_domains: Vec<DomainSetSpec>,
    resp_ips: Vec<Vec<Cidr>>,
    resp_sips: Vec<Vec<Cidr>>,
    resp_out: Vec<RespOut>,
    pub resp_fallback: RespOut,
    pub response_rule_lines: usize,

    pub notes: Vec<String>,
}

impl DnsRouter {
    /// 请求分流（无客户端地址；测试/兼容用）。生产走 `request_select_for`。
    #[allow(dead_code)]
    pub fn request_select(&self, q: &Question) -> ReqOut {
        self.request_select_for(q, None)
    }

    /// 请求分流；`client` 为查询发起方地址（`sip()` 匹配用）。
    /// 不会失败（未命中 → fallback）。
    pub fn request_select_for(&self, q: &Question, client: Option<IpAddr>) -> ReqOut {
        let mut good = false;
        let mut bad = false;
        for (i, e) in self.req.iter().enumerate() {
            if !bad && !good {
                let hit = match &e.kind {
                    ReqKind::QName(idx) => {
                        dns::domain_set_matches(&self.req_domains[*idx], &q.qname)
                    }
                    ReqKind::QType(t) => q.qtype == *t,
                    ReqKind::Sip(idx) => client
                        .map(|ip| ip_hits(&self.req_ips[*idx], ip))
                        .unwrap_or(false),
                };
                if hit {
                    good = true;
                }
            }
            if e.chain != Chain::Or {
                if good == e.not {
                    bad = true;
                }
                good = false;
            }
            if e.chain == Chain::Tail {
                if !bad {
                    return self.req_out[i].clone();
                }
                bad = false;
            }
        }
        self.req_fallback.clone()
    }

    /// 应答分流（无客户端地址；测试/兼容用）。生产走 `response_select_for`。
    #[allow(dead_code)]
    pub fn response_select(&self, resp: &[u8], served: &ReqOut) -> RespOut {
        self.response_select_for(resp, served, None)
    }

    /// 应答分流；`served` 是请求阶段选中的出口（用于 `upstream(...)`）；
    /// `client` 为查询发起方地址（`sip()` 匹配用）。
    pub fn response_select_for(
        &self,
        resp: &[u8],
        served: &ReqOut,
        client: Option<IpAddr>,
    ) -> RespOut {
        let q = dns::parse_query(resp);
        let qname = q.as_ref().map(|q| q.qname.clone()).unwrap_or_default();
        let qtype = q.as_ref().map(|q| q.qtype).unwrap_or(0);
        let ips = ips_of(resp);
        let mut good = false;
        let mut bad = false;
        for (i, e) in self.resp.iter().enumerate() {
            if !bad && !good {
                let hit = match &e.kind {
                    RespKind::QName(idx) => {
                        !qname.is_empty()
                            && dns::domain_set_matches(&self.resp_domains[*idx], &qname)
                    }
                    RespKind::QType(t) => qtype == *t,
                    RespKind::Sip(idx) => client
                        .map(|ip| ip_hits(&self.resp_sips[*idx], ip))
                        .unwrap_or(false),
                    RespKind::Upstream(u) => u == served,
                    RespKind::Ip(idx) => ips.iter().any(|ip| ip_hits(&self.resp_ips[*idx], *ip)),
                };
                if hit {
                    good = true;
                }
            }
            if e.chain != Chain::Or {
                if good == e.not {
                    bad = true;
                }
                good = false;
            }
            if e.chain == Chain::Tail {
                if !bad {
                    return self.resp_out[i].clone();
                }
                bad = false;
            }
        }
        self.resp_fallback.clone()
    }
}

fn ips_of(resp: &[u8]) -> Vec<IpAddr> {
    let (v4, v6) = dns::answer_a_and_aaaa_records(resp);
    let mut out: Vec<IpAddr> = v4.into_iter().map(IpAddr::from).collect();
    out.extend(v6.into_iter().map(IpAddr::from));
    out
}

/// 16 字节归一化（v4 → mapped），对照 dae `Prefix2bin128`。
fn ip16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(a) => dns::map_v4(a.octets()),
        IpAddr::V6(a) => a.octets(),
    }
}

fn cidr16(c: &Cidr) -> ([u8; 16], u32) {
    match c.ip.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(&c.ip);
            (dns::map_v4(a), c.plen + 96)
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&c.ip);
            (a, c.plen)
        }
        _ => ([0u8; 16], 0),
    }
}

fn ip_hits(set: &[Cidr], ip: IpAddr) -> bool {
    let b = ip16(ip);
    set.iter().any(|c| {
        let (cb, plen) = cidr16(c);
        let plen = plen.min(128) as usize;
        let full = plen / 8;
        if b[..full] != cb[..full] {
            return false;
        }
        let rem = plen % 8;
        rem == 0 || (b[full] >> (8 - rem)) == (cb[full] >> (8 - rem))
    })
}

// ------------------------------------------------------------------
// 编译
// ------------------------------------------------------------------

/// 常见 DNS 类型名（对照 miekg/dns StringToType 的常用子集；数字也接受）。
fn qtype_by_name(v: &str) -> Option<u16> {
    let up = v.to_ascii_uppercase();
    let t = match up.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "NAPTR" => 35,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "DS" => 43,
        "SSHFP" => 44,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "NSEC3" => 50,
        "TLSA" => 52,
        "SVCB" => 64,
        "HTTPS" => 65,
        "CAA" => 257,
        _ => return v.parse::<u16>().ok(),
    };
    Some(t)
}

fn parse_req_out(name: &str, tags: &HashMap<String, String>) -> Result<ReqOut, String> {
    match name {
        "reject" => Ok(ReqOut::Reject),
        "asis" => Ok(ReqOut::AsIs),
        other if tags.contains_key(other) => Ok(ReqOut::Tag(other.to_string())),
        other => Err(format!(
            "dns.routing.request: 未知出口 {other:?}（可用 reject/asis 或 dns.upstream 的 tag）"
        )),
    }
}

fn parse_resp_out(name: &str, tags: &HashMap<String, String>) -> Result<RespOut, String> {
    match name {
        "accept" => Ok(RespOut::Accept),
        "reject" => Ok(RespOut::Reject),
        other if tags.contains_key(other) => Ok(RespOut::Tag(other.to_string())),
        other => Err(format!(
            "dns.routing.response: 未知出口 {other:?}（可用 accept/reject 或 dns.upstream 的 tag）"
        )),
    }
}

fn check_outbound_params(f: &Function) -> Result<(), String> {
    for p in &f.params {
        match p.key.as_deref() {
            Some("must") => return Err("unsupported param: must".into()),
            Some("mark") => return Err("unsupported param: mark".into()),
            _ => {}
        }
    }
    Ok(())
}

fn param_text(p: &Param) -> Result<(Option<String>, String), String> {
    if let Some(v) = &p.val {
        return Ok((p.key.clone(), v.clone()));
    }
    if let Some(fs) = &p.funcs {
        if fs.len() == 1 && fs[0].params.is_empty() {
            return Ok((p.key.clone(), fs[0].name.clone()));
        }
    }
    Err("参数必须是字符串值".into())
}

/// 展开 `qname` 的参数组：返回按 key 分组的 (key, values)。
/// `files` 为配置参与合并的文件表（`file:` 相对路径按规则所在文件目录解析）。
fn qname_groups(
    f: &Function,
    geo: Option<&geodata::Geodata>,
    files: &[std::path::PathBuf],
    notes: &mut Vec<String>,
) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    let push = |order: &mut Vec<String>,
                groups: &mut HashMap<String, Vec<String>>,
                key: &str,
                val: String| {
        if !groups.contains_key(key) {
            order.push(key.to_string());
        }
        groups.entry(key.to_string()).or_default().push(val);
    };
    for p in &f.params {
        let (key, val) = param_text(p)?;
        let key = key.unwrap_or_else(|| "suffix".to_string());
        match key.as_str() {
            "suffix" | "full" | "keyword" | "regex" => push(&mut order, &mut groups, &key, val),
            "file" => {
                // mini 扩展：自定义名单文件（每行一条；`#` 注释；行首可按
                // `full:`/`keyword:`/`regex:` 覆盖类型，默认 suffix；相对路径
                // 按**规则所在文件**的目录解析）。
                let path = resolve_relative(files, f.loc.file, &val);
                let entries = parse_domain_file(&path)?;
                notes.push(format!(
                    "{}(file: {}) → {} 条域名",
                    f.name,
                    path.display(),
                    entries.len()
                ));
                for (k, v) in entries {
                    push(&mut order, &mut groups, &k, v);
                }
            }
            "geosite" | "ext" => {
                let g = geo.ok_or_else(|| {
                    format!(
                        "{}({}:{}) 需要 geodata 文件（--geodata-dir/DAE_LOCATION_ASSET）",
                        f.name, key, val
                    )
                })?;
                let entries = if key == "geosite" {
                    g.geosite_code(&val)?
                } else {
                    let (file, code) = geodata::split_ext(&val)?;
                    g.geosite_ext(file, code)?
                };
                notes.push(format!(
                    "{}({}:{}) → {} 条域名",
                    f.name,
                    key,
                    val,
                    entries.len()
                ));
                for e in entries.iter() {
                    push(
                        &mut order,
                        &mut groups,
                        e.dtype.routing_key(),
                        e.value.clone(),
                    );
                }
            }
            other => {
                return Err(format!(
                "{}(…) 不认识的 key: {other}（可用 suffix/full/keyword/regex/geosite/ext/file）",
                f.name
            ))
            }
        }
    }
    Ok(order
        .into_iter()
        .map(|k| (k.clone(), groups.remove(&k).unwrap_or_default()))
        .collect())
}

/// 展开 `ip` 函数的全部参数为一个 CIDR 集合（裸 CIDR / geoip / ext）。
fn ip_set(
    f: &Function,
    geo: Option<&geodata::Geodata>,
    notes: &mut Vec<String>,
) -> Result<Vec<Cidr>, String> {
    let mut out: Vec<Cidr> = Vec::new();
    for p in &f.params {
        let (key, val) = param_text(p)?;
        match key.as_deref() {
            Some("geoip") | Some("ext") => {
                let g = geo.ok_or_else(|| {
                    format!(
                        "{}({}:{}) 需要 geodata 文件",
                        f.name,
                        key.clone().unwrap_or_default(),
                        val
                    )
                })?;
                let hit = if key.as_deref() == Some("geoip") {
                    g.geoip_code(&val)?
                } else {
                    let (file, code) = geodata::split_ext(&val)?;
                    g.geoip_ext(file, code)?
                };
                notes.push(format!(
                    "{}({}:{}) → {} 条前缀",
                    f.name,
                    key.clone().unwrap_or_default(),
                    val,
                    hit.0.len()
                ));
                out.extend(hit.0.iter().cloned());
            }
            None => out.push(parse_cidr_plain(&val)?),
            Some(other) => {
                return Err(format!(
                    "{}(…) 不认识的 key: {other}（可用裸 CIDR/geoip/ext）",
                    f.name
                ))
            }
        }
    }
    Ok(out)
}

fn parse_cidr_plain(v: &str) -> Result<Cidr, String> {
    let (addr, plen) = match v.split_once('/') {
        Some((a, p)) => (
            a.parse::<IpAddr>().map_err(|e| format!("CIDR {v}: {e}"))?,
            p.parse::<u32>().map_err(|e| format!("CIDR {v}: {e}"))?,
        ),
        None => (
            v.parse::<IpAddr>().map_err(|e| format!("CIDR {v}: {e}"))?,
            if v.contains(':') { 128 } else { 32 },
        ),
    };
    let ip = match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let max = if ip.len() == 4 { 32 } else { 128 };
    if plen > max {
        return Err(format!("CIDR {v}: 前缀长度越界 /{plen}"));
    }
    Ok(Cidr { ip, plen })
}

fn rule_params(rule: &Rule) -> Result<(), String> {
    for f in &rule.and_functions {
        if f.params.iter().any(|p| p.annotation.iter().count() > 0) {
            return Err(format!("{} 不支持 [annotation]", f.name));
        }
    }
    check_outbound_params(&rule.outbound)?;
    Ok(())
}

/// `file:` 参数：绝对路径原样；相对路径按**规则所在文件**的目录解析。
fn resolve_relative(
    files: &[std::path::PathBuf],
    file_idx: usize,
    val: &str,
) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(val);
    if p.is_absolute() {
        return p;
    }
    if let Some(f) = files.get(file_idx) {
        if let Some(dir) = f.parent() {
            return dir.join(p);
        }
    }
    p
}

/// 解析自定义域名名单文件（mini 扩展）：每行一条；`#` 开始为注释；
/// 行首 `suffix:`/`full:`/`keyword:`/`regex:` 可覆盖类型（默认 suffix）；
/// 空行忽略。返回 (key, value) 列表。
fn parse_domain_file(path: &std::path::Path) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("qname(file: {}): {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, val) = match line.split_once(':') {
            Some((k, v)) if matches!(k.trim(), "suffix" | "full" | "keyword" | "regex") => {
                (k.trim().to_string(), v.trim().to_string())
            }
            _ => ("suffix".to_string(), line.to_string()),
        };
        if val.is_empty() {
            return Err(format!(
                "qname(file: {}):{}: 缺少域名",
                path.display(),
                i + 1
            ));
        }
        out.push((key, val));
    }
    Ok(out)
}

/// 从 config 编译请求/应答路由。`tags` 是 `dns.upstream` 的 tag 集合。
/// 返回 `None` 表示配置里没有 `dns.routing` 段（保持 legacy 单上游行为）。
pub fn compile(
    cfg: &Config,
    tags: &HashMap<String, String>,
    geo: Option<&geodata::Geodata>,
) -> Result<Option<DnsRouter>, String> {
    let Some(dns_sec) = cfg.sections.iter().find(|s| s.name == "dns") else {
        return Ok(None);
    };
    let Some(routing) = dns_sec.items.iter().find_map(|i| match i {
        Item::Section(s) if s.name == "routing" => Some(s),
        _ => None,
    }) else {
        return Ok(None);
    };
    let Some(sec) = routing.items.iter().find_map(|i| match i {
        Item::Section(s) if s.name == "request" => Some(s),
        _ => None,
    }) else {
        // response-only 也允许（dae 两者独立）
        let Some(resp_sec) = routing.items.iter().find_map(|i| match i {
            Item::Section(s) if s.name == "response" => Some(s),
            _ => None,
        }) else {
            return Ok(None);
        };
        let mut notes = Vec::new();
        let (resp, resp_domains, resp_ips, resp_sips, resp_out, resp_fb, lines) =
            compile_response(resp_sec, tags, geo, &cfg.files, &mut notes)?;
        return Ok(Some(DnsRouter {
            req: Vec::new(),
            req_domains: Vec::new(),
            req_ips: Vec::new(),
            req_out: Vec::new(),
            req_fallback: ReqOut::AsIs,
            request_rule_lines: 0,
            resp,
            resp_domains,
            resp_ips,
            resp_sips,
            resp_out,
            resp_fallback: resp_fb,
            response_rule_lines: lines,
            notes,
        }));
    };
    let mut notes = Vec::new();
    let (req, req_domains, req_ips, req_out, req_fb, lines) =
        compile_request(sec, tags, geo, &cfg.files, &mut notes)?;
    let (resp, resp_domains, resp_ips, resp_sips, resp_out, resp_fb, rlines) =
        match routing.items.iter().find_map(|i| match i {
            Item::Section(s) if s.name == "response" => Some(s),
            _ => None,
        }) {
            Some(s) => compile_response(s, tags, geo, &cfg.files, &mut notes)?,
            None => (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                RespOut::Accept,
                0,
            ),
        };
    Ok(Some(DnsRouter {
        req,
        req_domains,
        req_ips,
        req_out,
        req_fallback: req_fb,
        request_rule_lines: lines,
        resp,
        resp_domains,
        resp_ips,
        resp_sips,
        resp_out,
        resp_fallback: resp_fb,
        response_rule_lines: rlines,
        notes,
    }))
}

type RequestParts = (
    Vec<ReqEntry>,
    Vec<DomainSetSpec>,
    Vec<Vec<Cidr>>,
    Vec<ReqOut>,
    ReqOut,
    usize,
);
type ResponseParts = (
    Vec<RespEntry>,
    Vec<DomainSetSpec>,
    Vec<Vec<Cidr>>,
    Vec<Vec<Cidr>>,
    Vec<RespOut>,
    RespOut,
    usize,
);

fn compile_request(
    sec: &crate::config::Section,
    tags: &HashMap<String, String>,
    geo: Option<&geodata::Geodata>,
    files: &[std::path::PathBuf],
    notes: &mut Vec<String>,
) -> Result<RequestParts, String> {
    let mut entries: Vec<ReqEntry> = Vec::new();
    let mut domains: Vec<DomainSetSpec> = Vec::new();
    let mut ipsets: Vec<Vec<Cidr>> = Vec::new();
    let mut outs: Vec<ReqOut> = Vec::new();
    let mut fallback: Option<ReqOut> = None;
    let mut lines = 0usize;
    for item in &sec.items {
        match item {
            Item::Rule(rule) => {
                rule_params(rule)?;
                // sub/node/subnode：只影响 dae 自身查询；mini 无此类查询 → 跳过并记 note
                if rule
                    .and_functions
                    .iter()
                    .any(|f| matches!(f.name.as_str(), "sub" | "node" | "subnode"))
                {
                    let text: Vec<String> =
                        rule.and_functions.iter().map(Function::display).collect();
                    notes.push(format!(
                        "跳过（mini 无内部订阅/节点查询，语义等效）：{} -> {}",
                        text.join(" && "),
                        rule.outbound.display()
                    ));
                    continue;
                }
                let out = parse_req_out(&rule.outbound.name, tags)?;
                let mut rule_entries: Vec<(ReqEntry, Option<ReqOut>)> = Vec::new();
                let mut func_ends: Vec<usize> = Vec::new();
                for f in &rule.and_functions {
                    let before = rule_entries.len();
                    match f.name.as_str() {
                        "qname" => {
                            for (key, values) in qname_groups(f, geo, files, notes)? {
                                let idx = domains.len() as u32;
                                domains.push(DomainSetSpec::build(idx, &key, &values)?);
                                rule_entries.push((
                                    ReqEntry {
                                        kind: ReqKind::QName(idx as usize),
                                        not: f.not,
                                        chain: Chain::Or,
                                    },
                                    None,
                                ));
                            }
                        }
                        "qtype" => {
                            for p in &f.params {
                                let (key, val) = param_text(p)?;
                                if key.is_some() {
                                    return Err(format!("qtype({val}) 不接受带 key 的参数"));
                                }
                                let t = qtype_by_name(&val).ok_or_else(|| {
                                    format!("unknown DNS request type: {val}")
                                })?;
                                rule_entries.push((
                                    ReqEntry {
                                        kind: ReqKind::QType(t),
                                        not: f.not,
                                        chain: Chain::Or,
                                    },
                                    None,
                                ));
                            }
                        }
                        "sip" => {
                            // mini 扩展：客户端源地址匹配（裸 CIDR / geoip / ext）
                            let set = ip_set(f, geo, notes)?;
                            let idx = ipsets.len();
                            ipsets.push(set);
                            rule_entries.push((
                                ReqEntry {
                                    kind: ReqKind::Sip(idx),
                                    not: f.not,
                                    chain: Chain::Or,
                                },
                                None,
                            ));
                        }
                        other => {
                            return Err(format!(
                                "dns.routing.request 不支持函数 {other}（可用 qname/qtype/sip/sub/node/subnode）"
                            ))
                        }
                    }
                    if rule_entries.len() > before {
                        func_ends.push(rule_entries.len() - 1);
                    }
                }
                let last_func_end = func_ends.last().copied().unwrap_or(0);
                for (i, (entry, slot)) in rule_entries.iter_mut().enumerate() {
                    if i == last_func_end {
                        entry.chain = Chain::Tail;
                        *slot = Some(out.clone());
                    } else if func_ends.contains(&i) {
                        entry.chain = Chain::And;
                    } else {
                        entry.chain = Chain::Or;
                    }
                }
                lines += 1;
                for (entry, slot) in rule_entries {
                    outs.push(slot.unwrap_or(ReqOut::AsIs)); // 非 Tail 项占位，不使用
                    entries.push(entry);
                }
            }
            Item::Param(p) if p.key.as_deref() == Some("fallback") => {
                if p.annotation.iter().count() > 0 {
                    return Err("fallback 不支持 [annotation]".into());
                }
                let (_, name) = param_text(p)?;
                fallback = Some(parse_req_out(&name, tags)?);
            }
            Item::Param(p) => {
                return Err(format!(
                    "dns.routing.request 不认识的 key: {}",
                    p.key.clone().unwrap_or_default()
                ))
            }
            Item::Section(s) => {
                return Err(format!("dns.routing.request 不支持子 section: {}", s.name))
            }
        }
    }
    Ok((
        entries,
        domains,
        ipsets,
        outs,
        fallback.unwrap_or(ReqOut::AsIs),
        lines,
    ))
}

fn compile_response(
    sec: &crate::config::Section,
    tags: &HashMap<String, String>,
    geo: Option<&geodata::Geodata>,
    files: &[std::path::PathBuf],
    notes: &mut Vec<String>,
) -> Result<ResponseParts, String> {
    let mut entries: Vec<RespEntry> = Vec::new();
    let mut domains: Vec<DomainSetSpec> = Vec::new();
    let mut ipsets: Vec<Vec<Cidr>> = Vec::new();
    let mut sipsets: Vec<Vec<Cidr>> = Vec::new();
    let mut outs: Vec<RespOut> = Vec::new();
    let mut fallback: Option<RespOut> = None;
    let mut lines = 0usize;
    for item in &sec.items {
        match item {
            Item::Rule(rule) => {
                rule_params(rule)?;
                let out = parse_resp_out(&rule.outbound.name, tags)?;
                let mut rule_entries: Vec<(RespEntry, Option<RespOut>)> = Vec::new();
                let mut func_ends: Vec<usize> = Vec::new();
                for f in &rule.and_functions {
                    let before = rule_entries.len();
                    match f.name.as_str() {
                        "qname" => {
                            for (key, values) in qname_groups(f, geo, files, notes)? {
                                let idx = domains.len() as u32;
                                domains.push(DomainSetSpec::build(idx, &key, &values)?);
                                rule_entries.push((
                                    RespEntry {
                                        kind: RespKind::QName(idx as usize),
                                        not: f.not,
                                        chain: Chain::Or,
                                    },
                                    None,
                                ));
                            }
                        }
                        "qtype" => {
                            for p in &f.params {
                                let (key, val) = param_text(p)?;
                                if key.is_some() {
                                    return Err(format!("qtype({val}) 不接受带 key 的参数"));
                                }
                                let t = qtype_by_name(&val)
                                    .ok_or_else(|| format!("unknown DNS request type: {val}"))?;
                                rule_entries.push((
                                    RespEntry {
                                        kind: RespKind::QType(t),
                                        not: f.not,
                                        chain: Chain::Or,
                                    },
                                    None,
                                ));
                            }
                        }
                        "upstream" => {
                            for p in &f.params {
                                let (key, val) = param_text(p)?;
                                if key.is_some() {
                                    return Err(format!("upstream({val}) 不接受带 key 的参数"));
                                }
                                let u = match val.as_str() {
                                    "asis" => ReqOut::AsIs,
                                    "reject" => ReqOut::Reject,
                                    t if tags.contains_key(t) => ReqOut::Tag(t.to_string()),
                                    t => {
                                        return Err(format!(
                                            "upstream({t})：unknown upstream（可用 asis/reject 或 dns.upstream 的 tag）"
                                        ))
                                    }
                                };
                                rule_entries.push((
                                    RespEntry {
                                        kind: RespKind::Upstream(u),
                                        not: f.not,
                                        chain: Chain::Or,
                                    },
                                    None,
                                ));
                            }
                        }
                        "ip" => {
                            let set = ip_set(f, geo, notes)?;
                            let idx = ipsets.len();
                            ipsets.push(set);
                            rule_entries.push((
                                RespEntry {
                                    kind: RespKind::Ip(idx),
                                    not: f.not,
                                    chain: Chain::Or,
                                },
                                None,
                            ));
                        }
                        "sip" => {
                            // mini 扩展：客户端源地址匹配（应答侧过滤）
                            let set = ip_set(f, geo, notes)?;
                            let idx = sipsets.len();
                            sipsets.push(set);
                            rule_entries.push((
                                RespEntry {
                                    kind: RespKind::Sip(idx),
                                    not: f.not,
                                    chain: Chain::Or,
                                },
                                None,
                            ));
                        }
                        other => {
                            return Err(format!(
                                "dns.routing.response 不支持函数 {other}（可用 qname/qtype/upstream/ip/sip）"
                            ))
                        }
                    }
                    if rule_entries.len() > before {
                        func_ends.push(rule_entries.len() - 1);
                    }
                }
                let last_func_end = func_ends.last().copied().unwrap_or(0);
                for (i, (entry, slot)) in rule_entries.iter_mut().enumerate() {
                    if i == last_func_end {
                        entry.chain = Chain::Tail;
                        *slot = Some(out.clone());
                    } else if func_ends.contains(&i) {
                        entry.chain = Chain::And;
                    } else {
                        entry.chain = Chain::Or;
                    }
                }
                lines += 1;
                for (entry, slot) in rule_entries {
                    outs.push(slot.unwrap_or(RespOut::Accept));
                    entries.push(entry);
                }
            }
            Item::Param(p) if p.key.as_deref() == Some("fallback") => {
                let (_, name) = param_text(p)?;
                fallback = Some(parse_resp_out(&name, tags)?);
            }
            Item::Param(p) => {
                return Err(format!(
                    "dns.routing.response 不认识的 key: {}",
                    p.key.clone().unwrap_or_default()
                ))
            }
            Item::Section(s) => {
                return Err(format!("dns.routing.response 不支持子 section: {}", s.name))
            }
        }
    }
    Ok((
        entries,
        domains,
        ipsets,
        sipsets,
        outs,
        fallback.unwrap_or(RespOut::Accept),
        lines,
    ))
}

// ------------------------------------------------------------------
// 测试
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn cfg_with(dns_body: &str) -> config::Config {
        let src = format!(
            "global {{ dial_mode: 'ip' }}\nrouting {{\n  fallback: direct\n}}\n{}",
            dns_body
        );
        let sections = config::parse_text(&src, std::path::Path::new("t.dae"), 0).unwrap();
        config::Config {
            entry: std::path::PathBuf::from("t.dae"),
            files: vec![std::path::PathBuf::from("t.dae")],
            sections,
        }
    }

    fn tags() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("up1".to_string(), "udp://127.0.0.1:5353".to_string());
        m.insert("up2".to_string(), "udp://127.0.0.1:5354".to_string());
        m
    }

    fn q(name: &str, qtype: u16) -> Question {
        Question {
            qname: name.to_string(),
            qtype,
            qclass: 1,
        }
    }

    #[test]
    fn request_rules_compile_and_select() {
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n  up2: 'udp://127.0.0.1:5354'\n }\n routing {\n  request {\n   qname(full: blocked.test) -> reject\n   qname(suffix: google.test) -> up2\n   qtype(aaaa) -> up2\n   fallback: up1\n  }\n }\n}\n",
        );
        let r = compile(&cfg, &tags(), None).unwrap().unwrap();
        assert_eq!(r.request_rule_lines, 3);
        assert_eq!(r.request_select(&q("blocked.test", 1)), ReqOut::Reject);
        assert_eq!(
            r.request_select(&q("x.blocked.test", 1)),
            ReqOut::Tag("up1".into())
        );
        assert_eq!(
            r.request_select(&q("www.google.test", 1)),
            ReqOut::Tag("up2".into())
        );
        assert_eq!(
            r.request_select(&q("other.test", 28)),
            ReqOut::Tag("up2".into())
        );
        assert_eq!(
            r.request_select(&q("other.test", 1)),
            ReqOut::Tag("up1".into())
        );
    }

    #[test]
    fn request_and_chain_and_not() {
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n  up2: 'udp://127.0.0.1:5354'\n }\n routing {\n  request {\n   qname(full: a.test) && qtype(a) -> up2\n   qname(full: blocked.test) -> reject\n   !qname(suffix: safe.test) -> up1\n   fallback: up2\n  }\n }\n}\n",
        );
        let r = compile(&cfg, &tags(), None).unwrap().unwrap();
        // AND：两函数都命中才走 up2
        assert_eq!(r.request_select(&q("a.test", 1)), ReqOut::Tag("up2".into()));
        // AND 不成立（qtype）→ !suffix(safe.test) 命中 → up1
        assert_eq!(
            r.request_select(&q("a.test", 28)),
            ReqOut::Tag("up1".into())
        );
        // 精确 reject
        assert_eq!(r.request_select(&q("blocked.test", 1)), ReqOut::Reject);
        // NOT：safe.test 不命中 !suffix → fallback up2
        assert_eq!(
            r.request_select(&q("safe.test", 1)),
            ReqOut::Tag("up2".into())
        );
        assert_eq!(
            r.request_select(&q("x.safe.test", 1)),
            ReqOut::Tag("up2".into())
        );
        // 其他域名命中 !suffix → up1
        assert_eq!(r.request_select(&q("c.test", 1)), ReqOut::Tag("up1".into()));
    }

    #[test]
    fn response_rules_ip_and_upstream() {
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n  up2: 'udp://127.0.0.1:5354'\n }\n routing {\n  request { fallback: up1 }\n  response {\n   upstream(up2) -> accept\n   ip(10.9.10.60/32) -> reject\n   ip(10.9.10.61/32) -> up2\n   fallback: accept\n  }\n }\n}\n",
        );
        let r = compile(&cfg, &tags(), None).unwrap().unwrap();
        assert_eq!(r.response_rule_lines, 3);
        // 构造带 A 记录的应答
        let resp60 = crate::dns::tests_support::a_response("x.test", [10, 9, 10, 60], 30);
        let resp61 = crate::dns::tests_support::a_response("x.test", [10, 9, 10, 61], 30);
        let resp_ok = crate::dns::tests_support::a_response("x.test", [10, 9, 10, 62], 30);
        assert_eq!(
            r.response_select(&resp60, &ReqOut::Tag("up1".into())),
            RespOut::Reject
        );
        assert_eq!(
            r.response_select(&resp61, &ReqOut::Tag("up1".into())),
            RespOut::Tag("up2".into())
        );
        assert_eq!(
            r.response_select(&resp_ok, &ReqOut::Tag("up1".into())),
            RespOut::Accept
        );
        assert_eq!(
            r.response_select(&resp60, &ReqOut::Tag("up2".into())),
            RespOut::Accept
        );
    }

    #[test]
    fn qname_file_list() {
        let dir = std::env::temp_dir().join(format!("dnsroute-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("blocklist.txt");
        std::fs::write(
            &list,
            "# 注释\n\nblocked.test\nfull:only.test  # 行内注释\nkeyword:kw-\nregex:^re\\.",
        )
        .unwrap();
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n }\n routing {\n  request {\n   qname(file: 'blocklist.txt') -> reject\n   fallback: up1\n  }\n }\n}\n",
        );
        // 相对路径：按规则所在文件（cfg.files[0]）的目录解析
        let mut cfg = cfg;
        cfg.files = vec![dir.join("entry.dae")];
        let r = compile(&cfg, &tags(), None).unwrap().unwrap();
        assert!(
            r.notes.iter().any(|n| n.contains("4 条域名")),
            "{:?}",
            r.notes
        );
        assert_eq!(r.request_select(&q("blocked.test", 1)), ReqOut::Reject);
        assert_eq!(r.request_select(&q("sub.blocked.test", 1)), ReqOut::Reject);
        assert_eq!(r.request_select(&q("only.test", 1)), ReqOut::Reject);
        assert_eq!(
            r.request_select(&q("sub.only.test", 1)),
            ReqOut::Tag("up1".into())
        );
        assert_eq!(r.request_select(&q("a-kw-b.test", 1)), ReqOut::Reject);
        assert_eq!(r.request_select(&q("re.x", 1)), ReqOut::Reject);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qname_file_missing_is_error() {
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n }\n routing {\n  request {\n   qname(file: '/nonexistent/dnsroute-blocklist.txt') -> reject\n   fallback: up1\n  }\n }\n}\n",
        );
        assert!(compile(&cfg, &tags(), None).is_err());
    }

    #[test]
    fn request_sip_client_subnet() {
        use std::net::IpAddr;
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n  up2: 'udp://127.0.0.1:5354'\n }\n routing {\n  request {\n   qname(full: b.test) && sip(10.0.0.0/8) -> reject\n   qname(full: b.test) && !sip(10.0.0.0/8) -> up2\n   fallback: up1\n  }\n }\n}\n",
        );
        let r = compile(&cfg, &tags(), None).unwrap().unwrap();
        let lan: IpAddr = "10.0.0.2".parse().unwrap();
        let wan: IpAddr = "192.0.2.254".parse().unwrap();
        assert_eq!(
            r.request_select_for(&q("b.test", 1), Some(lan)),
            ReqOut::Reject
        );
        assert_eq!(
            r.request_select_for(&q("b.test", 1), Some(wan)),
            ReqOut::Tag("up2".into())
        );
        // 无客户端信息：sip 不命中、!sip 命中 → up2（负向规则命中）
        assert_eq!(
            r.request_select_for(&q("b.test", 1), None),
            ReqOut::Tag("up2".into())
        );
        // 无关域名走 fallback
        assert_eq!(
            r.request_select_for(&q("other.test", 1), Some(lan)),
            ReqOut::Tag("up1".into())
        );
    }

    #[test]
    fn response_sip_filters_by_client() {
        use std::net::IpAddr;
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n }\n routing {\n  request { fallback: up1 }\n  response {\n   sip(10.9.9.0/24) && ip(10.9.10.60/32) -> reject\n   sip(10.0.0.0/24) && ip(10.9.10.60/32) -> up1\n   fallback: accept\n  }\n }\n}\n",
        );
        let r = compile(&cfg, &tags(), None).unwrap().unwrap();
        assert_eq!(r.response_rule_lines, 2);
        let resp = crate::dns::tests_support::a_response("x.test", [10, 9, 10, 60], 30);
        let lan: IpAddr = "10.0.0.2".parse().unwrap();
        let other: IpAddr = "10.9.9.2".parse().unwrap();
        assert_eq!(
            r.response_select_for(&resp, &ReqOut::Tag("up1".into()), Some(other)),
            RespOut::Reject
        );
        assert_eq!(
            r.response_select_for(&resp, &ReqOut::Tag("up1".into()), Some(lan)),
            RespOut::Tag("up1".into())
        );
        // 无客户端信息：sip 不命中 → 落到 fallback
        assert_eq!(
            r.response_select_for(&resp, &ReqOut::Tag("up1".into()), None),
            RespOut::Accept
        );
    }

    #[test]
    fn unknown_upstream_is_error() {
        let cfg = cfg_with(
            "dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n }\n routing {\n  request {\n   qname(full: a.test) -> nope\n   fallback: up1\n  }\n }\n}\n",
        );
        assert!(compile(&cfg, &tags(), None).is_err());
    }

    #[test]
    fn missing_routing_section_is_none() {
        let cfg = cfg_with("dns {\n upstream {\n  up1: 'udp://127.0.0.1:5353'\n }\n}\n");
        assert!(compile(&cfg, &tags(), None).unwrap().is_none());
    }
}

// SPDX-License-Identifier: GPL-2.0
//! P17a：v2ray geodata（`geoip.dat` / `geosite.dat`）读取与 `geoip:`/`geosite:` 展开。
//!
//! 对照 dae：`pkg/geodata/{geodata,decode,common}.pb.go` + `component/routing/optimizer.go`
//! （`DatReaderOptimizer`）。对齐点：
//! - 文件格式：v2ray protobuf。`GeoIPList{GeoIP{country_code, cidr{CIDR{ip,prefix}}, inverse_match}}`、
//!   `GeoSiteList{GeoSite{country_code, domain{Domain{type,value,attribute}}}}`；
//!   `Domain.Type`：Plain=0 / Regex=1 / RootDomain=2 / Full=3。
//! - key 语义：`geoip:cn` → 展开为裸 CIDR 集合；`geosite:cn` → 展开为域名参数，
//!   类型映射 Plain→keyword、RootDomain→suffix、Full→full、Regex→regex（与 dae 相同）。
//! - `geosite:code@attr`：按 attribute.key 大小写不敏感过滤。
//! - `ext:<file>[:<code>]`：自定义 dat 文件（文件名缺 `.dat` 后缀时自动补）。
//! - 搜索目录（对照 `common/assets/assets.go`）：CLI `--geodata-dir` > `$DAE_LOCATION_ASSET`
//!   > 配置文件目录 > `/etc/dae` > `/usr/local/share/dae` > `/usr/share/dae`。
//! - `inverse_match` 不支持（硬错误，与 dae 一致）；文件/代码缺失是硬错误，
//!   由调用方决定是否回退（mini 在 reload 里保持旧规则）。
//!
//! 与 dae 的差异（如实）：
//! - 不做流式“按 code seek”扫描，整文件解析（文件 ~MB 级；单条 entry 处理完即丢弃）。
//! - 无 XDG 搜索目录；`--geodata-dir` 是 mini 扩展（便于测试与显式部署）。

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
// 缓存值用 Arc（静态存储要求 Send/Sync；编译仅主循环线程持锁使用）
use std::sync::Arc as Rc;

/// 单个 CIDR（ip 为 4 或 16 字节原始形式）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub ip: Vec<u8>,
    pub plen: u32,
}

/// geosite 域名条目（类型 + 值 + attribute key 列表）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainEntry {
    pub dtype: DomainType,
    pub value: String,
    pub attrs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    Plain,
    Regex,
    RootDomain,
    Full,
}

impl DomainType {
    /// dae 的映射（optimizer.go:236-262）：Plain→keyword、RootDomain→suffix、
    /// Full→full、Regex→regex。
    pub fn routing_key(self) -> &'static str {
        match self {
            DomainType::Plain => "keyword",
            DomainType::RootDomain => "suffix",
            DomainType::Full => "full",
            DomainType::Regex => "regex",
        }
    }
}

// ------------------------------------------------------------------
// 极简 protobuf 读取（varint / length-delimited / skip）
// ------------------------------------------------------------------

struct Pb<'a> {
    b: &'a [u8],
    p: usize,
}

#[derive(Debug, Clone, Copy)]
struct Field {
    num: u64,
    wire: u64,
}

impl<'a> Pb<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn eof(&self) -> bool {
        self.p >= self.b.len()
    }
    fn varint(&mut self) -> Result<u64, String> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let c = *self
                .b
                .get(self.p)
                .ok_or_else(|| "geodata: varint 截断".to_string())?;
            self.p += 1;
            if shift >= 64 {
                return Err("geodata: varint 溢出".into());
            }
            v |= u64::from(c & 0x7f) << shift;
            if c & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }
    fn field(&mut self) -> Result<Field, String> {
        let key = self.varint()?;
        Ok(Field {
            num: key >> 3,
            wire: key & 7,
        })
    }
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.varint()? as usize;
        let s = self
            .b
            .get(self.p..self.p + n)
            .ok_or_else(|| "geodata: length-delimited 截断".to_string())?;
        self.p += n;
        Ok(s)
    }
    fn skip(&mut self, wire: u64) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.p += 8,
            2 => {
                let n = self.varint()? as usize;
                self.p += n;
            }
            5 => self.p += 4,
            other => return Err(format!("geodata: 不支持的 wire type {other}")),
        }
        if self.p > self.b.len() {
            return Err("geodata: skip 越界".into());
        }
        Ok(())
    }
}

fn parse_cidr(b: &[u8]) -> Result<Cidr, String> {
    let mut pb = Pb::new(b);
    let mut ip = Vec::new();
    let mut plen = 0u32;
    while !pb.eof() {
        let f = pb.field()?;
        match (f.num, f.wire) {
            (1, 2) => ip = pb.bytes()?.to_vec(),
            (2, 0) => plen = pb.varint()? as u32,
            _ => pb.skip(f.wire)?,
        }
    }
    if ip.len() != 4 && ip.len() != 16 {
        return Err(format!("geodata: CIDR ip 长度非法（{} 字节）", ip.len()));
    }
    let max = if ip.len() == 4 { 32 } else { 128 };
    if plen > max {
        return Err(format!("geodata: CIDR 前缀长度越界（{plen}/{max}）"));
    }
    Ok(Cidr { ip, plen })
}

/// 解析一个 GeoIP entry；`want` 大小写不敏感。
fn parse_geoip_entry(b: &[u8], want: &str) -> Result<Option<(Vec<Cidr>, bool)>, String> {
    let mut pb = Pb::new(b);
    let mut code = String::new();
    let mut cidrs = Vec::new();
    let mut inverse = false;
    while !pb.eof() {
        let f = pb.field()?;
        match (f.num, f.wire) {
            (1, 2) => {
                code = String::from_utf8_lossy(pb.bytes()?).into_owned();
            }
            (2, 2) => cidrs.push(parse_cidr(pb.bytes()?)?),
            (3, 0) => inverse = pb.varint()? != 0,
            _ => pb.skip(f.wire)?,
        }
    }
    if code.eq_ignore_ascii_case(want) {
        Ok(Some((cidrs, inverse)))
    } else {
        Ok(None)
    }
}

fn parse_domain_entry(b: &[u8]) -> Result<DomainEntry, String> {
    let mut pb = Pb::new(b);
    let mut dtype = DomainType::Plain;
    let mut value = String::new();
    let mut attrs = Vec::new();
    while !pb.eof() {
        let f = pb.field()?;
        match (f.num, f.wire) {
            (1, 0) => {
                dtype = match pb.varint()? {
                    0 => DomainType::Plain,
                    1 => DomainType::Regex,
                    2 => DomainType::RootDomain,
                    3 => DomainType::Full,
                    other => return Err(format!("geodata: Domain.Type 未知取值 {other}")),
                }
            }
            (2, 2) => value = String::from_utf8_lossy(pb.bytes()?).into_owned(),
            (3, 2) => {
                // Attribute{key=1, value=2..}：只取 key（dae 只按 key 过滤）
                let mut ab = Pb::new(pb.bytes()?);
                let mut key = String::new();
                while !ab.eof() {
                    let af = ab.field()?;
                    match (af.num, af.wire) {
                        (1, 2) => key = String::from_utf8_lossy(ab.bytes()?).into_owned(),
                        _ => ab.skip(af.wire)?,
                    }
                }
                if !key.is_empty() {
                    attrs.push(key);
                }
            }
            _ => pb.skip(f.wire)?,
        }
    }
    Ok(DomainEntry {
        dtype,
        value,
        attrs,
    })
}

/// 解析一个 GeoSite entry，按 code[@attr] 过滤。
fn parse_geosite_entry(
    b: &[u8],
    want_code: &str,
    attr: Option<&str>,
) -> Result<Option<Vec<DomainEntry>>, String> {
    let mut pb = Pb::new(b);
    let mut code = String::new();
    let mut domains = Vec::new();
    while !pb.eof() {
        let f = pb.field()?;
        match (f.num, f.wire) {
            (1, 2) => {
                code = String::from_utf8_lossy(pb.bytes()?).into_owned();
            }
            (2, 2) => domains.push(parse_domain_entry(pb.bytes()?)?),
            _ => pb.skip(f.wire)?,
        }
    }
    if !code.eq_ignore_ascii_case(want_code) {
        return Ok(None);
    }
    if let Some(attr) = attr {
        domains.retain(|d| d.attrs.iter().any(|k| k.eq_ignore_ascii_case(attr)));
    }
    Ok(Some(domains))
}

/// 在 `GeoIPList` 中找 code（只保留最长匹配？不需要——code 唯一）。
fn parse_geoip_list(b: &[u8], code: &str) -> Result<Option<(Vec<Cidr>, bool)>, String> {
    let mut pb = Pb::new(b);
    while !pb.eof() {
        let f = pb.field()?;
        match (f.num, f.wire) {
            (1, 2) => {
                if let Some(hit) = parse_geoip_entry(pb.bytes()?, code)? {
                    return Ok(Some(hit));
                }
            }
            _ => pb.skip(f.wire)?,
        }
    }
    Ok(None)
}

fn parse_geosite_list(
    b: &[u8],
    code: &str,
    attr: Option<&str>,
) -> Result<Option<Vec<DomainEntry>>, String> {
    let mut pb = Pb::new(b);
    while !pb.eof() {
        let f = pb.field()?;
        match (f.num, f.wire) {
            (1, 2) => {
                if let Some(hit) = parse_geosite_entry(pb.bytes()?, code, attr)? {
                    return Ok(Some(hit));
                }
            }
            _ => pb.skip(f.wire)?,
        }
    }
    Ok(None)
}

// ------------------------------------------------------------------
// 文件解析 & 缓存
// ------------------------------------------------------------------

struct GeoFile {
    path: PathBuf,
    raw: Vec<u8>,
}

fn parse_geoip_buf(raw: &[u8], code: &str) -> Result<Option<(Vec<Cidr>, bool)>, String> {
    parse_geoip_list(raw, code).map_err(|e| format!("geoip.dat 解析失败: {e}"))
}

fn parse_geosite_buf(
    raw: &[u8],
    code: &str,
    attr: Option<&str>,
) -> Result<Option<Vec<DomainEntry>>, String> {
    parse_geosite_list(raw, code, attr).map_err(|e| format!("geosite.dat 解析失败: {e}"))
}

/// geodata 上下文：目录搜索 + 文件/结果缓存（单线程编译期使用，RefCell 足够）。
pub struct Geodata {
    dirs: Vec<PathBuf>,
    geoip_files: RefCell<HashMap<PathBuf, Rc<GeoFile>>>,
    geosite_files: RefCell<HashMap<PathBuf, Rc<GeoFile>>>,
    geoip_cache: RefCell<HashMap<(PathBuf, String), Rc<(Vec<Cidr>, bool)>>>,
    geosite_cache: RefCell<HashMap<(PathBuf, String), Rc<Vec<DomainEntry>>>>,
}

impl Geodata {
    pub fn new(dirs: Vec<PathBuf>) -> Self {
        Self {
            dirs,
            geoip_files: RefCell::new(HashMap::new()),
            geosite_files: RefCell::new(HashMap::new()),
            geoip_cache: RefCell::new(HashMap::new()),
            geosite_cache: RefCell::new(HashMap::new()),
        }
    }

    /// 按搜索顺序解析文件；`name` 可为绝对路径（ext 用）。
    fn find(&self, name: &str) -> Result<PathBuf, String> {
        let p = Path::new(name);
        if p.is_absolute() {
            return if p.is_file() {
                Ok(p.to_path_buf())
            } else {
                Err(format!("geodata 文件不存在: {name}"))
            };
        }
        for d in &self.dirs {
            let candidate = d.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err(format!(
            "找不到 geodata 文件 {name}（搜索目录: {}）",
            if self.dirs.is_empty() {
                "（无；可用 --geodata-dir 或 DAE_LOCATION_ASSET 指定）".to_string()
            } else {
                self.dirs
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| format!("读取 geodata 文件 {} 失败: {e}", path.display()))
    }

    fn geoip_file(&self, path: &Path) -> Result<Rc<GeoFile>, String> {
        if let Some(f) = self.geoip_files.borrow().get(path) {
            return Ok(f.clone());
        }
        let raw = self.read(path)?;
        let f = Rc::new(GeoFile {
            path: path.to_path_buf(),
            raw,
        });
        self.geoip_files
            .borrow_mut()
            .insert(path.to_path_buf(), f.clone());
        Ok(f)
    }

    fn geosite_file(&self, path: &Path) -> Result<Rc<GeoFile>, String> {
        if let Some(f) = self.geosite_files.borrow().get(path) {
            return Ok(f.clone());
        }
        let raw = self.read(path)?;
        let f = Rc::new(GeoFile {
            path: path.to_path_buf(),
            raw,
        });
        self.geosite_files
            .borrow_mut()
            .insert(path.to_path_buf(), f.clone());
        Ok(f)
    }

    /// `geoip:<code>`（geoip.dat）。
    pub fn geoip_code(&self, code: &str) -> Result<Rc<(Vec<Cidr>, bool)>, String> {
        let path = self.find("geoip.dat")?;
        self.geoip_lookup(&path, code)
    }

    fn geoip_lookup(&self, path: &Path, code: &str) -> Result<Rc<(Vec<Cidr>, bool)>, String> {
        let key = (path.to_path_buf(), code.to_ascii_uppercase());
        if let Some(v) = self.geoip_cache.borrow().get(&key) {
            return Ok(v.clone());
        }
        let f = self.geoip_file(path)?;
        let hit = parse_geoip_buf(&f.raw, code)?
            .ok_or_else(|| format!("{} 中没有 geoip code: {code}", f.path.display()))?;
        if hit.1 {
            return Err(format!(
                "{}:{code} 标记 inverse_match，dae/mini 均不支持",
                f.path.display()
            ));
        }
        let v = Rc::new(hit);
        self.geoip_cache.borrow_mut().insert(key, v.clone());
        Ok(v)
    }

    /// `geosite:<code[@attr]>`（geosite.dat）。
    pub fn geosite_code(&self, code_attr: &str) -> Result<Rc<Vec<DomainEntry>>, String> {
        let path = self.find("geosite.dat")?;
        self.geosite_lookup(&path, code_attr)
    }

    fn geosite_lookup(&self, path: &Path, code_attr: &str) -> Result<Rc<Vec<DomainEntry>>, String> {
        let key = (path.to_path_buf(), code_attr.to_string());
        if let Some(v) = self.geosite_cache.borrow().get(&key) {
            return Ok(v.clone());
        }
        let (code, attr) = match code_attr.split_once('@') {
            Some((c, a)) => (c, Some(a)),
            None => (code_attr, None),
        };
        let f = self.geosite_file(path)?;
        let hit = parse_geosite_buf(&f.raw, code, attr)?
            .ok_or_else(|| format!("{} 中没有 geosite code: {code}", f.path.display()))?;
        let v = Rc::new(hit);
        self.geosite_cache.borrow_mut().insert(key, v.clone());
        Ok(v)
    }

    /// `ext:<file>[:<code>]` 的通用入口（geoip 或 geosite 取决于调用方）。
    fn ext_path(&self, file: &str) -> Result<PathBuf, String> {
        let with_ext = if Path::new(file).extension().is_some() {
            file.to_string()
        } else {
            format!("{file}.dat")
        };
        self.find(&with_ext)
    }

    pub fn geoip_ext(&self, file: &str, code: &str) -> Result<Rc<(Vec<Cidr>, bool)>, String> {
        let path = self.ext_path(file)?;
        self.geoip_lookup(&path, code)
    }

    pub fn geosite_ext(&self, file: &str, code_attr: &str) -> Result<Rc<Vec<DomainEntry>>, String> {
        let path = self.ext_path(file)?;
        self.geosite_lookup(&path, code_attr)
    }

    /// P17a：供测试/排障查看搜索目录（当前仅单测与未来状态面使用）。
    #[allow(dead_code)]
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }
}

/// 解析 `ext:file:code` 的 val 部分（`file:code` → (file, code)）。
pub fn split_ext(val: &str) -> Result<(&str, &str), String> {
    val.rsplit_once(':')
        .ok_or_else(|| format!("ext 参数需要 file:code 形式: {val}"))
}

// ------------------------------------------------------------------
// 搜索目录装配
// ------------------------------------------------------------------

/// 按 dae 的顺序装配搜索目录：CLI > DAE_LOCATION_ASSET > 配置目录 > 系统目录。
pub fn search_dirs(cli_dirs: &[PathBuf], config_path: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let push = |d: PathBuf, dirs: &mut Vec<PathBuf>| {
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    };
    for d in cli_dirs {
        push(d.clone(), &mut dirs);
    }
    if let Ok(env) = std::env::var("DAE_LOCATION_ASSET") {
        if !env.is_empty() {
            push(PathBuf::from(env), &mut dirs);
        }
    }
    if let Some(cfg) = config_path {
        if let Some(parent) = cfg.parent() {
            push(parent.to_path_buf(), &mut dirs);
        }
    }
    // XDG 数据目录（$XDG_DATA_HOME/dae + $XDG_DATA_DIRS/*/dae，含 ~/.local/share/dae）。
    if let Ok(home) = std::env::var("XDG_DATA_HOME") {
        if !home.is_empty() {
            push(PathBuf::from(home).join("dae"), &mut dirs);
        }
    } else if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            push(PathBuf::from(h).join(".local/share/dae"), &mut dirs);
        }
    }
    let data_dirs = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_string());
    for d in data_dirs.split(':').filter(|s| !s.is_empty()) {
        push(PathBuf::from(d).join("dae"), &mut dirs);
    }
    for d in ["/etc/dae", "/usr/local/share/dae", "/usr/share/dae"] {
        push(PathBuf::from(d), &mut dirs);
    }
    dirs
}

// ------------------------------------------------------------------
// 测试
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 极简 protobuf 写入（测试编码器） ----
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }
    fn tag(num: u64, wire: u64, out: &mut Vec<u8>) {
        varint((num << 3) | wire, out);
    }
    fn len_field(num: u64, payload: &[u8], out: &mut Vec<u8>) {
        tag(num, 2, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }
    fn cidr(ip: &[u8], plen: u32) -> Vec<u8> {
        let mut b = Vec::new();
        len_field(1, ip, &mut b);
        tag(2, 0, &mut b);
        varint(plen as u64, &mut b);
        b
    }
    fn geoip_entry(code: &str, cidrs: &[Vec<u8>], inverse: bool) -> Vec<u8> {
        let mut b = Vec::new();
        len_field(1, code.as_bytes(), &mut b);
        for c in cidrs {
            len_field(2, c, &mut b);
        }
        if inverse {
            tag(3, 0, &mut b);
            varint(1, &mut b);
        }
        b
    }
    fn attr(key: &str) -> Vec<u8> {
        let mut b = Vec::new();
        len_field(1, key.as_bytes(), &mut b);
        b
    }
    fn domain(dtype: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut b = Vec::new();
        tag(1, 0, &mut b);
        varint(dtype, &mut b);
        len_field(2, value.as_bytes(), &mut b);
        for a in attrs {
            len_field(3, &attr(a), &mut b);
        }
        b
    }
    fn geosite_entry(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        len_field(1, code.as_bytes(), &mut b);
        for d in domains {
            len_field(2, d, &mut b);
        }
        b
    }
    fn list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        for e in entries {
            len_field(1, e, &mut b);
        }
        b
    }

    #[test]
    fn geoip_parse_and_expand() {
        let raw = list(&[
            geoip_entry(
                "cn",
                &[
                    cidr(&[10, 9, 10, 4], 32),
                    cidr(&[10, 9, 9, 0], 24),
                    cidr(
                        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        128,
                    ),
                ],
                false,
            ),
            geoip_entry("us", &[cidr(&[1, 2, 3, 0], 24)], false),
        ]);
        let hit = parse_geoip_buf(&raw, "CN").unwrap().unwrap();
        assert_eq!(hit.0.len(), 3);
        assert_eq!(hit.0[0].plen, 32);
        // 大小写不敏感
        assert!(parse_geoip_buf(&raw, "cn").unwrap().is_some());
        assert!(parse_geoip_buf(&raw, "nope").unwrap().is_none());
    }

    #[test]
    fn geoip_geosite_expansion_through_compiler() {
        // 端到端（编码器在本模块）：dat → Geodata → mini 规则编译 → LPM/域集
        let dir = std::env::temp_dir().join(format!("mini-dae-geo-exp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let geoip = list(&[geoip_entry(
            "cn",
            &[cidr(&[10, 9, 10, 4], 32), cidr(&[10, 9, 9, 0], 24)],
            false,
        )]);
        let geosite = list(&[geosite_entry(
            "cn",
            &[
                domain(2, "geo.test", &[]),
                domain(3, "full.geo.test", &[]),
                domain(0, "kwgeo", &[]),
            ],
        )]);
        std::fs::write(dir.join("geoip.dat"), &geoip).unwrap();
        std::fs::write(dir.join("geosite.dat"), &geosite).unwrap();
        let g = Geodata::new(vec![dir.clone()]);

        let text = "dip(geoip: cn) && dport(9999) -> direct\ndomain(geosite: cn) -> proxy\nfallback -> direct\n";
        let c = crate::rules::parse_and_compile_with_geo(text, Some(&g)).unwrap();
        // LPM 集合：2 条前缀（排序 + 去重后 /24 在前）
        let lpm = &c.lpm_tries[&0];
        assert_eq!(lpm.len(), 2);
        assert_eq!(lpm[0].0, 96 + 24);
        // 域集：suffix/full/keyword 各一个 match_set（按 dat 首次出现顺序）
        let keys: Vec<&str> = c.domain_sets.iter().map(|d| d.key.as_str()).collect();
        assert_eq!(keys, vec!["suffix", "full", "keyword"]);
        assert!(c
            .notes
            .iter()
            .any(|n| n.contains("geoip:cn") && n.contains("2 条前缀")));
        assert!(c.notes.iter().any(|n| n.contains("geosite:cn")));
        assert!(crate::dns::domain_set_matches(
            &c.domain_sets[0],
            "a.geo.test"
        ));
        assert!(crate::dns::domain_set_matches(
            &c.domain_sets[1],
            "full.geo.test"
        ));
        assert!(crate::dns::domain_set_matches(
            &c.domain_sets[2],
            "x.kwgeo.y"
        ));

        // 缺 code / 缺 geodata 上下文是硬错误
        assert!(crate::rules::parse_and_compile_with_geo(
            "dip(geoip: zz) -> direct\nfallback -> direct\n",
            Some(&g)
        )
        .is_err());
        assert!(crate::rules::parse_and_compile_with_geo(
            "dip(geoip: cn) -> direct\nfallback -> direct\n",
            None
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn geoip_inverse_rejected() {
        let raw = list(&[geoip_entry("cn", &[cidr(&[1, 1, 1, 1], 32)], true)]);
        assert!(parse_geoip_buf(&raw, "cn").unwrap().unwrap().1);
        // lookup 路径会拒绝（见 geoip_lookup）；此处仅验证解析出 inverse 标记
    }

    #[test]
    fn geosite_types_and_attr() {
        let raw = list(&[geosite_entry(
            "cn",
            &[
                domain(0, "kw.example", &["ads"]),
                domain(2, "suffix.example", &[]),
                domain(3, "full.example", &["ads"]),
                domain(1, r"^re\.example$", &[]),
            ],
        )]);
        let all = parse_geosite_buf(&raw, "cn", None).unwrap().unwrap();
        assert_eq!(all.len(), 4);
        let types: Vec<&str> = all.iter().map(|d| d.dtype.routing_key()).collect();
        assert_eq!(types, vec!["keyword", "suffix", "full", "regex"]);
        let ads = parse_geosite_buf(&raw, "cn", Some("ADS")).unwrap().unwrap();
        assert_eq!(ads.len(), 2);
        assert_eq!(ads[0].value, "kw.example");
        assert_eq!(ads[1].value, "full.example");
    }

    #[test]
    fn file_search_and_cache() {
        let dir = std::env::temp_dir().join(format!("mini-dae-geo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let geoip = list(&[geoip_entry("cn", &[cidr(&[10, 0, 0, 0], 8)], false)]);
        std::fs::write(dir.join("geoip.dat"), &geoip).unwrap();
        let geosite = list(&[geosite_entry("cn", &[domain(2, "example.cn", &[])])]);
        std::fs::write(dir.join("geosite.dat"), &geosite).unwrap();
        std::fs::write(dir.join("mygeo.dat"), &geoip).unwrap();

        let g = Geodata::new(vec![dir.clone()]);
        let c = g.geoip_code("cn").unwrap();
        assert_eq!(c.0.len(), 1);
        let c2 = g.geoip_ext("mygeo", "cn").unwrap();
        assert_eq!(c2.0.len(), 1);
        let d = g.geosite_code("cn").unwrap();
        assert_eq!(d[0].value, "example.cn");
        // 缺失 code / 文件
        assert!(g.geoip_code("zz").is_err());
        assert!(g.geosite_ext("nofile", "cn").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn split_ext_ok() {
        assert_eq!(split_ext("mydata.dat:cn").unwrap(), ("mydata.dat", "cn"));
        assert!(split_ext("nocode").is_err());
    }
}

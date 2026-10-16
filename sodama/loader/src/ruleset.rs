//! P36：规则集（`rule_set { tag: 'url|路径' }`）——标准格式分流规则文件的获取/缓存/解析。
//!
//! 支持格式（按内容自动识别）：
//! - **sing-box rule-set JSON v1**：`{"version":1,"rules":[{"domain":[…],
//!   "domain_suffix":[…],"domain_keyword":[…],"domain_regex":[…]}]}`；
//! - **Clash rule-provider YAML**（`payload:` 列表）与 **classical 列表**：
//!   `DOMAIN,` / `DOMAIN-SUFFIX,` / `DOMAIN-KEYWORD,` / `DOMAIN-REGEX,`；
//! - **纯文本域名列表**：每行一个，`#`/`//` 注释；可选 `full:`/`suffix:`/`keyword:`/
//!   `regex:` 前缀（同 `qname(file:)` 约定），裸条目 = suffix。
//! 非域名条目（IP-CIDR/PROCESS-NAME/GEOIP 等）**如实计数**（status 面可见），不静默丢弃。
//!
//! 远程 URL：缓存到 `rule_set_cache_dir`（缺省 XDG cache → ~/.cache → /var/cache → /tmp），
//! `global { rule_set_update_interval: 秒 }` 内直接用缓存（**0 = 每次 reload 都刷新**；
//! 缺省 86400）；刷新失败回退旧缓存（日志警示），无缓存可用则**硬失败**——
//! 保持「配置/规则缺失不静默降级」的既有口径（对照 ADR-0037 的 `qname(file:)`）。

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::config;
use crate::subscribe;

#[derive(Debug, Default, Clone)]
pub struct RuleSetData {
    pub full: Vec<String>,
    pub suffix: Vec<String>,
    pub keyword: Vec<String>,
    pub regex: Vec<String>,
    /// 非域名条目数（IP-CIDR/GEOIP/PROCESS-NAME…）——如实上报
    pub ignored: usize,
}

impl RuleSetData {
    pub fn total(&self) -> usize {
        self.full.len() + self.suffix.len() + self.keyword.len() + self.regex.len()
    }
}

pub struct RuleSet {
    pub tag: String,
    pub remote: bool,
    pub from_cache: bool,
    pub updated_secs_ago: Option<u64>,
    /// 本地直接读取的文件（P36：加入 inotify 监听，改名单即热生效；远程为 None）。
    pub local_path: Option<PathBuf>,
    pub data: RuleSetData,
    /// 本集合本次加载的失败原因（软失败：集合置空，但**不阻塞其它集合与整体 reload**）。
    ///
    /// 背景（2026-10-09）：旧行为是「远程首拉失败 + 无缓存 → 硬失败」，而面板落盘时
    /// **不回滚**，一个写错的远程 URL 会永久留在 config.dae 里，导致之后**每一次**
    /// reload 都失败（自锁）。现改为软失败 + 状态面显式上报。
    pub error: Option<String>,
}

#[derive(Default)]
pub struct RuleSetStore {
    sets: HashMap<String, RuleSet>,
}

impl RuleSetStore {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn get(&self, tag: &str) -> Option<&RuleSet> {
        self.sets.get(tag)
    }

    pub fn tags(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.sets.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }

    pub fn iter(&self) -> impl Iterator<Item = &RuleSet> {
        self.sets.values()
    }

    /// 解析 `config` 的 `rule_set` 段并加载全部规则集。
    ///
    /// 单个集合失败**不再**使整体失败（软失败）：失败者置空并在 `RuleSet::error`
    /// 上报，其余集合与整体 reload 照常。返回 `Ok` 恒成立，保留 `Result` 形状是为
    /// 兼容调用点与未来可能的全局错误（如缓存目录完全不可用）。
    pub fn load(
        cfg: &config::Config,
        cfg_path: Option<&Path>,
        interval_secs: u64,
        cache_dir: Option<&str>,
    ) -> Result<Self, String> {
        let specs = config::rule_sets(cfg);
        let cfg_dir = cfg_path.and_then(|p| p.parent());
        let mut sets = HashMap::new();
        for (tag, src) in specs {
            let rs = load_one(&tag, &src, cfg_dir, interval_secs, cache_dir);
            sets.insert(tag, rs);
        }
        Ok(Self { sets })
    }
}

/// 软失败包装：把「单个规则集加载失败」降级为空集合 + `error` 字段。
/// 旧行为直接 `Err` 向上冒，使整次 reload 失败（并因面板不回滚而自锁）。
fn load_one(
    tag: &str,
    src: &str,
    cfg_dir: Option<&Path>,
    interval_secs: u64,
    cache_dir: Option<&str>,
) -> RuleSet {
    match load_one_inner(tag, src, cfg_dir, interval_secs, cache_dir) {
        Ok(rs) => rs,
        Err(e) => {
            crate::log(&format!(
                "规则集 {tag}: {e} —— 软失败（本集合置空，不阻塞整体 reload；请修正配置或补缓存）"
            ));
            RuleSet {
                tag: tag.to_string(),
                remote: src.starts_with("http://") || src.starts_with("https://"),
                from_cache: false,
                updated_secs_ago: None,
                local_path: None,
                data: RuleSetData::default(),
                error: Some(e),
            }
        }
    }
}

fn load_one_inner(
    tag: &str,
    src: &str,
    cfg_dir: Option<&Path>,
    interval_secs: u64,
    cache_dir: Option<&str>,
) -> Result<RuleSet, String> {
    let remote = src.starts_with("http://") || src.starts_with("https://");
    let mut from_cache = false;
    // P38：延迟初始化（每条路径在使用前赋值；初值 None 从未被读—— clippy::unused_assignments）。
    let updated;
    let mut local_path: Option<PathBuf> = None;
    let body: Vec<u8>;
    if remote {
        let dir = match cache_dir {
            Some(d) => {
                let p = PathBuf::from(d);
                std::fs::create_dir_all(&p)
                    .map_err(|e| format!("规则集 {tag}: 创建缓存目录 {d}: {e}"))?;
                p
            }
            None => default_cache_dir().ok_or_else(|| {
                format!("规则集 {tag}: 无可写缓存目录（可设 global.rule_set_cache_dir）")
            })?,
        };
        let cache = dir.join(format!("{tag}.ruleset"));
        let age: Option<Duration> = std::fs::metadata(&cache)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| SystemTime::now().duration_since(t).unwrap_or_default());
        let fresh = interval_secs > 0
            && age
                .map(|a| a < Duration::from_secs(interval_secs))
                .unwrap_or(false);
        if fresh {
            body = std::fs::read(&cache)
                .map_err(|e| format!("规则集 {tag}: 读缓存 {cache:?}: {e}"))?;
            from_cache = true;
            updated = age.map(|a| a.as_secs());
            crate::log(&format!(
                "规则集 {tag}: 使用缓存（{}s 前抓取，{} 字节）",
                updated.unwrap_or(0),
                body.len()
            ));
        } else {
            match subscribe::fetch(src, Duration::from_secs(20)) {
                Ok(b) => {
                    // 原子写缓存（临时文件 + rename），失败只警告（不阻塞启动）
                    let tmp = cache.with_extension("tmp");
                    if std::fs::File::create(&tmp)
                        .and_then(|mut f| f.write_all(&b))
                        .and_then(|_| std::fs::rename(&tmp, &cache))
                        .is_err()
                    {
                        crate::log(&format!("规则集 {tag}: 缓存写入失败（不影响本次使用）"));
                    }
                    body = b;
                    updated = Some(0);
                    crate::log(&format!(
                        "规则集 {tag}: 已更新（网络，{} 字节）",
                        body.len()
                    ));
                }
                Err(e) => match std::fs::read(&cache) {
                    Ok(b) if !b.is_empty() => {
                        crate::log(&format!(
                            "规则集 {tag}: 拉取失败（{e}），回退旧缓存（{} 字节）",
                            b.len()
                        ));
                        body = b;
                        from_cache = true;
                        updated = age.map(|a| a.as_secs());
                    }
                    _ => {
                        return Err(format!(
                            "规则集 {tag}: 拉取失败且无可用缓存: {e}（源: {src}）"
                        ))
                    }
                },
            }
        }
    } else {
        let p = resolve_local(cfg_dir, src);
        let md = std::fs::metadata(&p).map_err(|e| format!("规则集 {tag}: {p:?} 不可读: {e}"))?;
        updated = md.modified().ok().map(|t| {
            SystemTime::now()
                .duration_since(t)
                .unwrap_or_default()
                .as_secs()
        });
        body = std::fs::read(&p).map_err(|e| format!("规则集 {tag}: 读 {p:?}: {e}"))?;
        local_path = Some(p);
    }
    let data = parse_ruleset(&body)?;
    let rs = RuleSet {
        tag: tag.to_string(),
        remote,
        from_cache,
        updated_secs_ago: updated,
        local_path,
        data,
        error: None,
    };
    crate::log(&format!(
        "规则集 {tag}: {} 条域名（full/suffix/keyword/regex = {}/{}/{}/{}，忽略非域名 {} 条；{}）",
        rs.data.total(),
        rs.data.full.len(),
        rs.data.suffix.len(),
        rs.data.keyword.len(),
        rs.data.regex.len(),
        rs.data.ignored,
        if from_cache {
            "缓存"
        } else if remote {
            "网络"
        } else {
            "本地文件"
        },
    ));
    Ok(rs)
}

/// 本地路径规整：`~/` 展开；config 内相对路径按配置目录解析（同订阅的约定）。
fn resolve_local(cfg_dir: Option<&Path>, src: &str) -> PathBuf {
    let s = src.strip_prefix("file://").unwrap_or(src);
    let expanded = match s.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(h) => format!("{h}/{rest}"),
            Err(_) => s.to_string(),
        },
        None => s.to_string(),
    };
    if expanded.starts_with('/') {
        return PathBuf::from(expanded);
    }
    if let Some(dir) = cfg_dir {
        let cand = dir.join(&expanded);
        if cand.is_file() {
            return cand;
        }
    }
    PathBuf::from(expanded)
}

/// 缺省缓存目录（按序尝试创建）：XDG cache → ~/.cache → /var/cache → /tmp。
fn default_cache_dir() -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        if !x.is_empty() {
            cands.push(PathBuf::from(x).join("sodama/rulesets"));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            cands.push(PathBuf::from(h).join(".cache/sodama/rulesets"));
        }
    }
    cands.push(PathBuf::from("/var/cache/sodama/rulesets"));
    cands.push(std::env::temp_dir().join("sodama-rulesets"));
    cands
        .into_iter()
        .find(|p| std::fs::create_dir_all(p).is_ok())
}

/// 解析规则集正文（自动识别 JSON / Clash / 纯文本）。
pub fn parse_ruleset(body: &[u8]) -> Result<RuleSetData, String> {
    let text = String::from_utf8_lossy(body);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text); // 容忍 BOM
    let t = text.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        return parse_singbox_json(text);
    }
    if looks_like_clash(text) {
        return Ok(parse_clash(text));
    }
    Ok(parse_plain(text))
}

fn looks_like_clash(text: &str) -> bool {
    text.lines().any(|raw| {
        let l = raw
            .trim()
            .trim_start_matches('-')
            .trim()
            .trim_matches(|c| c == '\'' || c == '"');
        let kind = l
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        matches!(
            kind.as_str(),
            "PAYLOAD:"
                | "DOMAIN"
                | "DOMAIN-SUFFIX"
                | "DOMAIN-KEYWORD"
                | "DOMAIN-REGEX"
                | "IP-CIDR"
                | "IP-CIDR6"
                | "SRC-IP-CIDR"
                | "GEOIP"
                | "PROCESS-NAME"
                | "RULE-SET"
                | "SRC-PORT"
                | "DST-PORT"
                | "MATCH"
                | "FINAL"
        )
    })
}

fn push_norm(v: &mut Vec<String>, s: &str) {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if !s.is_empty() {
        v.push(s);
    }
}

fn parse_clash(text: &str) -> RuleSetData {
    let mut d = RuleSetData::default();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l
            .strip_prefix("- ")
            .unwrap_or(l)
            .trim()
            .trim_matches(|c| c == '\'' || c == '"');
        let mut fields = l.split(',').map(str::trim);
        let kind = fields.next().unwrap_or("").to_ascii_uppercase();
        if kind == "PAYLOAD:" || kind.is_empty() {
            continue;
        }
        let Some(val) = fields.next() else {
            d.ignored += 1;
            continue;
        };
        match kind.as_str() {
            "DOMAIN" => push_norm(&mut d.full, val),
            "DOMAIN-SUFFIX" => push_norm(&mut d.suffix, val),
            "DOMAIN-KEYWORD" => push_norm(&mut d.keyword, val),
            "DOMAIN-REGEX" => {
                if !val.is_empty() {
                    d.regex.push(val.to_string());
                }
            }
            _ => d.ignored += 1, // IP-CIDR / GEOIP / PROCESS-NAME / FINAL 等
        }
    }
    d
}

fn parse_plain(text: &str) -> RuleSetData {
    let mut d = RuleSetData::default();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        match l.split_once(':') {
            Some((k, v)) if matches!(k, "full" | "suffix" | "keyword" | "regex") => match k {
                "full" => push_norm(&mut d.full, v),
                "suffix" => push_norm(&mut d.suffix, v),
                "keyword" => push_norm(&mut d.keyword, v),
                _ => {
                    if !v.trim().is_empty() {
                        d.regex.push(v.trim().to_string());
                    }
                }
            },
            _ => push_norm(&mut d.suffix, l),
        }
    }
    d
}

fn parse_singbox_json(text: &str) -> Result<RuleSetData, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("sing-box JSON 解析失败: {e}"))?;
    let rules = v
        .get("rules")
        .and_then(|r| r.as_array())
        .ok_or_else(|| "sing-box rule-set 缺 rules 数组".to_string())?;
    let mut d = RuleSetData::default();
    for r in rules {
        let Some(obj) = r.as_object() else { continue };
        for (k, val) in obj {
            let Some(arr) = val.as_array() else {
                d.ignored += 1;
                continue;
            };
            match k.as_str() {
                "domain" => {
                    for x in arr.iter().filter_map(|x| x.as_str()) {
                        push_norm(&mut d.full, x);
                    }
                }
                "domain_suffix" => {
                    for x in arr.iter().filter_map(|x| x.as_str()) {
                        push_norm(&mut d.suffix, x);
                    }
                }
                "domain_keyword" => {
                    for x in arr.iter().filter_map(|x| x.as_str()) {
                        push_norm(&mut d.keyword, x);
                    }
                }
                "domain_regex" => {
                    for x in arr.iter().filter_map(|x| x.as_str()) {
                        if !x.is_empty() {
                            d.regex.push(x.to_string());
                        }
                    }
                }
                _ => d.ignored += arr.len(), // ip_cidr/port/process_name…
            }
        }
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clash_payload_and_classical() {
        let text = "payload:\n  - DOMAIN-SUFFIX,Example.COM\n  - 'DOMAIN,exact.test'\n  - DOMAIN-KEYWORD, foo \n  - DOMAIN-REGEX,^a.*\n  - IP-CIDR,10.0.0.0/8,no-resolve\n";
        let d = parse_ruleset(text.as_bytes()).unwrap();
        assert_eq!(d.suffix, vec!["example.com"]);
        assert_eq!(d.full, vec!["exact.test"]);
        assert_eq!(d.keyword, vec!["foo"]);
        assert_eq!(d.regex, vec!["^a.*"]);
        assert_eq!(d.ignored, 1);

        // classical 规则列表（第三列策略）：只取第二列
        let classical = "DOMAIN-SUFFIX,google.com,PROXY\nDOMAIN,ads.com,REJECT\nGEOIP,CN,DIRECT\n";
        let d = parse_ruleset(classical.as_bytes()).unwrap();
        assert_eq!(d.suffix, vec!["google.com"]);
        assert_eq!(d.full, vec!["ads.com"]);
        assert_eq!(d.ignored, 1);
    }

    #[test]
    fn parse_singbox_json_v1() {
        let text = r#"{"version":1,"rules":[{"domain":["A.test"],"domain_suffix":["b.test"],"domain_keyword":["Kw"],"domain_regex":["^x\\d+$"],"ip_cidr":["10.0.0.0/8"]}]}"#;
        let d = parse_ruleset(text.as_bytes()).unwrap();
        assert_eq!(d.full, vec!["a.test"]);
        assert_eq!(d.suffix, vec!["b.test"]);
        assert_eq!(d.keyword, vec!["kw"]);
        assert_eq!(d.regex.len(), 1);
        assert_eq!(d.ignored, 1);
        assert!(parse_ruleset(b"{\"version\":1}").is_err());
    }

    #[test]
    fn parse_plain_with_prefixes() {
        let text = "# 注释\n// 也是注释\n\nExample.com\nfull:exact.test\nkeyword:Kw\nregex:^y\n";
        let d = parse_ruleset(text.as_bytes()).unwrap();
        assert_eq!(d.suffix, vec!["example.com"]);
        assert_eq!(d.full, vec!["exact.test"]);
        assert_eq!(d.keyword, vec!["kw"]);
        assert_eq!(d.regex, vec!["^y"]);
        assert_eq!(d.ignored, 0);
    }
}

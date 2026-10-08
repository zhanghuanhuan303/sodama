//! 配置页 API：结构化改配置（订阅 / 规则集 / 本地分流规则文件）。
//!
//! 设计前提：`config.dae` 是**唯一事实来源**，引擎用 inotify 目录级热驱动
//! （含 `rule_set` 指向的文件）。所以面板改配置 = 「改文本 → validate 护栏 →
//! 落盘 → 等 reload 回执」，**不需要任何引擎/数据面改动**。
//!
//! 订阅「解析预览」复用引擎自身的拉取/解码/解析实现（`sodama sub-parse`，只读），
//! 避免在面板里重复一套节点链接解析（协议漂移风险）。

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use shared::{
    DomainFileView, DomainsView, InspectView, ParamKind, ParamSetReq, ParamsView, ProtoCount,
    SaveResult, SubNode, PARAMS,
};

use crate::{
    apply_config_text, auth, block_kv, current_reload_at, err_json, redact, require_actions,
    run_cmd, wait_reload, write_preserving, Ctx, Engine,
};

pub fn routes() -> Router<Ctx> {
    Router::new()
        .route("/api/v1/config/params", get(api_params).post(api_param_set))
        .route("/api/v1/config/inspect", post(api_inspect))
        .route("/api/v1/config/subs", post(api_sub_add))
        .route("/api/v1/config/subs/bulk", post(api_sub_bulk))
        .route("/api/v1/config/subs/remove", post(api_sub_remove))
        .route("/api/v1/config/subs/move", post(api_sub_move))
        .route("/api/v1/config/group/policy", post(api_group_policy))
        .route("/api/v1/config/rulesets", post(api_ruleset_add))
        .route("/api/v1/config/rulesets/remove", post(api_ruleset_remove))
        .route("/api/v1/config/rule-files", get(api_rule_files))
        .route("/api/v1/config/rule-files/add", post(api_rule_file_add))
        .route(
            "/api/v1/config/rule-files/remove",
            post(api_rule_file_remove),
        )
}

// ---------------------------------------------------------------- 文本编辑（纯函数）

/// `name {` … `}` 块的行号区间（含起止行；跳过注释行）。
fn find_block(text: &str, name: &str) -> Option<(usize, usize)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut start = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if start.is_none() {
            if let Some(rest) = t.strip_prefix(name) {
                let rest = rest.trim_start();
                if rest.starts_with('{') {
                    start = Some(i);
                    if rest.contains('}') {
                        return Some((i, i)); // 单行块
                    }
                }
            }
            continue;
        }
        if t.starts_with('}') {
            return Some((start.unwrap(), i));
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    line: usize,
    indent: String,
    tag: String,
    value: String,
}

/// 块内 `tag: 'value'` 条目（保留原始行号与缩进，便于原地替换）。
fn entries_of(lines: &[&str], start: usize, end: usize) -> Vec<Entry> {
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('}') {
            continue;
        }
        if let Some((k, v)) = t.split_once(':') {
            let tag = k.trim().to_string();
            let value = v
                .trim()
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['\'', '"'])
                .trim()
                .to_string();
            if !tag.is_empty() && !value.is_empty() {
                let indent = line[..line.len() - line.trim_start().len()].to_string();
                out.push(Entry {
                    line: i,
                    indent,
                    tag,
                    value,
                });
            }
        }
    }
    out
}

/// tag 合法性：与引擎 `rule_set` 校验一致（字母/数字/_/-/.）。
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// 订阅/规则集值合法性：http(s)/file URL 或相对路径（禁止空白、引号、越级路径）。
fn valid_value(v: &str) -> bool {
    if v.is_empty() || v.contains(['\'', '"', '\n', '\r']) || v.split_whitespace().count() != 1 {
        return false;
    }
    if let Some(rest) = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))
        .or_else(|| v.strip_prefix("file://"))
    {
        return !rest.is_empty();
    }
    if v.contains("://") {
        return false; // 只认 http/https/file
    }
    !v.starts_with('/') && !v.contains("..")
}

/// 新增或更新条目（tag 已存在则原地改值，否则插到块尾）。
fn upsert_entry(text: &str, block: &str, tag: &str, value: &str) -> Result<String, String> {
    if !valid_tag(tag) {
        return Err(format!("名称 {tag} 非法（仅限字母/数字/_/-/.）"));
    }
    if !valid_value(value) {
        return Err("值非法：需为 http(s):// 链接或相对路径".into());
    }
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let tail_nl = text.ends_with('\n');
    match find_block(text, block) {
        Some((start, end)) if start != end => {
            let refs: Vec<&str> = text.lines().collect();
            let entries = entries_of(&refs, start, end);
            if let Some(e) = entries.iter().find(|e| e.tag == tag) {
                lines[e.line] = format!("{}{}: '{}'", e.indent, tag, value);
            } else {
                let indent = entries
                    .first()
                    .map(|e| e.indent.clone())
                    .unwrap_or_else(|| "    ".into());
                lines.insert(end, format!("{indent}{tag}: '{value}'"));
            }
        }
        Some((start, _)) => {
            // 单行块：展开成多行
            let indent =
                lines[start][..lines[start].len() - lines[start].trim_start().len()].to_string();
            lines[start] = format!("{block} {{");
            lines.insert(start + 1, format!("{indent}    {tag}: '{value}'"));
            lines.insert(start + 2, format!("{indent}}}"));
        }
        None => {
            // 整块缺失：追加到文件末尾
            if lines.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
                lines.push(String::new());
            }
            lines.push(format!("{block} {{"));
            lines.push(format!("    {tag}: '{value}'"));
            lines.push("}".into());
        }
    }
    let mut out = lines.join("\n");
    if tail_nl {
        out.push('\n');
    }
    Ok(out)
}

/// 删除条目；`min_keep` = 块内至少保留的条目数（订阅块必须 ≥1）。
fn remove_entry(text: &str, block: &str, tag: &str, min_keep: usize) -> Result<String, String> {
    let (start, end) = find_block(text, block).ok_or(format!("配置里找不到 {block} 块"))?;
    let refs: Vec<&str> = text.lines().collect();
    let entries = entries_of(&refs, start, end);
    let e = entries
        .iter()
        .find(|e| e.tag == tag)
        .ok_or(format!("{block} 里没有 {tag}"))?;
    if entries.len() <= min_keep {
        return Err(format!(
            "{block} 至少需要保留 {min_keep} 条，不能删除 {tag}"
        ));
    }
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    lines.remove(e.line);
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// 块内上/下移一条（保持缩进）。
fn move_entry(text: &str, block: &str, tag: &str, up: bool) -> Result<String, String> {
    let (start, end) = find_block(text, block).ok_or(format!("配置里找不到 {block} 块"))?;
    let refs: Vec<&str> = text.lines().collect();
    let entries = entries_of(&refs, start, end);
    let pos = entries
        .iter()
        .position(|e| e.tag == tag)
        .ok_or(format!("{block} 里没有 {tag}"))?;
    if (up && pos == 0) || (!up && pos + 1 == entries.len()) {
        return Ok(text.to_string());
    }
    let other = if up { pos - 1 } else { pos + 1 };
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    lines.swap(entries[pos].line, entries[other].line);
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// 在 `outer { inner { … } }` 里设置/替换 `key: value`（用于 `group.<name>.policy`）。
fn set_nested_param(
    text: &str,
    outer: &str,
    inner: &str,
    key: &str,
    value: &str,
) -> Result<String, String> {
    let (os, oe) = find_block(text, outer).ok_or(format!("配置里找不到 {outer} 块"))?;
    let all: Vec<&str> = text.lines().collect();
    let mut is = None;
    let mut ie = None;
    for (i, line) in all.iter().enumerate().take(oe + 1).skip(os + 1) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if is.is_none() {
            if let Some(rest) = t.strip_prefix(inner) {
                let rest = rest.trim_start();
                if rest.starts_with('{') {
                    is = Some(i);
                    if rest.contains('}') {
                        ie = Some(i); // 单行子块
                    }
                }
            }
            continue;
        }
        if t.starts_with('}') {
            ie = Some(i);
            break;
        }
    }
    let (is, ie) = match (is, ie) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(format!("{outer} 里找不到 {inner} 子块")),
    };
    let indent = |s: &str| s[..s.len() - s.trim_start().len()].to_string();
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    if is == ie {
        // 单行子块 → 展开成多行
        let outer_indent = indent(all[is]);
        lines[is] = format!("{outer_indent}{inner} {{");
        lines.insert(is + 1, format!("{outer_indent}    {key}: {value}"));
        lines.insert(is + 2, format!("{outer_indent}}}"));
    } else {
        let child_indent = all[is + 1..ie]
            .iter()
            .find(|l| !l.trim().is_empty())
            .map(|l| indent(l))
            .unwrap_or_else(|| format!("{}    ", indent(all[is])));
        let mut found = None;
        for (i, line) in all.iter().enumerate().take(ie).skip(is + 1) {
            let t = line.trim();
            if t.starts_with('#') {
                continue;
            }
            if let Some(rest) = t.strip_prefix(key) {
                if rest.trim_start().starts_with(':') {
                    found = Some(i);
                    break;
                }
            }
        }
        match found {
            Some(i) => lines[i] = format!("{}{key}: {value}", indent(all[i])),
            None => lines.insert(is + 1, format!("{child_indent}{key}: {value}")),
        }
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// 域名/规则条目规范化 + 粗校验（最终仍由引擎 validate 兜底）。
fn norm_entry(raw: &str) -> Result<String, String> {
    let mut e = raw.trim().to_string();
    for p in ["http://", "https://"] {
        if let Some(rest) = e.strip_prefix(p) {
            e = rest.split('/').next().unwrap_or("").to_string();
        }
    }
    if e.is_empty() {
        return Err("空条目".into());
    }
    if e.contains(['\'', '"', ' ', '\t', '\n', '\r']) {
        return Err(format!("{e}: 含空白/引号"));
    }
    let body = ["full:", "suffix:", "keyword:", "regex:"]
        .iter()
        .find_map(|p| e.strip_prefix(p))
        .unwrap_or(&e);
    if body.is_empty() {
        return Err(format!("{e}: 缺内容"));
    }
    Ok(e)
}

/// 规则文件内容：追加条目（去重；返回 (新文本, 新增数, 跳过数)）。
fn file_add_entries(text: &str, entries: &[String]) -> (String, usize, usize) {
    let existing: std::collections::HashSet<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let mut add = Vec::new();
    let mut skipped = 0;
    for e in entries {
        if existing.contains(e) || add.contains(e) {
            skipped += 1;
        } else {
            add.push(e.clone());
        }
    }
    if add.is_empty() {
        return (text.to_string(), 0, skipped);
    }
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&add.join("\n"));
    out.push('\n');
    (out, add.len(), skipped)
}

/// 规则文件内容：删除条目（精确匹配裸条目，忽略注释行）。
fn file_remove_entries(text: &str, entries: &[String]) -> (String, usize) {
    let want: std::collections::HashSet<&str> = entries.iter().map(|s| s.as_str()).collect();
    let mut kept = Vec::new();
    let mut removed = 0;
    for line in text.lines() {
        let bare = line.split('#').next().unwrap_or("").trim();
        if !bare.is_empty() && want.contains(bare) {
            removed += 1;
            continue;
        }
        kept.push(line.to_string());
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    (out, removed)
}

// ---------------------------------------------------------------- 路径解析

/// 相对 `rule_set` 值 → 绝对路径（仅本地文件；拒绝越级/绝对路径）。
fn local_rule_path(engine: &Engine, value: &str) -> Option<std::path::PathBuf> {
    if value.contains("://") || value.starts_with('/') || value.contains("..") {
        return None;
    }
    Some(
        engine
            .engine_config
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(value),
    )
}

fn read_text(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// 规则文件里的有效条目（去注释/空行）。
fn file_entries(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// 把待执行命令里的参数做 POSIX 单引号转义（`run_cmd` 走 `sh -c`）。
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ---------------------------------------------------------------- 处理器：订阅解析预览

#[derive(Deserialize)]
struct InspectReq {
    url: String,
    tag: Option<String>,
}

/// 只读：拉取订阅 → 解码 → 逐行解析（复用引擎 `sub-parse`）。
async fn api_inspect(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<InspectReq>,
) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let url = req.url.trim();
    if !valid_value(url) {
        return err_json(StatusCode::BAD_REQUEST, "订阅链接非法");
    }
    let tag = req.tag.unwrap_or_else(|| "sub".into());
    let engine = ctx.engine.clone();
    // 拉取由引擎自己做（与运行时同一条路径）；外层 run_cmd 还有 panel timeout 兜底。
    let inner = ctx.cfg.timeout.as_secs().saturating_sub(3).clamp(3, 60);
    let cmd = format!(
        "{} sub-parse {} --json --tag {} --limit 300 --timeout {}",
        engine.sodama,
        shq(url),
        shq(&tag),
        inner
    );
    let (code, out, err) = match run_cmd(&ctx.cfg, &cmd).await {
        Ok(v) => v,
        Err(e) => return err_json(StatusCode::BAD_GATEWAY, e),
    };
    let v: serde_json::Value = match serde_json::from_str(out.trim()) {
        Ok(v) => v,
        Err(_) => {
            let hint = if code != 0 {
                format!("解析失败（退出码 {code}）：{}", err.trim())
            } else {
                "解析输出不是 JSON（引擎二进制过旧？需要带 sub-parse 的版本）".to_string()
            };
            return err_json(StatusCode::BAD_GATEWAY, hint);
        }
    };
    let nodes: Vec<SubNode> = v["nodes"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|n| SubNode {
                    name: n["name"].as_str().unwrap_or_default().to_string(),
                    protocol: n["protocol"].as_str().unwrap_or_default().to_string(),
                    addr: n["addr"].as_str().map(str::to_string),
                    detail: n["detail"].as_str().unwrap_or_default().to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    let mut protocols: Vec<ProtoCount> = v["protocols"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, c)| ProtoCount {
                    name: k.clone(),
                    count: c.as_u64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default();
    protocols.sort_by(|a, b| b.count.cmp(&a.count));
    // 订阅头信息条目（“剩余流量/套餐到期”等）运行时会命中 group.filter，不算真实节点。
    let info_kw = [
        "剩余", "到期", "流量", "重置", "官网", "订阅", "套餐", "群组", "频道", "机场", "通知",
    ];
    let info_entries = nodes
        .iter()
        .filter(|n| info_kw.iter().any(|k| n.name.contains(k)))
        .count() as u64;
    Json(InspectView {
        ok: true,
        tag: v["tag"].as_str().unwrap_or(&tag).to_string(),
        source: redact(v["source"].as_str().unwrap_or(url)),
        bytes: v["bytes"].as_u64().unwrap_or(0),
        format: v["format"].as_str().unwrap_or_default().to_string(),
        count: v["count"].as_u64().unwrap_or(nodes.len() as u64),
        protocols,
        nodes,
        truncated: v["truncated"].as_bool().unwrap_or(false),
        errors: v["errors"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| x.as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default(),
        elapsed_ms: v["elapsed_ms"].as_u64().unwrap_or(0),
        info_entries,
    })
    .into_response()
}

// ---------------------------------------------------------------- 处理器：订阅增删改

#[derive(Deserialize)]
struct SubReq {
    tag: String,
    url: String,
}

async fn api_sub_add(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<SubReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let existed = block_kv(&text, "subscription")
        .iter()
        .any(|(t, _)| *t == req.tag);
    let new_text = match upsert_entry(&text, "subscription", req.tag.trim(), req.url.trim()) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    let msg = if existed {
        format!("已更新订阅 {} 的链接", req.tag)
    } else {
        format!("已添加订阅 {}（排在最后 = 优先级最低；可上移）", req.tag)
    };
    apply_config_text(&ctx, &engine, &new_text, msg).await
}

#[derive(Deserialize)]
struct TagReq {
    tag: String,
}

async fn api_sub_remove(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<TagReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let new_text = match remove_entry(&text, "subscription", req.tag.trim(), 1) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    apply_config_text(&ctx, &engine, &new_text, format!("已删除订阅 {}", req.tag)).await
}

#[derive(Deserialize)]
struct MoveReq {
    tag: String,
    dir: String,
}

async fn api_sub_move(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<MoveReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let up = match req.dir.as_str() {
        "up" => true,
        "down" => false,
        _ => return err_json(StatusCode::BAD_REQUEST, "dir 只能是 up/down"),
    };
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let new_text = match move_entry(&text, "subscription", req.tag.trim(), up) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    if new_text == text {
        return Json(SaveResult {
            ok: true,
            message: format!("订阅 {} 已在边界，无需移动", req.tag),
            reload_ok: None,
        })
        .into_response();
    }
    apply_config_text(
        &ctx,
        &engine,
        &new_text,
        format!("已{}移订阅 {}", if up { "上" } else { "下" }, req.tag),
    )
    .await
}

// ---------------------------------------------------------------- 处理器：订阅批量导入

#[derive(Deserialize)]
struct BulkReq {
    entries: Vec<SubReq>,
}

/// 批量导入：一个请求内多次 upsert → 只校验/落盘/热重载一次（N 个订阅不限）。
async fn api_sub_bulk(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<BulkReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    if req.entries.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "没有可添加的订阅");
    }
    if req.entries.len() > 500 {
        return err_json(StatusCode::BAD_REQUEST, "单次最多 500 条（可分次添加）");
    }
    let engine = ctx.engine.clone();
    let mut text = read_text(&engine.engine_config);
    let mut added = 0usize;
    let mut updated = 0usize;
    for e in &req.entries {
        let tag = e.tag.trim();
        let existed = block_kv(&text, "subscription")
            .iter()
            .any(|(t, _)| t == tag);
        text = match upsert_entry(&text, "subscription", tag, e.url.trim()) {
            Ok(t) => t,
            Err(err) => return err_json(StatusCode::BAD_REQUEST, format!("{tag}: {err}")),
        };
        if existed {
            updated += 1;
        } else {
            added += 1;
        }
    }
    let msg = format!(
        "已批量导入 {added} 个订阅{}",
        if updated > 0 {
            format!("，更新 {updated} 个")
        } else {
            String::new()
        }
    );
    apply_config_text(&ctx, &engine, &text, msg).await
}

// ---------------------------------------------------------------- 处理器：手动切换节点

#[derive(Deserialize)]
struct PolicyReq {
    /// `auto` | `min_moving_avg` | `min` | `min_avg10` | `random` | `fixed`
    policy: String,
    /// `policy = fixed` 时的节点名（按**名字**点名，订阅刷新重排成员不影响）
    node: Option<String>,
    /// 组名（缺省用配置里第一个组）
    group: Option<String>,
}

/// `group { <name> { policy: … } }` 里第一个子块名。
fn first_group_name(text: &str) -> Option<String> {
    let (s, e) = find_block(text, "group")?;
    let all: Vec<&str> = text.lines().collect();
    for line in all.iter().take(e).skip(s + 1) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('}') {
            continue;
        }
        if let Some((name, rest)) = t.split_once('{') {
            let name = name.trim();
            if rest.trim().is_empty() && !name.is_empty() && !name.contains(':') {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// 手动切节点 / 恢复自动：改 `group.<name>.policy`（引擎 inotify 热驱动生效）。
async fn api_group_policy(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<PolicyReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let group_name = match req
        .group
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(g) => g.to_string(),
        None => match first_group_name(&text) {
            Some(g) => g,
            None => return err_json(StatusCode::BAD_REQUEST, "配置里找不到 group 子块"),
        },
    };
    let kind = req.policy.trim();
    let (value, msg) = match kind {
        "auto" | "min_moving_avg" => (
            "min_moving_avg".to_string(),
            "已切回自动策略 min_moving_avg".to_string(),
        ),
        "min" | "min_avg10" | "random" => (kind.to_string(), format!("已切回自动策略 {kind}")),
        "fixed" => {
            let Some(node) = req.node.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
                return err_json(StatusCode::BAD_REQUEST, "锁定节点需要节点名");
            };
            if node.contains(['\'', '"', '\n', '\r']) {
                return err_json(StatusCode::BAD_REQUEST, "节点名含非法字符");
            }
            (
                format!("fixed('{node}')"),
                format!("已锁定节点 {node}（死亡自动兑底）"),
            )
        }
        other => return err_json(StatusCode::BAD_REQUEST, format!("未知策略 {other}")),
    };
    let new_text = match set_nested_param(&text, "group", &group_name, "policy", &value) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    if new_text == text {
        return Json(SaveResult {
            ok: true,
            message: format!("策略已是 {value}，无需修改"),
            reload_ok: None,
        })
        .into_response();
    }
    apply_config_text(&ctx, &engine, &new_text, msg).await
}

// ---------------------------------------------------------------- 处理器：规则集增删

#[derive(Deserialize)]
struct RuleSetReq {
    tag: String,
    url: String,
}

async fn api_ruleset_add(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<RuleSetReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let existed = block_kv(&text, "rule_set")
        .iter()
        .any(|(t, _)| *t == req.tag);
    let new_text = match upsert_entry(&text, "rule_set", req.tag.trim(), req.url.trim()) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    let msg = if existed {
        format!("已更新规则集 {}", req.tag)
    } else {
        format!(
            "已添加规则集 {}（记得在 routing 里引用，否则不生效）",
            req.tag
        )
    };
    apply_config_text(&ctx, &engine, &new_text, msg).await
}

async fn api_ruleset_remove(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<TagReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let new_text = match remove_entry(&text, "rule_set", req.tag.trim(), 0) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    apply_config_text(
        &ctx,
        &engine,
        &new_text,
        format!("已删除规则集 {}", req.tag),
    )
    .await
}

// ---------------------------------------------------------------- 处理器：本地规则文件

/// 本地规则集列表 + 条目（远程只列 tag/URL，不下载）。
async fn api_rule_files(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    // routing 里被引用的 tag（`domain(ruleset: X)`）
    let routing = routing_text(&text);
    // 引擎侧的软失败原因（tag → error）。引擎已把「单个规则集失败」降级为软失败，
    // 这里把它透出到配置页，让用户能看到到底是哪一条拉不到。
    let errs: std::collections::HashMap<String, String> =
        match crate::fetch_view(&ctx, &engine).await {
            Ok(v) => v
                .rule_sets
                .into_iter()
                .filter_map(|r| r.error.map(|e| (r.tag, e)))
                .collect(),
            Err(_) => std::collections::HashMap::new(),
        };
    let mut files = Vec::new();
    for (tag, value) in block_kv(&text, "rule_set") {
        let remote = value.contains("://");
        let referenced = routing.contains(&format!("ruleset: {tag}"))
            || routing.contains(&format!("ruleset:{tag}"));
        let (path, exists, mut entries, size) = match local_rule_path(&engine, &value) {
            Some(p) => {
                let t = std::fs::read_to_string(&p).ok();
                let e = t.as_deref().map(file_entries).unwrap_or_default();
                let size = t.as_deref().map(|s| s.len() as u64).unwrap_or(0);
                (p, t.is_some(), e, size)
            }
            None => (std::path::PathBuf::new(), false, Vec::new(), 0),
        };
        let count = entries.len() as u64;
        // 只回传尾部（面板新加的都在尾部），避免大文件搬全量
        if entries.len() > 500 {
            entries.drain(..entries.len() - 500);
        }
        files.push(DomainFileView {
            tag: tag.clone(),
            target: redact(&value),
            remote,
            referenced,
            path: path.display().to_string(),
            exists,
            count,
            entries,
            bytes: size,
            error: errs.get(&tag).cloned(),
        });
    }
    Json(DomainsView { files }).into_response()
}

/// `routing { … }` 段原文（用于判断规则集是否被引用）。
fn routing_text(text: &str) -> String {
    match find_block(text, "routing") {
        Some((s, e)) => text
            .lines()
            .skip(s)
            .take(e - s + 1)
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    }
}

#[derive(Deserialize)]
struct RuleFileReq {
    tag: String,
    /// 每行一条（也接受前端传来的数组）
    entries: Vec<String>,
}

async fn api_rule_file_add(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<RuleFileReq>,
) -> Response {
    rule_file_edit(ctx, headers, uri, req, true).await
}

async fn api_rule_file_remove(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<RuleFileReq>,
) -> Response {
    rule_file_edit(ctx, headers, uri, req, false).await
}

async fn rule_file_edit(
    ctx: Ctx,
    headers: HeaderMap,
    uri: Uri,
    req: RuleFileReq,
    add: bool,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let cfg_text = read_text(&engine.engine_config);
    let value = match block_kv(&cfg_text, "rule_set")
        .into_iter()
        .find(|(t, _)| *t == req.tag)
    {
        Some((_, v)) => v,
        None => {
            return err_json(
                StatusCode::NOT_FOUND,
                format!("配置里没有规则集 {}", req.tag),
            )
        }
    };
    let Some(path) = local_rule_path(&engine, &value) else {
        return err_json(
            StatusCode::BAD_REQUEST,
            format!("规则集 {} 是远程 URL，不能本地编辑", req.tag),
        );
    };
    if req.entries.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "条目为空");
    }
    let mut items = Vec::new();
    for raw in &req.entries {
        match norm_entry(raw) {
            Ok(e) => {
                if !items.contains(&e) {
                    items.push(e);
                }
            }
            Err(e) => return err_json(StatusCode::BAD_REQUEST, format!("非法条目 —— {e}")),
        }
    }
    if items.len() > 2000 {
        return err_json(StatusCode::BAD_REQUEST, "单次最多 2000 条");
    }
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let prev_at = current_reload_at(&ctx, &engine).await;
    let (new_text, msg) = if add {
        let (t, added, skipped) = file_add_entries(&text, &items);
        (
            t,
            format!(
                "已向 {} 添加 {added} 条{}",
                req.tag,
                if skipped > 0 {
                    format!("（跳过 {skipped} 条重复）")
                } else {
                    String::new()
                }
            ),
        )
    } else {
        let (t, removed) = file_remove_entries(&text, &items);
        (t, format!("已从 {} 删除 {removed} 条", req.tag))
    };
    if new_text == text {
        return Json(SaveResult {
            ok: true,
            message: format!("{} 无变化", req.tag),
            reload_ok: None,
        })
        .into_response();
    }
    if let Err(e) = write_preserving(&path, &new_text) {
        return err_json(StatusCode::BAD_GATEWAY, e);
    }
    // 引擎 inotify 监听规则集文件；显式 reload 一次更确定（判据仍是 reload.at_sec 推进）。
    let _ = run_cmd(&ctx.cfg, &engine.reload_cmd).await;
    let reload_ok = wait_reload(&ctx, &engine, prev_at, 20).await;
    Json(SaveResult {
        ok: true,
        message: msg,
        reload_ok,
    })
    .into_response()
}

// ---------------------------------------------------------------- 单元测试

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "global {\n}\n\nsubscription {\n    main: 'https://a.example/sub?token=x'\n    backup: 'https://b.example/sub'\n}\n\nrule_set {\n    user_proxy: 'rules/user_proxy.txt'\n    remote: 'https://c.example/cn.yaml'\n}\n";

    #[test]
    fn upsert_updates_existing() {
        let out = upsert_entry(CFG, "subscription", "backup", "https://c.example/x").unwrap();
        assert!(out.contains("    backup: 'https://c.example/x'"));
        assert!(out.contains("main: 'https://a.example/sub?token=x'"));
    }

    #[test]
    fn upsert_appends_new_in_block() {
        let out = upsert_entry(CFG, "subscription", "third", "https://d.example/s").unwrap();
        let subs: Vec<_> = block_kv(&out, "subscription");
        assert_eq!(
            subs.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            vec!["main", "backup", "third"]
        );
        // 新条目必须在 subscription 块内（rule_set 之前）
        let pos_sub = out.find("third").unwrap();
        let pos_rule = out.find("rule_set").unwrap();
        assert!(pos_sub < pos_rule);
    }

    #[test]
    fn remove_respects_min_keep() {
        assert!(remove_entry(CFG, "subscription", "main", 1).is_ok());
        // 只剩 1 条时不许再删
        let one = remove_entry(CFG, "subscription", "main", 1).unwrap();
        assert!(remove_entry(&one, "subscription", "backup", 1).is_err());
    }

    #[test]
    fn move_swaps_order() {
        let out = move_entry(CFG, "subscription", "backup", true).unwrap();
        assert_eq!(
            block_kv(&out, "subscription")
                .iter()
                .map(|(t, _)| t.as_str())
                .collect::<Vec<_>>(),
            vec!["backup", "main"]
        );
        // 边界不动
        assert_eq!(move_entry(CFG, "subscription", "main", true).unwrap(), CFG);
    }

    #[test]
    fn add_missing_block() {
        let out = upsert_entry("global {\n}\n", "subscription", "main", "https://a/s").unwrap();
        assert_eq!(block_kv(&out, "subscription").len(), 1);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(upsert_entry(CFG, "subscription", "bad tag", "https://a/s").is_err());
        assert!(upsert_entry(CFG, "subscription", "ok", "https://a/ s").is_err());
        assert!(upsert_entry(CFG, "subscription", "ok", "../../etc/passwd").is_err());
        assert!(upsert_entry(CFG, "subscription", "main", "ftp://x").is_err());
    }

    #[test]
    fn nested_policy_replace_and_insert() {
        let cfg = "group {\n    proxy {\n        policy: min_moving_avg\n        filter: !name(keyword: 'x')\n    }\n}\n";
        let out = set_nested_param(cfg, "group", "proxy", "policy", "fixed('HK-01')").unwrap();
        assert!(out.contains("policy: fixed('HK-01')"), "{out}");
        assert!(!out.contains("min_moving_avg"));
        assert!(
            out.contains("filter: !name(keyword: 'x')"),
            "其他参数不能丢"
        );
        // 子块里没有 policy 行 → 插到首行，缩进对齐
        let cfg2 = "group {\n    proxy {\n        filter: a\n    }\n}\n";
        let out2 = set_nested_param(cfg2, "group", "proxy", "policy", "min").unwrap();
        let lines: Vec<&str> = out2.lines().collect();
        assert_eq!(lines[2].trim(), "policy: min");
        assert_eq!(
            lines[2].len() - lines[2].trim_start().len(),
            8,
            "缩进同 filter"
        );
        assert!(out2.contains("filter: a"));
        // 找不到子块要报错，不能静默改坏
        assert!(set_nested_param(cfg2, "group", "nope", "policy", "min").is_err());
    }

    #[test]
    fn first_group_name_works() {
        assert_eq!(
            first_group_name("group {\n    proxy {\n        policy: min\n    }\n}\n").as_deref(),
            Some("proxy")
        );
        assert_eq!(first_group_name("global {\n}\n"), None);
    }

    #[test]
    fn rule_file_roundtrip() {
        let text = "a.com\n# 注释\nb.com\n";
        let (t, added, skipped) = file_add_entries(text, &["b.com".into(), "c.com".into()]);
        assert_eq!((added, skipped), (1, 1));
        assert!(t.contains("c.com"));
        let (t2, removed) = file_remove_entries(&t, &["a.com".into(), "zz.com".into()]);
        assert_eq!(removed, 1);
        assert!(!t2.contains("a.com") && t2.contains("b.com") && t2.contains("# 注释"));
    }

    #[test]
    fn norm_entries() {
        assert_eq!(norm_entry("  Example.COM ").unwrap(), "Example.COM");
        assert_eq!(norm_entry("https://a.com/path").unwrap(), "a.com");
        assert_eq!(norm_entry("full:a.com").unwrap(), "full:a.com");
        assert!(norm_entry("a b").is_err());
        assert!(norm_entry("").is_err());
    }
}

// ---------------------------------------------------------------- 内核参数（可视化）

/// 段内编辑范围（行号含起止）：`group` 取**第一个组的内层块**，其余取段块本身。
fn param_scope(text: &str, section: &str) -> Option<(usize, usize)> {
    let (s, e) = find_block(text, section)?;
    if section != "group" || s == e {
        return Some((s, e));
    }
    let name = first_group_name(text)?;
    let all: Vec<&str> = text.lines().collect();
    for (i, line) in all.iter().enumerate().take(e + 1).skip(s + 1) {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix(name.as_str()) {
            if rest.trim_start().starts_with('{') {
                return Some((i, e));
            }
        }
    }
    None
}

/// 读段内 `key: value`（只回显显式写了的键；值去掉引号/行尾注释）。
fn read_param(text: &str, section: &str, key: &str) -> Option<String> {
    let (s, e) = param_scope(text, section)?;
    let all: Vec<&str> = text.lines().collect();
    for line in all.iter().take(e).skip(s + 1) {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix(key) {
            if rest.trim_start().starts_with(':') {
                let v = rest.trim_start()[1..]
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches(['\'', '"'])
                    .trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// 写/删段内 `key: value`（`value = None` → 删行 = 回到引擎默认；键不存在则插到段首）。
fn edit_param(text: &str, section: &str, key: &str, value: Option<&str>) -> Result<String, String> {
    let (s, e) = param_scope(text, section).ok_or(format!("配置里找不到 {section} 段"))?;
    let all: Vec<&str> = text.lines().collect();
    let indent_of = |l: &str| l[..l.len() - l.trim_start().len()].to_string();
    let mut found: Option<usize> = None;
    for (i, line) in all.iter().enumerate().take(e).skip(s + 1) {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix(key) {
            if rest.trim_start().starts_with(':') {
                found = Some(i);
                break;
            }
        }
    }
    let tail_nl = text.ends_with('\n');
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    match (found, value) {
        (Some(i), Some(v)) => lines[i] = format!("{}{key}: {v}", indent_of(all[i])),
        (Some(i), None) => {
            lines.remove(i);
        }
        (None, Some(v)) => {
            let child = all[s + 1..e]
                .iter()
                .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .map(|l| indent_of(l))
                .unwrap_or_else(|| format!("{}    ", indent_of(all[s])));
            lines.insert(s + 1, format!("{child}{key}: {v}"));
        }
        (None, None) => {} // 删不存在的键 = no-op
    }
    let mut out = lines.join("\n");
    if tail_nl {
        out.push('\n');
    }
    Ok(out)
}

/// 值的书写形式：数字/布尔/时长裸写，含特殊字符的（URL、路径）加引号。
/// 注意：`Expr`（如节点 filter）一律**原样裸写**——里面引号是语法的一部分。
fn param_literal(kind: ParamKind, v: &str) -> String {
    let t = v.trim();
    if kind == ParamKind::Expr {
        return t.to_string();
    }
    let bare = t.parse::<f64>().is_ok()
        || matches!(t, "true" | "false")
        || (t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | ':'))
            && !t.contains("://"));
    if bare {
        t.to_string()
    } else {
        format!("'{t}'")
    }
}

/// 轻量类型校验（最终仍由引擎 `validate` 兜底）；返回规范化后的值。
fn norm_param_value(spec: &shared::ParamSpec, raw: &str) -> Result<String, String> {
    let v = raw.trim();
    if v.is_empty() {
        return Ok(String::new()); // 空 = 恢复默认
    }
    if v.contains(['\n', '\r', '{', '}']) {
        return Err("值里不能有换行/花括号".into());
    }
    if spec.kind != ParamKind::Expr && v.contains(['\'', '"']) {
        return Err("值里不能有引号".into());
    }
    match spec.kind {
        ParamKind::Bool => {
            let lv = v.to_ascii_lowercase();
            match lv.as_str() {
                "true" | "on" | "1" | "yes" => Ok("true".into()),
                "false" | "off" | "0" | "no" => Ok("false".into()),
                _ => Err(format!("{} 需要 true/false", spec.label)),
            }
        }
        ParamKind::Int => v
            .parse::<i64>()
            .map(|n| n.to_string())
            .map_err(|_| format!("{} 需要整数", spec.label)),
        ParamKind::Duration => {
            // 接受 300 / 300s / 5min / 2h（引擎同样两种都认）
            let digits = v.trim_end_matches(|c: char| c.is_ascii_alphabetic());
            let unit = &v[digits.len()..];
            if digits.is_empty() || digits.parse::<u64>().is_err() {
                return Err(format!("{} 需要秒数（如 300 或 5min）", spec.label));
            }
            if matches!(unit, "" | "s" | "ms" | "min" | "m" | "h") {
                Ok(v.to_string())
            } else {
                Err(format!("{} 的单位只支持 s/ms/min/h", spec.label))
            }
        }
        ParamKind::Enum => {
            if spec.options.contains(&v) {
                Ok(v.to_string())
            } else {
                Err(format!(
                    "{} 只接受：{}",
                    spec.label,
                    spec.options[1..].join(" / ")
                ))
            }
        }
        ParamKind::Str => Ok(v.to_string()),
        // 表达式：只拒绝换行/花括号（已在上方统一校验），原样返回
        ParamKind::Expr => Ok(v.to_string()),
    }
}

/// 读参数当前值（只回显配置文件里显式写了的键）。
async fn api_params(State(ctx): State<Ctx>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(r) = auth(&ctx, &headers, &uri) {
        return r;
    }
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let mut values = std::collections::BTreeMap::new();
    for p in PARAMS {
        if let Some(v) = read_param(&text, p.section, p.key) {
            values.insert(format!("{}.{}", p.section, p.key), v);
        }
    }
    Json(ParamsView { values }).into_response()
}

/// 写参数：空值 = 从配置移除（回到引擎默认）。走统一「validate → 落盘 → 等热重载回执」。
async fn api_param_set(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<ParamSetReq>,
) -> Response {
    if let Err(r) = require_actions(&ctx, &headers, &uri) {
        return r;
    }
    let Some(spec) = PARAMS
        .iter()
        .find(|p| p.section == req.section && p.key == req.key)
    else {
        return err_json(
            StatusCode::BAD_REQUEST,
            format!("未知参数 {}.{}", req.section, req.key),
        );
    };
    let value = match norm_param_value(spec, &req.value) {
        Ok(v) => v,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    let engine = ctx.engine.clone();
    let text = read_text(&engine.engine_config);
    let literal = if value.is_empty() {
        None
    } else {
        Some(param_literal(spec.kind, &value))
    };
    let new_text = match edit_param(&text, spec.section, spec.key, literal.as_deref()) {
        Ok(t) => t,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    let msg = if value.is_empty() {
        format!("{} 已恢复引擎默认", spec.label)
    } else {
        format!("{} = {}", spec.label, value)
    };
    apply_config_text(&ctx, &engine, &new_text, msg).await
}

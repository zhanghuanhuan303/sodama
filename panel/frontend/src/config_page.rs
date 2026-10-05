//! 配置页：结构化改配置（订阅导入 + 解析预览、规则集、本地分流规则文件）。
//!
//! 前提：`config.dae` 是唯一事实来源，引擎 inotify 热驱动 ——
//! 面板这边只做「改文本 → validate 护栏 → 落盘 → 等 reload 回执」。

use leptos::prelude::*;
use shared::{
    DomainFileView, DomainsView, InspectView, ParamKind, ParamsView, SaveResult, SourcesView,
};

use crate::{fmt_bytes, get_json, post_json};

/// 前端侧 URL 脱敏（只回避 token 值，用于批量预览列表）。
fn redact_hint(url: &str) -> String {
    match url.split_once("token=") {
        Some((head, rest)) => {
            let tail = rest.find('&').map(|i| &rest[i..]).unwrap_or("");
            format!("{head}token=REDACTED{tail}")
        }
        None => url.to_string(),
    }
}

/// 拉取配置页数据（订阅源列表 + 规则集/规则文件）。
fn refresh_cfg(
    token: RwSignal<Option<String>>,
    sources: RwSignal<Option<SourcesView>>,
    rules: RwSignal<Option<DomainsView>>,
) {
    let tok = token.get_untracked();
    leptos::task::spawn_local(async move {
        if let Ok(s) = get_json::<SourcesView>("/api/v1/sources", tok.as_deref()).await {
            sources.set(Some(s));
        }
        if let Ok(r) = get_json::<DomainsView>("/api/v1/config/rule-files", tok.as_deref()).await {
            rules.set(Some(r));
        }
    });
}

/// 写配置动作的统一入口：POST → 提示 → 刷新数据。
#[allow(clippy::too_many_arguments)]
fn run_action(
    path: &'static str,
    body: serde_json::Value,
    token: RwSignal<Option<String>>,
    msg: RwSignal<Option<(bool, String)>>,
    busy: RwSignal<bool>,
    sources: RwSignal<Option<SourcesView>>,
    rules: RwSignal<Option<DomainsView>>,
) {
    let tok = token.get_untracked();
    busy.set(true);
    msg.set(Some((true, "正在写入配置…".into())));
    leptos::task::spawn_local(async move {
        let r = post_json::<_, SaveResult>(path, &body, tok.as_deref()).await;
        busy.set(false);
        msg.set(Some(match r {
            Ok(v) => {
                let tail = match v.reload_ok {
                    Some(true) => " · 热重载 ✓",
                    Some(false) => " · 热重载未确认",
                    None => "",
                };
                (v.ok, format!("{}{tail}", v.message))
            }
            Err(e) => (false, e),
        }));
        refresh_cfg(token, sources, rules);
    });
}

/// 内核参数区块：把引擎可设置的能力（`global`/`dns`/`group` 白名单）做成表单。
/// 口径同订阅/规则集：改文本 → validate 护栏 → 落盘 → 等热重载回执；空值 = 回引擎默认。
#[component]
fn ParamsSection(
    token: RwSignal<Option<String>>,
    msg: RwSignal<Option<(bool, String)>>,
    busy: RwSignal<bool>,
) -> impl IntoView {
    let values = RwSignal::new(std::collections::BTreeMap::<String, String>::new());

    let reload = move || {
        let tok = token.get_untracked();
        leptos::task::spawn_local(async move {
            if let Ok(v) = get_json::<ParamsView>("/api/v1/config/params", tok.as_deref()).await {
                values.set(v.values);
            }
        });
    };
    reload();

    let save = move |section: &'static str, key: &'static str, value: String| {
        let tok = token.get_untracked();
        busy.set(true);
        msg.set(Some((true, "正在写入配置…".into())));
        leptos::task::spawn_local(async move {
            let body = serde_json::json!({ "section": section, "key": key, "value": value });
            let r =
                post_json::<_, SaveResult>("/api/v1/config/params", &body, tok.as_deref()).await;
            busy.set(false);
            msg.set(Some(match r {
                Ok(v) => {
                    let tail = match v.reload_ok {
                        Some(true) => " · 热重载 ✓",
                        Some(false) => " · 热重载未确认",
                        None => "",
                    };
                    (v.ok, format!("{}{tail}", v.message))
                }
                Err(e) => (false, e),
            }));
            if let Ok(v) = get_json::<ParamsView>("/api/v1/config/params", tok.as_deref()).await {
                values.set(v.values);
            }
        });
    };

    view! {
        <section class="panel">
            <div class="panel-head">
                <span class="panel-title">"内核参数"</span>
                <span class="panel-meta">"写回 config.dae → 校验 → 热重载（无需重启）；未设置 = 引擎默认"</span>
                {move || {
                    let n = values.get().len();
                    (n > 0).then(|| view! { <span class="chip chip-use">{format!("已改 {n} 项")}</span> })
                }}
            </div>
            <div class="params">
                {move || {
                    let cur = values.get();
                    let mut out: Vec<AnyView> = Vec::new();
                    let mut last = "";
                    for p in shared::PARAMS {
                        if p.group != last {
                            last = p.group;
                            out.push(view! { <div class="param-group">{p.group}</div> }.into_any());
                        }
                        let now = cur.get(&format!("{}.{}", p.section, p.key)).cloned();
                        out.push(param_row(p, now, busy, save).into_any());
                    }
                    out
                }}
            </div>
        </section>
    }
}

/// 单行参数：标签/说明（左）+ 控件（右）+ 恢复默认；已改的项用强调色标出。
fn param_row(
    p: &'static shared::ParamSpec,
    now: Option<String>,
    busy: RwSignal<bool>,
    save: impl Fn(&'static str, &'static str, String) + Copy + 'static,
) -> impl IntoView {
    let is_set = now.is_some();
    let val = now.unwrap_or_default();
    let section = p.section;
    let key = p.key;
    let label = p.label;
    let help = p.help;
    let unit = p.unit;
    let def = p.default;
    let kind = p.kind;
    let opts = p.options;
    let v2 = val.clone();
    let ctl = match kind {
        ParamKind::Bool => view! {
            <select class="inp sel sel-mini" prop:value=v2.clone()
                on:change=move |ev| save(section, key, event_target_value(&ev))>
                <option value="">"引擎默认"</option>
                <option value="true">"开"</option>
                <option value="false">"关"</option>
            </select>
        }
        .into_any(),
        ParamKind::Enum => view! {
            <select class="inp sel sel-mini" prop:value=v2.clone()
                on:change=move |ev| save(section, key, event_target_value(&ev))>
                {opts
                    .iter()
                    .map(|o| {
                        view! {
                            <option value=*o>
                                {if o.is_empty() { "引擎默认".to_string() } else { (*o).to_string() }}
                            </option>
                        }
                    })
                    .collect_view()}
            </select>
        }
        .into_any(),
        _ => {
            let cls = if kind == ParamKind::Expr {
                "inp param-inp param-inp-expr"
            } else {
                "inp param-inp"
            };
            view! {
                <input class=cls prop:value=v2.clone()
                    on:change=move |ev| save(section, key, event_target_value(&ev)) />
            }
            .into_any()
        }
    };
    view! {
        <div class=if is_set { "param-row param-on" } else { "param-row" }>
            <div class="param-main">
                <div class="param-label">
                    {label}
                    {(!def.is_empty())
                        .then(|| view! { <span class="param-def">{format!("默认 {def}")}</span> })}</div>
                <div class="param-help">{help}</div>
            </div>
            <div class="param-ctl">
                {ctl}
                {(!unit.is_empty()).then(|| view! { <span class="param-unit dim">{unit}</span> })}
                {is_set
                    .then(|| {
                        view! {
                            <button class="btn btn-mini" disabled=move || busy.get()
                                on:click=move |_| save(section, key, String::new())>"恢复默认"</button>
                        }
                    })}
            </div>
        </div>
    }
}

#[component]
pub fn ConfigPage(token: RwSignal<Option<String>>) -> impl IntoView {
    // 配置页自带状态条（不污染总览顶部 banner）
    let msg = RwSignal::new(Option::<(bool, String)>::None);
    let sources = RwSignal::new(Option::<SourcesView>::None);
    let rules = RwSignal::new(Option::<DomainsView>::None);
    let busy = RwSignal::new(false);
    let inspect = RwSignal::new(Option::<InspectView>::None);
    let inspecting = RwSignal::new(false);
    let new_tag = RwSignal::new(String::new());
    let new_url = RwSignal::new(String::new());
    let rs_tag = RwSignal::new(String::new());
    let rs_url = RwSignal::new(String::new());
    let open_tag = RwSignal::new(String::new());
    let add_text = RwSignal::new(String::new());
    let filter = RwSignal::new(String::new());
    let bulk_text = RwSignal::new(String::new());
    let bulk_busy = RwSignal::new(false);
    let bulk_results = RwSignal::new(Vec::<(String, String, Result<InspectView, String>)>::new());

    refresh_cfg(token, sources, rules);

    // 深链：#config,open=<tag> 直接展开某个规则文件
    leptos::task::spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(500).await;
        let hash = leptos::web_sys::window()
            .and_then(|w| w.location().hash().ok())
            .unwrap_or_default();
        if let Some(rest) = hash.split("open=").nth(1) {
            let tag = crate::percent_decode(rest.split(',').next().unwrap_or(rest));
            if !tag.is_empty() {
                open_tag.set(tag);
            }
        }
    });

    // ---- 订阅：解析预览 ----
    let do_inspect = move |_| {
        let url = new_url.get_untracked().trim().to_string();
        let tag = new_tag.get_untracked().trim().to_string();
        if url.is_empty() {
            msg.set(Some((false, "先填订阅链接".into())));
            return;
        }
        let tok = token.get_untracked();
        inspecting.set(true);
        inspect.set(None);
        msg.set(Some((true, "正在拉取并解析订阅…（可能要几秒）".into())));
        leptos::task::spawn_local(async move {
            let body = serde_json::json!({
                "url": url,
                "tag": if tag.is_empty() { "sub".to_string() } else { tag },
            });
            match post_json::<_, InspectView>("/api/v1/config/inspect", &body, tok.as_deref()).await
            {
                Ok(v) => {
                    msg.set(Some((
                        true,
                        format!(
                            "解析完成：{} 个节点 · {} · {} ms",
                            v.count, v.format, v.elapsed_ms
                        ),
                    )));
                    inspect.set(Some(v));
                }
                Err(e) => msg.set(Some((false, format!("解析失败：{e}")))),
            }
            inspecting.set(false);
        });
    };

    // ---- 订阅：添加并生效 ----
    let do_add_sub = move |_| {
        let url = new_url.get_untracked().trim().to_string();
        let tag = new_tag.get_untracked().trim().to_string();
        if url.is_empty() || tag.is_empty() {
            msg.set(Some((false, "名称与链接都要填".into())));
            return;
        }
        run_action(
            "/api/v1/config/subs",
            serde_json::json!({ "tag": tag, "url": url }),
            token,
            msg,
            busy,
            sources,
            rules,
        );
        new_tag.set(String::new());
        new_url.set(String::new());
        inspect.set(None);
    };

    let rule_file_of = move |tag: &str| -> Option<DomainFileView> {
        rules
            .get()
            .and_then(|r| r.files.into_iter().find(|f| f.tag == tag))
    };

    // ---- 批量导入：每行 `tag url` 或只有 `url`（自动起名 sub1..subN）----
    let parse_lines = move |text: &str| -> Vec<(String, String)> {
        text.lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    return None;
                }
                if l.starts_with("http://") || l.starts_with("https://") {
                    return Some((String::new(), l.to_string()));
                }
                let mut it = l.split_whitespace();
                let tag = it.next().unwrap_or("").to_string();
                let url = it.next().unwrap_or("").to_string();
                (!url.is_empty()).then_some((tag, url))
            })
            .collect()
    };
    // 未指定 tag 的行：在已有 tag 之外依次取 sub2/sub3/…
    let with_auto_tags = move |items: Vec<(String, String)>| -> Vec<(String, String)> {
        let mut used: Vec<String> = sources
            .get_untracked()
            .map(|s| s.sources.into_iter().map(|x| x.tag).collect())
            .unwrap_or_default();
        let mut n = 2;
        items
            .into_iter()
            .map(|(tag, url)| {
                if !tag.is_empty() {
                    used.push(tag.clone());
                    (tag, url)
                } else {
                    while used.iter().any(|t| *t == format!("sub{n}")) {
                        n += 1;
                    }
                    let t = format!("sub{n}");
                    used.push(t.clone());
                    n += 1;
                    (t, url)
                }
            })
            .collect()
    };

    let do_bulk_preview = move |_| {
        let items = with_auto_tags(parse_lines(&bulk_text.get_untracked()));
        if items.is_empty() {
            msg.set(Some((false, "每行一个订阅链接（可写 `tag url`）".into())));
            return;
        }
        if items.len() > 12 {
            msg.set(Some((
                false,
                format!("预览一次最多 12 条（当前 {}），可分批", items.len()),
            )));
            return;
        }
        let tok = token.get_untracked();
        bulk_busy.set(true);
        bulk_results.set(Vec::new());
        msg.set(Some((
            true,
            format!("正在逐个解析 {} 个订阅…", items.len()),
        )));
        leptos::task::spawn_local(async move {
            for (tag, url) in items {
                let body = serde_json::json!({ "url": url, "tag": tag });
                let r =
                    post_json::<_, InspectView>("/api/v1/config/inspect", &body, tok.as_deref())
                        .await;
                let mut cur = bulk_results.get_untracked();
                cur.push((tag, url, r));
                bulk_results.set(cur);
            }
            bulk_busy.set(false);
            let ok = bulk_results
                .get_untracked()
                .iter()
                .filter(|(_, _, r)| r.is_ok())
                .count();
            msg.set(Some((true, format!("解析完成：{ok} 成功"))));
        });
    };

    let do_bulk_add = move |_| {
        let items = with_auto_tags(parse_lines(&bulk_text.get_untracked()));
        if items.is_empty() {
            msg.set(Some((false, "没有可导入的行".into())));
            return;
        }
        let entries: Vec<serde_json::Value> = items
            .iter()
            .map(|(t, u)| serde_json::json!({"tag": t, "url": u}))
            .collect();
        run_action(
            "/api/v1/config/subs/bulk",
            serde_json::json!({ "entries": entries }),
            token,
            msg,
            busy,
            sources,
            rules,
        );
        bulk_text.set(String::new());
        bulk_results.set(Vec::new());
    };

    view! {
        <main class="wrap">
            {move || msg.get().map(|(ok, m)| view! {
                <div class=if ok { "banner banner-ok" } else { "banner" }>
                    <span class=if ok { "banner-msg" } else { "banner-err" }>{m}</span>
                    <button class="btn" on:click=move |_| msg.set(None)>"关闭"</button>
                </div>
            })}
            <section class="panel">
                <div class="panel-head">
                    <span class="panel-title">"订阅源 · 声明顺序 = 优先级（首个有活节点的生效）"</span>
                    <span class="panel-meta">"导入前可先「解析预览」，确认节点与协议再落盘"</span>
                </div>
                <div class="tbl-wrap">
                <table class="tbl">
                    <thead>
                        <tr>
                            <th class="num">"#"</th><th>"tag"</th><th>"URL"</th>
                            <th class="num">"节点"</th><th>"状态"</th><th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each=move || sources.get().map(|s| s.sources).unwrap_or_default()
                             key=|s| s.tag.clone()
                             children=move |s| {
                                let tag = s.tag.clone();
                                let t1 = tag.clone();
                                let t2 = tag.clone();
                                let t3 = tag.clone();
                                let active = s.active;
                                view! {
                                    <tr class="row">
                                        <td class="mono num dim">{s.order.to_string()}</td>
                                        <td class="mono">{tag.clone()}</td>
                                        <td class="mono dim url-cell">{s.url.clone()}</td>
                                        <td class="mono num">{format!("{} / {}", s.alive, s.nodes)}</td>
                                        <td>{if active {
                                            view! { <span class="tag-on">"当前"</span> }.into_any()
                                        } else {
                                            view! { <span class="dim">"—"</span> }.into_any()
                                        }}</td>
                                        <td class="act-cell">
                                            <button class="btn btn-mini" disabled=move || busy.get()
                                                on:click=move |_| run_action("/api/v1/config/subs/move",
                                                    serde_json::json!({"tag": t1.clone(), "dir": "up"}),
                                                    token, msg, busy, sources, rules)>"↑"</button>
                                            <button class="btn btn-mini" disabled=move || busy.get()
                                                on:click=move |_| run_action("/api/v1/config/subs/move",
                                                    serde_json::json!({"tag": t2.clone(), "dir": "down"}),
                                                    token, msg, busy, sources, rules)>"↓"</button>
                                            <button class="btn btn-mini btn-danger" disabled=move || busy.get()
                                                on:click=move |_| run_action("/api/v1/config/subs/remove",
                                                    serde_json::json!({"tag": t3.clone()}),
                                                    token, msg, busy, sources, rules)>"删除"</button>
                                        </td>
                                    </tr>
                                }
                             }/>
                    </tbody>
                </table>
                </div>

                <div class="cfg-form pad">
                    <span class="panel-title">"导入新订阅"</span>
                    <input class="inp" style="width:9rem" placeholder="名称（如 sub2）" prop:value=move || new_tag.get()
                        on:input=move |ev| new_tag.set(event_target_value(&ev))/>
                    <input class="inp grow" placeholder="订阅链接（http/https）" prop:value=move || new_url.get()
                        on:input=move |ev| new_url.set(event_target_value(&ev))/>
                    <button class="btn" disabled=move || inspecting.get() on:click=do_inspect>
                        {move || if inspecting.get() { "解析中…" } else { "解析预览" }}
                    </button>
                    <button class="btn btn-primary" disabled=move || busy.get() || inspect.get().is_none()
                        on:click=do_add_sub>"添加并生效"</button>
                </div>

                {move || inspect.get().map(|v| {
                    let summary = format!(
                        "{} 个节点 · {} · {} · {:.1}s",
                        v.count, v.format, fmt_bytes(v.bytes), v.elapsed_ms as f64 / 1000.0
                    );
                    view! {
                        <div class="inspect-card">
                            <div class="panel-head">
                                <span class="panel-title">
                                    {format!("解析结果：{}", v.source)}
                                </span>
                                <span class="panel-meta">{summary}</span>
                            </div>
                            <div class="proto-chips">
                                {v.protocols.into_iter().map(|p| view! {
                                    <span class="chip">{format!("{} ×{}", p.name, p.count)}</span>
                                }).collect_view()}
                                {(v.info_entries > 0).then(|| view! {
                                    <span class="chip chip-warn">
                                        {format!("疑似头信息 {} 条（运行时被 group.filter 排除）", v.info_entries)}
                                    </span>
                                })}
                                {v.truncated.then(|| view! { <span class="chip chip-dim">"仅显示前 300 条"</span> })}
                            </div>
                            {(!v.errors.is_empty()).then(|| view! {
                                <pre class="mono small err-box">{v.errors.join("\n")}</pre>
                            })}
                            <div class="node-list">
                                {v.nodes.into_iter().map(|n| view! {
                                    <div class="node-row">
                                        <span class="mono dim">{n.protocol}</span>
                                        <span class="mono grow">{n.name}</span>
                                        <span class="mono dim">{n.addr.unwrap_or_default()}</span>
                                    </div>
                                }).collect_view()}
                            </div>
                        </div>
                    }
                })}

                <div class="cfg-form pad">
                    <span class="panel-title">"批量导入（每行一个，`tag url` 或只写 url）"</span>
                    <span class="panel-meta">"N 个不限 · 只校验/落盘/热重载一次"</span>
                </div>
                <div class="cfg-row pad">
                    <textarea class="ta-mini grow" spellcheck="false" rows="5"
                        placeholder="https://a.example/sub?token=xxx\nsub3 https://b.example/sub?token=yyy\n# 以 # 开头的行忽略"
                        prop:value=move || bulk_text.get()
                        on:input=move |ev| bulk_text.set(event_target_value(&ev))></textarea>
                    <div class="bulk-actions">
                        <button class="btn" disabled=move || bulk_busy.get() || busy.get() on:click=do_bulk_preview>
                            {move || if bulk_busy.get() { "解析中…" } else { "解析全部" }}
                        </button>
                        <button class="btn btn-primary" disabled=move || busy.get() || bulk_busy.get()
                            on:click=do_bulk_add>"全部导入并生效"</button>
                    </div>
                </div>
                {move || {
                    let rs = bulk_results.get();
                    (!rs.is_empty()).then(|| view! {
                        <div class="entry-list">
                            {rs.into_iter().map(|(tag, url, r)| {
                                let (cls, text) = match &r {
                                    Ok(v) => (
                                        "chip",
                                        format!("{} · {} 节点 · {}", tag, v.count, v.format),
                                    ),
                                    Err(_) => ("chip chip-warn", format!("{tag} · 解析失败")),
                                };
                                let detail = match &r {
                                    Ok(v) => {
                                        let ps: Vec<String> = v.protocols.iter()
                                            .map(|p| format!("{} ×{}", p.name, p.count)).collect();
                                        ps.join("　")
                                    }
                                    Err(e) => e.clone(),
                                };
                                view! {
                                    <div class="entry-row">
                                        <span class=cls>{text}</span>
                                        <span class="mono grow dim url-cell">{redact_hint(&url)}</span>
                                        <span class="mono dim">{detail}</span>
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                    })
                }}
            </section>

            <ParamsSection token=token msg=msg busy=busy />

            <section class="panel">
                <div class="panel-head">
                    <span class="panel-title">"规则集（routing 里 `domain(ruleset: tag)` 引用才生效）"</span>
                    <span class="panel-meta">"本地文件可直接改条目；远程由引擎按间隔刷新"</span>
                </div>
                <div class="tbl-wrap">
                <table class="tbl">
                    <thead>
                        <tr>
                            <th>"tag"</th><th>"目标"</th><th>"类型"</th><th class="num">"条数"</th>
                            <th>"引用"</th><th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each=move || rules.get().map(|r| r.files).unwrap_or_default()
                             key=|f| f.tag.clone()
                             children=move |f| {
                                let tag = f.tag.clone();
                                let t1 = tag.clone();
                                let is_open = move || open_tag.get() == t1;
                                view! {
                                    <tr class="row">
                                        <td class="mono">{tag.clone()}</td>
                                        <td class="mono dim url-cell">{f.target.clone()}</td>
                                        <td class="mono dim">{if f.remote { "远程" } else if f.exists { "本地" } else { "缺失" }}</td>
                                        <td class="mono num">{f.count.to_string()}</td>
                                        <td>{if f.referenced {
                                            view! { <span class="tag-on">"✓"</span> }.into_any()
                                        } else {
                                            view! { <span class="chip chip-warn">"未被引用"</span> }.into_any()
                                        }}</td>
                                        <td class="act-cell">
                                            {(!f.remote).then(|| {
                                                let t = tag.clone();
                                                view! {
                                                    <button class="btn btn-mini"
                                                        on:click=move |_| open_tag.update(|o| *o = if *o == t { String::new() } else { t.clone() })>
                                                        {move || if is_open() { "收起" } else { "条目" }}
                                                    </button>
                                                }
                                            })}
                                            <button class="btn btn-mini btn-danger" disabled=move || busy.get()
                                                on:click=move |_| run_action("/api/v1/config/rulesets/remove",
                                                    serde_json::json!({"tag": tag.clone()}),
                                                    token, msg, busy, sources, rules)>"删除"</button>
                                        </td>
                                    </tr>
                                }
                             }/>
                    </tbody>
                </table>
                </div>
                <div class="cfg-form pad">
                    <span class="panel-title">"添加规则集"</span>
                    <input class="inp" style="width:9rem" placeholder="tag（如 cn_site）" prop:value=move || rs_tag.get()
                        on:input=move |ev| rs_tag.set(event_target_value(&ev))/>
                    <input class="inp grow" placeholder="远程 URL 或相对路径（rules/xxx.txt）" prop:value=move || rs_url.get()
                        on:input=move |ev| rs_url.set(event_target_value(&ev))/>
                    <button class="btn" disabled=move || busy.get()
                        on:click=move |_| {
                            let tag = rs_tag.get_untracked().trim().to_string();
                            let url = rs_url.get_untracked().trim().to_string();
                            if tag.is_empty() || url.is_empty() {
                                msg.set(Some((false, "tag 与目标都要填".into())));
                                return;
                            }
                            run_action("/api/v1/config/rulesets",
                                serde_json::json!({"tag": tag, "url": url}),
                                token, msg, busy, sources, rules);
                            rs_tag.set(String::new());
                            rs_url.set(String::new());
                        }>"添加"</button>
                </div>

                {move || {
                    let tag = open_tag.get();
                    if tag.is_empty() { return None; }
                    rule_file_of(&tag).map(|f| {
                        let t_add = f.tag.clone();
                        let t_del = f.tag.clone();
                        let file_tag = f.tag.clone();
                        let entries = f.entries.clone();
                        view! {
                            <div class="inspect-card">
                                <div class="panel-head">
                                    <span class="panel-title">{format!("{} · {}", f.tag, f.path)}</span>
                                    <span class="panel-meta">{format!("{} 条 · {}", f.count, fmt_bytes(f.bytes))}</span>
                                </div>
                                <div class="cfg-form pad">
                                    <textarea class="ta-mini grow" spellcheck="false"
                                        placeholder="每行一条：a.com / full:a.com / keyword:xx / regex:^ad\\. / 也可直接粘域名"
                                        prop:value=move || add_text.get()
                                        on:input=move |ev| add_text.set(event_target_value(&ev))></textarea>
                                    <button class="btn btn-primary" disabled=move || busy.get()
                                        on:click=move |_| {
                                            let list: Vec<String> = add_text.get_untracked()
                                                .lines().map(|l| l.trim().to_string())
                                                .filter(|l| !l.is_empty()).collect();
                                            if list.is_empty() {
                                                msg.set(Some((false, "先填条目（每行一条）".into())));
                                                return;
                                            }
                                            run_action("/api/v1/config/rule-files/add",
                                                serde_json::json!({"tag": t_add.clone(), "entries": list}),
                                                token, msg, busy, sources, rules);
                                            add_text.set(String::new());
                                        }>"追加并生效"</button>
                                </div>
                                <div class="cfg-form pad">
                                    <input class="inp grow" placeholder="过滤条目（子串匹配）"
                                        prop:value=move || filter.get()
                                        on:input=move |ev| filter.set(event_target_value(&ev))/>
                                </div>
                                <div class="entry-list">
                                    {move || {
                                        let q = filter.get().to_lowercase();
                                        let tag = file_tag.clone();
                                        entries.iter()
                                            .filter(|e| q.is_empty() || e.to_lowercase().contains(&q))
                                            .map(|e| {
                                                let entry = e.clone();
                                                let t = tag.clone();
                                                let e2 = e.clone();
                                                view! {
                                                    <div class="entry-row">
                                                        <span class="mono grow">{entry}</span>
                                                        <button class="btn btn-mini btn-danger" disabled=move || busy.get()
                                                            on:click=move |_| {
                                                                let t = t.clone();
                                                                let e = e2.clone();
                                                                run_action("/api/v1/config/rule-files/remove",
                                                                    serde_json::json!({"tag": t, "entries": [e]}),
                                                                    token, msg, busy, sources, rules);
                                                            }>"×"</button>
                                                    </div>
                                                }
                                            }).collect_view()
                                    }}
                                </div>
                                <div class="panel-meta pad">
                                    {format!("提示：条目写在 {}，删改后引擎按 inotify 自动热重载", t_del)}
                                </div>
                            </div>
                        }
                    })
                }}
            </section>
        </main>
    }
}

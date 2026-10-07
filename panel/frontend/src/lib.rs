//! sodama 控制面板前端（Leptos CSR → WASM）。
//!
//! 视觉基调：Tufte 式极简 —— 无卡片框、无线可省则省（只剩节分隔/表头/表尾三种用途）、
//! 排版承担层级（小字大写标签 + 大号等宽数字 tabular-nums）、强调色只编码数据、
//! 曲线即 sparkline、行内动作悬停才现。
//!
//! M0 只读总览 · M1 曲线/CSV/订阅源 · M2 控制/会话登录 · M3 配置在线编辑 · 节点详情

mod charts;
mod config_page;
mod editor;
mod node;
mod runtime;

use config_page::ConfigPage;
use editor::{open_editor, EditorModal, EditorState};
use gloo_net::http::Request;
use gloo_storage::{LocalStorage, Storage};
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use node::{load_node, NodeModal};
use runtime::{AiTrafficCard, MetricsTable, RuntimeCard, TrendRow};
use shared::{ActionResult, LogsView, NodeDetail, SeriesView, StatusView};
use wasm_bindgen::prelude::*;

const REFRESH_MS: u32 = 2000;

/// 顶部两个页面：总览（只读仪表盘）/ 配置（结构化改配置）。
#[derive(Clone, Copy, PartialEq)]
enum Page {
    Overview,
    Config,
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}

// ---------------------------------------------------------------- 数据层

fn load_token() -> Option<String> {
    LocalStorage::get::<String>("panel_token")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn save_token(t: &str) {
    let t = t.trim();
    if t.is_empty() {
        let _ = LocalStorage::delete("panel_token");
    } else {
        let _ = LocalStorage::set("panel_token", t.to_string());
    }
}

fn err_from(code: u16, text: &str) -> String {
    if code == 401 {
        return "需要登录（输入访问 token）".into();
    }
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {code}"))
}

pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
    path: &str,
    token: Option<&str>,
) -> Result<T, String> {
    let mut req = Request::get(path);
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
    let code = resp.status();
    let text = resp.text().await.map_err(|e| format!("读取失败: {e}"))?;
    if !(200..300).contains(&code) {
        return Err(err_from(code, &text));
    }
    serde_json::from_str::<T>(&text).map_err(|e| format!("解析失败: {e}"))
}

pub(crate) async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    path: &str,
    body: &B,
    token: Option<&str>,
) -> Result<T, String> {
    let mut req = Request::post(path);
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let payload = serde_json::to_string(body).map_err(|e| e.to_string())?;
    let req = req
        .header("Content-Type", "application/json")
        .body(payload)
        .map_err(|e| format!("编码失败: {e}"))?;
    let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
    let code = resp.status();
    let text = resp.text().await.map_err(|e| format!("读取失败: {e}"))?;
    if !(200..300).contains(&code) {
        return Err(err_from(code, &text));
    }
    serde_json::from_str::<T>(&text).map_err(|e| format!("解析失败: {e}"))
}

/// 手动切节点 / 恢复自动策略：写 `group.<name>.policy`（引擎 inotify 热驱动生效）。
pub(crate) fn set_group_policy(
    token: RwSignal<Option<String>>,
    msg: RwSignal<Option<(bool, String)>>,
    policy: &str,
    node: Option<String>,
) {
    let tok = token.get_untracked();
    let body = serde_json::json!({ "policy": policy, "node": node });
    msg.set(Some((true, "正在写入 group.policy…".into())));
    leptos::task::spawn_local(async move {
        match post_json::<_, shared::SaveResult>(
            "/api/v1/config/group/policy",
            &body,
            tok.as_deref(),
        )
        .await
        {
            Ok(v) => msg.set(Some((
                v.ok,
                match v.reload_ok {
                    Some(true) => format!("{} · 热重载 ✓", v.message),
                    Some(false) => format!("{} · 热重载未确认", v.message),
                    None => v.message,
                },
            ))),
            Err(e) => msg.set(Some((false, e))),
        }
    });
}

// ---------------------------------------------------------------- 格式化

pub(crate) fn fmt_uptime(s: u64) -> String {
    let d = s / 86400;
    let h = (s % 86400) / 3600;
    let m = (s % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {}s", s % 60)
    }
}

pub(crate) fn fmt_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub(crate) fn fmt_rate(bps: f64) -> String {
    let kb = bps / 1024.0;
    if kb > 1024.0 {
        format!("{:.1} MB/s", kb / 1024.0)
    } else {
        format!("{kb:.0} KB/s")
    }
}

fn fmt_secs(s: u64) -> String {
    if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

pub(crate) fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        a as f64 * 100.0 / b as f64
    }
}

/// 极简 percent-decode（深链参数用）。
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------- 组件：动作按钮

#[component]
pub(crate) fn ActionButton(
    label: &'static str,
    path: &'static str,
    token: RwSignal<Option<String>>,
    msg: RwSignal<Option<(bool, String)>>,
    #[prop(default = false)] danger: bool,
) -> impl IntoView {
    let armed = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let cls = if danger { "btn btn-danger" } else { "btn" };
    view! {
        <button class=cls disabled=move || busy.get()
            on:click=move |_| {
                if danger && !armed.get() {
                    armed.set(true);
                    return;
                }
                armed.set(false);
                let tok = token.get_untracked();
                busy.set(true);
                msg.set(None);
                leptos::task::spawn_local(async move {
                    let body = serde_json::json!({});
                    let r = post_json::<_, ActionResult>(path, &body, tok.as_deref()).await;
                    busy.set(false);
                    msg.set(Some(match r {
                        Ok(v) => {
                            let detail = format!("{}{}", v.stdout.trim(), v.stderr.trim());
                            (v.ok, if detail.is_empty() { format!("{label} 完成") } else { format!("{label}：{detail}") })
                        }
                        Err(e) => (false, format!("{label} 失败：{e}")),
                    }));
                });
            }>
            {move || if armed.get() { "再点一次确认" } else { label }}
        </button>
    }
}

// ---------------------------------------------------------------- 主组件

#[component]
fn App() -> impl IntoView {
    let status = RwSignal::new(Option::<StatusView>::None);
    let series = RwSignal::new(Option::<SeriesView>::None);
    let node_detail = RwSignal::new(Option::<NodeDetail>::None);
    let logs = RwSignal::new(Vec::<String>::new());
    let error = RwSignal::new(Option::<String>::None);
    let action_msg = RwSignal::new(Option::<(bool, String)>::None);
    let paused = RwSignal::new(false);
    let authed = RwSignal::new(true);
    let auth_required = RwSignal::new(false);
    let token = RwSignal::new(load_token());
    let token_input = RwSignal::new(load_token().unwrap_or_default());
    let editor = RwSignal::new(EditorState::default());
    let page = RwSignal::new(Page::Overview);
    // 节点表：默认只显示前 24 行（当前节点优先）；失败节点往往排在后面 → 额外提供
    // 「显示全部」与「仅看不可用」，避免失败节点被截断得看不见。
    let show_all = RwSignal::new(false);
    let dead_only = RwSignal::new(false);
    // 数据新鲜度：last_ok_ms = 上一次成功取数的时间戳（ms），data_age = 距今秒数。
    // 它同时覆盖「浏览器↔面板」与「面板↔引擎」两类失联——涨上去就是真停更。
    let last_ok_ms = RwSignal::new(0.0f64);
    let data_age = RwSignal::new(Option::<u64>::None);

    // 鉴权模式（进入时拉一次）
    {
        let tok = token.get_untracked();
        leptos::task::spawn_local(async move {
            if let Ok(h) = get_json::<serde_json::Value>("/api/v1/health", tok.as_deref()).await {
                auth_required.set(
                    h.get("auth_required")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                );
            }
        });
    }

    leptos::task::spawn_local(async move {
        let mut tick: u32 = 0;
        loop {
            if !paused.get_untracked() {
                let tok = token.get_untracked();
                match get_json::<StatusView>("/api/v1/status", tok.as_deref()).await {
                    Ok(s) => {
                        status.set(Some(s));
                        error.set(None);
                        authed.set(true);
                        last_ok_ms.set(js_sys::Date::now());
                    }
                    Err(e) => {
                        if e.contains("需要登录") {
                            authed.set(false);
                        } else {
                            error.set(Some(e));
                        }
                    }
                }
                // 每轮都重算新鲜度（请求失败时年龄照样增长）
                let now = js_sys::Date::now();
                let last = last_ok_ms.get_untracked();
                data_age.set(if last <= 0.0 {
                    None
                } else {
                    Some(((now - last) / 1000.0).max(0.0) as u64)
                });
                if tick % 2 == 0 {
                    if let Ok(l) =
                        get_json::<LogsView>("/api/v1/logs?tail=200", tok.as_deref()).await
                    {
                        logs.set(l.lines);
                    }
                }
                if tick % 3 == 0 {
                    if let Ok(s) =
                        get_json::<SeriesView>("/api/v1/series?points=360", tok.as_deref()).await
                    {
                        series.set(Some(s));
                    }
                }
            }
            tick = tick.wrapping_add(1);
            TimeoutFuture::new(REFRESH_MS).await;
        }
    });

    // 深链：#editor 打开编辑器；#node=<tag>|<name> 打开节点详情
    leptos::task::spawn_local(async move {
        TimeoutFuture::new(400).await;
        let hash = leptos::web_sys::window()
            .and_then(|w| w.location().hash().ok())
            .unwrap_or_default();
        if hash.contains("editor") {
            open_editor(editor, token);
        }
        if hash.contains("config") {
            page.set(Page::Config);
        }
        if let Some(rest) = hash.split("node=").nth(1) {
            let spec = percent_decode(rest);
            if let Some((tag, name)) = spec.split_once('|') {
                load_node(node_detail, token, tag.to_string(), name.to_string());
            }
        }
    });

    let num = move |f: fn(&StatusView) -> String| {
        Signal::derive(move || status.get().map(|s| f(&s)).unwrap_or_else(|| "—".into()))
    };
    let nodes = move || {
        let s = status.get();
        let cur = s.as_ref().and_then(|s| s.group.current);
        let mut ns = s.map(|s| s.nodes).unwrap_or_default();
        ns.sort_by(|a, b| {
            // 「当前使用」置顶，其余按 存活 → 延迟
            let ca = Some(a.index) == cur;
            let cb = Some(b.index) == cur;
            cb.cmp(&ca).then(b.alive.cmp(&a.alive)).then(
                a.ema_ms
                    .partial_cmp(&b.ema_ms)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });
        if dead_only.get() {
            ns.retain(|n| !n.alive);
        }
        if !show_all.get() && !dead_only.get() {
            ns.truncate(24);
        }
        ns
    };

    let csv_href = "/api/v1/series.csv?points=1440";

    view! {
        <header class="top">
            <div class="brand">
                <span class="logo">"SODAMA"</span>
                <span class="brand-sub">"CONTROL PANEL"</span>
            </div>
            <nav class="nav">
                <button class=move || if page.get() == Page::Overview { "nav-item nav-item-on" } else { "nav-item" }
                    on:click=move |_| page.set(Page::Overview)>"总览"</button>
                <button class=move || if page.get() == Page::Config { "nav-item nav-item-on" } else { "nav-item" }
                    on:click=move |_| page.set(Page::Config)>"配置"</button>
            </nav>
            <div class="top-right">
                <span class="meta meta-hide-sm">{num(|s| format!("v{} · {}", s.version, s.kernel))}</span>
                <span class="meta">{num(|s| format!("UP {}", fmt_uptime(s.uptime_sec)))}</span>
                <span class="meta">{move || if paused.get() { "已暂停".to_string() } else { format!("自动刷新 {}s", REFRESH_MS / 1000) }}</span>
                <button class="btn" on:click=move |_| open_editor(editor, token)>"编辑配置"</button>
                <button class="btn" on:click=move |_| paused.update(|p| *p = !*p)>
                    {move || if paused.get() { "▶" } else { "⏸" }}
                </button>
                {move || auth_required.get().then(|| view! {
                    <button class="btn" on:click=move |_| {
                        let tok = token.get_untracked();
                        leptos::task::spawn_local(async move {
                            let _ = post_json::<_, serde_json::Value>("/api/v1/logout", &serde_json::json!({}), tok.as_deref()).await;
                            save_token("");
                            token.set(None);
                            authed.set(false);
                        });
                    }>"登出"</button>
                })}
            </div>
        </header>

        {move || (auth_required.get() && !authed.get()).then(|| view! {
            <div class="banner">
                <span class="banner-err">"需要登录：输入 panel.conf 里的 token"</span>
                <input class="inp" type="password" placeholder="访问 token"
                    prop:value=move || token_input.get()
                    on:input=move |ev| token_input.set(event_target_value(&ev)) />
                <button class="btn btn-primary" on:click=move |_| {
                    let t = token_input.get();
                    leptos::task::spawn_local(async move {
                        let body = serde_json::json!({ "token": t.clone() });
                        match post_json::<_, shared::LoginResp>("/api/v1/login", &body, None).await {
                            Ok(r) if r.ok => {
                                save_token(&t);
                                token.set(load_token());
                                authed.set(true);
                                action_msg.set(Some((true, r.message)));
                            }
                            Ok(r) => action_msg.set(Some((false, r.message))),
                            Err(e) => action_msg.set(Some((false, e))),
                        }
                    });
                }>"登录"</button>
            </div>
        })}

        {move || error.get().map(|e| view! {
            <div class="banner"><span class="banner-err">{e}</span>
                <button class="btn" on:click=move |_| error.set(None)>"关闭"</button>
            </div>
        })}

        {move || action_msg.get().map(|(ok, m)| view! {
            <div class=if ok { "banner banner-ok" } else { "banner" }>
                <span class=if ok { "banner-msg" } else { "banner-err" }>{m}</span>
                <button class="btn" on:click=move |_| action_msg.set(None)>"关闭"</button>
            </div>
        })}

        <main class="wrap">
        {move || match page.get() {
            Page::Overview => view! {
            <RuntimeCard status=status series=series
                data_age=Signal::derive(move || data_age.get())
                paused=Signal::derive(move || paused.get())
                token=token msg=action_msg />
            <MetricsTable status=status />
            <AiTrafficCard status=status />
            <TrendRow status=status series=series />

            <div class="charts-foot">
                <a class="btn btn-link" href=csv_href download=true>"导出 CSV（按需生成，不落盘）"</a>
                <span class="meta">{move || series.get().map(|s| format!("当前缓冲 {} 点（{}s/点，约 {}）", s.points.len(), s.step_secs, fmt_secs(s.points.len() as u64 * s.step_secs))).unwrap_or_default()}</span>
            </div>

            <section class="panel">
                <div class="panel-head">
                    <span class="panel-title">"节点（当前使用置顶 · 点击行看详情 · 可手动锁定）"</span>
                    <span class="panel-meta">{num(|s| format!("{} / {} 存活 · 总拨号 {} · 策略 {}", s.group.alive, s.group.members, s.group.dials, s.group.policy))}</span>
                    {move || {
                        let (pinned, ok) = status.get().map(|s| (s.group.pinned, s.group.pinned_ok)).unwrap_or_default();
                        (!pinned.is_empty()).then(|| view! {
                            <span class="chip chip-use">{format!("已锁定 {pinned}")}</span>
                            {(!ok).then(|| view! { <span class="chip chip-warn">"不在当前节点池（已兜底自动）"</span> })}
                            <button class="btn btn-mini" on:click=move |_| set_group_policy(token, action_msg, "auto", None)>"恢复自动"</button>
                        })
                    }}
                    {move || {
                        let pinned = status.get().map(|s| s.group.pinned).unwrap_or_default();
                        pinned.is_empty().then(|| view! {
                            <select class="inp sel sel-mini" prop:value=move || status.get().map(|s| s.group.policy).unwrap_or_default()
                                on:change=move |ev| {
                                    let v = event_target_value(&ev);
                                    set_group_policy(token, action_msg, &v, None);
                                }>
                                <option value="min_moving_avg">"自动 · min_moving_avg"</option>
                                <option value="min">"自动 · min"</option>
                                <option value="min_avg10">"自动 · min_avg10"</option>
                                <option value="random">"自动 · random"</option>
                            </select>
                        })
                    }}
                    // 失败节点可见性（默认 24 行截断会把排在后面的失败节点藏掉）
                    {move || {
                        let (members, alive) = status
                            .get()
                            .map(|s| (s.group.members, s.group.alive))
                            .unwrap_or((0, 0));
                        let dead = members.saturating_sub(alive);
                        view! {
                            <button class="btn btn-mini"
                                class:btn-primary=move || dead_only.get()
                                on:click=move |_| dead_only.update(|v| *v = !*v)>
                                {format!("仅看不可用（{dead}）")}
                            </button>
                            <button class="btn btn-mini"
                                class:btn-primary=move || show_all.get()
                                on:click=move |_| show_all.update(|v| *v = !*v)>
                                {move || if show_all.get() { "收起（只显示前 24）".to_string() }
                                          else { format!("显示全部（{members}）") }}
                            </button>
                        }
                    }}
                </div>
                <table class="tbl">
                    <thead>
                        <tr>
                            <th></th><th>"节点"</th><th class="col-proto">"协议"</th><th class="udp-col col-opt">"UDP"</th><th class="col-addr">"地址"</th><th class="col-tag">"来源"</th><th class="num">"EMA(ms)"</th><th class="col-bar">"延迟分布"</th><th class="num col-last">"最近"</th><th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each=nodes key=|n| format!("{}|{}", n.tag, n.name) children=move |n| {
                            let alive = n.alive;
                            let ema = n.ema_ms;
                            let width = (ema / 20.0).clamp(2.0, 100.0);
                            let idx = n.index;
                            let node_name2 = n.name.clone();
                            let is_cur = Signal::derive(move || {
                                status.get().and_then(|s| s.group.current) == Some(idx)
                            });
                            let is_pinned = Signal::derive(move || {
                                status.get().map(|s| s.group.pinned == node_name2).unwrap_or(false)
                            });
                            let row_cls = Signal::derive(move || {
                                if is_cur.get() {
                                    "row row-click row-current"
                                } else if alive {
                                    "row row-click"
                                } else {
                                    "row row-dead row-click"
                                }
                            });
                            let dot_cls = if alive { "dot dot-ok" } else { "dot dot-dead" };
                            let tag = n.tag.clone();
                            let name = n.name.clone();
                            let lock_name = n.name.clone();
                            view! {
                                <tr class=row_cls on:click=move |_| load_node(node_detail, token, tag.clone(), name.clone())>
                                    <td class="dot-cell"><span class=dot_cls></span></td>
                                    <td class="mono node-cell">
                                        {n.name.clone()}
                                        {move || is_cur.get().then(|| view! { <span class="chip chip-use">"使用中"</span> })}
                                        {move || is_pinned.get().then(|| view! { <span class="chip">"已锁定"</span> })}
                                    </td>
                                    <td class="mono col-proto" title=format!("{} · {} · {}", n.protocol, n.transport, n.security)>
                                        {n.protocol.clone()}
                                        {(!matches!(n.security.as_str(), "" | "none" | "—")).then(|| view! {
                                            <span class="dim">{format!("·{}", n.security)}</span>
                                        })}
                                        {(n.transport == "ws" || n.transport == "quic" || n.transport == "h2").then(|| view! {
                                            <span class="dim">{format!("·{}", n.transport)}</span>
                                        })}
                                    </td>
                                    <td class="mono udp-col col-opt">
                                        {if n.udp {
                                            view! { <span class="ok-mark">"✓"</span> }.into_any()
                                        } else {
                                            view! { <span class="dim">"·"</span> }.into_any()
                                        }}
                                    </td>
                                    <td class="mono dim addr-cell col-addr">{n.addr.clone()}</td>
                                    <td class="mono dim col-tag">{n.tag.clone()}</td>
                                    <td class="mono num">{format!("{ema:.0}")}</td>
                                    <td class="bar-cell col-bar"><div class="bar" style=format!("width:{width:.0}%")></div></td>
                                    <td class="mono num dim col-last">{n.last_ms.to_string()}</td>
                                    <td class="act-cell">
                                        <button class="btn btn-mini" disabled=move || is_pinned.get()
                                            on:click=move |ev| {
                                                ev.stop_propagation();
                                                let n = lock_name.clone();
                                                set_group_policy(token, action_msg, "fixed", Some(n));
                                            }>"锁定"</button>
                                        <button class="btn btn-mini" disabled=move || !is_pinned.get()
                                            on:click=move |ev| {
                                                ev.stop_propagation();
                                                set_group_policy(token, action_msg, "auto", None);
                                            }>"解锁"</button>
                                    </td>
                                </tr>
                            }
                        }/>
                    </tbody>
                </table>
                <div class="panel-meta pad">
                    {move || {
                        let (members, alive, shown) = status
                            .get()
                            .map(|s| (s.group.members, s.group.alive, nodes().len()))
                            .unwrap_or((0, 0, 0));
                        format!(
                            "显示 {} / {} · 存活 {} · 不可用 {}（已标死，仍参与探测；想只看它们点上方「仅看不可用」）",
                            shown,
                            members,
                            alive,
                            members.saturating_sub(alive)
                        )
                    }}
                </div>
            </section>

            <section class="cols">
                <div class="panel">
                    <div class="panel-head"><span class="panel-title">"eBPF 钩子"</span></div>
                    <pre class="mono small">{num(|s| s.hooks.join("\n"))}</pre>
                </div>
                <div class="panel">
                    <div class="panel-head">
                        <span class="panel-title">"规则集 / 远程刷新"</span>
                        <button class="btn btn-mini" on:click=move |_| {
                            let tok = token.get_untracked();
                            action_msg.set(Some((true, "正在触发规则集刷新（reload）…".into())));
                            leptos::task::spawn_local(async move {
                                let body = serde_json::json!({});
                                let r = post_json::<_, ActionResult>("/api/v1/actions/reload", &body, tok.as_deref()).await;
                                action_msg.set(Some(match r {
                                    Ok(v) => (v.ok, if v.ok { "规则集已刷新（reload ✓）".to_string() } else { format!("刷新失败：{}{}", v.stdout, v.stderr) }),
                                    Err(e) => (false, format!("刷新失败：{e}")),
                                }));
                            });
                        }>"立即刷新"</button>
                    </div>
                    <table class="tbl">
                        <thead>
                            <tr><th>"tag"</th><th class="num">"条数"</th><th>"来源"</th><th class="num">"更新于"</th><th class="num">"下次刷新"</th></tr>
                        </thead>
                        <tbody>
                            <For each=move || status.get().map(|s| s.rule_sets).unwrap_or_default()
                                 key=|r| r.tag.clone()
                                 children=move |r| {
                                    let src = if !r.remote {
                                        "本地".to_string()
                                    } else if r.from_cache {
                                        "远程·缓存".to_string()
                                    } else {
                                        "远程".to_string()
                                    };
                                    let next = if r.interval_secs == 0 {
                                        "每次 reload".to_string()
                                    } else if r.next_update_secs == 0 {
                                        "即将".to_string()
                                    } else {
                                        fmt_secs(r.next_update_secs)
                                    };
                                    view! {
                                        <tr class="row">
                                            <td class="mono">{r.tag.clone()}</td>
                                            <td class="mono num">{r.entries.to_string()}</td>
                                            <td class="mono dim">{src}</td>
                                            <td class="mono num dim">{fmt_secs(r.updated_secs_ago)}</td>
                                            <td class="mono num dim">{next}</td>
                                        </tr>
                                    }
                                 }/>
                        </tbody>
                    </table>
                    <div class="panel-meta pad">
                        {num(|s| format!("配置 {} · 段 {}", s.config.entry, s.config.sections.join(", ")))}
                    </div>
                </div>
            </section>

            <section class="panel">
                <div class="panel-head">
                    <span class="panel-title">"引擎日志（新→旧）"</span>
                    <span class="panel-meta">{move || format!("{} 行", logs.get().len())}</span>
                </div>
                <pre class="log-body">{
                    move || {
                        let mut v = logs.get();
                        v.reverse();
                        v.join("\n")
                    }
                }</pre>
            </section>

            <footer class="foot">
                <span>{num(|s| format!("pid {} · tproxy {} · slot {}", s.pid, s.tproxy_port, s.active_slot))}</span>
                <span>{num(|s| format!("splice {} · offload {} · 空闲回收 {}s", s.relay.splice_enabled, s.relay.offload_enabled, s.relay.idle_timeout_secs))}</span>
                <span>{num(|s| format!("inotify {} · 去抖 {}ms", s.config_watch.transport, s.config_watch.debounce_ms))}</span>
            </footer>
            }.into_any(),
            Page::Config => view! { <ConfigPage token=token /> }.into_any(),
        }}
        </main>

        <EditorModal state=editor token=token />
        <NodeModal detail=node_detail />
    }
}

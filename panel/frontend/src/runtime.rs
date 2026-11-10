// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! 总览页的两个头部区块：
//! - `RuntimeCard`：引擎运行时（内存 / 线程 / FD / CPU + 控制动作）——页面重点
//! - `MetricsTable`：运行指标三线表（表头线 + 数据 + 注释行，无竖线）

use leptos::prelude::*;
use shared::{ActionResult, Sample, SeriesView, StatusView, TraceResult};

use crate::charts::{Chart, CurveSerie};
use crate::{fmt_bytes, fmt_rate, fmt_uptime, pct, post_json, ActionButton};

/// KB → (数值, 单位)，用于把数字与单位分开排版。
fn split_size(kb: u64) -> (String, &'static str) {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = kb as f64 * 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let s = if i <= 1 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    };
    (s, U[i])
}

/// 秒 → `H:MM:SS`（CPU 累计时间）。
fn fmt_clock(secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// 秒 → 跨度短标签（`90s` / `10min` / `2h`）——曲线窗口时长用。
fn fmt_span(secs: u64) -> String {
    if secs < 120 {
        format!("{secs}s")
    } else if secs < 7200 {
        format!("{}min", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// 窗口统计：`(min, max, 首值, 末值)`（不足两点返回 None）。
fn win_stats(vals: &[f64]) -> Option<(f64, f64, f64, f64)> {
    if vals.len() < 2 {
        return None;
    }
    let min = vals.iter().cloned().fold(f64::MAX, f64::min);
    let max = vals.iter().cloned().fold(f64::MIN, f64::max);
    Some((min, max, vals[0], vals[vals.len() - 1]))
}

#[component]
fn Stat(label: &'static str, value: Signal<String>, hint: Signal<String>) -> impl IntoView {
    view! {
        <div class="rt-stat">
            <div class="rt-stat-label">{label}</div>
            <div class="rt-stat-value">{move || value.get()}</div>
            <div class="rt-stat-hint">{move || hint.get()}</div>
        </div>
    }
}

/// 引擎运行时：左侧大号 RSS + 内存曲线 + 活跃连接曲线 + 右侧专业参数 + 控制动作。
#[component]
pub fn RuntimeCard(
    status: RwSignal<Option<StatusView>>,
    series: RwSignal<Option<SeriesView>>,
    /// 距上一次成功取数的秒数（面板数据新鲜度；None = 还没拿到过）
    data_age: Signal<Option<u64>>,
    /// 用户手动暂停自动刷新：此时"停更"是预期的，不报黄。
    paused: Signal<bool>,
    token: RwSignal<Option<String>>,
    msg: RwSignal<Option<(bool, String)>>,
) -> impl IntoView {
    let rt = move || status.get().map(|s| s.runtime).unwrap_or_default();
    let rss_vals = move || {
        series
            .get()
            .map(|s| {
                s.points
                    .iter()
                    .map(|p: &Sample| p.rss_kb as f64 / 1024.0)
                    .collect::<Vec<f64>>()
            })
            .unwrap_or_default()
    };
    let conn_vals = move || {
        series
            .get()
            .map(|s| {
                s.points
                    .iter()
                    .map(|p: &Sample| p.conns_active as f64)
                    .collect::<Vec<f64>>()
            })
            .unwrap_or_default()
    };
    // 窗口时长（点数 × 步长）——标注 Δ 的区间用。
    let win_label = move || {
        series
            .get()
            .map(|s| {
                let n = s.points.len().max(1) as u64;
                fmt_span(n.saturating_sub(1) * s.step_secs.max(1))
            })
            .unwrap_or_default()
    };
    view! {
        <section class="panel runtime">
            <div class="panel-head">
                <span class="panel-title">"引擎运行时"</span>
                <span class="panel-meta">
                    {move || status.get().map(|s| format!(
                        "pid {} · slot {} · 运行 {} · 采样 {}s/点",
                        s.pid,
                        s.active_slot,
                        fmt_uptime(s.uptime_sec),
                        series.get().map(|x| x.step_secs).unwrap_or(0),
                    )).unwrap_or_default()}
                </span>
                <span class="rt-head-right">
                    // 数据新鲜度：一眼分清「面板/引擎卡住」与「指标本来就稳」。
                    {move || {
                        let (cls, label) = match (paused.get(), data_age.get()) {
                            (true, _) => ("pill pill-dim", "已暂停".to_string()),
                            (false, Some(0)) => ("pill pill-dim", "数据 <1s 前".to_string()),
                            (false, Some(a)) if a <= 12 => ("pill pill-dim", format!("数据 {a}s 前")),
                            (false, Some(a)) => ("pill pill-warn", format!("数据 {a}s 前 · 已停更")),
                            (false, None) => ("pill pill-dim", "等待数据".to_string()),
                        };
                        view! { <span class=cls><span class="pill-dot"></span>{label}</span> }
                    }}
                    {move || {
                        let (cls, label) = match status.get() {
                            Some(s) if s.suspended => ("pill pill-warn", "SUSPENDED"),
                            Some(_) => ("pill pill-ok", "RUNNING"),
                            None => ("pill pill-dim", "连接中"),
                        };
                        view! { <span class=cls><span class="pill-dot"></span>{label}</span> }
                    }}
                    <ActionButton label="重新加载引擎" path="/api/v1/actions/reload" token=token msg=msg />
                    <ActionButton label="挂起" path="/api/v1/actions/suspend" token=token msg=msg danger=true />
                    <ActionButton label="恢复" path="/api/v1/actions/resume" token=token msg=msg />
                </span>
            </div>
            <EngineOps token=token msg=msg />
            <div class="runtime-body">
                <div class="rt-hero">
                    <div class="rt-hero-label">"常驻内存 RSS"</div>
                    <div class="rt-hero-value">
                        {move || split_size(rt().rss_kb).0}
                        <span class="rt-hero-unit">{move || split_size(rt().rss_kb).1}</span>
                    </div>
                    <div class="rt-hero-sub">
                        {move || {
                            let r = rt();
                            format!(
                                "峰值 {} · 虚拟 {}",
                                fmt_bytes(r.hwm_kb * 1024),
                                fmt_bytes(r.vmsize_kb * 1024)
                            )
                        }}
                    </div>
                </div>
                <div class="rt-spark">
                    // 内存：窗口区间 + Δ 是「稳」的正面证据（平不代表挂）。
                    <Chart
                        title="内存曲线（RSS）"
                        hint=Signal::derive(move || {
                            match win_stats(&rss_vals()) {
                                Some((_, _, first, last)) => {
                                    format!("Δ {:+.1} MB / {}", last - first, win_label())
                                }
                                None => String::new(),
                            }
                        })
                        ts=Signal::derive(move || {
                            series
                                .get()
                                .map(|s| s.points.iter().map(|p| p.t).collect::<Vec<u64>>())
                                .unwrap_or_default()
                        })
                        series=Signal::derive(move || {
                            vec![CurveSerie::new("RSS", "#29ffa4", rss_vals())]
                        })
                        unit=" MB"
                        foot_mid=Signal::derive(move || {
                            match win_stats(&rss_vals()) {
                                Some((min, max, _, _)) => format!("窗口 {min:.1}–{max:.1} MB"),
                                None => String::new(),
                            }
                        })
                    />
                    // 同窗口的活跃连接：内存不动时，它动 = 引擎在干活。
                    <Chart
                        title="活跃连接（同窗口）"
                        hint=Signal::derive(move || {
                            let v = conn_vals();
                            match (v.last().copied(), v.iter().cloned().fold(f64::MIN, f64::max)) {
                                (Some(last), peak) if !v.is_empty() => {
                                    format!("当前 {last:.0} · 窗口峰值 {peak:.0}")
                                }
                                _ => String::new(),
                            }
                        })
                        ts=Signal::derive(move || {
                            series
                                .get()
                                .map(|s| s.points.iter().map(|p| p.t).collect::<Vec<u64>>())
                                .unwrap_or_default()
                        })
                        series=Signal::derive(move || {
                            vec![CurveSerie::new("连接", "#3c73ff", conn_vals())]
                        })
                        unit=""
                        compact=true
                    />
                </div>
                <div class="rt-stats">
                    <Stat
                        label="线程"
                        value=Signal::derive(move || rt().threads.to_string())
                        hint=Signal::derive(move || "reactor + 探测池".to_string())
                    />
                    <Stat
                        label="FD 使用"
                        value=Signal::derive(move || {
                            status.get().map(|s| s.relay.fds_used.to_string()).unwrap_or_else(|| "—".into())
                        })
                        hint=Signal::derive(move || {
                            status.get().map(|s| format!("上限 {}", s.relay.fds_soft_limit)).unwrap_or_default()
                        })
                    />
                    <Stat
                        label="CPU 占用"
                        value=Signal::derive(move || format!("{:.1}%", rt().cpu_pct))
                        hint=Signal::derive(move || "近次采样窗口".to_string())
                    />
                    <Stat
                        label="CPU 累计"
                        value=Signal::derive(move || fmt_clock(rt().cpu_secs))
                        hint=Signal::derive(move || "进程 utime+stime".to_string())
                    />
                    <Stat
                        label="活跃连接"
                        value=Signal::derive(move || {
                            status.get().map(|s| s.relay.conns_active.to_string()).unwrap_or_else(|| "—".into())
                        })
                        hint=Signal::derive(move || {
                            status.get().map(|s| format!("累计 {}", s.relay.conns_total)).unwrap_or_default()
                        })
                    />
                    <Stat
                        label="探测"
                        value=Signal::derive(move || {
                            status.get().map(|s| format!("{}s", s.group.probe_interval_secs)).unwrap_or_else(|| "—".into())
                        })
                        hint=Signal::derive(move || {
                            match status.get() {
                                Some(s) if s.group.probe_active => "活跃（有人看/有流量）".to_string(),
                                Some(_) => "空闲退避".to_string(),
                                None => String::new(),
                            }
                        })
                    />
                    <Stat
                        label="引擎构建"
                        value=Signal::derive(move || {
                            status.get().and_then(|s| s.engine_build).map(|b| b.git_sha).unwrap_or_else(|| "—".into())
                        })
                        hint=Signal::derive(move || {
                            status.get().and_then(|s| s.engine_build).map(|b| {
                                let mut h = b.version;
                                if b.dirty { h.push_str(" · dirty"); }
                                h
                            }).unwrap_or_else(|| "sodama --version".into())
                        })
                    />
                </div>
            </div>
        </section>
    }
}

// ---------------------------------------------------------------- v2.0：引擎运维工具

/// 引擎运维工具行（A1/A2 取证面在面板上的入口）：
/// - `--drain=N` / `--abort`：reload/suspend 的可选排空预算与中断在飞会话；
/// - `trace`：短时内核事件抓取（秒数/协议/只看丢弃），结果就地展示；
/// - `sysdump`：一键下载诊断包（tar.gz，含 status/config/maps + 现场 ip/nft/sysctl）。
#[component]
pub fn EngineOps(
    token: RwSignal<Option<String>>,
    msg: RwSignal<Option<(bool, String)>>,
) -> impl IntoView {
    let drain = RwSignal::new(String::new());
    let abort = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let armed = RwSignal::new("");
    let l4 = RwSignal::new(String::new());
    let drop_only = RwSignal::new(false);
    let secs = RwSignal::new("5".to_string());
    let trace_res = RwSignal::new(Option::<TraceResult>::None);

    let opts = move || {
        let d: Option<u64> = drain.get().trim().parse().ok().filter(|v: &u64| *v > 0);
        serde_json::json!({
            "drain_secs": d,
            "abort": abort.get(),
        })
    };
    let act =
        move |label: &'static str, path: &'static str, body: serde_json::Value, must_arm: bool| {
            if must_arm && armed.get() != label {
                armed.set(label);
                return;
            }
            armed.set("");
            let tok = token.get_untracked();
            busy.set(true);
            msg.set(None);
            leptos::task::spawn_local(async move {
                let r = post_json::<_, ActionResult>(path, &body, tok.as_deref()).await;
                busy.set(false);
                msg.set(Some(match r {
                    Ok(v) => {
                        let detail = format!("{}{}", v.stdout.trim(), v.stderr.trim());
                        (
                            v.ok,
                            if detail.is_empty() {
                                format!("{label} 完成")
                            } else {
                                format!("{label}：{detail}")
                            },
                        )
                    }
                    Err(e) => (false, format!("{label} 失败：{e}")),
                }));
            });
        };

    let sysdump_href = move || match token.get() {
        Some(t) if !t.is_empty() => format!("/api/v1/engine/sysdump?token={t}"),
        _ => "/api/v1/engine/sysdump".to_string(),
    };

    view! {
        <div class="ops-row">
            <span class="ops-label">"运维"</span>
            <label class="ops-inline" title="旧代在飞会话排空预算（秒；空 = 不排空）">
                "drain"
                <input class="inp inp-sm" type="number" min="0" max="600" placeholder="—"
                    prop:value=move || drain.get()
                    on:input=move |ev| drain.set(event_target_value(&ev)) />
            </label>
            <label class="ops-inline" title="中断在飞会话（不等待排空）">
                <input type="checkbox" prop:checked=move || abort.get()
                    on:change=move |ev| abort.set(event_target_checked(&ev)) />
                "abort"
            </label>
            <button class="btn" disabled=move || busy.get()
                on:click=move |_| act("重新加载引擎", "/api/v1/actions/reload", opts(), true)>
                {move || if armed.get() == "重新加载引擎" { "再点一次确认" } else { "重新加载引擎" }}
            </button>
            <button class="btn btn-danger" disabled=move || busy.get()
                on:click=move |_| act("挂起", "/api/v1/actions/suspend", opts(), true)>
                {move || if armed.get() == "挂起" { "再点一次确认" } else { "挂起" }}
            </button>
            <button class="btn" disabled=move || busy.get()
                on:click=move |_| act("恢复", "/api/v1/actions/resume", serde_json::json!({}), false)>
                "恢复"
            </button>
        </div>
        <div class="ops-row">
            <span class="ops-label">"取证"</span>
            <label class="ops-inline" title="trace 保持秒数（1–30）">
                "trace"
                <input class="inp inp-sm" type="number" min="1" max="30"
                    prop:value=move || secs.get()
                    on:input=move |ev| secs.set(event_target_value(&ev)) />
                "s"
            </label>
            <select class="inp inp-sm" prop:value=move || l4.get()
                on:change=move |ev| l4.set(event_target_value(&ev))>
                <option value="">"全部协议"</option>
                <option value="tcp">"仅 TCP"</option>
                <option value="udp">"仅 UDP"</option>
            </select>
            <label class="ops-inline" title="只看被内核判丢/拒的会话">
                <input type="checkbox" prop:checked=move || drop_only.get()
                    on:change=move |ev| drop_only.set(event_target_checked(&ev)) />
                "只看丢弃"
            </label>
            <button class="btn" disabled=move || busy.get() on:click=move |_| {
                let tok = token.get_untracked();
                let n: u64 = secs.get().trim().parse().unwrap_or(5).clamp(1, 30);
                let body = serde_json::json!({
                    "seconds": n,
                    "l4": l4.get(),
                    "drop_only": drop_only.get(),
                });
                busy.set(true);
                trace_res.set(None);
                leptos::task::spawn_local(async move {
                    let r = post_json::<_, TraceResult>("/api/v1/engine/trace", &body, tok.as_deref()).await;
                    busy.set(false);
                    match r {
                        Ok(v) => trace_res.set(Some(v)),
                        Err(e) => msg.set(Some((false, format!("抓取事件失败：{e}")))),
                    }
                });
            }>"抓取事件"</button>
            <a class="btn btn-link" href=sysdump_href download=true
                title="status/rules/config/maps + system + 现场（ip/nft/iptables/sysctl）打包下载">"下载诊断包"</a>
        </div>
        {move || trace_res.get().map(|t| {
            let head = if t.ok {
                format!("trace {}s：{} 行{}（文件 {}）", t.seconds, t.total_lines,
                    if t.truncated { "，已截断展示" } else { "" }, t.file)
            } else {
                format!("trace {}s：失败 {}｜{}", t.seconds, t.message, t.file)
            };
            let body = t.lines.join("\n");
            view! {
                <div class="trace-out">
                    <div class="trace-head">
                        <span>{head}</span>
                        <button class="btn btn-sm" on:click=move |_| trace_res.set(None)>"收起"</button>
                    </div>
                    <pre class="trace-pre">{body}</pre>
                </div>
            }
        })}
    }
}

/// 运行指标三线表：表头一行、数值一行、注释一行（无竖线，专业报表式）。
#[component]
pub fn MetricsTable(status: RwSignal<Option<StatusView>>) -> impl IntoView {
    let f = |g: fn(&StatusView) -> String| {
        Signal::derive(move || status.get().map(|s| g(&s)).unwrap_or_else(|| "—".into()))
    };
    view! {
        <div class="t3-wrap">
        <table class="tbl-3line">
            <thead>
                <tr>
                    <th>"节点组"</th>
                    <th>"活跃连接"</th>
                    <th>"累计流量"</th>
                    <th>"DNS 缓存命中"</th>
                    <th>"SNI 嗅探"</th>
                    <th>"文件描述符"</th>
                    <th>"规则 / 重载"</th>
                    <th>"分组探测"</th>
                </tr>
            </thead>
            <tbody>
                <tr class="t3-values">
                    <td>{f(|s| format!("{} / {}", s.group.alive, s.group.members))}</td>
                    <td>{f(|s| s.relay.conns_active.to_string())}</td>
                    <td>{f(|s| fmt_bytes(s.relay.bytes_up + s.relay.bytes_down))}</td>
                    <td>{f(|s| format!("{:.1}%", pct(s.dns.cache_hits, s.dns.cache_hits + s.dns.cache_misses)))}</td>
                    <td>{f(|s| format!("{:.1}%", pct(s.sniffing.hits, s.sniffing.attempts)))}</td>
                    <td>{f(|s| s.relay.fds_used.to_string())}</td>
                    <td>{f(|s| s.reload.match_sets.to_string())}</td>
                    <td>{f(|s| s.group.probes_ok.to_string())}</td>
                </tr>
                <tr class="t3-notes">
                    <td>{f(|s| format!("{} · {}", s.group.name, s.group.policy))}</td>
                    <td>{f(|s| format!("累计 {} · 拨号错误 {}", s.relay.conns_total, s.relay.dial_errors))}</td>
                    <td>{f(|s| format!("↑ {} · ↓ {}", fmt_bytes(s.relay.bytes_up), fmt_bytes(s.relay.bytes_down)))}</td>
                    <td>{f(|s| format!("查询 {} · 缓存 {} · 拦截 {}", s.dns.queries, s.dns.cache_entries, s.dns.rejects))}</td>
                    <td>{f(|s| format!("{} / {} · 模式 {}", s.sniffing.hits, s.sniffing.attempts, s.sniffing.dial_mode))}</td>
                    <td>{f(|s| format!("上限 {} · 驱逐 {}", s.relay.fds_soft_limit, s.relay.evicted))}</td>
                    <td>{f(|s| format!("slot {} · {} · deferred {}", s.active_slot, if s.reload.ok { "ok" } else { "ERR" }, s.config.routing_deferred))}</td>
                    <td>{f(|s| format!("失败 {} · failover {}", s.group.probes_fail, s.group.failovers))}</td>
                </tr>
            </tbody>
        </table>
        </div>
    }
}

/// v2.0：数据面卡片 —— UDP NAT（含 GSO）/ 卸载与零拷贝 / 错误面 / 观测面。
///
/// 口径：`错误面` 那组计数**正常应恒为 0**（溢出/丢弃/记账失败才不为零）；非零时整格转
/// 警告色，作为「数据面出了问题」的单点信号。GSO 两列对应 2026-10-17 修复后的聚合发送面：
/// `GSO 聚合` = 实际聚合发送次数，`回退面` = 逐包回退/raw_udp 次数。
#[component]
pub fn DataplaneCard(status: RwSignal<Option<StatusView>>) -> impl IntoView {
    let f = |g: fn(&StatusView) -> String| {
        Signal::derive(move || status.get().map(|s| g(&s)).unwrap_or_else(|| "—".into()))
    };
    let err_total = move || {
        status
            .get()
            .map(|s| {
                let st = &s.stats;
                st.udp_conn_overflow
                    + st.tcp_conn_overflow
                    + st.redirect_overflow
                    + st.redirect_update_failed
                    + st.domain_publish_dropped
                    + st.event_drops
                    + st.offload_account_drops
                    + s.udp_nat.errors
            })
            .unwrap_or(0)
    };
    let err_total_sig = Signal::derive(err_total);
    let err_cls = Signal::derive(move || {
        if err_total_sig.get() > 0 {
            "cell-warn".to_string()
        } else {
            String::new()
        }
    });
    view! {
        <div class="t3-wrap">
        <table class="tbl-3line">
            <thead>
                <tr>
                    <th>"UDP NAT 流量"</th>
                    <th>"UDP 会话"</th>
                    <th>"GSO 聚合"</th>
                    <th>"回退面"</th>
                    <th>"卸载 / 零拷贝"</th>
                    <th>"错误面"</th>
                    <th>"观测"</th>
                </tr>
            </thead>
            <tbody>
                <tr class="t3-values">
                    <td>{f(|s| fmt_bytes(s.udp_nat.bytes_up + s.udp_nat.bytes_down))}</td>
                    <td>{f(|s| s.udp_nat.sessions_active.to_string())}</td>
                    <td>{f(|s| s.udp_nat.gso_sends.to_string())}</td>
                    <td>{f(|s| s.udp_nat.raw_udp_fallbacks.to_string())}</td>
                    <td>{f(|s| s.relay.offloaded_total.to_string())}</td>
                    <td class=err_cls>
                        {move || err_total_sig.get().to_string()}
                    </td>
                    <td>{f(|s| format!("{} / {}", s.sysctl.watched, s.sysctl.rewrites))}</td>
                </tr>
                <tr class="t3-notes">
                    <td>{f(|s| format!(
                        "累计 {} · 代理 {} · 直回 {}",
                        s.udp_nat.sessions_total, s.udp_nat.sessions_proxied, s.udp_nat.direct_fallback
                    ))}</td>
                    <td>{f(|s| format!("full-cone {} · 回收 {}", s.udp_nat.cone_sessions, s.udp_nat.evicted))}</td>
                    <td>{f(|s| format!("用户包 {} · 不支持 {}", s.udp_nat.gso_datagrams, s.udp_nat.gso_unsupported))}</td>
                    <td>{f(|s| format!("负缓存 {} · 回程套接字回收 {}", s.udp_nat.negcache_hits, s.udp_nat.reply_sockets_evicted))}</td>
                    <td>{f(|s| format!(
                        "splice {} · reactor {} · pipe 泄漏 {}",
                        s.relay.splice_total, s.relay.reactor_codec_sessions,
                        s.relay.pipe_created.saturating_sub(s.relay.pipe_released)
                    ))}</td>
                    <td>{f(|s| {
                        if s.relay.offload_failures + s.stats.fuse_failures > 0 {
                            format!("卸载失败 {} · fuse 失败 {}", s.relay.offload_failures, s.stats.fuse_failures)
                        } else {
                            "正常（0 溢出/丢弃）".to_string()
                        }
                    })}</td>
                    <td>{f(|s| format!(
                        "域确认 {} · trace {}",
                        s.real_domain.confirmed, if s.trace.active { "进行中" } else { "空闲" }
                    ))}</td>
                </tr>
            </tbody>
        </table>
        </div>
    }
}

/// P-AI：域名流量卡片（Top 域名 + AI 标记；数据源 `status.domain_stats`）。
/// 与三线表同构：表头细线 + 数据行，无竖线。
#[component]
pub fn AiTrafficCard(status: RwSignal<Option<StatusView>>) -> impl IntoView {
    let rows = Signal::derive(move || {
        let mut v = status
            .get()
            .map(|s| s.domain_stats.clone())
            .unwrap_or_default();
        v.truncate(10);
        v
    });
    view! {
        <section class="ai-card">
            <div class="t3-wrap">
                <table class="tbl-3line">
                    <thead>
                        <tr>
                            <th>"域名（按流量 Top）"</th>
                            <th>"AI"</th>
                            <th>"连接 活跃/累计"</th>
                            <th>"下行"</th>
                            <th>"上行"</th>
                            <th>"最近活动"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || {
                            let rs = rows.get();
                            if rs.is_empty() {
                                return view! {
                                    <tr class="ai-empty">
                                        <td colspan="6">
                                            "暂无域名流量（连接产生后出现；IP 直连目标无域名）"
                                        </td>
                                    </tr>
                                }
                                    .into_any();
                            }
                            rs.into_iter()
                                .map(|d| {
                                    view! {
                                        <tr class="ai-row">
                                            <td class="ai-dom">{d.domain.clone()}</td>
                                            <td class="ai-mark">
                                                {if d.ai { "●" } else { "·" }}
                                            </td>
                                            <td class="num">
                                                {format!("{} / {}", d.active, d.conns)}
                                            </td>
                                            <td class="num">{fmt_bytes(d.bytes_down)}</td>
                                            <td class="num">{fmt_bytes(d.bytes_up)}</td>
                                            <td class="dim">{fmt_ago(d.last_seen_secs_ago)}</td>
                                        </tr>
                                    }
                                })
                                .collect_view()
                                .into_any()
                        }}
                    </tbody>
                </table>
            </div>
        </section>
    }
}

/// 距今秒数 → 人类可读。
pub(crate) fn fmt_ago(secs: u64) -> String {
    match secs {
        0..=2 => "刚刚".to_string(),
        s if s < 60 => format!("{s}s 前"),
        s if s < 3600 => format!("{}m 前", s / 60),
        s => format!("{}h 前", s / 3600),
    }
}

/// 曲线行（活跃连接 / 吞吐 / 最优延迟）——与运行时卡片配套。
#[component]
pub fn TrendRow(
    status: RwSignal<Option<StatusView>>,
    series: RwSignal<Option<SeriesView>>,
) -> impl IntoView {
    let ts_all = Signal::derive(move || {
        series
            .get()
            .map(|s| s.points.iter().map(|p| p.t).collect::<Vec<u64>>())
            .unwrap_or_default()
    });
    // 单序列快捷构造（名称 / 色 / 取值函数）。
    let one = move |name: &'static str, color: &'static str, g: fn(&Sample) -> f64| {
        Signal::derive(move || {
            vec![CurveSerie::new(
                name,
                color,
                series
                    .get()
                    .map(|s| s.points.iter().map(g).collect::<Vec<f64>>())
                    .unwrap_or_default(),
            )]
        })
    };
    // 流量对比：代理（含面积）叠加在全网（WAN）之上——一图看清直连 vs 代理。
    let flows = Signal::derive(move || {
        let (mut px, mut wan) = (Vec::new(), Vec::new());
        if let Some(s) = series.get() {
            for p in &s.points {
                px.push((p.up_bps + p.down_bps) as f64 / 1024.0);
                wan.push((p.wan_up_bps + p.wan_down_bps) as f64 / 1024.0);
            }
        }
        vec![
            CurveSerie::new("代理", "#3c73ff", px),
            CurveSerie::new("全网", "#ff9e64", wan),
        ]
    });
    view! {
        <section class="charts">
            <Chart
                title="流量对比（代理 vs 全网）"
                hint=Signal::derive(move || {
                    series
                        .get()
                        .map(|s| {
                            s.points
                                .last()
                                .map(|p| {
                                    format!(
                                        "代理 ↑{} ↓{} · 全网 ↑{} ↓{}",
                                        fmt_rate(p.up_bps as f64),
                                        fmt_rate(p.down_bps as f64),
                                        fmt_rate(p.wan_up_bps as f64),
                                        fmt_rate(p.wan_down_bps as f64)
                                    )
                                })
                                .unwrap_or_default()
                        })
                        .unwrap_or_default()
                })
                ts=ts_all
                series=flows
                unit=" KB/s"
            />
            <Chart
                title="活跃连接"
                hint=Signal::derive(move || {
                    series.get().map(|s| format!("最近 {} 点 · {}s/点", s.points.len(), s.step_secs)).unwrap_or_default()
                })
                ts=ts_all
                series=one("连接", "#29ffa4", |s| s.conns_active as f64)
                unit=""
            />
            <Chart
                title="最优节点延迟"
                hint=Signal::derive(move || {
                    status.get().map(|s| format!("存活 {}/{}", s.group.alive, s.group.members)).unwrap_or_default()
                })
                ts=ts_all
                series=one("EMA", "#d0ff00", |s| s.ema_min)
                unit=" ms"
            />
        </section>
    }
}

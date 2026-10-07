//! 总览页的两个头部区块：
//! - `RuntimeCard`：引擎运行时（内存 / 线程 / FD / CPU + 控制动作）——页面重点
//! - `MetricsTable`：运行指标三线表（表头线 + 数据 + 注释行，无竖线）

use leptos::prelude::*;
use shared::{Sample, SeriesView, StatusView};

use crate::charts::{Chart, CurveSerie};
use crate::{fmt_bytes, fmt_rate, fmt_uptime, pct, ActionButton};

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
                </div>
            </div>
        </section>
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
fn fmt_ago(secs: u64) -> String {
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

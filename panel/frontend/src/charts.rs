// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! 纯 SVG 曲线（无 JS 图表依赖）：多序列叠加 + 十字光标（悬停查单点）。
//!
//! 十字光标：鼠标移动 → 吸附最近数据点 → 垂直虚线 + 各序列圆点 + tooltip
//! （时间 + 各序列值）；靠近右缘时 tooltip 自动左置，避免出界。

use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// 一条序列（values 与 x 轴对齐；第一条带面积高亮）。
#[derive(Clone, PartialEq)]
pub struct CurveSerie {
    pub name: String,
    pub color: String,
    pub values: Vec<f64>,
}

impl CurveSerie {
    pub fn new(name: &str, color: &str, values: Vec<f64>) -> Self {
        Self {
            name: name.to_string(),
            color: color.to_string(),
            values,
        }
    }
}

/// viewBox 宽度（CSS 层面按容器拉伸）。
const VW: f64 = 300.0;

/// 跨序列统一 y 轴范围。
fn bounds(ss: &[CurveSerie]) -> (f64, f64) {
    let mut max = 1e-9f64;
    let mut min = f64::MAX;
    let mut any = false;
    for s in ss {
        for v in &s.values {
            any = true;
            if *v > max {
                max = *v;
            }
            if *v < min {
                min = *v;
            }
        }
    }
    if !any {
        min = 0.0;
    }
    (min.min(max), max)
}

fn line_path(vals: &[f64], h: f64, min: f64, max: f64) -> String {
    let n = vals.len();
    if n < 2 {
        return String::new();
    }
    let span = (max - min).max(1e-9);
    let xf = |i: usize| i as f64 / (n - 1) as f64 * VW;
    let yf = |v: f64| h - ((v - min) / span) * (h - 8.0) - 4.0;
    let mut line = String::new();
    for (i, v) in vals.iter().enumerate() {
        line.push_str(if i == 0 { "M" } else { " L" });
        line.push_str(&format!("{:.1},{:.1}", xf(i), yf(*v)));
    }
    line
}

fn area_path(vals: &[f64], h: f64, min: f64, max: f64) -> String {
    let l = line_path(vals, h, min, max);
    if l.is_empty() {
        return l;
    }
    format!("{l} L{VW:.1},{h:.1} L0.0,{h:.1} Z")
}

/// 统一数值格式化（KB/s 与 ms 自适应，其余按原单位）。
pub fn fmt_val(v: f64, unit: &str) -> String {
    match unit {
        " KB/s" => {
            if v >= 1024.0 * 1024.0 {
                format!("{:.2} GB/s", v / 1024.0 / 1024.0)
            } else if v >= 1024.0 {
                format!("{:.1} MB/s", v / 1024.0)
            } else {
                format!("{v:.0} KB/s")
            }
        }
        " ms" => {
            if v >= 1000.0 {
                format!("{:.2} s", v / 1000.0)
            } else {
                format!("{v:.0} ms")
            }
        }
        _ => format!("{v:.0}{unit}"),
    }
}

/// Unix 秒 → 本地钟表时间（HH:MM:SS）。
fn fmt_ts(t: u64) -> String {
    let d = js_sys::Date::new(&(t as f64 * 1000.0).into());
    format!(
        "{:02}:{:02}:{:02}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds()
    )
}

/// 曲线卡：标题 + 提示 + 多序列折线/面积 + 十字光标 + 尾注。
#[component]
pub fn Chart(
    title: &'static str,
    hint: Signal<String>,
    /// 与各序列值对齐的时间戳（Unix 秒）。
    ts: Signal<Vec<u64>>,
    /// 序列（第一条带面积高亮）。
    series: Signal<Vec<CurveSerie>>,
    unit: &'static str,
    #[prop(optional)] foot_mid: Option<Signal<String>>,
    #[prop(optional)] compact: bool,
) -> impl IntoView {
    let h = if compact { 40.0 } else { 64.0 };
    let hover = RwSignal::new(None::<usize>);

    let paths = Signal::derive(move || {
        let ss = series.get();
        let (min, max) = bounds(&ss);
        ss.iter()
            .map(|s| line_path(&s.values, h, min, max))
            .collect::<Vec<String>>()
    });
    let area = Signal::derive(move || {
        let ss = series.get();
        let (min, max) = bounds(&ss);
        ss.first()
            .map(|s| area_path(&s.values, h, min, max))
            .unwrap_or_default()
    });
    let area_color = Signal::derive(move || {
        series
            .get()
            .first()
            .map(|s| s.color.clone())
            .unwrap_or_default()
    });
    // 十字光标：垂直线 x + 各序列吸附点 (x, y, color)
    let cross = Signal::derive(move || {
        let idx = hover.get()?;
        let ss = series.get();
        let n = ss.first().map(|s| s.values.len()).unwrap_or(0);
        if n < 2 || idx >= n {
            return None;
        }
        let (min, max) = bounds(&ss);
        let span = (max - min).max(1e-9);
        let x = idx as f64 / (n - 1) as f64 * VW;
        let pts: Vec<(String, String, String)> = ss
            .iter()
            .filter(|s| idx < s.values.len())
            .map(|s| {
                let y = h - ((s.values[idx] - min) / span) * (h - 8.0) - 4.0;
                (format!("{x:.1}"), format!("{y:.1}"), s.color.clone())
            })
            .collect();
        Some((format!("{x:.1}"), pts))
    });
    // tooltip：时间 + 各序列值
    let tip = Signal::derive(move || {
        let idx = hover.get()?;
        let ss = series.get();
        let t = ts.get().get(idx).copied();
        let rows: Vec<(String, String, String)> = ss
            .iter()
            .filter(|s| idx < s.values.len())
            .map(|s| {
                (
                    s.color.clone(),
                    s.name.clone(),
                    fmt_val(s.values[idx], unit),
                )
            })
            .collect();
        if rows.is_empty() {
            return None;
        }
        Some((t.map(fmt_ts).unwrap_or_default(), rows))
    });
    // 鼠标在左半区 → tooltip 靠右，反之靠左（不出界）。
    let tip_align_right = Signal::derive(move || {
        let Some(idx) = hover.get() else { return true };
        let n = series
            .get()
            .first()
            .map(|s| s.values.len())
            .unwrap_or(2)
            .max(2);
        (idx as f64 / (n - 1) as f64) < 0.5
    });

    let on_move = move |ev: leptos::ev::MouseEvent| {
        let n = series
            .get_untracked()
            .first()
            .map(|s| s.values.len())
            .unwrap_or(0);
        if n < 2 {
            return;
        }
        let w = ev
            .current_target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            .map(|e| e.client_width() as f64)
            .unwrap_or(VW)
            .max(1.0);
        let idx = ((ev.offset_x() as f64 / w) * (n as f64 - 1.0)).round() as i64;
        hover.set(Some(idx.clamp(0, n as i64 - 1) as usize));
    };
    let on_leave = move |_| hover.set(None);

    let svg_cls = if compact {
        "chart-svg chart-svg-sm"
    } else {
        "chart-svg"
    };
    let h_attr = format!("0 0 300 {h:.0}");
    let h_str = format!("{h:.0}");

    view! {
        <div class="chart">
            <div class="chart-head">
                <span class="chart-title">{title}</span>
                <span class="chart-hint">{move || hint.get()}</span>
            </div>
            <div class="chart-wrap">
                <svg class=svg_cls viewBox=h_attr preserveAspectRatio="none"
                    on:mousemove=on_move on:mouseleave=on_leave>
                    <path d=move || area.get() fill=area_color fill-opacity="0.09" stroke="none"></path>
                    {move || {
                        let ps = paths.get();
                        let cs = series.get();
                        ps.into_iter()
                            .enumerate()
                            .map(|(i, d)| {
                                let c = cs.get(i).map(|s| s.color.clone()).unwrap_or_default();
                                view! { <path d=d fill="none" stroke=c stroke-width="1.2"></path> }
                            })
                            .collect_view()
                    }}
                    {move || {
                        cross
                            .get()
                            .map(|(x, pts)| {
                                view! {
                                    <g>
                                        <line
                                            x1=x.clone()
                                            y1="0"
                                            x2=x.clone()
                                            y2=h_str.clone()
                                            stroke="#8a8f98"
                                            stroke-width="0.6"
                                            stroke-dasharray="2,2"
                                        ></line>
                                        {pts
                                            .into_iter()
                                            .map(|(px, py, c)| {
                                                view! { <circle cx=px cy=py r="2.2" fill=c></circle> }
                                            })
                                            .collect_view()}
                                    </g>
                                }
                            })
                    }}
                </svg>
                {move || {
                    tip.get()
                        .map(|(t, rows)| {
                            view! {
                                <div
                                    class="chart-tip"
                                    class:chart-tip-right=move || tip_align_right.get()
                                >
                                    <div class="chart-tip-t">{t}</div>
                                    {rows
                                        .into_iter()
                                        .map(|(c, name, v)| {
                                            view! {
                                                <div class="tip-row">
                                                    <i class="tip-dot" style=format!("background:{c}")></i>
                                                    <span class="tip-name">{name}</span>
                                                    <span class="tip-val">{v}</span>
                                                </div>
                                            }
                                        })
                                        .collect_view()}
                                </div>
                            }
                        })
                }}
            </div>
            <div class="chart-foot">
                {move || {
                    series
                        .get()
                        .iter()
                        .map(|s| {
                            let c = s.color.clone();
                            let v = s.values.last().copied().unwrap_or(0.0);
                            view! {
                                <span class="mono">
                                    <i class="tip-dot" style=format!("background:{c}")></i>
                                    {fmt_val(v, unit)}
                                </span>
                            }
                        })
                        .collect_view()
                }}
                {foot_mid.map(|s| view! { <span class="mono dim">{move || s.get()}</span> })}
                <span class="mono dim">
                    {move || {
                        let ss = series.get();
                        let peak = ss
                            .first()
                            .map(|s| s.values.iter().cloned().fold(f64::MIN, f64::max))
                            .unwrap_or(0.0);
                        format!("峰值 {}", fmt_val(peak.max(0.0), unit))
                    }}
                </span>
            </div>
        </div>
    }
}

//! 纯 SVG 曲线（无 JS 图表依赖）。

use leptos::prelude::*;

fn geom(vals: &[f64], h: f64) -> (String, String, f64, f64) {
    let n = vals.len();
    let w = 300.0f64;
    if n < 2 {
        return (String::new(), String::new(), 0.0, 0.0);
    }
    let max = vals.iter().cloned().fold(f64::MIN, f64::max).max(1e-9);
    let min = vals.iter().cloned().fold(f64::MAX, f64::min).min(max);
    let span = (max - min).max(1e-9);
    let x = |i: usize| i as f64 / (n - 1) as f64 * w;
    let y = |v: f64| h - ((v - min) / span) * (h - 8.0) - 4.0;
    let mut line = String::new();
    for (i, v) in vals.iter().enumerate() {
        line.push_str(if i == 0 { "M" } else { " L" });
        line.push_str(&format!("{:.1},{:.1}", x(i), y(*v)));
    }
    let area = format!("{line} L{w:.1},{h:.1} L0.0,{h:.1} Z");
    let last = *vals.last().unwrap_or(&0.0);
    (line, area, last, max)
}

/// 一条曲线：标题 + 提示 + 面积图 + 当前/峰值（可选中间脚注与紧凑高度）。
#[component]
pub fn Chart(
    title: &'static str,
    hint: Signal<String>,
    values: Signal<Vec<f64>>,
    color: &'static str,
    unit: &'static str,
    #[prop(optional)] foot_mid: Option<Signal<String>>,
    #[prop(optional)] compact: bool,
) -> impl IntoView {
    // 紧凑型（运行时卡片里的第二条曲线）矮一些，避免首屏过高；手机上也更好读。
    let h = if compact { 40.0 } else { 64.0 };
    let line = Signal::derive(move || geom(&values.get(), h).0);
    let area = Signal::derive(move || geom(&values.get(), h).1);
    let last = Signal::derive(move || geom(&values.get(), h).2);
    let peak = Signal::derive(move || geom(&values.get(), h).3);
    let svg_cls = if compact {
        "chart-svg chart-svg-sm"
    } else {
        "chart-svg"
    };
    view! {
        <div class="chart">
            <div class="chart-head">
                <span class="chart-title">{title}</span>
                <span class="chart-hint">{move || hint.get()}</span>
            </div>
            <svg class=svg_cls viewBox=format!("0 0 300 {h:.0}") preserveAspectRatio="none">
                <path d=move || area.get() fill=color fill-opacity="0.09" stroke="none"></path>
                <path d=move || line.get() fill="none" stroke=color stroke-width="1.2"></path>
            </svg>
            <div class="chart-foot">
                <span class="mono">{move || format!("{:.0}{}", last.get(), unit)}</span>
                {foot_mid.map(|s| view! { <span class="mono dim">{move || s.get()}</span> })}
                <span class="mono dim">{move || format!("峰值 {:.0}{}", peak.get(), unit)}</span>
            </div>
        </div>
    }
}

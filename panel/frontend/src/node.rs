//! 单节点详情：延迟/健康历史（内存环形缓冲）+ 曲线。

use leptos::prelude::*;
use shared::NodeDetail;

use crate::charts::Chart;
use crate::get_json;

/// 拉取某节点详情到 `detail`。
pub fn load_node(
    detail: RwSignal<Option<NodeDetail>>,
    token: RwSignal<Option<String>>,
    tag: String,
    name: String,
) {
    let tok = token.get_untracked();
    leptos::task::spawn_local(async move {
        let path = format!(
            "/api/v1/node?tag={}&name={}",
            urlencode(&tag),
            urlencode(&name)
        );
        if let Ok(d) = get_json::<NodeDetail>(&path, tok.as_deref()).await {
            detail.set(Some(d));
        }
    });
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[component]
pub fn NodeModal(detail: RwSignal<Option<NodeDetail>>) -> impl IntoView {
    view! {
        {move || detail.get().map(|d| {
            let emas: Vec<f64> = d.samples.iter().map(|p| p.ema_ms).collect();
            let alive_ratio = if d.samples.is_empty() {
                0.0
            } else {
                d.samples.iter().filter(|p| p.alive).count() as f64 * 100.0 / d.samples.len() as f64
            };
            let min = emas.iter().cloned().fold(f64::MAX, f64::min);
            let max = emas.iter().cloned().fold(f64::MIN, f64::max);
            let avg = if emas.is_empty() { 0.0 } else { emas.iter().sum::<f64>() / emas.len() as f64 };
            let (min, max) = if emas.is_empty() { (0.0, 0.0) } else { (min, max) };
            let chart_vals = emas.clone();
            let chart_len = emas.len();
            view! {
                <div class="modal-mask">
                    <div class="modal modal-narrow">
                        <div class="modal-head">
                            <span class="panel-title">"节点详情"</span>
                            <span class="panel-meta">{format!("{} · 来源 {}", d.name.clone(), d.tag.clone())}</span>
                            <div class="modal-actions">
                                <button class="btn" on:click=move |_| detail.set(None)>"关闭"</button>
                            </div>
                        </div>
                        <div class="modal-body modal-body-col">
                            <div class="grid grid-4">
                                <div class="card">
                                    <div class="card-label">"状态"</div>
                                    <div class="card-value">
                                        {if d.alive { "存活" } else { "不可用" }}
                                        <span class="card-unit">{format!("{alive_ratio:.1}% 采样存活")}</span>
                                    </div>
                                    <div class="card-hint">{format!("{} 个采样点", d.samples.len())}</div>
                                </div>
                                <div class="card">
                                    <div class="card-label">"EMA 延迟"</div>
                                    <div class="card-value">{format!("{:.0}", d.ema_ms)}<span class="card-unit">"ms"</span></div>
                                    <div class="card-hint">{format!("最近一次 {} ms", d.last_ms)}</div>
                                </div>
                                <div class="card">
                                    <div class="card-label">"历史区间"</div>
                                    <div class="card-value">{format!("{:.0}–{:.0}", min, max)}<span class="card-unit">"ms"</span></div>
                                    <div class="card-hint">{format!("均值 {avg:.0} ms")}</div>
                                </div>
                            </div>
                            <div class="grid grid-4">
                                <div class="card">
                                    <div class="card-label">"协议"</div>
                                    <div class="card-value card-value-sm">
                                        {d.protocol.clone()}
                                        <span class="card-unit">{d.security.clone()}</span>
                                    </div>
                                    <div class="card-hint">{format!("传输 {} · 来源 {}", d.transport, d.tag)}</div>
                                </div>
                                <div class="card">
                                    <div class="card-label">"UDP 承载"</div>
                                    <div class="card-value card-value-sm">
                                        {if d.udp { "支持" } else { "不支持" }}
                                    </div>
                                    <div class="card-hint">"协议能力；分流当前把 UDP 送 direct"</div>
                                </div>
                                <div class="card">
                                    <div class="card-label">"服务器"</div>
                                    <div class="card-value card-value-sm">{d.addr.clone()}</div>
                                    <div class="card-hint">"节点名 "{d.name.clone()}</div>
                                </div>
                            </div>
                            <div class="panel">
                                <div class="panel-head"><span class="panel-title">"延迟历史（EMA ms）"</span></div>
                                <div class="chart-embed">
                                    <Chart title="EMA" hint=Signal::derive(move || format!("{chart_len} 点"))
                                           values=Signal::derive(move || chart_vals.clone())
                                           color="#d0ff00" unit=" ms"/>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            }
        })}
    }
}

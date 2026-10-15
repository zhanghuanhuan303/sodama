//! C3：事件通道（ringbuf + 每键限速），对照 dae `send_dae_event` /
//! `blocked_event_rate_limited`（`dae/control/kern/tproxy.c:749-875`）。
//!
//! 替代旧的 per-packet `bpf_printk`：printk 在 release 构建里是 trace 侧成本，
//! 且用户态无法结构化消费。事件走 ringbuf，loader 侧线程解码后写日志/计数。
//!
//! 两条可观测性原则（继承 dae）：
//!   1. 计数永远按次推进（`bump_stat`），事件只做「限速采样」——洪泛时日志不刷爆；
//!   2. ringbuf 满导致丢弃时要可数（`SODAMA_STAT_EVENT_DROPS`），否则丢事件是静默的。

use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

use crate::common::*;
use crate::maps::*;

/// 累加一件数据面统计（per-CPU array，无需原子）。
#[inline(always)]
pub unsafe fn bump_stat(key: u32) {
    if let Some(v) = sodama_stats_map.get_ptr_mut(key) {
        *v += 1;
    }
}

/// 限速判定：本 CPU 上该键在窗口内是否已发过事件。
/// 返回 `true` = 本次应当限速（不发送）。
///
/// 顺序与 dae 一致：**先读旧值再取现在**，保证 `now >= old`（同一 CPU 上单调时钟
/// 不回退），避免无符号减法下溢成大数而误判「窗口已过」。
#[inline(always)]
unsafe fn rate_limited(key: u32) -> bool {
    let Some(last) = event_rate_map.get_ptr_mut(key) else {
        /* 取不到限速槽：宁可不发（限速优先于可观测性）。 */
        return true;
    };
    let old = *last;
    let now = bpf_ktime_get_ns();
    if now.wrapping_sub(old) < SODAMA_EVENT_RATE_WINDOW_NS {
        return true;
    }
    *last = now;
    false
}

/// 发一条事件（不做限速；调用方自行决定）。`tuple` 为 `None` 时地址/端口清零
/// （对照 dae `send_dae_event` 的 NULL sip/dip 分支）。
///
/// `pid/pname` 恒置 0：TC/sk_skb 上下文拿不到进程信息（sodama 的 pname 采集在
/// cgroup 钩子，只有 WAN egress 新连接能按 socket cookie 反查），dae 的 TC 路径
/// 同样传 `pid=0, pname=NULL`。
#[inline(always)]
pub unsafe fn send_event(type_: u32, outbound: u8, l4proto: u8, tuple: Option<&SodaTuple>) {
    let mut ev = SodaEvent {
        timestamp: bpf_ktime_get_ns(),
        type_,
        pid: 0,
        pname: [0u8; 16],
        outbound,
        l4proto,
        pad: [0u8; 2],
        sip: [0u8; 16],
        dip: [0u8; 16],
        sport: 0,
        dport: 0,
    };
    if let Some(t) = tuple {
        ev.sip = t.sip;
        ev.dip = t.dip;
        ev.sport = t.sport;
        ev.dport = t.dport;
        ev.l4proto = t.l4proto;
    }

    /* 满（-E2BIG/-ENOSPC）与其它错误都只记一次丢弃：事件本身就丢了。 */
    if event_ringbuf.output(&ev, 0).is_err() {
        bump_stat(SODAMA_STAT_EVENT_DROPS);
    }
}

/// 限速发一条事件：每 CPU 每键每秒最多一条（见 `maps.rs::event_rate_map` 的说明）。
#[inline(always)]
pub unsafe fn send_event_limited(
    rate_key: u32,
    type_: u32,
    outbound: u8,
    l4proto: u8,
    tuple: Option<&SodaTuple>,
) -> bool {
    if rate_limited(rate_key) {
        return false;
    }
    send_event(type_, outbound, l4proto, tuple);
    true
}

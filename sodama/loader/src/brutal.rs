// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! P5-G3b+：Brutal 拥塞控制的近似移植（ADR-0020）。
//!
//! Go 侧 hysteria2 客户端在认证成功后按 `min(server_rx, client_tx)` 安装 **Brutal**
//! 发送器（`protocol/tuic/congestion.UseBrutal`）：固定速率 + 不因丢包降速 + 窗口 = 2×BDP。
//! quinn 的 `Controller` 只有「发送事件 / ack / 丢包事件 / 窗口」粒度，拿不到 pacer 的
//! 直接控制权，所以这里做**近似**：
//!
//! - 速率目标用 `Arc<AtomicU64>` 与认证流程解耦（认证后才知道 server_rx）；
//! - 目标 = 0 时完全委托给 inner（quinn BBR，近似 Go 侧 bbr3 默认的探测行为）；
//! - 目标 > 0 时 `window() = max(2×mtu, target × srtt)`，且**忽略丢包事件对窗口的影响**；
//!   quinn 自带的 pacer 由窗口推导（窗口/RTT 比例 + 25% 余量），因此实际发送速率
//!   会被放大约 1.25×——这是与真 Brutal 的已知差异，记入 ADR-0020。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

/// Brutal 目标窗口（字节）：`max(2×mtu, rate × rtt)`。
pub fn brutal_window(rate_bps: u64, rtt: Duration, mtu: u64) -> u64 {
    let by_rtt = (rate_bps as u128 * rtt.as_nanos() / 1_000_000_000) as u64;
    by_rtt.max(2 * mtu).max(2 * 1200)
}

/// 速率目标句柄（认证成功后由 hysteria2 层写入）。
#[derive(Clone, Debug)]
pub struct RateTarget {
    rate: Arc<AtomicU64>,
}

impl RateTarget {
    pub fn set(&self, bytes_per_sec: u64) {
        self.rate.store(bytes_per_sec, Ordering::Relaxed);
    }
}

/// 生成 (速率句柄, 控制器工厂)：inner 固定为 quinn BBR；目标 > 0 时切换成 Brutal 窗口。
pub fn hybrid_bbr() -> (RateTarget, Arc<dyn ControllerFactory + Send + Sync>) {
    let rate = Arc::new(AtomicU64::new(0));
    (
        RateTarget { rate: rate.clone() },
        Arc::new(HybridFactory { rate }),
    )
}

struct HybridFactory {
    rate: Arc<AtomicU64>,
}

struct HybridController {
    inner: Box<dyn Controller>,
    rate: Arc<AtomicU64>,
    mtu: u64,
    rtt: Duration,
}

impl HybridController {
    fn brutal_window(&self) -> u64 {
        brutal_window(self.rate.load(Ordering::Relaxed), self.rtt, self.mtu)
    }

    fn brutal_active(&self) -> bool {
        self.rate.load(Ordering::Relaxed) > 0
    }
}

impl Controller for HybridController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
        self.rtt = rtt.get();
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // inner 维护自身状态；Brutal 窗口不随丢包收缩（窗口由 rate×rtt 决定）
        self.inner
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.inner.on_mtu_update(new_mtu);
        self.mtu = new_mtu as u64;
    }

    fn window(&self) -> u64 {
        if self.brutal_active() {
            self.brutal_window()
        } else {
            self.inner.window()
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        if self.brutal_active() {
            let mut m = ControllerMetrics::default();
            m.congestion_window = self.brutal_window();
            m.pacing_rate = Some(self.rate.load(Ordering::Relaxed).saturating_mul(8));
            m
        } else {
            self.inner.metrics()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            rate: self.rate.clone(),
            mtu: self.mtu,
            rtt: self.rtt,
        })
    }

    fn initial_window(&self) -> u64 {
        if self.brutal_active() {
            self.brutal_window()
        } else {
            self.inner.initial_window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

impl ControllerFactory for HybridFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let inner = Arc::new(BbrConfig::default()).build(now, current_mtu);
        Box::new(HybridController {
            inner,
            rate: self.rate.clone(),
            mtu: current_mtu as u64,
            // quinn 的初始 RTT 估计为 333ms；这里给一个中性初值，ack 后即被 srtt 覆盖
            rtt: Duration::from_millis(100),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_math() {
        // 1 MB/s × 100ms = 100KB；远大于 2×mtu
        assert_eq!(
            brutal_window(1_000_000, Duration::from_millis(100), 1200),
            100_000
        );
        // 低速率时下限 = 2×mtu
        assert_eq!(brutal_window(1000, Duration::from_millis(10), 1200), 2400);
        // 亚毫秒 RTT 也不为零
        assert_eq!(brutal_window(1, Duration::from_nanos(1), 1200), 2400);
    }

    #[test]
    fn hybrid_switches_on_target() {
        let (target, factory) = hybrid_bbr();
        let c = factory.build(Instant::now(), 1200);
        let probing = c.window();
        assert!(probing >= 2 * 1200);
        // 目标未设置：窗口由 inner（BBR）决定，通常等于初始窗口
        assert_eq!(probing, c.initial_window());
        target.set(4_000_000); // 4 MB/s（× 初始 100ms = 400KB，大于 BBR 初始窗口）
        let w = c.window();
        assert!(w > probing, "brutal 窗口 {w} 应大于探测窗口 {probing}");
        assert_eq!(w, 400_000);
        assert_eq!(c.initial_window(), 400_000);
        // clone_box 共享同一个速率句柄
        let mut c2 = c.clone_box();
        target.set(5_000_000);
        assert_eq!(c2.window(), 500_000);
        c2.on_mtu_update(1400);
        assert_eq!(c2.window(), 500_000);
    }
}

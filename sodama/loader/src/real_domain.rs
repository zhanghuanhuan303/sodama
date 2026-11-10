// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! A2 #10：`real_domain_runtime`——「已验证真实域名」的确认集与负缓存
//! （对照 dae `control/real_domain_runtime.go` + `control_plane_dialtarget.go`）。
//!
//! 问题：`dial_mode: domain` 时嗅探到的域名会直接交给节点远端解析；但有些「域名」
//! （内网名、被中间设备篡改的 SNI、随机字符串）在公网根本解析不到，交远端解析必然
//! 拨号失败——**每次连接都要走完整失败链**。dae 的对策：
//!
//! 1. DNS 控制器「已知」该域名（我们的 DNS 缓存有 A/AAAA）→ 视为真实域名，域名拨号；
//! 2. 否则查确认集（容量 8192 的 FIFO）：命中即域名拨号；
//! 3. 否则**异步探测**（bootstrap/fallback 解析）并**本次按 IP 拨号**（不阻塞首屏路径）；
//!    探测成功 → 记入确认集；失败 → 负缓存（TTL 内不再探测）。
//!
//! sodama 与 dae 的差异（如实）：dae 的确认集/负缓存按单飞（singleflight）合并并发探测，
//! 这里用「进行中集合」近似（同域名并发探测只跑一个）；负缓存 TTL 取 300s。

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 确认集容量（对照 dae `realDomainSetCapacity`）。
pub const CAPACITY: usize = 8192;
/// 负缓存 TTL（dae `realDomainNegativeCacheTTL`）。
pub const NEG_TTL: Duration = Duration::from_secs(300);

#[derive(Default)]
struct State {
    confirmed: HashSet<String>,
    /// FIFO 顺序（确认集的淘汰顺序）。
    order: VecDeque<String>,
    /// 负缓存：域名 → 过期时刻。
    negative: HashMap<String, Instant>,
    /// 探测进行中（单飞近似）。
    inflight: HashSet<String>,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State::default()))
}

fn lock_state() -> std::sync::MutexGuard<'static, State> {
    match state().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// 探测计数（status 面）。
#[derive(Default)]
pub struct RealDomainStats {
    pub probes: std::sync::atomic::AtomicU64,
    pub confirmed_total: std::sync::atomic::AtomicU64,
    pub negative_total: std::sync::atomic::AtomicU64,
    pub hits: std::sync::atomic::AtomicU64,
}
pub static STATS: RealDomainStats = RealDomainStats {
    probes: std::sync::atomic::AtomicU64::new(0),
    confirmed_total: std::sync::atomic::AtomicU64::new(0),
    negative_total: std::sync::atomic::AtomicU64::new(0),
    hits: std::sync::atomic::AtomicU64::new(0),
};

/// IP 字面量形态的「域名」（对照 dae `isIPLikeDomain`：`1.2.3.4` / `[::1]` / `host:port`）。
pub fn is_ip_like(domain: &str) -> bool {
    let d = domain.trim_matches(['[', ']']);
    if d.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Some((host, port)) = d.rsplit_once(':') {
        if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() && port.parse::<u16>().is_ok() {
            return true;
        }
        // 裸 IPv6（含 `::`）在无端口时上面已覆盖；带端口但 host 非 IP → 不是
    }
    false
}

/// 查询确认状态：`Some(true)` = 已确认；`Some(false)` = 负缓存命中；`None` = 未知。
pub fn lookup(domain: &str, now: Instant) -> Option<bool> {
    {
        let g = lock_state();
        if g.confirmed.contains(domain) {
            STATS
                .hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(true);
        }
        if let Some(exp) = g.negative.get(domain) {
            if *exp > now {
                return Some(false);
            }
        }
    }
    // 过期负缓存条目惰性清理。
    let mut g = lock_state();
    if let Some(exp) = g.negative.get(domain) {
        if *exp <= now {
            g.negative.remove(domain);
        }
    }
    None
}

/// 记入确认集（FIFO 淘汰；已存在不重复入队）。
pub fn remember(domain: &str) {
    let mut g = lock_state();
    if g.confirmed.insert(domain.to_string()) {
        g.order.push_back(domain.to_string());
        STATS
            .confirmed_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        while g.order.len() > CAPACITY {
            if let Some(old) = g.order.pop_front() {
                g.confirmed.remove(&old);
            }
        }
    }
    g.negative.remove(domain);
}

/// 记入负缓存（TTL `NEG_TTL`）。
pub fn remember_negative(domain: &str, now: Instant) {
    let mut g = lock_state();
    g.negative.insert(domain.to_string(), now + NEG_TTL);
    STATS
        .negative_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// 尝试启动一次探测（单飞近似：同域名已有探测在跑则不重复）。
/// 返回 `true` = 本次调用实际启动了探测（调用方本连接按 IP 拨号）。
pub fn trigger_probe(domain: &str) -> bool {
    if is_ip_like(domain) {
        return false;
    }
    {
        let mut g = lock_state();
        if g.confirmed.contains(domain) || g.inflight.contains(domain) {
            return false;
        }
        g.inflight.insert(domain.to_string());
    }
    STATS
        .probes
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = domain.to_string();
    std::thread::Builder::new()
        .name("real-domain-probe".into())
        .spawn(move || {
            let ok = probe(&d);
            {
                let mut g = lock_state();
                g.inflight.remove(&d);
            }
            let now = Instant::now();
            if ok {
                remember(&d);
                crate::log_debug(&format!("real_domain: {d} 探测成功（记入确认集）"));
            } else {
                remember_negative(&d, now);
                crate::log_debug(&format!("real_domain: {d} 探测失败（负缓存 {NEG_TTL:?}）"));
            }
        })
        .ok();
    true
}

/// 探测实现：bootstrap → fallback_resolver → 系统解析器（与节点解析同链）。
/// 注意：systemd-resolved 等环境里的系统解析对不存在域名可能返回合成地址——
/// 这里以「能解析出 ≥1 个地址」为准（与 dae 的 bootstrap 探测同口径）。
fn probe(domain: &str) -> bool {
    let host = domain.trim_matches(['[', ']']);
    if crate::bootstrap::enabled() {
        if let Ok(v) = crate::bootstrap::resolve_host(host) {
            if !v.is_empty() {
                return true;
            }
        }
    }
    if let Some(f) = crate::sticky::fallback_resolver() {
        if let Ok(v) = crate::bootstrap::query_server(f, host) {
            if !v.is_empty() {
                return true;
            }
        }
    }
    std::net::ToSocketAddrs::to_socket_addrs(&(host, 0))
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}

/// 状态面快照。
pub fn snapshot() -> serde_json::Value {
    let g = lock_state();
    serde_json::json!({
        "confirmed": g.confirmed.len(),
        "negative": g.negative.len(),
        "inflight": g.inflight.len(),
        "capacity": CAPACITY,
        "probes": STATS.probes.load(std::sync::atomic::Ordering::Relaxed),
        "confirmed_total": STATS.confirmed_total.load(std::sync::atomic::Ordering::Relaxed),
        "negative_total": STATS.negative_total.load(std::sync::atomic::Ordering::Relaxed),
        "hits": STATS.hits.load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ip_like_detects_literals() {
        assert!(is_ip_like("1.2.3.4"));
        assert!(is_ip_like("1.2.3.4:443"));
        assert!(is_ip_like("[2606:4700::1]"));
        assert!(is_ip_like("[2606:4700::1]:443"));
        assert!(!is_ip_like("example.com"));
        assert!(!is_ip_like("example.com:443"));
    }

    #[test]
    fn fifo_eviction_and_negative_cache() {
        let now = Instant::now();
        // 负缓存：命中 → Some(false)；过期 → None（惰性清理）
        remember_negative("neg.test", now);
        assert_eq!(
            lookup("neg.test", now + Duration::from_secs(1)),
            Some(false)
        );
        assert_eq!(
            lookup("neg.test", now + NEG_TTL + Duration::from_secs(1)),
            None
        );
        // 确认集 + FIFO 淘汰（用小容量路径无法直接改常量，改用批量插入验证总数不超限）
        for i in 0..(CAPACITY + 10) {
            remember(&format!("d{i}.test"));
        }
        let g = lock_state();
        assert!(g.confirmed.len() <= CAPACITY, "确认集不得超容量");
        assert!(!g.confirmed.contains("d0.test"), "最老的条目应被淘汰");
        assert!(g.confirmed.contains(&format!("d{}.test", CAPACITY + 9)));
    }

    #[test]
    fn remember_clears_negative_and_hits_count() {
        let now = Instant::now();
        remember_negative("flip.test", now);
        assert_eq!(lookup("flip.test", now), Some(false));
        remember("flip.test");
        assert_eq!(lookup("flip.test", now), Some(true), "确认后负缓存应被清除");
    }
}

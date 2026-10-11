//! P23：代理服务器域名的粘滞 IP（对照 dae `StickyIpDialer`/`ProxyIpCache`）。
//!
//! 代理节点地址是域名时（如 `ss://…@node.example.com:8388`），每次拨号都重新解析
//! 会因 DNS 轮询/污染换 IP，导致同一节点时好时坏。dae 的对策（`sticky_cache.go`）：
//!
//! - 解析一次后**钉住**该 IP（粘滞），后续拨号直接用；
//! - **连续 3 次**拨号失败（`maxConsecutiveFailures`）→ 作废缓存并重新解析（故障转移）；
//! - 成功一次即清零失败计数（`recordProxySuccess`）；
//! - reload 时重置全局状态（`ResetGlobalProxyStateForReload`），避免继承坏状态。
//!
//! 与 dae 的差异（如实）：dae 的健康检查周期（`IncrementCheckCycle`）与
//! 协议/IP 版本维度缓存更细；这里按「条目 TTL + 失败计数」近似，覆盖同样的
//! 可观察行为：不抖动 + 失败自动换 IP。
//!
//! 修正（2026-10-11，生产 §10/§11）：作废/TTL 到期后的重解析从「仅解析期」
//! 修正为「每次拨号」——接入点是 `outbound::marked_tcp_connect`（§resolve_for_dial）。

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 连续失败多少次作废粘滞 IP（dae `maxConsecutiveFailures`）。
const FAIL_THRESHOLD: u32 = 3;
/// 条目最长粘滞时间；过期后**下次拨号**重新走 DNS（近似 dae 的健康检查周期刷新）。
const ENTRY_TTL: Duration = Duration::from_secs(600);

struct Entry {
    addr: SocketAddr,
    resolved_at: Instant,
    failures: u32,
}

#[derive(Default)]
struct State {
    /// host:port（原始输入）→ 粘滞条目
    by_key: HashMap<String, Entry>,
    /// 已解析地址 → 域名 host:port（拨号失败/重解析只能拿到地址；
    /// 条目被作废后 origin 仍保留——不然没法知道该重解析谁）。
    origin: HashMap<SocketAddr, String>,
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

/// 解析函数抽出便于单测注入。
fn resolve_with<F>(hostport: &str, resolve_fn: F, now: Instant) -> Result<SocketAddr, String>
where
    F: FnOnce(&str) -> Result<Vec<SocketAddr>, String>,
{
    // IP 字面量直通（dae needsStickyIpCaching：IP 不需要缓存）。
    if let Ok(a) = hostport.parse::<SocketAddr>() {
        return Ok(a);
    }
    {
        let st = lock_state();
        if let Some(e) = st.by_key.get(hostport) {
            if now.saturating_duration_since(e.resolved_at) < ENTRY_TTL {
                return Ok(e.addr);
            }
        }
    }
    let addrs = resolve_fn(hostport)?;
    let first = addrs
        .first()
        .copied()
        .ok_or_else(|| format!("解析 {hostport} 无结果"))?;
    // 数据面协议只吃 IPv4：节点域名常同时有 AAAA（双栈 VPS），v6 优先会误拒。
    let chosen = if first.is_ipv4() {
        first
    } else {
        addrs.iter().find(|a| a.is_ipv4()).copied().unwrap_or(first)
    };
    let mut st = lock_state();
    let prev = st.by_key.get(hostport).map(|e| e.addr);
    st.origin.insert(chosen, hostport.to_string());
    st.by_key.insert(
        hostport.to_string(),
        Entry {
            addr: chosen,
            resolved_at: now,
            failures: 0,
        },
    );
    // 只在首次固定或 IP 变化时打日志（TTL 到期同 IP 重钉、失败重解析回同 IP 都不刷屏）。
    if prev != Some(chosen) {
        crate::log(&format!("sticky: {hostport} → {chosen}（粘滞 IP 已固定）"));
    }
    Ok(chosen)
}

/// 解析代理服务器地址（域名时粘滞；IP 字面量直通）。
pub fn resolve(hostport: &str) -> Result<SocketAddr, String> {
    resolve_with(
        hostport,
        |hp| {
            let addrs: Vec<SocketAddr> = hp
                .to_socket_addrs()
                .map_err(|e| format!("解析 {hp} 失败: {e}"))?
                .collect();
            Ok(addrs)
        },
        Instant::now(),
    )
}

/// P0（2026-10-11）：**拨号时**重解析——把 pinned 地址换成粘滞缓存的「当前有效」地址。
///
/// 旧实现只在 `parse_*` 解析期把域名固定成 `SocketAddr`，而「作废粘滞 IP」后
/// **没有任何运行时路径再解析**——机场轮换入口后，钉到旧 IP 的节点永远死亡
/// （生产实测：subA 63 个节点 57 个死透，直到进程重启重掷骰子）。
/// 现在每次拨号经过本函数：
/// - 非域名源（不在 origin 表）→ 原地址直通（零额外开销）；
/// - 域名源且钉仍有效（未失效、未超 TTL）→ 原地址；
/// - 已作废 / 超 TTL / 已被换到别的 IP → 重新走 DNS（失败则退回原 IP，不打断拨号）。
pub fn resolve_for_dial(pinned: SocketAddr) -> SocketAddr {
    resolve_for_dial_with(
        pinned,
        |hp| {
            let addrs: Vec<SocketAddr> = hp
                .to_socket_addrs()
                .map_err(|e| format!("解析 {hp} 失败: {e}"))?
                .collect();
            Ok(addrs)
        },
        Instant::now(),
    )
}

/// 抽出可注入解析函数便于单测。
fn resolve_for_dial_with<F>(pinned: SocketAddr, resolve_fn: F, now: Instant) -> SocketAddr
where
    F: FnOnce(&str) -> Result<Vec<SocketAddr>, String>,
{
    let host = {
        let st = lock_state();
        let Some(host) = st.origin.get(&pinned) else {
            return pinned;
        };
        if let Some(e) = st.by_key.get(host) {
            if e.addr == pinned && now.saturating_duration_since(e.resolved_at) < ENTRY_TTL {
                return pinned;
            }
        }
        host.clone()
    };
    match resolve_with(&host, resolve_fn, now) {
        Ok(a) => a,
        Err(_) => pinned,
    }
}

/// 拨号结果反馈：失败累计到阈值作废粘滞 IP；成功清零。
/// 按**域名**计数（origin 映射）——拨号可能用重解析后的新 IP，而调用方手里
/// 还是解析期固定地址，必须回到域名维度才不会记错。
pub fn note_dial(server: SocketAddr, ok: bool) {
    let host = {
        let st = lock_state();
        match st.origin.get(&server) {
            Some(h) => h.clone(),
            None => return,
        }
    };
    let mut st = lock_state();
    let mut invalidated = false;
    if let Some(e) = st.by_key.get_mut(&host) {
        if ok {
            e.failures = 0;
        } else {
            e.failures += 1;
            invalidated = e.failures >= FAIL_THRESHOLD;
        }
    } else {
        return;
    }
    if invalidated {
        st.by_key.remove(&host);
        drop(st);
        crate::log(&format!(
            "sticky: {host} 连续 {FAIL_THRESHOLD} 次拨号失败，作废粘滞 IP（下次拨号重新解析）"
        ));
    }
}

/// reload 时重置（对照 dae `ResetGlobalProxyStateForReload`）。
pub fn reset() {
    let mut st = lock_state();
    if !st.by_key.is_empty() {
        crate::log(&format!(
            "sticky: reload 重置 {} 条粘滞 IP（下次解析重新走 DNS）",
            st.by_key.len()
        ));
    }
    st.by_key.clear();
    st.origin.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(v: &[&str]) -> Vec<SocketAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn sticks_to_first_resolution_and_reuses() {
        let now = Instant::now();
        let first = resolve_with(
            "node.test:443",
            |_| Ok(addrs(&["1.1.1.1:443", "2.2.2.2:443"])),
            now,
        )
        .unwrap();
        assert_eq!(first, "1.1.1.1:443".parse().unwrap());
        // 第二次即使 DNS 给出不同答案，也应粘滞
        let second = resolve_with(
            "node.test:443",
            |_| Ok(addrs(&["9.9.9.9:443"])),
            now + Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(second, first);
    }

    #[test]
    fn prefers_ipv4_then_falls_back_to_v6() {
        let now = Instant::now();
        let a = resolve_with(
            "v6first.test:443",
            |_| Ok(addrs(&["[2001:db8::1]:443", "1.1.1.1:443"])),
            now,
        )
        .unwrap();
        assert_eq!(a, "1.1.1.1:443".parse().unwrap());
        let b = resolve_with(
            "v6only.test:443",
            |_| Ok(addrs(&["[2001:db8::1]:443"])),
            now,
        )
        .unwrap();
        assert_eq!(b, "[2001:db8::1]:443".parse().unwrap());
    }

    #[test]
    fn three_failures_invalidate() {
        let now = Instant::now();
        let a = resolve_with("bad.test:443", |_| Ok(addrs(&["3.3.3.3:443"])), now).unwrap();
        note_dial(a, false);
        note_dial(a, false);
        // 第 3 次失败 → 作废；随后解析拿到新地址
        note_dial(a, false);
        let b = resolve_with(
            "bad.test:443",
            |_| Ok(addrs(&["4.4.4.4:443"])),
            now + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(b, "4.4.4.4:443".parse().unwrap());
    }

    #[test]
    fn success_resets_failure_counter() {
        let now = Instant::now();
        let a = resolve_with("ok.test:443", |_| Ok(addrs(&["5.5.5.5:443"])), now).unwrap();
        note_dial(a, false);
        note_dial(a, false);
        note_dial(a, true); // 清零
        note_dial(a, false);
        note_dial(a, false);
        // 未达 3 次 → 仍粘滞
        let again = resolve_with(
            "ok.test:443",
            |_| Ok(addrs(&["6.6.6.6:443"])),
            now + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(again, a);
    }

    #[test]
    fn ip_literal_passthrough() {
        let r = resolve_with(
            "7.7.7.7:8388",
            |_| panic!("不应解析 IP 字面量"),
            Instant::now(),
        );
        assert_eq!(r.unwrap(), "7.7.7.7:8388".parse().unwrap());
    }

    #[test]
    fn dial_time_keeps_valid_pin() {
        let now = Instant::now();
        let a = resolve_with("keep.test:443", |_| Ok(addrs(&["1.1.1.1:443"])), now).unwrap();
        // 钉仍有效：即使 DNS 现在给出别的答案，也不重解析。
        let b = resolve_for_dial_with(a, |_| Ok(addrs(&["9.9.9.9:443"])), now + Duration::from_secs(5));
        assert_eq!(b, a);
    }

    #[test]
    fn dial_time_reresolves_after_invalidation() {
        let now = Instant::now();
        let a = resolve_with("redeem.test:443", |_| Ok(addrs(&["3.3.3.3:443"])), now).unwrap();
        note_dial(a, false);
        note_dial(a, false);
        note_dial(a, false); // 作废
        let b = resolve_for_dial_with(a, |_| Ok(addrs(&["4.4.4.4:443"])), now + Duration::from_secs(1));
        assert_eq!(b, "4.4.4.4:443".parse().unwrap());
        // 重解析后 note_dial 仍按域名记数：新地址连续失败也能再次作废。
        note_dial(a, false);
        note_dial(a, false);
        note_dial(a, false);
        let c = resolve_for_dial_with(a, |_| Ok(addrs(&["5.5.5.5:443"])), now + Duration::from_secs(2));
        assert_eq!(c, "5.5.5.5:443".parse().unwrap());
    }

    #[test]
    fn dial_time_ttl_refresh() {
        let now = Instant::now();
        let a = resolve_with("ttl2.test:443", |_| Ok(addrs(&["8.8.8.8:443"])), now).unwrap();
        let b = resolve_for_dial_with(
            a,
            |_| Ok(addrs(&["9.9.9.9:443"])),
            now + ENTRY_TTL + Duration::from_secs(1),
        );
        assert_eq!(b, "9.9.9.9:443".parse().unwrap());
    }

    #[test]
    fn dial_time_ip_literal_passthrough() {
        let r = resolve_for_dial_with(
            "7.7.7.7:8388".parse().unwrap(),
            |_| panic!("IP 字面量不应触发解析"),
            Instant::now(),
        );
        assert_eq!(r, "7.7.7.7:8388".parse().unwrap());
    }

    #[test]
    fn ttl_expiry_reresolves() {
        let now = Instant::now();
        let _ = resolve_with("ttl.test:443", |_| Ok(addrs(&["8.8.8.8:443"])), now).unwrap();
        let b = resolve_with(
            "ttl.test:443",
            |_| Ok(addrs(&["9.9.9.9:443"])),
            now + ENTRY_TTL + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(b, "9.9.9.9:443".parse().unwrap());
    }
}

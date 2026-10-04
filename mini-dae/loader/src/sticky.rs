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

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 连续失败多少次作废粘滞 IP（dae `maxConsecutiveFailures`）。
const FAIL_THRESHOLD: u32 = 3;
/// 条目最长粘滞时间；过期后下次解析重新走 DNS（近似 dae 的健康检查周期刷新）。
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
    /// 已解析地址 → 引用它的 key（拨号失败只能拿到地址）
    by_addr: HashMap<SocketAddr, Vec<String>>,
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
    // 旧地址的反向引用先清掉（重解析换 IP 时）
    if let Some(old) = st.by_key.get(hostport) {
        let old_addr = old.addr;
        if old_addr != chosen {
            if let Some(v) = st.by_addr.get_mut(&old_addr) {
                v.retain(|k| k != hostport);
                if v.is_empty() {
                    st.by_addr.remove(&old_addr);
                }
            }
        }
    }
    st.by_addr
        .entry(chosen)
        .or_default()
        .push(hostport.to_string());
    st.by_key.insert(
        hostport.to_string(),
        Entry {
            addr: chosen,
            resolved_at: now,
            failures: 0,
        },
    );
    crate::log(&format!("sticky: {hostport} → {chosen}（粘滞 IP 已固定）"));
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

/// 拨号结果反馈：失败累计到阈值作废粘滞 IP；成功清零。
pub fn note_dial(server: SocketAddr, ok: bool) {
    let mut st = lock_state();
    let Some(keys) = st.by_addr.get(&server).cloned() else {
        return;
    };
    if ok {
        for k in &keys {
            if let Some(e) = st.by_key.get_mut(k) {
                e.failures = 0;
            }
        }
        return;
    }
    let mut invalidated = Vec::new();
    for k in &keys {
        if let Some(e) = st.by_key.get_mut(k) {
            e.failures += 1;
            if e.failures >= FAIL_THRESHOLD {
                invalidated.push(k.clone());
            }
        }
    }
    for k in &invalidated {
        st.by_key.remove(k);
        crate::log(&format!(
            "sticky: {k} 连续 {FAIL_THRESHOLD} 次拨号失败，作废粘滞 IP（下次重新解析）"
        ));
    }
    if let Some(v) = st.by_addr.get_mut(&server) {
        v.retain(|k| !invalidated.contains(k));
        if v.is_empty() {
            st.by_addr.remove(&server);
        }
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
    st.by_addr.clear();
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

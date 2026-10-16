// SPDX-License-Identifier: AGPL-3.0-only
//! A2 #7/#12：`ipversion_prefer` 的 50ms 偏好等待（对照 dae `dns_preference_wait.go`）。
//!
//! RFC 8305（Happy Eyeballs v2）§3：若 A 应答先到（可能只是乱序），客户端应等待一小段
//! 时间看 AAAA 是否紧随其后（推荐 50ms）。dae 的实现是一张「按 qname 登记等待」的表：
//! 非首选族查询登记等待 → 首选族应答到达（带地址记录）→ 通知等待者抑制自己的应答
//! （回空 NOERROR，把首选族让给客户端）；50ms 内没等到就正常返回非首选族应答。
//!
//! sodama 的形态差异（如实）：dae 的 DNS 监听是「每查询一 goroutine」，等待不影响其它
//! 查询；sodama 的 UDP DNS 主循环是串行的，因此**仅在 `ipversion_prefer` 开启时**把
//! 非首选族查询交给工作线程（见 `dns_loop`）——默认关闭时零影响。

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

/// 等多久（对照 dae `PreferenceResolutionDelay`）。
pub const PREFERENCE_DELAY: Duration = Duration::from_millis(50);

pub struct WaitState {
    /// 等待结束（首选族到达或超时）。
    done: bool,
    /// 首选族应答**带地址记录**（空应答/NXDOMAIN 不抑制非首选族）。
    preferred_has_records: bool,
}

pub type Entry = Arc<(Mutex<WaitState>, Condvar)>;

fn registry() -> &'static Mutex<HashMap<String, Entry>> {
    static R: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_reg() -> std::sync::MutexGuard<'static, HashMap<String, Entry>> {
    match registry().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// 登记一个非首选族查询的等待（同一 qname 已有等待则复用——对照 dae 的
/// 「existing wait 直接返回」）。
pub fn register(qname: &str) -> Entry {
    let mut g = lock_reg();
    if let Some(e) = g.get(qname) {
        return e.clone();
    }
    let e: Entry = Arc::new((
        Mutex::new(WaitState {
            done: false,
            preferred_has_records: false,
        }),
        Condvar::new(),
    ));
    g.insert(qname.to_string(), e.clone());
    e
}

/// 首选族应答到达（`has_records` = 该应答带首选族地址记录）→ 唤醒等待者。
pub fn notify(qname: &str, has_records: bool) {
    let entry = lock_reg().get(qname).cloned();
    let Some(e) = entry else { return };
    let (m, cv) = &*e;
    let mut st = match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if !st.done {
        st.done = true;
        st.preferred_has_records = has_records;
        cv.notify_all();
    }
}

/// 等待首选族（至多 `timeout`）；返回 `true` = 首选族已到**且有记录** → 调用方抑制
/// 自己的非首选族应答。等待结束后清理登记表（同一 qname 不会长期滞留）。
pub fn wait(entry: &Entry, qname: &str, timeout: Duration) -> bool {
    let (m, cv) = &**entry;
    let mut st = match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if !st.done {
        let (g2, _) = match cv.wait_timeout(st, timeout) {
            Ok(v) => v,
            Err(p) => p.into_inner(),
        };
        st = g2;
    }
    let suppress = st.done && st.preferred_has_records;
    drop(st);
    // 清理：只删自己（同 qname 可能被后继查询复用为新 Entry）。
    let mut g = lock_reg();
    if let Some(cur) = g.get(qname) {
        if Arc::ptr_eq(cur, entry) {
            g.remove(qname);
        }
    }
    suppress
}

/// 首选族对应的 qtype（prefer=4 → A(1)；prefer=6 → AAAA(28)）。
pub fn preferred_qtype(prefer: u8) -> u16 {
    if prefer == 4 {
        1
    } else {
        28
    }
}

/// 是否应把该查询交给工作线程（仅在开启偏好等待且是 A/AAAA 的**非**首选族时）。
pub fn needs_deferred(prefer: u16, qtype: u16) -> bool {
    prefer != 0 && (qtype == 1 || qtype == 28) && qtype != preferred_qtype(prefer as u8)
}

/// 当前登记数（状态面/测试用）。
pub fn pending() -> usize {
    lock_reg().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_with_records_suppresses_waiter() {
        let e = register("a.test");
        let e2 = e.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            // 首选族（带记录）到达 → 等待者应被抑制
            notify("a.test", true);
            std::thread::sleep(Duration::from_millis(5));
        });
        assert!(wait(&e2, "a.test", Duration::from_millis(200)));
        t.join().unwrap();
        // 登记表清理：同 qname 再登记必须是新 Entry（注册表进程全局，测试并行，
        // 不能用 pending() 总计数断言）。
        let e3 = register("a.test");
        assert!(!Arc::ptr_eq(&e, &e3), "等待结束后登记表应清理");
    }

    #[test]
    fn no_notify_times_out_and_does_not_suppress() {
        let e = register("b.test");
        assert!(!wait(&e, "b.test", Duration::from_millis(20)));
        let e2 = register("b.test");
        assert!(!Arc::ptr_eq(&e, &e2), "超时后登记表同样应清理");
    }

    #[test]
    fn notify_without_records_does_not_suppress() {
        let e = register("c.test");
        notify("c.test", false);
        assert!(!wait(&e, "c.test", Duration::from_millis(20)));
    }

    #[test]
    fn needs_deferred_semantics() {
        // prefer=4 = 首选 A（qtype 1）：A 不需等待，AAAA 需等待；prefer=6 反之。
        assert!(!needs_deferred(4, 1));
        assert!(needs_deferred(4, 28));
        assert!(!needs_deferred(6, 28));
        assert!(needs_deferred(6, 1));
        assert!(!needs_deferred(0, 1));
        assert!(!needs_deferred(4, 15)); // MX 等不参与
    }

    /// 首选族对应的 qtype（prefer=4 → A(1)；prefer=6 → AAAA(28)）——与 main.rs 的
    /// `preferred_qtype` 同源（此处保留一份供测试对照）。
    #[test]
    fn preferred_qtype_mapping() {
        assert_eq!(super::preferred_qtype(4), 1);
        assert_eq!(super::preferred_qtype(6), 28);
    }
}

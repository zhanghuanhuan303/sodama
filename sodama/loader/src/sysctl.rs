// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! A2 #16：sysctl 期望值管理器（对照 dae `control/sysctl.go` 的 `SysctlManager`）。
//!
//! 背景：`auto_config_kernel_parameter` 会让 sodama 写一批内核参数（ip_forward、
//! 各接口 forwarding/send_redirects 等）。运行期被其它软件（或管理员）改回去时，
//! 转发会静默退化。dae 用 fsnotify 监视**已写过**的 sysctl 文件：发现值 ≠ 期望值
//! 就记一条日志并改写回去。本模块是同一语义的 Rust 形态：
//!
//! - `set(path, value, watch=true)`：写值并登记期望值；
//! - 后台线程 `inotify`（`IN_MODIFY|IN_CLOSE_WRITE`）监视这些文件；
//! - inotify 不可用（`inotify_add_watch` 失败）→ 该路径降级为 **2s 轮询**兜底
//!   （procfs 的 inotify 支持随内核而异；降级不改变可观察行为，只是纠偏延迟变长）。
//!
//! 与 dae 的差异（如实）：dae 只订阅 inotify（procfs 支持其平台）；sodama 加轮询兜底。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// 期望值表（path → value；查询/测试用）。
struct Expect {
    /// path → expected value
    values: HashMap<PathBuf, String>,
    /// inotify 不可用的路径（轮询兜底集合）。
    poll_paths: Vec<PathBuf>,
    /// 纠偏次数（status/测试可见）。
    rewrites: u64,
}

fn expect() -> &'static Mutex<Expect> {
    static E: OnceLock<Mutex<Expect>> = OnceLock::new();
    E.get_or_init(|| {
        Mutex::new(Expect {
            values: HashMap::new(),
            poll_paths: Vec::new(),
            rewrites: 0,
        })
    })
}

fn lock_expect() -> std::sync::MutexGuard<'static, Expect> {
    match expect().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// 读一个 sysctl 文件（trim 后返回）。
pub fn read_value(path: &std::path::Path) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path).map(|s| s.trim().to_string())
}

/// 写一个 sysctl 文件；`watch=true` 时登记期望值（被改回即纠正）。
/// 返回写入前的实际值（供调用方记录/测试断言）。
pub fn set(path: &std::path::Path, value: &str, watch: bool) -> Result<String, String> {
    let prev = read_value(path).unwrap_or_default();
    std::fs::write(path, value.as_bytes())
        .map_err(|e| format!("写 {} 失败: {e}", path.display()))?;
    if watch {
        let watch_new = {
            let mut e = lock_expect();
            let new = !e.values.contains_key(path) && !e.poll_paths.contains(&path.to_path_buf());
            e.values.insert(path.to_path_buf(), value.to_string());
            new
        };
        if watch_new {
            register_watch(path);
        }
    }
    Ok(prev)
}

/// 登记 inotify 监视（失败 → 轮询兜底集合）。
fn register_watch(path: &std::path::Path) {
    start_watcher();
    if ensure_inotify() && inotify_add(path).is_ok() {
        return;
    }
    let added = {
        let mut e = lock_expect();
        if e.poll_paths.contains(&path.to_path_buf()) {
            false
        } else {
            e.poll_paths.push(path.to_path_buf());
            true
        }
    };
    if added {
        poll_loop_start();
    }
}

static INOTIFY_FD: OnceLock<i32> = OnceLock::new();

fn inotify_fd() -> Option<i32> {
    INOTIFY_FD.get().copied()
}

fn inotify_add(path: &std::path::Path) -> Result<(), ()> {
    let fd = inotify_fd().ok_or(())?;
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| ())?;
    let wd = unsafe {
        libc::inotify_add_watch(
            fd,
            c.as_ptr(),
            libc::IN_MODIFY | libc::IN_CLOSE_WRITE | libc::IN_ATTRIB,
        )
    };
    if wd < 0 {
        return Err(());
    }
    Ok(())
}

fn ensure_inotify() -> bool {
    if INOTIFY_FD.get().is_some() {
        return true;
    }
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let _ = INOTIFY_FD.set(fd);
    true
}

/// 纠偏：值 ≠ 期望值 → 记日志 + 改写回去（对照 dae `handleWatchEvent`：
/// 读失败只记读失败，不把「未观测到的值」写成一次纠偏）。
pub fn handle_change(path: &std::path::Path, expected: &str) -> bool {
    let Ok(cur) = read_value(path) else {
        crate::log_warn(&format!("sysctl: 读取 {} 失败，跳过纠偏", path.display()));
        return false;
    };
    if cur == expected {
        return false;
    }
    crate::log_warn(&format!(
        "sysctl {} 被改为 {cur}（期望 {expected}），已纠正",
        path.display()
    ));
    if std::fs::write(path, expected.as_bytes()).is_ok() {
        let mut e = lock_expect();
        e.rewrites += 1;
        true
    } else {
        crate::log_warn(&format!("sysctl: 回写 {} 失败", path.display()));
        false
    }
}

/// inotify 事件线程（进程内一次；惰性启动）。
pub fn start_watcher() {
    if !ensure_inotify() {
        crate::log_warn("sysctl: inotify 不可用，全部监视路径降级为 2s 轮询");
        poll_loop_start();
        return;
    }
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::Builder::new()
        .name("sysctl-watch".into())
        .spawn(|| {
            let fd = inotify_fd().expect("inotify fd");
            let mut buf = [0u8; 4096];
            loop {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    continue;
                }
                // 解析 inotify 事件（name 常为空——我们监视的是文件本身）。
                let mut off = 0usize;
                let hdr = std::mem::size_of::<libc::inotify_event>();
                let data = &buf[..n as usize];
                while off + hdr <= data.len() {
                    let ev = unsafe { &*(data.as_ptr().add(off).cast::<libc::inotify_event>()) };
                    let len = hdr + ev.len as usize;
                    // 逐个期望值比对（监视的文件数 = sysctl 写数，量级 < 20）。
                    let pairs: Vec<(PathBuf, String)> = {
                        let e = lock_expect();
                        e.values
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect()
                    };
                    for (p, v) in pairs {
                        let _ = handle_change(&p, &v);
                    }
                    off += len;
                }
            }
        })
        .ok();
}

/// 轮询兜底（2s 周期；inotify 不可用时使用）。
fn poll_loop_start() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::Builder::new()
        .name("sysctl-poll".into())
        .spawn(|| loop {
            let pairs: Vec<(PathBuf, String)> = {
                let e = lock_expect();
                e.poll_paths
                    .iter()
                    .filter_map(|p| e.values.get(p).map(|v| (p.clone(), v.clone())))
                    .collect()
            };
            for (p, v) in pairs {
                handle_change(&p, &v);
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        })
        .ok();
}

/// 期望值表快照（测试/状态面用）。
pub fn expectations() -> Vec<(PathBuf, String)> {
    let e = lock_expect();
    let mut v: Vec<(PathBuf, String)> = e
        .values
        .iter()
        .map(|(k, s)| (k.clone(), s.clone()))
        .collect();
    v.sort();
    v
}

/// 纠偏计数（状态面用）。
pub fn rewrites() -> u64 {
    lock_expect().rewrites
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_rewrites_and_handles_change() {
        let dir = std::env::temp_dir().join(format!("sodama-sysctl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 不登记 watch（watch=false）：纠偏函数本体可确定性地单独测。
        let p = dir.join("ip_forward");
        std::fs::write(&p, "0\n").unwrap();
        let prev = set(&p, "1", false).unwrap();
        assert_eq!(prev, "0");
        assert_eq!(read_value(&p).unwrap(), "1");
        // 外部改回 0 → handle_change 纠偏
        std::fs::write(&p, "0\n").unwrap();
        assert!(handle_change(&p, "1"), "应发生一次纠偏");
        assert_eq!(read_value(&p).unwrap(), "1");
        assert!(!handle_change(&p, "1"), "值已一致时不应再纠偏");
        // 读失败（不存在）→ 不纠偏、不 panic
        let missing = dir.join("nope");
        assert!(!handle_change(&missing, "1"));
        // watch=true 只负责登记期望值（纠偏由 watcher 线程做；此处不断言时序）。
        let p2 = dir.join("send_redirects");
        std::fs::write(&p2, "1\n").unwrap();
        set(&p2, "0", true).unwrap();
        assert!(expectations().iter().any(|(k, v)| k == &p2 && v == "0"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

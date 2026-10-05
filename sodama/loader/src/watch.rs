//! P35：配置热驱动的内核事件层——inotify 目录监听 + 事件名过滤 + 去抖合并。
//!
//! 设计取舍（对照 P33 的纯轮询）：
//! - 监听**父目录**而非文件本身：编辑器普遍「写临时文件 + rename 覆盖」，只有目录级
//!   `IN_MOVED_TO`/`IN_CREATE` 才能稳定捕获；文件级 watch 在 rename 后即失效（IN_IGNORED）。
//! - 目录里其它文件的噪声用**事件名过滤**消掉——只关心目标文件名（如 `/tmp` 这种繁忙目录
//!   不会因为无关文件变化而误触发）。
//! - `IN_Q_OVERFLOW`（队列溢出）与被监听目录自身被删/改名一律视为「可疑事件」，交由上层用
//!   `(mtime,size)` 快照复核——inotify 是加速器，**正确性仍由快照保证**（网络文件系统不触发
//!   inotify 时，由上层慢速兜底扫描兜底）。
//! - 去抖：编辑器保存往往产生一串事件（临时文件创建/写/rename），`settle()` 等一个静默
//!   窗口再交给上层 reload（niri 同款「事件驱动 + 静默期」思路）。

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::Duration;

/// 目录级关心的掩码：写关闭/创建/删除/改名（`IN_MODIFY` 不订阅，避免写入过程的高频噪声）。
const MASK: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF;

/// 去抖静默窗口：首批事件后再等这么久没有新事件才交给上层。
pub const DEBOUNCE: Duration = Duration::from_millis(100);

pub struct DirWatcher {
    fd: OwnedFd,
    /// wd → (目录, 关心的文件名原始字节集合)
    wds: HashMap<i32, (PathBuf, HashSet<Vec<u8>>)>,
}

impl DirWatcher {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            wds: HashMap::new(),
        })
    }

    /// 设置监听集合（目录 → 关心的文件名）；幂等，可每轮调用（include 集合会随配置变化）。
    pub fn set_targets(&mut self, targets: &HashMap<PathBuf, HashSet<Vec<u8>>>) {
        // 移除不再需要的（目录或文件集合变化都重挂）
        let stale: Vec<i32> = self
            .wds
            .iter()
            .filter(|(_, (d, names))| targets.get(d).map(|want| want != names).unwrap_or(true))
            .map(|(wd, _)| *wd)
            .collect();
        for wd in stale {
            self.wds.remove(&wd);
            unsafe {
                libc::inotify_rm_watch(self.fd.as_raw_fd(), wd);
            }
        }
        // 新增
        for (dir, names) in targets {
            if self.wds.values().any(|(d, n)| d == dir && n == names) {
                continue;
            }
            let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
                continue;
            };
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), c.as_ptr(), MASK) };
            if wd >= 0 {
                self.wds.insert(wd, (dir.clone(), names.clone()));
            }
        }
    }

    pub fn watched_dirs(&self) -> usize {
        self.wds.len()
    }

    /// 等待「关心的」事件：有则排空事件队列并返回 true；超时/仅无关事件返回 false。
    /// `timeout = None` 表示永久阻塞。
    pub fn wait(&mut self, timeout: Option<Duration>) -> bool {
        let ms = match timeout {
            None => -1,
            Some(d) => d.as_millis().min(i32::MAX as u128) as i32,
        };
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, ms) };
        if r <= 0 {
            return false; // 超时 / EINTR
        }
        self.drain()
    }

    /// 去抖：等待一个静默窗口，把同一批保存产生的事件合并掉。
    pub fn settle(&mut self) {
        while self.wait(Some(DEBOUNCE)) {}
    }

    /// 排空事件队列并判断是否有「关心的」事件。
    fn drain(&mut self) -> bool {
        let mut hot = false;
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break; // EAGAIN 或错误
            }
            let hdr = std::mem::size_of::<libc::inotify_event>();
            let mut off = 0usize;
            while off + hdr <= n as usize {
                let ev = unsafe { &*(buf.as_ptr().add(off).cast::<libc::inotify_event>()) };
                let len = ev.len as usize;
                let name = &buf[off + hdr..(off + hdr + len).min(n as usize)];
                off += hdr + len;
                if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                    hot = true; // 队列溢出：丢失了事件，交给快照复核
                    continue;
                }
                if ev.mask & libc::IN_IGNORED != 0 {
                    self.wds.remove(&ev.wd);
                    continue;
                }
                let Some((_, names)) = self.wds.get(&ev.wd) else {
                    hot = true; // 未登记的 wd（重新 arm 窗口内）：保守当作可疑
                    continue;
                };
                if len == 0 {
                    hot = true; // 目录自身被删/改名
                    continue;
                }
                let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
                if names.contains(&name[..end].to_vec()) {
                    hot = true;
                }
            }
        }
        hot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn targets_for(paths: &[PathBuf]) -> HashMap<PathBuf, HashSet<Vec<u8>>> {
        let mut t: HashMap<PathBuf, HashSet<Vec<u8>>> = HashMap::new();
        for p in paths {
            if let (Some(d), Some(n)) = (p.parent(), p.file_name()) {
                t.entry(d.to_path_buf())
                    .or_default()
                    .insert(n.as_encoded_bytes().to_vec());
            }
        }
        t
    }

    #[test]
    fn dir_watch_catches_write_and_ignores_other_names() {
        let dir = std::env::temp_dir().join(format!("sodama-watch-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.dae");
        std::fs::write(&target, "a=1\n").unwrap();

        let mut w = DirWatcher::new().unwrap();
        w.set_targets(&targets_for(&[target.clone()]));
        assert_eq!(w.watched_dirs(), 1);

        // 覆盖写 + close → IN_CLOSE_WRITE（目录级，带目标文件名）
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&target)
            .unwrap();
        f.write_all(b"a=2\n").unwrap();
        drop(f);
        assert!(w.wait(Some(Duration::from_secs(2))), "应捕获目标文件写入");

        // 同目录无关文件：被事件名过滤（不触发）
        std::fs::write(dir.join("unrelated.txt"), "x").unwrap();
        assert!(
            !w.wait(Some(Duration::from_millis(150))),
            "无关文件不应触发"
        );

        // 编辑器 rename 覆盖：也应捕获（IN_MOVED_TO）
        std::fs::write(dir.join("config.dae.tmp"), "a=3\n").unwrap();
        std::fs::rename(dir.join("config.dae.tmp"), &target).unwrap();
        assert!(w.wait(Some(Duration::from_secs(2))), "应捕获 rename 覆盖");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

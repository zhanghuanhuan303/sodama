// SPDX-License-Identifier: GPL-2.0
//! M4：epoll worker 池——每连接 0 线程。stage 1 接管字节透明 splice 链路
//! （Direct / VLESS 明文 / kTLS 成功的 TLS）；stage 2 起同时接管已对 WouldBlock
//! 可重入的 codec 链路（rustls VLESS-TCP / Trojan，见 `Outbound::codec_reactor_capable`）：
//! 读半/写半在 worker 内非阻塞驱动。
//! 其余加解密/成帧链路（reality/vision/ws/ss/vmess…）仍走「每连接线程」模型。
//!
//! 结构：
//! - N 个 worker 线程，各持独立 epoll；新会话经共享 channel + eventfd 唤醒；
//! - 每连接两个惰性缓冲方向：`splice(src→pipe)` 读入、`splice(pipe→dst)` 写出，
//!   以管道水位（HIGH_WM）控制「先排空再续读」，避免 level-triggered 忙轮询；
//! - EOF → `shutdown(dst, SHUT_WR)`（与 splice_pump 半关闭语义一致）；
//!   两方向都 EOF 且管道排空 → 关闭并收尾（注册表/统计）；
//! - 收尾动作与原线程路径一致：从 `RELAY_CONNS` 摘除 + `conns_active` 递减；
//!   空闲回收仍由 `relay_janitor_loop` 负责（shutdown 会唤醒 epoll）。
//!
//! 关闭开关：`SODAMA_NO_REACTOR=1`（A/B 与排障用）。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::{log, monotonic_now_ns, RelayHandle, RELAY_CONNS, RELAY_STATS};

/// 单次 splice 搬运上限与管道水位（超过则暂停读 src，先排空）。
const CHUNK: usize = 1 << 20;
const PIPE_SZ: i32 = 1 << 20;
const HIGH_WM: usize = 1 << 20;
/// codec 方向水位：out 是用户态保有（万级连接要控内存），比 splice 管道小。
const CODEC_WM: usize = 128 * 1024;
/// codec 单次读块（64KB：一次多记录/多分片，少一轮 epoll）。
const CODEC_CHUNK: usize = 64 * 1024;
/// worker 数量上限/下限（按可用并行度；codec 会话是 CPU 密集（TLS/AEAD），
/// 需要能压满全部核，因此取完整并行度而非一半）。
const MAX_WORKERS: usize = 16;
const MIN_WORKERS: usize = 2;

static ENABLED: OnceLock<bool> = OnceLock::new();
/// stage 2 codec 会话开关（`SODAMA_REACTOR_CODEC=0` 关闭；默认开）。
static CODEC_ENABLED: OnceLock<bool> = OnceLock::new();
static WORKERS: OnceLock<Vec<Arc<Mutex<Worker>>>> = OnceLock::new();
static SUBMIT_TX: OnceLock<Sender<Session>> = OnceLock::new();
static NEXT_WORKER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// 会话 → worker 索引（prelude 完成后的 resume/kill 需要跨线程定位）。
static LOCATIONS: OnceLock<Mutex<HashMap<u64, usize>>> = OnceLock::new();

fn dbg_on() -> bool {
    std::env::var("SODAMA_REACTOR_DEBUG").is_ok()
}

/// 是否启用 reactor（`SODAMA_NO_REACTOR=1` 关闭）。
pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var("SODAMA_NO_REACTOR").is_err())
}

/// stage 2：codec 链路是否可交 reactor（worker 池已启动且未被开关关闭）。
pub fn codec_available() -> bool {
    *CODEC_ENABLED.get_or_init(|| std::env::var("SODAMA_REACTOR_CODEC").map_or(true, |v| v != "0"))
        && enabled()
        && SUBMIT_TX.get().is_some()
        && WORKERS.get().is_some()
}

struct Dir {
    /// 源/目的 fd（属于会话的 client/upstream，不拥有）。
    src: RawFd,
    dst: RawFd,
    /// [读端, 写端]
    pipe: [RawFd; 2],
    /// 管道中尚未写出的字节数。
    pending: usize,
    eof: bool,
    done: bool,
}

impl Dir {
    fn interest_in(&self) -> u32 {
        if !self.eof && self.pending < HIGH_WM {
            libc::EPOLLIN as u32
        } else {
            0
        }
    }
    fn interest_out(&self) -> u32 {
        if self.pending > 0 {
            libc::EPOLLOUT as u32
        } else {
            0
        }
    }
}

/// 数据面模式：stage 1 字节透明 splice；stage 2 用户态 codec（rustls 等）。
enum Mode {
    Splice { c2u: Dir, u2c: Dir },
    Codec { c2u: CodecDir, u2c: CodecDir },
}

struct Session {
    id: u64,
    client: OwnedFd,
    upstream: OwnedFd,
    mode: Mode,
    /// prelude（codec 响应头消费）未完成时，u2c 暂停读取，避免与 header 读半抢字节。
    /// 仅 Splice 使用（Codec 的读半自身可重入）。
    u2c_paused: bool,
    /// 仅 Splice：两个 socket 是否已设为 O_NONBLOCK：置位后 fill/drain 可循环搬运到
    /// EAGAIN；prelude 阶段必须保持阻塞（读半/写在同一 file description 上），
    /// resume 后置位。
    nonblock: bool,
    handle: Arc<RelayHandle>,
    client_reg: bool,
    upstream_reg: bool,
    dead: bool,
}

impl Session {
    fn fd_client(&self) -> RawFd {
        self.client.as_raw_fd()
    }
    fn fd_upstream(&self) -> RawFd {
        self.upstream.as_raw_fd()
    }

    fn interest(&self, fd: RawFd) -> u32 {
        match &self.mode {
            Mode::Splice { c2u, u2c } => {
                let u2c_in = if self.u2c_paused {
                    0
                } else {
                    u2c.interest_in()
                };
                if fd == self.fd_client() {
                    c2u.interest_in() | u2c.interest_out()
                } else {
                    u2c_in | c2u.interest_out()
                }
            }
            Mode::Codec { c2u, u2c } => {
                let mut mask = 0;
                if fd == c2u.src {
                    mask |= c2u.interest_in();
                }
                if fd == c2u.dst {
                    mask |= c2u.interest_out();
                }
                if fd == u2c.src {
                    mask |= u2c.interest_in();
                }
                if fd == u2c.dst {
                    mask |= u2c.interest_out();
                }
                mask
            }
        }
    }

    /// 从 src 读入管道：**每次事件最多一次 splice**。
    ///
    /// 关键：`SPLICE_F_NONBLOCK` 只作用于管道端，socket 端是阻塞 fd 时
    /// 第二次 splice 会真的阻塞 worker（实测），因此由 EPOLLIN 水平触发
    /// 驱动「每次搬一车」，不做循环预读。
    fn fill(&mut self, c2u: bool) -> io::Result<()> {
        let handle = self.handle.clone();
        let nonblock = self.nonblock;
        let mut moved = false;
        {
            let dir = match &mut self.mode {
                Mode::Splice { c2u: d1, u2c: d2 } => {
                    if c2u {
                        d1
                    } else {
                        d2
                    }
                }
                Mode::Codec { .. } => return Ok(()),
            };
            loop {
                if dir.eof || dir.pending >= HIGH_WM {
                    break;
                }
                let want = (HIGH_WM - dir.pending).min(CHUNK);
                let n = unsafe {
                    libc::splice(
                        dir.src,
                        std::ptr::null_mut(),
                        dir.pipe[1],
                        std::ptr::null_mut(),
                        want,
                        libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                    )
                };
                if n > 0 {
                    dir.pending += n as usize;
                    moved = true;
                    if dbg_on() {
                        log(&format!(
                            "reactor-dbg: fill {} n={n} pending={}",
                            if c2u { "c2u" } else { "u2c" },
                            dir.pending
                        ));
                    }
                    handle.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
                    let c = if c2u {
                        &RELAY_STATS.bytes_up
                    } else {
                        &RELAY_STATS.bytes_down
                    };
                    c.fetch_add(n as u64, Ordering::Relaxed);
                    if !nonblock {
                        break; // 阻塞 fd：每次事件只搬一车（多搬会阻塞）
                    }
                } else if n == 0 {
                    dir.eof = true;
                    if dbg_on() {
                        log(&format!(
                            "reactor-dbg: fill {} EOF",
                            if c2u { "c2u" } else { "u2c" }
                        ));
                    }
                    break;
                } else {
                    let e = io::Error::last_os_error();
                    match e.raw_os_error() {
                        Some(libc::EAGAIN) | Some(libc::EINTR) => break,
                        Some(libc::EINVAL) => {
                            // kTLS RX 的控制记录（NST 等）会让 splice requeue 并返回 EINVAL：
                            // 用带 cmsg 的 recvmsg 消费掉再重试（普通 socket 上不会误吞数据）。
                            match crate::ktls_take_control_record(dir.src) {
                                Ok(true) => continue,
                                _ => return Err(e),
                            }
                        }
                        _ => {
                            if dbg_on() {
                                log(&format!(
                                    "reactor-dbg: fill {} err {e}",
                                    if c2u { "c2u" } else { "u2c" }
                                ));
                            }
                            return Err(e);
                        }
                    }
                }
            }
        }
        self.maybe_half_close(c2u)?;
        // 非阻塞模式：填完直接尝试排空（不必等下一轮 EPOLLOUT）。
        if nonblock && moved {
            self.drain(c2u)?;
        }
        Ok(())
    }

    /// 管道排空到 dst：**每次事件最多一次 splice**（同上，由 EPOLLOUT 驱动）。
    fn drain(&mut self, c2u: bool) -> io::Result<()> {
        let handle = self.handle.clone();
        let nonblock = self.nonblock;
        {
            let dir = match &mut self.mode {
                Mode::Splice { c2u: d1, u2c: d2 } => {
                    if c2u {
                        d1
                    } else {
                        d2
                    }
                }
                Mode::Codec { .. } => return Ok(()),
            };
            if dir.pending > 0 {
                loop {
                    let n = unsafe {
                        libc::splice(
                            dir.pipe[0],
                            std::ptr::null_mut(),
                            dir.dst,
                            std::ptr::null_mut(),
                            dir.pending.min(CHUNK),
                            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                        )
                    };
                    if n > 0 {
                        dir.pending -= n as usize;
                        if dbg_on() {
                            log(&format!(
                                "reactor-dbg: drain {} n={n} pending={}",
                                if c2u { "c2u" } else { "u2c" },
                                dir.pending
                            ));
                        }
                        handle.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
                        if dir.pending == 0 || !nonblock {
                            break;
                        }
                    } else if n < 0 {
                        let e = io::Error::last_os_error();
                        match e.raw_os_error() {
                            Some(libc::EAGAIN) | Some(libc::EINTR) => break,
                            _ => {
                                if dbg_on() {
                                    log(&format!(
                                        "reactor-dbg: drain {} err {e}",
                                        if c2u { "c2u" } else { "u2c" }
                                    ));
                                }
                                return Err(e);
                            }
                        }
                    } else {
                        return Err(io::Error::other("reactor: 管道读端空转"));
                    }
                }
            }
        }
        self.maybe_half_close(c2u)
    }

    /// EOF 且管道排空 → 向 dst 半关闭（与 splice_pump 语义一致）。
    fn maybe_half_close(&mut self, c2u: bool) -> io::Result<()> {
        let dir = match &mut self.mode {
            Mode::Splice { c2u: d1, u2c: d2 } => {
                if c2u {
                    d1
                } else {
                    d2
                }
            }
            Mode::Codec { .. } => return Ok(()),
        };
        if dir.eof && dir.pending == 0 && !dir.done {
            unsafe {
                libc::shutdown(dir.dst, libc::SHUT_WR);
            }
            dir.done = true;
        }
        Ok(())
    }

    /// 单 fd 事件分派（Splice：splice 泵；Codec：读半/写半状态机）。
    /// 返回 `true` 表示 codec 会话可能仍有内部数据可泵（需自驱补泵）。
    fn on_event(&mut self, sid: u64, fd: RawFd, revents: u32) -> bool {
        let is_client = fd == self.fd_client();
        let mut err = false;
        let mut more = false;
        if matches!(self.mode, Mode::Splice { .. }) {
            // 该 fd 在两个方向中的角色：client 是 c2u 的 src、u2c 的 dst；upstream 反之。
            if revents & (libc::EPOLLIN as u32)
                | revents & (libc::EPOLLHUP as u32 | libc::EPOLLERR as u32)
                != 0
            {
                if let Err(e) = self.fill(is_client) {
                    log(&format!("reactor: splice 读失败 #{sid}（{e}）"));
                    err = true;
                }
            }
            if revents & (libc::EPOLLOUT as u32) != 0 || revents & (libc::EPOLLERR as u32) != 0 {
                // EPOLLOUT：另一方向的 dst 可写（client 的 OUT 服务 u2c；upstream 的 OUT 服务 c2u）。
                if let Err(e) = self.drain(!is_client) {
                    log(&format!("reactor: splice 写失败 #{sid}（{e}）"));
                    err = true;
                }
            }
        } else {
            let has_in = revents
                & (libc::EPOLLIN as u32 | libc::EPOLLHUP as u32 | libc::EPOLLERR as u32)
                != 0;
            let has_out = revents & (libc::EPOLLOUT as u32 | libc::EPOLLERR as u32) != 0;
            match self.codec_event(fd, has_in, has_out) {
                Ok(m) => more = m,
                Err(e) => {
                    log(&format!("reactor: codec 泵失败 #{sid}（{e}）"));
                    err = true;
                }
            }
        }
        if revents & (libc::EPOLLERR as u32) != 0 {
            self.dead = true;
        }
        if err {
            self.dead = true;
        }
        more && !self.dead
    }

    /// 无事件自驱：两个方向各推一轮（预算耗尽后的补泵）。
    fn codec_pump_both(&mut self, sid: u64) -> bool {
        let handle = self.handle.clone();
        let Mode::Codec { c2u, u2c } = &mut self.mode else {
            return false;
        };
        let mut more = false;
        match c2u.pump(&handle, true) {
            Ok(m) => more |= m,
            Err(e) => {
                log(&format!("reactor: codec 泵失败 #{sid}（{e}）"));
                self.dead = true;
            }
        }
        match u2c.pump(&handle, false) {
            Ok(m) => more |= m,
            Err(e) => {
                log(&format!("reactor: codec 泵失败 #{sid}（{e}）"));
                self.dead = true;
            }
        }
        more && !self.dead
    }

    fn codec_event(&mut self, fd: RawFd, has_in: bool, has_out: bool) -> io::Result<bool> {
        let handle = self.handle.clone();
        let Mode::Codec { c2u, u2c } = &mut self.mode else {
            return Ok(false);
        };
        let mut more = false;
        if (has_in && fd == c2u.src) || (has_out && fd == c2u.dst) {
            more |= c2u.pump(&handle, true)?;
        }
        if (has_in && fd == u2c.src) || (has_out && fd == u2c.dst) {
            more |= u2c.pump(&handle, false)?;
        }
        Ok(more)
    }

    fn finished(&self) -> bool {
        if self.dead {
            return true;
        }
        match &self.mode {
            Mode::Splice { c2u, u2c } => c2u.done && u2c.done,
            Mode::Codec { c2u, u2c } => c2u.done && u2c.done,
        }
    }
}

/// codec 单方向状态机（stage 2）：src --（读半解密/解帧）--> out --（写半加密）--> dst。
struct CodecDir {
    src: RawFd,
    dst: RawFd,
    side: CodecSide,
    /// 已读出/已解出、待推送的明文字节（O8：缓冲池化，会话结束归还）。
    out: crate::bufpool::PoolBuf,
    off: usize,
    eof: bool,
    /// 写半内部仍有密文未刷出（等 dst EPOLLOUT）。
    flush_pending: bool,
    done: bool,
}

enum CodecSide {
    /// 写半：接受明文，内部加密/成帧（c2u）。
    Sink(Box<dyn crate::outbound::WriteHalf>),
    /// 读半：产出明文，内部解密/解帧（u2c）。
    Source(Box<dyn crate::outbound::ReadHalf>),
}

fn retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

impl CodecDir {
    fn pending(&self) -> usize {
        self.out.len() - self.off
    }

    fn interest_in(&self) -> u32 {
        if !self.eof && self.pending() < CODEC_WM {
            libc::EPOLLIN as u32
        } else {
            0
        }
    }

    fn interest_out(&self) -> u32 {
        if self.pending() > 0 || self.flush_pending {
            libc::EPOLLOUT as u32
        } else {
            0
        }
    }

    /// 驱动方向：抽干读侧 → 推送对端 →（必要时）冲刷写半缓冲；每轮有界。
    /// 返回 `true` 表示预算耗尽、内部（rustls 等）可能仍有已就绪数据——
    /// 此时内核可能无可读事件，需由 worker 自驱补泵。
    fn pump(&mut self, handle: &RelayHandle, c2u: bool) -> io::Result<bool> {
        let mut budget = 8;
        let mut exhausted = false;
        loop {
            let r = self.read_some(handle, c2u)?;
            let w = self.write_some(handle, c2u)?;
            budget -= 1;
            if budget == 0 {
                exhausted = true;
                if dbg_on() {
                    log(&format!(
                        "reactor-dbg: codec {} pump 预算耗尽（pend={} eof={} fl={} done={}）",
                        if c2u { "c2u" } else { "u2c" },
                        self.pending(),
                        self.eof,
                        self.flush_pending,
                        self.done
                    ));
                }
                break;
            }
            if self.eof && self.pending() == 0 {
                if dbg_on() {
                    log(&format!(
                        "reactor-dbg: codec {} pump 收尾（pend={} eof={} fl={} done={}）",
                        if c2u { "c2u" } else { "u2c" },
                        self.pending(),
                        self.eof,
                        self.flush_pending,
                        self.done
                    ));
                }
                break;
            }
            if r == 0 && w == 0 {
                break;
            }
            if self.pending() > 0 {
                break; // 对端暂不可写：等 EPOLLOUT
            }
        }
        Ok(exhausted)
    }

    /// 读侧推进；返回读入/解出的字节数（0 = 无新数据或已 EOF）。
    fn read_some(&mut self, handle: &RelayHandle, c2u: bool) -> io::Result<usize> {
        let mut total = 0usize;
        let mut tmp = [0u8; CODEC_CHUNK];
        while !self.eof && self.pending() < CODEC_WM {
            let n: isize = match &mut self.side {
                CodecSide::Source(r) => match r.read(&mut tmp) {
                    Ok(n) => n as isize,
                    Err(e) if retryable(&e) => -1,
                    Err(e) => return Err(e),
                },
                CodecSide::Sink(_) => unsafe {
                    libc::read(self.src, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len())
                },
            };
            if n == 0 {
                self.eof = true;
                if dbg_on() {
                    log(&format!(
                        "reactor-dbg: codec {} src EOF（pend={}）",
                        if c2u { "c2u" } else { "u2c" },
                        self.pending()
                    ));
                }
                break;
            }
            if n < 0 {
                if matches!(self.side, CodecSide::Sink(_)) {
                    let e = io::Error::last_os_error();
                    match e.raw_os_error() {
                        Some(libc::EAGAIN) | Some(libc::EINTR) => {}
                        _ => return Err(e),
                    }
                }
                break;
            }
            let n = n as usize;
            self.out.extend_from_slice(&tmp[..n]);
            total += n;
            handle.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
            let c = if c2u {
                &RELAY_STATS.bytes_up
            } else {
                &RELAY_STATS.bytes_down
            };
            c.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok(total)
    }

    /// 写侧推进；返回交付/写出的字节数。
    fn write_some(&mut self, handle: &RelayHandle, c2u: bool) -> io::Result<usize> {
        let mut total = 0usize;
        let mut guard = 64;
        loop {
            if guard == 0 {
                break;
            }
            guard -= 1;
            if self.pending() == 0 {
                self.compact();
                if let CodecSide::Sink(w) = &mut self.side {
                    match w.flush() {
                        Ok(()) => self.flush_pending = false,
                        Err(e) if retryable(&e) => {
                            self.flush_pending = true;
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
                if self.eof && !self.done && !self.flush_pending {
                    if dbg_on() {
                        log(&format!(
                            "reactor-dbg: codec {} 半关闭（shutdown_write）",
                            if c2u { "c2u" } else { "u2c" }
                        ));
                    }
                    match &mut self.side {
                        // 写半协议终止（vmess 终止块/裸 FIN 等）；WO 时待 EPOLLOUT 重试。
                        CodecSide::Sink(w) => match w.shutdown_write() {
                            Ok(()) => self.done = true,
                            Err(e) if retryable(&e) => self.flush_pending = true,
                            Err(_) => self.done = true,
                        },
                        CodecSide::Source(_) => {
                            unsafe {
                                libc::shutdown(self.dst, libc::SHUT_WR);
                            }
                            self.done = true;
                        }
                    }
                }
                break;
            }
            match &mut self.side {
                CodecSide::Sink(w) => match w.write(&self.out[self.off..]) {
                    Ok(0) => {
                        if dbg_on() {
                            log(&format!(
                                "reactor-dbg: codec 写半缓冲满（pend={}）→ flush 重试",
                                self.out.len() - self.off
                            ));
                        }
                        // 写半缓冲满：先冲刷再重试；冲刷不动则等 EPOLLOUT。
                        match w.flush() {
                            Ok(()) => {
                                self.flush_pending = false;
                                continue;
                            }
                            Err(e) if retryable(&e) => {
                                self.flush_pending = true;
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(n) => {
                        self.off += n;
                        self.flush_pending = true; // 写半内部可能仍有密文待刷
                        total += n;
                        handle.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
                    }
                    Err(e) if retryable(&e) => {
                        self.flush_pending = true;
                        break;
                    }
                    Err(e) => return Err(e),
                },
                CodecSide::Source(_) => {
                    let n = unsafe {
                        libc::write(
                            self.dst,
                            self.out[self.off..].as_ptr() as *const libc::c_void,
                            self.out.len() - self.off,
                        )
                    };
                    if n > 0 {
                        self.off += n as usize;
                        total += n as usize;
                        handle.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
                    } else if n < 0 {
                        let e = io::Error::last_os_error();
                        match e.raw_os_error() {
                            Some(libc::EAGAIN) | Some(libc::EINTR) => break,
                            _ => return Err(e),
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        Ok(total)
    }

    /// out 已排空：释放游标；异常膨胀时缩容，避免长跑连接常驻大缓冲。
    fn compact(&mut self) {
        if self.off > 0 {
            self.out.drain(..self.off);
            self.off = 0;
        }
        if self.out.capacity() > 2 * CODEC_WM {
            self.out.shrink_to(CODEC_WM);
        }
    }
}

struct Worker {
    idx: usize,
    epfd: OwnedFd,
    wake: OwnedFd,
    sessions: HashMap<u64, Session>,
    fd_index: HashMap<RawFd, u64>,
    /// 预算耗尽的 codec 会话：无内核事件也要自驱补泵（内部缓冲可能已就绪）。
    pending: Vec<u64>,
}

impl Worker {
    fn new(idx: usize) -> io::Result<Worker> {
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wake < 0 {
            unsafe { libc::close(epfd) };
            return Err(io::Error::last_os_error());
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: wake as u64,
        };
        if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, wake, &mut ev) } != 0 {
            let e = io::Error::last_os_error();
            unsafe {
                libc::close(epfd);
                libc::close(wake);
            }
            return Err(e);
        }
        Ok(Worker {
            idx,
            epfd: unsafe { OwnedFd::from_raw_fd(epfd) },
            wake: unsafe { OwnedFd::from_raw_fd(wake) },
            sessions: HashMap::new(),
            fd_index: HashMap::new(),
            pending: Vec::new(),
        })
    }

    fn sync_fd(&mut self, sid: u64, fd: RawFd, registered: &mut bool) -> io::Result<()> {
        let mask = self.sessions.get(&sid).map(|s| s.interest(fd)).unwrap_or(0);
        if mask == 0 {
            if *registered {
                unsafe {
                    libc::epoll_ctl(
                        self.epfd.as_raw_fd(),
                        libc::EPOLL_CTL_DEL,
                        fd,
                        std::ptr::null_mut(),
                    )
                };
                *registered = false;
            }
            return Ok(());
        }
        let mut ev = libc::epoll_event {
            events: mask,
            u64: fd as u64,
        };
        let op = if *registered {
            libc::EPOLL_CTL_MOD
        } else {
            libc::EPOLL_CTL_ADD
        };
        if unsafe { libc::epoll_ctl(self.epfd.as_raw_fd(), op, fd, &mut ev) } != 0 {
            return Err(io::Error::last_os_error());
        }
        *registered = true;
        Ok(())
    }

    fn register(&mut self, sess: Session) {
        let sid = sess.id;
        let (cfd, ufd) = (sess.fd_client(), sess.fd_upstream());
        self.fd_index.insert(cfd, sid);
        self.fd_index.insert(ufd, sid);
        self.sessions.insert(sid, sess);
        let mut c_reg = false;
        let mut u_reg = false;
        if let Err(e) = self.sync_fd(sid, cfd, &mut c_reg) {
            log(&format!("reactor: 注册 client fd 失败（{e}）"));
            self.destroy(sid);
            return;
        }
        if let Err(e) = self.sync_fd(sid, ufd, &mut u_reg) {
            log(&format!("reactor: 注册 upstream fd 失败（{e}）"));
            self.destroy(sid);
            return;
        }
        if let Some(s) = self.sessions.get_mut(&sid) {
            s.client_reg = c_reg;
            s.upstream_reg = u_reg;
        }
        if let Some(loc) = LOCATIONS.get() {
            loc.lock().unwrap().insert(sid, self.idx);
        }
        if dbg_on() {
            log(&format!(
                "reactor-dbg: 注册 #{sid} cfd={cfd} ufd={ufd} worker={}",
                self.idx
            ));
        }
    }

    /// 会话收尾：摘 epoll/索引/注册表，统计递减，OwnedFd 随 drop 关闭。
    fn destroy(&mut self, sid: u64) {
        let Some(sess) = self.sessions.remove(&sid) else {
            return;
        };
        unsafe {
            libc::epoll_ctl(
                self.epfd.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                sess.client.as_raw_fd(),
                std::ptr::null_mut(),
            );
            libc::epoll_ctl(
                self.epfd.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                sess.upstream.as_raw_fd(),
                std::ptr::null_mut(),
            );
        }
        self.fd_index.remove(&sess.client.as_raw_fd());
        self.fd_index.remove(&sess.upstream.as_raw_fd());
        if let Some(loc) = LOCATIONS.get() {
            loc.lock().unwrap().remove(&sid);
        }
        if let Ok(mut m) = RELAY_CONNS.lock() {
            m.remove(&sid);
        }
        RELAY_STATS.conns_active.fetch_sub(1, Ordering::Relaxed);
    }

    fn handle_event(&mut self, fd: RawFd, revents: u32) {
        let Some(&sid) = self.fd_index.get(&fd) else {
            return;
        };
        if dbg_on() {
            log(&format!(
                "reactor-dbg: 事件 #{sid} fd={fd} revents=0x{revents:x}"
            ));
        }
        let (more, finished) = {
            let Some(sess) = self.sessions.get_mut(&sid) else {
                return;
            };
            let more = sess.on_event(sid, fd, revents);
            (more, sess.finished())
        };
        if more {
            self.pending.push(sid);
        }
        if finished {
            self.destroy(sid);
            return;
        }
        self.rearm(sid);
    }

    /// 依会话当前状态重新武装两个 fd（事件处理与自驱补泵共用）。
    fn rearm(&mut self, sid: u64) {
        let Some(sess) = self.sessions.get_mut(&sid) else {
            return;
        };
        // 重新武装两个 fd
        let (mut c_reg, mut u_reg) = (sess.client_reg, sess.upstream_reg);
        let (cfd, ufd) = (sess.fd_client(), sess.fd_upstream());
        if let Err(e) = self
            .sync_fd(sid, cfd, &mut c_reg)
            .and_then(|_| self.sync_fd(sid, ufd, &mut u_reg))
        {
            log(&format!("reactor: 重新武装失败 #{sid}（{e}）"));
            self.destroy(sid);
            return;
        }
        if let Some(s) = self.sessions.get_mut(&sid) {
            s.client_reg = c_reg;
            s.upstream_reg = u_reg;
        }
    }

    /// 自驱补泵一条 codec 会话（不依赖内核事件）；仍有内部余量则重新入队。
    fn pump_session(&mut self, sid: u64) {
        let (more, finished) = {
            let Some(sess) = self.sessions.get_mut(&sid) else {
                return;
            };
            let more = sess.codec_pump_both(sid);
            (more, sess.finished())
        };
        if more {
            self.pending.push(sid);
        }
        if finished {
            self.destroy(sid);
            return;
        }
        self.rearm(sid);
    }

    /// 周期检查：被强制 stop（janitor/关停）或注册表已移除的会话收尾。
    fn sweep(&mut self) {
        if dbg_on() && !self.sessions.is_empty() {
            let now = std::time::Instant::now();
            let _ = now;
            for (sid, s) in &self.sessions {
                let (cfd, ufd) = (s.fd_client(), s.fd_upstream());
                let ci = s.interest(cfd);
                let ui = s.interest(ufd);
                match &s.mode {
                    Mode::Codec { c2u, u2c } => log(&format!(
                        "reactor-dbg: dump #{sid} codec w={} c2u[pend={} eof={} fl={} done={}] u2c[pend={} eof={} fl={} done={}] int=0x{ci:x}/0x{ui:x}",
                        self.idx, c2u.pending(), c2u.eof, c2u.flush_pending, c2u.done,
                        u2c.pending(), u2c.eof, u2c.flush_pending, u2c.done
                    )),
                    Mode::Splice { .. } => {}
                }
            }
        }
        let dead: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.handle.stop.load(Ordering::Relaxed))
            .map(|(id, _)| *id)
            .collect();
        for sid in dead {
            self.destroy(sid);
        }
    }
}

/// 在拨号线程完成的「首读」：消费 VLESS 响应头/首个数据块并写给客户端。
/// 返回 `true` 表示还有后续数据（可交 reactor 继续 splice），`false` 表示首读即 EOF。
pub fn prelude<R: Read + ?Sized>(
    from_remote: &mut R,
    client: &mut TcpStream,
    handle: &RelayHandle,
) -> io::Result<bool> {
    let mut buf = [0u8; 65536];
    match from_remote.read(&mut buf)? {
        0 => Ok(false),
        n => {
            client.write_all(&buf[..n])?;
            handle.last_ns.store(monotonic_now_ns(), Ordering::Relaxed);
            RELAY_STATS
                .bytes_down
                .fetch_add(n as u64, Ordering::Relaxed);
            Ok(true)
        }
    }
}

/// 初始化 worker 池（幂等；在 relay 通道建立后调用一次）。
pub fn init() {
    if !enabled() {
        return;
    }
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(MIN_WORKERS, MAX_WORKERS);
    let (tx, rx) = std::sync::mpsc::channel::<Session>();
    let rx = Arc::new(Mutex::new(rx));
    let _ = LOCATIONS.set(Mutex::new(HashMap::new()));
    let mut workers = Vec::with_capacity(threads);
    for i in 0..threads {
        let w = match Worker::new(i) {
            Ok(w) => Arc::new(Mutex::new(w)),
            Err(e) => {
                log(&format!("reactor: worker 创建失败（{e}）"));
                continue;
            }
        };
        workers.push(w.clone());
        let rx = rx.clone();
        std::thread::spawn(move || worker_loop(w, rx, i));
    }
    if workers.is_empty() {
        log("reactor: 无可用 worker，回退线程模型");
        return;
    }
    log(&format!(
        "M4 reactor 已启动（{} workers，epoll/splice+codec，每连接 0 线程）",
        workers.len()
    ));
    let _ = WORKERS.set(workers);
    let _ = SUBMIT_TX.set(tx);
}

/// 交一条 splice 会话给 reactor。所有权：client/upstream fd 全部移交。
///
/// `prelude`：需要先消费协议响应头（VLESS）的读半。存在时下行（u2c）暂停，
/// 由一个短命线程用 codec 读半消费响应头/首块并写给客户端，完成后 `resume`。
/// 返回 false 表示 reactor 不可用或投递失败（fd 已关闭，调用方自行收尾统计）。
pub fn submit(
    client: TcpStream,
    upstream: TcpStream,
    handle: Arc<RelayHandle>,
    id: u64,
    prelude: Option<Box<dyn crate::outbound::ReadHalf>>,
) -> bool {
    // prelude 需要自己的一份 client 写半（此时 reactor 不碰 u2c）
    let (ca, cp, ua, upa) = (
        client.local_addr(),
        client.peer_addr(),
        upstream.local_addr(),
        upstream.peer_addr(),
    );
    let prelude_client = if prelude.is_some() {
        match client.try_clone() {
            Ok(c) => Some(c),
            Err(e) => {
                log(&format!("reactor: prelude client 克隆失败（{e}）"));
                return false;
            }
        }
    } else {
        None
    };
    let client: OwnedFd = client.into();
    let upstream: OwnedFd = upstream.into();
    let Some(tx) = SUBMIT_TX.get() else {
        // 未初始化：fd 随 OwnedFd 关闭，调用方收尾统计
        return false;
    };
    let paused = prelude.is_some();
    let sess = new_session(id, client, upstream, handle.clone(), paused);
    if tx.send(sess).is_err() {
        return false;
    }
    if dbg_on() {
        log(&format!(
            "reactor-dbg: 投递 #{id} paused={paused} prelude={} client={ca:?}->{cp:?} upstream={ua:?}->{upa:?}",
            prelude.is_some(),
        ));
    }
    wake_next();
    if let (Some(mut reader), Some(mut cw)) = (prelude, prelude_client) {
        std::thread::spawn(
            move || match self::prelude(&mut *reader, &mut cw, &handle) {
                Ok(_) => resume(id),
                Err(e) => {
                    log(&format!("reactor: prelude 首读失败（{e}）"));
                    kill(id);
                }
            },
        );
    }
    true
}

/// prelude 完成：恢复下行 splice。
pub fn resume(id: u64) {
    let Some(workers) = WORKERS.get() else { return };
    let Some(loc) = LOCATIONS.get() else { return };
    let idx = loc.lock().unwrap().get(&id).copied();
    let Some(idx) = idx else { return };
    let Some(w) = workers.get(idx) else { return };
    let mut w = w.lock().unwrap();
    let Some(sess) = w.sessions.get_mut(&id) else {
        return;
    };
    if !matches!(sess.mode, Mode::Splice { .. }) {
        return; // prelude 仅用于 splice 会话
    }
    sess.u2c_paused = false;
    // prelude 结束：读/写半不再被 codec 阻塞使用，切非阻塞让 fill/drain 批量搬运。
    set_nonblock(sess.fd_client());
    set_nonblock(sess.fd_upstream());
    sess.nonblock = true;
    let (mut c_reg, mut u_reg) = (sess.client_reg, sess.upstream_reg);
    let (cfd, ufd) = (sess.fd_client(), sess.fd_upstream());
    if let Err(e) = w
        .sync_fd(id, cfd, &mut c_reg)
        .and_then(|_| w.sync_fd(id, ufd, &mut u_reg))
    {
        log(&format!("reactor: resume 重新武装失败 #{id}（{e}）"));
        w.destroy(id);
        return;
    }
    if let Some(s) = w.sessions.get_mut(&id) {
        s.client_reg = c_reg;
        s.upstream_reg = u_reg;
    }
}

/// prelude 失败：立即结束会话。
pub fn kill(id: u64) {
    let Some(workers) = WORKERS.get() else { return };
    let Some(loc) = LOCATIONS.get() else { return };
    let idx = loc.lock().unwrap().get(&id).copied();
    let Some(idx) = idx else { return };
    if let Some(w) = workers.get(idx) {
        w.lock().unwrap().destroy(id);
    }
}

fn set_nonblock(fd: RawFd) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

/// 交一条 codec（非 splice）会话给 reactor：读半/写半在 worker 内非阻塞驱动。
///
/// 前置：调用方需确认 `codec_available()` 且该出站链路已通过
/// `Outbound::codec_reactor_capable()`（rustls VLESS-TCP / Trojan 等）。
/// `reader`/`writer` 必须对 WouldBlock 可重入（rustls 包装与 VLESS 响应头已支持）。
/// 返回 false 表示投递失败（fd 已随移交关闭，调用方收尾统计）。
pub fn submit_codec(
    client: TcpStream,
    upstream: TcpStream,
    handle: Arc<RelayHandle>,
    id: u64,
    reader: Box<dyn crate::outbound::ReadHalf>,
    writer: Box<dyn crate::outbound::WriteHalf>,
) -> bool {
    let Some(tx) = SUBMIT_TX.get() else {
        return false;
    };
    // 握手期读写超时对非阻塞数据面无意义（且在 epoll 下行为微妙），清掉。
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let _ = upstream.set_write_timeout(None);
    let sess = new_codec_session(id, client.into(), upstream.into(), handle, reader, writer);
    if tx.send(sess).is_err() {
        return false;
    }
    wake_next();
    if dbg_on() {
        log(&format!("reactor-dbg: codec 投递 #{id}"));
    }
    true
}

fn new_codec_session(
    id: u64,
    client: OwnedFd,
    upstream: OwnedFd,
    handle: Arc<RelayHandle>,
    reader: Box<dyn crate::outbound::ReadHalf>,
    writer: Box<dyn crate::outbound::WriteHalf>,
) -> Session {
    let (cfd, ufd) = (client.as_raw_fd(), upstream.as_raw_fd());
    set_nonblock(cfd);
    set_nonblock(ufd);
    Session {
        id,
        client,
        upstream,
        mode: Mode::Codec {
            c2u: CodecDir {
                src: cfd,
                dst: ufd,
                side: CodecSide::Sink(writer),
                out: crate::bufpool::PoolBuf::empty(),
                off: 0,
                eof: false,
                flush_pending: false,
                done: false,
            },
            u2c: CodecDir {
                src: ufd,
                dst: cfd,
                side: CodecSide::Source(reader),
                out: crate::bufpool::PoolBuf::empty(),
                off: 0,
                eof: false,
                flush_pending: false,
                done: false,
            },
        },
        u2c_paused: false,
        nonblock: true,
        handle,
        client_reg: false,
        upstream_reg: false,
        dead: false,
    }
}

/// 唤醒一个 worker（轮转）认领会话队列；`submit`/`submit_codec` 共用。
fn wake_next() {
    if let Some(workers) = WORKERS.get() {
        if workers.is_empty() {
            return;
        }
        let idx = NEXT_WORKER.fetch_add(1, Ordering::Relaxed) % workers.len();
        let v: u64 = 1;
        unsafe {
            libc::write(
                workers[idx].lock().unwrap().wake.as_raw_fd(),
                &v as *const u64 as *const libc::c_void,
                8,
            );
        }
    }
}

fn new_session(
    id: u64,
    client: OwnedFd,
    upstream: OwnedFd,
    handle: Arc<RelayHandle>,
    u2c_paused: bool,
) -> Session {
    fn pipe() -> io::Result<[RawFd; 2]> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_SZ);
        }
        Ok(fds)
    }
    let p1 = pipe().unwrap_or([-1, -1]);
    let p2 = pipe().unwrap_or([-1, -1]);
    let (cfd, ufd) = (client.as_raw_fd(), upstream.as_raw_fd());
    // 无 prelude（Direct 等）时立即切非阻塞，fill/drain 可批量搬运；
    // 有 prelude 时不能提前切（读半与 prelude 共享同一 file description），
    // 由 resume() 在首读完成后切。
    let nonblock = !u2c_paused;
    if nonblock {
        set_nonblock(cfd);
        set_nonblock(ufd);
    }
    Session {
        id,
        client,
        upstream,
        mode: Mode::Splice {
            c2u: Dir {
                src: cfd,
                dst: ufd,
                pipe: p1,
                pending: 0,
                eof: false,
                done: false,
            },
            u2c: Dir {
                src: ufd,
                dst: cfd,
                pipe: p2,
                pending: 0,
                eof: false,
                done: false,
            },
        },
        u2c_paused,
        nonblock,
        handle,
        client_reg: false,
        upstream_reg: false,
        dead: false,
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Mode::Splice { c2u, u2c } = &self.mode {
            for p in [c2u.pipe, u2c.pipe] {
                if p[0] >= 0 {
                    unsafe {
                        libc::close(p[0]);
                        libc::close(p[1]);
                    }
                }
            }
        }
        // Codec：读半/写半随 Mode 一并 drop（其 socket dup 随之关闭）。
    }
}

fn worker_loop(worker: Arc<Mutex<Worker>>, rx: Arc<Mutex<Receiver<Session>>>, _idx: usize) {
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 1024];
    let mut last_sweep = std::time::Instant::now();
    loop {
        let epfd = worker.lock().unwrap().epfd.as_raw_fd();
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, 1000) };
        // 先认领新会话（可能被其它 worker 抢走）
        loop {
            let sess = {
                let r = rx.lock().unwrap();
                match r.try_recv() {
                    Ok(s) => Some(s),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => None,
                }
            };
            match sess {
                Some(s) => worker.lock().unwrap().register(s),
                None => break,
            }
        }
        if n <= 0 {
            if last_sweep.elapsed() > Duration::from_millis(900) {
                worker.lock().unwrap().sweep();
                last_sweep = std::time::Instant::now();
            }
        } else {
            for ev in events.iter().take(n as usize) {
                let fd = ev.u64 as RawFd;
                let revents = ev.events;
                let mut w = worker.lock().unwrap();
                if fd == w.wake.as_raw_fd() {
                    // 清 eventfd
                    let mut buf = [0u8; 8];
                    unsafe {
                        libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8);
                    }
                    continue;
                }
                w.handle_event(fd, revents);
            }
        }
        // 预算耗尽的 codec 会话自驱补泵（内部缓冲已就绪但可能无内核事件）。
        // 每轮上限防饿死其它 fd；剩余项下轮继续。
        for _ in 0..256 {
            let mut w = worker.lock().unwrap();
            match w.pending.pop() {
                Some(sid) => w.pump_session(sid),
                None => break,
            }
        }
    }
}

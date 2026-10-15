// SPDX-License-Identifier: GPL-2.0
//! P5：outbound 协议栈——Dialer 抽象 + direct/socks5/http/shadowsocks/trojan/vless/vmess/tuic/hysteria2。
//!
//! 梯度与边界见 ADR-0004/ADR-0016/ADR-0018/ADR-0019：
//! - G1：direct、socks5（TCP）、http CONNECT（TCP）、shadowsocks（classic AEAD 与
//!   SIP022 2022-blake3-*，均 TCP+UDP）、trojan（TCP over TLS）；
//! - G2：vless（TCP+UDP，tls/none）、vmess（AEAD，alterId=0，tcp，TCP+UDP，tls 可选）；
//! - G3a：tuic v5（QUIC，TCP+UDP datagram）；G3b：hysteria2（QUIC，TCP+UDP datagram）；
//! - offload（内核拼接）只对「字节透明」的 direct/socks5 开启：其余协议需要在用户态
//!   做 AEAD/TLS 编解码，内核拼接会绕过协议层（ADR-0016 第 3 条）。

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use percent_encoding::percent_decode_str;
use sha2::{Digest as _, Sha256};

use crate::{
    anytls, group::GroupRuntime, hysteria2, juicity, quicsock, reality, shadowtls, socks5, ss, ssr,
    target::Target, tls, tls13, trojan, tuic, vision, vless, vmess, ws, DAE_SOCKET_MARK,
};

const SO_MARK_OPT: libc::c_int = 36;

/// 打 SO_MARK。lab/生产路径以 root 运行；非 root（例如 cargo test 本机跑跨实现
/// 单测）降级为告警而不是失败——此时没有数据面，不存在自环风险。
fn set_mark_fd(fd: RawFd) -> io::Result<()> {
    let value: libc::c_int = DAE_SOCKET_MARK;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_MARK_OPT,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EPERM) {
            eprintln!("sodama: SO_MARK 失败（非 root？），出口自环保护降级");
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

fn sockaddr_in_of(addr: SocketAddr) -> Option<libc::sockaddr_in> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        return None;
    };
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = addr.port().to_be();
    sin.sin_addr.s_addr = u32::from(v4).to_be();
    Some(sin)
}

/// 带 SO_MARK 的 TCP 连接（非阻塞 connect + poll 超时）。
/// 数据面（sodama_wan_egress/sodama_lan_ingress）见 mark 直接放行，避免代理出口自环。
pub fn marked_tcp_connect(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    // P0（2026-10-11）：域名节点每次拨号过粘滞缓存——作废/TTL 到期即重新解析
    // （旧实现只在解析期固定一次，机场轮换入口后节点永远钉在旧 IP 上）。
    // 非域名源（不在 origin 表）与仍有效的钉选原地址直通，零网络开销。
    let addr = crate::sticky::resolve_for_dial(addr);
    let (family, storage, sa_len) = match addr {
        SocketAddr::V4(_) => {
            let sin = sockaddr_in_of(addr).unwrap();
            let mut st = [0u8; 128];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    st.as_mut_ptr(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (
                libc::AF_INET,
                st,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            let mut st = [0u8; 128];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const _ as *const u8,
                    st.as_mut_ptr(),
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (
                libc::AF_INET6,
                st,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    let raw = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_mark_fd(fd.as_raw_fd())?;
    let sa = storage;
    let rc = unsafe { libc::connect(fd.as_raw_fd(), sa.as_ptr() as *const libc::sockaddr, sa_len) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err);
        }
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let prc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if prc == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
        }
        if prc < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut soerr: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut soerr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if soerr != 0 {
            return Err(io::Error::from_raw_os_error(soerr));
        }
    }
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    }
    // P7：控制面出站 socket 一律关 Nagle。ss/trojan/vless/vmess 写入是
    // 「帧头 + 载荷」多次小写，Nagle 等 ACK 会叠加 40ms 延迟（基准实测 ss
    // ping-pong p50=43ms；开 NODELAY 后回到微秒级）。
    let stream = TcpStream::from(fd);
    let _ = stream.set_nodelay(true);
    // ⚠ 握手期硬超时（2026-10-09 生产事故）：connect 的 timeout 只盖到
    // `poll(POLLOUT)` 为止；连接建立后 socket 是**阻塞且无读写超时**的，
    // 协议握手（VLESS 应答头 / anytls settings / TLS 记录）一旦碰上
    // “能建连但不回包”的节点就会在 recvfrom 里**永久阻塞**。
    // 这里先把 RCVTIMEO/SNDTIMEO 设成同一个 timeout，由 `Outbound::dial_tcp`
    // 在握手完成后清除（见那里的注释），不污染后续长空闲转发。
    set_sock_timeouts(stream.as_raw_fd(), Some(timeout))?;
    // 墙钟上限：握手无论怎么重试，到点都会被 shutdown 打断
    arm_dial_watchdog(stream.as_raw_fd(), timeout);
    Ok(stream)
}

/// 设置/清除 socket 的 `SO_RCVTIMEO` + `SO_SNDTIMEO`。
/// `None` = 清除（timeval 全 0 意为“永不超时”）。
/// SO_*TIMEO 是 socket 级选项，对该 socket 的所有 `dup` 副本生效，
/// 因此在一个 fd 上设/清即可惠及 `from_remote`/`to_remote`/`socket`。
// ---- 拨号墙钟看门狗 ----------------------------------------------------------
//
// 起因（2026-10-10 生产事故）：`marked_tcp_connect` 的 `timeout` 只覆盖
// `poll(POLLOUT)`；建连后 socket 是阻塞且无读写超时的，协议握手碰上
// “端口开、能建连、但不回包”的节点就在 recvfrom 里永久阻塞（实测 553 个
// probe 线程卡死 / VmSize 432 MB）。
// 加上 `SO_RCVTIMEO` 后阻塞被降级为「超时返回」，但握手路径仍可能在超时后
// 继续重试 —— 总时长依旧无上界。这里再加一层**墙钟上限**：到点直接
// `shutdown(2)` 该 socket，让任何阻塞中的读立刻返回，从而结束整个拨号。
//
// 用线程局部保存「本次拨号在看护的标志」：拨号在同一线程内完成；组拨号会
// 嵌套调用成员拨号，内层 armed→disarm 后外层拿到空值，互不干扰。

thread_local! {
    static CUR_DIAL_WATCH: std::cell::RefCell<Option<Arc<AtomicBool>>> =
        std::cell::RefCell::new(None);
}

/// 给 `fd` 起墙钟看门狗；返回取消标志（由 `disarm_dial_watchdog` 置位）。
fn arm_dial_watchdog(fd: RawFd, deadline: Duration) -> Option<Arc<AtomicBool>> {
    if deadline.is_zero() {
        return None;
    }
    // 取一份 dup 给看门狗，保证 shutdown 时 fd 仍有效
    let owned = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }
        .try_clone_to_owned()
        .ok()?;
    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    std::thread::Builder::new()
        .name("dial-wd".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            // 分片睡眠：正常拨号完成时立即退出，不空等整个 deadline
            let step = Duration::from_millis(20);
            let mut waited = Duration::ZERO;
            while waited < deadline {
                if c.load(AtomicOrdering::Relaxed) {
                    return;
                }
                let s = step.min(deadline - waited);
                std::thread::sleep(s);
                waited += s;
            }
            if c.load(AtomicOrdering::Relaxed) {
                return;
            }
            // 到点仍未结束：掐断连接，让阻塞中的读写立即返回
            let _ = unsafe { libc::shutdown(owned.as_raw_fd(), libc::SHUT_RDWR) };
        })
        .ok()?;
    CUR_DIAL_WATCH.with(|w| *w.borrow_mut() = Some(cancel.clone()));
    Some(cancel)
}

/// 拨号结束（无论成败）：取消本线程的看门狗。
/// H2 修复起对外可见（`pub(crate)`）：不经 `dial_tcp` 的拨号路径靠 `DialWatchdogGuard` 兜底。
pub(crate) fn disarm_dial_watchdog() {
    CUR_DIAL_WATCH.with(|w| {
        if let Some(c) = w.borrow_mut().take() {
            c.store(true, AtomicOrdering::Relaxed);
        }
    });
}

/// H2 修复：拨号看门狗作用域守卫——在 `marked_tcp_connect` 成功后创建，作用域结束
/// 自动解除本线程看门狗。修复「只在 `dial_tcp` 解除、其它路径武装后无人解除 → 到点
/// `shutdown(2)` 活跃 socket（DoH 持久连接实测 3 s 生命周期、UDP-over-stream 到点被断）」
/// 的 arm/disarm 不对称。
pub(crate) struct DialWatchdogGuard;

impl DialWatchdogGuard {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Drop for DialWatchdogGuard {
    fn drop(&mut self) {
        disarm_dial_watchdog();
    }
}

pub(crate) fn set_sock_timeouts(fd: std::os::fd::RawFd, t: Option<Duration>) -> io::Result<()> {
    let tv = match t {
        Some(d) => libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: d.subsec_micros() as libc::suseconds_t,
        },
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// 带 SO_MARK 的 UDP socket（未绑定；用于 DNS 上游与 UDP NAT/relay 出口）。
pub fn new_marked_udp() -> io::Result<UdpSocket> {
    new_marked_udp_for(std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
}

/// P22：按对端地址族创建（v6 目标/服务端需要 AF_INET6 才能 sendto）。
pub fn new_marked_udp_for(peer: SocketAddr) -> io::Result<UdpSocket> {
    let family = if peer.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_mark_fd(fd.as_raw_fd())?;
    set_udp_bufs(fd.as_raw_fd());
    Ok(UdpSocket::from(fd))
}

/// O7：UDP 转发 socket 收发缓冲（默认 ~212KB，突发/高 PPS 下会丢包）。
fn set_udp_bufs(fd: RawFd) {
    let sz: libc::c_int = 4 << 20;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

// ---------------------------------------------------------------- 流抽象

/// relay 的泵只需读半/写半；ss/trojan 在这里接入。
pub trait ReadHalf: Read + Send {}
impl<T: Read + Send + 'static> ReadHalf for T {}

/// 写半：能半关闭（EOF 后 shutdown write）。
pub trait WriteHalf: Write + Send {
    fn shutdown_write(&self) -> io::Result<()>;
}

impl WriteHalf for TcpStream {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

impl WriteHalf for ss::SsWriter {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl WriteHalf for tls::TlsWriter {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl WriteHalf for tuic::TuicWriteHalf {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl WriteHalf for hysteria2::Hy2WriteHalf {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl WriteHalf for juicity::JuicityWriteHalf {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl<W: WriteHalf> WriteHalf for vless::VlessWriter<W> {
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner().shutdown_write()
    }
}

impl WriteHalf for tls13::Tls13Writer {
    fn shutdown_write(&self) -> io::Result<()> {
        tls13::Tls13Writer::shutdown_write(self)
    }
}

impl WriteHalf for crate::h2client::TunnelWriter {
    fn shutdown_write(&self) -> io::Result<()> {
        crate::h2client::TunnelWriter::end_stream(self)
    }
}

impl WriteHalf for crate::h3client::H3TunnelWriter {
    fn shutdown_write(&self) -> io::Result<()> {
        crate::h3client::H3TunnelWriter::end_stream(self)
    }
}

impl WriteHalf for ssr::SsrWriteHalf {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl<W: WriteHalf> WriteHalf for vision::VisionWriter<W> {
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner().shutdown_write()
    }
}

impl<W: WriteHalf> WriteHalf for ws::WsWriter<W> {
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner().shutdown_write()
    }
}

impl<W: WriteHalf> WriteHalf for anytls::AnyTlsWriter<W> {
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner().shutdown_write()
    }
}

impl WriteHalf for Box<dyn WriteHalf> {
    fn shutdown_write(&self) -> io::Result<()> {
        (**self).shutdown_write()
    }
}

/// 按传输层包一层（tcp 直通 / ws 握手后帧化），统一到读写半的盒子里。
fn apply_ws<R, W>(
    r: R,
    w: W,
    transport: &VlessTransport,
) -> io::Result<(Box<dyn ReadHalf>, Box<dyn WriteHalf>)>
where
    R: Read + Send + 'static,
    W: WriteHalf + 'static,
{
    match transport {
        VlessTransport::Tcp => Ok((Box::new(r), Box::new(w))),
        VlessTransport::Ws { host, path } => {
            let (r, w) = ws::connect(r, w, host, path)?;
            Ok((Box::new(r), Box::new(w)))
        }
    }
}

impl<W: WriteHalf> WriteHalf for vmess::VmessWriter<W> {
    fn shutdown_write(&self) -> io::Result<()> {
        // 先发协议层终止块（服务端据此判半关闭），再关底层写方向
        self.send_terminator()?;
        match self.inner().lock() {
            Ok(g) => g.shutdown_write(),
            Err(p) => p.into_inner().shutdown_write(),
        }
    }
}

/// 拨号结果：读写两半（可并发）+ 底层 TCP（offload 注册/强制关闭）。
/// `splice`：数据面是否可直接 splice 零拷贝（字节透明且前缀已一次性发出；
/// 目前 Direct 与 VLESS 明文 TCP 置位）。
pub struct DialedStream {
    pub from_remote: Box<dyn ReadHalf>,
    pub to_remote: Box<dyn WriteHalf>,
    pub socket: Option<TcpStream>,
    /// 数据面可 splice（字节透明且前缀已一次性发出）。
    pub splice: bool,
    /// splice 前需由 codec 读半消费协议响应头（VLESS 等；Direct 为 false）。
    pub splice_prelude: bool,
}

// ---------------------------------------------------------------- UDP relay

/// 流式 UDP（vless/vmess）的发送/接收半：两种协议的帧格式不同，用 trait 抹平。
pub trait UdpDatagramSink: Send {
    fn send_datagram(&mut self, data: &[u8]) -> io::Result<()>;
}

pub trait UdpDatagramSource: Send {
    fn recv_datagram(&mut self) -> io::Result<Vec<u8>>;
}

impl<W: Write + Send> UdpDatagramSink for vless::VlessUdpWriter<W> {
    fn send_datagram(&mut self, data: &[u8]) -> io::Result<()> {
        vless::VlessUdpWriter::send_datagram(self, data)
    }
}

impl<R: Read + Send> UdpDatagramSource for vless::VlessUdpReader<R> {
    fn recv_datagram(&mut self) -> io::Result<Vec<u8>> {
        vless::VlessUdpReader::recv_datagram(self)
    }
}

impl<W: Write + Send> UdpDatagramSink for vmess::VmessUdpWriter<W> {
    fn send_datagram(&mut self, data: &[u8]) -> io::Result<()> {
        vmess::VmessUdpWriter::send_datagram(self, data)
    }
}

impl<R: Read + Send> UdpDatagramSource for vmess::VmessUdpReader<R> {
    fn recv_datagram(&mut self) -> io::Result<Vec<u8>> {
        vmess::VmessUdpReader::recv_datagram(self)
    }
}

enum UdpKind {
    /// 直连：send_to(target)/recv_from（不校验来源，保持 P4b 语义）。
    Plain(UdpSocket),
    /// shadowsocks：classic 每包独立 salt，SIP022 需要会话状态；socket 已 connect 到服务端。
    Ss {
        socket: UdpSocket,
        method: ss::SsMethod,
        master: Vec<u8>,
        /// SIP022 会话（packet id/重放窗口有状态）；classic 方法为 None。
        session: Option<Mutex<ss::Ss2022UdpSession>>,
    },
    /// vless/vmess 的 UDP over stream（TCP 或 TLS）：帧式封装，读写两半分开。
    Stream {
        /// 底层 TCP 副本，仅用于设置读超时（TLS 读也走同一个 socket）。
        timeout: TcpStream,
        read: Mutex<Box<dyn UdpDatagramSource>>,
        write: Mutex<Box<dyn UdpDatagramSink>>,
    },
    /// tuic v5：QUIC datagram（每会话一个 ASSOC_ID，无字节流）。
    Tuic { udp: Box<tuic::TuicUdp> },
    /// hysteria2：QUIC datagram（每会话一个 SessionID，一个 NAT 会话对应一个 ID）。
    Hy2 { udp: Box<hysteria2::Hy2Udp> },
    /// juicity：QUIC 双向流帧（元数据 + len u16 + 载荷）。
    Juicity { udp: Box<juicity::JuicityUdp> },
}

/// UDP 会话的出口（direct / ss / vless / vmess）。
pub struct UdpRelay {
    target: SocketAddr,
    kind: UdpKind,
}

fn lock_err<T>(_: T) -> io::Error {
    io::Error::other("udp relay: 锁中毒")
}

// ---------------------------------------------------------------- O7：UDP 批量收发

/// 接收槽容量（明文安全上限 65507 + 协议头余量；密文亦够）。
const UDP_SLOT: usize = 65_600;

/// v4/v6 通用 sockaddr（sendmmsg 的 msg_name 需要）。
fn sockaddr_any(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(a) => {
            let sin = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            (
                st,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(a) => {
            let sin6 = unsafe { &mut *(&mut st as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr.s6_addr = a.ip().octets();
            sin6.sin6_scope_id = a.scope_id();
            (
                st,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

/// O7 批量上限（栈上定长中转，避免每批堆分配）。
const UDP_BATCH_MAX: usize = 64;

/// 一次 `sendmmsg` 发出多个 UDP 报文；`name` 为 None 时走已 connect 的 socket。
/// 返回实际发出的字节数（UDP 无部分写语义：非 EINTR 的失败即丢失，与逐包一致）。
fn sendmmsg_udp(fd: RawFd, name: Option<SocketAddr>, datas: &[&[u8]]) -> io::Result<usize> {
    let n = datas.len().min(UDP_BATCH_MAX);
    let mut iovecs: [libc::iovec; UDP_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut names: [libc::sockaddr_storage; UDP_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; UDP_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut name_len: libc::socklen_t = 0;
    if let Some(addr) = name {
        let (st, l) = sockaddr_any(addr);
        name_len = l;
        for slot in names.iter_mut().take(n) {
            *slot = st;
        }
    }
    for i in 0..n {
        iovecs[i] = libc::iovec {
            iov_base: datas[i].as_ptr() as *mut libc::c_void,
            iov_len: datas[i].len(),
        };
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        if name.is_some() {
            msgs[i].msg_hdr.msg_name = &mut names[i] as *mut _ as *mut libc::c_void;
            msgs[i].msg_hdr.msg_namelen = name_len;
        }
    }
    let mut done = 0usize;
    let mut bytes = 0usize;
    while done < n {
        let rc = unsafe {
            libc::sendmmsg(
                fd,
                msgs.as_mut_ptr().add(done),
                (n - done) as libc::c_uint,
                0,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => break, // 非阻塞满：已发部分，其余按 UDP 语义丢弃
                _ => return Err(e),
            }
        }
        if rc == 0 {
            break;
        }
        let got = rc as usize;
        for d in datas.iter().skip(done).take(got) {
            bytes += d.len();
        }
        done += got;
    }
    Ok(bytes)
}

/// 一次 `recvmmsg` 收多个 UDP 报文（阻塞至首包，`MSG_WAITFORONE` 之后非阻塞排空）。
/// `out` 槽会被复用：先把 len 顶到槽容量再收，收完 truncate 到实际长度。
/// O8：槽按需增长——上一批收满才扩一个（上限 `max`），空闲会话只占 1 个槽。
fn recvmmsg_udp(
    fd: RawFd,
    out: &mut Vec<crate::bufpool::PoolBuf>,
    max: usize,
) -> io::Result<usize> {
    let cap = max.min(UDP_BATCH_MAX);
    if out.is_empty() {
        out.push(crate::bufpool::PoolBuf::zeroed(UDP_SLOT));
    }
    let n = out.len().min(cap);
    let mut iovecs: [libc::iovec; UDP_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut names: [libc::sockaddr_storage; UDP_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; UDP_BATCH_MAX] = unsafe { std::mem::zeroed() };
    for i in 0..n {
        let slot = &mut out[i];
        if slot.capacity() < UDP_SLOT {
            // 罕见路径（当前调用图不可达）：一次性补齐容量并零初始化。
            // L2 修复：旧守卫 `reserve(UDP_SLOT - cap)` 语义错误（reserve 保证的是
            // capacity ≥ len+additional），在 len<cap 时会越过容量。
            slot.as_mut_vec().resize(UDP_SLOT, 0);
        } else {
            // SAFETY：容量 ≥ UDP_SLOT；`PoolBuf` 缓冲自 zeroed() 起全字节已初始化
            // （之后仅 truncate 缩短 len），set_len 暴露的区间均已初始化。
            unsafe { slot.as_mut_vec().set_len(UDP_SLOT) };
        }
        iovecs[i] = libc::iovec {
            iov_base: slot.as_mut_ptr() as *mut libc::c_void,
            iov_len: UDP_SLOT,
        };
        msgs[i].msg_hdr.msg_name = &mut names[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    loop {
        let rc = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                n as libc::c_uint,
                crate::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        let got = rc as usize;
        for i in 0..got {
            let len = msgs[i].msg_len as usize;
            out[i].truncate(len.min(UDP_SLOT));
        }
        // 本批收满 → 下一批扩容一档（队列持续深时逐步升到 max）。
        if got == n && n < cap {
            out.push(crate::bufpool::PoolBuf::zeroed(UDP_SLOT));
        }
        return Ok(got);
    }
}

impl UdpRelay {
    /// O7：会话目标地址（日志/诊断用）。
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        match &self.kind {
            UdpKind::Plain(s) | UdpKind::Ss { socket: s, .. } => s.set_read_timeout(d),
            UdpKind::Stream { timeout, .. } => timeout.set_read_timeout(d),
            UdpKind::Tuic { udp } => {
                udp.set_read_timeout(d);
                Ok(())
            }
            UdpKind::Hy2 { udp } => {
                udp.set_read_timeout(d);
                Ok(())
            }
            UdpKind::Juicity { udp } => {
                udp.set_read_timeout(d);
                Ok(())
            }
        }
    }

    /// ss UDP 载荷：SOCKS5 风格目标地址头 + 数据（服务端据此路由）。
    fn ss_frame(&self, data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(data.len() + 19);
        match self.target {
            SocketAddr::V4(v4) => {
                frame.push(0x01);
                frame.extend_from_slice(&v4.ip().octets());
            }
            // P22：IPv6 目标（RFC1928 ATYP=0x04，16 字节地址）
            SocketAddr::V6(v6) => {
                frame.push(0x04);
                frame.extend_from_slice(&v6.ip().octets());
            }
        }
        frame.extend_from_slice(&self.target.port().to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    pub fn send_payload(&self, data: &[u8]) -> io::Result<usize> {
        match &self.kind {
            UdpKind::Plain(socket) => socket.send_to(data, self.target),
            UdpKind::Ss {
                socket,
                method,
                master,
                session,
            } => {
                let frame = self.ss_frame(data);
                let dg = match session {
                    Some(sess) => sess.lock().map_err(lock_err)?.seal(&frame),
                    None => ss::udp_seal(*method, master, &frame),
                };
                socket.send(&dg)
            }
            UdpKind::Stream { write, .. } => {
                let mut w = write.lock().map_err(lock_err)?;
                w.send_datagram(data).map(|_| data.len())
            }
            UdpKind::Tuic { udp } => udp.send(data),
            UdpKind::Hy2 { udp } => udp.send(data),
            UdpKind::Juicity { udp } => udp.send(data),
        }
    }

    /// O7：同一会话的连续报文批量上行。Plain/Ss 走 `sendmmsg`（1 次 syscall/N 包）；
    /// Stream/Tuic/Hy2/Juicity 因各自协议栈有状态/分帧，逐包发送（语义与旧路径一致）。
    pub fn send_batch(&self, datas: &[&[u8]]) -> io::Result<usize> {
        if datas.is_empty() {
            return Ok(0);
        }
        if datas.len() == 1 {
            return self.send_payload(datas[0]);
        }
        match &self.kind {
            UdpKind::Plain(socket) => sendmmsg_udp(socket.as_raw_fd(), Some(self.target), datas),
            UdpKind::Ss {
                socket,
                method,
                master,
                session,
            } => {
                // 顺序 seal（SIP022 packet id/重放窗口有状态，不能乱序）。
                let mut frames: Vec<Vec<u8>> = Vec::with_capacity(datas.len());
                for d in datas {
                    let frame = self.ss_frame(d);
                    let dg = match session {
                        Some(sess) => sess.lock().map_err(lock_err)?.seal(&frame),
                        None => ss::udp_seal(*method, master, &frame),
                    };
                    frames.push(dg);
                }
                let refs: Vec<&[u8]> = frames.iter().map(|v| v.as_slice()).collect();
                sendmmsg_udp(socket.as_raw_fd(), None, &refs)
            }
            _ => {
                let mut total = 0usize;
                for d in datas {
                    total += self.send_payload(d)?;
                }
                Ok(total)
            }
        }
    }

    /// 收一个包；Plain 返回原始载荷，Ss 解密后返回，流式协议解帧后返回。
    pub fn recv_payload(&self, _buf: &mut [u8]) -> io::Result<Vec<u8>> {
        match &self.kind {
            UdpKind::Plain(socket) => {
                let mut b = vec![0u8; 65536];
                let (n, _peer) = socket.recv_from(&mut b)?;
                b.truncate(n);
                Ok(b)
            }
            UdpKind::Ss {
                socket,
                method,
                master,
                session,
            } => {
                let mut b = vec![0u8; 65536];
                let n = socket.recv(&mut b)?;
                match session {
                    Some(sess) => sess.lock().map_err(lock_err)?.open(&b[..n]),
                    None => ss::udp_open(*method, master, &b[..n]),
                }
            }
            UdpKind::Stream { read, .. } => {
                let mut r = read.lock().map_err(lock_err)?;
                r.recv_datagram()
            }
            UdpKind::Tuic { udp } => udp.recv(),
            UdpKind::Hy2 { udp } => udp.recv(),
            UdpKind::Juicity { udp } => udp.recv(),
        }
    }

    /// O7：批量下行。Plain/Ss 用 `recvmmsg`（首包阻塞，`MSG_WAITFORONE` 之后非阻塞排空）；
    /// Stream/Tuic/Hy2/Juicity 逐包（QUIC/TCP 帧内已聚合，不再粘连阻塞）。
    /// `out` 为可复用槽（调用方保留；本函数负责扩容量与写入明文）。返回收到的包数。
    /// O8：槽按需增长（空会话只占 1 个 64KB 槽，队列深时才扩），且走缓冲池。
    pub fn recv_batch(
        &self,
        out: &mut Vec<crate::bufpool::PoolBuf>,
        max: usize,
    ) -> io::Result<usize> {
        if max == 0 {
            return Ok(0);
        }
        match &self.kind {
            UdpKind::Plain(socket) => recvmmsg_udp(socket.as_raw_fd(), out, max),
            UdpKind::Ss {
                socket,
                method,
                master,
                session,
            } => {
                let got = recvmmsg_udp(socket.as_raw_fd(), out, max)?;
                for slot in out.iter_mut().take(got) {
                    let pt = match session {
                        Some(sess) => sess.lock().map_err(lock_err)?.open(slot)?,
                        None => ss::udp_open(*method, master, slot)?,
                    };
                    slot.clear();
                    slot.extend_from_slice(&pt);
                }
                Ok(got)
            }
            _ => {
                let payload = self.recv_payload(&mut [])?;
                if out.is_empty() {
                    out.push(crate::bufpool::PoolBuf::zeroed(UDP_SLOT));
                }
                out[0].clear();
                out[0].extend_from_slice(&payload);
                Ok(1)
            }
        }
    }
}

// ---------------------------------------------------------------- Dialer

/// VLESS 传输层（P10：tcp / ws；grpc/h2/kcp 仍不支持）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VlessTransport {
    Tcp,
    /// WebSocket（RFC6455）；`host` 是 HTTP Host 头（CDN 域），`path` 是 Upgrade 路径。
    Ws {
        host: String,
        path: String,
    },
}

/// 可公开的节点元信息（状态面用；不含凭据）。
#[derive(Debug, Clone, Copy)]
pub struct NodeFacts {
    pub protocol: &'static str,
    /// tcp / ws / quic / h2 / —
    pub transport: &'static str,
    /// tls / reality / shadowtls / none / —
    pub security: &'static str,
    /// 该协议能否承载 UDP（不代表路由已放行 UDP；当前路由把 UDP 送 direct）
    pub udp: bool,
    pub addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub enum Outbound {
    Direct,
    Socks5 {
        server: SocketAddr,
    },
    /// HTTP CONNECT 隧道（`http://[user:pass@]host:port`，可选 Basic 认证）。
    Http {
        server: SocketAddr,
        /// `Proxy-Authorization: Basic base64(user:pass)`。
        auth: Option<(String, String)>,
    },
    Shadowsocks {
        server: SocketAddr,
        method: ss::SsMethod,
        master: Vec<u8>,
        /// P31：SIP003 `plugin=shadow-tls;...`（None = 直连 ss 服务端）。
        shadowtls: Option<shadowtls::ShadowTlsConfig>,
    },
    Trojan {
        server: SocketAddr,
        password: String,
        sni: String,
        insecure: bool,
    },
    Vless {
        server: SocketAddr,
        uuid: [u8; 16],
        tls: bool,
        sni: String,
        insecure: bool,
        transport: VlessTransport,
        /// P18c+：security=reality（pbk/sid/fp）；与 `tls` 互斥（reality 自带 TLS）。
        reality: Option<reality::RealityConfig>,
        /// P18c+：VLESS flow（仅支持 `xtls-rprx-vision`，且目前限 reality 传输）。
        flow: Option<String>,
    },
    Vmess {
        server: SocketAddr,
        uuid: [u8; 16],
        security: vmess::VmessSecurity,
        tls: bool,
        sni: String,
        insecure: bool,
    },
    Tuic {
        dialer: std::sync::Arc<tuic::TuicDialer>,
    },
    Hysteria2 {
        dialer: std::sync::Arc<hysteria2::Hy2Dialer>,
    },
    /// P11：AnyTLS（anytls-go 协议 v2，单 Stream）；TLS 固定开启。
    AnyTls {
        server: SocketAddr,
        password_sha256: [u8; 32],
        sni: String,
        insecure: bool,
    },
    /// P27：juicity v0（QUIC + TUIC 式认证 + trojan 风格元数据）。
    Juicity {
        dialer: std::sync::Arc<juicity::JuicityDialer>,
    },
    /// P30：SSR（shadowsocksr-stream；当前 origin+plain + 流密码，TCP）。
    Ssr {
        dialer: std::sync::Arc<ssr::SsrDialer>,
    },
    /// P25/P26：naive（CONNECT + Basic）；`h3=false` 走 HTTP/2（`naive+https://`），
    /// `h3=true` 走 HTTP/3（`naive+quic://`，QUIC 无底层 TcpStream）。
    Naive {
        server: SocketAddr,
        user: String,
        pass: String,
        sni: String,
        insecure: bool,
        h3: bool,
    },
    /// P15：节点组（订阅/内联节点池）+ policy + 健康检查；拨号层选择与失败切换。
    Group(std::sync::Arc<GroupRuntime>),
}

impl Outbound {
    pub fn name(&self) -> String {
        match self {
            Self::Direct => "direct".into(),
            Self::Socks5 { server } => format!("socks5://{server}"),
            Self::Http { server, .. } => format!("http://{server}"),
            Self::Shadowsocks { server, method, .. } => {
                format!("ss://{method_name}@{server}", method_name = method.name())
            }
            Self::Trojan { server, .. } => format!("trojan://{server}"),
            Self::Vless {
                server,
                tls,
                transport,
                reality,
                flow,
                ..
            } => {
                let xport = match transport {
                    VlessTransport::Tcp => String::new(),
                    VlessTransport::Ws { .. } => "&type=ws".to_string(),
                };
                let sec = if let Some(rc) = reality {
                    format!("reality&sni={}", rc.server_name)
                } else if *tls {
                    "tls".to_string()
                } else {
                    "none".to_string()
                };
                let fl = flow.as_deref().unwrap_or("");
                format!("vless://{server}?security={sec}{xport}&flow={fl}")
            }
            Self::Vmess {
                server, security, ..
            } => {
                let scy = match security {
                    vmess::VmessSecurity::Aes128Gcm => "aes-128-gcm",
                    vmess::VmessSecurity::Chacha20Poly1305 => "chacha20-poly1305",
                };
                format!("vmess://{server}?scy={scy}")
            }
            Self::Tuic { dialer } => dialer.name(),
            Self::Hysteria2 { dialer } => dialer.name(),
            Self::Juicity { dialer } => dialer.name(),
            Self::Ssr { dialer } => dialer.name(),
            Self::AnyTls { server, sni, .. } => format!("anytls://{server}?sni={sni}"),
            Self::Naive {
                server, h3: true, ..
            } => format!("naive+quic://{server}"),
            Self::Naive { server, .. } => format!("naive+https://{server}"),
            Self::Group(g) => format!("group:{}（{} 节点）", g.name, g.member_count()),
        }
    }

    /// 协议标签（稳定小写串；订阅解析预览/统计用）。
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Socks5 { .. } => "socks5",
            Self::Http { .. } => "http",
            Self::Shadowsocks { shadowtls, .. } => {
                if shadowtls.is_some() {
                    "shadowtls"
                } else {
                    "shadowsocks"
                }
            }
            Self::Trojan { .. } => "trojan",
            Self::Vless { .. } => "vless",
            Self::Vmess { .. } => "vmess",
            Self::Tuic { .. } => "tuic",
            Self::Hysteria2 { .. } => "hysteria2",
            Self::AnyTls { .. } => "anytls",
            Self::Juicity { .. } => "juicity",
            Self::Ssr { .. } => "ssr",
            Self::Naive { h3: true, .. } => "naive-quic",
            Self::Naive { .. } => "naive",
            Self::Group(_) => "group",
        }
    }

    /// O6：同健康/同延迟节点的 AEAD 方法偏好（小者优先）。
    ///
    /// 实测（本机 i9-9900KF，RustCrypto AEAD，16KB 块）：chacha20-poly1305
    /// 1.73 GB/s vs aes-256-gcm 1.57 GB/s（AES-GCM 受 GHASH ~2.3 GB/s 串行限制，
    /// 纯 AES-NI 块加密虽有 ~6 GB/s 但用不上）；端到端 ss TCP 也是 chacha 领先
    /// （5.8–9.7 vs 4.4–8.0 Gbps，CPU 更低）。因此本客户端保留 chacha 优先；
    /// TLS 类链路的方法由 rustls 按 CPU 特性自行协商（不受此影响）。
    pub fn crypto_pref(&self) -> u8 {
        match self {
            Self::Shadowsocks { method, .. } => u8::from(method.is_aes()),
            Self::Vmess { security, .. } => match security {
                vmess::VmessSecurity::Aes128Gcm => 1,
                vmess::VmessSecurity::Chacha20Poly1305 => 0,
            },
            _ => 0,
        }
    }

    /// offload 只对字节透明的封装开启（ss/trojan 有 AEAD/TLS 帧，内核拼接会绕过协议层）。
    pub fn supports_offload(&self) -> bool {
        matches!(self, Self::Direct | Self::Socks5 { .. })
    }

    /// M4 stage 2：该出站链路的读/写半是否已对 WouldBlock 可重入
    /// （可交 reactor codec 会话，每连接 0 线程）。
    ///
    /// 覆盖：Trojan（rustls）、VLESS-TCP 全组合（明文/rustls/REALITY/±vision）、
    /// vmess、ss（classic + SIP022，仅非 shadow-tls——shadow-tls 帧层仍用
    /// `read_exact`/`write_all` 原子语义，未审计）、ssr（origin+plain）、anytls。
    /// kTLS 成功的链路走 splice 分支；其余（tuic/hysteria2/juicity/naive/QUIC）不入池。
    pub fn codec_reactor_capable(&self) -> bool {
        match self {
            Self::Trojan { .. } => true,
            // VLESS 全组合（Tcp/Ws × 明文/rustls/REALITY/±vision）：读半/写半均已做
            // WouldBlock 可重入（VisionReader 帧头游标、WsReader 缓冲解析、VlessReader 状态机、
            // TlsReader/Tls13Reader 可续读；TlsWriter/Tls13Writer/VisionWriter/WsWriter 待刷队列）。
            Self::Vless { .. } => true,
            // vmess：读半为「缓冲+游标」可重入；写半已改待刷队列（stage 2）。
            Self::Vmess { .. } => true,
            // ss：读半 inbuf+帧游标、写半待刷队列（stage 2）；shadow-tls 插件除外。
            Self::Shadowsocks { shadowtls, .. } => shadowtls.is_none(),
            // ssr：读半 IV 缓冲续读、写半待刷队列（流密码只加密一次）。
            Self::Ssr { .. } => true,
            // anytls：读半 inbuf 帧解析、写半组帧入队（padding 只打散一次）。
            Self::AnyTls { .. } => true,
            // 组：全部成员都支持才放行（保守；成员随订阅热更新，逐成员实算）。
            //
            // 背景（生产实测 2026-10-08）：旧实现漏了 Group，落 `_ => false`，而生产
            // dialer 正是 `group:proxy` ⟹ `reactor_codec=false` ⟹ 所有代理连接退回
            // 双泵线程路径。现场斜率拟合：`线程 = 15.9 + 2.39 × 活跃连接`，而 Reactor
            // 池（2 workers）空转；开 `SODAMA_REACTOR_DEBUG=1` 复测 90s 真实流量，
            // `reactor-dbg: codec 投递` 行数为 **0**。
            Self::Group(g) => g.codec_reactor_capable_all(),
            _ => false,
        }
    }

    /// 状态面 / 控制面板用的「节点事实」：协议 + 传输 + 安全 + UDP 能力 + 地址。
    /// 只暴露可公开的元信息（不含 uuid/密码/密钥）。
    pub fn facts(&self) -> NodeFacts {
        let udp = self.supports_udp();
        let addr = self.server_addr();
        let (protocol, transport, security) = match self {
            Self::Direct => ("direct", "—", "—"),
            Self::Socks5 { .. } => ("socks5", "tcp", "—"),
            Self::Http { .. } => ("http", "tcp", "—"),
            Self::Shadowsocks { shadowtls, .. } => (
                if shadowtls.is_some() {
                    "shadowsocks"
                } else {
                    "shadowsocks"
                },
                "tcp",
                if shadowtls.is_some() {
                    "shadowtls"
                } else {
                    "none"
                },
            ),
            Self::Trojan { .. } => ("trojan", "tcp", "tls"),
            Self::Vless {
                tls,
                transport,
                reality,
                ..
            } => (
                "vless",
                match transport {
                    VlessTransport::Tcp => "tcp",
                    VlessTransport::Ws { .. } => "ws",
                },
                if reality.is_some() {
                    "reality"
                } else if *tls {
                    "tls"
                } else {
                    "none"
                },
            ),
            Self::Vmess { tls, .. } => ("vmess", "tcp", if *tls { "tls" } else { "none" }),
            Self::Tuic { .. } => ("tuic", "quic", "tls"),
            Self::Hysteria2 { .. } => ("hysteria2", "quic", "tls"),
            Self::AnyTls { .. } => ("anytls", "tcp", "tls"),
            Self::Juicity { .. } => ("juicity", "quic", "tls"),
            Self::Ssr { .. } => ("ssr", "tcp", "none"),
            Self::Naive { h3: true, .. } => ("naive", "quic", "tls"),
            Self::Naive { .. } => ("naive", "h2", "tls"),
            Self::Group(_) => ("group", "—", "—"),
        };
        NodeFacts {
            protocol,
            transport,
            security,
            udp,
            addr,
        }
    }

    /// 当前支持 UDP 代理的协议：ss（classic + SIP022）、vless/vmess（G2）、tuic（G3）、
    /// hysteria2（G3b）、juicity（P27）；http CONNECT/naive 仅 TCP。
    pub fn supports_udp(&self) -> bool {
        if let Self::Group(g) = self {
            return g.supports_udp();
        }
        if let Self::Shadowsocks { shadowtls, .. } = self {
            // shadow-tls 插件只做 TCP（P31 边界）。
            return shadowtls.is_none();
        }
        matches!(
            self,
            Self::Vless { .. }
                | Self::Vmess { .. }
                | Self::Tuic { .. }
                | Self::Hysteria2 { .. }
                | Self::Juicity { .. }
        )
    }

    /// P23：代理服务器地址（粘滞 IP 拨号结果反馈用；direct/组/QUIC 系返回 None）。
    pub fn server_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Socks5 { server }
            | Self::Http { server, .. }
            | Self::Shadowsocks { server, .. }
            | Self::Trojan { server, .. }
            | Self::Vless { server, .. }
            | Self::Vmess { server, .. }
            | Self::AnyTls { server, .. } => Some(*server),
            Self::Naive { server, .. } => Some(*server),
            Self::Ssr { dialer } => Some(dialer.server()),
            _ => None,
        }
    }

    pub fn dial_tcp(&self, target: &Target, timeout: Duration) -> io::Result<DialedStream> {
        let r = self.dial_tcp_inner(target, timeout);
        // 拨号已结束：先解除墙钟看门狗（成败都要）
        disarm_dial_watchdog();
        if let Some(server) = self.server_addr() {
            crate::sticky::note_dial(server, r.is_ok());
        }
        // 握手已结束：清掉 `marked_tcp_connect` 为握手设的读写超时。
        // 不留下是为了避免污染后续转发：泵路径会长时间空闲，残留的
        // RCVTIMEO 会把“安静但正常的连接”误判为超时。
        // （reactor 路径自己会把它置为非阻塞，非阻塞下 SO_RCVTIMEO 本就被忽略。）
        if let Ok(d) = &r {
            if let Some(s) = d.socket.as_ref() {
                let _ = set_sock_timeouts(s.as_raw_fd(), None);
            }
        }
        r
    }

    fn dial_tcp_inner(&self, target: &Target, timeout: Duration) -> io::Result<DialedStream> {
        match self {
            Self::Direct => {
                let addr = target.resolve_local()?;
                let sock = marked_tcp_connect(addr, timeout)?;
                let kill = sock.try_clone()?;
                let read = sock.try_clone()?;
                Ok(DialedStream {
                    from_remote: Box::new(read),
                    to_remote: Box::new(sock),
                    socket: Some(kill),
                    splice: true,
                    splice_prelude: false,
                })
            }
            Self::Socks5 { server } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let s = socks5::handshake(sock, target, timeout)?;
                let read = s.try_clone()?;
                Ok(DialedStream {
                    from_remote: Box::new(read),
                    to_remote: Box::new(s),
                    socket: Some(kill),
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Http { server, auth } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let s = http_connect(sock, target, auth.as_ref(), timeout)?;
                let read = s.try_clone()?;
                Ok(DialedStream {
                    from_remote: Box::new(read),
                    to_remote: Box::new(s),
                    socket: Some(kill),
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Shadowsocks {
                server,
                method,
                master,
                shadowtls: plugin,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let (reader, mut writer): (Box<dyn ReadHalf>, Box<dyn WriteHalf>) =
                    if let Some(cfg) = plugin {
                        if method.is_2022() {
                            return Err(io::Error::new(
                                io::ErrorKind::Unsupported,
                                "ss2022 + shadow-tls 插件未实现（P31 边界）",
                            ));
                        }
                        let (r, w) = shadowtls::connect(sock, cfg)?;
                        let kill2 = kill.try_clone()?;
                        let shutdown: ss::ShutdownFn =
                            Box::new(move || kill2.shutdown(std::net::Shutdown::Write));
                        let (r, w) = ss::connect_split_boxed(
                            Box::new(r),
                            Box::new(w),
                            Some(shutdown),
                            *method,
                            master,
                        )?;
                        (Box::new(r), Box::new(w))
                    } else {
                        let (r, w) = ss::connect_split(sock, *method, master)?;
                        (Box::new(r), Box::new(w))
                    };
                // 首块写 SOCKS5 风格目标地址头（IPv4 / 域名）
                let mut head = Vec::with_capacity(7 + 1 + 255);
                target.encode_socks_addr_port(&mut head)?;
                writer.write_all(&head)?;
                writer.flush()?;
                Ok(DialedStream {
                    from_remote: reader,
                    to_remote: writer,
                    socket: Some(kill),
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Trojan {
                server,
                password,
                sni,
                insecure,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let (reader, writer) =
                    trojan::connect(*server, password, sni, *insecure, target, timeout, sock)?;
                Ok(DialedStream {
                    from_remote: Box::new(reader),
                    to_remote: Box::new(writer),
                    socket: Some(kill),
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Vless {
                server,
                uuid,
                tls: use_tls,
                sni,
                insecure,
                transport,
                reality: reality_cfg,
                flow,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let vision = flow.as_deref() == Some("xtls-rprx-vision");
                // M3：vision 是 TCP+外层 TLS1.3 的会话级协议，不能与 ws 组合（Xray 同义）。
                if vision && !matches!(*transport, VlessTransport::Tcp) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "vless: flow=xtls-rprx-vision 仅支持 tcp 传输",
                    ));
                }
                // splice 条件：字节透明且无 vision（请求头已在 connect 时一次性发出，
                // 响应头由 relay 首读消费，之后可直接裸搬）；kTLS 成功时 TLS 路径同样透明。
                let mut splice = !*use_tls
                    && reality_cfg.is_none()
                    && matches!(*transport, VlessTransport::Tcp)
                    && !vision;
                let (from_remote, to_remote): (Box<dyn ReadHalf>, Box<dyn WriteHalf>) =
                    if let Some(rc) = reality_cfg {
                        let (tls_r, tls_w, raw_read, raw_write) =
                            reality::connect(sock, rc, Some(timeout))?;
                        // 外层 REALITY = TLS 1.3，满足 XTLS DIRECT 前提。
                        let sniffer = Arc::new(vision::TlsSniffer::new(true));
                        let (vr, vw) =
                            vless::connect_split_flow(tls_r, tls_w, uuid, target, flow.as_deref())?;
                        if vision {
                            (
                                Box::new(vision::VisionReader::new(
                                    vr,
                                    *uuid,
                                    raw_read,
                                    sniffer.clone(),
                                )),
                                Box::new(vision::VisionWriter::new(vw, *uuid, raw_write, sniffer)),
                            )
                        } else {
                            (Box::new(vr), Box::new(vw))
                        }
                    } else if *use_tls {
                        if vision {
                            // M3：Vision-over-TLS——不使用 kTLS（DIRECT 需中途停用外层加解密），
                            // 读半逐记录有界喂入，置位 raw 后双向裸 TCP 直通。
                            let ((r, w), raw) =
                                tls::connect_vision(sock, sni, *insecure, &[], timeout)?;
                            if !raw.outer_tls13 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "vless: flow=xtls-rprx-vision 需要外层 TLS 1.3",
                                ));
                            }
                            let sniffer = Arc::new(vision::TlsSniffer::new(true));
                            let (vr, vw) =
                                vless::connect_split_flow(r, w, uuid, target, flow.as_deref())?;
                            (
                                Box::new(vision::VisionReader::new(
                                    vr,
                                    *uuid,
                                    raw.read,
                                    sniffer.clone(),
                                )),
                                Box::new(vision::VisionWriter::new(vw, *uuid, raw.write, sniffer)),
                            )
                        } else {
                            let (r, w) = tls::connect(sock, sni, *insecure, &[], timeout)?;
                            if r.is_ktls() && w.is_ktls() {
                                // kTLS：加解密已下沉内核，数据面回到字节透明（同明文）。
                                splice = matches!(*transport, VlessTransport::Tcp);
                            }
                            let (r, w) = apply_ws(r, w, transport)?;
                            let (r, w) =
                                vless::connect_split_flow(r, w, uuid, target, flow.as_deref())?;
                            (Box::new(r), Box::new(w))
                        }
                    } else {
                        let read = sock.try_clone()?;
                        let (r, w) = apply_ws(read, sock, transport)?;
                        let (r, w) =
                            vless::connect_split_flow(r, w, uuid, target, flow.as_deref())?;
                        (Box::new(r), Box::new(w))
                    };
                Ok(DialedStream {
                    from_remote,
                    to_remote,
                    socket: Some(kill),
                    splice,
                    splice_prelude: splice,
                })
            }
            Self::Vmess {
                server,
                uuid,
                security,
                tls: use_tls,
                sni,
                insecure,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let cmd_key = vmess::cmd_key(uuid);
                if *use_tls {
                    let (r, w) = tls::connect(sock, sni, *insecure, &[], timeout)?;
                    let (r, w) = vmess::connect_split(r, w, &cmd_key, *security, target)?;
                    Ok(DialedStream {
                        from_remote: Box::new(r),
                        to_remote: Box::new(w),
                        socket: Some(kill),
                        splice: false,
                        splice_prelude: false,
                    })
                } else {
                    let read = sock.try_clone()?;
                    let (r, w) = vmess::connect_split(read, sock, &cmd_key, *security, target)?;
                    Ok(DialedStream {
                        from_remote: Box::new(r),
                        to_remote: Box::new(w),
                        socket: Some(kill),
                        splice: false,
                        splice_prelude: false,
                    })
                }
            }
            Self::Naive {
                server,
                user,
                pass,
                sni,
                insecure,
                h3,
            } => {
                use base64::Engine as _;
                let auth = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
                );
                if *h3 {
                    // P26：naive+quic（HTTP/3 CONNECT）——QUIC 无底层 TcpStream（socket=None，
                    // 与 tuic/hy2 一样不与 offload 搭配）。
                    let rustls_cfg = tls::build_rustls_config(*insecure, &[b"h3".to_vec()]);
                    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
                        .map_err(|e| io::Error::other(format!("naive h3 TLS 配置: {e}")))?;
                    let mut transport = quinn::TransportConfig::default();
                    transport.keep_alive_interval(Some(Duration::from_secs(5)));
                    transport.max_idle_timeout(Some(
                        quinn::IdleTimeout::try_from(Duration::from_secs(60))
                            .map_err(|e| io::Error::other(format!("naive h3 idle: {e}")))?,
                    ));
                    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
                    client_cfg.transport_config(Arc::new(transport));
                    let sock = new_marked_udp()?;
                    let rt = crate::tuic::runtime();
                    let mut endpoint = rt.block_on(async {
                        quinn::Endpoint::new(
                            quinn::EndpointConfig::default(),
                            None,
                            sock,
                            Arc::new(quinn::TokioRuntime),
                        )
                        .map_err(|e| io::Error::other(format!("naive h3 endpoint: {e}")))
                    })?;
                    endpoint.set_default_client_config(client_cfg);
                    let conn = rt.block_on(async {
                        let connecting = endpoint
                            .connect(*server, sni)
                            .map_err(|e| io::Error::other(format!("naive h3 connect: {e}")))?;
                        match tokio::time::timeout(timeout, connecting).await {
                            Ok(Ok(c)) => Ok(c),
                            Ok(Err(e)) => Err(io::Error::other(format!("naive h3 握手失败: {e}"))),
                            Err(_) => Err(io::Error::other("naive h3 连接超时")),
                        }
                    })?;
                    let h3conn =
                        crate::h3client::H3Conn::new(conn, endpoint).map_err(io::Error::other)?;
                    let (tr, tw) = h3conn
                        .connect_tunnel(
                            &target.to_string(),
                            &[("proxy-authorization", auth.as_str())],
                            timeout,
                        )
                        .map_err(io::Error::other)?;
                    return Ok(DialedStream {
                        from_remote: Box::new(tr),
                        to_remote: Box::new(tw),
                        socket: None,
                        splice: false,
                        splice_prelude: false,
                    });
                }
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let ((mut r, mut w), alpn) =
                    tls::connect_alpn(sock, sni, *insecure, &[b"h2".to_vec()], timeout)?;
                if alpn.as_deref() != Some(b"h2") {
                    return Err(io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "naive: 服务端未协商 ALPN=h2（naive+quic 用于 HTTP/3）",
                    ));
                }
                let mut h2 =
                    crate::h2client::H2Conn::handshake(&mut r, &mut w).map_err(io::Error::other)?;
                let (tr, tw) = h2
                    .connect_tunnel(
                        r,
                        w,
                        kill.try_clone()?,
                        &target.to_string(),
                        &[("proxy-authorization", auth.as_str())],
                    )
                    .map_err(io::Error::other)?;
                Ok(DialedStream {
                    from_remote: Box::new(tr),
                    to_remote: Box::new(tw),
                    socket: Some(kill),
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Tuic { dialer } => {
                // QUIC 无底层 TcpStream：socket=None（不与 offload 搭配，见 supports_offload）
                let (r, w) = dialer.connect_tcp(target, timeout)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: None,
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Hysteria2 { dialer } => {
                // QUIC 无底层 TcpStream：socket=None（不与 offload 搭配，见 supports_offload）
                let (r, w) = dialer.connect_tcp(target, timeout)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: None,
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Juicity { dialer } => {
                // QUIC 无底层 TcpStream：socket=None（不与 offload 搭配，见 supports_offload）
                let (r, w) = dialer.connect_tcp(target, timeout)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: None,
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Ssr { dialer } => {
                let sock = marked_tcp_connect(dialer.server(), timeout)?;
                let kill = sock.try_clone()?;
                let (r, w) = ssr::connect(sock, dialer.config(), target)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: Some(kill),
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::AnyTls {
                server,
                password_sha256,
                sni,
                insecure,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let (r, w) = tls::connect(sock, sni, *insecure, &[], timeout)?;
                let (r, w) = anytls::connect_split(r, w, password_sha256, target)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: Some(kill),
                    splice: false,
                    splice_prelude: false,
                })
            }
            Self::Group(g) => g.dial_tcp(target, timeout),
        }
    }

    /// UDP 出口；Ok(None) = 该协议不支持 UDP 代理（调用方决定直连回退）。
    pub fn dial_udp(&self, target: SocketAddr, timeout: Duration) -> io::Result<Option<UdpRelay>> {
        let r = self.dial_udp_inner(target, timeout);
        // H2 修复：与 dial_tcp 对称解除墙钟看门狗。旧实现遗漏此处：VLESS/VMess 的
        // UDP-over-stream 长连接会在 `timeout` 到点时被看门狗 shutdown（生产实测该
        // 机制导致 DoH 持久连接 3 s 生命周期；UDP-over-stream 同理）。
        disarm_dial_watchdog();
        if let Some(server) = self.server_addr() {
            crate::sticky::note_dial(server, r.is_ok());
        }
        r
    }

    fn dial_udp_inner(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> io::Result<Option<UdpRelay>> {
        match self {
            Self::Shadowsocks {
                server,
                method,
                master,
                shadowtls: plugin,
            } => {
                if plugin.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "ss + shadow-tls 不支持 UDP（P31 边界）",
                    ));
                }
                let socket = new_marked_udp_for(*server)?;
                socket.connect(server)?;
                // SIP022 UDP 需要客户会话 ID/packet id/重放窗口，建会话状态；classic 无状态。
                let session = if method.is_2022() {
                    Some(Mutex::new(ss::Ss2022UdpSession::new(*method, master)?))
                } else {
                    None
                };
                Ok(Some(UdpRelay {
                    target,
                    kind: UdpKind::Ss {
                        socket,
                        method: *method,
                        master: master.clone(),
                        session,
                    },
                }))
            }
            Self::Vless {
                server,
                uuid,
                tls: use_tls,
                sni,
                insecure,
                transport,
                reality: reality_cfg,
                ..
            } => {
                if reality_cfg.is_some() {
                    // P18c+：reality（含 vision）暂不支持 UDP over stream（vision 为 TCP 直通设计）。
                    return Ok(None);
                }
                let sock = marked_tcp_connect(*server, timeout)?;
                let timeout_sock = sock.try_clone()?;
                let (read, write): (Box<dyn UdpDatagramSource>, Box<dyn UdpDatagramSink>) =
                    if *use_tls {
                        let (r, w) = tls::connect(sock, sni, *insecure, &[], timeout)?;
                        let (r, w) = apply_ws(r, w, transport)?;
                        let (r, w) = vless::connect_split_udp(r, w, uuid, target)?;
                        (Box::new(r), Box::new(w))
                    } else {
                        let r = sock.try_clone()?;
                        let (r, w) = apply_ws(r, sock, transport)?;
                        let (r, w) = vless::connect_split_udp(r, w, uuid, target)?;
                        (Box::new(r), Box::new(w))
                    };
                Ok(Some(UdpRelay {
                    target,
                    kind: UdpKind::Stream {
                        timeout: timeout_sock,
                        read: Mutex::new(read),
                        write: Mutex::new(write),
                    },
                }))
            }
            Self::Vmess {
                server,
                uuid,
                security,
                tls: use_tls,
                sni,
                insecure,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let timeout_sock = sock.try_clone()?;
                let cmd_key = vmess::cmd_key(uuid);
                let (read, write): (Box<dyn UdpDatagramSource>, Box<dyn UdpDatagramSink>) =
                    if *use_tls {
                        let (r, w) = tls::connect(sock, sni, *insecure, &[], timeout)?;
                        let (r, w) = vmess::connect_split_udp(r, w, &cmd_key, *security, target)?;
                        (Box::new(r), Box::new(w))
                    } else {
                        let r = sock.try_clone()?;
                        let (r, w) =
                            vmess::connect_split_udp(r, sock, &cmd_key, *security, target)?;
                        (Box::new(r), Box::new(w))
                    };
                Ok(Some(UdpRelay {
                    target,
                    kind: UdpKind::Stream {
                        timeout: timeout_sock,
                        read: Mutex::new(read),
                        write: Mutex::new(write),
                    },
                }))
            }
            Self::Tuic { dialer } => Ok(Some(UdpRelay {
                target,
                kind: UdpKind::Tuic {
                    udp: Box::new(dialer.connect_udp(target)?),
                },
            })),
            Self::Hysteria2 { dialer } => Ok(Some(UdpRelay {
                target,
                kind: UdpKind::Hy2 {
                    udp: Box::new(dialer.connect_udp(target)?),
                },
            })),
            Self::Juicity { dialer } => Ok(Some(UdpRelay {
                target,
                kind: UdpKind::Juicity {
                    udp: Box::new(dialer.connect_udp(target)?),
                },
            })),
            Self::Group(g) => g.dial_udp(target, timeout),
            _ => Ok(None),
        }
    }

    /// 直连 UDP 出口（无 dialer 或协议不支持 UDP 时的回退）。
    pub fn direct_udp(target: SocketAddr) -> io::Result<UdpRelay> {
        Ok(UdpRelay {
            target,
            kind: UdpKind::Plain(new_marked_udp_for(target)?),
        })
    }
}

// ---------------------------------------------------------------- URL 解析

/// 解析 `--dialer`：direct / socks5:// / ss:// / trojan:// / vless:// / vmess:// / tuic:// /
/// hysteria2://（别名 hy2://）。（为兼容也接受裸 host:port = socks5）。
pub fn parse(url: &str) -> Result<Outbound, String> {
    if url == "direct" || url.starts_with("direct://") {
        return Ok(Outbound::Direct);
    }
    if let Some(rest) = url.strip_prefix("ss://") {
        return parse_ss(rest);
    }
    if let Some(rest) = url.strip_prefix("http://") {
        return parse_http(rest);
    }
    if let Some(rest) = url.strip_prefix("trojan://") {
        return parse_trojan(rest);
    }
    if let Some(rest) = url.strip_prefix("vless://") {
        return parse_vless(rest);
    }
    if let Some(rest) = url.strip_prefix("vmess://") {
        return parse_vmess(rest);
    }
    if let Some(rest) = url.strip_prefix("tuic://") {
        return parse_tuic(rest);
    }
    if let Some(rest) = url.strip_prefix("hysteria2://") {
        return parse_hysteria2(rest);
    }
    if let Some(rest) = url.strip_prefix("hy2://") {
        return parse_hysteria2(rest);
    }
    if let Some(rest) = url.strip_prefix("anytls://") {
        return parse_anytls(rest);
    }
    if let Some(rest) = url.strip_prefix("juicity://") {
        return parse_juicity(rest);
    }
    if url.starts_with("ssr://") {
        return parse_ssr_link(url);
    }
    // P25/P26：naive（h2 = naive+https/naive；h3 = naive+quic）
    if let Some(rest) = url.strip_prefix("naive+https://") {
        return parse_naive(rest, false);
    }
    if let Some(rest) = url.strip_prefix("naive+quic://") {
        return parse_naive(rest, true);
    }
    if let Some(rest) = url.strip_prefix("naive://") {
        return parse_naive(rest, false);
    }
    if url.starts_with("socks5://") || url.contains(':') {
        return Ok(Outbound::Socks5 {
            server: resolve(socks5::parse_proxy(url)?.as_str())?,
        });
    }
    Err(format!(
        "--dialer 不支持 {url}（direct / socks5:// / http:// / ss:// / ssr:// / trojan:// / vless:// / \
         vmess:// / tuic:// / hysteria2:// / hy2:// / anytls:// / naive+https:// / naive+quic:// / \
         juicity://）"
    ))
}

fn resolve(hostport: &str) -> Result<SocketAddr, String> {
    // P23：域名地址走粘滞 IP 缓存（dae StickyIpDialer）：固定 IP + 失败阈值后重解析。
    crate::sticky::resolve(hostport)
}

/// `anytls://password@host:port?sni=...&insecure=1`（anytls-go 协议，见 `anytls.rs`）。
///
/// TLS 固定开启（AnyTLS 基于 TLS）；密码在解析期即 SHA-256（协议认证只发摘要）。
fn parse_anytls(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let (id, hostport) = main
        .split_once('@')
        .ok_or_else(|| "anytls:// 需要 password@host:port".to_string())?;
    let password = percent_decode(id);
    if password.is_empty() {
        return Err("anytls:// 密码为空".to_string());
    }
    let mut sni: Option<String> = None;
    let mut insecure = false;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k.to_ascii_lowercase().as_str() {
            "sni" | "peer" => sni = Some(percent_decode(v)),
            "insecure" | "allowinsecure" | "skip-cert-verify" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            _ => {}
        }
    }
    let hostport = percent_decode(hostport);
    let default_sni = hostport
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| hostport.clone());
    let password_sha256: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    Ok(Outbound::AnyTls {
        server: resolve(&hostport)?,
        password_sha256,
        sni: sni.unwrap_or(default_sni),
        insecure,
    })
}

/// `naive+https://user:pass@host:port?sni=…&insecure=1`（naiveproxy；`h3=false` 走
/// HTTP/2 CONNECT，`h3=true`（`naive+quic://`）走 HTTP/3 CONNECT）。
fn parse_naive(rest: &str, h3: bool) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let (userinfo, hostport) = main
        .rsplit_once('@')
        .ok_or_else(|| "naive:// 需要 user:pass@host:port".to_string())?;
    let (user, pass) = match userinfo.split_once(':') {
        Some((u, p)) => (percent_decode(u), percent_decode(p)),
        None => (percent_decode(userinfo), String::new()),
    };
    let mut sni: Option<String> = None;
    let mut insecure = false;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k.to_ascii_lowercase().as_str() {
            "sni" | "peer" | "servername" => sni = Some(percent_decode(v)),
            "insecure" | "allowinsecure" | "allow_insecure" | "skipverify" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            "alpn" => { /* naive 固定传输（h2/h3 由 scheme 决定），忽略 */ }
            _ => {}
        }
    }
    let hostport = percent_decode(hostport);
    let default_sni = if let Some(r) = hostport.strip_prefix('[') {
        r.split_once(']')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| hostport.clone())
    } else {
        hostport
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| hostport.clone())
    };
    Ok(Outbound::Naive {
        server: resolve(&hostport)?,
        user,
        pass,
        sni: sni.unwrap_or(default_sni),
        insecure,
        h3,
    })
}

/// `juicity://uuid:password@host:port?sni=…&allow_insecure=1`（juicity v0，QUIC）。
///
/// 本地 CC 参数（`congestion_control`/`cwnd`/`cc_override`）与
/// `pinned_certchain_sha256` 未实现（忽略，边界见 ADR-0051）。
fn parse_juicity(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let (userinfo, hostport) = main
        .split_once('@')
        .ok_or_else(|| "juicity:// 需要 uuid:password@host:port".to_string())?;
    let (uuid_s, password_raw) = userinfo
        .split_once(':')
        .ok_or_else(|| "juicity:// userinfo 需要 uuid:password".to_string())?;
    let uuid_s = percent_decode(uuid_s);
    let compact: String = uuid_s.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("juicity:// uuid 非法: {uuid_s}"));
    }
    let uuid = vless::parse_uuid(&uuid_s).ok_or_else(|| "juicity:// uuid 非法".to_string())?;
    let password = percent_decode(password_raw);
    let mut sni: Option<String> = None;
    let mut insecure = false;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k.to_ascii_lowercase().as_str() {
            "sni" | "peer" | "servername" => sni = Some(percent_decode(v)),
            "allowinsecure" | "allow_insecure" | "insecure" | "skipverify" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            // 本地 CC/证书固定：忽略（见 ADR-0051 边界）
            "congestion_control"
            | "congestion"
            | "cc_override"
            | "cwnd"
            | "pinned_certchain_sha256" => {}
            _ => {}
        }
    }
    let hostport = percent_decode(hostport);
    let default_sni = if let Some(r) = hostport.strip_prefix('[') {
        r.split_once(']')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| hostport.clone())
    } else {
        hostport
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| hostport.clone())
    };
    Ok(Outbound::Juicity {
        dialer: Arc::new(juicity::JuicityDialer::new(juicity::JuicityConfig {
            server: resolve(&hostport)?,
            uuid,
            password,
            sni: sni.unwrap_or(default_sni),
            insecure,
        })),
    })
}

/// `ssr://...`（shadowsocksr-stream；当前 origin+plain + 流密码，见 ADR-0054）。
fn parse_ssr_link(url: &str) -> Result<Outbound, String> {
    // 先剥 fragment（生态里会有 #remarks 附加）
    let url = url.split('#').next().unwrap_or(url);
    let cfg = ssr::parse_link(url)?;
    Ok(Outbound::Ssr {
        dialer: Arc::new(ssr::SsrDialer::new(cfg)),
    })
}

fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for e in engines {
        if let Ok(v) = e.decode(s) {
            return Some(v);
        }
    }
    None
}

/// `vless://uuid@host:port?type=tcp|ws&security=tls|reality&sni=...&flow=xtls-rprx-vision`
///
/// 传输：tcp / ws（`host`/`path` 参数，缺省 host=sni、path=/）；headerType=none；
/// security=reality 需 `pbk`（base64url）/`sid`（hex）/`fp`（chrome）；
/// flow 仅支持 `xtls-rprx-vision`（P18c+，且目前限 reality 传输）。
fn parse_vless(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let (id, hostport) = main
        .split_once('@')
        .ok_or_else(|| "vless:// 需要 uuid@host:port".to_string())?;
    let mut use_tls = false;
    let mut sni: Option<String> = None;
    let mut insecure = false;
    let mut ws = false;
    let mut ws_host: Option<String> = None;
    let mut ws_path: Option<String> = None;
    let mut flow: Option<String> = None;
    let mut is_reality = false;
    let mut pbk: Option<String> = None;
    let mut sid: Option<String> = None;
    let mut fp: Option<String> = None;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k.to_ascii_lowercase().as_str() {
            "type" => match v.to_ascii_lowercase().as_str() {
                "" | "tcp" => {}
                "ws" => ws = true,
                other => return Err(format!("vless:// 传输 {other} 未实现（只做 tcp/ws）")),
            },
            "headertype" if !matches!(v.to_ascii_lowercase().as_str(), "" | "none") => {
                return Err(format!("vless:// headerType={v} 未实现（G2 只做 none）"))
            }
            "security" => match v.to_ascii_lowercase().as_str() {
                "" | "none" => use_tls = false,
                "tls" => use_tls = true,
                "reality" => is_reality = true,
                other => {
                    return Err(format!(
                        "vless:// security={other} 未实现（只做 tls/none/reality）"
                    ))
                }
            },
            "sni" | "peer" | "servername" => sni = Some(percent_decode(v)),
            "host" => ws_host = Some(percent_decode(v)),
            "path" => ws_path = Some(percent_decode(v)),
            "allowinsecure" | "insecure" | "skip-cert-verify" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            "flow" if !v.is_empty() => {
                let f = percent_decode(v);
                if f != "xtls-rprx-vision" {
                    return Err(format!("vless:// flow={f} 未实现（只做 xtls-rprx-vision）"));
                }
                flow = Some(f);
            }
            "encryption" if !matches!(v.to_ascii_lowercase().as_str(), "" | "none") => {
                return Err(format!("vless:// encryption={v} 未实现（只做 none）"))
            }
            "pbk" | "publickey" => pbk = Some(percent_decode(v)),
            "sid" | "shortid" => sid = Some(percent_decode(v)),
            "fp" | "fingerprint" => fp = Some(percent_decode(v)),
            _ => {}
        }
    }
    let hostport = percent_decode(hostport);
    let uuid =
        vless::parse_uuid(&percent_decode(id)).ok_or_else(|| "vless:// uuid 非法".to_string())?;
    let default_sni = hostport
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| hostport.clone());
    let sni = sni.unwrap_or(default_sni);
    let transport = if ws {
        VlessTransport::Ws {
            host: ws_host.unwrap_or_else(|| sni.clone()),
            path: ws_path.unwrap_or_else(|| "/".to_string()),
        }
    } else {
        VlessTransport::Tcp
    };
    let reality = if is_reality {
        if !matches!(transport, VlessTransport::Tcp) {
            return Err("vless:// reality 只支持 tcp 传输".to_string());
        }
        let pbk = pbk.ok_or_else(|| "vless:// security=reality 缺 pbk".to_string())?;
        let pk =
            reality::RealityConfig::parse_public_key(&pbk).map_err(|e| format!("vless:// {e}"))?;
        let short = reality::RealityConfig::parse_short_id(sid.as_deref().unwrap_or(""))
            .map_err(|e| format!("vless:// {e}"))?;
        let fp = fp.unwrap_or_else(|| "chrome".to_string());
        Some(reality::RealityConfig::new(&sni, pk, short, &fp))
    } else {
        None
    };
    // M3：vision 需外层 TLS1.3（tls 或 reality）且限 TCP（Xray 同义）。
    if flow.is_some() {
        if !use_tls && reality.is_none() {
            return Err(
                "vless:// flow=xtls-rprx-vision 需要 security=tls 或 security=reality".to_string(),
            );
        }
        if ws {
            return Err("vless:// flow=xtls-rprx-vision 仅支持 tcp 传输".to_string());
        }
    }
    Ok(Outbound::Vless {
        server: resolve(&hostport)?,
        uuid,
        tls: use_tls,
        sni,
        insecure,
        transport,
        reality,
        flow,
    })
}

/// `vmess://base64(JSON)`（v2rayN 分享格式）。
///
/// 支持子集：net=tcp、type=none、aid=0、scy ∈ {auto,aes-128-gcm,chacha20-poly1305}、
/// tls 可选；legacy 文本形式与 ws/grpc/h2/kcp 显式拒绝（ADR-0017）。
fn parse_vmess(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let raw = b64_decode_any(rest).ok_or_else(|| "vmess:// base64 解码失败".to_string())?;
    let text = String::from_utf8(raw).map_err(|e| format!("vmess:// 不是 UTF-8: {e}"))?;
    let obj: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("vmess:// JSON 解析失败: {e}"))?;
    let get_str = |k: &str| -> Option<String> {
        obj.get(k).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    };
    let add = get_str("add").ok_or_else(|| "vmess:// 缺少 add".to_string())?;
    let port: u16 = get_str("port")
        .ok_or_else(|| "vmess:// 缺少 port".to_string())?
        .parse()
        .map_err(|e| format!("vmess:// port 非法: {e}"))?;
    let id = get_str("id").ok_or_else(|| "vmess:// 缺少 id".to_string())?;
    let aid = get_str("aid").unwrap_or_default();
    if !matches!(aid.as_str(), "" | "0") {
        return Err(format!(
            "vmess:// alterId={aid} 未实现（G2 只做 AEAD，aid=0）"
        ));
    }
    let scy = get_str("scy").unwrap_or_else(|| "auto".into());
    let security = vmess::VmessSecurity::from_scy(&scy).ok_or_else(|| {
        format!("vmess:// scy={scy} 未实现（只做 aes-128-gcm/chacha20-poly1305）")
    })?;
    let net = get_str("net").unwrap_or_default();
    if !matches!(net.to_ascii_lowercase().as_str(), "" | "tcp") {
        return Err(format!("vmess:// net={net} 未实现（G2 只做 tcp）"));
    }
    let htype = get_str("type").unwrap_or_default();
    if !matches!(htype.to_ascii_lowercase().as_str(), "" | "none") {
        return Err(format!("vmess:// type={htype} 未实现（G2 只做 none）"));
    }
    for k in ["flow", "pbk", "sid", "spx"] {
        if get_str(k).map(|v| !v.is_empty()).unwrap_or(false) {
            return Err(format!("vmess:// {k} 未实现（reality/vision 属后续档位）"));
        }
    }
    if get_str("fp").map(|v| !v.is_empty()).unwrap_or(false) {
        return Err("vmess:// fp（uTLS 指纹）未实现".into());
    }
    let tls_field = get_str("tls").unwrap_or_default();
    let use_tls = match tls_field.to_ascii_lowercase().as_str() {
        "" | "none" => false,
        "tls" => true,
        other => return Err(format!("vmess:// tls={other} 未实现（只做 tls/none）")),
    };
    if !use_tls && get_str("alpn").map(|v| !v.is_empty()).unwrap_or(false) {
        return Err("vmess:// 未开 tls 却带 alpn".into());
    }
    let insecure = obj
        .get("allowInsecure")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let uuid = vless::parse_uuid(&id).ok_or_else(|| "vmess:// id 非法".to_string())?;
    let sni = get_str("sni")
        .or_else(|| get_str("host"))
        .filter(|s| !s.is_empty())
        .unwrap_or(add.clone());
    Ok(Outbound::Vmess {
        server: resolve(&format!("{add}:{port}"))?,
        uuid,
        security,
        tls: use_tls,
        sni,
        insecure,
    })
}

/// `tuic://uuid:password@host:port?sni=&allow_insecure=1&alpn=h3&congestion_control=bbr&udp_relay_mode=native`
///
/// 边界（ADR-0018）：只做 native datagram 模式（`udp_relay_mode=quic` 拒绝）；
/// `congestion_control`/`cc_override`/`cwnd` 是客户端本地 CC 选择，无线上语义，接受但不
/// 参与（quinn 用自带 CC）；`disable_sni=1` 强制 insecure（与 Go 侧一致）。
fn parse_tuic(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let (userinfo, hostport) = main
        .split_once('@')
        .ok_or_else(|| "tuic:// 需要 uuid:password@host:port".to_string())?;
    let (uuid_s, password_raw) = userinfo
        .split_once(':')
        .ok_or_else(|| "tuic:// userinfo 需要 uuid:password".to_string())?;
    let uuid_s = percent_decode(uuid_s);
    // tuic 严格校验 UUID（不做 UUID5 回退，对照 uuid.Parse）
    let compact: String = uuid_s.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("tuic:// uuid 非法: {uuid_s}"));
    }
    let uuid = vless::parse_uuid(&uuid_s).ok_or_else(|| "tuic:// uuid 非法".to_string())?;
    let password = percent_decode(password_raw);

    let mut sni: Option<String> = None;
    let mut insecure = false;
    let mut alpn: Option<Vec<Vec<u8>>> = None;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k.to_ascii_lowercase().as_str() {
            "sni" | "peer" => sni = Some(percent_decode(v)),
            "allowinsecure" | "allow_insecure" | "skipverify" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            "disable_sni" => {
                if matches!(v, "1" | "true" | "TRUE" | "True") {
                    sni = Some(String::new());
                    insecure = true;
                }
            }
            "alpn" => {
                let list: Vec<Vec<u8>> = v
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.as_bytes().to_vec())
                    .collect();
                if !list.is_empty() {
                    alpn = Some(list);
                }
            }
            "udp_relay_mode" => match v.to_ascii_lowercase().as_str() {
                "" | "native" => {}
                other => {
                    return Err(format!(
                        "tuic:// udp_relay_mode={other} 未实现（G3 只做 native datagram）"
                    ))
                }
            },
            // 客户端本地 CC 选择，无线上语义（quinn 用自带 CC）
            "congestion_control" | "congestion" | "cc_override" | "cwnd" | "type" => {}
            _ => {}
        }
    }
    let hostport = percent_decode(hostport);
    let default_sni = hostport
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| hostport.clone());
    let sni = sni.unwrap_or(default_sni);
    let cfg = tuic::TuicConfig {
        server: resolve(&hostport)?,
        uuid,
        password,
        sni,
        insecure,
        alpn: alpn.unwrap_or_default(),
    };
    Ok(Outbound::Tuic {
        dialer: std::sync::Arc::new(tuic::TuicDialer::new(cfg)),
    })
}

/// `hysteria2://auth@host:port?sni=&insecure=1&downmbps=100&upmbps=50`（别名 `hy2://`）
///
/// 端口可写并集（`443,8443-8450` / `all`）= udphop；`obfs=salamander&obfs-password=…` = 混淆；
/// `cc_override=bbr|brutal|bbr3`（其余拒绝，与 Go 侧一致）。仍不做：pinSHA256/ECH/自定义 CA。
/// upmbps/downmbps 按 Go 侧语义转字节/秒（Mbps × 1_000_000 / 8）：下行（downmbps/maxRx）
/// 作为 `Hysteria-CC-RX` 上报；上行（upmbps/maxTx）是 Brutal 目标的客户端上限。
/// `udphop-interval=<秒>`（默认 30，最小 5）是 sodama 扩展：dae 把该值放在全局配置
/// `udphop_interval`，链接语法里没有（见 ADR-0020）。
fn parse_hysteria2(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    // url.User 语义：user/password 分开百分号解码后按 `:` 拼回（hysteria2 认证串即 user:pass）。
    // 无 userinfo（无 `@`）时 auth 为空串（与 Go 的 u.User.Username() 一致）。
    let (userinfo, hostport) = match main.split_once('@') {
        Some((u, h)) => (u, h),
        None => ("", main),
    };
    let auth = match userinfo.split_once(':') {
        Some((u, p)) => format!("{}:{}", percent_decode(u), percent_decode(p)),
        None => percent_decode(userinfo),
    };

    let mut sni: Option<String> = None;
    let mut insecure = false;
    let mut max_tx: u64 = 0;
    let mut max_rx: u64 = 0;
    let mut max_tx_param: Option<String> = None;
    let mut max_rx_param: Option<String> = None;
    let mut obfs_type: Option<String> = None;
    let mut obfs_password: Option<String> = None;
    let mut cc_override: Option<String> = None;
    let mut hop_interval = Duration::from_secs(30);
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k.to_ascii_lowercase().as_str() {
            "sni" | "peer" => sni = Some(percent_decode(v)),
            "insecure" => insecure = parse_go_bool(v)?,
            "obfs" => match v.to_ascii_lowercase().as_str() {
                "" => {}
                "salamander" => obfs_type = Some("salamander".into()),
                "gecko" => return Err("hysteria2:// obfs=gecko 未实现（ADR-0020）".into()),
                other => return Err(format!("hysteria2:// 未知 obfs 类型 {other:?}")),
            },
            "obfs-password" | "obfspassword" => obfs_password = Some(percent_decode(v)),
            "pinsha256" | "pin-sha256" => return Err("hysteria2:// pinSHA256 未实现".into()),
            "ech" => {
                return Err(
                    "hysteria2:// ech 未实现（rustls/quinn 无客户端 ECH；dae 侧由 ot/quic-go fork 提供；见 ADR-0056）"
                        .into(),
                )
            }
            "ca" => return Err("hysteria2:// 自定义 ca 未实现".into()),
            "upmbps" => max_tx = mbps_to_bps(v, "upmbps")?,
            "downmbps" => max_rx = mbps_to_bps(v, "downmbps")?,
            "maxtx" => max_tx_param = Some(v.to_string()),
            "maxrx" => max_rx_param = Some(v.to_string()),
            // 客户端本地 CC 选择（对照 Go ValidateCongestionOverride：bbr/brutal/bbr3 之外的显式值拒绝）
            "cc_override" | "cc-override" | "cc" => {
                let val = v.trim().to_ascii_lowercase();
                cc_override = match val.as_str() {
                    "" => None,
                    "bbr" | "brutal" | "bbr3" => Some(val),
                    "cubic" | "new_reno" => {
                        return Err(format!(
                            "hysteria2:// cc_override={val} 不被 hysteria2 支持（Go 侧同样拒绝）"
                        ))
                    }
                    other => {
                        return Err(format!(
                            "hysteria2:// 未知 cc_override {other:?}：支持 bbr/brutal/bbr3"
                        ))
                    }
                };
            }
            // sodama 扩展：dae 的 udphop_interval 在全局配置里，链接语法没有
            "udphop-interval" | "udphop_interval" => {
                let secs = parse_u64_param(v, "udphop-interval")?;
                if secs < 5 {
                    return Err("hysteria2:// udphop-interval 至少 5 秒（同 Go）".into());
                }
                hop_interval = Duration::from_secs(secs);
            }
            _ => {}
        }
    }
    // Go 侧：maxTx/maxRx 在两者同时出现时才解析，且不覆盖 upmbps/downmbps 已给出的维度
    if let (Some(tx_raw), Some(rx_raw)) = (&max_tx_param, &max_rx_param) {
        if max_tx == 0 {
            max_tx = parse_u64_param(tx_raw, "maxTx")?;
        }
        if max_rx == 0 {
            max_rx = parse_u64_param(rx_raw, "maxRx")?;
        }
    }
    let obfs_password = match obfs_type.as_deref() {
        Some("salamander") => {
            let pw = obfs_password
                .ok_or_else(|| "hysteria2:// obfs=salamander 需要 obfs-password".to_string())?;
            if pw.len() < 4 {
                return Err("hysteria2:// obfs-password 至少 4 字节（同 Go）".into());
            }
            Some(pw)
        }
        _ => None,
    };

    // host:port 并集；端口串含 `,`/`-` 即 udphop（Go isPortHoppingPort 同判据）
    let hostport = percent_decode(hostport);
    let (host, port_str) = split_host_port(&hostport)
        .ok_or_else(|| format!("hysteria2:// 地址非法（需要 host:port）: {hostport}"))?;
    let ports = quicsock::parse_port_union(port_str)?;
    let first_port = ports[0];
    let server = resolve(&join_host_port(host, first_port))?;
    let hop_ports = if ports.len() > 1 { ports } else { Vec::new() };
    let sni = sni
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| host.to_string());
    let cfg = hysteria2::Hy2Config {
        server,
        hop_ports,
        hop_interval,
        auth,
        sni,
        insecure,
        alpn: Vec::new(),
        rx_bytes_per_sec: max_rx,
        tx_bytes_per_sec: max_tx,
        cc_override,
        obfs_password,
    };
    Ok(Outbound::Hysteria2 {
        dialer: std::sync::Arc::new(hysteria2::Hy2Dialer::new(cfg)),
    })
}

/// 拆 `host:port`（支持 `[v6]:port`）。
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        Some((host, port))
    } else {
        s.rsplit_once(':')
    }
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Go `strconv.ParseBool` 的接受集合。
fn parse_go_bool(v: &str) -> Result<bool, String> {
    match v {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        other => Err(format!("布尔参数非法: {other}")),
    }
}

fn parse_u64_param(v: &str, what: &str) -> Result<u64, String> {
    v.parse::<u64>()
        .map_err(|_| format!("hysteria2:// {what} 非法: {v}"))
}

/// Mbps → 字节/秒（Go 侧同一公式，饱和处理超界值）。
fn mbps_to_bps(v: &str, what: &str) -> Result<u64, String> {
    let mbps = parse_u64_param(v, what)?;
    Ok(mbps.saturating_mul(1_000_000) / 8)
}

fn percent_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// HTTP CONNECT 握手（RFC 7231 §4.3.6）：`CONNECT host:port HTTP/1.1`。
///
/// 响应头逐字节读取，避免把 200 之后紧跟的隧道数据吞进头部缓冲；非 200 直接报错。
fn http_connect(
    mut sock: TcpStream,
    target: &Target,
    auth: Option<&(String, String)>,
    timeout: Duration,
) -> io::Result<TcpStream> {
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    let authority = target_authority(target);
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, pass)) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes())?;
    sock.flush()?;

    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        sock.read_exact(&mut b)?;
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http: 代理响应头过长",
            ));
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status = text.lines().next().unwrap_or("");
    let code: Option<u16> = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok());
    match code {
        Some(200) => {}
        Some(c) => {
            return Err(io::Error::other(format!(
                "http: CONNECT {authority} 失败（代理返回 {c}）"
            )))
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("http: 非法状态行 {status:?}"),
            ))
        }
    }
    sock.set_read_timeout(None)?;
    sock.set_write_timeout(None)?;
    Ok(sock)
}

/// CONNECT 请求行/Host 头里的 authority（IPv6 带方括号）。
fn target_authority(target: &Target) -> String {
    match target {
        Target::Ip(std::net::IpAddr::V6(ip), port) => format!("[{ip}]:{port}"),
        Target::Ip(ip, port) => format!("{ip}:{port}"),
        Target::Domain(name, port) => format!("{name}:{port}"),
    }
}

/// `http://[user:pass@]host:port`：CONNECT 隧道（可选 Basic 认证）；UDP 不支持。
fn parse_http(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let rest = rest.split('?').next().unwrap_or(rest);
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let auth = match userinfo {
        Some(u) => {
            let u = percent_decode(u);
            let (user, pass) = match u.split_once(':') {
                Some((a, b)) => (a.to_string(), b.to_string()),
                None => (u, String::new()),
            };
            if user.is_empty() {
                return Err("http:// 用户名不能为空".into());
            }
            Some((user, pass))
        }
        None => None,
    };
    let server = resolve(&percent_decode(hostport))?;
    Ok(Outbound::Http { server, auth })
}

/// `ss://`：支持 SIP002（base64url 或明文 userinfo）与旧式（整体 base64）。
fn parse_ss(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let mut plugin: Option<shadowtls::ShadowTlsConfig> = None;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        if k.eq_ignore_ascii_case("plugin") {
            plugin = Some(parse_shadowtls_plugin(&percent_decode(v))?);
        }
    }
    let (userinfo, hostport) = match main.split_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => {
            // 旧式：整体 base64(method:password@host:port)
            let decoded = b64_decode_any(main)
                .ok_or_else(|| "ss:// 缺少 @host:port 且整体 base64 解码失败".to_string())?;
            let text = String::from_utf8(decoded).map_err(|e| format!("ss:// base64 非法: {e}"))?;
            let (u, h) = text
                .split_once('@')
                .ok_or_else(|| "ss:// 旧式编码中缺少 @".to_string())?;
            (u.to_string(), h.to_string())
        }
    };
    // userinfo：优先尝试 base64（SIP002），否则按明文（password 可能被百分号编码）
    let creds = if let Some(v) = b64_decode_any(&userinfo) {
        String::from_utf8(v).map_err(|e| format!("ss:// userinfo base64 非法: {e}"))?
    } else {
        percent_decode(&userinfo)
    };
    let (method_s, password) = creds
        .split_once(':')
        .ok_or_else(|| "ss:// userinfo 需要 method:password".to_string())?;
    let method =
        ss::SsMethod::parse(method_s).ok_or_else(|| format!("ss:// 不支持的方法 {method_s}"))?;
    let master = if method.is_2022() {
        // SIP022：password 是 PSK 的标准 base64（可带 padding），**不做** EVP_BytesToKey。
        let psk = b64_decode_any(password)
            .ok_or_else(|| format!("ss:// {method_s} 的 password 必须是 base64 PSK"))?;
        if psk.len() != method.key_len() {
            return Err(format!(
                "ss:// {method_s} 需要 {} 字节 PSK（base64 解出 {} 字节）",
                method.key_len(),
                psk.len()
            ));
        }
        psk
    } else {
        ss::evp_bytes_to_key(password.as_bytes(), ss::KEY_LEN)
    };
    Ok(Outbound::Shadowsocks {
        server: resolve(&hostport)?,
        method,
        master,
        shadowtls: plugin,
    })
}

/// SIP003 插件串（`shadow-tls;password=…;version=3;host=…;allowInsecure=1`）。
/// 当前仅支持 shadow-tls；其余插件显式报错（不静默）。
fn parse_shadowtls_plugin(raw: &str) -> Result<shadowtls::ShadowTlsConfig, String> {
    let mut fields = raw.split(';');
    let name = fields.next().unwrap_or("").trim();
    if !matches!(
        name.to_ascii_lowercase().as_str(),
        "shadow-tls" | "shadowtls"
    ) {
        return Err(format!(
            "ss:// 插件 {name} 未实现（当前仅 shadow-tls；P31 边界）"
        ));
    }
    let mut password = String::new();
    let mut version = 3u8;
    let mut sni: Option<String> = None;
    let mut host: Option<String> = None;
    let mut allow_insecure = false;
    for f in fields {
        let f = f.trim();
        if f.is_empty() {
            continue;
        }
        let (k, v) = f.split_once('=').unwrap_or((f, ""));
        let v = percent_decode(v.trim());
        match k.trim().to_ascii_lowercase().as_str() {
            "password" | "passwd" | "pwd" => password = v,
            "version" => {
                version = v
                    .parse()
                    .map_err(|_| format!("shadow-tls 插件版本非法: {v}"))?
            }
            "sni" => sni = Some(v),
            "host" => host = Some(v),
            "allowinsecure" | "allow_insecure" | "insecure" | "skipverify" | "skip-cert-verify" => {
                allow_insecure = matches!(v.as_str(), "1" | "true" | "TRUE" | "True")
            }
            _ => {}
        }
    }
    let sni = sni
        .or(host)
        .ok_or_else(|| "shadow-tls 插件需要 host/sni".to_string())?;
    shadowtls::ShadowTlsConfig::new(version, password, sni, allow_insecure)
        .map_err(|e| format!("shadow-tls 插件: {e}"))
}

/// `trojan://password@host:port?sni=...&allowInsecure=1&type=tcp`
fn parse_trojan(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    let (password_raw, hostport) = main
        .split_once('@')
        .ok_or_else(|| "trojan:// 需要 password@host:port".to_string())?;
    let mut sni = None;
    let mut insecure = false;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k.to_ascii_lowercase().as_str() {
            "sni" | "peer" => sni = Some(percent_decode(v)),
            "allowinsecure" | "skip-cert-verify" | "insecure" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            "type" if !matches!(v.to_ascii_lowercase().as_str(), "" | "tcp" | "none") => {
                return Err(format!("trojan:// 传输 {v} 未实现（G1 只做 tcp+tls）"))
            }
            "security" if !matches!(v.to_ascii_lowercase().as_str(), "tls" | "") => {
                return Err(format!("trojan:// security={v} 未实现（G1 只做 tls）"))
            }
            _ => {}
        }
    }
    let hostport_s = hostport.to_string();
    let sni = sni.unwrap_or_else(|| {
        hostport_s
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| hostport_s.clone())
    });
    Ok(Outbound::Trojan {
        server: resolve(&hostport_s)?,
        password: percent_decode(password_raw),
        sni,
        insecure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 墙钟看门狗：到点应 `shutdown` socket，让阻塞中的读立即返回。
    /// 这是「握手可能超时后继续重试」的最终兜底（见 arm_dial_watchdog 注释）。
    #[test]
    fn dial_watchdog_shuts_down_after_deadline() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let s = std::net::TcpStream::connect(addr).unwrap();
        let rd = s.try_clone().unwrap();
        arm_dial_watchdog(s.as_raw_fd(), Duration::from_millis(200)).unwrap();
        let t0 = std::time::Instant::now();
        let mut b = [0u8; 8];
        let r = (&rd).read(&mut b); // 阻塞读：等看门狗掐断
        let dt = t0.elapsed();
        assert!(
            matches!(r, Ok(0) | Err(_)),
            "看门狗应让读返回 0/错误，实际 {r:?}"
        );
        assert!(dt < Duration::from_secs(2), "应在 deadline 附近返回，实际 {dt:?}");
        disarm_dial_watchdog();
    }

    /// 正常拨号路径：取消后 socket **不得**被掐断（否则会误杀成功连接）。
    #[test]
    fn dial_watchdog_cancel_keeps_socket_alive() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let s = std::net::TcpStream::connect(addr).unwrap();
        let (mut peer, _) = l.accept().unwrap();
        arm_dial_watchdog(s.as_raw_fd(), Duration::from_millis(250)).unwrap();
        disarm_dial_watchdog(); // 模拟 dial_tcp 收尾
        std::thread::sleep(Duration::from_millis(500)); // 超过 deadline
        peer.write_all(b"hi").unwrap();
        let mut b = [0u8; 2];
        (&s).read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hi", "取消后连接应仍然可用");
    }

    /// 读回 socket 的 `SO_RCVTIMEO`（微秒；0 = 未设）。
    fn rcvtimeo_us(fd: std::os::fd::RawFd) -> i64 {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &mut tv as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(SO_RCVTIMEO) 应成功");
        tv.tv_sec as i64 * 1_000_000 + tv.tv_usec as i64
    }

    /// 近似比较：内核会把 `SO_*TIMEO` 向上取整到时钟粒度（实测 1_500_000 µs
    /// 读回 1_500_333 µs），因此不能用严格相等。
    fn assert_timeo_us(got: i64, want: i64, what: &str) {
        let d = (got - want).abs();
        assert!(
            d <= 100_000,
            "{what}: 期望约 {want} µs，实际 {got} µs（差 {d} µs）"
        );
    }

    /// 回归（2026-10-09 生产事故）：`marked_tcp_connect` 过去只盖了 connect 的
    /// poll 超时，返回的 socket 是**阻塞无读写超时**的 —— 碰上"能建连但不回包"的
    /// 节点，协议握手会在 recvfrom 里永久阻塞（实测 553 个 probe 线程卡死、
    /// VmSize 432 MB / RSS 105 MB）。
    ///
    /// 本用例先验 helper 的设/清语义（不需特权），再在 root 下顺带验一次
    /// `marked_tcp_connect` 真的会设上（设 SO_MARK 需要 CAP_NET_ADMIN）。
    #[test]
    fn handshake_timeout_set_then_cleared() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let s = std::net::TcpStream::connect(addr).unwrap();
        let fd = s.as_raw_fd();
        assert_eq!(rcvtimeo_us(fd), 0, "新 socket 默认无读超时");
        set_sock_timeouts(fd, Some(Duration::from_secs(2))).unwrap();
        assert_timeo_us(rcvtimeo_us(fd), 2_000_000, "设置后应可读回");
        set_sock_timeouts(fd, None).unwrap();
        assert_eq!(rcvtimeo_us(fd), 0, "清除后应回到 0");
        // dup 共享同一 socket 选项：在一个 fd 上设即对所有副本生效
        let dup = s.try_clone().unwrap();
        set_sock_timeouts(dup.as_raw_fd(), Some(Duration::from_millis(1500))).unwrap();
        assert_timeo_us(rcvtimeo_us(fd), 1_500_000, "dup 共享同一 socket 选项");

        // root 下才能设 SO_MARK；顺带验握手期超时确实被设上
        if unsafe { libc::geteuid() } == 0 {
            let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let a2 = l2.local_addr().unwrap();
            let m = marked_tcp_connect(a2, Duration::from_secs(2)).unwrap();
            assert_timeo_us(
                rcvtimeo_us(m.as_raw_fd()),
                2_000_000,
                "握手期必须已设 RCVTIMEO（否则握手读会永久阻塞）",
            );
            set_sock_timeouts(m.as_raw_fd(), None).unwrap();
            assert_eq!(rcvtimeo_us(m.as_raw_fd()), 0, "dial_tcp 收尾应清除");
        }
    }

    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;

    #[test]
    fn parse_ss_shadowtls_plugin() {
        let ob = parse(
            "ss://chacha20-ietf-poly1305:testpass@127.0.0.1:8399\
             ?plugin=shadow-tls;password=pw;version=3;sni=cdn.example.com;allowInsecure=1",
        )
        .unwrap();
        match ob {
            Outbound::Shadowsocks {
                method,
                shadowtls: Some(cfg),
                ..
            } => {
                assert_eq!(method, ss::SsMethod::Chacha20IetfPoly1305);
                assert_eq!(cfg.version, 3);
                assert_eq!(cfg.password, "pw");
                assert_eq!(cfg.sni, "cdn.example.com");
                assert!(cfg.allow_insecure);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parse_ss_shadowtls_plugin_defaults_and_percent_encoding() {
        // 百分号编码的 SIP003 串（生态里常见）与 version 缺省（3）、host→sni。
        let ob = parse(
            "ss://chacha20-ietf-poly1305:testpass@127.0.0.1:8399\
             ?plugin=shadow-tls%3Bpassword%3Dpw%3Bhost%3Dwww.microsoft.com",
        )
        .unwrap();
        match ob {
            Outbound::Shadowsocks {
                shadowtls: Some(cfg),
                ..
            } => {
                assert_eq!(cfg.version, 3);
                assert_eq!(cfg.sni, "www.microsoft.com");
                assert!(!cfg.allow_insecure);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parse_ss_unknown_plugin_rejected() {
        let e = parse(
            "ss://chacha20-ietf-poly1305:testpass@127.0.0.1:8388?plugin=obfs-local;obfs=http",
        )
        .unwrap_err();
        assert!(e.contains("未实现"), "{e}");
    }

    #[test]
    fn hy2_ech_rejected_loudly() {
        // P32：ECH 是如实边界（ADR-0056）——带 ech 的链接必须显式报错，不得静默降级为明文 SNI。
        let e = parse("hysteria2://auth@127.0.0.1:8753?sni=localhost&ech=AAECAwQ=").unwrap_err();
        assert!(e.contains("ech 未实现"), "{e}");
        let e = parse("hysteria2://auth@127.0.0.1:8753?sni=localhost&pinSHA256=abcd").unwrap_err();
        assert!(e.contains("pinSHA256 未实现"), "{e}");
    }

    #[test]
    fn parse_vless_ws_url() {
        let ob = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?encryption=none&security=tls&sni=cdn.example.com&type=ws\
             &host=cdn.example.com&path=%2Fabc%3Fed%3D2048&fp=chrome",
        )
        .unwrap();
        match ob {
            Outbound::Vless {
                tls,
                sni,
                transport,
                ..
            } => {
                assert!(tls);
                assert_eq!(sni, "cdn.example.com");
                assert_eq!(
                    transport,
                    VlessTransport::Ws {
                        host: "cdn.example.com".into(),
                        path: "/abc?ed=2048".into()
                    }
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parse_vless_ws_defaults_host_to_sni_path_to_slash() {
        let ob = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?security=tls&sni=cdn.example.com&type=ws",
        )
        .unwrap();
        match ob {
            Outbound::Vless { transport, .. } => assert_eq!(
                transport,
                VlessTransport::Ws {
                    host: "cdn.example.com".into(),
                    path: "/".into()
                }
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parse_vless_rejects_grpc() {
        let e = parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=grpc")
            .unwrap_err();
        assert!(e.contains("未实现"), "{e}");
    }

    // P18c+：REALITY 已实现（D+vision），URL 应能解析出配置；坏 pbk/sid 仍报错。
    #[test]
    fn parse_vless_reality_ok_and_bad_fields_rejected() {
        let ob = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&security=reality&sni=www.microsoft.com\
             &pbk=GD_dxMYmX6k5E3jcSitfWYY4QNMYof3Qig4tj0TrC3M&sid=41b9cb10b696&fp=chrome\
             &flow=xtls-rprx-vision",
        )
        .unwrap();
        match ob {
            Outbound::Vless {
                reality: Some(rc),
                flow,
                tls,
                ..
            } => {
                assert_eq!(rc.server_name, "www.microsoft.com");
                assert_eq!(&rc.short_id[..6], &[0x41, 0xb9, 0xcb, 0x10, 0xb6, 0x96]);
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
                assert!(!tls);
            }
            other => panic!("应为 reality vless: {other:?}"),
        }
        // 坏 pbk
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&security=reality&sni=a.com&pbk=short",
        )
        .unwrap_err();
        assert!(e.contains("pbk"), "{e}");
        // 缺 pbk
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&security=reality&sni=a.com&sid=00",
        )
        .unwrap_err();
        assert!(e.contains("pbk"), "{e}");
        // reality + ws 拒绝
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=ws&security=reality&sni=a.com&pbk=GD_dxMYmX6k5E3jcSitfWYY4QNMYof3Qig4tj0TrC3M",
        )
        .unwrap_err();
        assert!(e.contains("tcp"), "{e}");
    }

    #[test]
    fn parse_vless_vision_flow_constraints() {
        // M3：vision 支持 tls/reality 外层（tcp），非 TLS 与 ws 拒绝。
        let ob = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&security=tls&flow=xtls-rprx-vision",
        )
        .unwrap();
        match ob {
            Outbound::Vless {
                flow, reality, tls, ..
            } => {
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
                assert!(reality.is_none());
                assert!(tls);
            }
            _ => panic!("应为 Vless"),
        }
        // 无外层 TLS：拒绝
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&security=none&flow=xtls-rprx-vision",
        )
        .unwrap_err();
        assert!(e.contains("tls") || e.contains("reality"), "{e}");
        // ws + vision：拒绝（Xray 同义，仅 tcp）
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=ws&security=tls&flow=xtls-rprx-vision",
        )
        .unwrap_err();
        assert!(e.contains("tcp"), "{e}");
        // 其它 flow 值拒绝
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&flow=xtls-rprx-direct",
        )
        .unwrap_err();
        assert!(e.contains("flow"), "{e}");
    }

    #[test]
    fn parse_rejects_anytls_scheme() {
        // anytls 已实现（P11）：空密码必须报错，不能静默降级
        let e = parse("anytls://@1.2.3.4:8443").unwrap_err();
        assert!(e.contains("密码"), "{e}");
    }

    #[test]
    fn parse_naive_url() {
        let ob =
            parse("naive+https://alice:s3cret@1.2.3.4:8443?sni=example.com&insecure=1").unwrap();
        match ob {
            Outbound::Naive {
                user,
                pass,
                sni,
                insecure,
                ..
            } => {
                assert_eq!(user, "alice");
                assert_eq!(pass, "s3cret");
                assert_eq!(sni, "example.com");
                assert!(insecure);
            }
            other => panic!("应为 Naive: {other:?}"),
        }
        // 无 query 时 SNI 取自 host（去端口）
        match parse("naive://bob@127.0.0.1:9443").unwrap() {
            Outbound::Naive {
                user, pass, sni, ..
            } => {
                assert_eq!(user, "bob");
                assert!(pass.is_empty());
                assert_eq!(sni, "127.0.0.1");
            }
            other => panic!("应为 Naive: {other:?}"),
        }
        // P26：naive+quic（HTTP/3）解析（真实拨号在 lab/真机验证）
        match parse("naive+quic://carol:pw@1.2.3.4:443?sni=quic.example").unwrap() {
            Outbound::Naive {
                user,
                pass,
                sni,
                h3,
                ..
            } => {
                assert_eq!(user, "carol");
                assert_eq!(pass, "pw");
                assert_eq!(sni, "quic.example");
                assert!(h3, "naive+quic 应标记 h3");
            }
            other => panic!("应为 Naive: {other:?}"),
        }
        // naive+https 保持 h2
        match parse("naive+https://u:p@1.2.3.4:8443").unwrap() {
            Outbound::Naive { h3, .. } => assert!(!h3),
            other => panic!("应为 Naive: {other:?}"),
        }
        // 缺少 userinfo 报错
        assert!(parse("naive+https://127.0.0.1:8443").is_err());
        assert!(parse("naive+quic://127.0.0.1:443").is_err());
    }

    #[test]
    fn parse_juicity_url() {
        let ob = parse(
            "juicity://b831381d-6324-4d53-ad4f-8cda48b30811:pw%40x@1.2.3.4:18964?sni=example.com&allow_insecure=1&congestion_control=bbr",
        )
        .unwrap();
        match ob {
            Outbound::Juicity { dialer } => {
                let cfg = dialer.config();
                assert_eq!(cfg.server, "1.2.3.4:18964".parse().unwrap());
                assert_eq!(cfg.uuid[0], 0xb8);
                assert_eq!(cfg.uuid[15], 0x11);
                assert_eq!(cfg.password, "pw@x");
                assert_eq!(cfg.sni, "example.com");
                assert!(cfg.insecure);
                assert_eq!(dialer.name(), "juicity://1.2.3.4:18964");
            }
            other => panic!("应为 Juicity: {other:?}"),
        }
        // uuid 非法 / 缺 userinfo / 缺 password 分隔
        assert!(parse("juicity://not-a-uuid:pw@1.2.3.4:443").is_err());
        assert!(parse("juicity://1.2.3.4:443").is_err());
        assert!(parse("juicity://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443").is_err());
    }

    #[test]
    fn parse_anytls_url() {
        let ob = parse("anytls://testpass@1.2.3.4:8443?sni=example.com&insecure=1").unwrap();
        match ob {
            Outbound::AnyTls {
                password_sha256,
                sni,
                insecure,
                ..
            } => {
                let want: [u8; 32] = Sha256::digest(b"testpass").into();
                assert_eq!(password_sha256, want);
                assert_eq!(sni, "example.com");
                assert!(insecure);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parse_http_url_and_auth() {
        let ob = parse("http://alice:s3cret@127.0.0.1:8080").unwrap();
        match ob {
            Outbound::Http { server, auth } => {
                assert_eq!(server, "127.0.0.1:8080".parse().unwrap());
                assert_eq!(auth, Some(("alice".into(), "s3cret".into())));
            }
            other => panic!("{other:?}"),
        }
        // 无认证
        let ob = parse("http://127.0.0.1:3128").unwrap();
        match ob {
            Outbound::Http { auth, .. } => assert!(auth.is_none()),
            other => panic!("{other:?}"),
        }
        // 百分号编码的密码
        let ob = parse("http://bob:p%40ss%3Aword@127.0.0.1:3128").unwrap();
        match ob {
            Outbound::Http { auth, .. } => {
                assert_eq!(auth, Some(("bob".into(), "p@ss:word".into())))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn http_connect_mock_roundtrip() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel::<String>();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            loop {
                sock.read_exact(&mut b).unwrap();
                req.push(b[0]);
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            tx.send(String::from_utf8_lossy(&req).into_owned()).unwrap();
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            // 200 之后直接回显，验证隧道透传
            let mut buf = [0u8; 64];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let ob = parse(&format!("http://user:pass@{proxy_addr}")).unwrap();
        let target = Target::domain("example.com", 443);
        let mut d = ob.dial_tcp(&target, Duration::from_secs(5)).unwrap();
        let req = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("\r\nHost: example.com:443\r\n"), "{req}");
        let want = format!(
            "Proxy-Authorization: Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:pass")
        );
        assert!(req.contains(&want), "{req}");

        d.to_remote.write_all(b"ping").unwrap();
        d.to_remote.flush().unwrap();
        let mut buf = [0u8; 4];
        d.from_remote.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        drop(d);
        let _ = server.join();
    }

    #[test]
    fn http_connect_rejects_non_200() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            loop {
                sock.read_exact(&mut b).unwrap();
                req.push(b[0]);
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
            )
            .unwrap();
        });

        let ob = parse(&format!("http://{proxy_addr}")).unwrap();
        let target = Target::domain("example.com", 443);
        match ob.dial_tcp(&target, Duration::from_secs(5)) {
            Ok(_) => panic!("407 不应视为成功"),
            Err(e) => assert!(e.to_string().contains("407"), "{e}"),
        }
        server.join().unwrap();
    }

    /// SIP022：`ss://` password 是 PSK 的标准 base64；解出的长度必须等于方法密钥长度。
    #[test]
    fn parse_ss_2022_psk() {
        use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};

        // 0xfb 的 base64 含 `+`/`/`，验证内层用标准 base64 解码。
        let psk = [0xfbu8; 32];
        let creds = format!("2022-blake3-aes-256-gcm:{}", B64.encode(psk));
        let url = format!("ss://{}@127.0.0.1:8388", B64URL.encode(creds.as_bytes()));
        match parse(&url).unwrap() {
            Outbound::Shadowsocks { method, master, .. } => {
                assert_eq!(method, ss::SsMethod::Ss2022Aes256Gcm);
                assert_eq!(master, psk.to_vec());
            }
            other => panic!("{other:?}"),
        }

        // aes-128：PSK 必须 16 字节
        let creds = format!("2022-blake3-aes-128-gcm:{}", B64.encode([0x11u8; 16]));
        let url = format!("ss://{}@127.0.0.1:8388", B64URL.encode(creds.as_bytes()));
        match parse(&url).unwrap() {
            Outbound::Shadowsocks { master, .. } => assert_eq!(master, vec![0x11u8; 16]),
            other => panic!("{other:?}"),
        }

        // 长度不符（aes-128 给 32 字节 PSK）必须报错
        let creds = format!("2022-blake3-aes-128-gcm:{}", B64.encode([0x22u8; 32]));
        let url = format!("ss://{}@127.0.0.1:8388", B64URL.encode(creds.as_bytes()));
        let e = parse(&url).unwrap_err();
        assert!(e.contains("需要 16 字节"), "{e}");

        // 非 base64 的 password 必须报错
        let creds = "2022-blake3-aes-256-gcm:not-base64-!!!!";
        let url = format!("ss://{}@127.0.0.1:8388", B64URL.encode(creds.as_bytes()));
        let e = parse(&url).unwrap_err();
        assert!(e.contains("base64"), "{e}");
    }

    /// 真实订阅节点探针（默认忽略，需要网络与环境变量）：
    ///   REAL_VLESS_WS_URL='vless://...type=ws...' [REAL_VLESS_WS_TARGET=www.gstatic.com:80] \
    ///   cargo test --release real_vless_ws_probe -- --ignored --nocapture
    #[test]
    #[ignore = "需要真实节点环境变量 REAL_VLESS_WS_URL"]
    fn real_vless_ws_probe() {
        let Ok(url) = std::env::var("REAL_VLESS_WS_URL") else {
            eprintln!("skip: 未设 REAL_VLESS_WS_URL");
            return;
        };
        let target_host = std::env::var("REAL_VLESS_WS_TARGET")
            .unwrap_or_else(|_| "www.gstatic.com:80".to_string());
        let target: SocketAddr = target_host
            .to_socket_addrs()
            .expect("解析 REAL_VLESS_WS_TARGET 失败")
            .next()
            .expect("REAL_VLESS_WS_TARGET 无结果");
        let ob = parse(&url).expect("解析 dialer");
        assert!(
            matches!(
                ob,
                Outbound::Vless {
                    transport: VlessTransport::Ws { .. },
                    ..
                }
            ),
            "该探针需要 ws 节点"
        );
        let mut d = ob
            .dial_tcp(
                &Target::from_socket_addr(target).unwrap(),
                Duration::from_secs(10),
            )
            .expect("dial");
        if let Some(s) = d.socket.as_ref() {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        }
        let req = format!(
            "GET /generate_204 HTTP/1.1\r\nHost: {}\r\nUser-Agent: sodama-probe\r\nConnection: close\r\n\r\n",
            target.ip()
        );
        d.to_remote.write_all(req.as_bytes()).unwrap();
        d.to_remote.flush().unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match d.from_remote.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > 8192 {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break
                }
                Err(e) => panic!("read: {e}"),
            }
        }
        let head = String::from_utf8_lossy(&buf[..buf.len().min(200)]).to_string();
        eprintln!("status head: {}", head.lines().next().unwrap_or("(empty)"));
        assert!(head.starts_with("HTTP/1."), "未拿到 HTTP 响应: {head}");
    }

    /// 交叉对拍（默认忽略）：本机装有 shadowsocks-rust 的 `ss-server` 时，
    /// 用真实服务端验证 SS2022 TCP 互通；没有则打印 skip 并返回。
    ///
    ///   cargo test --release ss2022_vs_ssserver -- --ignored --nocapture
    #[test]
    #[ignore = "需要本机安装 shadowsocks-rust 的 ss-server"]
    fn ss2022_vs_ssserver() {
        use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
        use std::net::{TcpListener, TcpStream};

        if std::process::Command::new("ss-server")
            .arg("--help")
            .output()
            .is_err()
        {
            eprintln!("skip: 未找到 ss-server（shadowsocks-rust）");
            return;
        }

        // 本地 echo 服务
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in echo.incoming() {
                let Ok(mut s) = s else { continue };
                std::thread::spawn(move || {
                    let mut w = s.try_clone().unwrap();
                    let _ = std::io::copy(&mut s, &mut w);
                });
            }
        });

        let port = 18998u16;
        let psk = [0x5au8; 32];
        let method = "2022-blake3-aes-256-gcm";
        let child = std::process::Command::new("ss-server")
            .args([
                "-s",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                method,
                "-k",
                &B64.encode(psk),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skip: 无法启动 ss-server: {e}");
                return;
            }
        };
        std::thread::sleep(Duration::from_millis(800));
        if let Ok(Some(st)) = child.try_wait() {
            eprintln!("skip: ss-server 提前退出（{st}），参数可能与本机版本不符");
            return;
        }

        struct Guard(std::process::Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = Guard(child);

        let creds = format!("{method}:{}", B64.encode(psk));
        let url = format!("ss://{}@127.0.0.1:{port}", B64URL.encode(creds.as_bytes()));
        let ob = parse(&url).unwrap();
        let target = Target::from_socket_addr(echo_addr).unwrap();
        let mut d = ob.dial_tcp(&target, Duration::from_secs(5)).unwrap();
        d.to_remote.write_all(b"ping-ss2022").unwrap();
        d.to_remote.flush().unwrap();
        let mut buf = [0u8; 11];
        d.from_remote.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping-ss2022");
        let _ = TcpStream::connect(echo_addr); // 保活，避免 lint
    }

    // ------------------------------------------------------------ O7：UDP 批量收发

    /// echo 服务端：回环 N 个报文（原样回发）。
    fn spawn_udp_echo(n: usize) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = s.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            for _ in 0..n {
                let Ok((len, peer)) = s.recv_from(&mut buf) else {
                    return;
                };
                let _ = s.send_to(&buf[..len], peer);
            }
        });
        (addr, h)
    }

    fn collect_batch(relay: &UdpRelay, want: usize) -> Vec<Vec<u8>> {
        let mut out: Vec<crate::bufpool::PoolBuf> = Vec::new();
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut spins = 0;
        while got.len() < want {
            match relay.recv_batch(&mut out, want) {
                Ok(0) => {}
                Ok(n) => got.extend(out.iter().take(n).map(|v| v.to_vec())),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("recv_batch: {e}"),
            }
            spins += 1;
            assert!(spins < 100, "批量回包超时");
        }
        got
    }

    #[test]
    fn udp_plain_send_recv_batch() {
        let (echo, h) = spawn_udp_echo(3);
        let relay = Outbound::direct_udp(echo).unwrap();
        relay
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let datas: [&[u8]; 3] = [b"alpha", b"bravo", b"charlie"];
        let sent = relay.send_batch(&datas).unwrap();
        assert_eq!(sent, 5 + 5 + 7);
        let got = collect_batch(&relay, 3);
        let mut got_sorted: Vec<Vec<u8>> = got.clone();
        got_sorted.sort();
        let mut want: Vec<Vec<u8>> = datas.iter().map(|d| d.to_vec()).collect();
        want.sort();
        assert_eq!(got_sorted, want, "批量回环应逐包还原（顺序不计）");
        h.join().unwrap();
    }

    #[test]
    fn udp_ss_send_recv_batch() {
        // 最小 ss UDP 服务端：udp_open 解出 [socks 地址][数据]，原样回发。
        let master = ss::evp_bytes_to_key(b"p@ss", ss::KEY_LEN);
        let method = ss::SsMethod::Aes256Gcm;
        let server_master = master.clone();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let target: std::net::SocketAddr = "9.9.9.9:53".parse().unwrap();
        let h = std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            for _ in 0..2 {
                let Ok((len, peer)) = server.recv_from(&mut buf) else {
                    return;
                };
                let frame = ss::udp_open(method, &server_master, &buf[..len]).unwrap();
                // frame = [ATYP][IP][port][payload]
                assert_eq!(frame[0], 0x01);
                assert_eq!(&frame[1..5], &[9, 9, 9, 9]);
                assert_eq!(u16::from_be_bytes([frame[5], frame[6]]), 53);
                // 服务端→客户端方向无 SOCKS 头，只回载荷。
                let reply = ss::udp_seal(method, &server_master, &frame[7..]);
                let _ = server.send_to(&reply, peer);
            }
        });
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.connect(server_addr).unwrap();
        let relay = UdpRelay {
            target,
            kind: UdpKind::Ss {
                socket,
                method,
                master,
                session: None,
            },
        };
        relay
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let datas: [&[u8]; 2] = [b"ping-1", b"ping-2"];
        // Ss 路径与单包路径一致：统计的是密文字节（salt+AEAD 开销）。
        let sent = relay.send_batch(&datas).unwrap();
        assert!(sent >= 12, "密文字节应不少于明文（{sent}）");
        let got = collect_batch(&relay, 2);
        let mut got_sorted: Vec<Vec<u8>> = got.clone();
        got_sorted.sort();
        let mut want: Vec<Vec<u8>> = datas.iter().map(|d| d.to_vec()).collect();
        want.sort();
        assert_eq!(got_sorted, want, "ss UDP 批量应解密还原");
        h.join().unwrap();
    }
}

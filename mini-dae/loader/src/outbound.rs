// SPDX-License-Identifier: GPL-2.0
//! P5：outbound 协议栈——Dialer 抽象 + direct/socks5/shadowsocks/trojan/vless/vmess/tuic/hysteria2。
//!
//! 梯度与边界见 ADR-0004/ADR-0016/ADR-0018/ADR-0019：
//! - G1：direct、socks5（TCP）、shadowsocks（classic AEAD，TCP+UDP）、trojan（TCP over TLS）；
//! - G2：vless（TCP+UDP，tls/none）、vmess（AEAD，alterId=0，tcp，TCP+UDP，tls 可选）；
//! - G3a：tuic v5（QUIC，TCP+UDP datagram）；G3b：hysteria2（QUIC，TCP+UDP datagram）；
//! - offload（内核拼接）只对「字节透明」的 direct/socks5 开启：其余协议需要在用户态
//!   做 AEAD/TLS 编解码，内核拼接会绕过协议层（ADR-0016 第 3 条）。

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use percent_encoding::percent_decode_str;

use crate::{
    hysteria2, quicsock, socks5, ss, tls, trojan, tuic, vless, vmess, ws, DAE_SOCKET_MARK,
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
            eprintln!("mini-dae: SO_MARK 失败（非 root？），出口自环保护降级");
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
/// 数据面（mini_wan_egress/mini_lan_ingress）见 mark 直接放行，避免代理出口自环。
pub fn marked_tcp_connect(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let raw = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_mark_fd(fd.as_raw_fd())?;
    let Some(sin) = sockaddr_in_of(addr) else {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "只有 IPv4"));
    };
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
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
    Ok(stream)
}

/// 带 SO_MARK 的 UDP socket（未绑定；用于 DNS 上游与 UDP NAT/relay 出口）。
pub fn new_marked_udp() -> io::Result<UdpSocket> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_mark_fd(fd.as_raw_fd())?;
    Ok(UdpSocket::from(fd))
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

impl<W: WriteHalf> WriteHalf for vless::VlessWriter<W> {
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner().shutdown_write()
    }
}

impl<W: WriteHalf> WriteHalf for ws::WsWriter<W> {
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
pub struct DialedStream {
    pub from_remote: Box<dyn ReadHalf>,
    pub to_remote: Box<dyn WriteHalf>,
    pub socket: Option<TcpStream>,
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
    /// shadowsocks：每个包独立 salt 的 AEAD，socket 已 connect 到服务端。
    Ss {
        socket: UdpSocket,
        method: ss::SsMethod,
        master: Vec<u8>,
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
}

/// UDP 会话的出口（direct / ss / vless / vmess）。
pub struct UdpRelay {
    target: SocketAddr,
    kind: UdpKind,
}

fn lock_err<T>(_: T) -> io::Error {
    io::Error::other("udp relay: 锁中毒")
}

impl UdpRelay {
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
        }
    }

    pub fn send_payload(&self, data: &[u8]) -> io::Result<usize> {
        match &self.kind {
            UdpKind::Plain(socket) => socket.send_to(data, self.target),
            UdpKind::Ss {
                socket,
                method,
                master,
            } => {
                // classic ss UDP：载荷 = SOCKS5 风格目标地址头 + 数据（服务端据此路由）
                let mut frame = Vec::with_capacity(data.len() + 7);
                match self.target {
                    SocketAddr::V4(v4) => {
                        frame.push(0x01);
                        frame.extend_from_slice(&v4.ip().octets());
                    }
                    SocketAddr::V6(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "ss udp 目标仅支持 IPv4",
                        ))
                    }
                }
                frame.extend_from_slice(&self.target.port().to_be_bytes());
                frame.extend_from_slice(data);
                let dg = ss::udp_seal(*method, master, &frame);
                socket.send(&dg)
            }
            UdpKind::Stream { write, .. } => {
                let mut w = write.lock().map_err(lock_err)?;
                w.send_datagram(data).map(|_| data.len())
            }
            UdpKind::Tuic { udp } => udp.send(data),
            UdpKind::Hy2 { udp } => udp.send(data),
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
            } => {
                let mut b = vec![0u8; 65536];
                let n = socket.recv(&mut b)?;
                ss::udp_open(*method, master, &b[..n])
            }
            UdpKind::Stream { read, .. } => {
                let mut r = read.lock().map_err(lock_err)?;
                r.recv_datagram()
            }
            UdpKind::Tuic { udp } => udp.recv(),
            UdpKind::Hy2 { udp } => udp.recv(),
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

#[derive(Clone, Debug)]
pub enum Outbound {
    Direct,
    Socks5 {
        server: SocketAddr,
    },
    Shadowsocks {
        server: SocketAddr,
        method: ss::SsMethod,
        master: Vec<u8>,
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
}

impl Outbound {
    pub fn name(&self) -> String {
        match self {
            Self::Direct => "direct".into(),
            Self::Socks5 { server } => format!("socks5://{server}"),
            Self::Shadowsocks { server, method, .. } => {
                format!("ss://{method_name}@{server}", method_name = method.name())
            }
            Self::Trojan { server, .. } => format!("trojan://{server}"),
            Self::Vless {
                server,
                tls,
                transport,
                ..
            } => {
                let xport = match transport {
                    VlessTransport::Tcp => String::new(),
                    VlessTransport::Ws { .. } => "&type=ws".to_string(),
                };
                format!(
                    "vless://{server}?security={}{xport}",
                    if *tls { "tls" } else { "none" }
                )
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
        }
    }

    /// offload 只对字节透明的封装开启（ss/trojan 有 AEAD/TLS 帧，内核拼接会绕过协议层）。
    pub fn supports_offload(&self) -> bool {
        matches!(self, Self::Direct | Self::Socks5 { .. })
    }

    /// 当前支持 UDP 代理的协议：ss（G1）、vless/vmess（G2）、tuic（G3）、hysteria2（G3b）。
    pub fn supports_udp(&self) -> bool {
        matches!(
            self,
            Self::Shadowsocks { .. }
                | Self::Vless { .. }
                | Self::Vmess { .. }
                | Self::Tuic { .. }
                | Self::Hysteria2 { .. }
        )
    }

    pub fn dial_tcp(&self, target: SocketAddr, timeout: Duration) -> io::Result<DialedStream> {
        match self {
            Self::Direct => {
                let sock = marked_tcp_connect(target, timeout)?;
                let kill = sock.try_clone()?;
                let read = sock.try_clone()?;
                Ok(DialedStream {
                    from_remote: Box::new(read),
                    to_remote: Box::new(sock),
                    socket: Some(kill),
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
                })
            }
            Self::Shadowsocks {
                server,
                method,
                master,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let (reader, mut writer) = ss::connect_split(sock, *method, master)?;
                // 首块写 SOCKS5 风格目标地址头（ATYP=IPv4）
                let mut head = Vec::with_capacity(7);
                match target {
                    SocketAddr::V4(v4) => {
                        head.push(0x01);
                        head.extend_from_slice(&v4.ip().octets());
                    }
                    SocketAddr::V6(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "ss 目标仅支持 IPv4",
                        ))
                    }
                }
                head.extend_from_slice(&target.port().to_be_bytes());
                writer.write_all(&head)?;
                writer.flush()?;
                Ok(DialedStream {
                    from_remote: Box::new(reader),
                    to_remote: Box::new(writer),
                    socket: Some(kill),
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
                })
            }
            Self::Vless {
                server,
                uuid,
                tls: use_tls,
                sni,
                insecure,
                transport,
            } => {
                let sock = marked_tcp_connect(*server, timeout)?;
                let kill = sock.try_clone()?;
                let (r, w) = if *use_tls {
                    let (r, w) = tls::connect(sock, sni, *insecure, &[], timeout)?;
                    apply_ws(r, w, transport)?
                } else {
                    let read = sock.try_clone()?;
                    apply_ws(read, sock, transport)?
                };
                let (r, w) = vless::connect_split(r, w, uuid, target)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: Some(kill),
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
                    })
                } else {
                    let read = sock.try_clone()?;
                    let (r, w) = vmess::connect_split(read, sock, &cmd_key, *security, target)?;
                    Ok(DialedStream {
                        from_remote: Box::new(r),
                        to_remote: Box::new(w),
                        socket: Some(kill),
                    })
                }
            }
            Self::Tuic { dialer } => {
                // QUIC 无底层 TcpStream：socket=None（不与 offload 搭配，见 supports_offload）
                let (r, w) = dialer.connect_tcp(target, timeout)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: None,
                })
            }
            Self::Hysteria2 { dialer } => {
                // QUIC 无底层 TcpStream：socket=None（不与 offload 搭配，见 supports_offload）
                let (r, w) = dialer.connect_tcp(target, timeout)?;
                Ok(DialedStream {
                    from_remote: Box::new(r),
                    to_remote: Box::new(w),
                    socket: None,
                })
            }
        }
    }

    /// UDP 出口；Ok(None) = 该协议不支持 UDP 代理（调用方决定直连回退）。
    pub fn dial_udp(&self, target: SocketAddr, timeout: Duration) -> io::Result<Option<UdpRelay>> {
        match self {
            Self::Shadowsocks {
                server,
                method,
                master,
            } => {
                let socket = new_marked_udp()?;
                socket.connect(server)?;
                Ok(Some(UdpRelay {
                    target,
                    kind: UdpKind::Ss {
                        socket,
                        method: *method,
                        master: master.clone(),
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
            } => {
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
            _ => Ok(None),
        }
    }

    /// 直连 UDP 出口（无 dialer 或协议不支持 UDP 时的回退）。
    pub fn direct_udp(target: SocketAddr) -> io::Result<UdpRelay> {
        Ok(UdpRelay {
            target,
            kind: UdpKind::Plain(new_marked_udp()?),
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
    if url.starts_with("socks5://") || url.contains(':') {
        return Ok(Outbound::Socks5 {
            server: resolve(socks5::parse_proxy(url)?.as_str())?,
        });
    }
    Err(format!(
        "--dialer 不支持 {url}（G3b：direct / socks5:// / ss:// / trojan:// / vless:// / vmess:// / \
         tuic:// / hysteria2:// / hy2://）"
    ))
}

fn resolve(hostport: &str) -> Result<SocketAddr, String> {
    hostport
        .to_socket_addrs()
        .map_err(|e| format!("解析 {hostport} 失败: {e}"))?
        .next()
        .ok_or_else(|| format!("解析 {hostport} 无结果"))
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

/// `vless://uuid@host:port?type=tcp|ws&security=tls&sni=...&allowInsecure=1`
///
/// 传输：tcp / ws（`host`/`path` 参数，缺省 host=sni、path=/）；headerType=none；
/// flow 非空（vision/XUDP）与 security=reality 显式拒绝（ADR-0017，ws 为 P10 新增）。
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
                other => return Err(format!("vless:// security={other} 未实现（只做 tls/none）")),
            },
            "sni" | "peer" => sni = Some(percent_decode(v)),
            "host" => ws_host = Some(percent_decode(v)),
            "path" => ws_path = Some(percent_decode(v)),
            "allowinsecure" | "insecure" | "skip-cert-verify" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            "flow" if !v.is_empty() => {
                return Err(format!(
                    "vless:// flow={v} 未实现（vision/XUDP 属后续档位）"
                ))
            }
            "encryption" if !matches!(v.to_ascii_lowercase().as_str(), "" | "none") => {
                return Err(format!("vless:// encryption={v} 未实现（只做 none）"))
            }
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
    Ok(Outbound::Vless {
        server: resolve(&hostport)?,
        uuid,
        tls: use_tls,
        sni,
        insecure,
        transport,
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
/// `udphop-interval=<秒>`（默认 30，最小 5）是 mini-dae 扩展：dae 把该值放在全局配置
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
            "ech" => return Err("hysteria2:// ech 未实现".into()),
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
            // mini-dae 扩展：dae 的 udphop_interval 在全局配置里，链接语法没有
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

/// `ss://`：支持 SIP002（base64url 或明文 userinfo）与旧式（整体 base64）。
fn parse_ss(rest: &str) -> Result<Outbound, String> {
    let rest = rest.split('#').next().unwrap_or(rest);
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m, q),
        None => (rest, ""),
    };
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        if kv.starts_with("plugin") {
            return Err("ss:// 暂不支持 plugin（G1 边界）".into());
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
    let master = ss::evp_bytes_to_key(password.as_bytes(), ss::KEY_LEN);
    Ok(Outbound::Shadowsocks {
        server: resolve(&hostport)?,
        method,
        master,
    })
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
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;

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

    // 真实订阅普查（ADR-0026 边界）：REALITY 与 Vision 仍显式拒绝。
    #[test]
    fn parse_vless_rejects_reality() {
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&security=reality&sni=www.microsoft.com&pbk=abc&sid=def",
        )
        .unwrap_err();
        assert!(e.contains("reality") && e.contains("未实现"), "{e}");
    }

    #[test]
    fn parse_vless_rejects_vision_flow() {
        let e = parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443\
             ?type=tcp&security=tls&flow=xtls-rprx-vision",
        )
        .unwrap_err();
        assert!(e.contains("flow") && e.contains("未实现"), "{e}");
    }

    #[test]
    fn parse_rejects_anytls_scheme() {
        // anytls 未实现：不能静默降级成 socks5 解析
        let e = parse("anytls://pass@1.2.3.4:8443?insecure=1&sni=example.com").unwrap_err();
        assert!(!e.is_empty(), "{e}");
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
        let mut d = ob.dial_tcp(target, Duration::from_secs(10)).expect("dial");
        if let Some(s) = d.socket.as_ref() {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        }
        let req = format!(
            "GET /generate_204 HTTP/1.1\r\nHost: {}\r\nUser-Agent: mini-dae-probe\r\nConnection: close\r\n\r\n",
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
}

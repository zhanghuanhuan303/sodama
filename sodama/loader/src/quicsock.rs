// SPDX-License-Identifier: GPL-2.0
//! P5-G3b+：QUIC 底层 socket 中间件——salamander 混淆与 udphop。
//!
//! 对照 olicesx/outbound `protocol/hysteria2/{obfs,udphop}`：
//! - **salamander**：每个 wire datagram = `[8B 随机 salt][payload XOR key]`，
//!   `key = BLAKE2b-256(PSK || salt)`，keystream 以 32B 为一周期循环（Go 侧同）；
//!   PSK < 4B 拒绝；收侧 packet ≤ 8B 视为非法并丢弃。
//! - **udphop**：目标端口列表（`443,8443-8450` / `all`）按间隔随机跳；每跳换一个
//!   本地端口的 socket（= 新四元组），旧 socket 保留一个间隔做宽限（Go 侧 prevConn 语义），
//!   期间两个 socket 都收。跳由「有包要发」驱动（Go 是 ticker；QUIC keepalive 亦会触达）。
//!   对 quinn 侧一律谎报逻辑服务器地址（否则会触发客户端侧 migration 丢弃），
//!   服务端（quic-go fork 的 "Hysteria connection migration"）按最后有效包更新客户端地址。
//!
//! 两个包装都只支持单段 Transmit/Recv（`max_transmit_segments`/`max_receive_segments = 1`）：
//! GSO/GRO 会按段切分 wire datagram，而混淆必须逐 datagram 加盐；Go 侧包装后同样退回
//! 非 GSO 路径。代价是每包一次 sendmsg，换来语义简单可证。

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::Rng;

// ---------------------------------------------------------------- salamander

const SALAMANDER_SALT: usize = 8;
const SALAMANDER_KEY: usize = 32;

/// `key = BLAKE2b-256(PSK || salt)`（对照 Go `salamanderObfuscator.keyLocked`）。
pub fn salamander_key(psk: &[u8], salt: &[u8]) -> [u8; SALAMANDER_KEY] {
    let mut h = Blake2b::<U32>::new();
    h.update(psk);
    h.update(salt);
    h.finalize().into()
}

/// 混淆一个 wire datagram；`out` 会被覆盖为 `[salt][密文]`。
pub fn salamander_obfuscate(psk: &[u8], payload: &[u8], out: &mut Vec<u8>) {
    let salt: [u8; SALAMANDER_SALT] = rand::thread_rng().gen();
    let key = salamander_key(psk, &salt);
    out.clear();
    out.reserve(SALAMANDER_SALT + payload.len());
    out.extend_from_slice(&salt);
    for (i, &b) in payload.iter().enumerate() {
        out.push(b ^ key[i % SALAMANDER_KEY]);
    }
}

/// 解混淆一个 wire datagram；`packet` ≤ 8B 返回 None（Go 侧返回 0 长度 = 丢弃）。
/// 运行路径是原地解密（见 `ObfsSocket::poll_recv`），此函数供单测与对拍。
#[cfg(test)]
pub fn salamander_deobfuscate(psk: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() <= SALAMANDER_SALT {
        return None;
    }
    let key = salamander_key(psk, &packet[..SALAMANDER_SALT]);
    Some(
        packet[SALAMANDER_SALT..]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % SALAMANDER_KEY])
            .collect(),
    )
}

// ---------------------------------------------------------------- 端口并集

/// 解析 Go `udphop.ParsePortUnion` 的端口串：逗号分隔的单端口/范围，`all`/`*` = 全端口。
/// 返回排序、合并后的端口列表（范围展开）。
pub fn parse_port_union(s: &str) -> Result<Vec<u16>, String> {
    let s = s.trim();
    let mut ranges: Vec<(u16, u16)> = Vec::new();
    if s == "all" || s == "*" {
        ranges.push((0, u16::MAX));
    } else {
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(format!("非法端口串: {s:?}"));
            }
            if let Some((a, b)) = part.split_once('-') {
                let start: u16 = a.parse().map_err(|_| format!("非法端口: {part}"))?;
                let end: u16 = b.parse().map_err(|_| format!("非法端口: {part}"))?;
                let (lo, hi) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };
                ranges.push((lo, hi));
            } else {
                let p: u16 = part.parse().map_err(|_| format!("非法端口: {part}"))?;
                ranges.push((p, p));
            }
        }
    }
    if ranges.is_empty() {
        return Err("端口串为空".into());
    }
    ranges.sort_unstable();
    let mut out: Vec<u16> = Vec::new();
    let (mut lo, mut hi) = ranges[0];
    for &(a, b) in &ranges[1..] {
        if a <= hi.saturating_add(1) {
            hi = hi.max(b);
        } else {
            out.extend(lo..=hi);
            lo = a;
            hi = b;
        }
    }
    out.extend(lo..=hi);
    Ok(out)
}

// ---------------------------------------------------------------- PlainUdpSocket

/// 直接持有的 tokio UDP socket（无 GSO/GRO；单段语义）。
/// 用于 obfs/hop 包装的底座；非 obfs/hop 的 hysteria2 仍走 TokioRuntime 包装。
pub struct PlainUdpSocket {
    io: tokio::net::UdpSocket,
    id: usize,
}

impl fmt::Debug for PlainUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlainUdpSocket(#{} {:?})", self.id, self.io.local_addr())
    }
}

impl PlainUdpSocket {
    pub fn new(std_sock: std::net::UdpSocket) -> io::Result<Self> {
        static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        std_sock.set_nonblocking(true)?;
        Ok(Self {
            io: tokio::net::UdpSocket::from_std(std_sock)?,
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        })
    }

    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }

    fn try_send_one(&self, destination: SocketAddr, contents: &[u8]) -> io::Result<()> {
        let n = self.io.try_send_to(contents, destination)?;
        if n != contents.len() {
            return Err(io::Error::other(format!(
                "UDP 短写: {n}/{}",
                contents.len()
            )));
        }
        Ok(())
    }

    fn poll_recv_one(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut rb = tokio::io::ReadBuf::new(buf);
        match self.io.poll_recv_from(cx, &mut rb) {
            Poll::Ready(Ok(addr)) => {
                let n = rb.filled().len();
                Poll::Ready(Ok((n, addr)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct PlainPoller {
    sock: Arc<PlainUdpSocket>,
}

impl fmt::Debug for PlainPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlainPoller")
    }
}

impl UdpPoller for PlainPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sock.poll_writable(cx)
    }
}

impl AsyncUdpSocket for PlainUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PlainPoller { sock: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        debug_assert!(transmit.segment_size.is_none(), "PlainUdpSocket 只支持单段");
        self.try_send_one(transmit.destination, transmit.contents)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_recv_one(cx, &mut bufs[0]) {
            Poll::Ready(Ok((n, addr))) => {
                meta[0] = RecvMeta {
                    addr,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            other => match other {
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(_)) => unreachable!(),
            },
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------- ObfsSocket

/// salamander 包装：对 quinn 透明，wire 上每包 `[salt][XOR]`。
pub struct ObfsSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    psk: Vec<u8>,
    scratch: Mutex<Vec<u8>>,
}

impl fmt::Debug for ObfsSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObfsSocket(salamander)")
    }
}

impl ObfsSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, password: &[u8]) -> io::Result<Self> {
        if password.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salamander PSK 至少 4 字节",
            ));
        }
        Ok(Self {
            inner,
            psk: password.to_vec(),
            scratch: Mutex::new(Vec::with_capacity(2048)),
        })
    }
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        debug_assert!(transmit.segment_size.is_none(), "ObfsSocket 只支持单段");
        let mut wire = self
            .scratch
            .lock()
            .map_err(|_| io::Error::other("obfs: scratch 锁中毒"))?;
        salamander_obfuscate(&self.psk, transmit.contents, &mut wire);
        let wire = wire.clone();
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &wire,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            // 先收进调用方缓冲（≥ wire 长度），再原地解密左移 8 字节。
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let n = meta[0].len;
            let addr = meta[0].addr;
            if n <= SALAMANDER_SALT {
                continue; // 非法包，丢弃重收
            }
            let buf: &mut [u8] = &mut bufs[0];
            let key = salamander_key(&self.psk, &buf[..SALAMANDER_SALT]);
            for i in SALAMANDER_SALT..n {
                buf[i - SALAMANDER_SALT] = buf[i] ^ key[(i - SALAMANDER_SALT) % SALAMANDER_KEY];
            }
            meta[0] = RecvMeta {
                addr,
                len: n - SALAMANDER_SALT,
                stride: n - SALAMANDER_SALT,
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ---------------------------------------------------------------- HopSocket

/// udphop：目标端口轮换 + 本地 socket 轮换；对 quinn 恒定谎报逻辑地址。
pub struct HopSocket {
    logical: SocketAddr,
    addrs: Vec<SocketAddr>,
    interval: Duration,
    state: Mutex<HopState>,
    /// quinn 驱动的接收 waker：新增 socket 后必须唤醒它，否则驱动不会
    /// 再调 poll_recv（旧 socket 无数据就永远不会触发新 socket 的就绪）。
    recv_waker: Mutex<Option<std::task::Waker>>,
}

struct HopState {
    /// 宽限保留的旧 socket + 当前 socket（最多 2 个，当前在最后）。
    sockets: Vec<Arc<PlainUdpSocket>>,
    /// 下一跳目标在 `addrs` 中的下标。
    next: usize,
    last_hop: Instant,
}

impl fmt::Debug for HopSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HopSocket(logical={}, hops={}, interval={:?})",
            self.logical,
            self.addrs.len(),
            self.interval
        )
    }
}

impl HopSocket {
    /// `first_sock` 已绑定并打好 SO_MARK；`addrs[0]` 是首跳目标。
    pub fn new(
        first_sock: std::net::UdpSocket,
        logical: SocketAddr,
        addrs: Vec<SocketAddr>,
        interval: Duration,
    ) -> io::Result<Self> {
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "udphop 目标为空",
            ));
        }
        let first = Arc::new(PlainUdpSocket::new(first_sock)?);
        Ok(Self {
            logical,
            addrs,
            interval,
            state: Mutex::new(HopState {
                sockets: vec![first],
                next: 0,
                last_hop: Instant::now(),
            }),
            recv_waker: Mutex::new(None),
        })
    }

    /// 可能跳一次（按间隔）；在 try_send 路径调用。
    fn maybe_hop(&self) -> io::Result<()> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| io::Error::other("hop: 锁中毒"))?;
        if st.last_hop.elapsed() < self.interval {
            return Ok(());
        }
        st.last_hop = Instant::now();
        if self.addrs.len() <= 1 {
            return Ok(());
        }
        // 随机挑一个目标（Go 侧 rand.Intn(len(addrs))，允许原地打转）
        let idx = rand::thread_rng().gen_range(0..self.addrs.len());
        st.next = idx;
        // 新 socket（新本地端口 = 新四元组）；旧 socket 保留一个间隔，再旧的关掉
        let std_sock = crate::outbound::new_marked_udp()?;
        let sock = Arc::new(PlainUdpSocket::new(std_sock)?);
        if st.sockets.len() >= 2 {
            st.sockets.remove(0);
        }
        st.sockets.push(sock);
        drop(st);
        // 关键：唤醒 quinn 驱动，让它在新 socket 上注册接收就绪（见 recv_waker 注释）
        let w = match self.recv_waker.lock() {
            Ok(mut g) => g.take(),
            Err(p) => p.into_inner().take(),
        };
        if let Some(w) = w {
            w.wake();
        }
        Ok(())
    }

    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let st = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let sock = st.sockets.last().expect("hop: 至少一个 socket").clone();
        drop(st);
        sock.poll_writable(cx)
    }
}

struct HopPoller {
    sock: Arc<HopSocket>,
}

impl fmt::Debug for HopPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HopPoller")
    }
}

impl UdpPoller for HopPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sock.poll_writable(cx)
    }
}

impl AsyncUdpSocket for HopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HopPoller { sock: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        debug_assert!(transmit.segment_size.is_none(), "HopSocket 只支持单段");
        self.maybe_hop()?;
        let (sock, dest) = {
            let st = self
                .state
                .lock()
                .map_err(|_| io::Error::other("hop: 锁中毒"))?;
            let sock = st.sockets.last().expect("hop: 至少一个 socket").clone();
            (sock, self.addrs[st.next])
        };
        // 忽略 quinn 给的 destination（它以为是逻辑地址），发往当前跳
        sock.try_send_one(dest, transmit.contents)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let sockets: Vec<Arc<PlainUdpSocket>> = {
            let st = match self.state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            st.sockets.clone()
        };
        match self.recv_waker.lock() {
            Ok(mut g) => *g = Some(cx.waker().clone()),
            Err(p) => *p.into_inner() = Some(cx.waker().clone()),
        };
        let mut pending = false;
        // 当前 socket 优先，其次宽限中的旧 socket
        for sock in sockets.iter().rev() {
            match sock.poll_recv_one(cx, &mut bufs[0]) {
                Poll::Ready(Ok((n, _addr))) => {
                    meta[0] = RecvMeta {
                        // 谎报逻辑地址：源端口每跳会变，quinn 客户端会当作 migration 丢弃
                        addr: self.logical,
                        len: n,
                        stride: n,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => pending = true,
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(0))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // 逻辑视图：始终报首 socket 的本地地址（端口会随跳变化，但客户端侧仅供参考）
        let st = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        st.sockets[0].local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_union_matches_go_semantics() {
        assert_eq!(parse_port_union("443").unwrap(), vec![443]);
        assert_eq!(
            parse_port_union("8443-8445,443").unwrap(),
            vec![443, 8443, 8444, 8445]
        );
        // 逆序范围归一 + 重叠合并
        assert_eq!(
            parse_port_union("100-102,101").unwrap(),
            vec![100, 101, 102]
        );
        assert_eq!(parse_port_union("99-97").unwrap(), vec![97, 98, 99]);
        let all = parse_port_union("all").unwrap();
        assert_eq!(all.len(), 65536);
        assert_eq!(all[0], 0);
        assert_eq!(all[65535], 65535);
        assert_eq!(parse_port_union("*").unwrap().len(), 65536);
        assert!(parse_port_union("").is_err());
        assert!(parse_port_union("443-").is_err());
        assert!(parse_port_union("70000").is_err());
        assert!(parse_port_union("1-2-3").is_err());
    }

    #[test]
    fn hop_rotates_sockets_and_changes_source_port() {
        use std::net::UdpSocket as StdUdp;
        let _enter = crate::tuic::runtime().enter();
        let r1 = StdUdp::bind("127.0.0.1:0").unwrap();
        let r2 = StdUdp::bind("127.0.0.1:0").unwrap();
        let a1 = r1.local_addr().unwrap();
        let a2 = r2.local_addr().unwrap();
        let sock = StdUdp::bind("127.0.0.1:0").unwrap();
        let hop =
            Arc::new(HopSocket::new(sock, a1, vec![a1, a2], Duration::from_millis(30)).unwrap());
        let transmit = |dest: SocketAddr| Transmit {
            destination: dest,
            ecn: None,
            contents: b"hello-hop",
            segment_size: None,
            src_ip: None,
        };
        // 测试专用：WouldBlock 时用 noop waker 轮询 io poller（真实环境由 quinn 驱动）
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        let send = |t: &Transmit| loop {
            match hop.try_send(t) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let waker = std::task::Waker::from(Arc::new(NoopWaker));
                    let mut cx = std::task::Context::from_waker(&waker);
                    let mut poller = hop.clone().create_io_poller();
                    while poller.as_mut().poll_writable(&mut cx).is_pending() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(e) => panic!("hop try_send: {e}"),
            }
        };
        r1.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        r2.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut b = [0u8; 64];
        // 首包必然走 a1（next=0）
        send(&transmit(a1));
        let (_, src_first) = r1.recv_from(&mut b).expect("r1 首包");
        // 反复发送直至随机跳到 a2（最多 ~2s）
        let mut got2 = None;
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(50));
            send(&transmit(a2));
            if let Ok((n, src)) = r2.recv_from(&mut b) {
                assert_eq!(&b[..n], b"hello-hop");
                got2 = Some(src);
                break;
            }
        }
        let src_second = got2.expect("始终未跳到 a2");
        // 新 socket = 新的本地端口
        assert_ne!(src_first.port(), src_second.port(), "跳后应换本地端口");
        // 回程：接收端把回包发给第二个 socket 的本地端口，验证 poll_recv 能取到
        let waker = std::task::Waker::from(Arc::new(NoopWaker));
        let mut cx = std::task::Context::from_waker(&waker);
        let mut buf = [0u8; 64];
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let mut meta = [RecvMeta::default()];
        r1.send_to(b"reply-to-hop", src_second).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got_reply = false;
        while Instant::now() < deadline {
            match hop.poll_recv(&mut cx, &mut iov, &mut meta) {
                Poll::Ready(Ok(1)) => {
                    got_reply = true;
                    break;
                }
                Poll::Ready(Ok(_)) => continue,
                Poll::Ready(Err(e)) => panic!("poll_recv: {e}"),
                Poll::Pending => std::thread::sleep(Duration::from_millis(2)),
            }
        }
        assert!(got_reply, "poll_recv 未收到回包（接收路径坏）");
    }

    #[test]
    fn salamander_roundtrip_and_salt() {
        let psk = b"testpass";
        let payload = b"hello hy2 obfs world, this payload is longer than the salt";
        let mut wire = Vec::new();
        salamander_obfuscate(psk, payload, &mut wire);
        assert_eq!(wire.len(), payload.len() + SALAMANDER_SALT);
        let plain = salamander_deobfuscate(psk, &wire).expect("deobfuscate");
        assert_eq!(plain, payload);
        // 同载荷两次输出不同（salt 随机）
        let mut w2 = Vec::new();
        salamander_obfuscate(psk, payload, &mut w2);
        assert_ne!(wire, w2);
        // 短包 / 错 PSK
        assert!(salamander_deobfuscate(psk, &[0u8; 8]).is_none());
        let plain2 = salamander_deobfuscate(b"wrongpsk", &wire).unwrap();
        assert_ne!(plain2, payload);
    }

    #[test]
    fn salamander_key_matches_go_vector() {
        // 由 Go 侧 blake2b.Sum256(PSK||salt) 生成的跨实现向量（lab/gen 见 ADR-0020）
        let psk = b"cry_me_a_river";
        let salt: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let key = salamander_key(psk, &salt);
        let expected: [u8; 32] = [
            0x77, 0xf7, 0x85, 0x57, 0x2a, 0xdf, 0x9e, 0xb7, 0x81, 0x18, 0x0a, 0xd1, 0x13, 0x83,
            0xb7, 0xd4, 0x81, 0x84, 0x42, 0x11, 0x27, 0xbd, 0x22, 0x95, 0xb7, 0x9a, 0x30, 0x2e,
            0x5a, 0x10, 0xe8, 0x70,
        ];
        assert_eq!(key, expected);
    }
}

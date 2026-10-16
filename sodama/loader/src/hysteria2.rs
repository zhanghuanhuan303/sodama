// SPDX-License-Identifier: GPL-2.0
//! P5-G3b：hysteria2 客户端（QUIC + 最小 HTTP/3 认证 + 代理帧）。
//!
//! 规格对照 olicesx/outbound `protocol/hysteria2/{client,internal/protocol}`：
//! ```text
//! 认证（HTTP/3）：control 流 [0x00][SETTINGS 0x04 0x00]
//!   请求流：HEADERS 帧 [0x01][len varint][QPACK 块]
//!           头：:method POST / :scheme https / :authority hysteria / :path /auth
//!               hysteria-auth / hysteria-cc-rx / hysteria-padding（256..2048 随机字母数字）
//!   响应：:status == 233 为成功；hysteria-udp / hysteria-cc-rx 取自响应头
//! TCP：双向流首帧（对照 proxy.go FrameTypeTCPRequest=0x401）
//!   [varint 0x401][varint addrLen][addr "host:port"][varint padLen][padding(64..511)]
//!   响应：[status 1B（0=ok,1=err）][varint msgLen][msg][varint padLen][padding]
//! UDP（QUIC DATAGRAM，对照 internal/protocol/udp 与 client/udp.go）：
//!   [SessionID u32 BE][PacketID u16 BE][FragID u8][FragCount u8][varint addrLen][addr][data]
//!   单包 PacketID=0/FragID=0/FragCount=1；分片时随机 PacketID(1..=0xffff)，每片都带地址
//! ```
//! 边界（ADR-0019）：不做 salamander/gecko 混淆（配置即拒绝）；不做 Brutal（用 quinn 自带 CC）；
//! TCP 不等 FastOpen（拨号阶段就读响应，便于错误上报）；不做 udphop/ECH/pinSHA256。
//! 连接策略与 tuic 一致：一个 dialer 复用一条 QUIC 连接，失效后下次拨号重建。

use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::congestion::ControllerFactory;
use quinn::{AsyncUdpSocket, Runtime as _};
use rand::Rng;
use tokio::runtime::Runtime;

use crate::brutal::{self, RateTarget};
use crate::hpack::{qpack_decode, qpack_encode};
use crate::quicsock::{HopSocket, ObfsSocket, PlainUdpSocket};
use crate::quicvarint::{read_varint, read_varint_async, varint_len, write_varint};

const FRAME_HEADERS: u64 = 0x01;
const FRAME_DATA: u64 = 0x00;
const TCP_REQUEST_FRAME: u64 = 0x401;
const FRAG_MAX: usize = 1452;
const FRAG_IDLE: Duration = Duration::from_secs(30);

pub fn runtime() -> &'static Runtime {
    // 与 tuic 共用同一个全局运行时
    crate::tuic::runtime()
}

#[derive(Debug, Clone)]
pub struct Hy2Config {
    pub server: SocketAddr,
    /// 非空 = udphop：目标端口列表（含 `server.port` 作为首跳）。
    pub hop_ports: Vec<u16>,
    pub hop_interval: Duration,
    pub auth: String,
    pub sni: String,
    pub insecure: bool,
    pub alpn: Vec<Vec<u8>>,
    /// Hysteria-CC-RX（下行带宽，字节/秒；0 = 交给服务端做带宽检测）
    pub rx_bytes_per_sec: u64,
    /// 上行带宽声明（upmbps/maxTx，字节/秒；Brutal 目标的客户端上限）
    pub tx_bytes_per_sec: u64,
    /// cc_override：bbr / brutal / bbr3（其余在链接解析期拒绝）
    pub cc_override: Option<String>,
    /// salamander PSK（非空 = 启用混淆）
    pub obfs_password: Option<String>,
}

pub struct Hy2Dialer {
    cfg: Hy2Config,
    /// Brutal 速率目标（认证成功后写入；0 = 用 inner BBR）
    rate: RateTarget,
    /// 拥塞控制器工厂（与 `rate` 共享同一个句柄）
    ctrl_factory: Arc<dyn ControllerFactory + Send + Sync>,
    endpoint: Mutex<Option<quinn::Endpoint>>,
    conn: Mutex<Option<quinn::Connection>>,
    /// 控制流（SETTINGS）需要保持打开，否则会被服务端视为关闭关键流
    control: Mutex<Option<quinn::SendStream>>,
    udp_enabled: AtomicBool,
}

impl std::fmt::Debug for Hy2Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hy2Dialer({})", self.cfg.server)
    }
}

fn map_err<E: std::fmt::Display>(what: &'static str, e: E) -> io::Error {
    io::Error::other(format!("hy2: {what}: {e}"))
}

fn random_pad(rng: &mut impl Rng, min: usize, max: usize) -> Vec<u8> {
    let n = rng.gen_range(min..=max);
    let mut v = vec![0u8; n];
    for b in v.iter_mut() {
        // 字母数字（与 Go 侧 padding.go 同风格）
        const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        *b = ALNUM[rng.gen_range(0..ALNUM.len())];
    }
    v
}

// ---------------------------------------------------------------- 拨号

impl Hy2Dialer {
    pub fn new(cfg: Hy2Config) -> Self {
        let (rate, ctrl_factory) = brutal::hybrid_bbr();
        Self {
            cfg,
            rate,
            ctrl_factory,
            endpoint: Mutex::new(None),
            conn: Mutex::new(None),
            control: Mutex::new(None),
            udp_enabled: AtomicBool::new(false),
        }
    }

    fn ensure_conn(&self) -> io::Result<quinn::Connection> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| io::Error::other("hy2: 连接锁中毒"))?;
        if let Some(c) = guard.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let mut ep_guard = self
            .endpoint
            .lock()
            .map_err(|_| io::Error::other("hy2: endpoint 锁中毒"))?;
        let ep = match ep_guard.as_ref() {
            Some(ep) => ep.clone(),
            None => {
                let ep = self.build_endpoint()?;
                *ep_guard = Some(ep.clone());
                ep
            }
        };
        let conn = self.connect_and_auth(&ep)?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    fn build_endpoint(&self) -> io::Result<quinn::Endpoint> {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(60))
                .map_err(|e| map_err("idle", e))?,
        ));
        transport.datagram_receive_buffer_size(Some(1 << 20));
        transport.datagram_send_buffer_size(1 << 20);
        transport.stream_receive_window(quinn::VarInt::from_u32(8 << 20));
        transport.receive_window(quinn::VarInt::from_u32(20 << 20));
        // Brutal 近似：认证后写入速率目标，目标为 0 时走 inner BBR（见 brutal.rs）
        transport.congestion_controller_factory(self.ctrl_factory.clone());
        let mut alpn = self.cfg.alpn.clone();
        if alpn.is_empty() {
            alpn.push(b"h3".to_vec());
        }
        let rustls_cfg = crate::tls::build_rustls_config(self.cfg.insecure, &alpn);
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| map_err("tls 配置", e))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(transport));
        let sock = crate::outbound::new_marked_udp()?;
        // `tokio::net::UdpSocket::from_std` 需要 runtime 上下文
        let abstract_sock = {
            let _enter = runtime().enter();
            self.wrap_socket(sock)?
        };
        let mut endpoint = runtime().block_on(async {
            quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                abstract_sock,
                Arc::new(quinn::TokioRuntime),
            )
        })?;
        endpoint.set_default_client_config(client_cfg);
        Ok(endpoint)
    }

    /// 按配置包装底层 socket：hop（内）→ obfs（外）；两者都无则走 TokioRuntime 包装
    /// （保留 GSO/GRO，现有行为不变）。
    fn wrap_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let hop = !self.cfg.hop_ports.is_empty();
        let obfs = self.cfg.obfs_password.is_some();
        if !hop && !obfs {
            return Arc::new(quinn::TokioRuntime).wrap_udp_socket(sock);
        }
        let base: Arc<dyn AsyncUdpSocket> = if hop {
            let addrs: Vec<SocketAddr> = self
                .cfg
                .hop_ports
                .iter()
                .map(|p| SocketAddr::new(self.cfg.server.ip(), *p))
                .collect();
            Arc::new(HopSocket::new(
                sock,
                self.cfg.server,
                addrs,
                self.cfg.hop_interval,
            )?)
        } else {
            Arc::new(PlainUdpSocket::new(sock)?)
        };
        match &self.cfg.obfs_password {
            Some(pw) => Ok(Arc::new(ObfsSocket::new(base, pw.as_bytes())?)),
            None => Ok(base),
        }
    }

    fn connect_and_auth(&self, endpoint: &quinn::Endpoint) -> io::Result<quinn::Connection> {
        let cfg = &self.cfg;
        runtime().block_on(async {
            let connecting = endpoint
                .connect(cfg.server, &cfg.sni)
                .map_err(|e| map_err("connect", e))?;
            let conn = tokio::time::timeout(Duration::from_secs(8), connecting)
                .await
                .map_err(|_| map_err("握手超时", "8s"))?
                .map_err(|e| map_err("握手", e))?;

            // 1) control 流：type 0x00 + SETTINGS(0x04, len 0)；保持打开
            {
                let mut uni = conn
                    .open_uni()
                    .await
                    .map_err(|e| map_err("control 流", e))?;
                uni.write_all(&[0x00, 0x04, 0x00])
                    .await
                    .map_err(|e| map_err("SETTINGS 写", e))?;
                let mut slot = self
                    .control
                    .lock()
                    .map_err(|_| io::Error::other("hy2: 控制流锁中毒"))?;
                *slot = Some(uni);
            }

            // 2) 认证请求（HEADERS + FIN）
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| map_err("认证流", e))?;
            let mut rng = rand::thread_rng();
            let pad = random_pad(&mut rng, 256, 2048);
            let rx = cfg.rx_bytes_per_sec.to_string();
            let mut block = Vec::new();
            qpack_encode(
                &mut block,
                &[
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", "hysteria"),
                    (":path", "/auth"),
                    ("hysteria-auth", &cfg.auth),
                    ("hysteria-cc-rx", &rx),
                    ("hysteria-padding", std::str::from_utf8(&pad).unwrap_or("")),
                ],
            );
            let mut frame = Vec::with_capacity(block.len() + 5);
            write_varint(&mut frame, FRAME_HEADERS);
            write_varint(&mut frame, block.len() as u64);
            frame.extend_from_slice(&block);
            send.write_all(&frame)
                .await
                .map_err(|e| map_err("认证写", e))?;
            send.finish().map_err(|e| map_err("认证 FIN", e))?;

            // 3) 读响应 HEADERS（带超时）
            let read_resp = async {
                loop {
                    let ty = read_varint_async(&mut recv).await?;
                    let len = read_varint_async(&mut recv).await?;
                    let mut payload = vec![0u8; len as usize];
                    recv.read_exact(&mut payload)
                        .await
                        .map_err(|e| map_err("响应读", e))?;
                    match ty {
                        FRAME_HEADERS => {
                            return qpack_decode(&payload).map_err(|e| map_err("QPACK 解码", e))
                        }
                        FRAME_DATA => continue,
                        _ => continue,
                    }
                }
            };
            let fields = tokio::time::timeout(Duration::from_secs(5), read_resp)
                .await
                .map_err(|_| map_err("认证响应超时", "5s"))??;
            let mut status: Option<String> = None;
            let mut udp = false;
            let mut cc_rx: Option<String> = None;
            for (k, v) in &fields {
                if k == ":status" {
                    status = Some(v.clone());
                } else if k.eq_ignore_ascii_case("hysteria-udp") {
                    udp = v.eq_ignore_ascii_case("true") || v == "1";
                } else if k.eq_ignore_ascii_case("hysteria-cc-rx") {
                    cc_rx = Some(v.clone());
                }
            }
            if status.as_deref() != Some("233") {
                return Err(map_err(
                    "认证失败",
                    format!("status={:?}", status.unwrap_or_else(|| "?".into())),
                ));
            }
            self.udp_enabled.store(udp, Ordering::Relaxed);
            // 拥塞控制决策（对照 Go resolveCongestion/brutalTarget）：
            // - 空 override：服务端回 auto → 保持探测式 CC（我们 inner 是 BBR）；
            //   否则 min(server_rx, client_tx) > 0 → 换上 Brutal 近似目标；
            // - override=bbr/bbr3 → 保持 BBR（bbr3 以 BBR v1 近似，记入 ADR-0020）；
            // - override=brutal → 同 min() 计算，无带宽信息时自然回退 BBR。
            let rx_auto = cc_rx.as_deref() == Some("auto");
            let server_rx = cc_rx
                .as_deref()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let target = match self.cfg.cc_override.as_deref() {
                Some("bbr") | Some("bbr3") => 0,
                Some("brutal") => min_bandwidth(server_rx, self.cfg.tx_bytes_per_sec),
                _ => {
                    if rx_auto {
                        0
                    } else {
                        min_bandwidth(server_rx, self.cfg.tx_bytes_per_sec)
                    }
                }
            };
            self.rate.set(target);
            drop(recv); // 响应已拿到；服务端 handler 已返回
            Ok(conn)
        })
    }

    /// 每条 TCP relay 连接开一条 QUIC 双向流；拨号阶段解析服务端响应（非 FastOpen）。
    pub fn connect_tcp(
        &self,
        target: &crate::target::Target,
        timeout: Duration,
    ) -> io::Result<(Hy2ReadHalf, Hy2WriteHalf)> {
        let conn = self.ensure_conn()?;
        let rt = runtime();
        let (mut send, recv) = rt.block_on(async {
            match tokio::time::timeout(timeout, conn.open_bi()).await {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => Err(map_err("open_bi", e)),
                Err(_) => Err(map_err("开流超时", "")),
            }
        })?;
        // 请求帧：0x401 + addr 长度 + "host:port" + padding
        let mut rng = rand::thread_rng();
        let addr = target.to_string();
        let pad = random_pad(&mut rng, 64, 511);
        let mut frame = Vec::with_capacity(addr.len() + pad.len() + 16);
        write_varint(&mut frame, TCP_REQUEST_FRAME);
        write_varint(&mut frame, addr.len() as u64);
        frame.extend_from_slice(addr.as_bytes());
        write_varint(&mut frame, pad.len() as u64);
        frame.extend_from_slice(&pad);
        let mut recv = recv;
        rt.block_on(async {
            match tokio::time::timeout(timeout, send.write_all(&frame)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(map_err("请求帧写", e)),
                Err(_) => Err(map_err("请求帧写超时", "")),
            }
        })?;
        // 响应帧：status + msg + padding。
        // P38：去掉外层的 `async {{ async {{…}} }}`（clippy::async_yields_async 报错）——
        // 旧写法只是把内层 future 包了一层“壳”，语义不变（真正的轮询在下面的 timeout）。
        let resp = async {
            let mut status = [0u8; 1];
            recv.read_exact(&mut status)
                .await
                .map_err(|e| map_err("响应 status", e))?;
            let msg_len = read_varint_async(&mut recv).await?;
            let mut msg = vec![0u8; msg_len as usize];
            recv.read_exact(&mut msg)
                .await
                .map_err(|e| map_err("响应 msg", e))?;
            let pad_len = read_varint_async(&mut recv).await?;
            let mut pad = vec![0u8; pad_len as usize];
            recv.read_exact(&mut pad)
                .await
                .map_err(|e| map_err("响应 padding", e))?;
            Ok::<(u8, String), io::Error>((status[0], String::from_utf8_lossy(&msg).into_owned()))
        };
        let (status, msg) = rt.block_on(async {
            match tokio::time::timeout(timeout, resp).await {
                Ok(r) => r,
                Err(_) => Err(map_err("响应超时", "")),
            }
        })?;
        if status != 0 {
            return Err(map_err("目标不可达", msg));
        }
        Ok((
            Hy2ReadHalf { rt, recv },
            Hy2WriteHalf {
                rt,
                send: Mutex::new(send),
            },
        ))
    }

    /// 一个 UDP NAT 会话 = 一个 SessionID（u32，从 1 递增）。
    pub fn connect_udp(&self, target: SocketAddr) -> io::Result<Hy2Udp> {
        let conn = self.ensure_conn()?;
        if !self.udp_enabled.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "hy2: 服务端未启用 UDP（Hysteria-UDP != true）",
            ));
        }
        static NEXT_SESSION: AtomicU32 = AtomicU32::new(1);
        let sid = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        Ok(Hy2Udp {
            rt: runtime(),
            conn,
            session: sid,
            target,
            timeout: Mutex::new(Duration::from_secs(2)),
            defrag: Mutex::new(DefragState::default()),
        })
    }

    pub fn name(&self) -> String {
        if self.cfg.hop_ports.len() > 1 {
            format!(
                "hysteria2://{}+udphop({})",
                self.cfg.server,
                self.cfg.hop_ports.len()
            )
        } else {
            format!("hysteria2://{}", self.cfg.server)
        }
    }

    /// 诊断用（测试断言失败时打印）：当前 QUIC 连接的关闭原因。
    #[cfg(test)]
    pub fn close_reason(&self) -> Option<String> {
        let g = self.conn.lock().ok()?;
        let c = g.as_ref()?;
        c.close_reason().map(|e| format!("{e:?}"))
    }
}

/// Go `brutalTarget`：tx = server_rx；为 0 或大于 client_tx 时取 client_tx；都为 0 → 0。
fn min_bandwidth(server_rx: u64, client_tx: u64) -> u64 {
    let mut tx = server_rx;
    if tx == 0 || tx > client_tx {
        tx = client_tx;
    }
    tx
}

// ---------------------------------------------------------------- TCP 读写半

pub struct Hy2ReadHalf {
    rt: &'static Runtime,
    recv: quinn::RecvStream,
}

impl Read for Hy2ReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rt.block_on(self.recv.read(buf)) {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(e) => Err(map_err("流读", e)),
        }
    }
}

pub struct Hy2WriteHalf {
    rt: &'static Runtime,
    send: Mutex<quinn::SendStream>,
}

impl Hy2WriteHalf {
    pub fn shutdown_write(&self) -> io::Result<()> {
        let mut s = self
            .send
            .lock()
            .map_err(|_| io::Error::other("hy2: 写锁中毒"))?;
        s.finish().map_err(|e| map_err("finish", e))
    }
}

impl Write for Hy2WriteHalf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut s = self
            .send
            .lock()
            .map_err(|_| io::Error::other("hy2: 写锁中毒"))?;
        self.rt
            .block_on(s.write(buf))
            .map_err(|e| map_err("流写", e))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------- UDP

#[derive(Clone, Debug)]
pub struct UdpFrame {
    pub session: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: Option<String>,
    pub data: Vec<u8>,
}

pub fn parse_udp_frame(buf: &[u8]) -> Option<UdpFrame> {
    if buf.len() < 8 {
        return None;
    }
    let session = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_id = buf[6];
    let frag_count = buf[7];
    let mut pos = 8usize;
    let addr_len = read_varint(buf, &mut pos)? as usize;
    if buf.len() < pos + addr_len {
        return None;
    }
    let addr = String::from_utf8(buf[pos..pos + addr_len].to_vec()).ok()?;
    pos += addr_len;
    Some(UdpFrame {
        session,
        packet_id,
        frag_id,
        frag_count,
        addr: Some(addr),
        data: buf[pos..].to_vec(),
    })
}

pub fn encode_udp_frame(
    session: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + addr.len() + 2 + data.len());
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_id);
    out.push(frag_count);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    out.extend_from_slice(data);
    out
}

struct FragBucket {
    total: u8,
    slots: Vec<Option<Vec<u8>>>,
    seen: Instant,
}

impl FragBucket {
    fn new(total: u8) -> Self {
        Self {
            total,
            slots: vec![None; total.max(1) as usize],
            seen: Instant::now(),
        }
    }
}

#[derive(Default)]
pub struct DefragState {
    buckets: std::collections::HashMap<u16, FragBucket>,
}

impl DefragState {
    fn push(&mut self, f: &UdpFrame) -> Option<(Vec<u8>, String)> {
        self.buckets.retain(|_, b| b.seen.elapsed() < FRAG_IDLE);
        let addr = f.addr.clone().unwrap_or_default();
        if f.frag_count <= 1 {
            return Some((f.data.clone(), addr));
        }
        if f.frag_count == 0 || f.frag_id >= f.frag_count {
            return None;
        }
        let bucket = self
            .buckets
            .entry(f.packet_id)
            .or_insert_with(|| FragBucket::new(f.frag_count));
        if bucket.total != f.frag_count {
            *bucket = FragBucket::new(f.frag_count);
        }
        bucket.seen = Instant::now();
        let idx = f.frag_id as usize;
        if bucket.slots[idx].is_some() {
            return None; // 重复片
        }
        bucket.slots[idx] = Some(f.data.clone());
        if bucket.slots.iter().any(|s| s.is_none()) {
            return None;
        }
        let mut out = Vec::new();
        for s in &bucket.slots {
            out.extend_from_slice(s.as_ref().expect("slot"));
        }
        self.buckets.remove(&f.packet_id);
        Some((out, addr))
    }
}

pub struct Hy2Udp {
    rt: &'static Runtime,
    conn: quinn::Connection,
    session: u32,
    target: SocketAddr,
    timeout: Mutex<Duration>,
    defrag: Mutex<DefragState>,
}

impl Hy2Udp {
    pub fn set_read_timeout(&self, d: Option<Duration>) {
        let mut t = match self.timeout.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *t = d.unwrap_or(Duration::from_secs(2));
    }

    /// 发一个数据报；超上限时按 1200 字节安全预算分片（每片都带地址）。
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let Some(max) = self.conn.max_datagram_size() else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "hy2: 对端未启用 QUIC datagram",
            ));
        };
        let addr = self.target.to_string();
        let head = 8 + varint_len(addr.len() as u64) + addr.len();
        let budget = FRAG_MAX.min(max.saturating_sub(head)).min(1200);
        if budget == 0 {
            return Err(io::Error::new(ErrorKind::InvalidInput, "hy2: 分片预算为 0"));
        }
        if head + data.len() <= max {
            let frame = encode_udp_frame(self.session, 0, 0, 1, &addr, data);
            return self.send_raw(frame).map(|_| data.len());
        }
        let total = data.len().div_ceil(budget);
        if total > 255 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("hy2: 需要 {total} 片（上限 255）"),
            ));
        }
        let pkt = rand::thread_rng().gen_range(1..=0xFFFFu16);
        for (i, chunk) in data.chunks(budget).enumerate() {
            let frame = encode_udp_frame(self.session, pkt, i as u8, total as u8, &addr, chunk);
            self.send_raw(frame)?;
        }
        Ok(data.len())
    }

    fn send_raw(&self, frame: Vec<u8>) -> io::Result<()> {
        let rt = self.rt;
        rt.block_on(async {
            match self.conn.send_datagram(Bytes::from(frame)) {
                Ok(()) => Ok(()),
                Err(quinn::SendDatagramError::TooLarge) => Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "hy2: datagram 过大",
                )),
                Err(e) => Err(map_err("datagram 发送", e)),
            }
        })
    }

    /// 阻塞收一个数据报（超时返回 TimedOut）；返回 （数据, 服务端回报的源地址）。
    pub fn recv_with_addr(&self) -> io::Result<(Vec<u8>, String)> {
        loop {
            let timeout = match self.timeout.lock() {
                Ok(g) => *g,
                Err(p) => *p.into_inner(),
            };
            let rt = self.rt;
            let got = rt
                .block_on(async { tokio::time::timeout(timeout, self.conn.read_datagram()).await });
            let dg: Bytes = match got {
                Err(_) => return Err(io::Error::new(ErrorKind::TimedOut, "hy2: 空闲")),
                Ok(Err(e)) => return Err(map_err("datagram 接收", e)),
                Ok(Ok(d)) => d,
            };
            let Some(f) = parse_udp_frame(&dg) else {
                continue;
            };
            if f.session != self.session {
                continue;
            }
            let mut d = self
                .defrag
                .lock()
                .map_err(|_| io::Error::other("hy2: 重组锁中毒"))?;
            if let Some(v) = d.push(&f) {
                return Ok(v);
            }
        }
    }

    /// 只取数据的便捷入口（UdpRelay 用）。
    pub fn recv(&self) -> io::Result<Vec<u8>> {
        self.recv_with_addr().map(|(d, _)| d)
    }
}

// ---------------------------------------------------------------- 单测

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::process::Command;

    #[test]
    fn varint_roundtrip_and_lengths() {
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            0x3fff_ffff_ffff_ffff,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_len(v), "value {v}");
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos), Some(v));
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn tcp_request_frame_layout() {
        // 对照 proxy.go：0x401 + addrLen + addr + padLen + pad
        let addr = "1.1.1.1:8080";
        let pad = b"abc";
        let mut frame = Vec::new();
        write_varint(&mut frame, TCP_REQUEST_FRAME);
        write_varint(&mut frame, addr.len() as u64);
        frame.extend_from_slice(addr.as_bytes());
        write_varint(&mut frame, pad.len() as u64);
        frame.extend_from_slice(pad);
        assert_eq!(&frame[..2], &[0x44, 0x01]); // 0x401 的 QUIC varint 编码
        assert_eq!(frame[2], addr.len() as u8);
        let mut pos = 2;
        assert_eq!(read_varint(&frame, &mut pos), Some(addr.len() as u64));
        assert_eq!(&frame[pos..pos + addr.len()], addr.as_bytes());
        pos += addr.len();
        assert_eq!(read_varint(&frame, &mut pos), Some(3));
        assert_eq!(&frame[pos..], pad);
    }

    #[test]
    fn udp_frame_roundtrip_and_defrag() {
        let f = encode_udp_frame(9, 0, 0, 1, "2.2.2.2:9998", b"ping");
        let p = parse_udp_frame(&f).expect("parse");
        assert_eq!(p.session, 9);
        assert_eq!(p.frag_count, 1);
        assert_eq!(p.addr.as_deref(), Some("2.2.2.2:9998"));
        assert_eq!(p.data, b"ping");

        let mut d = DefragState::default();
        let f0 = parse_udp_frame(&encode_udp_frame(1, 77, 0, 3, "9.9.9.9:53", b"aa")).unwrap();
        let f1 = parse_udp_frame(&encode_udp_frame(1, 77, 1, 3, "9.9.9.9:53", b"bb")).unwrap();
        let f2 = parse_udp_frame(&encode_udp_frame(1, 77, 2, 3, "9.9.9.9:53", b"cc")).unwrap();
        assert!(d.push(&f0).is_none());
        assert!(d.push(&f2).is_none());
        let (out, addr) = d.push(&f1).expect("complete");
        assert_eq!(out, b"aabbcc");
        assert_eq!(addr, "9.9.9.9:53");
        // 重复片/越界片
        assert!(d.push(&f0).is_none());
        let bad = parse_udp_frame(&encode_udp_frame(1, 78, 5, 3, "x", b"z")).unwrap();
        assert!(d.push(&bad).is_none());
    }

    #[test]
    fn malformed_udp_frames_rejected() {
        assert!(parse_udp_frame(&[]).is_none());
        assert!(parse_udp_frame(&[0, 0, 0, 1, 0, 0, 0]).is_none());
        // addr 长度超过缓冲
        let mut f = vec![0, 0, 0, 1, 0, 0, 0, 1];
        write_varint(&mut f, 100);
        assert!(parse_udp_frame(&f).is_none());
    }

    // ---- 跨实现：Rust/quinn 客户端 ↔ lab 的 Go 参考服务端（需先构建）----

    struct Guard(std::process::Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_server(port: u16, log: &std::path::Path, extra: &[&str]) -> Option<Guard> {
        let lab = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lab");
        let bin = lab.join("proto-check/bin/hy2-server");
        if !bin.exists() {
            eprintln!(
                "skip: {} 不存在（先跑 lab/proto-check/build-hy2-server.sh）",
                bin.display()
            );
            return None;
        }
        let _ = std::fs::remove_file(log);
        let mut cmd = Command::new(&bin);
        cmd.arg("-port")
            .arg(port.to_string())
            .arg("-auth")
            .arg("testpass")
            .arg("-cert")
            .arg(lab.join("certs/cert.pem"))
            .arg("-key")
            .arg(lab.join("certs/key.pem"))
            .arg("-log")
            .arg(log);
        cmd.args(extra);
        let child = cmd.spawn().expect("spawn hy2-server");
        std::thread::sleep(Duration::from_millis(600));
        Some(Guard(child))
    }

    fn client_cfg(port: u16) -> Hy2Config {
        Hy2Config {
            server: format!("127.0.0.1:{port}").parse().unwrap(),
            hop_ports: Vec::new(),
            hop_interval: Duration::from_secs(30),
            auth: "testpass".into(),
            sni: "localhost".into(),
            insecure: true,
            alpn: Vec::new(),
            rx_bytes_per_sec: 0,
            tx_bytes_per_sec: 0,
            cc_override: None,
            obfs_password: None,
        }
    }

    #[test]
    fn tcp_roundtrip_against_go_server() {
        let port = 18961u16;
        let log = std::env::temp_dir().join(format!("hy2-tcp-{}.log", std::process::id()));
        let Some(_guard) = spawn_server(port, &log, &[]) else {
            return;
        };
        // 本地 TCP echo
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = ln.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in ln.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 65536];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let d = Hy2Dialer::new(client_cfg(port));
        let (mut r, mut w) = d
            .connect_tcp(
                &crate::target::Target::from_socket_addr(echo_addr).unwrap(),
                Duration::from_secs(5),
            )
            .expect("connect_tcp");
        // 256KB 往返（分块写读，避开握手窗口）
        let chunk = vec![0xa5u8; 64 * 1024];
        for _ in 0..4 {
            w.write_all(&chunk).unwrap();
            let mut got = vec![0u8; chunk.len()];
            r.read_exact(&mut got).expect("echo");
            assert_eq!(got, chunk);
        }
        w.shutdown_write().unwrap();
        let mut tail = [0u8; 1];
        assert_eq!(r.read(&mut tail).unwrap(), 0, "FIN 应透传为 EOF");
        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(log_text.contains("TCP target="), "server log: {log_text}");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn udp_roundtrip_against_go_server() {
        let port = 18962u16;
        let log = std::env::temp_dir().join(format!("hy2-udp-{}.log", std::process::id()));
        let Some(_guard) = spawn_server(port, &log, &[]) else {
            return;
        };
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, peer)) = echo.recv_from(&mut buf) else {
                    return;
                };
                let _ = echo.send_to(&buf[..n], peer);
            }
        });

        let d = Hy2Dialer::new(client_cfg(port));
        let udp = d.connect_udp(echo_addr).expect("connect_udp");
        udp.set_read_timeout(Some(Duration::from_secs(3)));
        // 小包（单 datagram）
        udp.send(b"ping").unwrap();
        assert_eq!(udp.recv().unwrap(), b"ping".to_vec());
        // 大包（>1200 预算，强制分片 + 服务端重组）
        let big = vec![7u8; 3000];
        udp.send(&big).unwrap();
        assert_eq!(udp.recv().unwrap(), big);
        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(log_text.contains("UDP target="), "server log: {log_text}");
        let _ = std::fs::remove_file(&log);
    }

    /// P5-G3b+：salamander 混淆（TCP+UDP 同时验证两个方向）。
    #[test]
    fn obfs_roundtrip_against_go_server() {
        let port = 18963u16;
        let log = std::env::temp_dir().join(format!("hy2-obfs-{}.log", std::process::id()));
        let Some(_guard) = spawn_server(port, &log, &["-obfs-password", "testpass"]) else {
            return;
        };
        // TCP echo
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = ln.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in ln.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 65536];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        let mut cfg = client_cfg(port);
        cfg.obfs_password = Some("testpass".into());
        let d = Hy2Dialer::new(cfg);
        let (mut r, mut w) = d
            .connect_tcp(
                &crate::target::Target::from_socket_addr(echo_addr).unwrap(),
                Duration::from_secs(5),
            )
            .expect("connect_tcp (obfs)");
        let chunk = vec![0x5au8; 64 * 1024];
        w.write_all(&chunk).unwrap();
        let mut got = vec![0u8; chunk.len()];
        r.read_exact(&mut got).expect("echo (obfs)");
        assert_eq!(got, chunk);
        w.shutdown_write().unwrap();
        let mut tail = [0u8; 1];
        assert_eq!(r.read(&mut tail).unwrap(), 0, "FIN 应透传为 EOF（obfs）");
        // UDP（小包 + 3000B 分片）
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let uaddr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, peer)) = echo.recv_from(&mut buf) else {
                    return;
                };
                let _ = echo.send_to(&buf[..n], peer);
            }
        });
        let udp = d.connect_udp(uaddr).expect("connect_udp (obfs)");
        udp.set_read_timeout(Some(Duration::from_secs(3)));
        udp.send(b"ping-obfs").unwrap();
        assert_eq!(udp.recv().unwrap(), b"ping-obfs".to_vec());
        let big = vec![9u8; 3000];
        udp.send(&big).unwrap();
        assert_eq!(udp.recv().unwrap(), big);
        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(
            log_text.contains("salamander obfs enabled"),
            "server log: {log_text}"
        );
        let _ = std::fs::remove_file(&log);
    }

    /// P5-G3b+：Brutal 近似路径（cc_override=brutal + 带宽声明）仍能正常转发。
    #[test]
    fn brutal_path_against_go_server() {
        let port = 18964u16;
        let log = std::env::temp_dir().join(format!("hy2-brutal-{}.log", std::process::id()));
        let Some(_guard) = spawn_server(port, &log, &[]) else {
            return;
        };
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = ln.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in ln.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 65536];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        let mut cfg = client_cfg(port);
        cfg.cc_override = Some("brutal".into());
        cfg.tx_bytes_per_sec = 2_000_000; // 2 MB/s → Brutal 窗口 200KB（初始 RTT 100ms）
        cfg.rx_bytes_per_sec = 1_000_000;
        let d = Hy2Dialer::new(cfg);
        let (mut r, mut w) = d
            .connect_tcp(
                &crate::target::Target::from_socket_addr(echo_addr).unwrap(),
                Duration::from_secs(5),
            )
            .expect("connect_tcp (brutal)");
        let chunk = vec![0x3cu8; 128 * 1024];
        for _ in 0..2 {
            w.write_all(&chunk).unwrap();
            let mut got = vec![0u8; chunk.len()];
            r.read_exact(&mut got).expect("echo (brutal)");
            assert_eq!(got, chunk);
        }
        w.shutdown_write().unwrap();
        let mut tail = [0u8; 1];
        assert_eq!(r.read(&mut tail).unwrap(), 0, "FIN 应透传为 EOF（brutal）");
        let _ = std::fs::remove_file(&log);
    }

    /// P5-G3b+：udphop（服务端多 socket mux；间隔 300ms 强制多次跳端口）。
    #[test]
    fn hop_roundtrip_against_go_server() {
        let port = 18965u16;
        let log = std::env::temp_dir().join(format!("hy2-hop-{}.log", std::process::id()));
        let Some(_guard) = spawn_server(port, &log, &["-hop-ports", "18966,18967"]) else {
            return;
        };
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = ln.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in ln.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 65536];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        let mut cfg = client_cfg(port);
        cfg.hop_ports = vec![18965, 18966, 18967];
        // Go 侧 NewUDPHopPacketConnContext 强制最小 5s；用真实下限跳 2 次以上
        cfg.hop_interval = Duration::from_secs(5);
        let d = Hy2Dialer::new(cfg);
        let (mut r, mut w) = d
            .connect_tcp(
                &crate::target::Target::from_socket_addr(echo_addr).unwrap(),
                Duration::from_secs(5),
            )
            .expect("connect_tcp (hop)");
        // 持续打流 ~11s（跨 2 次跳）；逐块回显校验
        let chunk = vec![0x77u8; 16 * 1024];
        for i in 0..20 {
            w.write_all(&chunk).unwrap();
            let mut got = vec![0u8; chunk.len()];
            if let Err(e) = r.read_exact(&mut got) {
                panic!(
                    "第 {i} 块回显失败: {e}；服务端 close_reason={:?}",
                    d.close_reason()
                );
            }
            assert_eq!(got, chunk, "第 {i} 块不一致（跳端口期间丢数据）");
            std::thread::sleep(Duration::from_millis(550));
        }
        w.shutdown_write().unwrap();
        let mut tail = [0u8; 1];
        assert_eq!(r.read(&mut tail).unwrap(), 0, "FIN 应透传为 EOF（hop）");
        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(log_text.contains("udphop mux"), "server log: {log_text}");
        assert!(log_text.contains("TCP target="), "server log: {log_text}");
        let _ = std::fs::remove_file(&log);
    }
}

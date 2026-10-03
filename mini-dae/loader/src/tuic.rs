// SPDX-License-Identifier: GPL-2.0
//! P5-G3：TUIC v5 客户端（QUIC，quinn 0.11）。
//!
//! 规格见 `docs/modules/tuic-v5-client-spec.md`（对照 olicesx/outbound
//! `protocol/tuic/{client,protocol,packet,frag}.go`）：
//! ```text
//! Authenticate（客户端单向流，50B）：[05][00][uuid16][token32]，写后 FIN
//!   token = TLS.ExportKeyingMaterial(label = uuid 16 裸字节, context = password)[32]
//! Connect（每条 TCP 一条客户端双向流）：[05][01][ATYP][ADDR][PORT]，之后裸字节
//! Packet（QUIC DATAGRAM）：[05][02][assoc u16][pkt u16][frag_total u8][frag_id u8]
//!                           [size u16][ATYP+ADDR+PORT | 0xff][data]
//! Dissociate（单向流）：[05][03][assoc u16]
//! ```
//! 失败语义：认证失败/非法命令 → 服务端 `CloseWithError(0xfffffff1/0xfffffff3)`；
//! 目标不可达 → 流 CancelRead+CancelWrite（无状态帧）。
//!
//! 边界（ADR-0018）：native datagram 模式（不做 relay/quic 模式）；不做 0-RTT、
//! 连接迁移与「退休宽限」；不做心跳发送；单流错误不拆隧道（连接复用但无重连状态机）；
//! ALPN 缺省用 `h3`（生态惯例，链接可用 `alpn=` 覆盖）。

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rand::Rng;
use tokio::runtime::Runtime;

pub const VER5: u8 = 0x05;
pub const CMD_AUTH: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
/// Dissociate：客户端关闭 UDP 关联时用；mini 不发送（会话随连接回收，见 ADR-0018）。
#[allow(dead_code)]
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;
const ATYP_V4: u8 = 0x01;
const ATYP_V6: u8 = 0x02;
const ATYP_NONE: u8 = 0xff;
#[allow(dead_code)]
const ERR_AUTH_FAILED: u64 = 0xfffffff1;
const FRAG_MAX: usize = 1452;

/// 全局 tokio 运行时（QUIC 驱动；阻塞 relay 线程通过 block_on 桥接）。
pub fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("mini-dae-quic")
            .build()
            .expect("tokio runtime")
    })
}

#[derive(Debug, Clone)]
pub struct TuicConfig {
    pub server: SocketAddr,
    pub uuid: [u8; 16],
    pub password: String,
    pub sni: String,
    pub insecure: bool,
    pub alpn: Vec<Vec<u8>>,
}

/// 复用一条 QUIC 连接（对照 Go 客户端：一个 dialer 一条连接；连接失效时下次拨号重建）。
pub struct TuicDialer {
    cfg: TuicConfig,
    endpoint: Mutex<Option<quinn::Endpoint>>,
    conn: Mutex<Option<quinn::Connection>>,
}

impl std::fmt::Debug for TuicDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TuicDialer({})", self.cfg.server)
    }
}

fn map_err<E: std::fmt::Display>(what: &'static str, e: E) -> io::Error {
    io::Error::new(ErrorKind::Other, format!("tuic: {what}: {e}"))
}

impl TuicDialer {
    pub fn new(cfg: TuicConfig) -> Self {
        Self {
            cfg,
            endpoint: Mutex::new(None),
            conn: Mutex::new(None),
        }
    }

    /// 取可用连接；没有或已关闭就重建（不做退休宽限，见模块边界）。
    fn ensure_conn(&self) -> io::Result<quinn::Connection> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| io::Error::other("tuic: 连接锁中毒"))?;
        if let Some(c) = guard.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let mut ep_guard = self
            .endpoint
            .lock()
            .map_err(|_| io::Error::other("tuic: endpoint 锁中毒"))?;
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
        // 上游 socket 必须打 SO_MARK，否则会被 mini-dae 数据面二次捕获。
        let sock = crate::outbound::new_marked_udp()?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(3)));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(30))
                .map_err(|e| map_err("idle", e))?,
        ));
        transport.datagram_receive_buffer_size(Some(1 << 20));
        transport.datagram_send_buffer_size(1 << 20);
        transport.stream_receive_window(quinn::VarInt::from_u32(8 << 20));
        transport.receive_window(quinn::VarInt::from_u32(20 << 20));
        if !self.cfg.insecure {
            // 生产路径：webpki 根（与 TCP 协议一致）
        }
        let mut alpn = self.cfg.alpn.clone();
        if alpn.is_empty() {
            alpn.push(b"h3".to_vec());
        }
        let rustls_cfg = crate::tls::build_rustls_config(self.cfg.insecure, &alpn);
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| map_err("tls 配置", e))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(transport));
        let mut endpoint = runtime().block_on(async {
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                sock,
                Arc::new(quinn::TokioRuntime),
            )
        })?;
        endpoint.set_default_client_config(client_cfg);
        Ok(endpoint)
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
            // token：TLS 1.3 exporter（label = uuid 裸字节，context = password）
            let mut token = [0u8; 32];
            conn.export_keying_material(&mut token, &cfg.uuid, cfg.password.as_bytes())
                .map_err(|e| map_err("exporter", format!("{e:?}")))?;
            let mut uni = conn.open_uni().await.map_err(|e| map_err("open_uni", e))?;
            let mut head = Vec::with_capacity(50);
            head.push(VER5);
            head.push(CMD_AUTH);
            head.extend_from_slice(&cfg.uuid);
            head.extend_from_slice(&token);
            uni.write_all(&head)
                .await
                .map_err(|e| map_err("auth 写", e))?;
            uni.finish().map_err(|e| map_err("auth fin", e))?;
            Ok::<_, io::Error>(conn)
        })
    }

    /// 每条 TCP relay 连接开一条 QUIC 双向流。
    pub fn connect_tcp(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> io::Result<(TuicReadHalf, TuicWriteHalf)> {
        let conn = self.ensure_conn()?;
        let rt = runtime();
        let (mut send, recv) = rt.block_on(async {
            match tokio::time::timeout(timeout, conn.open_bi()).await {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => Err(map_err("open_bi", e)),
                Err(_) => Err(map_err("开流超时", "")),
            }
        })?;
        let mut head = Vec::with_capacity(24);
        head.push(VER5);
        head.push(CMD_CONNECT);
        push_addr(&mut head, target)?;
        rt.block_on(async {
            match tokio::time::timeout(timeout, send.write_all(&head)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(map_err("流头写", e)),
                Err(_) => Err(map_err("流头写超时", "")),
            }
        })?;
        Ok((
            TuicReadHalf { rt, recv },
            TuicWriteHalf {
                rt,
                send: Mutex::new(send),
            },
        ))
    }

    /// 一个 UDP NAT 会话 = 共享连接上一个随机 ASSOC_ID（无创建握手）。
    pub fn connect_udp(&self, target: SocketAddr) -> io::Result<TuicUdp> {
        let conn = self.ensure_conn()?;
        let assoc = rand::thread_rng().gen_range(0..=0xFFFEu16);
        Ok(TuicUdp {
            rt: runtime(),
            conn,
            assoc,
            pkt_id: AtomicU16::new(0),
            target,
            timeout: Mutex::new(Duration::from_secs(2)),
            defrag: Mutex::new(DefragState::default()),
        })
    }

    pub fn name(&self) -> String {
        format!("tuic://{}", self.cfg.server)
    }
}

fn push_addr(buf: &mut Vec<u8>, target: SocketAddr) -> io::Result<()> {
    match target.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

// ---------------------------------------------------------------- TCP 读写半

pub struct TuicReadHalf {
    rt: &'static Runtime,
    recv: quinn::RecvStream,
}

impl Read for TuicReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rt.block_on(self.recv.read(buf)) {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0), // FIN
            Err(e) => Err(map_err("流读", e)),
        }
    }
}

pub struct TuicWriteHalf {
    rt: &'static Runtime,
    send: Mutex<quinn::SendStream>,
}

impl TuicWriteHalf {
    /// QUIC 流的半关闭 = FIN（对照 Go 的 CloseWrite）。
    pub fn shutdown_write(&self) -> io::Result<()> {
        let mut s = self
            .send
            .lock()
            .map_err(|_| io::Error::other("tuic: 写锁中毒"))?;
        s.finish().map_err(|e| map_err("finish", e))
    }
}

impl Write for TuicWriteHalf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut s = self
            .send
            .lock()
            .map_err(|_| io::Error::other("tuic: 写锁中毒"))?;
        self.rt
            .block_on(s.write(buf))
            .map_err(|e| map_err("流写", e))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------- UDP

const FRAG_IDLE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct ParsedPacket {
    pub assoc: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub addr: Option<SocketAddr>,
    pub data: Vec<u8>,
}

/// 解析 Packet 帧；None = malformed（丢弃）。
pub fn parse_packet(buf: &[u8]) -> Option<ParsedPacket> {
    if buf.len() < 10 || buf[0] != VER5 || buf[1] != CMD_PACKET {
        return None;
    }
    let assoc = u16::from_be_bytes([buf[2], buf[3]]);
    let pkt_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_total = buf[6];
    let frag_id = buf[7];
    let size = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let mut off = 10;
    let addr = if buf.get(off) == Some(&ATYP_NONE) {
        off += 1;
        None
    } else {
        let atyp = *buf.get(off)?;
        off += 1;
        let ip = match atyp {
            ATYP_V4 => {
                if buf.len() < off + 4 {
                    return None;
                }
                let ip = IpAddr::from([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
                off += 4;
                ip
            }
            ATYP_V6 => {
                if buf.len() < off + 16 {
                    return None;
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[off..off + 16]);
                off += 16;
                IpAddr::from(o)
            }
            _ => return None,
        };
        if buf.len() < off + 2 {
            return None;
        }
        let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
        off += 2;
        Some(SocketAddr::new(ip, port))
    };
    if buf.len() < off + size {
        return None;
    }
    Some(ParsedPacket {
        assoc,
        pkt_id,
        frag_total,
        frag_id,
        addr,
        data: buf[off..off + size].to_vec(),
    })
}

fn encode_packet(
    assoc: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: Option<SocketAddr>,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + data.len());
    out.push(VER5);
    out.push(CMD_PACKET);
    out.extend_from_slice(&assoc.to_be_bytes());
    out.extend_from_slice(&pkt_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    match addr {
        Some(a) => {
            let _ = push_addr(&mut out, a);
        }
        None => out.push(ATYP_NONE),
    }
    out.extend_from_slice(data);
    out
}

struct FragBucket {
    total: u8,
    slots: Vec<Option<Vec<u8>>>,
    addr: Option<SocketAddr>,
    seen: Instant,
}

impl FragBucket {
    fn new(total: u8) -> Self {
        Self {
            total,
            slots: vec![None; total as usize],
            addr: None,
            seen: Instant::now(),
        }
    }
}

#[derive(Default)]
pub struct DefragState {
    buckets: std::collections::HashMap<u16, FragBucket>,
}

impl DefragState {
    /// 推入一个分片；集齐（含首片地址）时返回完整数据报。
    fn push(&mut self, p: &ParsedPacket) -> Option<Vec<u8>> {
        self.buckets.retain(|_, b| b.seen.elapsed() < FRAG_IDLE);
        if p.frag_total <= 1 {
            return Some(p.data.clone());
        }
        if p.frag_total == 0 || p.frag_id >= p.frag_total {
            return None;
        }
        let bucket = self
            .buckets
            .entry(p.pkt_id)
            .or_insert_with(|| FragBucket::new(p.frag_total));
        if bucket.total != p.frag_total {
            // PKT_ID 复用且片数不同：整体重置
            bucket.total = p.frag_total;
            bucket.slots = vec![None; p.frag_total as usize];
            bucket.addr = None;
        }
        bucket.seen = Instant::now();
        let idx = p.frag_id as usize;
        if bucket.slots[idx].is_some() {
            return None; // 重复片
        }
        if p.frag_id == 0 {
            let Some(a) = p.addr else {
                // 首片必须带地址
                self.buckets.remove(&p.pkt_id);
                return None;
            };
            bucket.addr = Some(a);
        }
        bucket.slots[idx] = Some(p.data.clone());
        if bucket.slots.iter().any(|s| s.is_none()) || bucket.addr.is_none() {
            return None;
        }
        let mut out = Vec::new();
        for s in &bucket.slots {
            out.extend_from_slice(s.as_ref().expect("slot"));
        }
        self.buckets.remove(&p.pkt_id);
        Some(out)
    }
}

pub struct TuicUdp {
    rt: &'static Runtime,
    conn: quinn::Connection,
    assoc: u16,
    pkt_id: AtomicU16,
    target: SocketAddr,
    timeout: Mutex<Duration>,
    defrag: Mutex<DefragState>,
}

impl TuicUdp {
    pub fn set_read_timeout(&self, d: Option<Duration>) {
        let mut t = match self.timeout.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *t = d.unwrap_or(Duration::from_secs(2));
    }

    /// 发一个数据报；超出 datagram 上限时按 1452 上限分片（首片带地址）。
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let Some(max) = self.conn.max_datagram_size() else {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "tuic: 对端未启用 QUIC datagram",
            ));
        };
        // 头长（含地址）+ 数据
        let head_len = 12 + addr_len(self.target);
        if head_len + data.len() <= max {
            let pkt = encode_packet(self.assoc, 0, 1, 0, Some(self.target), data);
            self.send_raw(pkt)?;
            return Ok(data.len());
        }
        let frag_size = FRAG_MAX.min(max.saturating_sub(head_len));
        if frag_size == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "tuic: 分片预算为 0",
            ));
        }
        let total = data.len().div_ceil(frag_size);
        if total > 255 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("tuic: 需要 {total} 片（上限 255）"),
            ));
        }
        let pkt_id = rand::thread_rng().gen_range(1..=0xFFFFu16);
        self.pkt_id.store(pkt_id, Ordering::Relaxed);
        for (i, chunk) in data.chunks(frag_size).enumerate() {
            let addr = if i == 0 { Some(self.target) } else { None };
            let pkt = encode_packet(self.assoc, pkt_id, total as u8, i as u8, addr, chunk);
            self.send_raw(pkt)?;
        }
        Ok(data.len())
    }

    fn send_raw(&self, pkt: Vec<u8>) -> io::Result<()> {
        let rt = self.rt;
        rt.block_on(async {
            match self.conn.send_datagram(Bytes::from(pkt)) {
                Ok(()) => Ok(()),
                Err(quinn::SendDatagramError::TooLarge) => Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "tuic: datagram 过大（调用方应先分片）",
                )),
                Err(e) => Err(map_err("datagram 发送", e)),
            }
        })
    }

    /// 阻塞收一个数据报（超时返回 TimedOut，供会话存活检查）。
    pub fn recv(&self) -> io::Result<Vec<u8>> {
        loop {
            let timeout = match self.timeout.lock() {
                Ok(g) => *g,
                Err(p) => *p.into_inner(),
            };
            let rt = self.rt;
            let got = rt
                .block_on(async { tokio::time::timeout(timeout, self.conn.read_datagram()).await });
            let dg: Bytes = match got {
                Err(_) => return Err(io::Error::new(ErrorKind::TimedOut, "tuic: 空闲")),
                Ok(Err(e)) => return Err(map_err("datagram 接收", e)),
                Ok(Ok(d)) => d,
            };
            // 心跳/未知命令/未知 assoc：忽略并继续等
            if dg.first() == Some(&VER5) && dg.get(1) == Some(&CMD_HEARTBEAT) {
                continue;
            }
            let Some(p) = parse_packet(&dg) else {
                continue;
            };
            if p.assoc != self.assoc {
                continue;
            }
            let mut d = self
                .defrag
                .lock()
                .map_err(|_| io::Error::other("tuic: 重组锁中毒"))?;
            if let Some(payload) = d.push(&p) {
                return Ok(payload);
            }
        }
    }
}

fn addr_len(a: SocketAddr) -> usize {
    match a.ip() {
        IpAddr::V4(_) => 1 + 4 + 2,
        IpAddr::V6(_) => 1 + 16 + 2,
    }
}

// ---------------------------------------------------------------- 单测

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::process::Command;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn packet_roundtrip() {
        let a = addr("1.2.3.4:53");
        let wire = encode_packet(7, 0, 1, 0, Some(a), b"hello");
        let p = parse_packet(&wire).expect("parse");
        assert_eq!(p.assoc, 7);
        assert_eq!(p.frag_total, 1);
        assert_eq!(p.addr, Some(a));
        assert_eq!(p.data, b"hello");
    }

    #[test]
    fn packet_none_addr_and_zero_len() {
        let wire = encode_packet(1, 0x1234, 3, 2, None, b"");
        let p = parse_packet(&wire).expect("parse");
        assert_eq!(p.addr, None);
        assert_eq!(p.frag_id, 2);
        assert!(p.data.is_empty());
    }

    #[test]
    fn malformed_packets_rejected() {
        assert!(parse_packet(&[]).is_none());
        assert!(parse_packet(&[VER5, CMD_PACKET]).is_none());
        let mut short = encode_packet(1, 0, 1, 0, Some(addr("1.1.1.1:1")), b"abc");
        short.truncate(short.len() - 1); // size 与实长不符
        assert!(parse_packet(&short).is_none());
    }

    #[test]
    fn defrag_reassembles_in_order() {
        let a = addr("9.9.9.9:53");
        let mut d = DefragState::default();
        let f0 = parse_packet(&encode_packet(1, 42, 3, 0, Some(a), b"aa")).unwrap();
        let f1 = parse_packet(&encode_packet(1, 42, 3, 1, None, b"bb")).unwrap();
        let f2 = parse_packet(&encode_packet(1, 42, 3, 2, None, b"cc")).unwrap();
        assert!(d.push(&f0).is_none());
        assert!(d.push(&f2).is_none());
        let out = d.push(&f1).expect("complete");
        assert_eq!(out, b"aabbcc");
        // 重复片在同一 pkt_id 复用后不应重复投递
        let f0b = parse_packet(&encode_packet(1, 42, 3, 0, Some(a), b"aa")).unwrap();
        assert!(d.push(&f0b).is_none());
    }

    #[test]
    fn defrag_drops_non_first_without_addr_and_bad_index() {
        let a = addr("9.9.9.9:53");
        let mut d = DefragState::default();
        // 首片缺地址 → 整体丢弃
        let f0 = parse_packet(&encode_packet(1, 7, 2, 0, None, b"x")).unwrap();
        assert!(d.push(&f0).is_none());
        let f_last = parse_packet(&encode_packet(1, 8, 2, 1, None, b"y")).unwrap();
        assert!(d.push(&f_last).is_none());
        // 越界 frag_id
        let f_bad = parse_packet(&encode_packet(1, 9, 2, 5, Some(a), b"z")).unwrap();
        assert!(d.push(&f_bad).is_none());
    }

    // ---- 跨实现：Rust/quinn 客户端 ↔ lab 的 Go 参考服务端（需先构建）----

    struct Guard(std::process::Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_server(port: u16, log: &std::path::Path) -> Option<Guard> {
        let lab = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lab");
        let bin = lab.join("proto-check/bin/tuic-server");
        if !bin.exists() {
            eprintln!(
                "skip: {} 不存在（先跑 lab/proto-check/build-tuic-server.sh）",
                bin.display()
            );
            return None;
        }
        let _ = std::fs::remove_file(log);
        let child = Command::new(&bin)
            .arg("-port")
            .arg(port.to_string())
            .arg("-uuid")
            .arg("de305d54-75b4-431b-adb2-eb6b9e546014")
            .arg("-password")
            .arg("testpass")
            .arg("-cert")
            .arg(lab.join("certs/cert.pem"))
            .arg("-key")
            .arg(lab.join("certs/key.pem"))
            .arg("-log")
            .arg(log)
            .spawn()
            .expect("spawn tuic-server");
        std::thread::sleep(Duration::from_millis(500));
        Some(Guard(child))
    }

    fn cfg(port: u16) -> TuicConfig {
        TuicConfig {
            server: addr(&format!("127.0.0.1:{port}")),
            uuid: crate::vless::parse_uuid("de305d54-75b4-431b-adb2-eb6b9e546014").unwrap(),
            password: "testpass".into(),
            sni: "localhost".into(),
            insecure: true,
            alpn: Vec::new(),
        }
    }

    #[test]
    fn tcp_roundtrip_against_go_server() {
        let port = 18953u16;
        let log = std::env::temp_dir().join(format!("tuic-tcp-{}.log", std::process::id()));
        let Some(_guard) = spawn_server(port, &log) else {
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

        let d = TuicDialer::new(cfg(port));
        let (mut r, mut w) = d
            .connect_tcp(echo_addr, Duration::from_secs(5))
            .expect("connect_tcp");
        // 256KB 往返（分块写读，避开握手窗口）
        let chunk = vec![0x5au8; 64 * 1024];
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
        let port = 18954u16;
        let log = std::env::temp_dir().join(format!("tuic-udp-{}.log", std::process::id()));
        let Some(_guard) = spawn_server(port, &log) else {
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

        let d = TuicDialer::new(cfg(port));
        let udp = d.connect_udp(echo_addr).expect("connect_udp");
        udp.set_read_timeout(Some(Duration::from_secs(3)));
        // 小包
        udp.send(b"ping").unwrap();
        assert_eq!(udp.recv().unwrap(), b"ping".to_vec());
        // 大包（强制分片，验证分片编码 + 服务端重组）
        let big = vec![7u8; 3000];
        udp.send(&big).unwrap();
        assert_eq!(udp.recv().unwrap(), big);
        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(log_text.contains("UDP target="), "server log: {log_text}");
        let _ = std::fs::remove_file(&log);
    }
}

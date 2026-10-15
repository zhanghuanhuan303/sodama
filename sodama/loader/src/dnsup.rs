// SPDX-License-Identifier: GPL-2.0
//! P18a：DNS 上游传输（对照 dae `component/dns/upstream.go`）。
//!
//! 支持 scheme（与 dae 对齐）：
//! - 无 scheme / `tcp+udp` / `udp+tcp`：先 UDP，应答 TC 或超时再走 TCP；
//! - `udp://`：UDP（同一上游串行复用同一 marked socket，避免响应串包）；
//! - `tcp://`：TCP（2 字节长度分帧，每查询一条连接）；
//! - `tls://`（DoT，默认 853）：TLS + 2 字节分帧，**持久连接**（锁内串行）；
//! - `https://`（DoH，默认 443 /path=/dns-query）：TLS + **HTTP/2（ALPN 协商；
//!   自实现最小 h2 客户端）** POST `application/dns-message`，**持久连接**；协商不到 h2
//!   或 h2 握手失败时同连接/重连回退 HTTP/1.1（keep-alive + Content-Length/chunked）；
//! - `quic://`（DoQ，默认 853）：RFC 9250——线上 DNS ID 必须置 0（应答恢复客户端
//!   ID）、每查询一条双向流、**查询写完 FIN 后才读应答**、连接复用（错流/过期重建）；
//! - `h3://`（DoH over HTTP/3，默认 443/path=/dns-query）：QUIC + ALPN=h3 + 最小
//!   HTTP/3（`h3client`）POST `application/dns-message`，**连接复用**（失败重建重试）。
//!
//! URL 查询参数（sodama 扩展，与其它协议一致）：`sni=` 覆盖 TLS SNI、
//! `insecure=1|allowInsecure=1` 跳过证书校验（lab 自签用）。
//!
//! 与 dae 的差异（如实）：DoH 按 ALPN 优先 h2、可用 `h3://` 显式走 HTTP/3；
//! h2/h3 客户端均为最小实现（无服务端推送/动态表解码）；上游主机名解析默认系统解析，
//! 配置 `global.bootstrap_resolver` 后改为直连自举（对照 dae：dae 未配置时也有
//! 119.29/223.5 回退，sodama 不回退、保持系统解析）。

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::outbound;
use crate::tls;

use crate::log;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
/// 持久连接最大空闲时间（超过则新建）
const PERSIST_IDLE: Duration = Duration::from_secs(30);
/// DoQ 连接最大空闲时间（超过则新建）
const QUIC_IDLE: Duration = Duration::from_secs(60);
/// DoQ 请求取消错误码（RFC 9250 §4.3.1 DOQ_REQUEST_CANCELLED）
const DOQ_REQUEST_CANCELLED: u32 = 0x3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Udp,
    Tcp,
    TcpUdp,
    Tls,
    Https,
    H3,
    Quic,
}

impl Scheme {
    pub fn name(self) -> &'static str {
        match self {
            Scheme::Udp => "udp",
            Scheme::Tcp => "tcp",
            Scheme::TcpUdp => "tcp+udp",
            Scheme::Tls => "tls",
            Scheme::Https => "https",
            Scheme::H3 => "h3",
            Scheme::Quic => "quic",
        }
    }
}

/// ECS 注入模式（sodama 扩展；URL 参数 `ecs=auto|CIDR`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcsMode {
    /// 用查询发起方的地址归整：v4 /24、v6 /56
    Auto,
    /// 固定前缀
    Prefix(IpAddr, u8),
}

#[derive(Debug, Clone)]
pub struct UpstreamSpec {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub sni: Option<String>,
    pub insecure: bool,
    /// ECS 注入（默认不注入，透传客户端自带 EDNS）
    pub ecs: Option<EcsMode>,
}

/// 解析上游 URL（对照 dae `ParseRawUpstream` 的默认值）。
pub fn parse(raw: &str) -> Result<UpstreamSpec, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("DNS 上游为空".into());
    }
    // 允许裸 host:port / IPv6 字面量（无 scheme → tcp+udp，dae 同）
    let (scheme_s, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("tcp+udp".to_string(), raw),
    };
    let scheme = match scheme_s.as_str() {
        "udp" => Scheme::Udp,
        "tcp" => Scheme::Tcp,
        "tcp+udp" | "udp+tcp" => Scheme::TcpUdp,
        "tls" => Scheme::Tls,
        "https" => Scheme::Https,
        "h3" | "http3" => Scheme::H3,
        "quic" => Scheme::Quic,
        other => return Err(format!("DNS 上游 scheme 不支持: {other}")),
    };
    // 拆 query（?sni=…&insecure=1）
    let (hostpart, query) = match rest.split_once('?') {
        Some((h, q)) => (h, q),
        None => (rest, ""),
    };
    // https/h3 先切出 path（其余 scheme 无 path）
    let (hostport, path) = if matches!(scheme, Scheme::Https | Scheme::H3) {
        match hostpart.split_once('/') {
            Some((h, p)) => (h, format!("/{}", p.trim_start_matches('/'))),
            None => (hostpart, "/dns-query".to_string()),
        }
    } else {
        (hostpart, "/dns-query".to_string())
    };
    let default_port = match scheme {
        Scheme::Tls | Scheme::Quic => 853,
        Scheme::Https | Scheme::H3 => 443,
        _ => 53,
    };
    // host[:port]，支持 [v6]
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("DNS 上游 IPv6 括号不匹配: {raw}"))?;
        let p = tail
            .strip_prefix(':')
            .map(|p| p.parse::<u16>().map_err(|e| format!("端口非法: {e}")))
            .transpose()?
            .unwrap_or(default_port);
        (h.to_string(), p)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') {
            (
                h.to_string(),
                p.parse::<u16>().map_err(|e| format!("端口非法: {e}"))?,
            )
        } else {
            (hostport.to_string(), default_port)
        }
    } else {
        (hostport.to_string(), default_port)
    };
    if host.is_empty() {
        return Err(format!("DNS 上游缺少主机: {raw}"));
    }
    let mut sni = None;
    let mut insecure = false;
    let mut ecs = None;
    for kv in query.split('&') {
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        match k.to_ascii_lowercase().as_str() {
            "sni" => sni = Some(v.to_string()),
            "insecure" | "allowinsecure" | "skip-cert-verify" => {
                insecure = matches!(v, "1" | "true" | "TRUE" | "True")
            }
            "ecs" => {
                ecs = Some(parse_ecs(v)?);
            }
            _ => {}
        }
    }
    Ok(UpstreamSpec {
        scheme,
        host,
        port,
        path,
        sni,
        insecure,
        ecs,
    })
}

/// 解析 `ecs=auto` 或 `ecs=<ip>/<prefix>`（v4/v6）。
fn parse_ecs(v: &str) -> Result<EcsMode, String> {
    if v.eq_ignore_ascii_case("auto") {
        return Ok(EcsMode::Auto);
    }
    let (a, p) = v
        .split_once('/')
        .ok_or_else(|| format!("ecs 参数需为 auto 或 CIDR（如 192.168.0.0/24）: {v}"))?;
    let ip: IpAddr = a.parse().map_err(|e| format!("ecs 地址非法（{v}）: {e}"))?;
    let plen: u8 = p.parse().map_err(|e| format!("ecs 前缀非法（{v}）: {e}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if plen == 0 || plen > max {
        return Err(format!("ecs 前缀越界（{v}）"));
    }
    Ok(EcsMode::Prefix(ip, plen))
}

fn dns_id(msg: &[u8]) -> Option<u16> {
    if msg.len() < 12 {
        return None;
    }
    Some(u16::from_be_bytes([msg[0], msg[1]]))
}

fn truncated(msg: &[u8]) -> bool {
    msg.len() >= 4 && msg[2] & 0x02 != 0
}

/// 持久连接（DoT/DoH 共用）。DoH 若握手出 h2（ALPN）则 `h2` 有值。
struct Persist {
    r: tls::TlsReader,
    w: tls::TlsWriter,
    born: Instant,
    h2: Option<crate::h2client::H2Conn>,
}

/// DoQ 连接（quinn；连接复用，每查询一条双向流）。
struct QuicConn {
    conn: quinn::Connection,
    born: Instant,
}

/// DoH over H3 连接（quinn + 最小 HTTP/3；连接复用，请求串行）。
struct H3DoH {
    h3: crate::h3client::H3Conn,
    born: Instant,
}

pub struct Upstream {
    pub spec: UpstreamSpec,
    pub url: String,
    addr: SocketAddr,
    /// UDP（含 tcp+udp 的首选路径）；锁内串行避免响应串包
    udp: Option<Mutex<UdpSocket>>,
    persist: Mutex<Option<Persist>>,
    quic: Mutex<Option<QuicConn>>,
    h3: Mutex<Option<H3DoH>>,
    /// P23：该上游 ALPN 选了 h2 但 h2 握手仍失败（后续直接用 HTTP/1.1）。
    h2_broken: std::sync::atomic::AtomicBool,
}

impl Upstream {
    /// 解析 + 解析主机名（优先 IPv4）+ 建 UDP socket（如需）。
    pub fn new(raw: &str) -> Result<Arc<Self>, String> {
        let spec = parse(raw)?;
        // P23：配置了 bootstrap resolver 时，用直连解析器解析上游主机名
        // （对照 dae：dns.upstream 非 IP 字面量的主机名走 bootstrap）。
        let addrs: Vec<SocketAddr> = if crate::bootstrap::enabled() {
            crate::bootstrap::resolve_host(&spec.host)?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, spec.port))
                .collect()
        } else {
            (spec.host.as_str(), spec.port)
                .to_socket_addrs()
                .map_err(|e| format!("解析 DNS 上游 {}:{} 失败: {e}", spec.host, spec.port))?
                .collect()
        };
        let addr = addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| format!("DNS 上游 {}:{} 无地址", spec.host, spec.port))?;
        let udp = match spec.scheme {
            Scheme::Udp | Scheme::TcpUdp => Some(Mutex::new(
                outbound::new_marked_udp()
                    .map_err(|e| format!("建 DNS 上游 UDP socket 失败: {e}"))?,
            )),
            _ => None,
        };
        Ok(Arc::new(Self {
            spec,
            url: raw.to_string(),
            addr,
            udp,
            persist: Mutex::new(None),
            quic: Mutex::new(None),
            h3: Mutex::new(None),
            h2_broken: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn tls_sni(&self) -> String {
        self.spec
            .sni
            .clone()
            .unwrap_or_else(|| self.spec.host.clone())
    }

    /// 一次查询/应答交换（阻塞；含超时与一次重连重试）。
    pub fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        match self.spec.scheme {
            Scheme::Udp => self.exchange_udp(query),
            Scheme::Tcp => self.exchange_tcp(query),
            Scheme::TcpUdp => {
                let r = self.exchange_udp(query);
                match r {
                    Ok(resp) if !truncated(&resp) => Ok(resp),
                    Ok(_) | Err(_) => self.exchange_tcp(query),
                }
            }
            Scheme::Tls => self.exchange_tls(query),
            Scheme::Https => self.exchange_https(query),
            Scheme::H3 => self.exchange_h3(query),
            Scheme::Quic => self.exchange_quic(query),
        }
    }

    fn exchange_udp(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let udp = self
            .udp
            .as_ref()
            .ok_or_else(|| "上游无 UDP socket".to_string())?;
        // 锁中毒恢复：持有者 panic 后状态可直接重建（丢旧连接/旧 socket 更安全）
        let sock = udp.lock().unwrap_or_else(|e| e.into_inner());
        sock.set_read_timeout(Some(EXCHANGE_TIMEOUT))
            .map_err(|e| e.to_string())?;
        sock.send_to(query, self.addr).map_err(|e| e.to_string())?;
        let want = dns_id(query);
        let mut buf = vec![0u8; 4096];
        // 跳过不属于本查询的杂包（共享 socket 下的保险丝）
        for _ in 0..8 {
            let n = sock.recv(&mut buf).map_err(|e| e.to_string())?;
            let resp = &buf[..n];
            if want.is_none() || dns_id(resp) == want {
                return Ok(resp.to_vec());
            }
        }
        Err("UDP 上游响应与查询 ID 不匹配".into())
    }

    fn exchange_tcp(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut s = outbound::marked_tcp_connect(self.addr, CONNECT_TIMEOUT)
            .map_err(|e| format!("TCP 连接上游失败: {e}"))?;
        // H2 修复：作用域结束自动解除拨号看门狗（旧实现武装后无人解除，
        // 到点会把仍在用的 socket shutdown）。
        let _wg = outbound::DialWatchdogGuard::new();
        s.set_read_timeout(Some(EXCHANGE_TIMEOUT)).ok();
        s.set_write_timeout(Some(EXCHANGE_TIMEOUT)).ok();
        write_tcp_dns(&mut s, query)?;
        read_tcp_dns(&mut s)
    }

    /// 取得（必要时新建）持久 TLS 连接；陈旧则重建。`want_h2=true` 时按 ALPN 结果
    /// 决定是否发 HTTP/2 前言（协商不到 h2 就留在 HTTP/1.1，不浪费一次失败连接）。
    fn persist_conn(&self, alpn: &[Vec<u8>], want_h2: bool) -> Result<(), String> {
        let mut g = self.persist.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = g.as_ref() {
            if p.born.elapsed() < PERSIST_IDLE {
                return Ok(());
            }
        }
        let tcp = outbound::marked_tcp_connect(self.addr, CONNECT_TIMEOUT)
            .map_err(|e| format!("连接上游失败: {e}"))?;
        // H2 修复：看门狗覆盖本次 TLS 握手，persist_conn 返回（连接入库）即解除——
        // 持久连接不再在 `CONNECT_TIMEOUT` 到点时被掐断（生产实测 3 s 生命周期）。
        let _wg = outbound::DialWatchdogGuard::new();
        let ((r, w), negotiated) = tls::connect_alpn(
            tcp,
            &self.tls_sni(),
            self.spec.insecure,
            alpn,
            CONNECT_TIMEOUT,
        )
        .map_err(|e| format!("TLS 握手失败: {e}"))?;
        let mut p = Persist {
            r,
            w,
            born: Instant::now(),
            h2: None,
        };
        if want_h2 && negotiated.as_deref() == Some(b"h2") {
            p.h2 = Some(crate::h2client::H2Conn::handshake(&mut p.r, &mut p.w)?);
        }
        *g = Some(p);
        Ok(())
    }

    fn exchange_tls(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        // 一次重连重试
        for attempt in 0..2 {
            self.persist_conn(&[], false)?;
            let r = self.exchange_tls_once(query);
            if r.is_ok() {
                return r;
            }
            if attempt == 0 {
                if let Ok(mut g) = self.persist.lock() {
                    *g = None; // 丢弃可能已损坏的连接后重试
                }
            } else {
                return r;
            }
        }
        unreachable!()
    }

    fn exchange_tls_once(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut g = self.persist.lock().unwrap_or_else(|e| e.into_inner());
        let p = g.as_mut().ok_or_else(|| "无持久连接".to_string())?;
        p.r.set_read_timeout(Some(EXCHANGE_TIMEOUT)).ok();
        p.w.write_all(&(query.len() as u16).to_be_bytes())
            .map_err(|e| e.to_string())?;
        p.w.write_all(query).map_err(|e| e.to_string())?;
        p.w.flush().map_err(|e| e.to_string())?;
        p.r.set_read_timeout(Some(EXCHANGE_TIMEOUT)).ok();
        read_tcp_dns(&mut p.r)
    }

    /// P23：DoH 优先 HTTP/2（RFC 8484 要求 h2/h3；按 TLS ALPN 协商结果决定），
    /// 握手/复用失败则丢连接重试（必要时永久回退 HTTP/1.1）。
    fn exchange_https(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        use std::sync::atomic::Ordering as AOrd;
        let mut last = String::new();
        for _attempt in 0..3 {
            let need_new = match self.persist.lock() {
                Ok(g) => g.is_none(),
                Err(p) => p.into_inner().is_none(),
            };
            if need_new {
                let try_h2 = !self.h2_broken.load(AOrd::Relaxed);
                let alpn: Vec<Vec<u8>> = if try_h2 {
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                } else {
                    vec![b"http/1.1".to_vec()]
                };
                match self.persist_conn(&alpn, try_h2) {
                    Ok(()) => {}
                    Err(e) if try_h2 => {
                        self.h2_broken.store(true, AOrd::Relaxed);
                        log(&format!("DoH h2 握手失败，回退 HTTP/1.1: {e}"));
                        if let Ok(mut g) = self.persist.lock() {
                            *g = None;
                        }
                        self.persist_conn(&[b"http/1.1".to_vec()], false)?;
                    }
                    Err(e) => return Err(e),
                }
            }
            match self.exchange_https_once(query) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last = e;
                    if let Ok(mut g) = self.persist.lock() {
                        *g = None; // 丢弃可能已损坏的连接后重试
                    }
                }
            }
        }
        Err(last)
    }

    fn exchange_https_once(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut g = self.persist.lock().unwrap_or_else(|e| e.into_inner());
        let p = g.as_mut().ok_or_else(|| "无持久连接".to_string())?;
        let authority = if self.spec.port == 443 {
            self.spec.host.clone()
        } else {
            format!("{}:{}", self.spec.host, self.spec.port)
        };
        p.r.set_read_timeout(Some(EXCHANGE_TIMEOUT)).ok();
        if let Some(h2) = p.h2.as_mut() {
            // 借用拆分：h2 不持有 r/w，分字段借用
            let Persist { r, w, .. } = p;
            return h2.post(r, w, &authority, &self.spec.path, query);
        }
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\n\
             Content-Type: application/dns-message\r\nContent-Length: {}\r\n\
             Connection: keep-alive\r\n\r\n",
            self.spec.path,
            authority,
            query.len()
        );
        p.r.set_read_timeout(Some(EXCHANGE_TIMEOUT)).ok();
        p.w.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
        p.w.write_all(query).map_err(|e| e.to_string())?;
        p.w.flush().map_err(|e| e.to_string())?;
        p.r.set_read_timeout(Some(EXCHANGE_TIMEOUT)).ok();
        read_http_dns(&mut p.r)
    }

    /// 取得（必要时新建/重建）DoQ 连接（RFC 9250；ALPN doq）。
    fn quic_conn(&self) -> Result<(), String> {
        let mut g = self.quic.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(q) = g.as_ref() {
            if q.born.elapsed() < QUIC_IDLE && q.conn.close_reason().is_none() {
                return Ok(());
            }
        }
        let rustls_cfg = tls::build_rustls_config(self.spec.insecure, &[b"doq".to_vec()]);
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| format!("DoQ TLS 配置: {e}"))?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(QUIC_IDLE).map_err(|e| format!("idle timeout: {e}"))?,
        ));
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(transport));
        let sock =
            outbound::new_marked_udp().map_err(|e| format!("DoQ 建 UDP socket 失败: {e}"))?;
        // Endpoint::new 必须在 tokio 运行时上下文中创建（quinn 需要 reactor）。
        let mut endpoint = crate::tuic::runtime().block_on(async {
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                sock,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| format!("DoQ endpoint: {e}"))
        })?;
        endpoint.set_default_client_config(client_cfg);
        let sni = self.tls_sni();
        let conn = crate::tuic::runtime().block_on(async {
            let connecting = endpoint
                .connect(self.addr, &sni)
                .map_err(|e| format!("DoQ connect: {e}"))?;
            match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
                Ok(Ok(c)) => Ok(c),
                Ok(Err(e)) => Err(format!("DoQ 握手失败: {e}")),
                Err(_) => Err("DoQ 连接超时".to_string()),
            }
        })?;
        *g = Some(QuicConn {
            conn,
            born: Instant::now(),
        });
        Ok(())
    }

    fn exchange_quic(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        // 一次重建重试（连接被打断/流被拒时换连接）
        for attempt in 0..2 {
            self.quic_conn()?;
            match self.exchange_quic_once(query) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    if attempt == 0 {
                        if let Ok(mut g) = self.quic.lock() {
                            *g = None;
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!()
    }

    fn exchange_quic_once(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        if query.len() < 12 || query.len() > 65535 {
            return Err("DoQ 查询长度非法".into());
        }
        let g = self.quic.lock().unwrap_or_else(|e| e.into_inner());
        let q = g.as_ref().ok_or_else(|| "无 DoQ 连接".to_string())?;
        let wire = zero_dns_id(query);
        let out = crate::tuic::runtime().block_on(async {
            let fut = async {
                let (mut send, mut recv) = q
                    .conn
                    .open_bi()
                    .await
                    .map_err(|e| format!("DoQ open_bi: {e}"))?;
                send.write_all(&(wire.len() as u16).to_be_bytes())
                    .await
                    .map_err(|e| format!("DoQ 写头: {e}"))?;
                send.write_all(&wire)
                    .await
                    .map_err(|e| format!("DoQ 写查询: {e}"))?;
                // FIN：DoQ 服务器在查询 FIN 后才应答（RFC 9250 §4.2）
                send.finish().map_err(|e| format!("DoQ FIN: {e}"))?;
                let mut lb = [0u8; 2];
                recv.read_exact(&mut lb)
                    .await
                    .map_err(|e| format!("DoQ 读长度: {e}"))?;
                let n = u16::from_be_bytes(lb) as usize;
                if n == 0 {
                    return Err("DoQ 响应长度非法: 0".to_string());
                }
                let mut buf = vec![0u8; n];
                recv.read_exact(&mut buf)
                    .await
                    .map_err(|e| format!("DoQ 读应答: {e}"))?;
                // 已消费完整应答：取消读半端释放流槽（RFC 9250 §4.3.1）
                let _ = recv.stop(quinn::VarInt::from_u32(DOQ_REQUEST_CANCELLED));
                Ok::<Vec<u8>, String>(buf)
            };
            match tokio::time::timeout(EXCHANGE_TIMEOUT, fut).await {
                Ok(r) => r,
                Err(_) => Err("DoQ 交换超时".to_string()),
            }
        })?;
        let mut resp = out;
        restore_dns_id(&mut resp, query);
        Ok(resp)
    }

    /// 取得（必要时新建/重建）DoH H3 连接（ALPN=h3）。
    fn h3_conn(&self) -> Result<(), String> {
        let mut g = self.h3.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = g.as_ref() {
            if h.born.elapsed() < QUIC_IDLE && h.h3.connection().close_reason().is_none() {
                return Ok(());
            }
        }
        let rustls_cfg = tls::build_rustls_config(self.spec.insecure, &[b"h3".to_vec()]);
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| format!("DoH h3 TLS 配置: {e}"))?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(QUIC_IDLE).map_err(|e| format!("idle timeout: {e}"))?,
        ));
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(transport));
        let sock =
            outbound::new_marked_udp().map_err(|e| format!("DoH h3 建 UDP socket 失败: {e}"))?;
        let mut endpoint = crate::tuic::runtime().block_on(async {
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                sock,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| format!("DoH h3 endpoint: {e}"))
        })?;
        endpoint.set_default_client_config(client_cfg);
        let sni = self.tls_sni();
        let conn = crate::tuic::runtime().block_on(async {
            let connecting = endpoint
                .connect(self.addr, &sni)
                .map_err(|e| format!("DoH h3 connect: {e}"))?;
            match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
                Ok(Ok(c)) => Ok(c),
                Ok(Err(e)) => Err(format!("DoH h3 握手失败: {e}")),
                Err(_) => Err("DoH h3 连接超时".to_string()),
            }
        })?;
        // H3Conn::new 自己会 block_on（不能在 block_on 内嵌套调用）
        let h3 = crate::h3client::H3Conn::new(conn, endpoint)
            .map_err(|e| format!("DoH h3 初始化: {e}"))?;
        *g = Some(H3DoH {
            h3,
            born: Instant::now(),
        });
        Ok(())
    }

    /// DoH over H3：一次重建重试（连接被打断/流被拒时换连接）。
    fn exchange_h3(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        for attempt in 0..2 {
            self.h3_conn()?;
            match self.exchange_h3_once(query) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    if attempt == 0 {
                        if let Ok(mut g) = self.h3.lock() {
                            *g = None;
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!()
    }

    fn exchange_h3_once(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let g = self.h3.lock().unwrap_or_else(|e| e.into_inner());
        let h = g.as_ref().ok_or_else(|| "无 DoH h3 连接".to_string())?;
        let authority = if self.spec.port == 443 {
            self.spec.host.clone()
        } else {
            format!("{}:{}", self.spec.host, self.spec.port)
        };
        let len = query.len().to_string();
        let (status, _fields, body) =
            h.h3.request(
                "POST",
                "https",
                &authority,
                &self.spec.path,
                &[
                    ("accept", "application/dns-message"),
                    ("content-type", "application/dns-message"),
                    ("content-length", len.as_str()),
                ],
                query,
                EXCHANGE_TIMEOUT,
            )
            .map_err(|e| format!("DoH h3 请求: {e}"))?;
        if status != 200 {
            return Err(format!("DoH h3 响应状态 {status}"));
        }
        Ok(body)
    }
}

fn write_tcp_dns<W: Write>(w: &mut W, query: &[u8]) -> Result<(), String> {
    w.write_all(&(query.len() as u16).to_be_bytes())
        .map_err(|e| e.to_string())?;
    w.write_all(query).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

/// DoQ 线上 DNS ID 必须为 0（RFC 9250 §4.2.1）。
fn zero_dns_id(query: &[u8]) -> Vec<u8> {
    let mut w = query.to_vec();
    if w.len() >= 2 {
        w[0] = 0;
        w[1] = 0;
    }
    w
}

/// 应答恢复客户端原始 ID（DoQ 应答在线上的 ID 为 0）。
fn restore_dns_id(resp: &mut [u8], query: &[u8]) {
    if resp.len() >= 2 && query.len() >= 2 {
        resp[0] = query[0];
        resp[1] = query[1];
    }
}

fn read_tcp_dns<R: Read>(r: &mut R) -> Result<Vec<u8>, String> {
    let mut lb = [0u8; 2];
    r.read_exact(&mut lb).map_err(|e| e.to_string())?;
    let n = u16::from_be_bytes(lb) as usize;
    if n == 0 || n > 65535 {
        return Err(format!("DNS TCP 响应长度非法: {n}"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// 读一个 HTTP/1.1 响应（仅 200 + 报文头解析；支持 Content-Length 与 chunked）。
fn read_http_dns<R: Read>(r: &mut R) -> Result<Vec<u8>, String> {
    let mut hdr = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while !hdr.ends_with(b"\r\n\r\n") {
        if hdr.len() > 8192 {
            return Err("HTTP 响应头过大".into());
        }
        let n = r.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("HTTP 响应头读取中断".into());
        }
        hdr.push(b[0]);
    }
    let text = String::from_utf8_lossy(&hdr).to_string();
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("HTTP 状态行非法: {status}"))?;
    if code != 200 {
        return Err(format!("DoH 响应状态 {code}"));
    }
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':').unwrap_or((l, ""));
        match k.to_ascii_lowercase().as_str() {
            "content-length" => content_length = v.trim().parse().ok(),
            "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => chunked = true,
            _ => {}
        }
    }
    if chunked {
        return read_chunked(r);
    }
    let n = content_length.ok_or_else(|| "DoH 响应缺少 Content-Length".to_string())?;
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok(body)
}

fn read_chunked<R: Read>(r: &mut R) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        // 行读取（长度行）
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = r.read(&mut b).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("chunked 响应中断".into());
            }
            if b[0] == b'\n' {
                break;
            }
            if b[0] != b'\r' {
                line.push(b[0]);
            }
            if line.len() > 64 {
                return Err("chunked 长度行过长".into());
            }
        }
        let s = String::from_utf8_lossy(&line);
        let sz = usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|e| format!("chunked 长度非法 {s:?}: {e}"))?;
        if sz == 0 {
            // 末尾 CRLF（吸收）
            let mut crlf = [0u8; 2];
            let _ = r.read_exact(&mut crlf);
            return Ok(out);
        }
        let mut buf = vec![0u8; sz];
        r.read_exact(&mut buf).map_err(|e| e.to_string())?;
        out.extend_from_slice(&buf);
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf).map_err(|e| e.to_string())?;
        if out.len() > 65535 {
            return Err("chunked 响应过大".into());
        }
    }
}

// ------------------------------------------------------------------
// 测试
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_schemes_and_defaults() {
        let s = parse("223.5.5.5").unwrap();
        assert_eq!(s.scheme, Scheme::TcpUdp);
        assert_eq!((s.host.as_str(), s.port), ("223.5.5.5", 53));
        let s = parse("udp://1.1.1.1").unwrap();
        assert_eq!(s.scheme, Scheme::Udp);
        assert_eq!(s.port, 53);
        let s = parse("tcp+udp://dns.example:5353").unwrap();
        assert_eq!(s.scheme, Scheme::TcpUdp);
        assert_eq!(s.port, 5353);
        let s = parse("tls://dns.google").unwrap();
        assert_eq!(s.scheme, Scheme::Tls);
        assert_eq!(s.port, 853);
        let s = parse("https://dns.alidns.com/dns-query").unwrap();
        assert_eq!(s.scheme, Scheme::Https);
        assert_eq!(s.port, 443);
        assert_eq!(s.path, "/dns-query");
        let s = parse("https://doh.pub").unwrap();
        assert_eq!(s.path, "/dns-query");
        let s = parse("quic://dns.adguard-dns.com:8853").unwrap();
        assert_eq!(s.scheme, Scheme::Quic);
        assert_eq!(s.port, 8853);
        // P26：h3://（DoH over HTTP/3）
        let s = parse("h3://dns.google").unwrap();
        assert_eq!(s.scheme, Scheme::H3);
        assert_eq!(s.port, 443);
        assert_eq!(s.path, "/dns-query");
        let s = parse("h3://dns.example:8443/custom?insecure=1").unwrap();
        assert_eq!(
            (s.host.as_str(), s.port, s.path.as_str()),
            ("dns.example", 8443, "/custom")
        );
        assert!(s.insecure);
        // sni / insecure
        let s = parse("tls://10.0.0.1:853?sni=dns.test&insecure=1").unwrap();
        assert_eq!(s.sni.as_deref(), Some("dns.test"));
        assert!(s.insecure);
        // ecs（sodama 扩展）
        let s = parse("https://223.5.5.5/dns-query?sni=dns.alidns.com&ecs=auto").unwrap();
        assert_eq!(s.ecs, Some(EcsMode::Auto));
        let s = parse("udp://127.0.0.1:53?ecs=192.0.2.0/24").unwrap();
        assert_eq!(
            s.ecs,
            Some(EcsMode::Prefix("192.0.2.0".parse().unwrap(), 24))
        );
        assert!(parse("udp://127.0.0.1:53?ecs=10.0.0.0/33").is_err());
        assert!(parse("udp://127.0.0.1:53?ecs=banana").is_err());
        // v6 字面量
        let s = parse("tls://[2001:db8::1]:853").unwrap();
        assert_eq!(s.host, "2001:db8::1");
        assert_eq!(s.port, 853);
        // 错误
        assert!(parse("ftp://x").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn https_path_with_port() {
        let s = parse("https://dns.example:8443/custom/path").unwrap();
        assert_eq!((s.host.as_str(), s.port), ("dns.example", 8443));
        assert_eq!(s.path, "/custom/path");
    }

    #[test]
    fn http_response_parsing() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\nABCD";
        let body = read_http_dns(&mut Cursor::new(resp)).unwrap();
        assert_eq!(body, b"ABCD");
        // chunked
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nAB\r\n2\r\nCD\r\n0\r\n\r\n";
        let body = read_http_dns(&mut Cursor::new(resp)).unwrap();
        assert_eq!(body, b"ABCD");
        // 非 200
        let resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        assert!(read_http_dns(&mut Cursor::new(resp)).is_err());
    }

    #[test]
    fn quic_id_zero_and_restore() {
        let query = b"\x12\x34abcdefghij";
        let wire = zero_dns_id(query);
        assert_eq!(&wire[..2], &[0, 0]);
        assert_eq!(&wire[2..], &query[2..]);
        let mut resp = wire.clone();
        restore_dns_id(&mut resp, query);
        assert_eq!(resp, query);
    }

    #[test]
    fn tcp_framing_and_flags() {
        let mut out = Vec::new();
        let msg = b"\x12\x34abcdefghij"; // 12 字节（dns_id 要求 ≥ 12）
        write_tcp_dns(&mut out, msg).unwrap();
        assert_eq!(&out[..2], &[0, 12]);
        let body = read_tcp_dns(&mut Cursor::new(out)).unwrap();
        assert_eq!(body, msg);
        assert_eq!(dns_id(msg), Some(0x1234));
        // TC 位
        assert!(truncated(b"\x00\x01\x82\x00"));
        assert!(!truncated(b"\x00\x01\x80\x00"));
    }
}

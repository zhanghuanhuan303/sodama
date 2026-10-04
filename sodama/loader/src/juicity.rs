// SPDX-License-Identifier: GPL-2.0
//! P27：juicity v0 客户端（QUIC + TUIC 式认证 + trojan 风格元数据）。
//!
//! 对照 olicesx/outbound `protocol/juicity/{client,stream_conn,stream_packet_conn}.go`
//! （e2e 服务端为独立实现，lab 夹具由其移植）：
//! ```text
//! 认证（客户端单向流，50B，保持打开）：[00][00][uuid16][token32]
//!   token = TLS.ExportKeyingMaterial(label = uuid 16 裸字节, context = password)[32]
//! TCP（每条连接一条双向流）：[01][TYPE ADDR PORT] 之后裸字节
//! UDP（每条 NAT 会话一条双向流）：[03][会话目标元数据]
//!   每帧：[目标元数据][len u16][payload]；回包：[来源元数据][len u16][payload]
//! 元数据（trojan 风格）：[TYPE]...(ipv4 4+2 / ipv6 16+2 / domain 1+len+2)
//! ```
//! ALPN 固定 `h3`；无 CONNECT 状态帧（目标不可达 = 流 reset）。
//!
//! 边界（如实）：不做 full-cone 的 underlay 认证记录（`IV||PSK` 加密包路径，仅服务
//! 端兼容性保留）、不做 0-RTT、不做拥塞控制参数（`congestion_control`/`cwnd` 忽略）。

use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;

use crate::target::Target;

pub const VER0: u8 = 0x00;
pub const CMD_AUTH: u8 = 0x00;
const NET_TCP: u8 = 0x01;
const NET_UDP: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_MSG: u8 = 0x02;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

fn rt() -> &'static Runtime {
    crate::tuic::runtime()
}

fn map_err<E: std::fmt::Display>(what: &'static str, e: E) -> io::Error {
    io::Error::new(ErrorKind::Other, format!("juicity: {what}: {e}"))
}

#[derive(Debug, Clone)]
pub struct JuicityConfig {
    pub server: SocketAddr,
    pub uuid: [u8; 16],
    pub password: String,
    pub sni: String,
    pub insecure: bool,
}

/// 一条连接 + 认证流（认证流在连接存续期间保持打开——juicity 语义）。
struct ConnState {
    conn: quinn::Connection,
    /// 认证单向流：不 FIN（后续 underlay 记录也走这条流；我们暂不发记录）。
    _auth: quinn::SendStream,
}

/// 复用一条 QUIC 连接（对照 Go 客户端：一个 dialer 一条连接，失效后下次拨号重建）。
pub struct JuicityDialer {
    cfg: JuicityConfig,
    endpoint: Mutex<Option<quinn::Endpoint>>,
    conn: Mutex<Option<ConnState>>,
}

impl std::fmt::Debug for JuicityDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JuicityDialer({})", self.cfg.server)
    }
}

impl JuicityDialer {
    pub fn new(cfg: JuicityConfig) -> Self {
        Self {
            cfg,
            endpoint: Mutex::new(None),
            conn: Mutex::new(None),
        }
    }

    pub fn name(&self) -> String {
        format!("juicity://{}", self.cfg.server)
    }

    #[cfg(test)]
    pub fn config(&self) -> &JuicityConfig {
        &self.cfg
    }

    fn ensure_conn(&self) -> io::Result<quinn::Connection> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| io::Error::other("juicity: 连接锁中毒"))?;
        if let Some(st) = guard.as_ref() {
            if st.conn.close_reason().is_none() {
                return Ok(st.conn.clone());
            }
        }
        let mut ep_guard = self
            .endpoint
            .lock()
            .map_err(|_| io::Error::other("juicity: endpoint 锁中毒"))?;
        let ep = match ep_guard.as_ref() {
            Some(ep) => ep.clone(),
            None => {
                let ep = self.build_endpoint()?;
                *ep_guard = Some(ep.clone());
                ep
            }
        };
        let st = self.connect_and_auth(&ep)?;
        let conn = st.conn.clone();
        *guard = Some(st);
        Ok(conn)
    }

    fn build_endpoint(&self) -> io::Result<quinn::Endpoint> {
        // 上游 socket 必须打 SO_MARK，否则会被 sodama 数据面二次捕获。
        let sock = crate::outbound::new_marked_udp()?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(3)));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(30))
                .map_err(|e| map_err("idle", e))?,
        ));
        transport.stream_receive_window(quinn::VarInt::from_u32(8 << 20));
        transport.receive_window(quinn::VarInt::from_u32(20 << 20));
        // juicity 生态惯例：ALPN=h3（与 TUIC 一致）。
        let rustls_cfg = crate::tls::build_rustls_config(self.cfg.insecure, &[b"h3".to_vec()]);
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| map_err("tls 配置", e))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(transport));
        let mut endpoint = rt().block_on(async {
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

    fn connect_and_auth(&self, endpoint: &quinn::Endpoint) -> io::Result<ConnState> {
        let cfg = &self.cfg;
        rt().block_on(async {
            let connecting = endpoint
                .connect(cfg.server, &cfg.sni)
                .map_err(|e| map_err("connect", e))?;
            let conn = tokio::time::timeout(Duration::from_secs(8), connecting)
                .await
                .map_err(|_| map_err("握手超时", "8s"))?
                .map_err(|e| map_err("握手", e))?;
            // 认证：[00][00][uuid16][token32]，写后**不 FIN**（保持打开）。
            let mut token = [0u8; 32];
            conn.export_keying_material(&mut token, &cfg.uuid, cfg.password.as_bytes())
                .map_err(|e| map_err("exporter", format!("{e:?}")))?;
            let mut uni = conn.open_uni().await.map_err(|e| map_err("open_uni", e))?;
            let mut head = Vec::with_capacity(50);
            head.push(VER0);
            head.push(CMD_AUTH);
            head.extend_from_slice(&cfg.uuid);
            head.extend_from_slice(&token);
            uni.write_all(&head)
                .await
                .map_err(|e| map_err("auth 写", e))?;
            Ok(ConnState { conn, _auth: uni })
        })
    }

    /// 每条 TCP relay 连接开一条 QUIC 双向流；首头 `[01][元数据]` 立即写入。
    pub fn connect_tcp(
        &self,
        target: &Target,
        timeout: Duration,
    ) -> io::Result<(JuicityReadHalf, JuicityWriteHalf)> {
        let conn = self.ensure_conn()?;
        let (mut send, recv) = rt().block_on(async {
            match tokio::time::timeout(timeout, conn.open_bi()).await {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => Err(map_err("open_bi", e)),
                Err(_) => Err(map_err("开流超时", "")),
            }
        })?;
        let mut head = Vec::with_capacity(24);
        head.push(NET_TCP);
        target
            .encode_socks_addr_port(&mut head)
            .map_err(|e| map_err("目标编码", e))?;
        rt().block_on(async {
            send.write_all(&head)
                .await
                .map_err(|e| map_err("首头写", e))
        })?;
        Ok((
            JuicityReadHalf { rt: rt(), recv },
            JuicityWriteHalf {
                rt: rt(),
                send: Mutex::new(send),
            },
        ))
    }

    /// 一个 UDP NAT 会话 = 一条双向流；流首 `[03][目标元数据]`，之后每帧
    /// `[目标元数据][len u16][payload]`（回包为来源元数据 + 同格式）。
    pub fn connect_udp(&self, target: SocketAddr) -> io::Result<JuicityUdp> {
        let conn = self.ensure_conn()?;
        let tx = Target::from_socket_addr(target).map_err(|e| map_err("目标编码", e))?;
        let mut meta = Vec::with_capacity(20);
        target_encode(&tx, &mut meta)?;
        let (mut send, recv) =
            rt().block_on(async { conn.open_bi().await.map_err(|e| map_err("open_bi", e)) })?;
        let mut prologue = Vec::with_capacity(meta.len() + 1);
        prologue.push(NET_UDP);
        prologue.extend_from_slice(&meta);
        rt().block_on(async {
            send.write_all(&prologue)
                .await
                .map_err(|e| map_err("会话头写", e))
        })?;
        Ok(JuicityUdp {
            rt: rt(),
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            meta,
            timeout: Mutex::new(Duration::from_secs(2)),
        })
    }
}

fn target_encode(target: &Target, out: &mut Vec<u8>) -> io::Result<()> {
    target
        .encode_socks_addr_port(out)
        .map_err(|e| map_err("目标编码", e))
}

/// TCP 读半。
pub struct JuicityReadHalf {
    rt: &'static Runtime,
    recv: quinn::RecvStream,
}

impl Read for JuicityReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rt.block_on(self.recv.read(buf)) {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(e) => Err(map_err("流读", e)),
        }
    }
}

/// TCP 写半（半关闭 = QUIC FIN）。
pub struct JuicityWriteHalf {
    rt: &'static Runtime,
    send: Mutex<quinn::SendStream>,
}

impl JuicityWriteHalf {
    pub fn shutdown_write(&self) -> io::Result<()> {
        let mut send = self.send.lock().unwrap_or_else(|e| e.into_inner());
        send.finish().map_err(|e| map_err("FIN", e))
    }
}

impl Write for JuicityWriteHalf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut send = self.send.lock().unwrap_or_else(|e| e.into_inner());
        self.rt
            .block_on(send.write_all(buf))
            .map_err(|e| map_err("流写", e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// UDP 会话（每会话一条双向流；帧式元数据 + 长度 + 载荷）。
pub struct JuicityUdp {
    rt: &'static Runtime,
    send: Mutex<quinn::SendStream>,
    recv: Mutex<quinn::RecvStream>,
    /// 目标元数据（本会话固定目标，编码一次复用）。
    meta: Vec<u8>,
    timeout: Mutex<Duration>,
}

/// 读并跳过一个元数据块（回包来源地址；我们不需要它的值）。
async fn skip_metadata(recv: &mut quinn::RecvStream) -> io::Result<()> {
    let mut typ = [0u8; 1];
    recv.read_exact(&mut typ)
        .await
        .map_err(|e| map_err("元数据读", e))?;
    let skip = match typ[0] {
        ATYP_IPV4 => 6,
        ATYP_IPV6 => 18,
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            recv.read_exact(&mut l)
                .await
                .map_err(|e| map_err("域名长度读", e))?;
            2 + l[0] as usize
        }
        ATYP_MSG => 1,
        other => return Err(map_err("元数据类型", format!("{other:#x}"))),
    };
    let mut buf = [0u8; 18];
    recv.read_exact(&mut buf[..skip])
        .await
        .map_err(|e| map_err("元数据跳过", e))?;
    Ok(())
}

impl JuicityUdp {
    pub fn set_read_timeout(&self, d: Option<Duration>) {
        let mut t = self.timeout.lock().unwrap_or_else(|e| e.into_inner());
        *t = d.unwrap_or(Duration::from_secs(2));
    }

    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let mut frame = Vec::with_capacity(self.meta.len() + 2 + data.len());
        frame.extend_from_slice(&self.meta);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        let mut send = self.send.lock().unwrap_or_else(|e| e.into_inner());
        self.rt
            .block_on(send.write_all(&frame))
            .map_err(|e| map_err("UDP 帧写", e))?;
        Ok(data.len())
    }

    /// 阻塞收一帧（超时返回 TimedOut，供会话存活检查）。
    pub fn recv(&self) -> io::Result<Vec<u8>> {
        let timeout = *self.timeout.lock().unwrap_or_else(|e| e.into_inner());
        let mut recv = self.recv.lock().unwrap_or_else(|e| e.into_inner());
        let rt = self.rt;
        let fut = async {
            skip_metadata(&mut recv).await?;
            let mut lb = [0u8; 2];
            recv.read_exact(&mut lb)
                .await
                .map_err(|e| map_err("长度读", e))?;
            let n = u16::from_be_bytes(lb) as usize;
            let mut buf = vec![0u8; n];
            recv.read_exact(&mut buf)
                .await
                .map_err(|e| map_err("载荷读", e))?;
            Ok::<Vec<u8>, io::Error>(buf)
        };
        match rt.block_on(async { tokio::time::timeout(timeout, fut).await }) {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(ErrorKind::TimedOut, "juicity: UDP 空闲")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_layout_matches_trojan_convention() {
        // IPv4
        let t = Target::from_socket_addr("1.2.3.4:443".parse().unwrap()).unwrap();
        let mut b = Vec::new();
        target_encode(&t, &mut b).unwrap();
        assert_eq!(b, [0x01, 1, 2, 3, 4, 0x01, 0xBB]);
        // domain
        let t = Target::Domain("example.com".into(), 8443);
        let mut b = Vec::new();
        target_encode(&t, &mut b).unwrap();
        assert_eq!(&b[..2], &[0x03, 11]);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(&b[13..15], &8443u16.to_be_bytes());
    }

    #[test]
    fn auth_head_layout() {
        // [00][00][uuid16][token32] = 50B（与 Go 客户端一致）
        let mut head = Vec::new();
        head.push(VER0);
        head.push(CMD_AUTH);
        head.extend_from_slice(&[0xAB; 16]);
        head.extend_from_slice(&[0xCD; 32]);
        assert_eq!(head.len(), 50);
        assert_eq!((head[0], head[1]), (0, 0));
    }
}

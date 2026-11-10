// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors
//! P31：shadow-tls 客户端（v1/v2/v3）——sing-shadowtls 线格式的 Rust 实现（ADR-0055）。
//!
//! - **v1**：TLS（≤1.2）伪装握手后裸 TCP 隧道（无认证、无帧；参考实现同样锁 TLS 1.2）。
//! - **v2**：TLS 1.3 伪装握手；客户端把「服务端握手字节的 HMAC-SHA1(password) 前 8B」
//!   前置在首个应用数据里，之后按 TLS record（0x17）分帧。
//! - **v3**：ClientHello session_id = 28 随机 + 4B HMAC-SHA1(password, CH 零位)[:4]；
//!   握手后读方向先按 relay 方案校验（`HMAC(pw, serverRandom||payload)`，命中即跳过——
//!   那是伪装站握手期的票据类记录），随后切换 HMAC 链（`"S"` 后缀、MAC 反馈、不 XOR）；
//!   写方向从首个载荷起即 HMAC 链（`"C"`）：每帧 `[0x17 03 03 len][mac4][payload]`。
//!
//! 证书：默认 WebPKI 严格校验（链 + 主机名 + CV 验签，`CertPolicy::WebPki`）；
//! `allow_insecure=1` 跳过。v2/v3 只接受 TLS 1.3 伪装站（自实现栈），v1 走 rustls
//! TLS 1.2（与 olicesx/outbound 的 Go 客户端行为一致）。

use std::io::{self, Read, Write};
use std::net::TcpStream;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::tls13::{self, CertPolicy, ClientHelloSpec, ClientKx};

const TLS_APP_DATA: u8 = 23;
const TLS_ALERT: u8 = 21;
const MAX_FRAME: usize = 16384;
const HS_SERVER_HELLO: u8 = 2;
/// session_id 在 ClientHello（含 4B 握手头）内的偏移与其长度。
const SESSION_ID_OFF: usize = 39;
const SESSION_ID_LEN: usize = 32;

type HmacSha1 = Hmac<Sha1>;

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("shadow-tls: {}", m.into()),
    )
}

/// shadow-tls 插件配置（来自 `ss://...?plugin=shadow-tls;...`）。
#[derive(Debug, Clone)]
pub struct ShadowTlsConfig {
    pub version: u8,
    pub password: String,
    pub sni: String,
    pub allow_insecure: bool,
}

impl ShadowTlsConfig {
    pub fn new(
        version: u8,
        password: String,
        sni: String,
        allow_insecure: bool,
    ) -> Result<Self, String> {
        if !(1..=3).contains(&version) {
            return Err(format!("版本 {version} 不支持（1/2/3）"));
        }
        if version >= 2 && password.is_empty() {
            return Err("v2/v3 需要 password".into());
        }
        if sni.is_empty() {
            return Err("需要 host/sni".into());
        }
        Ok(Self {
            version,
            password,
            sni,
            allow_insecure,
        })
    }
}

fn hmac_sha1(key: &[u8]) -> io::Result<HmacSha1> {
    HmacSha1::new_from_slice(key).map_err(|e| bad(e.to_string()))
}

/// 拨号并完成 shadow-tls 握手，返回帧层读写两半。
pub fn connect(
    sock: TcpStream,
    cfg: &ShadowTlsConfig,
) -> io::Result<(ShadowTlsReader, ShadowTlsWriter)> {
    match cfg.version {
        1 => connect_v1(sock, cfg),
        2 => connect_v2(sock, cfg),
        3 => connect_v3(sock, cfg),
        v => Err(bad(format!("版本 {v} 不支持"))),
    }
}

fn policy_of(cfg: &ShadowTlsConfig) -> CertPolicy<'static> {
    if cfg.allow_insecure {
        CertPolicy::Insecure
    } else {
        CertPolicy::WebPki {
            sni: cfg.sni.clone(),
        }
    }
}

/// 构造（v3 时植入 session_id HMAC 的）ClientHello。
fn make_hello(cfg: &ShadowTlsConfig, v3: bool, kx: &ClientKx) -> Vec<u8> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    if v3 {
        session_id[SESSION_ID_LEN - 4..].fill(0);
    }
    let mut ch = tls13::build_client_hello(
        &ClientHelloSpec {
            server_name: cfg.sni.clone(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            session_id,
            random,
            hybrid: true,
        },
        kx,
    );
    if v3 {
        // HMAC 覆盖「最后 4 字节为零」的完整 CH，再回填末 4 字节。
        let mut mac = hmac_sha1(cfg.password.as_bytes()).expect("hmac key");
        mac.update(&ch);
        let tag = mac.finalize().into_bytes();
        ch[SESSION_ID_OFF + SESSION_ID_LEN - 4..SESSION_ID_OFF + SESSION_ID_LEN]
            .copy_from_slice(&tag[..4]);
    }
    ch
}

/// 从握手 transcript 提取 ServerHello 的 server random。
fn extract_server_random(transcript: &[u8], ch_len: usize) -> io::Result<[u8; 32]> {
    let off = ch_len;
    if transcript.len() < off + 4 + 34 || transcript[off] != HS_SERVER_HELLO {
        return Err(bad("transcript 中缺少 ServerHello"));
    }
    let body = &transcript[off + 4..];
    let mut out = [0u8; 32];
    out.copy_from_slice(&body[2..34]);
    Ok(out)
}

// ---------------------------------------------------------------- v1（rustls TLS 1.2）

fn connect_v1(
    sock: TcpStream,
    cfg: &ShadowTlsConfig,
) -> io::Result<(ShadowTlsReader, ShadowTlsWriter)> {
    let mut hs_sock = sock.try_clone()?;
    tls12_handshake(&mut hs_sock, cfg)?;
    Ok((ShadowTlsReader::raw(sock), ShadowTlsWriter::raw(hs_sock)))
}

fn tls12_handshake(sock: &mut TcpStream, cfg: &ShadowTlsConfig) -> io::Result<()> {
    let config = crate::tls::build_rustls_config_tls12(cfg.allow_insecure, &[]);
    let name = rustls::pki_types::ServerName::try_from(cfg.sni.clone())
        .map_err(|e| bad(format!("SNI 非法（{}）: {e}", cfg.sni)))?;
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
        .map_err(|e| bad(e.to_string()))?;
    loop {
        while conn.wants_write() {
            conn.write_tls(sock)?;
        }
        if !conn.is_handshaking() {
            break;
        }
        if conn.read_tls(sock)? == 0 {
            return Err(bad("v1 握手期连接关闭"));
        }
        conn.process_new_packets()
            .map_err(|e| bad(format!("v1 握手失败: {e}")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------- v2（TLS 1.3 + 首帧 HMAC）

/// 包装 socket：读取时把所有服务端字节喂给 HMAC（对应参考实现 hashReadConn）。
struct HashIo<'a> {
    sock: &'a mut TcpStream,
    mac: HmacSha1,
}

impl Read for HashIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.sock.read(buf)?;
        if n > 0 {
            self.mac.update(&buf[..n]);
        }
        Ok(n)
    }
}

impl Write for HashIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

fn connect_v2(
    sock: TcpStream,
    cfg: &ShadowTlsConfig,
) -> io::Result<(ShadowTlsReader, ShadowTlsWriter)> {
    let mut hs_sock = sock.try_clone()?;
    let kx = ClientKx::generate(true);
    let ch = make_hello(cfg, false, &kx);
    let mut io = HashIo {
        sock: &mut hs_sock,
        mac: hmac_sha1(cfg.password.as_bytes())?,
    };
    let hs = tls13::client_handshake(&mut io, &ch, &kx, policy_of(cfg))?;
    let sum8 = io.mac.clone().finalize().into_bytes()[..8].to_vec();
    Ok((
        ShadowTlsReader::framed(sock, hs.pending, ReadMode::V2 { keys: hs.read }),
        ShadowTlsWriter {
            sock: hs_sock,
            mode: WriteMode::V2 { first: true, sum8 },
        },
    ))
}

// ---------------------------------------------------------------- v3（session_id + MAC 链）

fn connect_v3(
    sock: TcpStream,
    cfg: &ShadowTlsConfig,
) -> io::Result<(ShadowTlsReader, ShadowTlsWriter)> {
    let mut hs_sock = sock.try_clone()?;
    let kx = ClientKx::generate(true);
    let ch = make_hello(cfg, true, &kx);
    // 握手期服务端的加密飞行会被服务端改写为 [mac4][xor(payload)] 帧，
    // 需要经 V3HandshakeIo 校验/解密/重帧后再交给 TLS 栈（对应参考实现 streamWrapper）。
    let (hs, relay_state, sr_adapter) = {
        let mut io = V3HandshakeIo::new(&mut hs_sock, &cfg.password);
        let hs = tls13::client_handshake(&mut io, &ch, &kx, policy_of(cfg))?;
        (hs, io.relay.take(), io.sr)
    };
    let server_random = extract_server_random(&hs.transcript, ch.len())?;
    if let Some(sr) = sr_adapter {
        if sr != server_random {
            return Err(bad("适配器与 transcript 的 serverRandom 不一致"));
        }
    }
    let relay = relay_state.ok_or_else(|| bad("握手期未捕获 ServerHello"))?;
    let pw = cfg.password.as_bytes();
    let mut chain = hmac_sha1(pw)?;
    chain.update(&server_random);
    chain.update(b"S");
    let mut wmac = hmac_sha1(pw)?;
    wmac.update(&server_random);
    wmac.update(b"C");
    Ok((
        // v3：握手读提前量是已重帧的 TLS 内部记录（如 tickets），对帧层无意义，丢弃。
        ShadowTlsReader::framed(
            sock,
            Vec::new(),
            ReadMode::V3(V3Read {
                relay: Some(relay),
                chain,
            }),
        ),
        ShadowTlsWriter {
            sock: hs_sock,
            mode: WriteMode::V3 { mac: wmac },
        },
    ))
}

/// v3 握手期 I/O 适配器：透传 handshake/CCS/alert；对 application-data 记录执行
/// relay 方案校验（`HMAC(pw, serverRandom||wire)`）→ XOR（`SHA256(pw||serverRandom)`）
/// → 按明文长度重帧后交给 TLS 栈；同时捕获 ServerHello 的 serverRandom。
struct V3HandshakeIo<'a> {
    sock: &'a mut TcpStream,
    pw: Vec<u8>,
    sr: Option<[u8; 32]>,
    relay: Option<HmacSha1>,
    read_key: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
}

impl<'a> V3HandshakeIo<'a> {
    fn new(sock: &'a mut TcpStream, password: &str) -> Self {
        Self {
            sock,
            pw: password.as_bytes().to_vec(),
            sr: None,
            relay: None,
            read_key: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        let mut hdr = [0u8; 5];
        self.sock.read_exact(&mut hdr)?;
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; len];
        self.sock.read_exact(&mut body)?;
        match hdr[0] {
            TLS_APP_DATA => {
                if body.len() < 4 {
                    return Err(bad("握手期应用记录过短"));
                }
                let (mac, wire) = body.split_at(4);
                let relay = self
                    .relay
                    .as_mut()
                    .ok_or_else(|| bad("握手期应用记录早于 ServerHello"))?;
                let mut trial = relay.clone();
                trial.update(wire);
                if trial.clone().verify_truncated_left(mac).is_err() {
                    return Err(bad("握手期服务端记录校验失败（口令错误？）"));
                }
                relay.update(wire);
                let plain: Vec<u8> = wire
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ self.read_key[i % self.read_key.len()])
                    .collect();
                let l = plain.len();
                self.out = Vec::with_capacity(5 + l);
                self.out
                    .extend_from_slice(&[TLS_APP_DATA, 3, 3, (l >> 8) as u8, l as u8]);
                self.out.extend_from_slice(&plain);
                self.out_pos = 0;
            }
            _ => {
                if hdr[0] == 0x16 {
                    self.capture_server_hello(&body)?;
                }
                self.out = Vec::with_capacity(5 + body.len());
                self.out.extend_from_slice(&hdr);
                self.out.extend_from_slice(&body);
                self.out_pos = 0;
            }
        }
        Ok(())
    }

    fn capture_server_hello(&mut self, body: &[u8]) -> io::Result<()> {
        if self.sr.is_some() || body.len() < 4 {
            return Ok(());
        }
        if body[0] != HS_SERVER_HELLO {
            return Ok(());
        }
        if body.len() < 4 + 34 {
            return Err(bad("ServerHello 过短"));
        }
        let mut sr = [0u8; 32];
        sr.copy_from_slice(&body[6..38]);
        let mut relay = hmac_sha1(&self.pw)?;
        relay.update(&sr);
        self.relay = Some(relay);
        self.read_key = Sha256::digest([self.pw.as_slice(), sr.as_slice()].concat()).to_vec();
        self.sr = Some(sr);
        Ok(())
    }
}

impl Read for V3HandshakeIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.out_pos >= self.out.len() {
            self.fill()?;
        }
        let n = buf.len().min(self.out.len() - self.out_pos);
        buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        Ok(n)
    }
}

impl Write for V3HandshakeIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

// ---------------------------------------------------------------- 读半

enum ReadMode {
    Raw,
    V2 { keys: tls13::RecordKeys },
    V3(V3Read),
}

struct V3Read {
    /// relay 阶段验证器（`HMAC(pw, serverRandom)`，无 MAC 反馈）；命中即跳过该帧。
    relay: Option<HmacSha1>,
    /// 链阶段验证器（`HMAC(pw, serverRandom||"S")`，每帧吸收 payload + mac4）。
    chain: HmacSha1,
}

pub struct ShadowTlsReader {
    sock: TcpStream,
    /// 握手读提前量（原始字节）。
    pending: Vec<u8>,
    pending_pos: usize,
    /// 当前交付中的帧载荷。
    payload: Vec<u8>,
    payload_pos: usize,
    mode: ReadMode,
}

impl ShadowTlsReader {
    fn raw(sock: TcpStream) -> Self {
        Self {
            sock,
            pending: Vec::new(),
            pending_pos: 0,
            payload: Vec::new(),
            payload_pos: 0,
            mode: ReadMode::Raw,
        }
    }

    fn framed(sock: TcpStream, pending: Vec<u8>, mode: ReadMode) -> Self {
        Self {
            sock,
            pending,
            pending_pos: 0,
            payload: Vec::new(),
            payload_pos: 0,
            mode,
        }
    }

    /// 从 pending + socket 精确读满。
    fn take_exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        let mut off = 0;
        while off < out.len() {
            if self.pending_pos < self.pending.len() {
                let n = (out.len() - off).min(self.pending.len() - self.pending_pos);
                out[off..off + n]
                    .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                off += n;
                if self.pending_pos >= self.pending.len() {
                    self.pending.clear();
                    self.pending_pos = 0;
                }
            } else {
                let n = self.sock.read(&mut out[off..])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "shadow-tls: 连接关闭",
                    ));
                }
                off += n;
            }
        }
        Ok(())
    }

    /// 读下一个应用数据帧；`None` = 对端 alert/关闭；v3 的 relay 帧（握手期票据）内部跳过。
    fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let mut hdr = [0u8; 5];
            self.take_exact(&mut hdr)?;
            // 长度字段是 u16，天然 ≤ 65535，无需额外上限。
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut body = vec![0u8; len];
            self.take_exact(&mut body)?;
            match hdr[0] {
                TLS_APP_DATA => {}
                // 参考实现在读到 EOF 时会向对端发一个随机 alert；对帧层即「对端关闭」。
                TLS_ALERT => return Ok(None),
                t => return Err(bad(format!("非预期记录类型 {t}"))),
            }
            match &mut self.mode {
                ReadMode::V2 { keys } => {
                    // 伪装站握手后的真实 TLS 记录（NewSessionTicket 等）用应用读密钥
                    // 识别并跳过：参考实现靠 TLS 栈读提前量侥幸规避；显式处理更稳。
                    // 隧道帧不是合法 TLS 密文（AEAD 失败），原样交付。
                    if keys.open(&hdr, &body).is_ok() {
                        continue;
                    }
                    return Ok(Some(body));
                }
                ReadMode::V3(v3) => {
                    if body.len() < 4 {
                        return Err(bad("v3 帧过短"));
                    }
                    let (mac, data) = body.split_at(4);
                    if let Some(relay) = &mut v3.relay {
                        let mut trial = relay.clone();
                        trial.update(data);
                        if trial.clone().verify_truncated_left(mac).is_ok() {
                            relay.update(data);
                            continue; // relay 帧不交付内层（Go verifiedConn 行为）
                        }
                        v3.relay = None;
                    }
                    let mut trial = v3.chain.clone();
                    trial.update(data);
                    if trial.clone().verify_truncated_left(mac).is_err() {
                        return Err(bad("v3 帧校验失败（口令错误或流量被劫持？）"));
                    }
                    v3.chain.update(data);
                    v3.chain.update(mac);
                    return Ok(Some(data.to_vec()));
                }
                ReadMode::Raw => unreachable!("raw 不走帧路径"),
            }
        }
    }
}

impl Read for ShadowTlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.payload_pos < self.payload.len() {
            let n = buf.len().min(self.payload.len() - self.payload_pos);
            buf[..n].copy_from_slice(&self.payload[self.payload_pos..self.payload_pos + n]);
            self.payload_pos += n;
            return Ok(n);
        }
        if matches!(self.mode, ReadMode::Raw) {
            if self.pending_pos < self.pending.len() {
                let n = buf.len().min(self.pending.len() - self.pending_pos);
                buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                return Ok(n);
            }
            self.pending.clear();
            self.pending_pos = 0;
            return self.sock.read(buf);
        }
        loop {
            let Some(frame) = self.next_frame()? else {
                return Ok(0);
            };
            self.payload = frame;
            self.payload_pos = 0;
            if !self.payload.is_empty() {
                let n = buf.len().min(self.payload.len());
                buf[..n].copy_from_slice(&self.payload[..n]);
                self.payload_pos = n;
                return Ok(n);
            }
        }
    }
}

// ---------------------------------------------------------------- 写半

enum WriteMode {
    Raw,
    V2 { first: bool, sum8: Vec<u8> },
    V3 { mac: HmacSha1 },
}

pub struct ShadowTlsWriter {
    sock: TcpStream,
    mode: WriteMode,
}

impl ShadowTlsWriter {
    fn raw(sock: TcpStream) -> Self {
        Self {
            sock,
            mode: WriteMode::Raw,
        }
    }
}

fn write_frames(sock: &mut TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = data.len().min(MAX_FRAME);
        let hdr = [TLS_APP_DATA, 3, 3, (n >> 8) as u8, n as u8];
        sock.write_all(&hdr)?;
        sock.write_all(&data[..n])?;
        data = &data[n..];
    }
    Ok(())
}

impl Write for ShadowTlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match &mut self.mode {
            WriteMode::Raw => self.sock.write(buf),
            WriteMode::V2 { first, sum8 } => {
                if *first {
                    *first = false;
                    let mut out = Vec::with_capacity(sum8.len() + buf.len());
                    out.extend_from_slice(sum8);
                    out.extend_from_slice(buf);
                    write_frames(&mut self.sock, &out)?;
                } else {
                    write_frames(&mut self.sock, buf)?;
                }
                Ok(buf.len())
            }
            WriteMode::V3 { mac } => {
                for chunk in buf.chunks(MAX_FRAME) {
                    mac.update(chunk);
                    let tag = mac.clone().finalize().into_bytes();
                    mac.update(&tag[..4]);
                    let l = 4 + chunk.len();
                    let hdr = [TLS_APP_DATA, 3, 3, (l >> 8) as u8, l as u8];
                    self.sock.write_all(&hdr)?;
                    self.sock.write_all(&tag[..4])?;
                    self.sock.write_all(chunk)?;
                }
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

impl ShadowTlsWriter {
    /// P38：当前无调用方（保留为对称 API：与 ShadowTlsReader/其他写半接口对齐）。
    #[allow(dead_code)]
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.sock.shutdown(std::net::Shutdown::Write)
    }
}

// ---------------------------------------------------------------- 单元测试

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(version: u8) -> ShadowTlsConfig {
        ShadowTlsConfig::new(version, "testpass".into(), "localhost".into(), true).unwrap()
    }

    fn pair() -> (TcpStream, TcpStream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = TcpStream::connect(addr).unwrap();
        let (s, _) = l.accept().unwrap();
        (c, s)
    }

    #[test]
    fn config_validation() {
        assert!(ShadowTlsConfig::new(4, "x".into(), "a".into(), true).is_err());
        assert!(ShadowTlsConfig::new(3, String::new(), "a".into(), true).is_err());
        assert!(ShadowTlsConfig::new(2, String::new(), "a".into(), true).is_err());
        assert!(ShadowTlsConfig::new(1, String::new(), "a".into(), true).is_ok());
        assert!(ShadowTlsConfig::new(1, String::new(), String::new(), true).is_err());
    }

    #[test]
    fn v3_session_id_mac_uses_zeroed_tail() {
        let kx = ClientKx::generate(true);
        let ch = make_hello(&test_cfg(3), true, &kx);
        let mut zeroed = ch.clone();
        zeroed[SESSION_ID_OFF + SESSION_ID_LEN - 4..SESSION_ID_OFF + SESSION_ID_LEN].fill(0);
        let mut mac = hmac_sha1(b"testpass").unwrap();
        mac.update(&zeroed);
        let tag = mac.finalize().into_bytes();
        assert_eq!(
            &ch[SESSION_ID_OFF + SESSION_ID_LEN - 4..SESSION_ID_OFF + SESSION_ID_LEN],
            &tag[..4]
        );
    }

    #[test]
    fn extract_server_random_ok_and_short() {
        let ch = vec![1u8; 128];
        let mut tr = ch.clone();
        let mut sh = vec![HS_SERVER_HELLO, 0, 0, 34, 0x03, 0x03];
        sh.extend_from_slice(&[0x77u8; 32]);
        tr.extend_from_slice(&sh);
        assert_eq!(extract_server_random(&tr, ch.len()).unwrap(), [0x77u8; 32]);
        assert!(extract_server_random(&ch, ch.len()).is_err());
    }

    #[test]
    fn v2_first_write_prefixes_hmac() {
        let (client, mut server) = pair();
        let mut h = hmac_sha1(b"testpass").unwrap();
        h.update(b"fake-server-flight");
        let sum8 = h.clone().finalize().into_bytes()[..8].to_vec();
        let mut w = ShadowTlsWriter {
            sock: client.try_clone().unwrap(),
            mode: WriteMode::V2 {
                first: true,
                sum8: sum8.clone(),
            },
        };
        w.write_all(b"hello").unwrap();
        // 第二写不再带前缀
        w.write_all(b"world").unwrap();
        let mut hdr = [0u8; 5];
        server.read_exact(&mut hdr).unwrap();
        assert_eq!(hdr[0], TLS_APP_DATA);
        let l = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; l];
        server.read_exact(&mut body).unwrap();
        assert_eq!(&body[..8], &sum8[..]);
        assert_eq!(&body[8..], b"hello");
        server.read_exact(&mut hdr).unwrap();
        let l = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; l];
        server.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"world");
    }

    #[test]
    fn v3_write_chain_verifiable_by_server_state() {
        let (client, mut server) = pair();
        let sr = [0x5au8; 32];
        let mut cw = hmac_sha1(b"testpass").unwrap();
        cw.update(&sr);
        cw.update(b"C");
        let mut w = ShadowTlsWriter {
            sock: client.try_clone().unwrap(),
            mode: WriteMode::V3 { mac: cw },
        };
        w.write_all(b"payload-1").unwrap();
        w.write_all(b"payload-2").unwrap();

        let mut verify = hmac_sha1(b"testpass").unwrap();
        verify.update(&sr);
        verify.update(b"C");
        for expect in [&b"payload-1"[..], &b"payload-2"[..]] {
            let mut hdr = [0u8; 5];
            server.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], TLS_APP_DATA);
            let l = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut body = vec![0u8; l];
            server.read_exact(&mut body).unwrap();
            let (mac, data) = body.split_at(4);
            let mut trial = verify.clone();
            trial.update(data);
            trial
                .clone()
                .verify_truncated_left(mac)
                .expect("server MAC 校验");
            verify.update(data);
            verify.update(mac);
            assert_eq!(data, expect);
        }
    }

    #[test]
    fn v3_handshake_io_unwraps_and_reframes() {
        let (client_sock, mut server_sock) = pair();
        let pw = "testpass";
        let sr = [0x42u8; 32];
        // 1) ServerHello 握手记录
        let mut sh = vec![HS_SERVER_HELLO, 0, 0, 34, 0x03, 0x03];
        sh.extend_from_slice(&sr);
        server_sock
            .write_all(&[0x16, 3, 3, 0, sh.len() as u8])
            .unwrap();
        server_sock.write_all(&sh).unwrap();
        // 2) 两条被服务端改写的应用记录 [mac4][xor(payload)]
        let read_key = Sha256::digest([pw.as_bytes(), sr.as_slice()].concat()).to_vec();
        let mut relay = hmac_sha1(pw.as_bytes()).unwrap();
        relay.update(&sr);
        let send_app = |server: &mut TcpStream, relay: &mut HmacSha1, plain: &[u8]| {
            let wire: Vec<u8> = plain
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ read_key[i % read_key.len()])
                .collect();
            relay.update(&wire);
            let mac = relay.clone().finalize().into_bytes();
            let l = 4 + wire.len();
            server
                .write_all(&[TLS_APP_DATA, 3, 3, (l >> 8) as u8, l as u8])
                .unwrap();
            server.write_all(&mac[..4]).unwrap();
            server.write_all(&wire).unwrap();
        };
        send_app(&mut server_sock, &mut relay, b"plain-1");
        send_app(&mut server_sock, &mut relay, b"plain-2");

        let mut c = client_sock.try_clone().unwrap();
        let mut io = V3HandshakeIo::new(&mut c, pw);
        let mut buf = vec![0u8; 128];
        let n = io.read(&mut buf).unwrap();
        assert_eq!(&buf[..5], &[0x16, 3, 3, 0, sh.len() as u8]);
        assert_eq!(&buf[5..n], &sh[..]);
        let n = io.read(&mut buf).unwrap();
        assert_eq!(&buf[..5], &[TLS_APP_DATA, 3, 3, 0, 7]);
        assert_eq!(&buf[5..n], b"plain-1");
        let n = io.read(&mut buf).unwrap();
        assert_eq!(&buf[5..n], b"plain-2");
        assert_eq!(io.sr, Some(sr));
    }

    #[test]
    fn v3_read_skips_relay_and_delivers_chain() {
        let (client_sock, mut server_sock) = pair();
        let sr = [0x33u8; 32];
        let mut relay = hmac_sha1(b"testpass").unwrap();
        relay.update(&sr);
        let mut chain = hmac_sha1(b"testpass").unwrap();
        chain.update(&sr);
        chain.update(b"S");
        let mut r = ShadowTlsReader::framed(
            client_sock.try_clone().unwrap(),
            Vec::new(),
            ReadMode::V3(V3Read {
                relay: Some(relay),
                chain,
            }),
        );
        // 服务端先发 relay 帧（ticket 类）：HMAC(pw, serverRandom||wire)
        let wire_ticket = b"ticket-wire-bytes";
        let mut rm = hmac_sha1(b"testpass").unwrap();
        rm.update(&sr);
        rm.update(wire_ticket);
        let rtag = rm.clone().finalize().into_bytes();
        let l = 4 + wire_ticket.len();
        server_sock
            .write_all(&[TLS_APP_DATA, 3, 3, (l >> 8) as u8, l as u8])
            .unwrap();
        server_sock.write_all(&rtag[..4]).unwrap();
        server_sock.write_all(wire_ticket).unwrap();
        // 再发链帧：HMAC(pw, serverRandom||"S"||payload)，吸收 mac
        let payload = b"real-data";
        let mut cm = hmac_sha1(b"testpass").unwrap();
        cm.update(&sr);
        cm.update(b"S");
        cm.update(payload);
        let ctag = cm.clone().finalize().into_bytes();
        let l = 4 + payload.len();
        server_sock
            .write_all(&[TLS_APP_DATA, 3, 3, (l >> 8) as u8, l as u8])
            .unwrap();
        server_sock.write_all(&ctag[..4]).unwrap();
        server_sock.write_all(payload).unwrap();

        let mut out = [0u8; 32];
        let n = r.read(&mut out).unwrap();
        assert_eq!(&out[..n], payload);
    }
}

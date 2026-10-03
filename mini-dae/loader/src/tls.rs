// SPDX-License-Identifier: GPL-2.0
//! P5-G2：可复用的 rustls 客户端（trojan / vless / vmess 共用）。
//!
//! 拆分后的读写两半共享同一个 `ClientConnection`（短锁），底层 TCP 各持一个 fd
//! 副本；阻塞读放在锁外，避免读方向饿死写方向。
//!
//! 读路径不变量：任意两次 `read_tls` 之间必须先抽干 `reader()` 明文。
//! rustls 的明文缓冲默认只有 16KB（`DEFAULT_RECEIVED_PLAINTEXT_LIMIT`），而一次
//! `sock.read` 可能带进 16KB 密文、deframer 每轮只吃 4KB——若连续喂而不抽，
//! process_new_packets 会因明文满而停摆，随后 read_tls 直接报错（实测 512KB
//! 必现拆连接）。因此未喂完的密文存 pending，一次喂一块后回到循环顶部抽明文。

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

pub struct TlsReader {
    conn: Arc<Mutex<ClientConnection>>,
    sock: TcpStream,
    eof: bool,
    /// 已从 socket 读出、尚未喂给 rustls 的 TLS 密文。
    pending: Vec<u8>,
}

pub struct TlsWriter {
    conn: Arc<Mutex<ClientConnection>>,
    sock: TcpStream,
}

impl TlsWriter {
    /// TLS 无半关闭语义（不发 close_notify，直接 FIN 即可）。
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.sock.shutdown(Shutdown::Write)
    }
}

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // 1) 先抽干已解密明文（有就立刻返回；没有才继续喂密文）
            {
                let mut c = self.conn.lock().map_err(poisoned)?;
                match c.reader().read(buf) {
                    Ok(n) if n > 0 => return Ok(n),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                if self.eof && self.pending.is_empty() {
                    return Ok(0);
                }
            }
            // 2) pending 空则从 socket 补一批密文（阻塞读在锁外）
            if self.pending.is_empty() {
                let mut tmp = [0u8; 16384];
                let n = self.sock.read(&mut tmp)?;
                if n == 0 {
                    self.eof = true;
                }
                self.pending.extend_from_slice(&tmp[..n]);
            }
            // 3) 只喂一次 read_tls，然后回到 1) 抽明文
            let mut c = self.conn.lock().map_err(poisoned)?;
            if !self.pending.is_empty() {
                let mut cursor: &[u8] = &self.pending;
                let used = match c.read_tls(&mut cursor) {
                    Ok(u) => u,
                    // 明文满（理论上有抽干不变量后不会出现）：当作没喂，下一轮先抽明文
                    Err(e) if e.kind() == io::ErrorKind::Other => 0,
                    Err(e) => return Err(e),
                };
                self.pending.drain(..used);
                if used == 0 {
                    // close_notify 或 EOF：不再有应用数据
                    self.eof = true;
                    self.pending.clear();
                }
            }
            c.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("tls: {e}")))?;
            // TLS 1.3 的回写（KeyUpdate/alert 等）
            while c.wants_write() {
                c.write_tls(&mut self.sock)?;
            }
        }
    }
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut c = self.conn.lock().map_err(poisoned)?;
        let n = c.writer().write(buf)?;
        while c.wants_write() {
            c.write_tls(&mut self.sock)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut c = self.conn.lock().map_err(poisoned)?;
        while c.wants_write() {
            c.write_tls(&mut self.sock)?;
        }
        Ok(())
    }
}

fn poisoned<T>(_: T) -> io::Error {
    io::Error::other("tls: 内部锁中毒")
}

fn provider_installed() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// 构造（并缓存）ClientConfig：按 (insecure, alpn) 缓存，无 ALPN 的两种常用
/// 组合是静态 OnceLock，带 ALPN 的按需构建（lab 场景）。
fn tls_config(insecure: bool, alpn: &[Vec<u8>]) -> Arc<ClientConfig> {
    static SECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static ALPN: OnceLock<Mutex<std::collections::HashMap<Vec<Vec<u8>>, Arc<ClientConfig>>>> =
        OnceLock::new();
    provider_installed();
    if !alpn.is_empty() {
        let cache = ALPN.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
        let key = alpn.to_vec();
        let mut map = match cache.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        return map
            .entry(key.clone())
            .or_insert_with(|| build_config(insecure, &key))
            .clone();
    }
    if insecure {
        INSECURE.get_or_init(|| build_config(true, &[])).clone()
    } else {
        SECURE.get_or_init(|| build_config(false, &[])).clone()
    }
}

fn build_config(insecure: bool, alpn: &[Vec<u8>]) -> Arc<ClientConfig> {
    Arc::new(build_rustls_config(insecure, alpn))
}

/// 构造 rustls ClientConfig（QUIC/TCP 共用：NoVerify 或 webpki 根 + ALPN）。
pub(crate) fn build_rustls_config(insecure: bool, alpn: &[Vec<u8>]) -> ClientConfig {
    provider_installed();
    let b = rustls::ClientConfig::builder();
    let mut cfg: ClientConfig = if insecure {
        b.dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        b.with_root_certificates(roots).with_no_client_auth()
    };
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.to_vec();
    }
    cfg
}

/// 在已连接的 TCP 上完成 TLS 握手（超时只用于握手期），返回可并发读写的两半。
pub fn connect(
    tcp: TcpStream,
    sni: &str,
    insecure: bool,
    alpn: &[Vec<u8>],
    timeout: Duration,
) -> io::Result<(TlsReader, TlsWriter)> {
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let name = ServerName::try_from(sni.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("sni 非法: {e}")))?
        .to_owned();
    let mut conn = ClientConnection::new(tls_config(insecure, alpn), name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("tls: {e}")))?;

    // 完整握手（阻塞至完成；超时保护来自上面的 socket 选项）
    {
        let mut sock = &tcp;
        conn.complete_io(&mut sock)?;
    }

    // 恢复阻塞语义（超时只用于握手期）
    tcp.set_read_timeout(None)?;
    tcp.set_write_timeout(None)?;
    let conn = Arc::new(Mutex::new(conn));
    Ok((
        TlsReader {
            conn: conn.clone(),
            sock: tcp.try_clone()?,
            eof: false,
            pending: Vec::new(),
        },
        TlsWriter {
            conn,
            sock: tcp.try_clone()?,
        },
    ))
}

// SPDX-License-Identifier: GPL-2.0
//! P30：SSR（shadowsocksr-stream）客户端。
//!
//! 当前形态（见 ADR-0054 边界）：**origin proto + plain obfs + 流密码**（`ssr_cipher`）、
//! TCP；`auth_*/obfs_*` 插件链路未做（解析即显式报错，不静默）。
//!
//! 线格式（对照 `olicesx/outbound` `protocol/shadowsocks_stream`）：
//! ```text
//! 客户端→服务端：[IV(ivLen)][E(目标地址 SOCKS5 风格 || 载荷 ...)]（流密码有状态）
//! 服务端→客户端：[IV(ivLen)][E(载荷 ...)]
//! ```
//! origin proto 无额外头（目标地址即首段明文）；plain obfs 无额外帧。

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};

use base64::Engine as _;

use crate::ssr_cipher::SsrCipher;
use crate::target::Target;

/// `ssr://` 链接解析结果（对照 outbound `ParseSSRURL`）。
#[derive(Debug, Clone)]
pub struct SsrConfig {
    pub server: SocketAddr,
    pub method: String,
    pub password: String,
    pub proto: String,
    pub obfs: String,
}

/// 一个 dialer = 配置（无连接复用；SSR 每连接独立流密码）。
pub struct SsrDialer {
    cfg: SsrConfig,
}

impl std::fmt::Debug for SsrDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SsrDialer({})", self.cfg.server)
    }
}

impl SsrDialer {
    pub fn new(cfg: SsrConfig) -> Self {
        Self { cfg }
    }

    pub fn name(&self) -> String {
        format!("ssr://{}", self.cfg.server)
    }

    pub fn server(&self) -> SocketAddr {
        self.cfg.server
    }

    pub fn config(&self) -> &SsrConfig {
        &self.cfg
    }

    /// 拨号：TCP + 流密码；首段写目标地址（origin proto）。
    pub fn connect_tcp(
        &self,
        target: &Target,
        timeout: std::time::Duration,
    ) -> io::Result<(SsrReadHalf, SsrWriteHalf)> {
        let sock = crate::outbound::marked_tcp_connect(self.cfg.server, timeout)?;
        connect(sock, &self.cfg, target)
    }
}

/// 在已建立的 TCP 上完成 SSR 初始化（写目标地址）并返回读写两半。
pub fn connect(
    sock: TcpStream,
    cfg: &SsrConfig,
    target: &Target,
) -> io::Result<(SsrReadHalf, SsrWriteHalf)> {
    // 与 Go 一致：加密/解密各持一个流密码对象（内部各自维护状态与 IV）。
    let read_cipher = SsrCipher::new(&cfg.method, &cfg.password)?;
    let write_cipher = SsrCipher::new(&cfg.method, &cfg.password)?;
    let read_sock = sock.try_clone()?;
    let mut w = SsrWriteHalf {
        sock,
        cipher: write_cipher,
        first: true,
        scratch: Vec::new(),
    };
    let mut addr = Vec::with_capacity(19);
    target
        .encode_socks_addr_port(&mut addr)
        .map_err(io::Error::other)?;
    w.write_all(&addr)?;
    Ok((
        SsrReadHalf {
            sock: read_sock,
            cipher: read_cipher,
            iv_done: false,
        },
        w,
    ))
}

/// 读半：首读先取对端 IV，之后解密。
pub struct SsrReadHalf {
    sock: TcpStream,
    cipher: SsrCipher,
    iv_done: bool,
}

impl Read for SsrReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.iv_done {
            let iv_len = self.cipher.iv_len();
            let mut iv = vec![0u8; iv_len];
            self.sock.read_exact(&mut iv)?;
            self.cipher.init_decrypt(&iv)?;
            self.iv_done = true;
        }
        let n = self.sock.read(buf)?;
        if n > 0 {
            self.cipher.decrypt(&mut buf[..n]);
        }
        Ok(n)
    }
}

/// 写半：首写先发本端 IV（随机），之后加密。
pub struct SsrWriteHalf {
    sock: TcpStream,
    cipher: SsrCipher,
    first: bool,
    scratch: Vec<u8>,
}

impl SsrWriteHalf {
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.sock.shutdown(std::net::Shutdown::Write)
    }
}

impl Write for SsrWriteHalf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.first {
            let iv = self.cipher.init_encrypt()?;
            self.sock.write_all(&iv)?;
            self.first = false;
        }
        self.scratch.clear();
        self.scratch.extend_from_slice(buf);
        self.cipher.encrypt(&mut self.scratch);
        self.sock.write_all(&self.scratch)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------- 链接解析

fn b64_any(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let attempts = [
        base64::engine::general_purpose::STANDARD.decode(s),
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(s),
        base64::engine::general_purpose::URL_SAFE.decode(s),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s),
    ];
    attempts.into_iter().find_map(Result::ok)
}

/// 解析 `ssr://...`（内层可为明文或 base64；格式对照 outbound `ParseSSRURL`）：
/// `server:port:proto:method:obfs:URLBASE64(password)/?remarks=&protoparam=&obfsparam=`
///
/// 当前支持 `proto=origin`（或空）与 `obfs=plain`（或空）——其余显式报错（ADR-0054）。
pub fn parse_link(url: &str) -> Result<SsrConfig, String> {
    let content = url
        .strip_prefix("ssr://")
        .ok_or_else(|| "ssr:// 前缀缺失".to_string())?;
    let cfg = match parse_inner(content) {
        Some(c) => c,
        None => {
            let dec =
                b64_any(content).ok_or_else(|| "ssr:// 链接非法（base64 解码失败）".to_string())?;
            let text =
                String::from_utf8(dec).map_err(|e| format!("ssr:// base64 内容非 UTF-8: {e}"))?;
            parse_inner(&text).ok_or_else(|| "ssr:// 链接非法（字段不足）".to_string())?
        }
    };
    let proto = cfg.proto.to_ascii_lowercase();
    let obfs = cfg.obfs.to_ascii_lowercase();
    if !matches!(proto.as_str(), "" | "origin") {
        return Err(format!(
            "SSR proto={} 暂不支持（当前 origin；见 ADR-0054）",
            cfg.proto
        ));
    }
    if !matches!(obfs.as_str(), "" | "plain") {
        return Err(format!(
            "SSR obfs={} 暂不支持（当前 plain；见 ADR-0054）",
            cfg.obfs
        ));
    }
    Ok(cfg)
}

fn parse_inner(content: &str) -> Option<SsrConfig> {
    let main = content.split("/?").next().unwrap_or(content);
    let segs: Vec<&str> = main.split(':').collect();
    if segs.len() < 6 {
        return None;
    }
    let host = segs[..segs.len() - 5].join(":");
    let port: u16 = segs[segs.len() - 5].parse().ok()?;
    let proto = segs[segs.len() - 4].to_string();
    let method = segs[segs.len() - 3].to_string();
    let obfs = segs[segs.len() - 2].to_string();
    let password = String::from_utf8(b64_any(segs[segs.len() - 1])?).ok()?;
    let server = crate::sticky::resolve(&format!("{host}:{port}")).ok()?;
    Some(SsrConfig {
        server,
        method: method.to_ascii_lowercase(),
        password,
        proto,
        obfs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "ssr://MTI3LjAuMC4xOjgzODk6b3JpZ2luOmFlcy0yNTYtY2ZiOnBsYWluOmRHVnpkSEJoYzNNLz9yZW1hcmtzPSZwcm90b3BhcmFtPSZvYmZzcGFyYW09";

    #[test]
    fn parse_base64_link_origin_plain() {
        let c = parse_link(LINK).unwrap();
        assert_eq!(c.server, "127.0.0.1:8389".parse().unwrap());
        assert_eq!(c.method, "aes-256-cfb");
        assert_eq!(c.password, "testpass");
        assert_eq!(c.proto, "origin");
        assert_eq!(c.obfs, "plain");
    }

    #[test]
    fn parse_plain_inner_link() {
        // 同一内容不 base64（内层明文）
        let inner =
            "127.0.0.1:8389:origin:aes-256-cfb:plain:dGVzdHBhc3M/?remarks=&protoparam=&obfsparam=";
        let url = format!("ssr://{inner}");
        let c = parse_link(&url).unwrap();
        assert_eq!(c.password, "testpass");
        assert_eq!(c.method, "aes-256-cfb");
    }

    #[test]
    fn unsupported_plugin_rejected_loudly() {
        let inner = "1.2.3.4:443:auth_aes128_sha1:aes-256-cfb:tls1.2_ticket_auth:cHc";
        let url = format!("ssr://{inner}");
        let e = parse_link(&url).unwrap_err();
        assert!(e.contains("暂不支持"), "{e}");
    }
}

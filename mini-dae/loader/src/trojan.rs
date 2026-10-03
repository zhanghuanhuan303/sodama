// SPDX-License-Identifier: GPL-2.0
//! P5 G1：Trojan（TCP CONNECT over TLS）。
//!
//! 协议（对照 trojan 官方文档）：
//! ```text
//! TLS 建立后：
//!   hex(SHA224(password))  + CRLF          # 56 字节十六进制
//!   cmd(0x01 CONNECT) + ATYP + ADDR + PORT + CRLF
//!   [payload...]                            # 之后双向透明
//! ```
//! 边界（ADR-0016）：只做 TCP CONNECT（01）、IPv4 目标；UDP ASSOCIATE（03）与
//! 域名目标（0x03）暂不支持（mini 的 relay 目标总是 IPv4）；TLS 验证默认走
//! webpki 根，`allowInsecure=1` 时跳过（仅实验/自签场景）。
//! TLS 读写机制在 `tls.rs`（trojan/vless/vmess 共用）。

use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use sha2::Digest as _;

use crate::tls;

/// 计算 trojan 口令摘要（56 字节 ASCII 十六进制）。
pub fn password_hash(password: &str) -> String {
    use sha2::Sha224;
    let mut h = Sha224::new();
    h.update(password.as_bytes());
    let d = h.finalize();
    let mut s = String::with_capacity(56);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 建立 TLS 连接、发起 CONNECT，返回可并发读写的两半。
pub fn connect(
    _server: SocketAddr,
    password: &str,
    sni: &str,
    insecure: bool,
    target: &crate::target::Target,
    timeout: Duration,
    tcp: TcpStream,
) -> io::Result<(tls::TlsReader, tls::TlsWriter)> {
    let (reader, mut writer) = tls::connect(tcp, sni, insecure, &[], timeout)?;

    // 握手头
    let mut head = Vec::with_capacity(64 + 6 + 18 + 2);
    head.extend_from_slice(password_hash(password).as_bytes());
    head.extend_from_slice(b"\r\n");
    head.push(0x01); // CONNECT
    target.encode_socks_addr_port(&mut head)?;
    head.extend_from_slice(b"\r\n");
    writer.write_all(&head)?;
    writer.flush()?;

    Ok((reader, writer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_matches_sha224_hex() {
        // SHA224("password") 的已知值
        assert_eq!(
            password_hash("password"),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(password_hash("password").len(), 56);
    }
}

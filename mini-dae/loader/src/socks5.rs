// SPDX-License-Identifier: GPL-2.0
//! 最小 SOCKS5 客户端（CONNECT，无认证）——过渡一跳/relay 的一种 Dialer。
//!
//! 背景（ADR-0011/ADR-0015）：P5 原生协议栈之前，被代理流量的出口可以交给一个
//! 本地 SOCKS5 后端；Rust 侧负责内核分流、透明交付与 relay，保持 orig_dst 语义。

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// 解析 `socks5://host:port`（也接受裸 `host:port`）。
pub fn parse_proxy(url: &str) -> Result<String, String> {
    let s = url.strip_prefix("socks5://").unwrap_or(url);
    match s.parse::<SocketAddr>() {
        Ok(_) => Ok(s.to_string()),
        Err(e) => Err(format!(
            "--forward 需要 socks5://host:port（得到 {url}: {e}）"
        )),
    }
}

/// 在一个**已连接到代理**的流上与 SOCKS5 代理握手并 CONNECT 到 target；
/// 成功返回可用的双向流。
pub fn handshake(
    mut s: TcpStream,
    target: SocketAddr,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;

    // greeting：仅无认证
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)?;
    if greet != [0x05, 0x00] {
        return Err(std::io::Error::other(format!(
            "socks5: 代理不接受无认证（reply {:?}）",
            greet
        )));
    }

    // request：CONNECT target
    let mut req = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req)?;

    // reply：VER REP RSV ATYP BND.ADDR BND.PORT
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks5: CONNECT 失败（rep={:#04x}）",
            hdr[1]
        )));
    }
    let skip = match hdr[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        other => {
            return Err(std::io::Error::other(format!(
                "socks5: 未知地址类型 {other:#04x}"
            )))
        }
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest)?;

    s.set_read_timeout(None)?;
    s.set_write_timeout(None)?;
    Ok(s)
}

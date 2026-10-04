// SPDX-License-Identifier: GPL-2.0
//! P12：本地 SOCKS5 入口（浏览器/桌面测试用；CONNECT only、无认证）。
//!
//! 只做协议解析与应答（RFC1928）：greeting（必须含 0x00 无认证）→ CONNECT →
//! 目标（IPv4 / 域名）。域名在调用侧本地解析（远端解析需要 dial 层支持 domain
//! target，留作后续；见 NOTES §11.19）。
//! 不支持：UDP ASSOCIATE、BIND、认证、IPv6 目标（显式拒绝，不静默）。

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};

pub const VER: u8 = 0x05;
pub const CMD_CONNECT: u8 = 0x01;
pub const ATYP_V4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_V6: u8 = 0x04;
pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL: u8 = 0x01;
pub const REP_CMD_UNSUPPORTED: u8 = 0x07;
pub const REP_ATYP_UNSUPPORTED: u8 = 0x08;

#[derive(Debug, PartialEq, Eq)]
pub enum SocksTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksTarget {
    pub fn display(&self) -> String {
        match self {
            Self::Ip(a) => a.to_string(),
            Self::Domain(h, p) => format!("{h}:{p}"),
        }
    }

    /// 解析成 SocketAddr（域名走系统解析器；IPv4 优先——数据面协议只支持 v4）。
    pub fn resolve(self) -> io::Result<SocketAddr> {
        match self {
            Self::Ip(a) => Ok(a),
            Self::Domain(h, p) => (h.as_str(), p)
                .to_socket_addrs()?
                .find(|a| a.is_ipv4())
                .ok_or_else(|| {
                    io::Error::new(ErrorKind::AddrNotAvailable, format!("{h}:{p} 无 IPv4 结果"))
                }),
        }
    }
}

/// 回响应：REP + 固定 BND 0.0.0.0:0（调用方先回失败码或成功后回 SUCCEEDED）。
pub fn reply<S: Write>(s: &mut S, rep: u8) -> io::Result<()> {
    s.write_all(&[VER, rep, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
}

/// 服务端握手：greeting + CONNECT 请求；成功返回目标（此刻**尚未**回 success，
/// 由调用方在拨号成功后调用 `reply(REP_SUCCEEDED)`）。
pub fn server_handshake<S: Read + Write>(s: &mut S) -> io::Result<SocksTarget> {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr)?;
    if hdr[0] != VER {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("socks: 不支持的版本 {}", hdr[0]),
        ));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    s.read_exact(&mut methods)?;
    if !methods.contains(&0x00) {
        let _ = s.write_all(&[VER, 0xFF]);
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "socks: 客户端不支持无认证",
        ));
    }
    s.write_all(&[VER, 0x00])?;

    let mut req = [0u8; 4];
    s.read_exact(&mut req)?;
    if req[0] != VER {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("socks: 请求版本 {}", req[0]),
        ));
    }
    if req[1] != CMD_CONNECT {
        let _ = reply(s, REP_CMD_UNSUPPORTED);
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            format!("socks: 仅支持 CONNECT（cmd={}）", req[1]),
        ));
    }
    match req[3] {
        ATYP_V4 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a)?;
            let port = read_port(s)?;
            Ok(SocksTarget::Ip(SocketAddr::from((a, port))))
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d)?;
            let host = String::from_utf8(d)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "socks: 域名不是 UTF-8"))?;
            let port = read_port(s)?;
            Ok(SocksTarget::Domain(host, port))
        }
        ATYP_V6 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a)?;
            let port = read_port(s)?;
            Ok(SocksTarget::Ip(SocketAddr::from((
                std::net::Ipv6Addr::from(a),
                port,
            ))))
        }
        other => {
            let _ = reply(s, REP_ATYP_UNSUPPORTED);
            Err(io::Error::new(
                ErrorKind::Unsupported,
                format!("socks: ATYP {other} 未支持"),
            ))
        }
    }
}

fn read_port<S: Read>(s: &mut S) -> io::Result<u16> {
    let mut p = [0u8; 2];
    s.read_exact(&mut p)?;
    Ok(u16::from_be_bytes(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 读/写分离的最小夹具：读来自脚本，写落到独立缓冲（便于断言应答字节）。
    struct Split {
        r: std::io::Cursor<Vec<u8>>,
        pub w: Vec<u8>,
    }
    impl Read for Split {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.r.read(buf)
        }
    }
    impl Write for Split {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.w.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn split(script: Vec<u8>) -> Split {
        Split {
            r: std::io::Cursor::new(script),
            w: Vec::new(),
        }
    }

    fn greet(methods: &[u8]) -> Vec<u8> {
        let mut v = vec![VER, methods.len() as u8];
        v.extend_from_slice(methods);
        v
    }

    #[test]
    fn parse_ipv4_connect() {
        let mut stream = Vec::new();
        stream.extend(greet(&[0x00]));
        stream.extend_from_slice(&[VER, CMD_CONNECT, 0x00, ATYP_V4, 1, 2, 3, 4, 0x1f, 0x90]);
        let mut io = split(stream);
        let t = server_handshake(&mut io).unwrap();
        assert_eq!(t, SocksTarget::Ip("1.2.3.4:8080".parse().unwrap()));
        assert_eq!(io.w, vec![VER, 0x00], "握手阶段不应提前回 success");
    }

    #[test]
    fn parse_domain_connect() {
        let mut stream = Vec::new();
        stream.extend(greet(&[0x02, 0x00]));
        stream.extend_from_slice(&[VER, CMD_CONNECT, 0x00, ATYP_DOMAIN]);
        stream.push(11);
        stream.extend_from_slice(b"example.com");
        stream.extend_from_slice(&443u16.to_be_bytes());
        let mut io = split(stream);
        let t = server_handshake(&mut io).unwrap();
        assert_eq!(t, SocksTarget::Domain("example.com".into(), 443));
    }

    #[test]
    fn reject_udp_associate() {
        let mut stream = Vec::new();
        stream.extend(greet(&[0x00]));
        stream.extend_from_slice(&[VER, 0x03, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 53]);
        let mut io = split(stream);
        let e = server_handshake(&mut io).unwrap_err();
        assert!(e.to_string().contains("CONNECT"), "{e}");
        // w = [5,0]（greeting 应答） + [5,REP,...]
        assert_eq!(io.w[2], VER);
        assert_eq!(io.w[3], REP_CMD_UNSUPPORTED);
    }

    #[test]
    fn accept_ipv6_target() {
        let mut stream = Vec::new();
        stream.extend(greet(&[0x00]));
        stream.extend_from_slice(&[VER, CMD_CONNECT, 0x00, ATYP_V6]);
        stream.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        stream.extend_from_slice(&80u16.to_be_bytes());
        let mut io = split(stream);
        let t = server_handshake(&mut io).unwrap();
        assert_eq!(t.display(), "[::1]:80");
    }

    #[test]
    fn resolve_domain_uses_local_dns() {
        let t = SocksTarget::Domain("localhost".into(), 80);
        let a = t.resolve().unwrap();
        assert_eq!(a.port(), 80);
        assert!(a.ip().is_loopback());
    }

    #[test]
    fn reply_bytes() {
        let mut out = Vec::new();
        reply(&mut out, REP_GENERAL).unwrap();
        assert_eq!(out, vec![VER, REP_GENERAL, 0, ATYP_V4, 0, 0, 0, 0, 0, 0]);
    }
}

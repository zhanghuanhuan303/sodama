// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
// Copyright (C) 2026 sodama contributors

//! P14：拨号目标地址——IPv4 或域名。
//!
//! 域名目标用于「远端域名解析」：嗅探到 SNI/Host 后，把域名（而不是 IP）发给
//! 代理节点，由节点侧解析（绕开本地 DNS 污染，对照 dae `dial_mode: domain`）。
//!
//! 各协议地址编码（与既有实现/规格逐字节对齐）：
//! - vless：ATYP 0x01=IPv4、0x02=域名（port 在前）
//! - vmess：ATYP 0x01=IPv4、0x02=域名（port 在前）
//! - socks5/ss/trojan/anytls（RFC1928 风格）：0x01=IPv4、0x03=域名（len+name）
//! - tuic v5：0x00=域名、0x01=IPv4（port 在地址后）
//! - hysteria2：`"host:port"` 字符串

use std::fmt;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

fn push_domain(out: &mut Vec<u8>, name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > 255 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("域名长度非法（{}）", name.len()),
        ));
    }
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl Target {
    pub fn domain(name: impl Into<String>, port: u16) -> Self {
        Self::Domain(name.into(), port)
    }

    /// 从 `SocketAddr` 构造（v4/v6 均可）。
    pub fn from_socket_addr(a: SocketAddr) -> io::Result<Self> {
        Ok(Self::Ip(a.ip(), a.port()))
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(_, p) | Self::Domain(_, p) => *p,
        }
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, Self::Domain(..))
    }

    /// 本地解析（域名 → 优先 IPv4 地址）；仅 direct 拨号与回退路径使用。
    pub fn resolve_local(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Ip(ip, port) => Ok(SocketAddr::new(*ip, *port)),
            Self::Domain(name, port) => {
                let addrs: Vec<SocketAddr> = (name.as_str(), *port).to_socket_addrs()?.collect();
                addrs
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| addrs.first())
                    .copied()
                    .ok_or_else(|| {
                        io::Error::new(ErrorKind::NotFound, format!("{name} 无解析结果"))
                    })
            }
        }
    }

    /// RFC1928 风格 ATYP+ADDR（不含端口；ss/trojan/anytls 用）。
    /// IPv4=0x01、IPv6=0x04、域名=0x03。
    pub fn encode_socks_addr(&self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Ip(IpAddr::V4(ip), _) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            Self::Ip(IpAddr::V6(ip), _) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
            }
            Self::Domain(name, _) => {
                out.push(0x03);
                push_domain(out, name)?;
            }
        }
        Ok(())
    }
    /// RFC1928 风格 ATYP+ADDR+PORT（ss/socks5 完整形式）。
    pub fn encode_socks_addr_port(&self, out: &mut Vec<u8>) -> io::Result<()> {
        self.encode_socks_addr(out)?;
        out.extend_from_slice(&self.port().to_be_bytes());
        Ok(())
    }

    /// vless/vmess 地址编码：0x01=IPv4、0x02=域名、0x03=IPv6（不含端口）。
    pub fn encode_v2ray_addr(&self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Ip(IpAddr::V4(ip), _) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            Self::Ip(IpAddr::V6(ip), _) => {
                out.push(0x03);
                out.extend_from_slice(&ip.octets());
            }
            Self::Domain(name, _) => {
                out.push(0x02);
                push_domain(out, name)?;
            }
        }
        Ok(())
    }

    /// tuic v5 地址编码：0x00=域名、0x01=IPv4、0x02=IPv6（含端口）。
    pub fn encode_tuic_addr(&self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Ip(IpAddr::V4(ip), _) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            Self::Ip(IpAddr::V6(ip), _) => {
                out.push(0x02);
                out.extend_from_slice(&ip.octets());
            }
            Self::Domain(name, _) => {
                out.push(0x00);
                push_domain(out, name)?;
            }
        }
        out.extend_from_slice(&self.port().to_be_bytes());
        Ok(())
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(IpAddr::V4(ip), port) => write!(f, "{ip}:{port}"),
            Self::Ip(IpAddr::V6(ip), port) => write!(f, "[{ip}]:{port}"),
            Self::Domain(name, port) => write!(f, "{name}:{port}"),
        }
    }
}

impl std::str::FromStr for Target {
    type Err = io::Error;

    /// `ip:port` 或 `domain:port`（域名不支持内嵌端口语法）。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            return Target::from_socket_addr(a);
        }
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, format!("目标缺端口: {s}")))?;
        if host.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("目标主机为空: {s}"),
            ));
        }
        let port: u16 = port
            .parse()
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("端口非法: {e}")))?;
        Ok(Self::Domain(host.to_string(), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_and_domain() {
        let a: Target = "1.2.3.4:443".parse().unwrap();
        assert_eq!(a, Target::Ip([1, 2, 3, 4].into(), 443));
        let b: Target = "www.example.com:8443".parse().unwrap();
        assert_eq!(b, Target::Domain("www.example.com".into(), 8443));
        assert!(b.is_domain());
        assert_eq!(b.to_string(), "www.example.com:8443");
    }

    #[test]
    fn encode_socks5_style() {
        let mut v = Vec::new();
        Target::Ip([9, 8, 7, 6].into(), 80)
            .encode_socks_addr_port(&mut v)
            .unwrap();
        assert_eq!(v, vec![0x01, 9, 8, 7, 6, 0, 80]);
        let mut v = Vec::new();
        Target::Domain("a.bc".into(), 53)
            .encode_socks_addr_port(&mut v)
            .unwrap();
        assert_eq!(v, vec![0x03, 4, b'a', b'.', b'b', b'c', 0, 53]);
    }

    #[test]
    fn encode_rejects_bad_domain() {
        let mut v = Vec::new();
        let long = "x".repeat(256);
        assert!(Target::Domain(long, 1).encode_socks_addr(&mut v).is_err());
        let mut v = Vec::new();
        assert!(Target::Domain(String::new(), 1)
            .encode_socks_addr(&mut v)
            .is_err());
    }

    #[test]
    fn encode_v6_forms() {
        let t: Target = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(t.to_string(), "[2001:db8::1]:443");
        let mut v = Vec::new();
        t.encode_socks_addr_port(&mut v).unwrap();
        assert_eq!(v[0], 0x04); // RFC1928 IPv6
        assert_eq!(
            &v[1..17],
            &std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()
        );
        assert_eq!(&v[17..19], &443u16.to_be_bytes());
        let mut v = Vec::new();
        t.encode_v2ray_addr(&mut v).unwrap();
        assert_eq!(v[0], 0x03); // vless/vmess IPv6
        let mut v = Vec::new();
        t.encode_tuic_addr(&mut v).unwrap();
        assert_eq!(v[0], 0x02); // tuic IPv6
    }

    #[test]
    fn resolve_local_ip_passthrough() {
        let t = Target::Ip([127, 0, 0, 1].into(), 9);
        assert_eq!(t.resolve_local().unwrap(), "127.0.0.1:9".parse().unwrap());
    }
}

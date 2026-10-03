//! P14：用户态嗅探（TLS ClientHello SNI / HTTP Host）——为 `dial_mode: domain`
//! 提供远端解析目标。
//!
//! 对照 dae：dae 的嗅探在内核侧做（`sniffing_timeout`，默认 30ms，读客户端
//! 首个 TCP 载荷的头部）；本实现把嗅探放在 relay accept 之后、拨号之前，
//! 用 `MSG_PEEK` 只读不消费（后续泵读到的是完整字节流），超时可在
//! `--sniffing-timeout-ms`（默认 100ms）约束。
//!
//! 边界（如实）：
//! - 只识别 TLS（SNI）与 HTTP/1.x（Host / CONNECT）；HTTP/2 前言、QUIC、其他
//!   二进制协议一律回退按 IP 拨号；
//! - ClientHello 跨多条 TLS record 到达属极端场景，本解析只看第一条 record
//!   （超时后按 IP 回退，不阻塞）；
//! - 不做 dae 的「域名单词表/后台探测门槛」：命中即用域名（等价 dae 的
//!   `domain+` 的“总是使用嗅探域名”行为，差异见 ADR-0030）。

use std::io;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// 单次嗅探最多观察的字节数（ClientHello 常见 < 1KB；给足扩展余量）。
pub const MAX_PEEK: usize = 4096;
/// HTTP 头解析上限（超过仍未见到完整头则放弃）。
const MAX_HTTP_HEAD: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
pub enum Sniff {
    /// 形态像 TLS/HTTP 但数据不完整——继续等（受超时约束）。
    NeedMore,
    /// 嗅到域名。
    Found(String),
    /// 不是可嗅探形态，或已可确定无法得到域名。
    No,
}

/// 解析已观察到的字节流（纯函数，供单测）。
pub fn sniff(buf: &[u8]) -> Sniff {
    if buf.is_empty() {
        return Sniff::NeedMore;
    }
    if buf[0] == 0x16 || buf[0] == 0x14 || buf[0] == 0x15 || buf[0] == 0x17 {
        return parse_tls(buf);
    }
    parse_http(buf)
}

fn parse_tls(buf: &[u8]) -> Sniff {
    // [content_type][ver_maj][ver_min][len u16]
    if buf.len() < 5 {
        return Sniff::NeedMore;
    }
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return Sniff::No;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len < 4 || rec_len > 16384 + 2048 {
        return Sniff::No;
    }
    if buf.len() < 5 + rec_len {
        return Sniff::NeedMore;
    }
    let rec = &buf[5..5 + rec_len];
    if rec[0] != 0x01 {
        return Sniff::No; // 非 ClientHello
    }
    let hs_len = ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | rec[3] as usize;
    if rec.len() < 4 + hs_len {
        return Sniff::NeedMore;
    }
    let hs = &rec[4..4 + hs_len];
    // client_version(2) + random(32) + session_id(1+n) + cipher_suites(2+n)
    // + compression(1+n) + extensions(2+n)
    let mut off = 34usize;
    if hs.len() < off + 1 {
        return Sniff::NeedMore;
    }
    off += 1 + hs[off] as usize;
    if hs.len() < off + 2 {
        return Sniff::NeedMore;
    }
    off += 2 + u16::from_be_bytes([hs[off], hs[off + 1]]) as usize;
    if hs.len() < off + 1 {
        return Sniff::NeedMore;
    }
    off += 1 + hs[off] as usize;
    if hs.len() < off + 2 {
        return Sniff::NeedMore;
    }
    let ext_total = u16::from_be_bytes([hs[off], hs[off + 1]]) as usize;
    off += 2;
    if hs.len() < off + ext_total {
        return Sniff::NeedMore;
    }
    let exts = &hs[off..off + ext_total];
    let mut i = 0usize;
    while i + 4 <= exts.len() {
        let etype = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let elen = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        if i + 4 + elen > exts.len() {
            return Sniff::NeedMore;
        }
        if etype == 0x0000 {
            let e = &exts[i + 4..i + 4 + elen];
            // server_name_list(2) + entry_type(1) + name_len(2) + name
            if e.len() < 5 || e[2] != 0x00 {
                return Sniff::No;
            }
            let list_len = u16::from_be_bytes([e[0], e[1]]) as usize;
            if list_len + 2 > e.len() {
                return Sniff::No;
            }
            let name_len = u16::from_be_bytes([e[3], e[4]]) as usize;
            if e.len() < 5 + name_len {
                return Sniff::NeedMore;
            }
            return match std::str::from_utf8(&e[5..5 + name_len]) {
                Ok(n) if !n.is_empty() => Sniff::Found(n.to_string()),
                _ => Sniff::No,
            };
        }
        i += 4 + elen;
    }
    Sniff::No // 无 SNI（如 IP 直连 TLS）
}

fn parse_http(buf: &[u8]) -> Sniff {
    const METHODS: [&[u8]; 8] = [
        b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"PATC", b"CONN",
    ];
    if buf.len() < 4 {
        return Sniff::NeedMore;
    }
    if !METHODS.iter().any(|m| buf.starts_with(m)) {
        return Sniff::No;
    }
    // CONNECT host:port HTTP/1.1
    if buf.starts_with(b"CONN") {
        let line_end = find_crlf(buf).unwrap_or(buf.len());
        let line = &buf[..line_end];
        let mut it = line.split(|&b| b == b' ');
        let _ = it.next();
        if let Some(auth) = it.next() {
            if let Ok(s) = std::str::from_utf8(auth) {
                if let Some((host, _port)) = s.rsplit_once(':') {
                    if !host.is_empty() {
                        return Sniff::Found(host.to_string());
                    }
                }
            }
        }
        return Sniff::No;
    }
    // 需要完整请求头（\r\n\r\n）再找 Host
    let Some(head_end) = find_double_crlf(buf) else {
        return if buf.len() >= MAX_HTTP_HEAD.min(MAX_PEEK) {
            Sniff::No
        } else {
            Sniff::NeedMore
        };
    };
    let head = &buf[..head_end];
    for line in head.split(|&b| b == b'\n') {
        let line = trim_cr(line);
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            let value = trim_space(&line[5..]);
            if !value.is_empty() {
                return match std::str::from_utf8(value) {
                    Ok(v) => Sniff::Found(v.to_string()),
                    Err(_) => Sniff::No,
                };
            }
        }
    }
    Sniff::No
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 2)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_space(mut v: &[u8]) -> &[u8] {
    while let Some((f, rest)) = v.split_first() {
        if f == &b' ' || f == &b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    while let Some((l, rest)) = v.split_last() {
        if l == &b' ' || l == &b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    v
}

/// 在 `client` 上做只读嗅探（MSG_PEEK，不消费字节）；命中返回域名。
pub fn sniff_domain(client: &TcpStream, timeout: Duration) -> Option<String> {
    let fd = client.as_raw_fd();
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; MAX_PEEK];
    loop {
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut _,
                MAX_PEEK,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::WouldBlock {
                return None;
            }
        } else if n == 0 {
            return None; // EOF
        } else {
            match sniff(&buf[..n as usize]) {
                Sniff::Found(d) => return Some(d),
                Sniff::No => return None,
                Sniff::NeedMore => {
                    if n as usize >= MAX_PEEK {
                        return None; // 缓冲打满仍不完整
                    }
                }
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remain = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, remain) };
        if r <= 0 {
            return None; // 超时或错误
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造带 SNI 的最小 TLS ClientHello（单 record）。
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        // SNI 扩展
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list len
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        // ClientHello body
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // version TLS1.2
        hs.extend_from_slice(&[0x11; 32]); // random
        hs.push(0); // session id
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hs.extend_from_slice(&[0x13, 0x01]); // suites
        hs.push(1); // compression len
        hs.push(0); // null
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);
        let mut rec = Vec::new();
        rec.push(0x01); // ClientHello
        let l = hs.len();
        rec.push(((l >> 16) & 0xff) as u8);
        rec.push(((l >> 8) & 0xff) as u8);
        rec.push((l & 0xff) as u8);
        rec.extend_from_slice(&hs);
        let mut out = Vec::new();
        out.push(0x16);
        out.extend_from_slice(&[0x03, 0x01]);
        out.extend_from_slice(&(rec.len() as u16).to_be_bytes());
        out.extend_from_slice(&rec);
        out
    }

    #[test]
    fn tls_sni_found() {
        let hello = client_hello("www.example.com");
        assert_eq!(sniff(&hello), Sniff::Found("www.example.com".into()));
    }

    #[test]
    fn tls_partial_need_more_then_found() {
        let hello = client_hello("a.b.c.example.org");
        for cut in [1usize, 5, 20, 40, hello.len() - 1] {
            assert_eq!(
                sniff(&hello[..cut.min(hello.len())]),
                Sniff::NeedMore,
                "cut={cut}"
            );
        }
        assert_eq!(sniff(&hello), Sniff::Found("a.b.c.example.org".into()));
    }

    #[test]
    fn tls_no_sni() {
        // 无扩展的 ClientHello（ext_total=0）
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[0x22; 32]);
        hs.push(0);
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&0u16.to_be_bytes());
        let mut rec = vec![0x01];
        let l = hs.len();
        rec.extend_from_slice(&[
            ((l >> 16) & 0xff) as u8,
            ((l >> 8) & 0xff) as u8,
            (l & 0xff) as u8,
        ]);
        rec.extend_from_slice(&hs);
        let mut out = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&(rec.len() as u16).to_be_bytes());
        out.extend_from_slice(&rec);
        assert_eq!(sniff(&out), Sniff::No);
    }

    #[test]
    fn http_host_found() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(sniff(req), Sniff::Found("example.com".into()));
    }

    #[test]
    fn http_host_partial() {
        let req = b"GET / HTTP/1.1\r\nHost: pa";
        assert_eq!(sniff(req), Sniff::NeedMore);
    }

    #[test]
    fn http_no_host() {
        let req = b"GET / HTTP/1.0\r\nAccept: */*\r\n\r\n";
        assert_eq!(sniff(req), Sniff::No);
    }

    #[test]
    fn http_connect_authority() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(sniff(req), Sniff::Found("example.com".into()));
    }

    #[test]
    fn binary_is_no() {
        assert_eq!(sniff(&[0x00, 0x01, 0x02, 0x03]), Sniff::No);
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.0\r\n"), Sniff::No);
    }
}

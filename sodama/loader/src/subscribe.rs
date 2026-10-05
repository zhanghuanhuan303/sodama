//! P15：订阅拉取（HTTP/HTTPS/file）与节点链接解析。
//!
//! 对照 dae `control/subscription`：拉取订阅 URL → base64（或明文）→ 逐行链接。
//! 边界（如实）：不支持 gzip/br 压缩体（报错提示）；只跟随绝对/同站绝对路径重定向
//! （最多 3 跳）；TLS 用 webpki 根（订阅站证书需公开可信）。

use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::time::Duration;

use base64::Engine as _;

use crate::outbound;

/// 一条订阅/内联节点解析结果。
#[derive(Clone)]
pub struct ParsedNode {
    pub name: String,
    pub tag: String,
    /// P34：来源顺序（0 = 最高优先；`subscription_failover` 按此分层回退）。
    pub rank: u32,
    pub outbound: outbound::Outbound,
}

const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;

/// P34：订阅 URL 文件——文件内容只有一行 http(s) URL 时，按该 URL 抓取（一层间接）。
/// 空文件/多行/非 http(s) 一律当作普通订阅正文（节点列表）。
fn url_file_target(body: &[u8]) -> Option<&str> {
    if body.is_empty() || body.len() > 4096 {
        return None;
    }
    let t = std::str::from_utf8(body).ok()?.trim();
    if t.is_empty() || t.contains('\n') || t.contains('\r') {
        return None;
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        Some(t)
    } else {
        None
    }
}

/// 拉取订阅正文：支持 `file://`、裸路径、`http://`、`https://`。
pub fn fetch(url: &str, timeout: Duration) -> io::Result<Vec<u8>> {
    let mut cur = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        match fetch_once(&cur, timeout)? {
            Fetch::Body(b) => return Ok(b),
            Fetch::Redirect(loc) => cur = resolve_location(&cur, &loc)?,
        }
    }
    Err(io::Error::other(format!("订阅重定向过多: {url}")))
}

enum Fetch {
    Body(Vec<u8>),
    Redirect(String),
}

fn fetch_once(url: &str, timeout: Duration) -> io::Result<Fetch> {
    if let Some(path) = url.strip_prefix("file://") {
        let body = std::fs::read(path)?;
        if let Some(target) = url_file_target(&body) {
            return fetch(target, timeout).map(Fetch::Body);
        }
        return Ok(Fetch::Body(body));
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        // 裸路径也当文件（lab 测试方便）；P34：内容为单行 http(s) URL 时按「订阅 URL 文件」处理
        // （便于把 token 单独放 ~/.config/sodama/subN.url，config 只写文件名）。
        let body = std::fs::read(url)?;
        if let Some(target) = url_file_target(&body) {
            return fetch(target, timeout).map(Fetch::Body);
        }
        return Ok(Fetch::Body(body));
    }
    let (use_tls, host, port, path) = parse_http_url(url)?;
    // P23：配置了 bootstrap resolver 时，订阅主机名也直连解析（对照 dae：
    // 订阅/节点服务器主机名在内部 DNS 路由下走 bootstrap）。
    let addrs: Vec<std::net::SocketAddr> =
        if crate::bootstrap::enabled() && host.parse::<std::net::IpAddr>().is_err() {
            crate::bootstrap::resolve_host(&host)
                .map_err(|e| io::Error::other(format!("bootstrap 解析 {host} 失败: {e}")))?
                .into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, port))
                .collect()
        } else {
            (host.as_str(), port).to_socket_addrs()?.collect()
        };
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("解析 {host} 失败")))?;
    let sock = crate::outbound::marked_tcp_connect(addr, timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    let host_header = if port == 80 || port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: sodama/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    let mut buf_reader: Box<dyn Read>;
    let mut writer: Box<dyn Write>;
    if use_tls {
        let (tr, tw) = crate::tls::connect(sock, &host, false, &[], timeout)?;
        tr.set_read_timeout(Some(timeout))?;
        buf_reader = Box::new(tr);
        writer = Box::new(tw);
    } else {
        buf_reader = Box::new(sock.try_clone()?);
        writer = Box::new(sock);
    }
    writer.write_all(req.as_bytes())?;
    writer.flush()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match buf_reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BODY {
                    return Err(io::Error::other("订阅正文超过 8MB 上限"));
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(e),
        }
    }
    parse_http_response(&raw)
}

fn parse_http_url(url: &str) -> io::Result<(bool, String, u16, String)> {
    let (use_tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("不支持的订阅 URL: {url}"),
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("订阅 URL 非法: {url}"),
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("端口非法: {e}"))
            })?,
        ),
        None => (authority.to_string(), if use_tls { 443 } else { 80 }),
    };
    if host.is_empty() || host.starts_with('[') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("订阅主机非法（IPv6 字面量不支持）: {url}"),
        ));
    }
    Ok((use_tls, host, port, path.to_string()))
}

fn resolve_location(base: &str, loc: &str) -> io::Result<String> {
    if loc.starts_with("http://") || loc.starts_with("https://") || loc.starts_with("file://") {
        return Ok(loc.to_string());
    }
    if let Some(path) = loc.strip_prefix('/') {
        let (use_tls, host, port, _) = parse_http_url(base)?;
        let scheme = if use_tls { "https" } else { "http" };
        let authority = if port == 80 || port == 443 {
            host
        } else {
            format!("{host}:{port}")
        };
        return Ok(format!("{scheme}://{authority}/{path}"));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("相对重定向不支持: {loc}"),
    ))
}

fn parse_http_response(raw: &[u8]) -> io::Result<Fetch> {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP 响应头不完整"))?;
    let head = String::from_utf8_lossy(&raw[..pos]);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("状态行非法: {status}"))
        })?;
    let mut location = None;
    let mut chunked = false;
    let mut gzip = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "location" => location = Some(v.to_string()),
            "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => chunked = true,
            "content-encoding" if v.to_ascii_lowercase().contains("gzip") => gzip = true,
            _ => {}
        }
    }
    if (300..400).contains(&code) {
        let loc = location.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("重定向 {code} 但缺少 Location"),
            )
        })?;
        return Ok(Fetch::Redirect(loc));
    }
    if !(200..300).contains(&code) {
        return Err(io::Error::other(format!("订阅 HTTP 状态 {code}")));
    }
    if gzip {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "订阅正文为 gzip（暂不支持压缩体；可让服务端返回 plain/base64）",
        ));
    }
    let body = &raw[pos + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    Ok(Fetch::Body(body))
}

fn decode_chunked(mut body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find_crlf(body)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunked: 缺长度行"))?;
        let size_str = String::from_utf8_lossy(&body[..line_end]);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("chunked 长度: {e}"))
        })?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked: 正文截断",
            ));
        }
        out.extend_from_slice(&body[..size]);
        if &body[size..size + 2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked: 缺 CRLF",
            ));
        }
        body = &body[size + 2..];
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// 正文解码：优先 base64（标准 / URL-safe / 无 padding），失败时按明文。
pub fn decode_body(body: &[u8]) -> io::Result<String> {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    for eng in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(dec) = eng.decode(&compact) {
            if let Ok(s) = String::from_utf8(dec) {
                if s.contains("://") {
                    return Ok(s);
                }
            }
        }
    }
    String::from_utf8(body.to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("订阅正文非 UTF-8: {e}")))
}

/// 解析订阅正文为节点列表（`(nodes, errors)`；错误逐行报告，不中断）。
pub fn parse_subscription(text: &str, tag: &str) -> (Vec<ParsedNode>, Vec<String>) {
    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let name = match line.split_once('#') {
            Some((_, frag)) if !frag.is_empty() => percent_encoding::percent_decode_str(frag)
                .decode_utf8_lossy()
                .to_string(),
            _ => format!("{tag}-{}", i + 1),
        };
        match outbound::parse(line) {
            Ok(o) => nodes.push(ParsedNode {
                name,
                tag: tag.to_string(),
                // P34：来源顺序由调用方（fetch_nodes）按订阅声明顺序覆写。
                rank: 0,
                outbound: o,
            }),
            Err(e) => errors.push(format!("第 {} 行不支持: {e}", i + 1)),
        }
    }
    (nodes, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_plain_and_base64() {
        let plain = b"ss://a@1.1.1.1:1#n1\nvless://b@2.2.2.2:2\n";
        assert!(decode_body(plain).unwrap().contains("ss://"));
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        let dec = decode_body(b64.as_bytes()).unwrap();
        assert!(dec.contains("vless://b@2.2.2.2:2"));
        let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plain);
        assert!(decode_body(b64u.as_bytes()).unwrap().contains("ss://"));
    }

    #[test]
    fn parse_links_names_and_errors() {
        let text = "# comment\n\nss://chacha20-ietf-poly1305:pass@1.1.1.1:8388#%E9%A6%99%E6%B8%AF-01\nbogus://x\n";
        let (nodes, errors) = parse_subscription(text, "sub");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "香港-01");
        assert_eq!(nodes[0].tag, "sub");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn url_file_target_detects_single_http_url() {
        // P34：subN.url 这类「URL 文件」——只有一行 http(s) URL 才当间接；其余当普通正文
        assert_eq!(
            url_file_target(b"https://example.com/sub?token=x\n"),
            Some("https://example.com/sub?token=x")
        );
        assert_eq!(
            url_file_target(b"http://1.2.3.4:8080/a"),
            Some("http://1.2.3.4:8080/a")
        );
        assert_eq!(url_file_target(b"https://a\nhttps://b\n"), None);
        assert_eq!(url_file_target(b"ss://a@1.1.1.1:1#n"), None);
        assert_eq!(url_file_target(b""), None);
    }

    #[test]
    fn http_response_plain_and_chunked() {
        let resp = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        match parse_http_response(resp).unwrap() {
            Fetch::Body(b) => assert_eq!(b, b"abc"),
            _ => panic!("expect body"),
        }
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        match parse_http_response(resp).unwrap() {
            Fetch::Body(b) => assert_eq!(b, b"abc"),
            _ => panic!("expect body"),
        }
    }

    #[test]
    fn http_response_redirect_and_gzip() {
        let resp = b"HTTP/1.1 302 Found\r\nLocation: https://x.example/sub\r\n\r\n";
        match parse_http_response(resp).unwrap() {
            Fetch::Redirect(l) => assert_eq!(l, "https://x.example/sub"),
            _ => panic!("expect redirect"),
        }
        let resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8b";
        assert!(parse_http_response(resp).is_err());
    }

    #[test]
    fn fetch_over_http_local() {
        // 本地假服务器：固定响应
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            use std::io::Read as _;
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .unwrap();
        });
        let body = fetch(
            &format!("http://127.0.0.1:{port}/sub"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(body, b"hello");
        h.join().unwrap();
    }

    #[test]
    fn url_parse_cases() {
        let (tls, host, port, path) = parse_http_url("https://a.example:8443/x/y?z=1").unwrap();
        assert!(tls);
        assert_eq!(host, "a.example");
        assert_eq!(port, 8443);
        assert_eq!(path, "/x/y?z=1");
        let (tls, host, port, path) = parse_http_url("http://b.example").unwrap();
        assert!(!tls);
        assert_eq!((host.as_str(), port, path.as_str()), ("b.example", 80, "/"));
        assert!(parse_http_url("ftp://x").is_err());
    }
}

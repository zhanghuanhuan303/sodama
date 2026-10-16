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

    /// P38：链式代理桥用——把服务端地址换成 `addr` 的副本（其余配置不变）。
    pub fn with_server(&self, addr: SocketAddr) -> Self {
        Self {
            cfg: SsrConfig {
                server: addr,
                ..self.cfg.clone()
            },
        }
    }

    pub fn config(&self) -> &SsrConfig {
        &self.cfg
    }

    /// 拨号：TCP + 流密码；首段写目标地址（origin proto）。
    /// P38：当前运行路径经 outbound 的 DialedStream → `connect()`；本方法保留为完整便捷入口。
    #[allow(dead_code)]
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
        out: Vec::new(),
        out_off: 0,
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
            inbuf: Vec::new(),
            inoff: 0,
        },
        w,
    ))
}

/// 读半：首读先取对端 IV，之后解密。
pub struct SsrReadHalf<W = TcpStream> {
    sock: W,
    cipher: SsrCipher,
    iv_done: bool,
    /// M4 stage 2：IV 跨 WouldBlock 续读缓冲（进度不丢）。
    inbuf: Vec<u8>,
    inoff: usize,
}

impl<W: Read> Read for SsrReadHalf<W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.iv_done {
            let iv_len = self.cipher.iv_len();
            while self.inbuf.len() - self.inoff < iv_len {
                if self.inoff > 0 {
                    self.inbuf.drain(..self.inoff);
                    self.inoff = 0;
                }
                let missing = iv_len - self.inbuf.len();
                let mut tmp = [0u8; 256];
                let want = missing.min(tmp.len());
                match self.sock.read(&mut tmp[..want]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ssr: IV 被截断",
                        ))
                    }
                    Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            let iv = self.inbuf[self.inoff..self.inoff + iv_len].to_vec();
            self.inbuf.clear();
            self.inoff = 0;
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
///
/// M4 stage 2：明文先加密进 `out` 再断点续写；流密码状态只在加密时推进一步，
/// WO 重试不得重新加密（否则对端解出乱码）。
pub struct SsrWriteHalf<W = TcpStream> {
    sock: W,
    cipher: SsrCipher,
    first: bool,
    out: Vec<u8>,
    out_off: usize,
}

impl SsrWriteHalf {
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.sock.shutdown(std::net::Shutdown::Write)
    }
}

impl<W: Write> SsrWriteHalf<W> {
    /// 把 `out` 中未写出的密文写到内层；WO/EINTR 时保留偏移（重试幂等）。
    fn drain_out(&mut self) -> io::Result<()> {
        while self.out_off < self.out.len() {
            match self.sock.write(&self.out[self.out_off..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "ssr: 内层写 0")),
                Ok(n) => self.out_off += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.out.clear();
        self.out_off = 0;
        Ok(())
    }
}

impl<W: Write> Write for SsrWriteHalf<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // 先冲刷上次未写完的帧；未清空前不消费新明文（WO 重试幂等）。
        self.drain_out()?;
        if self.first {
            let iv = self.cipher.init_encrypt()?;
            self.first = false;
            self.out.extend_from_slice(&iv);
        }
        let start = self.out.len();
        self.out.extend_from_slice(buf);
        self.cipher.encrypt(&mut self.out[start..]);
        // 尽力写出；WO 时密文留在 out，由 flush()/下次 write 续写（明文已接受）。
        match self.drain_out() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain_out()
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

    // ------------------------------------------------ stage 2：WouldBlock 可重入

    use std::sync::{Arc, Mutex};

    struct WobWrite {
        wire: Arc<Mutex<Vec<u8>>>,
        block_next: bool,
    }

    impl Write for WobWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.block_next {
                self.block_next = false;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.block_next = true;
            // 限制单次写入量：强制部分写 + WO 交替。
            let n = buf.len().min(97);
            self.wire.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct WobRead {
        data: Vec<u8>,
        off: usize,
        block_next: bool,
    }

    impl Read for WobRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.block_next {
                self.block_next = false;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.block_next = true;
            if self.off >= self.data.len() {
                return Ok(0);
            }
            // 限制单次读出量：强制 IV/载荷跨多次 read。
            let n = buf.len().min(11).min(self.data.len() - self.off);
            buf[..n].copy_from_slice(&self.data[self.off..self.off + n]);
            self.off += n;
            Ok(n)
        }
    }

    #[test]
    fn stream_survives_would_block() {
        let cipher = SsrCipher::new("aes-256-cfb", "testpass").unwrap();
        let plain: Vec<u8> = (0..4000u32).map(|i| (i % 239) as u8).collect();
        let wire = Arc::new(Mutex::new(Vec::new()));

        // 写半：WO 重试不得重复加密（流密码状态只推进一步）。
        let mut w = SsrWriteHalf {
            sock: WobWrite {
                wire: wire.clone(),
                block_next: true,
            },
            cipher,
            first: true,
            out: Vec::new(),
            out_off: 0,
        };
        let mut off = 0;
        let mut spins = 0;
        while off < plain.len() {
            match w.write(&plain[off..]) {
                Ok(n) if n > 0 => off += n,
                Ok(_) => panic!("write 返回 0"),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("非预期错误: {e}"),
            }
            spins += 1;
            assert!(spins < 100_000, "WO 重试不收敛");
        }
        loop {
            match w.flush() {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("非预期错误: {e}"),
            }
        }

        // 读半：IV 与载荷跨 WO 续读，解密还原明文。
        let bytes = wire.lock().unwrap().clone();
        let mut r = SsrReadHalf {
            sock: WobRead {
                data: bytes,
                off: 0,
                block_next: false,
            },
            cipher: SsrCipher::new("aes-256-cfb", "testpass").unwrap(),
            iv_done: false,
            inbuf: Vec::new(),
            inoff: 0,
        };
        let mut got = vec![0u8; plain.len()];
        let mut off = 0;
        let mut spins = 0;
        while off < got.len() {
            match r.read(&mut got[off..]) {
                Ok(0) => panic!("意外 EOF"),
                Ok(n) => off += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("非预期错误: {e}"),
            }
            spins += 1;
            assert!(spins < 100_000, "WO 重试不收敛");
        }
        assert_eq!(got, plain, "ssr WO 往返应逐字节一致");
    }
}

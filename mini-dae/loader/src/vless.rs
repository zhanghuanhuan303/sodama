// SPDX-License-Identifier: GPL-2.0
//! P5-G2：VLESS 客户端（TCP/UDP，可选 TLS）。
//!
//! wire 格式（对照 olicesx/outbound `protocol/vless/conn.go`）：
//! ```text
//! 请求：[ver=0][uuid 16B][addonLen 1B][addons][cmd 1B][port BE16][ATYP+ADDR][payload]
//!       cmd: 0x01=TCP，0x02=UDP（0x03=Mux/vision，显式拒绝）
//! 响应：[ver=0][addonLen 1B][addons]  之后才是数据（TCP 裸流 / UDP 帧序列）
//! UDP 帧：双向都是 [len BE16][payload]（一个数据报一帧，0 长度合法）
//! ```
//! UUID：标准 8-4-4-4-12（可省横线、大小写均可）；长度不在 [32,36] 时按
//! Xray 兼容行为做 UUID5 派生（SHA1(16×0x00 || password)，置 version5/variant）。
//! 边界（ADR-0017）：只做 type=tcp、flow 为空（拒绝 vision/XUDP）、IPv4 目标。

use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;

use sha1::Sha1;
use sha2::Digest as _;

use crate::target::Target;

/// 解析 VLESS UUID；失败返回 None。
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    if s.len() < 32 || s.len() > 36 {
        // Xray 兼容：非 UUID 形态的“密码”经 UUID5(零命名空间) 派生
        let mut h = Sha1::new();
        h.update([0u8; 16]);
        h.update(s.as_bytes());
        let mut u = [0u8; 16];
        u.copy_from_slice(&h.finalize()[..16]);
        u[6] = (u[6] & 0x0f) | 0x50;
        u[8] = (u[8] & 0x3f) | 0x80;
        return Some(u);
    }
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// 构造请求头（cmd 后的 port/ATYP/ADDR）。
pub fn build_request_header(uuid: &[u8; 16], target: &Target, udp: bool) -> io::Result<Vec<u8>> {
    let mut h = Vec::with_capacity(18 + 1 + 2 + 1 + 5);
    h.push(0x00);
    h.extend_from_slice(uuid);
    h.push(0x00); // addon 长度
    h.push(if udp { 0x02 } else { 0x01 });
    h.extend_from_slice(&target.port().to_be_bytes());
    target.encode_v2ray_addr(&mut h)?;
    Ok(h)
}

/// 读响应头：[ver][addonLen][addons]；ver 必须为 0。
fn read_response_header<R: Read>(r: &mut R) -> io::Result<()> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head)?;
    if head[0] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("vless: 响应版本 {} 不支持", head[0]),
        ));
    }
    let mut addons = vec![0u8; head[1] as usize];
    r.read_exact(&mut addons)?;
    Ok(())
}

// ---------------------------------------------------------------- TCP

pub struct VlessReader<R> {
    inner: R,
    header_done: bool,
}

impl<R: Read> Read for VlessReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.header_done {
            read_response_header(&mut self.inner)?;
            self.header_done = true;
        }
        self.inner.read(buf)
    }
}

pub struct VlessWriter<W> {
    inner: W,
}

impl<W: Write> VlessWriter<W> {
    /// 暴露底层写半（outbound 的 `WriteHalf::shutdown_write` 需要）。
    pub fn inner(&self) -> &W {
        &self.inner
    }
}

impl<W: Write> Write for VlessWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// 写请求头并拆出两半（TCP 模式）。
pub fn connect_split<R, W>(
    read: R,
    mut write: W,
    uuid: &[u8; 16],
    target: &Target,
) -> io::Result<(VlessReader<R>, VlessWriter<W>)>
where
    R: Read,
    W: Write,
{
    let head = build_request_header(uuid, target, false)?;
    write.write_all(&head)?;
    write.flush()?;
    Ok((
        VlessReader {
            inner: read,
            header_done: false,
        },
        VlessWriter { inner: write },
    ))
}

// ---------------------------------------------------------------- UDP over stream

/// UDP 帧的读半：带 pending 缓冲，超时/短读不会丢帧进度。
pub struct VlessUdpReader<R> {
    inner: R,
    header_done: bool,
    pending: Vec<u8>,
}

impl<R: Read> VlessUdpReader<R> {
    fn fill(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 16384];
        let n = self.inner.read(&mut tmp)?;
        self.pending.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    fn ensure_header(&mut self) -> io::Result<()> {
        while !self.header_done {
            if self.pending.len() >= 2 {
                if self.pending[0] != 0 {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("vless: 响应版本 {} 不支持", self.pending[0]),
                    ));
                }
                let n = self.pending[1] as usize;
                if self.pending.len() >= 2 + n {
                    self.pending.drain(..2 + n);
                    self.header_done = true;
                    break;
                }
            }
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "vless: 响应头前对端关闭",
                ));
            }
        }
        Ok(())
    }

    /// 收一个 UDP 数据报；空闲时返回 WouldBlock/TimedOut（不丢半帧进度）。
    pub fn recv_datagram(&mut self) -> io::Result<Vec<u8>> {
        self.ensure_header()?;
        loop {
            if self.pending.len() >= 2 {
                let len = u16::from_be_bytes([self.pending[0], self.pending[1]]) as usize;
                if self.pending.len() >= 2 + len {
                    let payload = self.pending[2..2 + len].to_vec();
                    self.pending.drain(..2 + len);
                    return Ok(payload);
                }
            }
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "vless: udp 流结束",
                ));
            }
        }
    }
}

pub struct VlessUdpWriter<W> {
    inner: W,
}

impl<W: Write> VlessUdpWriter<W> {
    /// 发一个 UDP 数据报（长度上限 65535，超长显式报错而不是静默截断）。
    pub fn send_datagram(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "vless: udp 包超过 65535",
            ));
        }
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.inner.write_all(&frame)?;
        self.inner.flush()
    }
}

/// 写请求头（UDP 模式）并拆出两半。
pub fn connect_split_udp<R, W>(
    read: R,
    mut write: W,
    uuid: &[u8; 16],
    target: SocketAddr,
) -> io::Result<(VlessUdpReader<R>, VlessUdpWriter<W>)>
where
    R: Read,
    W: Write,
{
    let head = build_request_header(uuid, &Target::from_socket_addr(target)?, true)?;
    write.write_all(&head)?;
    write.flush()?;
    Ok((
        VlessUdpReader {
            inner: read,
            header_done: false,
            pending: Vec::new(),
        },
        VlessUdpWriter { inner: write },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn uuid_parse_forms() {
        let a = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let b = parse_uuid("b831381d63244d53ad4f8cda48b30811").unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0], 0xb8);
        assert_eq!(a[15], 0x11);
        assert!(parse_uuid("b831381d-6324-4d53-ad4f-8cda48b3081").is_none()); // 35 字符但去横线非 32
    }

    #[test]
    fn uuid5_fallback_matches_xray() {
        // Xray 兼容：SHA1(16×0x00 || "test"), version 5 / variant 10xx
        let u = parse_uuid("test").unwrap();
        assert_eq!(u[6] & 0xf0, 0x50);
        assert_eq!(u[8] & 0xc0, 0x80);
        let mut h = Sha1::new();
        h.update([0u8; 16]);
        h.update(b"test");
        let digest = h.finalize();
        let mut want = [0u8; 16];
        want.copy_from_slice(&digest[..16]);
        want[6] = (want[6] & 0x0f) | 0x50;
        want[8] = (want[8] & 0x3f) | 0x80;
        assert_eq!(u, want);
    }

    #[test]
    fn request_header_layout() {
        let uuid = [0x11u8; 16];
        let target: Target = "1.2.3.4:8080".parse().unwrap();
        let h = build_request_header(&uuid, &target, false).unwrap();
        #[rustfmt::skip]
        let mut want = vec![
            0x00,
            0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
            0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
            0x00, 0x01, 0x1f, 0x90, 0x01, 0x01, 0x02, 0x03, 0x04,
        ];
        assert_eq!(h, want);
        // UDP cmd（idx18）
        want[18] = 0x02;
        assert_eq!(build_request_header(&uuid, &target, true).unwrap(), want);
    }

    #[test]
    fn request_header_domain_target() {
        let uuid = [0x22u8; 16];
        let target: Target = "www.example.com:443".parse().unwrap();
        let h = build_request_header(&uuid, &target, false).unwrap();
        let tail = &h[19..]; // cmd 之后：port(2) + ATYP+ADDR
        assert_eq!(&tail[..2], &443u16.to_be_bytes());
        assert_eq!(tail[2], 0x02); // ATYP=域名
        assert_eq!(tail[3] as usize, "www.example.com".len());
        assert_eq!(&tail[4..], b"www.example.com");
    }

    #[test]
    fn udp_framing_roundtrip() {
        // 响应流 = 响应头 + 两帧（含 0 长度） → reader 解析
        let uuid = [7u8; 16];
        let target: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&[0x00, 0x00]); // 响应头 ver=0 addon=0
        stream.extend_from_slice(&[0x00, 0x01, 0xaa]);
        stream.extend_from_slice(&[0x00, 0x00]);
        let (mut r, _w) =
            connect_split_udp(Cursor::new(stream), Vec::new(), &uuid, target).unwrap();
        assert_eq!(r.recv_datagram().unwrap(), vec![0xaa]);
        assert_eq!(r.recv_datagram().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn udp_roundtrip_against_python_server() {
        // 跨实现：Rust vless 客户端 ↔ lab 的独立 Python 服务端（需 python3；
        // 本仓库的 cargo test 与 lab 同一环境）。
        use std::net::{TcpStream, UdpSocket};
        use std::process::Command;
        use std::time::Duration;

        let lab = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lab");
        let server = lab.join("vless_server.py");
        if !server.exists() {
            eprintln!("skip: {} 不存在", server.display());
            return;
        }
        let log = std::env::temp_dir().join(format!("vless-test-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let port = 18943u16;

        // 本地 UDP echo
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_thread = std::thread::spawn(move || {
            let mut b = [0u8; 1024];
            let (n, peer) = echo.recv_from(&mut b).unwrap();
            echo.send_to(&b[..n], peer).unwrap();
        });

        let child = Command::new("python3")
            .arg("-u")
            .arg(&server)
            .arg(&log)
            .arg("b831381d-6324-4d53-ad4f-8cda48b30811")
            .arg(port.to_string())
            .spawn()
            .expect("spawn python3");
        // panic 时也要回收子进程，避免下一次跑端口被占
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = ChildGuard(child);
        std::thread::sleep(Duration::from_millis(600));

        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (mut r, mut w) =
            connect_split_udp(tcp.try_clone().unwrap(), tcp, &uuid, echo_addr).unwrap();
        w.send_datagram(b"ping").unwrap();
        let reply = r.recv_datagram().expect("recv reply");
        assert_eq!(reply, b"ping");
        echo_thread.join().unwrap();

        let log_text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(log_text.contains("UDP target="), "server log: {log_text}");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn udp_reader_keeps_partial_frame_across_short_reads() {
        // 逐字节喂：模拟网络短读/超时后续传
        struct Trickle(Vec<u8>, usize);
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if buf.is_empty() || self.1 >= self.0.len() {
                    return Ok(0);
                }
                buf[0] = self.0[self.1];
                self.1 += 1;
                Ok(1)
            }
        }
        let mut full = vec![0x00, 0x00]; // 响应头
        full.extend_from_slice(&[0x00, 0x03, 1, 2, 3]);
        let mut r = VlessUdpReader {
            inner: Trickle(full, 0),
            header_done: false,
            pending: Vec::new(),
        };
        assert_eq!(r.recv_datagram().unwrap(), vec![1, 2, 3]);
    }
}

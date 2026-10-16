// SPDX-License-Identifier: GPL-2.0
//! VLESS over WebSocket（RFC6455）客户端传输（P10：真实订阅节点）。
//!
//! wire：`GET {path} HTTP/1.1` Upgrade 握手 → 掩码二进制帧承载字节流。
//! - 客户端 → 服务端：必须掩码（opcode=0x2、FIN=1；每次 `write` 发一帧）；
//! - 服务端 → 客户端：不得掩码；数据/续帧直接当字节流交付（读半不缓存整帧：
//!   `remaining` 计数 + 直接读进调用方缓冲，避免大包分配）；
//! - 控制帧：ping → 排队 pong（写半顺手带出），close → EOF；
//! - 握手响应在升级处残留的字节会存进读半 pending，不会丢帧。
//! 边界：不做扩展协商（permessage-deflate 等）、不做分片发送、不做 close 半关闭
//! （与 TLS 层一致：直接 FIN）。

use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rand::RngCore as _;
use sha1::{Digest as _, Sha1};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HANDSHAKE: usize = 16 * 1024;

type Pongs = Arc<Mutex<Vec<Vec<u8>>>>;

pub struct WsReader<R> {
    inner: R,
    /// 握手响应里多读出来的字节（属于第一帧的开始）。
    pending: Vec<u8>,
    pending_pos: usize,
    /// 当前数据帧还未交付的载荷长度。
    remaining: u64,
    eof: bool,
    pongs: Pongs,
    /// stage 2：头已读、载荷待消费的控制帧（opcode, 长度）——跨 WO 可重入。
    pending_control: Option<(u8, u64)>,
}

pub struct WsWriter<W> {
    inner: W,
    pongs: Pongs,
    /// stage 2：已组帧待写出的字节（WO 后从断点续写，不重复组帧/掩码）。
    out: Vec<u8>,
    out_off: usize,
}

impl<W: Write> WsWriter<W> {
    /// 暴露底层写半（outbound 的 `WriteHalf::shutdown_write` 需要）。
    pub fn inner(&self) -> &W {
        &self.inner
    }

    fn queue_frame(&mut self, opcode: u8, payload: &[u8]) {
        let n = payload.len();
        let mut hdr = [0u8; 14];
        hdr[0] = 0x80 | opcode; // FIN=1
        let hlen = match n {
            0..=125 => {
                hdr[1] = 0x80 | n as u8; // MASK=1
                2
            }
            126..=0xffff => {
                hdr[1] = 0x80 | 126;
                hdr[2..4].copy_from_slice(&(n as u16).to_be_bytes());
                4
            }
            _ => {
                hdr[1] = 0x80 | 127;
                hdr[2..10].copy_from_slice(&(n as u64).to_be_bytes());
                10
            }
        };
        let mut mask = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask);
        hdr[hlen..hlen + 4].copy_from_slice(&mask);
        self.out.extend_from_slice(&hdr[..hlen + 4]);
        self.out
            .extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    }

    /// 把读半排队的 pong 组帧进 out（发送顺序在后续数据帧之前）。
    fn queue_pongs(&mut self) {
        let pongs = match self.pongs.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(p) => std::mem::take(&mut *p.into_inner()),
        };
        for p in pongs {
            self.queue_frame(0xA, &p);
        }
    }

    /// 尽力把 out 写出；WO 时保留偏移（可重入），由 flush()/后续事件续写。
    fn drain_out(&mut self) -> io::Result<()> {
        while self.out_off < self.out.len() {
            match self.inner.write(&self.out[self.out_off..]) {
                Ok(0) => return Err(io::Error::new(ErrorKind::WriteZero, "ws: inner 写 0")),
                Ok(n) => self.out_off += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.out.clear();
        self.out_off = 0;
        Ok(())
    }
}

impl<W: Write> Write for WsWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // 先冲刷上次组帧；未清空前不消费新明文（非阻塞 WO 重试幂等）。
        self.drain_out()?;
        self.queue_pongs();
        self.queue_frame(0x2, buf);
        // 尽力写出；WO 时留在 out，由 flush() 续写（明文已接受并组帧）。
        match self.drain_out() {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.queue_pongs();
        self.drain_out()?;
        self.inner.flush()
    }
}

impl<R: Read> WsReader<R> {
    /// 确保缓冲内至少有 `n` 个未消费字节；不足则补读。
    /// 返回 false = 对端关闭且缓冲不足（EOF）；WouldBlock 上抛且缓冲保留（可重入）。
    fn ensure_buffered(&mut self, n: usize) -> io::Result<bool> {
        while self.pending.len() - self.pending_pos < n {
            if self.pending_pos > 0 {
                let len = self.pending.len() - self.pending_pos;
                self.pending.copy_within(self.pending_pos.., 0);
                self.pending.truncate(len);
                self.pending_pos = 0;
            }
            let mut tmp = [0u8; 8192];
            let got = self.inner.read(&mut tmp)?;
            if got == 0 {
                return Ok(false);
            }
            self.pending.extend_from_slice(&tmp[..got]);
        }
        Ok(true)
    }

    /// 读帧头（缓冲解析，跨 WO 可重入）；返回 (opcode, payload 长度, 是否掩码)。
    fn read_frame_header(&mut self) -> io::Result<(u8, u64, bool)> {
        if !self.ensure_buffered(2)? {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "ws: 帧被截断"));
        }
        let b0 = self.pending[self.pending_pos];
        let b1 = self.pending[self.pending_pos + 1];
        let opcode = b0 & 0x0f;
        let masked = b1 & 0x80 != 0;
        let mut len = (b1 & 0x7f) as u64;
        let extra = match b1 & 0x7f {
            126 => 2usize,
            127 => 8,
            _ => 0,
        };
        if extra > 0 {
            if !self.ensure_buffered(2 + extra)? {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "ws: 帧被截断"));
            }
            let p = self.pending_pos + 2;
            if extra == 2 {
                len = u16::from_be_bytes([self.pending[p], self.pending[p + 1]]) as u64;
            } else {
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.pending[p..p + 8]);
                len = u64::from_be_bytes(b);
            }
        }
        self.pending_pos += 2 + extra;
        Ok((opcode, len, masked))
    }

    /// 取一个控制帧载荷（≤125B）；跨 WO 可重入（头已消费、载荷未取完时重调即可）。
    fn take_control(&mut self, len: u64) -> io::Result<Vec<u8>> {
        if len > 125 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("ws: 控制帧长度 {len} 非法"),
            ));
        }
        if !self.ensure_buffered(len as usize)? {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "ws: 控制帧被截断"));
        }
        let s = self.pending_pos;
        let e = s + len as usize;
        let v = self.pending[s..e].to_vec();
        self.pending_pos = e;
        Ok(v)
    }
}

impl<R: Read> Read for WsReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.eof {
            return Ok(0);
        }
        loop {
            // stage 2：控制帧头已消费、载荷未取完时从这里续（WO 可重入）。
            if let Some((op, len)) = self.pending_control {
                let payload = self.take_control(len)?;
                self.pending_control = None;
                match op {
                    0x8 => {
                        // close：读掉载荷，之后一律 EOF
                        self.eof = true;
                        return Ok(0);
                    }
                    0x9 => match self.pongs.lock() {
                        Ok(mut g) => g.push(payload),
                        Err(poison) => poison.into_inner().push(payload),
                    },
                    _ => {} // pong 丢弃
                }
                continue;
            }
            if self.remaining > 0 {
                let n = buf.len().min(self.remaining as usize);
                if self.pending_pos < self.pending.len() {
                    let avail = self.pending.len() - self.pending_pos;
                    let m = n.min(avail);
                    buf[..m].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + m]);
                    self.pending_pos += m;
                    self.remaining -= m as u64;
                    return Ok(m);
                }
                let got = self.inner.read(&mut buf[..n])?;
                if got == 0 {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "ws: 数据帧被截断"));
                }
                self.remaining -= got as u64;
                return Ok(got);
            }
            let (opcode, len, masked) = self.read_frame_header()?;
            if masked {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "ws: 服务端帧不应掩码",
                ));
            }
            match opcode {
                0x0..=0x2 => self.remaining = len,
                0x8..=0xA => self.pending_control = Some((opcode, len)),
                other => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("ws: 不支持 opcode {other}"),
                    ))
                }
            }
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// HTTP Upgrade 握手；成功返回读写两半。
pub fn connect<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
) -> io::Result<(WsReader<R>, WsWriter<W>)> {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key_b64}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    write.write_all(req.as_bytes())?;
    write.flush()?;

    let mut buf = Vec::with_capacity(1024);
    let mut scanned = 0usize;
    let head_end;
    loop {
        if buf.len() > MAX_HANDSHAKE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ws: 握手响应超过 16KB",
            ));
        }
        if let Some(pos) = find_subslice(&buf[scanned..], b"\r\n\r\n") {
            head_end = scanned + pos + 4;
            break;
        }
        // 下一轮从本次扫描末尾回退 3 字节（分隔符可跨读边界）
        scanned = buf.len().saturating_sub(3);
        let mut tmp = [0u8; 1024];
        let n = read.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "ws: 握手响应中途关闭",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "ws: 握手响应不是 ASCII"))?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    if !(status.contains(" 101 ") || status.contains(" 101\r")) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("ws: 握手状态非 101：{}", status.trim()),
        ));
    }
    let mut accept: Option<&str> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("sec-websocket-accept") {
                accept = Some(v.trim());
            }
        }
    }
    let mut h = Sha1::new();
    h.update(key_b64.as_bytes());
    h.update(WS_GUID.as_bytes());
    let want = base64::engine::general_purpose::STANDARD.encode(h.finalize());
    match accept {
        Some(a) if a == want => {}
        Some(a) => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("ws: Sec-WebSocket-Accept 不匹配（{a}）"),
            ))
        }
        None => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ws: 握手响应缺 Sec-WebSocket-Accept",
            ))
        }
    }
    let leftover = buf[head_end..].to_vec();
    let pongs: Pongs = Arc::new(Mutex::new(Vec::new()));
    Ok((
        WsReader {
            inner: read,
            pending: leftover,
            pending_pos: 0,
            remaining: 0,
            eof: false,
            pongs: pongs.clone(),
            pending_control: None,
        },
        WsWriter {
            inner: write,
            pongs,
            out: Vec::new(),
            out_off: 0,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Duration;

    /// 把字节流脚本喂给读半（不起网络）。
    fn reader_with(script: Vec<u8>) -> WsReader<std::io::Cursor<Vec<u8>>> {
        WsReader {
            inner: std::io::Cursor::new(script),
            pending: Vec::new(),
            pending_pos: 0,
            remaining: 0,
            eof: false,
            pongs: Arc::new(Mutex::new(Vec::new())),
            pending_control: None,
        }
    }

    /// 服务端风格的未掩码帧。
    fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x80 | opcode];
        let n = payload.len();
        if n < 126 {
            v.push(n as u8);
        } else {
            v.push(126);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        }
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn read_stream_with_continuation_and_ping() {
        let mut script = Vec::new();
        script.extend(frame(0x2, b"hello "));
        script.push(0x80); // 续帧（FIN=1, opcode=0）
        script.push(5);
        script.extend(b"world");
        script.extend(frame(0x9, b"pi")); // ping → pong 排队
        script.extend(frame(0x2, b"!!"));
        script.extend(frame(0x8, b"")); // close
        let mut r = reader_with(script);
        let mut out = Vec::new();
        // 逐字节读：验证 remaining/pending 路径都稳
        let mut one = [0u8; 1];
        loop {
            match r.read(&mut one) {
                Ok(0) => break,
                Ok(_) => out.push(one[0]),
                Err(e) => panic!("read: {e}"),
            }
        }
        assert_eq!(out, b"hello world!!");
        let pongs = r.pongs.lock().unwrap().clone();
        assert_eq!(pongs, vec![b"pi".to_vec()]);
    }

    #[test]
    fn server_mask_is_rejected() {
        let mut f = vec![0x82, 0x80 | 3]; // MASK=1
        f.extend_from_slice(&[1, 2, 3, 4]); // mask key
        f.extend_from_slice(&[0x41, 0x42, 0x43]);
        let mut r = reader_with(f);
        let mut b = [0u8; 8];
        assert!(r.read(&mut b).is_err());
    }

    #[test]
    fn write_masks_and_flushes_pongs() {
        let pongs: Pongs = Arc::new(Mutex::new(vec![b"hi".to_vec()]));
        let mut w = WsWriter {
            inner: Vec::new(),
            pongs,
            out: Vec::new(),
            out_off: 0,
        };
        w.write_all(b"abc").unwrap();
        w.flush().unwrap();
        let out = w.inner;
        // 第一帧：pong（0x8A，掩码，载荷 2，含 4B mask）
        assert_eq!(out[0], 0x8A);
        assert_eq!(out[1] & 0x80, 0x80);
        assert_eq!(out[1] & 0x7f, 2);
        let m0 = &out[2..6];
        assert_eq!(&[out[6] ^ m0[0], out[7] ^ m0[1]], b"hi");
        // 第二帧：binary "abc"
        let off = 8;
        assert_eq!(out[off], 0x82);
        assert_eq!(out[off + 1] & 0x7f, 3);
        let m1 = &out[off + 2..off + 6];
        assert_eq!(
            &[
                out[off + 6] ^ m1[0],
                out[off + 7] ^ m1[1],
                out[off + 8] ^ m1[2]
            ],
            b"abc"
        );
    }

    #[test]
    fn handshake_roundtrip_over_tcp() {
        // 真回环 mock 服务端：验 key/accept 计算与握手残留字节。
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 1];
            while !req.ends_with(b"\r\n\r\n") {
                let n = s.read(&mut b).unwrap();
                if n == 0 {
                    break;
                }
                req.push(b[0]);
            }
            let text = String::from_utf8_lossy(&req);
            let key = text
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                .expect("missing Sec-WebSocket-Key")
                .trim()
                .to_string();
            let mut h = Sha1::new();
            h.update(key.as_bytes());
            h.update(WS_GUID.as_bytes());
            let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            s.write_all(resp.as_bytes()).unwrap();
            // 101 后立刻补一帧（验证握手残留字节不丢）
            s.write_all(&frame(0x2, b"early")).unwrap();
            // 读一帧客户端掩码帧，校验掩码与载荷
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], 0x82);
            assert_eq!(hdr[1] & 0x80, 0x80);
            let n = (hdr[1] & 0x7f) as usize;
            let mut mask = [0u8; 4];
            s.read_exact(&mut mask).unwrap();
            let mut payload = vec![0u8; n];
            s.read_exact(&mut payload).unwrap();
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
            assert_eq!(payload, b"ping-data");
        });
        let sock = std::net::TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (mut r, mut w) = connect(sock.try_clone().unwrap(), sock, "example.com", "/x").unwrap();
        let mut got = [0u8; 5];
        r.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"early");
        w.write_all(b"ping-data").unwrap();
        w.flush().unwrap();
        server.join().unwrap();
    }

    /// stage 2：读半跨 WO 不丢进度（帧头/控制帧/数据帧）。
    #[test]
    fn reader_survives_would_block() {
        struct WobRead<'a> {
            data: &'a [u8],
            pos: usize,
            block_next: bool,
        }
        impl Read for WobRead<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                if self.block_next {
                    self.block_next = false;
                    return Err(ErrorKind::WouldBlock.into());
                }
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                buf[0] = self.data[self.pos];
                self.pos += 1;
                self.block_next = true;
                Ok(1)
            }
        }
        let mut script = Vec::new();
        script.extend(frame(0x2, b"hello "));
        script.extend(frame(0x9, b"pi")); // ping 排队 pong
        script.extend(frame(0x2, b"world!!"));
        script.extend(frame(0x8, b"")); // close
        let mut r = WsReader {
            inner: WobRead {
                data: &script,
                pos: 0,
                block_next: false,
            },
            pending: Vec::new(),
            pending_pos: 0,
            remaining: 0,
            eof: false,
            pongs: Arc::new(Mutex::new(Vec::new())),
            pending_control: None,
        };
        let mut out = Vec::new();
        let mut guard = 0u32;
        loop {
            guard += 1;
            assert!(guard < 1_000_000, "读循环未收敛");
            let mut b = [0u8; 3];
            match r.read(&mut b) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&b[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => panic!("read: {e}"),
            }
        }
        assert_eq!(out, b"hello world!!");
        assert_eq!(r.pongs.lock().unwrap().clone(), vec![b"pi".to_vec()]);
    }

    /// stage 2：写半跨 WO 不重复组帧/掩码。
    #[test]
    fn writer_survives_would_block() {
        struct WobWrite {
            out: Vec<u8>,
            block_next: bool,
            cap: usize,
        }
        impl Write for WobWrite {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.block_next {
                    self.block_next = false;
                    return Err(ErrorKind::WouldBlock.into());
                }
                let n = buf.len().min(self.cap);
                if n == 0 {
                    return Ok(0);
                }
                self.out.extend_from_slice(&buf[..n]);
                self.block_next = true;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut w = WsWriter {
            inner: WobWrite {
                out: Vec::new(),
                block_next: false,
                cap: 3,
            },
            pongs: Arc::new(Mutex::new(Vec::new())),
            out: Vec::new(),
            out_off: 0,
        };
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut off = 0usize;
        let mut guard = 0u32;
        while off < payload.len() && guard < 1_000_000 {
            guard += 1;
            match w.write(&payload[off..]) {
                Ok(n) => off += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    let _ = w.flush();
                }
                Err(e) => panic!("write: {e}"),
            }
        }
        loop {
            match w.flush() {
                Ok(()) => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => panic!("flush: {e}"),
            }
        }
        assert_eq!(off, payload.len());
        // 解析客户端掩码帧（含 126 扩展长度），还原载荷
        let wire = &w.inner.out;
        let mut pos = 0usize;
        let mut decoded = Vec::new();
        while pos < wire.len() {
            assert_eq!(wire[pos] & 0x80, 0x80, "FIN=1");
            let op = wire[pos] & 0x0f;
            pos += 1;
            let b1 = wire[pos];
            pos += 1;
            assert_eq!(b1 & 0x80, 0x80, "MASK=1");
            let mut n = (b1 & 0x7f) as usize;
            if n == 126 {
                n = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
                pos += 2;
            } else if n == 127 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&wire[pos..pos + 8]);
                n = u64::from_be_bytes(b) as usize;
                pos += 8;
            }
            let mask = [wire[pos], wire[pos + 1], wire[pos + 2], wire[pos + 3]];
            pos += 4;
            let mut pl = wire[pos..pos + n].to_vec();
            pos += n;
            for (i, b) in pl.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
            assert_eq!(op, 0x2, "数据帧");
            decoded.extend_from_slice(&pl);
        }
        assert_eq!(decoded, payload);
    }
}

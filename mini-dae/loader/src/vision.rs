// SPDX-License-Identifier: GPL-2.0
//! P18c+：VLESS `xtls-rprx-vision` 客户端帧层（对照 dae outbound `vision` 包）。
//!
//! 线上布局（VLESS 载荷之内，外层仍是 TLS/REALITY 加密）：
//!   首帧： [UUID 16B][cmd 1B][contentLen u16 BE][paddingLen u16 BE][content][padding]
//!   后续： [cmd 1B][contentLen u16 BE][paddingLen u16 BE][content][padding]
//! cmd：0x00 继续填充、0x01 结束填充（之后裸 VLESS 载荷直通）、
//!      0x02 直通（服务端把下行切成裸 TCP——Vision splice）。
//!
//! 本实现策略（可用优先）：
//! - 上行只发 0x00/0x01（不做上行 splice；服务端仍兼容，仅少一项优化）；
//! - 下行完整处理 0x01/0x02：遇到 0x02 后把 TLS 读半切换成裸 TCP 直通，
//!   之后的字节是目标站真实 TLS 记录，原样交给上层（浏览器自己解密）。

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const CMD_CONTINUE: u8 = 0x00;
pub const CMD_END: u8 = 0x01;
pub const CMD_DIRECT: u8 = 0x02;

const HEADER_LEN_UUID: usize = 16 + 1 + 2 + 2;
const HEADER_LEN: usize = 1 + 2 + 2;

fn rand_u32() -> u32 {
    use rand::RngCore;
    rand::thread_rng().next_u32()
}

/// 与 dae `ApplyPaddingFromPool` 对齐：TLS 首包把总长垫到 ~900+，否则 0..255。
fn padding_len(content_len: usize, long_padding: bool) -> usize {
    if content_len < 900 && long_padding {
        (rand_u32() % 500) as usize + 900 - content_len
    } else {
        (rand_u32() % 256) as usize
    }
}

/// Vision 读半：解析下行帧；遇到 direct 后经 `raw` 让 TLS 层裸读。
pub struct VisionReader<R> {
    inner: R,
    uuid: [u8; 16],
    first: bool,
    remaining_content: usize,
    remaining_padding: usize,
    /// 当前帧内容/填充耗尽后要进入的状态。
    after: Option<u8>,
    passthrough: bool,
    raw: Arc<AtomicBool>,
    hdr: [u8; HEADER_LEN_UUID],
}

impl<R: Read> VisionReader<R> {
    pub fn new(inner: R, uuid: [u8; 16], raw: Arc<AtomicBool>) -> Self {
        VisionReader {
            inner,
            uuid,
            first: true,
            remaining_content: 0,
            remaining_padding: 0,
            after: None,
            passthrough: false,
            raw,
            hdr: [0u8; HEADER_LEN_UUID],
        }
    }

    fn read_frame_header(&mut self) -> io::Result<Option<(u8, usize, usize)>> {
        let need = if self.first {
            HEADER_LEN_UUID
        } else {
            HEADER_LEN
        };
        let buf = &mut self.hdr[..need];
        let mut got = 0usize;
        while got < need {
            let n = self.inner.read(&mut buf[got..])?;
            if n == 0 {
                if got == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vision: 帧头读取中断",
                ));
            }
            got += n;
        }
        let mut off = 0usize;
        if self.first {
            if buf[..16] != self.uuid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vision: 服务端回显 UUID 不匹配",
                ));
            }
            self.first = false;
            off = 16;
        }
        let cmd = buf[off];
        let content = u16::from_be_bytes([buf[off + 1], buf[off + 2]]) as usize;
        let padding = u16::from_be_bytes([buf[off + 3], buf[off + 4]]) as usize;
        if cmd > CMD_DIRECT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("vision: 未知命令 {cmd}"),
            ));
        }
        Ok(Some((cmd, content, padding)))
    }
}

impl<R: Read> Read for VisionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.remaining_content > 0 {
                let n = self.remaining_content.min(buf.len());
                let got = self.inner.read(&mut buf[..n])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vision: 帧内容读取中断",
                    ));
                }
                self.remaining_content -= got;
                return Ok(got);
            }
            if self.remaining_padding > 0 {
                let mut tmp = [0u8; 512];
                let n = self.remaining_padding.min(tmp.len());
                let got = self.inner.read(&mut tmp[..n])?;
                if got == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vision: 帧填充读取中断",
                    ));
                }
                self.remaining_padding -= got;
                continue;
            }
            if let Some(cmd) = self.after.take() {
                match cmd {
                    CMD_DIRECT => {
                        // 切换 TLS 读半为裸 TCP 直通。
                        self.raw.store(true, Ordering::SeqCst);
                        self.passthrough = true;
                    }
                    CMD_END => {
                        self.passthrough = true;
                    }
                    _ => {}
                }
            }
            if self.passthrough {
                return self.inner.read(buf);
            }
            match self.read_frame_header()? {
                None => return Ok(0),
                Some((cmd, content, padding)) => {
                    self.remaining_content = content;
                    self.remaining_padding = padding;
                    if cmd != CMD_CONTINUE {
                        self.after = Some(cmd);
                    }
                }
            }
        }
    }
}

/// Vision 写半：首帧带 UUID；TLS 流量按需长填充；非 TLS 或过滤窗口结束发 0x01 后直通。
pub struct VisionWriter<W> {
    inner: W,
    uuid: [u8; 16],
    first: bool,
    packets_to_filter: u32,
    finished: bool,
}

impl<W: Write> VisionWriter<W> {
    pub fn new(inner: W, uuid: [u8; 16]) -> Self {
        VisionWriter {
            inner,
            uuid,
            first: true,
            packets_to_filter: 6,
            finished: false,
        }
    }

    pub fn inner(&self) -> &W {
        &self.inner
    }
}

fn looks_tls(buf: &[u8]) -> bool {
    buf.len() >= 3 && (buf[0] == 0x16 || buf[0] == 0x17) && buf[1] == 0x03
}

impl<W: Write> Write for VisionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.finished {
            return self.inner.write(buf);
        }
        // 帧头 contentLen 是 u16：单帧内容最大 65535；按 16KB 分帧（与 dae 的
        // 分段写行为一致；一次 write(128KB) 若不分帧会把长度截断为 0）。
        let mut off = 0usize;
        while off < buf.len() {
            let end = (off + 16384).min(buf.len());
            self.write_frame(&buf[off..end])?;
            off = end;
            if self.finished && off < buf.len() {
                return self.inner.write(&buf[off..]).map(|n| off + n);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> VisionWriter<W> {
    fn write_frame(&mut self, buf: &[u8]) -> io::Result<()> {
        debug_assert!(buf.len() <= u16::MAX as usize);
        let is_tls = looks_tls(buf);
        let first = self.first;
        let cmd;
        if first {
            // 首帧恒 0x00（UUID 在本帧里）。
            self.first = false;
            cmd = CMD_CONTINUE;
        } else if !is_tls {
            cmd = CMD_END;
            self.finished = true;
        } else if self.packets_to_filter <= 1 {
            cmd = CMD_END;
            self.finished = true;
        } else {
            self.packets_to_filter -= 1;
            cmd = CMD_CONTINUE;
        }
        let pad = padding_len(buf.len(), is_tls);
        let mut frame = Vec::with_capacity(HEADER_LEN_UUID + buf.len() + pad);
        if first {
            frame.extend_from_slice(&self.uuid);
        }
        frame.push(cmd);
        frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(pad as u16).to_be_bytes());
        frame.extend_from_slice(buf);
        frame.resize(frame.len() + pad, 0);
        self.inner.write_all(&frame)?;
        self.inner.flush()
    }
}

impl<W: Write> VisionWriter<W> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_reader_roundtrip() {
        // 内存通道：writer 写 → reader 读（不含 direct）。
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let uuid = [7u8; 16];
        let raw = Arc::new(AtomicBool::new(false));
        let mut w = VisionWriter::new(a, uuid);
        let mut r = VisionReader::new(b, uuid, raw.clone());
        // 第一笔：TLS 形状（长填充）
        let hello = [0x16u8, 0x03, 0x01, 1, 2, 3, 4];
        w.write_all(&hello).unwrap();
        drop(w);
        let mut out = [0u8; 16];
        let mut got = 0usize;
        while got < hello.len() {
            let n = r.read(&mut out[got..]).unwrap();
            assert!(n > 0);
            got += n;
        }
        assert_eq!(&out[..hello.len()], &hello);
        assert!(!raw.load(Ordering::SeqCst));
    }

    #[test]
    fn reader_handles_direct_switch() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let uuid = [3u8; 16];
        let raw = Arc::new(AtomicBool::new(false));
        // 手工构造：首帧(continue, content=2, pad=1) + 尾帧(direct, content=3, pad=0) + 裸数据
        let mut wire = Vec::new();
        wire.extend_from_slice(&uuid);
        wire.push(CMD_CONTINUE);
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(b"ab");
        wire.push(0); // padding
        wire.push(CMD_DIRECT);
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(b"xyz");
        wire.extend_from_slice(b"RAW");
        a.try_clone().unwrap().write_all(&wire).unwrap();
        drop(a);
        let mut r = VisionReader::new(b, uuid, raw.clone());
        let mut out = Vec::new();
        let mut tmp = [0u8; 16];
        loop {
            match r.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&tmp[..n]),
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(out, b"abxyzRAW");
        assert!(raw.load(Ordering::SeqCst));
    }
}

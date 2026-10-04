// SPDX-License-Identifier: GPL-2.0
//! P18c+ / M3：VLESS `xtls-rprx-vision` 客户端帧层（对照 dae outbound `vision` 包）。
//!
//! 线上布局（VLESS 载荷之内，外层仍是 TLS/REALITY 加密）：
//!   首帧： [UUID 16B][cmd 1B][contentLen u16 BE][paddingLen u16 BE][content][padding]
//!   后续： [cmd 1B][contentLen u16 BE][paddingLen u16 BE][content][padding]
//! cmd：0x00 继续填充、0x01 结束填充（之后视帧而不见，保持在内外层协议上）、
//!      0x02 直通（双向 splice：切到裸 TCP，外层加解密全部停用——XTLS DIRECT）。
//!
//! M3 对齐 Xray/dae 的完整 DIRECT 状态机：
//! - **内层 TLS 嗅探**（`TlsSniffer`，移植 dae `FilterTLS`）：过滤窗口内双向观察，
//!   识别内层 ServerHello 的 TLS 1.3 supported_versions + 受支持 cipher；
//! - **上行**：窗口结束/应用数据开始后，若内层确为 TLS 1.3 → 发 0x02 并置 `write_raw`，
//!   后续字节裸写 TCP（不再经外层 TLS）；否则发 0x01 维持原协议；
//! - **下行**：收到 0x02 后置 `read_raw`，后续从裸 TCP 直读（浏览器自己解密内层 TLS）；
//! - 外层必须 TLS 1.3（REALITY 天然满足；rustls 由 `connect_vision` 校验）。
//!
//! 与 dae 的差异：dae 用 unsafe 反射取 Go TLS 内部读缓冲（input/rawInput）做交接；
//! 我们的 rustls 读半用「逐记录有界喂入」保证切换前不多读一个字节（见 `tls.rs`），
//! 因此无需反射，读半置位后直接裸读。

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const CMD_CONTINUE: u8 = 0x00;
pub const CMD_END: u8 = 0x01;
pub const CMD_DIRECT: u8 = 0x02;

const HEADER_LEN_UUID: usize = 16 + 1 + 2 + 2;
const HEADER_LEN: usize = 1 + 2 + 2;

// 内层 TLS 嗅探用到的常量（对照 dae filter.go）。
const TLS_SERVER_HELLO_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_CLIENT_HELLO_START: [u8; 2] = [0x16, 0x03];
const TLS_APP_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

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

fn looks_tls(buf: &[u8]) -> bool {
    buf.len() >= 3 && (buf[0] == 0x16 || buf[0] == 0x17) && buf[1] == 0x03
}

fn looks_tls_app_data(buf: &[u8]) -> bool {
    buf.len() > 6 && buf[..3] == TLS_APP_DATA_START
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Xray TLS 1.3 cipher suite → XTLS DIRECT 是否可用（0x1305 CCM_8 除外）。
fn xtls_cipher_ok(cipher: u16) -> bool {
    matches!(cipher, 0x1301..=0x1304)
}

/// 双向共享的内层流量嗅探状态（dae `FilterTLS` 移植）。
struct SniffState {
    packets_to_filter: u32,
    is_tls: bool,
    enable_xtls: bool,
    cipher: u16,
    remaining_server_hello: usize,
    outer_tls13: bool,
}

/// 读写两半共享：内层 TLS 是否是「可用 XTLS DIRECT 的 TLS 1.3」。
pub struct TlsSniffer {
    state: Mutex<SniffState>,
}

#[derive(Clone, Copy)]
pub struct SniffSnapshot {
    pub is_tls: bool,
    pub enable_xtls: bool,
    pub packets_to_filter: u32,
}

impl TlsSniffer {
    /// `outer_tls13`：外层是否 TLS 1.3（XTLS DIRECT 的硬前提）。
    pub fn new(outer_tls13: bool) -> Self {
        TlsSniffer {
            state: Mutex::new(SniffState {
                packets_to_filter: 6,
                is_tls: false,
                enable_xtls: false,
                cipher: 0,
                remaining_server_hello: 0,
                outer_tls13,
            }),
        }
    }

    /// 喂入一段（任一方向的）内层字节。
    pub fn filter(&self, buf: &[u8]) {
        let mut st = match self.state.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        if st.packets_to_filter == 0 || buf.is_empty() {
            return;
        }
        st.packets_to_filter -= 1;
        let len_p = buf.len();
        let mut index: i64 = -1;
        if let Some(i) = find(buf, &TLS_SERVER_HELLO_START) {
            index = i as i64;
            if len_p > i + 5 && buf[0] == 22 && buf[1] == 3 && buf[2] == 3 {
                st.is_tls = true;
                if buf[i + 5] == 0x02 {
                    // ServerHello：记录总长 = len+5；从固定偏移取 cipher。
                    st.remaining_server_hello =
                        u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize + 5;
                    if len_p - i >= 79 && st.remaining_server_hello >= 79 {
                        let sid_len = buf[i + 43] as usize;
                        let cipher_off = i + 44 + sid_len;
                        // RSV8446：session_id 长度必须 ≤32，否则跳过 cipher 识别（保守失败）。
                        if sid_len <= 32 && cipher_off + 2 <= len_p {
                            st.cipher = u16::from_be_bytes([buf[cipher_off], buf[cipher_off + 1]]);
                        }
                    } else {
                        st.remaining_server_hello = 0;
                    }
                }
            }
        } else if let Some(i) = find(buf, &TLS_CLIENT_HELLO_START) {
            index = i as i64;
            if len_p > i + 5 && buf[i + 5] == 0x01 {
                st.is_tls = true;
            }
        }
        if st.remaining_server_hello > 0 {
            let i = if index < 0 { 0usize } else { index as usize };
            let want = st.remaining_server_hello;
            let segment_end;
            if i + want > len_p {
                segment_end = len_p;
                st.remaining_server_hello -= len_p - i;
            } else {
                st.remaining_server_hello -= want;
                segment_end = i + want;
            }
            if find(&buf[i..segment_end], &TLS13_SUPPORTED_VERSIONS).is_some() {
                if st.outer_tls13 && xtls_cipher_ok(st.cipher) {
                    st.enable_xtls = true;
                }
                st.packets_to_filter = 0;
            } else if st.remaining_server_hello == 0 {
                st.packets_to_filter = 0;
            }
        }
    }

    pub fn snapshot(&self) -> SniffSnapshot {
        let st = match self.state.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        SniffSnapshot {
            is_tls: st.is_tls,
            enable_xtls: st.enable_xtls,
            packets_to_filter: st.packets_to_filter,
        }
    }
}

/// Vision 读半：解析下行帧；收到 0x02 后经 `read_raw` 让 TLS 层裸读。
pub struct VisionReader<R> {
    inner: R,
    uuid: [u8; 16],
    first: bool,
    remaining_content: usize,
    remaining_padding: usize,
    /// 当前帧内容/填充耗尽后要进入的状态。
    after: Option<u8>,
    passthrough: bool,
    read_raw: Arc<AtomicBool>,
    sniffer: Arc<TlsSniffer>,
    hdr: [u8; HEADER_LEN_UUID],
    /// stage 2：帧头已读字节数（非阻塞 WO 后从断点续读，不丢进度）。
    hdr_got: usize,
    logged_direct: bool,
}

impl<R: Read> VisionReader<R> {
    pub fn new(
        inner: R,
        uuid: [u8; 16],
        read_raw: Arc<AtomicBool>,
        sniffer: Arc<TlsSniffer>,
    ) -> Self {
        VisionReader {
            inner,
            uuid,
            first: true,
            remaining_content: 0,
            remaining_padding: 0,
            after: None,
            passthrough: false,
            read_raw,
            sniffer,
            hdr: [0u8; HEADER_LEN_UUID],
            hdr_got: 0,
            logged_direct: false,
        }
    }

    fn read_frame_header(&mut self) -> io::Result<Option<(u8, usize, usize)>> {
        let need = if self.first {
            HEADER_LEN_UUID
        } else {
            HEADER_LEN
        };
        while self.hdr_got < need {
            let n = self.inner.read(&mut self.hdr[self.hdr_got..need])?;
            if n == 0 {
                if self.hdr_got == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vision: 帧头读取中断",
                ));
            }
            self.hdr_got += n;
        }
        self.hdr_got = 0;
        let mut off = 0usize;
        if self.first {
            if self.hdr[..16] != self.uuid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vision: 服务端回显 UUID 不匹配",
                ));
            }
            self.first = false;
            off = 16;
        }
        let cmd = self.hdr[off];
        let content = u16::from_be_bytes([self.hdr[off + 1], self.hdr[off + 2]]) as usize;
        let padding = u16::from_be_bytes([self.hdr[off + 3], self.hdr[off + 4]]) as usize;
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
                // 内层流量嗅探：内容真正的载体（dae 在 readRemainingContent 分支喂 FilterTLS）。
                self.sniffer.filter(&buf[..got]);
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
                        // XTLS DIRECT：TLS 读半切裸 TCP（tls.rs/tls13.rs 的 raw 开关）。
                        if !self.logged_direct {
                            self.logged_direct = true;
                            eprintln!("[sodama] vision: 下行 DIRECT 切换（裸 TCP 直通）");
                        }
                        self.read_raw.store(true, Ordering::SeqCst);
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

/// Vision 写半：首帧带 UUID；内层 TLS 1.3 确认后发 0x02 并切裸写（XTLS DIRECT），
/// 否则窗口结束发 0x01（保持外层协议，仅少一项优化）。
pub struct VisionWriter<W> {
    inner: W,
    uuid: [u8; 16],
    first: bool,
    finished: bool,
    write_raw: Arc<AtomicBool>,
    sniffer: Arc<TlsSniffer>,
    logged_direct: bool,
    /// stage 2：已组帧待写出的字节（非阻塞下部分写；组帧状态已在入队时推进）。
    out: Vec<u8>,
    out_off: usize,
    /// DIRECT 帧已入队：待 out 清空后再置 write_raw（0x02 不越位）。
    pending_direct: bool,
}

impl<W: Write> VisionWriter<W> {
    pub fn new(
        inner: W,
        uuid: [u8; 16],
        write_raw: Arc<AtomicBool>,
        sniffer: Arc<TlsSniffer>,
    ) -> Self {
        VisionWriter {
            inner,
            uuid,
            first: true,
            finished: false,
            write_raw,
            sniffer,
            logged_direct: false,
            out: Vec::new(),
            out_off: 0,
            pending_direct: false,
        }
    }

    pub fn inner(&self) -> &W {
        &self.inner
    }
}

impl<W: Write> Write for VisionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // 先冲刷上次组帧；未清空前不消费新明文（非阻塞 WO 重试幂等）。
        self.drain_out()?;
        if self.finished {
            return self.inner.write(buf);
        }
        // 帧头 contentLen 是 u16：单帧内容最大 65535；按 16KB 分帧（与 dae 的
        // 分段写行为一致；一次 write(128KB) 若不分帧会把长度截断为 0）。
        let mut off = 0usize;
        while off < buf.len() {
            let end = (off + 16384).min(buf.len());
            self.queue_frame(&buf[off..end]);
            off = end;
            if self.finished && off < buf.len() {
                match self.drain_out() {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(off),
                    Err(e) => return Err(e),
                }
                let n = self.inner.write(&buf[off..])?;
                return Ok(off + n);
            }
        }
        // 尽力写出；WO 时留在 out，由 flush() 续写（明文已接受并组帧）。
        match self.drain_out() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain_out()?;
        self.inner.flush()
    }
}

impl<W: Write> VisionWriter<W> {
    /// 写出 `out` 中未发出的帧；写空后应用 DIRECT 置位（保证 0x02 帧先出）。
    fn drain_out(&mut self) -> io::Result<()> {
        while self.out_off < self.out.len() {
            match self.inner.write(&self.out[self.out_off..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision: inner 写 0",
                    ))
                }
                Ok(n) => self.out_off += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.out.clear();
        self.out_off = 0;
        if self.pending_direct {
            self.pending_direct = false;
            if !self.logged_direct {
                self.logged_direct = true;
                eprintln!("[sodama] vision: 上行 DIRECT 切换（裸 TCP 直写）");
            }
            self.write_raw.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

impl<W: Write> VisionWriter<W> {
    fn queue_frame(&mut self, buf: &[u8]) {
        debug_assert!(buf.len() <= u16::MAX as usize);
        // 先喂嗅探器（与 dae 相同：本块决定本条命令）。
        self.sniffer.filter(buf);
        let sn = self.sniffer.snapshot();
        let is_tls = sn.is_tls || looks_tls(buf);
        let first = self.first;
        let mut direct = false;
        let cmd;
        if first {
            // 首帧恒 0x00（UUID 在本帧里）。
            self.first = false;
            cmd = CMD_CONTINUE;
        } else if !is_tls {
            cmd = CMD_END;
            self.finished = true;
        } else if looks_tls_app_data(buf) || sn.packets_to_filter == 0 {
            if sn.enable_xtls {
                cmd = CMD_DIRECT;
                direct = true;
            } else {
                cmd = CMD_END;
            }
            self.finished = true;
        } else {
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
        self.out.extend_from_slice(&frame);
        if direct {
            // 帧（含填充）全部写出后才置位裸写（下一笔起生效）。
            self.pending_direct = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn sniff_pair(outer_tls13: bool) -> Arc<TlsSniffer> {
        Arc::new(TlsSniffer::new(outer_tls13))
    }

    /// 构造内层 TLS 1.3 ServerHello（含 32B compat session_id 与 supported_versions），
    /// 喂给嗅探器。
    fn inner_server_hello_tls13() -> Vec<u8> {
        // 记录头 5B + handshake 头 4B + version 2 + random 32 + sid_len 1 + sid 32
        // + cipher 2 + comp 1 + ext_len 2 + supported_versions ext 6
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy version
        body.extend_from_slice(&[0xAAu8; 32]); // random
        body.push(32); // session_id len（TLS1.3 compat echo）
        body.extend_from_slice(&[0x5Au8; 32]);
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x00); // compression
        body.extend_from_slice(&[0x00, 0x06]); // ext total len
        body.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        let mut hs = Vec::new();
        hs.push(0x02); // ServerHello
        let hs_len = body.len();
        hs.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        hs.extend_from_slice(&body);
        let mut rec = Vec::new();
        rec.extend_from_slice(&[0x16, 0x03, 0x03]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sniffer_detects_inner_tls13() {
        let s = sniff_pair(true);
        s.filter(&inner_server_hello_tls13());
        let sn = s.snapshot();
        assert!(sn.is_tls);
        assert!(sn.enable_xtls, "内层 TLS1.3 + 支持 cipher 应启用 XTLS");
        assert_eq!(sn.packets_to_filter, 0);
    }

    #[test]
    fn sniffer_outer_tls12_never_enables_xtls() {
        let s = sniff_pair(false);
        s.filter(&inner_server_hello_tls13());
        let sn = s.snapshot();
        assert!(sn.is_tls);
        assert!(!sn.enable_xtls, "外层非 TLS1.3 不允许 DIRECT");
    }

    #[test]
    fn sniffer_detects_inner_client_hello_only_as_tls() {
        let s = sniff_pair(true);
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x40, 0x01];
        ch.extend_from_slice(&[0u8; 64]);
        s.filter(&ch);
        let sn = s.snapshot();
        assert!(sn.is_tls);
        assert!(!sn.enable_xtls, "ClientHello 不足以启用 XTLS");
    }

    #[test]
    fn writer_reader_roundtrip() {
        // 内存通道：writer 写 → reader 读（不含 direct）。
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let uuid = [7u8; 16];
        let read_raw = Arc::new(AtomicBool::new(false));
        let write_raw = Arc::new(AtomicBool::new(false));
        let mut w = VisionWriter::new(a, uuid, write_raw.clone(), sniff_pair(true));
        let mut r = VisionReader::new(b, uuid, read_raw.clone(), sniff_pair(true));
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
        assert!(!read_raw.load(Ordering::SeqCst));
        assert!(!write_raw.load(Ordering::SeqCst));
    }

    #[test]
    fn writer_sends_end_for_non_tls() {
        // 过滤窗口内出现非 TLS 数据：发 0x01 后裸（保持外层）直写。
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let uuid = [9u8; 16];
        let write_raw = Arc::new(AtomicBool::new(false));
        let mut w = VisionWriter::new(a, uuid, write_raw.clone(), sniff_pair(true));
        w.write_all(b"GET / HTTP/1.1\r\n").unwrap(); // 首帧 0x00
        w.write_all(b"more plain http").unwrap(); // 非 TLS → 0x01
        w.write_all(b"RAW").unwrap();
        w.flush().unwrap();
        drop(w);
        let mut wire = Vec::new();
        let mut r = b;
        r.read_to_end(&mut wire).unwrap();
        let mut off = 0usize;
        let mut frames = 0usize;
        loop {
            let hdr = if frames == 0 { 21 } else { 5 };
            if wire.len() < off + hdr {
                break;
            }
            let (cmd, clen_off, pad_off) = if frames == 0 {
                (wire[off + 16], off + 17, off + 19)
            } else {
                (wire[off], off + 1, off + 3)
            };
            let clen = u16::from_be_bytes([wire[clen_off], wire[clen_off + 1]]) as usize;
            let pad = u16::from_be_bytes([wire[pad_off], wire[pad_off + 1]]) as usize;
            off += hdr + clen + pad;
            if cmd == CMD_END {
                break;
            }
            frames += 1;
        }
        assert_eq!(&wire[off..], b"RAW", "CMD_END 之后必须是裸字节");
        assert!(!write_raw.load(Ordering::SeqCst), "非 XTLS 不得切裸写");
    }

    #[test]
    fn writer_direct_after_inner_tls13() {
        // 窗口内看到内层 TLS1.3 ServerHello + 应用数据 → 0x02 并置 write_raw。
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let uuid = [5u8; 16];
        let write_raw = Arc::new(AtomicBool::new(false));
        let sniffer = sniff_pair(true);
        // 预置嗅探状态：模拟 ServerHello 已在下行被看到。
        sniffer.filter(&inner_server_hello_tls13());
        assert!(sniffer.snapshot().enable_xtls);
        let mut w = VisionWriter::new(a, uuid, write_raw.clone(), sniffer);
        w.write_all(&[0x16, 0x03, 0x01, 0, 0]).unwrap(); // 首帧 0x00
                                                         // 下一笔 TLS 应用数据 + packets_to_filter 已为 0 → 0x02
        w.write_all(&[0x17, 0x03, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
            .unwrap();
        assert!(
            write_raw.load(Ordering::SeqCst),
            "TLS1.3 内层确认后应切裸写"
        );
        w.write_all(b"RAWDATA").unwrap(); // finished，直写
        w.flush().unwrap();
        drop(w);
        let mut wire = Vec::new();
        let mut r = b;
        r.read_to_end(&mut wire).unwrap();
        // 解析首帧与次帧，确认次帧 cmd=0x02 且其后是裸字节。
        let first_hdr = 21;
        let clen0 = u16::from_be_bytes([wire[17], wire[18]]) as usize;
        let pad0 = u16::from_be_bytes([wire[19], wire[20]]) as usize;
        let off1 = first_hdr + clen0 + pad0;
        assert_eq!(wire[off1], CMD_DIRECT);
        let clen1 = u16::from_be_bytes([wire[off1 + 1], wire[off1 + 2]]) as usize;
        let pad1 = u16::from_be_bytes([wire[off1 + 3], wire[off1 + 4]]) as usize;
        let off2 = off1 + 5 + clen1 + pad1;
        assert_eq!(&wire[off2..], b"RAWDATA");
    }

    #[test]
    fn reader_handles_direct_switch() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let uuid = [3u8; 16];
        let read_raw = Arc::new(AtomicBool::new(false));
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
        let mut r = VisionReader::new(b, uuid, read_raw.clone(), sniff_pair(true));
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
        assert!(read_raw.load(Ordering::SeqCst));
    }

    /// stage 2：注入 WouldBlock 的写半——wire 输出应与干净写逐字节一致。
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
                    return Err(io::ErrorKind::WouldBlock.into());
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
        let uuid = [5u8; 16];
        let payload: Vec<u8> = (0..30000u32).map(|i| (i % 253) as u8).collect();
        // WO 注入写：模拟 reactor codec 引擎（WO → flush 重试）
        let mut w = VisionWriter::new(
            WobWrite {
                out: Vec::new(),
                block_next: false,
                cap: 7,
            },
            uuid,
            Arc::new(AtomicBool::new(false)),
            sniff_pair(true),
        );
        let mut off = 0usize;
        let mut guard = 0u32;
        while off < payload.len() && guard < 2_000_000 {
            guard += 1;
            match w.write(&payload[off..]) {
                Ok(n) => off += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let _ = w.flush();
                }
                Err(e) => panic!("非预期错误: {e}"),
            }
        }
        loop {
            match w.flush() {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("非预期错误: {e}"),
            }
        }
        assert_eq!(off, payload.len());
        // 填充长度随机（防指纹），不能按 wire 字节比对：用读半把 WO 注入下的
        // wire 还原为原 payload（帧头跨多次 read 不丢进度）。
        let wire = w.inner().out.clone();
        let mut r = VisionReader::new(
            wire.as_slice(),
            uuid,
            Arc::new(AtomicBool::new(false)),
            sniff_pair(true),
        );
        let mut round = Vec::new();
        let mut guard = 0u32;
        loop {
            guard += 1;
            assert!(guard < 2_000_000, "读循环未收敛");
            let mut b = [0u8; 4096];
            match r.read(&mut b) {
                Ok(0) => break,
                Ok(n) => round.extend_from_slice(&b[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("非预期错误: {e}"),
            }
        }
        assert_eq!(round, payload, "WO 注入下 payload 应逐字节还原");
    }

    /// stage 2：注入 WouldBlock 的读半——帧头跨多次 read 不丢进度。
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
                    return Err(io::ErrorKind::WouldBlock.into());
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
        let uuid = [6u8; 16];
        let payload: Vec<u8> = (0..8000u32).map(|i| (i % 241) as u8).collect();
        // 干净写生成 wire
        let mut wire = Vec::new();
        {
            let mut w = VisionWriter::new(
                &mut wire,
                uuid,
                Arc::new(AtomicBool::new(false)),
                sniff_pair(true),
            );
            w.write_all(&payload).unwrap();
            w.flush().unwrap();
        }
        // WO 注入读还原
        let mut r = VisionReader::new(
            WobRead {
                data: &wire,
                pos: 0,
                block_next: false,
            },
            uuid,
            Arc::new(AtomicBool::new(false)),
            sniff_pair(true),
        );
        let mut out = Vec::new();
        let mut guard = 0u32;
        loop {
            guard += 1;
            assert!(guard < 2_000_000, "读循环未收敛");
            let mut buf = [0u8; 512];
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("非预期错误: {e}"),
            }
        }
        assert_eq!(out, payload);
    }
}

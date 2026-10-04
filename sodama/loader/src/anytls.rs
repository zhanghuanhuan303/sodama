// SPDX-License-Identifier: GPL-2.0
//! P11：AnyTLS 客户端（anytls-go 协议 v2；单 Stream，无会话复用）。
//!
//! wire（对照 anytls-go `docs/protocol.md` 与 `proxy/session/session.go`）：
//! - 认证：[sha256(password) 32B][padding0 len BE16][padding0]（默认 scheme `0=30-30`）；
//! - 帧：`[cmd 1B][sid BE32][len BE16][data]`；
//!   cmd: 0=Waste 1=SYN 2=PSH 3=FIN 4=Settings 5=Alert 6=UpdatePaddingScheme
//!        7=SYNACK 8=HeartRequest 9=HeartResponse 10=ServerSettings；
//! - 客户端首包 = Settings(v2/client/padding-md5) + SYN + PSH(SocksAddr) 批量一次写
//!   （对应 scheme 的 pkt 1），之后每次 `write` 一帧并按 paddingScheme 打散/填充；
//! - 服务器可用 UpdatePaddingScheme 下发给后续**新建会话**；本实现单会话，收到即生效；
//! - 边界（如实）：不实现会话复用（每次拨号一条 TLS + 一条 Stream）；UDP（udp-over-tcp v2）
//!   不做（Outbound 层走直连回退）；FIN 只在读方向处理，写方向半关闭直接 FIN TCP
//!   （单会话下与关闭整条连接等价）；HeartRequest 回 HeartResponse。

use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use md5::{Digest as _, Md5};
use rand::Rng as _;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const HEADER: usize = 7;
/// 单 Stream 会话固定 stream id。
const SID: u32 = 1;
const CLIENT_NAME: &str = "sodama/0.1.0";

/// 默认 paddingScheme（与 anytls-go `proxy/padding/padding.go` 逐字节一致，137 字节）。
pub const DEFAULT_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

#[derive(Clone, Debug, PartialEq, Eq)]
enum PktSpec {
    Range(u16, u16),
    CheckMark,
}

/// 解析后的 paddingScheme（`stop=N` + 若干 `pkt=a-b,c,...` 规则）。
#[derive(Clone, Debug)]
pub struct PaddingScheme {
    stop: u32,
    rules: HashMap<u32, Vec<PktSpec>>,
    md5: String,
}

impl PaddingScheme {
    pub fn parse(raw: &str) -> Option<Self> {
        let md5 = format!("{:x}", Md5::digest(raw.as_bytes()));
        let mut stop: Option<u32> = None;
        let mut rules: HashMap<u32, Vec<PktSpec>> = HashMap::new();
        for line in raw.split('\n') {
            let line = line.trim_end_matches('\r');
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            if k == "stop" {
                stop = v.trim().parse::<u32>().ok();
                continue;
            }
            let Ok(pkt) = k.trim().parse::<u32>() else {
                continue;
            };
            let mut specs = Vec::new();
            for part in v.trim().split(',') {
                if part == "c" {
                    specs.push(PktSpec::CheckMark);
                    continue;
                }
                if let Some((a, b)) = part.split_once('-') {
                    if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                        let (lo, hi) = (a.min(b), a.max(b));
                        if lo > 0 {
                            specs.push(PktSpec::Range(lo, hi));
                        }
                    }
                }
            }
            rules.insert(pkt, specs);
        }
        Some(Self {
            stop: stop?,
            rules,
            md5,
        })
    }

    pub fn default_scheme() -> Self {
        Self::parse(DEFAULT_SCHEME).expect("默认 padding scheme 必须可解析")
    }

    fn pkt_sizes(&self, pkt: u32) -> Vec<PktSpec> {
        self.rules.get(&pkt).cloned().unwrap_or_default()
    }
}

fn rand_in(lo: u16, hi: u16) -> usize {
    if hi <= lo {
        lo as usize
    } else {
        rand::thread_rng().gen_range(lo..hi) as usize
    }
}

struct Shared {
    padding: PaddingScheme,
    /// 待写控制帧（如 HeartResponse），由写半在下次写时带出。
    pending_controls: Vec<Vec<u8>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER + data.len());
    v.push(cmd);
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// RFC1928 SocksAddr（IPv4 / 域名）。
fn socks_addr(target: &crate::target::Target) -> io::Result<Vec<u8>> {
    let mut v = Vec::with_capacity(7 + 259);
    target.encode_socks_addr_port(&mut v)?;
    Ok(v)
}

pub struct AnyTlsWriter<W> {
    inner: W,
    shared: Arc<Mutex<Shared>>,
    pkt: u32,
    send_padding: bool,
    /// M4 stage 2：已组帧未写出的字节（WO 断点续写，padding 只打散一次）。
    out: Vec<u8>,
    out_off: usize,
}

impl<W: Write> AnyTlsWriter<W> {
    /// 暴露底层写半（outbound 的 `WriteHalf::shutdown_write` 需要）。
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// 把 `out` 中未写出的字节写到内层；WO/EINTR 时保留偏移（重试幂等）。
    fn drain_out(&mut self) -> io::Result<()> {
        while self.out_off < self.out.len() {
            match self.inner.write(&self.out[self.out_off..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "anytls: 内层写 0")),
                Ok(n) => self.out_off += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.out.clear();
        self.out_off = 0;
        Ok(())
    }

    /// 尽力冲刷：WO 视为「已接受」——字节留在 out，等 EPOLLOUT/下次 flush 续写。
    fn try_drain(&mut self) -> io::Result<()> {
        match self.drain_out() {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            r => r,
        }
    }

    /// 会话层组帧：带 paddingScheme 的打散/填充（对照 anytls-go `writeConn`）。
    /// 只把字节追加进 `out`（无 IO）；pkt 计数与随机量不重放。
    fn build_session(&mut self, bytes: &[u8]) {
        if !self.send_padding {
            self.out.extend_from_slice(bytes);
            return;
        }
        self.pkt += 1;
        let scheme = lock(&self.shared).padding.clone();
        if self.pkt >= scheme.stop {
            self.send_padding = false;
            self.out.extend_from_slice(bytes);
            return;
        }
        let mut b: &[u8] = bytes;
        for spec in scheme.pkt_sizes(self.pkt) {
            let remain = b.len();
            match spec {
                PktSpec::CheckMark => {
                    if remain == 0 {
                        break;
                    }
                }
                PktSpec::Range(lo, hi) => {
                    let l = rand_in(lo, hi);
                    if remain > l {
                        // 本包全是载荷
                        self.out.extend_from_slice(&b[..l]);
                        b = &b[l..];
                    } else if remain > 0 {
                        // 载荷 + 填充一个 waste 帧，凑满 l 字节
                        let padding_len = l.saturating_sub(remain + HEADER);
                        self.out.extend_from_slice(b);
                        if padding_len > 0 {
                            self.out.extend_from_slice(&waste_frame(padding_len));
                        }
                        b = &[];
                    } else {
                        // 整包填充
                        self.out.extend_from_slice(&waste_frame(l));
                    }
                }
            }
        }
        if !b.is_empty() {
            self.out.extend_from_slice(b);
        }
    }

    /// 取出待写控制帧并组帧入队（mem::take 取走一次，幂等）。
    fn queue_controls(&mut self) {
        let frames = {
            let mut s = lock(&self.shared);
            std::mem::take(&mut s.pending_controls)
        };
        for f in frames {
            self.build_session(&f);
        }
    }
}

fn waste_frame(payload_len: usize) -> Vec<u8> {
    let mut v = vec![0u8; HEADER + payload_len];
    v[0] = CMD_WASTE;
    // sid = 0
    v[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    v
}

impl<W: Write> Write for AnyTlsWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.queue_controls();
        // 先冲刷上次组帧；未清空前不消费新明文（WO 重试幂等）。
        self.drain_out()?;
        let mut off = 0;
        while off < buf.len() {
            let n = (buf.len() - off).min(u16::MAX as usize);
            let fr = frame(CMD_PSH, SID, &buf[off..off + n]);
            self.build_session(&fr);
            off += n;
        }
        // 尽力写出；WO 时帧留在 out，由 flush()/下次 write 续写（明文已接受）。
        self.try_drain()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.queue_controls();
        self.drain_out()?;
        self.inner.flush()
    }
}

pub struct AnyTlsReader<R> {
    inner: R,
    shared: Arc<Mutex<Shared>>,
    pending: Vec<u8>,
    pos: usize,
    /// M4 stage 2：原始帧字节缓冲（帧头/载荷跨 WO 续读，进度不丢）。
    inbuf: Vec<u8>,
    inoff: usize,
    eof: bool,
}

impl<R: Read> AnyTlsReader<R> {
    /// 从 inbuf 解析一帧；不足则读入更多。
    /// Ok(None)：非阻塞暂无完整帧且 `eof` 未置位，或流在帧边界 EOF（`eof` 置位）。
    fn poll_frame(&mut self) -> io::Result<Option<(u8, u32, Vec<u8>)>> {
        loop {
            let avail = self.inbuf.len() - self.inoff;
            if avail >= HEADER {
                let (cmd, sid, len) = {
                    let hdr = &self.inbuf[self.inoff..self.inoff + HEADER];
                    (
                        hdr[0],
                        u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]),
                        u16::from_be_bytes([hdr[5], hdr[6]]) as usize,
                    )
                };
                if avail >= HEADER + len {
                    let start = self.inoff + HEADER;
                    let data = self.inbuf[start..start + len].to_vec();
                    self.inoff += HEADER + len;
                    if self.inoff == self.inbuf.len() {
                        self.inbuf.clear();
                        self.inoff = 0;
                    }
                    return Ok(Some((cmd, sid, data)));
                }
            }
            // 需更多字节：保留未消费前缀，继续读。
            if self.inoff > 0 {
                self.inbuf.drain(..self.inoff);
                self.inoff = 0;
            }
            let mut tmp = [0u8; 16 * 1024];
            match self.inner.read(&mut tmp) {
                Ok(0) => {
                    if self.inbuf.is_empty() {
                        self.eof = true;
                        return Ok(None);
                    }
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "anytls: 帧被截断"));
                }
                Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
}

impl<R: Read> Read for AnyTlsReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.eof {
            return Ok(0);
        }
        loop {
            if self.pos < self.pending.len() {
                let n = buf.len().min(self.pending.len() - self.pos);
                buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                if self.pos == self.pending.len() {
                    self.pending.clear();
                    self.pos = 0;
                }
                return Ok(n);
            }
            let Some((cmd, sid, data)) = self.poll_frame()? else {
                if self.eof {
                    return Ok(0);
                }
                // 非阻塞：帧未收齐。进度保留在 inbuf；上抛 WO（绝不能误报 EOF）。
                return Err(io::Error::new(ErrorKind::WouldBlock, "anytls: 帧未收齐"));
            };
            match cmd {
                CMD_PSH => {
                    if sid == SID && !data.is_empty() {
                        self.pending = data;
                    }
                    // 非本流/空 PSH：等到下面循环继续
                }
                CMD_FIN => {
                    self.eof = true;
                    return Ok(0);
                }
                CMD_WASTE | CMD_HEART_RESPONSE => {}
                CMD_ALERT => {
                    return Err(io::Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("anytls: 服务器 alert: {}", String::from_utf8_lossy(&data)),
                    ))
                }
                CMD_UPDATE_PADDING => {
                    if let Ok(text) = std::str::from_utf8(&data) {
                        if let Some(p) = PaddingScheme::parse(text) {
                            lock(&self.shared).padding = p;
                        }
                    }
                }
                CMD_SERVER_SETTINGS => {
                    // v=2：无需处理（我们只发 v2）
                }
                CMD_SYNACK => {
                    if !data.is_empty() {
                        return Err(io::Error::new(
                            ErrorKind::ConnectionRefused,
                            format!("anytls: SYNACK 错误: {}", String::from_utf8_lossy(&data)),
                        ));
                    }
                }
                CMD_HEART_REQUEST => {
                    let f = frame(CMD_HEART_RESPONSE, sid, &[]);
                    lock(&self.shared).pending_controls.push(f);
                }
                CMD_SYN => {
                    // 服务器不该向单流客户端开新流；忽略
                }
                _ => {}
            }
        }
    }
}

/// 认证 + 首包（Settings/SYN/PSH(目标)）并拆出读写两半。
///
/// `password_sha256` 由 URL 密码预先 SHA-256 得到（避免原文在内存里多次传递）。
pub fn connect_split<R: Read, W: Write>(
    read: R,
    mut write: W,
    password_sha256: &[u8; 32],
    target: &crate::target::Target,
) -> io::Result<(AnyTlsReader<R>, AnyTlsWriter<W>)> {
    let scheme = PaddingScheme::default_scheme();
    let pad0 = scheme
        .pkt_sizes(0)
        .iter()
        .find_map(|s| match s {
            PktSpec::Range(lo, _) => Some(*lo as usize),
            PktSpec::CheckMark => None,
        })
        .unwrap_or(0);
    let shared = Arc::new(Mutex::new(Shared {
        padding: scheme,
        pending_controls: Vec::new(),
    }));

    // 认证：sha256(password) + padding0（默认 scheme 0=30-30）
    let mut auth = Vec::with_capacity(34 + pad0);
    auth.extend_from_slice(password_sha256);
    auth.extend_from_slice(&(pad0 as u16).to_be_bytes());
    auth.resize(34 + pad0, 0);
    write.write_all(&auth)?;

    let mut w = AnyTlsWriter {
        inner: write,
        shared: shared.clone(),
        pkt: 0,
        send_padding: true,
        out: Vec::new(),
        out_off: 0,
    };

    // 首包批：Settings + SYN + PSH(SocksAddr) —— 一帧一条 pkt（含 padding）
    let settings = format!(
        "v=2\nclient={CLIENT_NAME}\npadding-md5={}",
        lock(&shared).padding.md5
    );
    let mut batch = Vec::new();
    batch.extend_from_slice(&frame(CMD_SETTINGS, 0, settings.as_bytes()));
    batch.extend_from_slice(&frame(CMD_SYN, SID, &[]));
    batch.extend_from_slice(&frame(CMD_PSH, SID, &socks_addr(target)?));
    w.build_session(&batch);
    w.drain_out()?;

    Ok((
        AnyTlsReader {
            inner: read,
            shared,
            pending: Vec::new(),
            pos: 0,
            inbuf: Vec::new(),
            inoff: 0,
            eof: false,
        },
        w,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn default_scheme_md5_matches_go() {
        let s = PaddingScheme::default_scheme();
        assert_eq!(s.md5, "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(s.stop, 8);
        assert_eq!(s.pkt_sizes(1), vec![PktSpec::Range(100, 400)]);
        assert_eq!(
            s.pkt_sizes(2),
            vec![
                PktSpec::Range(400, 500),
                PktSpec::CheckMark,
                PktSpec::Range(500, 1000),
                PktSpec::CheckMark,
                PktSpec::Range(500, 1000),
                PktSpec::CheckMark,
                PktSpec::Range(500, 1000),
                PktSpec::CheckMark,
                PktSpec::Range(500, 1000),
            ]
        );
        assert_eq!(s.pkt_sizes(0), vec![PktSpec::Range(30, 30)]);
    }

    /// 内存 mock 服务端：读认证 + 首包批，回 PSH；供 framing 断言。
    fn spawn_mock_server(expected_hash: [u8; 32]) -> (u16, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut auth = [0u8; 34];
            s.read_exact(&mut auth).unwrap();
            assert_eq!(&auth[..32], &expected_hash);
            let pad0 = u16::from_be_bytes([auth[32], auth[33]]) as usize;
            assert_eq!(pad0, 30);
            let mut pad = vec![0u8; pad0];
            s.read_exact(&mut pad).unwrap();
            assert!(pad.iter().all(|b| *b == 0));
            // 首包批：Settings / SYN / PSH(SocksAddr)
            let mut got = Vec::new();
            let mut first_batch_size = 0usize;
            for expect_cmd in [CMD_SETTINGS, CMD_SYN, CMD_PSH] {
                let mut hdr = [0u8; HEADER];
                s.read_exact(&mut hdr).unwrap();
                let cmd = hdr[0];
                let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
                let mut data = vec![0u8; len];
                s.read_exact(&mut data).unwrap();
                assert_eq!(cmd, expect_cmd, "首包批帧序错");
                got.extend_from_slice(&hdr);
                got.extend_from_slice(&data);
                first_batch_size += HEADER + len;
            }
            // 首包批可能带一个 tail waste 帧（pkt1 padding）：短超时探测
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut hdr = [0u8; HEADER];
            match s.read_exact(&mut hdr) {
                Ok(()) => {
                    let len2 = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
                    let mut data2 = vec![0u8; len2];
                    s.read_exact(&mut data2).unwrap();
                    assert_eq!(hdr[0], CMD_WASTE, "首包尾部应为 waste 填充");
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => panic!("探测首包尾部失败: {e}"),
            }
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            // 回一行 PSH 数据
            let reply = frame(CMD_PSH, SID, b"hello-from-server");
            s.write_all(&reply).unwrap();
            // 客户端应发数据 PSH（读到后回显）
            let mut hdr3 = [0u8; HEADER];
            s.read_exact(&mut hdr3).unwrap();
            assert_eq!(hdr3[0], CMD_PSH);
            let len3 = u16::from_be_bytes([hdr3[5], hdr3[6]]) as usize;
            let mut data3 = vec![0u8; len3];
            s.read_exact(&mut data3).unwrap();
            assert_eq!(&data3, b"ping");
            s.write_all(&frame(CMD_FIN, SID, &[])).unwrap();
            let _ = first_batch_size;
            got
        });
        (port, h)
    }

    #[test]
    fn handshake_and_echo_roundtrip() {
        let pw = b"testpass";
        let hash: [u8; 32] = Sha256::digest(pw).into();
        let (port, server) = spawn_mock_server(hash);
        let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let target: crate::target::Target = "1.2.3.4:443".parse().unwrap();
        let (mut r, mut w) =
            connect_split(sock.try_clone().unwrap(), sock, &hash, &target).unwrap();
        let mut buf = [0u8; 64];
        let n = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-from-server");
        w.write_all(b"ping").unwrap();
        w.flush().unwrap();
        let n2 = r.read(&mut buf).unwrap();
        assert_eq!(n2, 0, "FIN 后应 EOF");
        server.join().unwrap();
    }

    #[test]
    fn settings_frame_carries_v2_and_md5() {
        let pw = b"pw";
        let hash: [u8; 32] = Sha256::digest(pw).into();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut auth = [0u8; 64];
            s.read_exact(&mut auth).unwrap();
            let mut hdr = [0u8; HEADER];
            s.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], CMD_SETTINGS);
            let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
            let mut data = vec![0u8; len];
            s.read_exact(&mut data).unwrap();
            String::from_utf8(data).unwrap()
        });
        let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let target: crate::target::Target = "9.9.9.9:80".parse().unwrap();
        let _ = connect_split(sock.try_clone().unwrap(), sock, &hash, &target).unwrap();
        let settings = h.join().unwrap();
        assert!(settings.contains("v=2"), "{settings}");
        assert!(settings.contains("client=sodama/0.1.0"), "{settings}");
        assert!(
            settings.contains("padding-md5=75cff2ad89aadf5e257059ee571ebe11"),
            "{settings}"
        );
    }

    #[test]
    fn update_padding_scheme_applies_to_next_write() {
        let pw = b"pw2";
        let hash: [u8; 32] = Sha256::digest(pw).into();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut auth = [0u8; 64];
            s.read_exact(&mut auth).unwrap();
            // 读掉 Settings/SYN/PSH(addr) + 可能的 pkt1 尾部 waste
            for _ in 0..3 {
                let mut hdr = [0u8; HEADER];
                s.read_exact(&mut hdr).unwrap();
                let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
                let mut d = vec![0u8; len];
                s.read_exact(&mut d).unwrap();
            }
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut hdr = [0u8; HEADER];
            match s.read_exact(&mut hdr) {
                Ok(()) => {
                    let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
                    let mut d = vec![0u8; len];
                    s.read_exact(&mut d).unwrap();
                    assert_eq!(hdr[0], CMD_WASTE);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => panic!("探测首包尾部失败: {e}"),
            }
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            // 下发新 scheme：stop=3，pkt2=64-64（定长便于断言）
            let scheme = "stop=3\n2=64-64";
            s.write_all(&frame(CMD_UPDATE_PADDING, 0, scheme.as_bytes()))
                .unwrap();
            // 发一条数据让客户端 read 处理 update
            s.write_all(&frame(CMD_PSH, SID, b"x")).unwrap();
            // 客户端下一写 = pkt2 → 应恰好 64 字节（帧 + waste 填充，一次性写）
            let mut buf = [0u8; 256];
            let mut total = 0usize;
            while total < 64 {
                let n = s.read(&mut buf[total..]).unwrap();
                assert!(n > 0);
                total += n;
            }
            assert_eq!(total, 64, "pkt2 应按新 scheme 填充到 64 字节");
            // 校验这 64 字节是一帧 PSH("pong") + 一个 waste 帧
            assert_eq!(buf[0], CMD_PSH);
            let len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
            assert_eq!(&buf[7..7 + len], b"pong");
            assert_eq!(buf[7 + len], CMD_WASTE);
            // 不阻塞后续测试：直接关闭
        });
        let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let target: crate::target::Target = "9.9.9.9:80".parse().unwrap();
        let (mut r, mut w) =
            connect_split(sock.try_clone().unwrap(), sock, &hash, &target).unwrap();
        let mut b = [0u8; 8];
        assert_eq!(r.read(&mut b).unwrap(), 1); // 触发 update 解析
        w.write_all(b"pong").unwrap();
        w.flush().unwrap();
        h.join().unwrap();
    }

    /// 跨实现：我们的 anytls 客户端 ↔ sing-box 的 anytls 服务端（本地自签）。
    /// 缺 sing-box / openssl 时跳过（与仓库其它跨实现测试同一约定）。
    #[test]
    fn roundtrip_against_singbox_server() {
        let lab = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lab");
        let cert = lab.join("certs/cert.pem");
        let key = lab.join("certs/key.pem");
        if !cert.exists() || !key.exists() {
            let gen = lab.join("gen-certs.sh");
            if !gen.exists()
                || !std::process::Command::new("bash")
                    .arg(&gen)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            {
                eprintln!("skip: 缺 lab/certs（openssl）");
                return;
            }
        }
        if std::process::Command::new("sing-box")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skip: 未安装 sing-box（跨实现服务端）");
            return;
        }
        // 本地 TCP echo
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_thread = std::thread::spawn(move || {
            let (mut c, _) = echo.accept().unwrap();
            let mut b = [0u8; 1024];
            let n = c.read(&mut b).unwrap();
            c.write_all(&b[..n]).unwrap();
        });
        // sing-box anytls inbound
        let cfg_path = std::env::temp_dir().join(format!("anytls-sb-{}.json", std::process::id()));
        let port = 18446u16;
        let cfg = serde_json::json!({
            "log": {"level": "error"},
            "inbounds": [{
                "type": "anytls", "tag": "in",
                "listen": "127.0.0.1", "listen_port": port,
                "users": [{"name": "u", "password": "testpass"}],
                "tls": {"enabled": true,
                    "certificate_path": cert.to_string_lossy(),
                    "key_path": key.to_string_lossy()}
            }],
            "outbounds": [{"type": "direct"}]
        });
        std::fs::write(&cfg_path, cfg.to_string()).unwrap();
        let child = std::process::Command::new("sing-box")
            .arg("run")
            .arg("-c")
            .arg(&cfg_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(child) = child else {
            eprintln!("skip: sing-box 启动失败");
            return;
        };
        struct Guard(std::process::Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = Guard(child);
        std::thread::sleep(Duration::from_millis(800));

        let hash: [u8; 32] = Sha256::digest(b"testpass").into();
        let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        let (r, w) = crate::tls::connect(sock, "localhost", true, &[], Duration::from_secs(8))
            .expect("tls to sing-box");
        let (mut r, mut w) = connect_split(
            r,
            w,
            &hash,
            &crate::target::Target::from_socket_addr(echo_addr).unwrap(),
        )
        .unwrap();
        w.write_all(b"ping-through-singbox").unwrap();
        w.flush().unwrap();
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        while got.len() < b"ping-through-singbox".len() {
            let n = r.read(&mut buf).expect("read echo");
            assert!(n > 0, "echo 流提前结束");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"ping-through-singbox");
        echo_thread.join().unwrap();
        let _ = std::fs::remove_file(&cfg_path);
    }

    /// 真实订阅节点探针（默认忽略）：
    ///   REAL_ANYTLS_URL='anytls://pass@host:port?sni=...&insecure=1' \
    ///   cargo test --release real_anytls_probe -- --ignored --nocapture
    #[test]
    #[ignore = "需要真实节点环境变量 REAL_ANYTLS_URL"]
    fn real_anytls_probe() {
        let Ok(url) = std::env::var("REAL_ANYTLS_URL") else {
            eprintln!("skip: 未设 REAL_ANYTLS_URL");
            return;
        };
        let target_host =
            std::env::var("REAL_ANYTLS_TARGET").unwrap_or_else(|_| "www.gstatic.com:80".into());
        use std::net::SocketAddr;
        use std::net::ToSocketAddrs as _;
        let target: SocketAddr = target_host
            .to_socket_addrs()
            .expect("解析目标失败")
            .next()
            .expect("目标无结果");
        let ob = crate::outbound::parse(&url).expect("解析 dialer");
        let dial_target = crate::target::Target::from_socket_addr(target).expect("v4 目标");
        let mut d = ob
            .dial_tcp(&dial_target, Duration::from_secs(10))
            .expect("dial anytls");
        if let Some(s) = d.socket.as_ref() {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        }
        let req = format!(
            "GET /generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            target.ip()
        );
        d.to_remote.write_all(req.as_bytes()).unwrap();
        d.to_remote.flush().unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match d.from_remote.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() > 8192 {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break
                }
                Err(e) => panic!("read: {e}"),
            }
        }
        let head = String::from_utf8_lossy(&buf[..buf.len().min(200)]).to_string();
        eprintln!("status head: {}", head.lines().next().unwrap_or("(empty)"));
        assert!(head.starts_with("HTTP/1."), "未拿到 HTTP 响应: {head}");
    }

    // ------------------------------------------------ stage 2：WouldBlock 可重入

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
            let n = buf.len().min(83);
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
            // 限制单次读出量：强制帧头/载荷跨多次 read。
            let n = buf.len().min(5).min(self.data.len() - self.off);
            buf[..n].copy_from_slice(&self.data[self.off..self.off + n]);
            self.off += n;
            Ok(n)
        }
    }

    #[test]
    fn stream_survives_would_block() {
        let wire = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Mutex::new(Shared {
            padding: PaddingScheme::default_scheme(),
            pending_controls: Vec::new(),
        }));
        // 写半：首调就 WO（模拟非阻塞 socket 未就绪），padding 打散只执行一次。
        let mut w = AnyTlsWriter {
            inner: WobWrite {
                wire: wire.clone(),
                block_next: true,
            },
            shared: shared.clone(),
            pkt: 0,
            send_padding: true,
            out: Vec::new(),
            out_off: 0,
        };
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 233) as u8).collect();
        let mut off = 0;
        let mut spins = 0;
        while off < payload.len() {
            match w.write(&payload[off..]) {
                Ok(n) if n > 0 => off += n,
                Ok(_) => panic!("write 返回 0"),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("非预期错误: {e}"),
            }
            spins += 1;
            assert!(spins < 100_000, "WO 重试不收敛");
        }
        loop {
            match w.flush() {
                Ok(()) => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("非预期错误: {e}"),
            }
        }

        // 读半：帧头/载荷跨 WO 续读，waste 帧跳过，PSH 载荷还原。
        let bytes = wire.lock().unwrap().clone();
        let rshared = Arc::new(Mutex::new(Shared {
            padding: PaddingScheme::default_scheme(),
            pending_controls: Vec::new(),
        }));
        let mut r = AnyTlsReader {
            inner: WobRead {
                data: bytes,
                off: 0,
                block_next: false,
            },
            shared: rshared,
            pending: Vec::new(),
            pos: 0,
            inbuf: Vec::new(),
            inoff: 0,
            eof: false,
        };
        let mut got = vec![0u8; payload.len()];
        let mut off = 0;
        let mut spins = 0;
        while off < got.len() {
            match r.read(&mut got[off..]) {
                Ok(0) => panic!("意外 EOF"),
                Ok(n) => off += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("非预期错误: {e}"),
            }
            spins += 1;
            assert!(spins < 200_000, "WO 重试不收敛");
        }
        assert_eq!(got, payload, "anytls WO 往返应逐字节一致");
    }
}

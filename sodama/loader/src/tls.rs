// SPDX-License-Identifier: GPL-2.0
//! P5-G2：可复用的 rustls 客户端（trojan / vless / vmess 共用）。
//!
//! 拆分后的读写两半共享同一个 `ClientConnection`（短锁），底层 TCP 各持一个 fd
//! 副本；阻塞读放在锁外，避免读方向饿死写方向。
//!
//! 读路径不变量：任意两次 `read_tls` 之间必须先抽干 `reader()` 明文。
//! rustls 的明文缓冲默认只有 16KB（`DEFAULT_RECEIVED_PLAINTEXT_LIMIT`）——若连续喂
//! 而不抽，process_new_packets 会因明文满而停摆，随后 read_tls 直接报错（实测 512KB
//! 必现拆连接）。因此未喂完的密文留在复用缓冲中，一次喂一块后回到循环顶部抽明文。
//! M2：socket → 64KB 复用缓冲 → rustls（游标），去掉了旧的「栈 16KB → pending Vec」
//! 两跳拷贝；读块从 16KB 提到 64KB（少 syscall、下游拿到更大明文块）。

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

pub struct TlsReader {
    conn: Arc<Mutex<ClientConnection>>,
    sock: TcpStream,
    eof: bool,
    /// 复用的密文读缓冲（M2：替代「栈 16KB tmp + pending Vec」——每次从 socket 直读
    /// 入缓冲，再以游标喂 rustls，少一次拷贝/扩容），容量 64KB（一次覆盖多条记录）。
    feed: Vec<u8>,
    feed_off: usize,
    feed_len: usize,
    /// M2：kTLS RX 已接管（内核解密）——read 直接读 socket 明文。
    ktls_rx: bool,
    /// M3：Vision 模式——按 TLS 记录边界有界喂入（切换 DIRECT 前不多读一个字节）。
    record_mode: bool,
    /// M3：Vision 下行 DIRECT 开关；置位后先交付 rustls 残留明文，再裸读 TCP。
    raw: Option<Arc<AtomicBool>>,
}

pub struct TlsWriter {
    conn: Arc<Mutex<ClientConnection>>,
    sock: TcpStream,
    /// M2：kTLS TX 已接管（内核加密）——write 直接写 socket 明文。
    ktls_tx: bool,
    /// M3：Vision 上行 DIRECT 开关；置位后写直接落到 socket（不经外层 TLS）。
    raw: Option<Arc<AtomicBool>>,
}

impl TlsWriter {
    /// TLS 无半关闭语义（不发 close_notify，直接 FIN 即可）。
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.sock.shutdown(Shutdown::Write)
    }
}

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // M2：kTLS RX（内核解密）——直接读明文（recvmsg 处理控制记录）。
        if self.ktls_rx {
            return ktls_read(&self.sock, buf);
        }
        // M3：Vision 下行 DIRECT——先交付 rustls 已解出的残留明文（切换前一个字节都
        // 没多读，正常为空），然后裸读 TCP（后续是目标站真实 TLS 记录）。
        if let Some(raw) = self.raw.as_ref() {
            if raw.load(Ordering::SeqCst) {
                {
                    let mut c = self.conn.lock().map_err(poisoned)?;
                    if let Ok(n) = c.reader().read(buf) {
                        if n > 0 {
                            return Ok(n);
                        }
                    }
                }
                return self.sock.read(buf);
            }
        }
        loop {
            // 1) 先抽干已解密明文（有就立刻返回；没有才继续喂密文）
            {
                let mut c = self.conn.lock().map_err(poisoned)?;
                match c.reader().read(buf) {
                    Ok(n) if n > 0 => return Ok(n),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                if self.eof && self.feed_off >= self.feed_len {
                    return Ok(0);
                }
            }
            // 2) 缓冲耗尽则从 socket 补数据（阻塞读在锁外）
            if self.feed_off >= self.feed_len {
                if self.record_mode {
                    if !self.fill_record()? {
                        self.eof = true;
                    }
                } else {
                    let cap = self.feed.len();
                    let n = self.sock.read(&mut self.feed[..cap])?;
                    self.feed_off = 0;
                    self.feed_len = n;
                    if n == 0 {
                        self.eof = true;
                    }
                }
            }
            // 3) 只喂一次 read_tls，然后回到 1) 抽明文
            let mut c = self.conn.lock().map_err(poisoned)?;
            if self.feed_off < self.feed_len {
                let mut cursor: &[u8] = &self.feed[self.feed_off..self.feed_len];
                let used = match c.read_tls(&mut cursor) {
                    Ok(u) => u,
                    // 明文满（有抽干不变量后理论上不会出现）：当作没喂，下一轮先抽明文
                    Err(e) if e.kind() == io::ErrorKind::Other => 0,
                    Err(e) => return Err(e),
                };
                self.feed_off += used;
                if used == 0 {
                    // close_notify 或 EOF：不再有应用数据
                    self.eof = true;
                    self.feed_off = self.feed_len;
                }
            }
            c.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("tls: {e}")))?;
            // TLS 1.3 的回写（KeyUpdate/alert 等）；非阻塞 socket 下 WouldBlock
            // 留待下次读/写活动重试（rustls 缓冲不丢）。
            while c.wants_write() {
                match c.write_tls(&mut self.sock) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

impl TlsReader {
    /// M3：Vision 模式专用的有界读取——保证缓冲内恰好一条完整 TLS 记录，
    /// 绝不多读记录后的字节（socket 上剩下的就是 DIRECT 切换后的裸数据）。
    fn fill_record(&mut self) -> io::Result<bool> {
        // 紧凑到缓冲头部
        if self.feed_off > 0 {
            let len = self.feed_len - self.feed_off;
            self.feed.copy_within(self.feed_off..self.feed_len, 0);
            self.feed_off = 0;
            self.feed_len = len;
        }
        loop {
            let (want, complete) = if self.feed_len >= 5 {
                let len = u16::from_be_bytes([self.feed[3], self.feed[4]]) as usize;
                // 记录荷载上限 2^14（+2048 容忍），64KB 缓冲必然装得下。
                if len > (1 << 14) + 2048 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tls: 记录长度非法（{len}）"),
                    ));
                }
                (5 + len - self.feed_len, self.feed_len >= 5 + len)
            } else {
                (5 - self.feed_len, false)
            };
            if complete {
                return Ok(true);
            }
            if self.feed_len + want > self.feed.len() {
                self.feed.resize(self.feed_len + want, 0);
            }
            let n = self
                .sock
                .read(&mut self.feed[self.feed_len..self.feed_len + want])?;
            if n == 0 {
                return Ok(false);
            }
            self.feed_len += n;
        }
    }

    /// P15：订阅拉取等短连接用——设置底层 socket 读超时。
    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(d)
    }

    /// M2：是否已启用 kTLS RX（内核解密）。
    pub fn is_ktls(&self) -> bool {
        self.ktls_rx
    }
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // M2：kTLS TX（内核加密）——直接写明文。
        if self.ktls_tx {
            return self.sock.write(buf);
        }
        // M3：Vision 上行 DIRECT——裸写 TCP（不再经外层 TLS）。
        if let Some(raw) = self.raw.as_ref() {
            if raw.load(Ordering::SeqCst) {
                return self.sock.write(buf);
            }
        }
        let mut c = self.conn.lock().map_err(poisoned)?;
        let n = c.writer().write(buf)?;
        // 尽力把密文刷到 socket：非阻塞下 WouldBlock 表示「还有缓冲」，
        // 由 flush()/后续事件重试（rustls 已接管明文，不会重复消费）。
        while c.wants_write() {
            match c.write_tls(&mut self.sock) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.ktls_tx {
            return Ok(());
        }
        if let Some(raw) = self.raw.as_ref() {
            if raw.load(Ordering::SeqCst) {
                return Ok(()); // TCP 无用户态缓冲
            }
        }
        let mut c = self.conn.lock().map_err(poisoned)?;
        while c.wants_write() {
            c.write_tls(&mut self.sock)?;
        }
        Ok(())
    }
}

impl TlsWriter {
    /// M2：是否已启用 kTLS TX（内核加密）。
    pub fn is_ktls(&self) -> bool {
        self.ktls_tx
    }
}

fn poisoned<T>(_: T) -> io::Error {
    io::Error::other("tls: 内部锁中毒")
}

fn provider_installed() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// 构造（并缓存）ClientConfig：按 (insecure, alpn) 缓存，无 ALPN 的两种常用
/// 组合是静态 OnceLock，带 ALPN 的按需构建（lab 场景）。
fn tls_config(insecure: bool, alpn: &[Vec<u8>]) -> Arc<ClientConfig> {
    static SECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static ALPN: OnceLock<Mutex<std::collections::HashMap<Vec<Vec<u8>>, Arc<ClientConfig>>>> =
        OnceLock::new();
    provider_installed();
    if !alpn.is_empty() {
        let cache = ALPN.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
        let key = alpn.to_vec();
        let mut map = match cache.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        return map
            .entry(key.clone())
            .or_insert_with(|| build_config(insecure, &key))
            .clone();
    }
    if insecure {
        INSECURE.get_or_init(|| build_config(true, &[])).clone()
    } else {
        SECURE.get_or_init(|| build_config(false, &[])).clone()
    }
}

fn build_config(insecure: bool, alpn: &[Vec<u8>]) -> Arc<ClientConfig> {
    Arc::new(build_rustls_config(insecure, alpn))
}

// ---------------------------------------------------------------- M2：kTLS（内核 TLS）

/// 是否启用 kTLS（`--ktls`）；默认关。
static KTLS_ENABLED: AtomicBool = AtomicBool::new(false);
static KTLS_LOGGED: AtomicBool = AtomicBool::new(false);

pub fn set_ktls_enabled(v: bool) {
    KTLS_ENABLED.store(v, Ordering::Relaxed);
}

#[derive(Default)]
struct KtlsSecrets {
    client: Option<Vec<u8>>,
    server: Option<Vec<u8>>,
}

thread_local! {
    /// 握手线程本地的流量密钥槽（rustls 不暴露 client_random，用线程本地归属并发握手）。
    static KTLS_SINK: RefCell<Option<KtlsSecrets>> = const { RefCell::new(None) };
}

struct KtlsKeyLog;
impl std::fmt::Debug for KtlsKeyLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KtlsKeyLog")
    }
}
impl rustls::KeyLog for KtlsKeyLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        KTLS_SINK.with(|s| {
            if let Some(secrets) = s.borrow_mut().as_mut() {
                match label {
                    "CLIENT_TRAFFIC_SECRET_0" => secrets.client = Some(secret.to_vec()),
                    "SERVER_TRAFFIC_SECRET_0" => secrets.server = Some(secret.to_vec()),
                    _ => {}
                }
            }
        });
    }
    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

/// RFC 8446 §7.1 HKDF-Expand-Label 的 info 构造。
fn hkdf_label_bytes(out_len: usize, label: &str) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    info
}

/// 从 TLS 1.3 流量密钥（secret）导出 key/iv。
fn expand_label(prk: &[u8], label: &str, len: usize, sha384: bool) -> Option<Vec<u8>> {
    let info = hkdf_label_bytes(len, label);
    let mut out = vec![0u8; len];
    if sha384 {
        hkdf::Hkdf::<sha2::Sha384>::from_prk(prk)
            .ok()?
            .expand(&info, &mut out)
            .ok()?;
    } else {
        hkdf::Hkdf::<sha2::Sha256>::from_prk(prk)
            .ok()?
            .expand(&info, &mut out)
            .ok()?;
    }
    Some(out)
}

/// setsockopt(SOL_TLS, opt, crypto_info)。
unsafe fn install_one(
    fd: libc::c_int,
    opt: libc::c_int,
    cipher_type: libc::__u16,
    key: &[u8],
    iv: &[u8],
) -> io::Result<()> {
    use libc::*;
    let rc = match cipher_type {
        TLS_CIPHER_AES_GCM_128 => {
            let mut info = tls12_crypto_info_aes_gcm_128 {
                info: tls_crypto_info {
                    version: TLS_1_3_VERSION,
                    cipher_type,
                },
                iv: [0; 8],
                key: [0; 16],
                salt: [0; 4],
                rec_seq: [0; 8],
            };
            info.salt.copy_from_slice(&iv[..4]);
            info.iv.copy_from_slice(&iv[4..12]);
            info.key.copy_from_slice(key);
            setsockopt(
                fd,
                SOL_TLS,
                opt,
                &info as *const _ as *const c_void,
                std::mem::size_of_val(&info) as socklen_t,
            )
        }
        TLS_CIPHER_AES_GCM_256 => {
            let mut info = tls12_crypto_info_aes_gcm_256 {
                info: tls_crypto_info {
                    version: TLS_1_3_VERSION,
                    cipher_type,
                },
                iv: [0; 8],
                key: [0; 32],
                salt: [0; 4],
                rec_seq: [0; 8],
            };
            info.salt.copy_from_slice(&iv[..4]);
            info.iv.copy_from_slice(&iv[4..12]);
            info.key.copy_from_slice(key);
            setsockopt(
                fd,
                SOL_TLS,
                opt,
                &info as *const _ as *const c_void,
                std::mem::size_of_val(&info) as socklen_t,
            )
        }
        TLS_CIPHER_CHACHA20_POLY1305 => {
            let mut info = tls12_crypto_info_chacha20_poly1305 {
                info: tls_crypto_info {
                    version: TLS_1_3_VERSION,
                    cipher_type,
                },
                iv: [0; 12],
                key: [0; 32],
                salt: [0; TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE],
                rec_seq: [0; 8],
            };
            info.iv.copy_from_slice(&iv[..12]);
            info.key.copy_from_slice(key);
            setsockopt(
                fd,
                SOL_TLS,
                opt,
                &info as *const _ as *const c_void,
                std::mem::size_of_val(&info) as socklen_t,
            )
        }
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported, "ktls: cipher")),
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// M2：kTLS RX 读取——用 recvmsg 处理控制记录：
/// 应用数据直接返回；握手类控制记录（NewSessionTicket，内层类型 22）丢弃后继续；
/// alert（21）视为对端关闭。普通 read() 遇到控制记录会直接报错（内核要求提供 cmsg）。
fn ktls_read(sock: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    #[repr(align(8))]
    struct Ctl([u8; 64]);
    loop {
        let mut ctl = Ctl([0u8; 64]);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctl.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = ctl.0.len() as _;
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // 内核拒绝解密（典型的 EBADMSG=对端 KeyUpdate / 记录序号失配）：无法中途
            // 交回 rustls（其序号状态已断层），只能断连；一次性日志给出抓手。
            static RX_ERR_LOGGED: AtomicBool = AtomicBool::new(false);
            if !RX_ERR_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[sodama] kTLS RX 解密失败（{e}）；若为 EBADMSG，多因对端 KeyUpdate 或记录序号失配（可去掉 --ktls 复测）"
                );
            }
            return Err(e);
        }
        if n == 0 {
            return Ok(0);
        }
        let mut ctl_type: Option<u8> = None;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_TLS
                    && (*cmsg).cmsg_type == libc::TLS_GET_RECORD_TYPE
                {
                    ctl_type = Some(*libc::CMSG_DATA(cmsg));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        match ctl_type {
            None => return Ok(n as usize),
            Some(23) => return Ok(n as usize), // application_data
            Some(21) => return Ok(0),          // alert：视作对端关闭
            Some(t) => {
                if std::env::var("SODAMA_KTLS_DEBUG").is_ok() {
                    eprintln!("[ktls-dbg] rx 控制记录 type={t}（{n}B），丢弃");
                }
                continue; // 其余（22=NST 等）丢弃后继续
            }
        }
    }
}

/// kTLS 专用握手驱动：逐条 TLS 记录喂 rustls，握手完成的一刻立即停止读取。
///
/// 动机：`complete_io` 会按 socket 可读到的字节整块消费——服务端的 NewSessionTicket
/// 常紧跟服务端 Finished 同一批到达，被 rustls 消费后其应用 epoch 记录序号前移，
/// 而内核 RX 从 wire 的 rec_seq=0 起算，两边错位必 EBADMSG（实测）。逐记录驱动把
/// 消费边界卡在「刚处理完服务端 Finished（is_handshaking 变 false）」——此时
/// 后续应用 epoch 记录（NST 等）一个都还没读，全部留给内核 kTLS RX。
///
/// 返回 Ok(()) 表示握手完成且 rustls 未消费任何应用 epoch 记录（RX 可安全安装）。
/// 出错时调用方回退 `complete_io`（此时禁用 RX，仅尝试 TX）。
fn handshake_record_by_record(sock: &TcpStream, conn: &mut ClientConnection) -> io::Result<()> {
    fn flush(conn: &mut ClientConnection, sock: &TcpStream) -> io::Result<()> {
        let mut s = sock;
        while conn.wants_write() {
            conn.write_tls(&mut s)?;
        }
        Ok(())
    }
    fn read_full(mut sock: &TcpStream, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match sock.read(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls: 握手期连接关闭",
                    ))
                }
                Ok(n) => buf = &mut buf[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    flush(conn, sock)?; // ClientHello
    let mut hdr = [0u8; 5];
    let mut rec = Vec::with_capacity(5 + 16384);
    while conn.is_handshaking() {
        read_full(sock, &mut hdr)?;
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        // 合法记录：20=CCS 21=alert 22=handshake 23=appdata；载荷上限 2^14（+2048 容忍）。
        if !(20..=23).contains(&hdr[0]) || len > (1 << 14) + 2048 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tls: 握手记录头非法（type={} len={len}）", hdr[0]),
            ));
        }
        rec.clear();
        rec.extend_from_slice(&hdr);
        rec.resize(5 + len, 0);
        read_full(sock, &mut rec[5..])?;
        let mut cur: &[u8] = &rec;
        while !cur.is_empty() {
            let n = conn.read_tls(&mut cur)?;
            if n == 0 {
                return Err(io::Error::other("tls: read_tls 未消费记录"));
            }
        }
        conn.process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("tls: {e}")))?;
        flush(conn, sock)?;
    }
    Ok(())
}

/// 尝试启用 kTLS（TLS 1.3）：校验握手完成/无待写 → 派生 → 安装。
/// 返回 (tx, rx) 各自是否接管；任何前置条件不满足返回全 false（继续 rustls 路径）。
///
/// `allow_rx`：握手是否由逐记录驱动完成（rustls 未消费任何应用 epoch 记录）。
/// 只有它为 true 才能安装 RX——内核从 wire 的 rec_seq=0 起算，两边必须一致；
/// 控制记录（NST）由 `ktls_read` 的 cmsg 循环丢弃。TX 无此约束，始终可尝试。
fn try_install_ktls(
    sock: &TcpStream,
    conn: &mut ClientConnection,
    secrets: &KtlsSecrets,
    allow_rx: bool,
) -> io::Result<(bool, bool)> {
    let dbg = std::env::var("SODAMA_KTLS_DEBUG").is_ok();
    macro_rules! bail {
        ($($arg:tt)*) => {{
            if dbg { eprintln!("[ktls-dbg] {}", format!($($arg)*)); }
            return Ok((false, false));
        }};
    }
    if conn.is_handshaking() {
        bail!("still handshaking");
    }
    while conn.wants_write() {
        if conn.write_tls(&mut &*sock).is_err() {
            return Ok((false, false));
        }
    }
    // 3) 算法与密钥派生
    let suite = match conn.negotiated_cipher_suite() {
        Some(s) => s.suite(),
        None => bail!("no negotiated suite"),
    };
    let (cipher_type, key_len, sha384) = match suite {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => {
            (libc::TLS_CIPHER_AES_GCM_128, 16usize, false)
        }
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => {
            (libc::TLS_CIPHER_AES_GCM_256, 32usize, true)
        }
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
            (libc::TLS_CIPHER_CHACHA20_POLY1305, 32usize, false)
        }
        _ => bail!("unsupported suite {suite:?}"),
    };
    if dbg {
        eprintln!(
            "[ktls-dbg] suite={suite:?} secrets client={} server={}",
            secrets.client.is_some(),
            secrets.server.is_some()
        );
    }
    let (Some(cs), Some(ss)) = (secrets.client.as_deref(), secrets.server.as_deref()) else {
        bail!("traffic secrets missing");
    };
    let (Some(tx_key), Some(tx_iv), Some(rx_key), Some(rx_iv)) = (
        expand_label(cs, "key", key_len, sha384),
        expand_label(cs, "iv", 12, sha384),
        expand_label(ss, "key", key_len, sha384),
        expand_label(ss, "iv", 12, sha384),
    ) else {
        bail!("hkdf expand failed");
    };
    if dbg {
        fn hx(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        eprintln!("[ktls-dbg] csec={}", hx(cs));
        eprintln!("[ktls-dbg] ssec={}", hx(ss));
        eprintln!("[ktls-dbg] txk={} txi={}", hx(&tx_key), hx(&tx_iv));
        eprintln!("[ktls-dbg] rxk={} rxi={}", hx(&rx_key), hx(&rx_iv));
    }
    let fd = sock.as_raw_fd();
    // kTLS 前置：挂载 TCP_ULP "tls"（需内核模块 tls，`modprobe tls` 或内建）。
    let attach = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_ULP,
            c"tls".as_ptr() as *const libc::c_void,
            4,
        )
    };
    if attach != 0 {
        bail!(
            "TCP_ULP tls 挂载失败（{}；需先 `modprobe tls`）",
            io::Error::last_os_error()
        );
    }
    let tx_res = unsafe { install_one(fd, libc::TLS_TX, cipher_type, &tx_key, &tx_iv) };
    let tx_only = std::env::var("SODAMA_KTLS_TXONLY").is_ok();
    let rx_res: io::Result<()> = if tx_only || !allow_rx {
        Err(io::Error::new(io::ErrorKind::Unsupported, "rx disabled"))
    } else {
        unsafe { install_one(fd, libc::TLS_RX, cipher_type, &rx_key, &rx_iv) }
    };
    if dbg {
        eprintln!(
            "[ktls-dbg] install tx={:?} rx={:?}",
            tx_res.as_ref().err().map(|e| e.to_string()),
            rx_res.as_ref().err().map(|e| e.to_string())
        );
    }
    let tx_ok = tx_res.is_ok();
    let rx_ok = rx_res.is_ok();
    if rx_ok {
        // TLS 1.3 数据记录免填补：直接解密进用户缓冲（对端不打填补时少一次内核拷贝；
        // 误判会被内核重解密并计数；对端可信环境使用）。
        let onep: i32 = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_TLS,
                libc::TLS_RX_EXPECT_NO_PAD,
                &onep as *const i32 as *const libc::c_void,
                4,
            );
        }
    }
    if (tx_ok || rx_ok) && !KTLS_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!("[sodama] kTLS 已启用（内核 TLS；TX={tx_ok} RX={rx_ok}，cipher={suite:?}）");
    }
    Ok((tx_ok, rx_ok))
}

/// 构造 rustls ClientConfig（QUIC/TCP 共用：NoVerify 或 webpki 根 + ALPN）。
pub(crate) fn build_rustls_config(insecure: bool, alpn: &[Vec<u8>]) -> ClientConfig {
    provider_installed();
    let b = rustls::ClientConfig::builder();
    let mut cfg: ClientConfig = if insecure {
        b.dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        b.with_root_certificates(roots).with_no_client_auth()
    };
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.to_vec();
    }
    // M2：KeyLog 钩子（kTLS 需要导出流量密钥；未启用时 sink 为空，开销忽略）。
    cfg.key_log = Arc::new(KtlsKeyLog);
    cfg
}

/// P31（shadow-tls v1）：TLS 1.2-only 的 rustls 配置。v1 服务端的「握手完成」
/// 检测不识别 TLS 1.3 的加密飞行，参考实现也把 v1 客户端锁到 TLS 1.2。
pub(crate) fn build_rustls_config_tls12(insecure: bool, alpn: &[Vec<u8>]) -> ClientConfig {
    provider_installed();
    let versions: &[&'static rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
    let b = rustls::ClientConfig::builder_with_protocol_versions(versions);
    let mut cfg: ClientConfig = if insecure {
        b.dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        b.with_root_certificates(roots).with_no_client_auth()
    };
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.to_vec();
    }
    cfg
}

/// 在已连接的 TCP 上完成 TLS 握手（超时只用于握手期），返回可并发读写的两半。
pub fn connect(
    tcp: TcpStream,
    sni: &str,
    insecure: bool,
    alpn: &[Vec<u8>],
    timeout: Duration,
) -> io::Result<(TlsReader, TlsWriter)> {
    let ((r, w), _) = connect_alpn(tcp, sni, insecure, alpn, timeout)?;
    Ok((r, w))
}

/// P23：同 `connect`，并返回协商出的 ALPN（DoH 据此判断是否走 h2，
/// 避免对 HTTP/1.1 服务端白白发一次 HTTP/2 前言）。
pub fn connect_alpn(
    tcp: TcpStream,
    sni: &str,
    insecure: bool,
    alpn: &[Vec<u8>],
    timeout: Duration,
) -> io::Result<((TlsReader, TlsWriter), Option<Vec<u8>>)> {
    let ((r, w), negotiated, _) = connect_impl(tcp, sni, insecure, alpn, timeout, true, false)?;
    Ok(((r, w), negotiated))
}

/// M3：Vision 专用连接——逐记录有界读 + 双向裸切换句柄；不使用 kTLS
/// （DIRECT 需要中途停用外层加解密，内核 kTLS 无法动态撤销）。
pub struct VisionRaw {
    /// 置位后读半切裸 TCP（对端下行 DIRECT）。
    pub read: Arc<AtomicBool>,
    /// 置位后写半切裸 TCP（本端上行 DIRECT）。
    pub write: Arc<AtomicBool>,
    /// 外层是否 TLS 1.3（XTLS DIRECT 的硬前提；否则只能走 END 模式）。
    pub outer_tls13: bool,
}

pub fn connect_vision(
    tcp: TcpStream,
    sni: &str,
    insecure: bool,
    alpn: &[Vec<u8>],
    timeout: Duration,
) -> io::Result<((TlsReader, TlsWriter), VisionRaw)> {
    let ((r, w), _negotiated, raw) = connect_impl(tcp, sni, insecure, alpn, timeout, false, true)?;
    let raw = raw.ok_or_else(|| io::Error::other("tls: vision 模式未生成 raw 句柄"))?;
    Ok(((r, w), raw))
}

#[allow(clippy::type_complexity)]
fn connect_impl(
    tcp: TcpStream,
    sni: &str,
    insecure: bool,
    alpn: &[Vec<u8>],
    timeout: Duration,
    ktls: bool,
    vision: bool,
) -> io::Result<((TlsReader, TlsWriter), Option<Vec<u8>>, Option<VisionRaw>)> {
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let name = ServerName::try_from(sni.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("sni 非法: {e}")))?
        .to_owned();
    let mut conn = ClientConnection::new(tls_config(insecure, alpn), name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("tls: {e}")))?;

    // 完整握手（阻塞至完成；超时保护来自上面的 socket 选项）
    let want_ktls = ktls && KTLS_ENABLED.load(Ordering::Relaxed);
    // RX 可安装的前提：rustls 严格未消费服务端 Finished 之后的应用 epoch 记录。
    let mut rx_installable = false;
    if want_ktls {
        KTLS_SINK.with(|s| *s.borrow_mut() = Some(KtlsSecrets::default()));
        match handshake_record_by_record(&tcp, &mut conn) {
            Ok(()) => rx_installable = true,
            Err(e) => {
                // 驱动失败（超时/异常记录等）——已读字节都在 rustls 缓冲里，可继续
                // 完整握手；但可能已消费 post-handshake 记录，RX 不可安装，只试 TX。
                let mut sock = &tcp;
                conn.complete_io(&mut sock).map_err(|e2| {
                    io::Error::new(
                        e.kind(),
                        format!("tls 握手失败（逐记录: {e}；complete_io: {e2}）"),
                    )
                })?;
            }
        }
    } else {
        let mut sock = &tcp;
        conn.complete_io(&mut sock)?;
    }

    // 恢复阻塞语义（超时只用于握手期）
    tcp.set_read_timeout(None)?;
    tcp.set_write_timeout(None)?;

    // M2：kTLS（内核 TLS）——成功后读写走内核加解密（明文直读写），并可参与 splice。
    let (ktls_tx, ktls_rx) = if want_ktls {
        let secrets = KTLS_SINK
            .with(|s| s.borrow_mut().take())
            .unwrap_or_default();
        match try_install_ktls(&tcp, &mut conn, &secrets, rx_installable) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => {
                eprintln!("[sodama] kTLS 安装失败，回退 rustls：{e}");
                (false, false)
            }
        }
    } else {
        (false, false)
    };

    let negotiated = conn.alpn_protocol().map(|p| p.to_vec());
    let vision_raw = if vision {
        Some(VisionRaw {
            read: Arc::new(AtomicBool::new(false)),
            write: Arc::new(AtomicBool::new(false)),
            outer_tls13: conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3),
        })
    } else {
        None
    };
    let conn = Arc::new(Mutex::new(conn));
    Ok((
        (
            TlsReader {
                conn: conn.clone(),
                sock: tcp.try_clone()?,
                eof: false,
                feed: vec![0u8; 65536],
                feed_off: 0,
                feed_len: 0,
                ktls_rx,
                record_mode: vision,
                raw: vision_raw.as_ref().map(|v| v.read.clone()),
            },
            TlsWriter {
                conn,
                sock: tcp.try_clone()?,
                ktls_tx,
                raw: vision_raw.as_ref().map(|v| v.write.clone()),
            },
        ),
        negotiated,
        vision_raw,
    ))
}

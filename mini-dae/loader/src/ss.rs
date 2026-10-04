// SPDX-License-Identifier: GPL-2.0
//! P5 G1：Shadowsocks classic AEAD（SIP004）+ Shadowsocks 2022（SIP022）——TCP 流 + UDP。
//!
//! classic 范围与边界（ADR-0016）：
//! - 支持 `aes-256-gcm` 与 `chacha20-ietf-poly1305` 两种 AEAD；
//! - 主密钥 = OpenSSL EVP_BytesToKey(MD5, 无盐, 1 轮)（经典实现，对照 Python
//!   `cryptography` 独立计算验证）；子密钥 = HKDF-SHA1(salt, info="ss-subkey")；
//! - TCP：`[salt][AEAD(len 2B)][AEAD(payload)]...`，nonce 为小端递增计数器；
//! - UDP：每个包 `[salt][AEAD(payload)]`（独立 salt）；
//! - **不做插件、不做 stream ciphers（rc4 等）**。
//!
//! SS2022（SIP022）范围与边界：
//! - 支持 `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` /
//!   `2022-blake3-chacha20-poly1305`；PSK 由用户直接提供（base64），**不做 EVP_BytesToKey**；
//! - 子密钥 = `BLAKE3 derive_key("shadowsocks 2022 session subkey", PSK || salt)`，
//!   按方法密钥长度截断；TCP/RESP nonce = 12B 小端递增计数器；
//! - TCP 请求：`salt | AEAD(type=0,ts,len) | AEAD(addr,padlen,padding[,payload]) | [AEAD(len)|AEAD(payload)]*`；
//!   TCP 响应：`salt | AEAD(type=1,ts,request_salt,len) | AEAD(payload)[,...]`；
//!   固定头与变量头一次 write 发出、一次 read 读出（SIP022 §3.1.3 防探测）；
//! - UDP AES：separate header = AES-ECB(PSK) 加密的 `[session id(8B BE)|packet id(8B BE)]`，
//!   子密钥 = BLAKE3(PSK || session_id)，AEAD nonce = separate header 明文 `[4..16]`；
//! - UDP ChaCha20：`[随机 24B nonce]` + XChaCha20-Poly1305(PSK)，session/packet id 在主头里；
//! - **不做 EIH（可扩展身份头，多用户）**；UDP 只实现客户端角色，收包按
//!   server session id 做滑动窗口重放保护（SIP022 §3.2.4）。
//!
//! 对照：daeuniverse/outbound 无 SS2022，故以
//! shadowsocks-rust `crates/shadowsocks/src/relay/{tcprelay,udprelay}/aead_2022.rs` 与
//! `shadowsocks-crypto` v2 为权威参考；另有由 shadowsocks-crypto 现场生成的密文
//! KAT（见测试），逐字节对拍。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

// `aes::cipher::KeyInit` 与 `aes_gcm::aead::KeyInit` 同为 crypto-common 的 trait，
// 一个导入即覆盖分组密码与 AEAD 的 `new_from_slice`。
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use md5::{Digest as _, Md5};
use rand::RngCore;
use sha1::Sha1;

pub const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MAX_CHUNK: usize = 0x3fff;
/// SIP022：payload 块上限为 u16（0xFFFF），classic 的 0x3FFF 上限不适用。
const MAX_CHUNK_2022: usize = 0xffff;
/// SIP022 §2.2 的子密钥派生 context（与 shadowsocks-crypto 一致）。
const SS2022_KDF_CONTEXT: &str = "shadowsocks 2022 session subkey";
/// SIP022 §3.1.3/§3.2.3：时间戳容差 30 秒（收发两端一致）。
const SS2022_TIMESTAMP_TOLERANCE: u64 = 30;
/// SIP022 §3.1.3：请求头填充上限。
const SS2022_MAX_PADDING: usize = 900;
/// 客户端记住的不同 server session 数上限（SIP022 §3.2.4 要求服务端重启后可换新会话）。
const SS2022_MAX_SERVER_SESSIONS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsMethod {
    Aes256Gcm,
    Chacha20IetfPoly1305,
    // ---- SIP022 ----
    Ss2022Aes128Gcm,
    Ss2022Aes256Gcm,
    Ss2022Chacha20Poly1305,
}

impl SsMethod {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Some(Self::Chacha20IetfPoly1305),
            "2022-blake3-aes-128-gcm" => Some(Self::Ss2022Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Ss2022Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Self::Ss2022Chacha20Poly1305),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Self::Ss2022Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Ss2022Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Ss2022Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    /// classic：salt 固定 32B；SIP022：salt 与密钥等长（§2.2）。
    pub const fn salt_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::Chacha20IetfPoly1305 => 32,
            _ => self.key_len(),
        }
    }

    /// PSK / 会话子密钥长度（SIP022 §2.1：aes-128=16，aes-256/chacha20=32）。
    pub const fn key_len(&self) -> usize {
        match self {
            Self::Ss2022Aes128Gcm => 16,
            _ => 32,
        }
    }

    pub const fn is_2022(&self) -> bool {
        matches!(
            self,
            Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm | Self::Ss2022Chacha20Poly1305
        )
    }

    /// SIP022 UDP 的 AES 构造（separate header + AES-GCM）。
    pub const fn is_2022_aes(&self) -> bool {
        matches!(self, Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm)
    }
}

/// OpenSSL `EVP_BytesToKey(cipher, MD5, salt=NULL, data=password, count=1)`。
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

/// SIP004：HKDF-SHA1(salt, master, info="ss-subkey")。
pub fn derive_subkey(master: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha1>::new(Some(salt), master);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(b"ss-subkey", &mut okm).expect("hkdf expand");
    okm
}

/// SIP022 §2.2：`subkey = BLAKE3::derive_key(context, PSK || salt)`（截断到 key_len）。
///
/// TCP 的 salt 为随机盐；UDP AES 的 salt 为 8B client session id（大端字节）。
fn derive_subkey_2022(method: SsMethod, psk: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let okm = blake3::derive_key(SS2022_KDF_CONTEXT, &material);
    okm[..method.key_len()].to_vec()
}

fn nonce_of(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn seal(method: SsMethod, key: &[u8], nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
    match method {
        SsMethod::Aes256Gcm | SsMethod::Ss2022Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .expect("key len")
            .encrypt(nonce.into(), plain)
            .expect("seal"),
        SsMethod::Ss2022Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .expect("key len")
            .encrypt(nonce.into(), plain)
            .expect("seal"),
        SsMethod::Chacha20IetfPoly1305 | SsMethod::Ss2022Chacha20Poly1305 => {
            ChaCha20Poly1305::new_from_slice(key)
                .expect("key len")
                .encrypt(nonce.into(), plain)
                .expect("seal")
        }
    }
}

fn open(method: SsMethod, key: &[u8], nonce: &[u8; 12], cipher: &[u8]) -> io::Result<Vec<u8>> {
    let r = match method {
        SsMethod::Aes256Gcm | SsMethod::Ss2022Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .expect("key len")
            .decrypt(nonce.into(), cipher),
        SsMethod::Ss2022Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .expect("key len")
            .decrypt(nonce.into(), cipher),
        SsMethod::Chacha20IetfPoly1305 | SsMethod::Ss2022Chacha20Poly1305 => {
            ChaCha20Poly1305::new_from_slice(key)
                .expect("key len")
                .decrypt(nonce.into(), cipher)
        }
    };
    r.map_err(|_| invalid("ss: AEAD 校验失败"))
}

/// SIP022 UDP ChaCha20：XChaCha20-Poly1305(PSK) + 24B 随机 nonce。
fn xchacha_seal(key: &[u8], nonce: &[u8; 24], plain: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new_from_slice(key)
        .expect("key len")
        .encrypt(nonce.into(), plain)
        .expect("xchacha seal")
}

fn xchacha_open(key: &[u8], nonce: &[u8; 24], cipher: &[u8]) -> io::Result<Vec<u8>> {
    XChaCha20Poly1305::new_from_slice(key)
        .expect("key len")
        .decrypt(nonce.into(), cipher)
        .map_err(|_| invalid("ss2022 udp: AEAD 校验失败"))
}

/// SIP022 UDP AES：separate header 用 PSK 做 AES 单块 ECB 加解密。
fn aes_ecb_encrypt(method: SsMethod, psk: &[u8], block: &mut [u8; 16]) {
    let mut b = aes::Block::clone_from_slice(block);
    match method {
        SsMethod::Ss2022Aes128Gcm => Aes128::new_from_slice(psk)
            .expect("aes128 psk")
            .encrypt_block(&mut b),
        SsMethod::Ss2022Aes256Gcm => Aes256::new_from_slice(psk)
            .expect("aes256 psk")
            .encrypt_block(&mut b),
        _ => unreachable!("非 AES SS2022 方法"),
    }
    block.copy_from_slice(&b);
}

fn aes_ecb_decrypt(method: SsMethod, psk: &[u8], block: &mut [u8; 16]) {
    let mut b = aes::Block::clone_from_slice(block);
    match method {
        SsMethod::Ss2022Aes128Gcm => Aes128::new_from_slice(psk)
            .expect("aes128 psk")
            .decrypt_block(&mut b),
        SsMethod::Ss2022Aes256Gcm => Aes256::new_from_slice(psk)
            .expect("aes256 psk")
            .decrypt_block(&mut b),
        _ => unreachable!("非 AES SS2022 方法"),
    }
    block.copy_from_slice(&b);
}

fn random_salt(n: usize) -> Vec<u8> {
    let mut s = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// 请求头填充：长度 1..=900。SIP022 §3.1.3 要求「无初始 payload 时必须带非零填充」。
fn random_padding() -> Vec<u8> {
    let n = 1 + (rand::random::<u16>() as usize % SS2022_MAX_PADDING);
    random_salt(n)
}

/// 解析 SOCKS5 风格地址（ATYP+ADDR+PORT）的长度；用于剥出 UDP 回包载荷。
fn socks_addr_len(buf: &[u8]) -> io::Result<usize> {
    match buf.first() {
        Some(0x01) if buf.len() >= 1 + 4 + 2 => Ok(7),
        Some(0x04) if buf.len() >= 1 + 16 + 2 => Ok(19),
        Some(0x03) => {
            let n = *buf.get(1).ok_or_else(|| invalid("ss2022 udp: 地址截断"))? as usize;
            let total = 1 + 1 + n + 2;
            if buf.len() >= total {
                Ok(total)
            } else {
                Err(invalid("ss2022 udp: 域名地址截断"))
            }
        }
        _ => Err(invalid("ss2022 udp: 地址类型非法")),
    }
}

/// 客户端方向的 TCP 流（对端为 ss 服务端），建流时发送 salt 并拆成读写两半。
pub struct SsReader {
    inner: TcpStream,
    method: SsMethod,
    master: Vec<u8>,
    key: Option<Vec<u8>>,
    nonce: u64,
    buf: Vec<u8>,
    pos: usize,
    /// SIP022：我方请求 salt，用于校验响应固定头里的 request salt。
    request_salt: Vec<u8>,
    /// SIP022：响应固定头是否已解析（classic 初始为 true，逻辑不经过该分支）。
    ss2022_header_done: bool,
}

pub struct SsWriter {
    inner: TcpStream,
    method: SsMethod,
    key: Vec<u8>,
    nonce: u64,
    /// SIP022：尚未随首块发出的 salt（salt+固定头+变量头凑一次 write，防探测）。
    pending_salt: Vec<u8>,
    /// SIP022：首块待发送；首块内容 = SOCKS5 目标地址，作为「变量长头」。
    ss2022_first: bool,
}

/// 建流并拆分：读半/写半各持一个 fd 副本，可并发。
///
/// SIP022 语义：salt 暂不写出，由 writer 首块与两个头凑成**一次 write**；
/// 首块写入必须是一次完整的 SOCKS5 目标地址（`dial_tcp` 即如此调用），
/// 随后 writer 会追加非零随机填充，之后才是常规长度/载荷分块。
pub fn connect_split(
    inner: TcpStream,
    method: SsMethod,
    master: &[u8],
) -> io::Result<(SsReader, SsWriter)> {
    if method.is_2022() {
        let salt = random_salt(method.salt_len());
        let send_key = derive_subkey_2022(method, master, &salt);
        let reader = SsReader {
            inner: inner.try_clone()?,
            method,
            master: master.to_vec(),
            key: None,
            nonce: 0,
            buf: Vec::new(),
            pos: 0,
            request_salt: salt.clone(),
            ss2022_header_done: false,
        };
        let writer = SsWriter {
            inner,
            method,
            key: send_key,
            nonce: 0,
            pending_salt: salt,
            ss2022_first: true,
        };
        return Ok((reader, writer));
    }

    let mut inner = inner;
    let salt = random_salt(method.salt_len());
    inner.write_all(&salt)?;
    let send_key = derive_subkey(master, &salt).to_vec();
    let reader = SsReader {
        inner: inner.try_clone()?,
        method,
        master: master.to_vec(),
        key: None,
        nonce: 0,
        buf: Vec::new(),
        pos: 0,
        request_salt: Vec::new(),
        ss2022_header_done: true,
    };
    let writer = SsWriter {
        inner,
        method,
        key: send_key,
        nonce: 0,
        pending_salt: Vec::new(),
        ss2022_first: false,
    };
    Ok((reader, writer))
}

impl SsWriter {
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown(std::net::Shutdown::Write)
    }

    fn write_classic(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(MAX_CHUNK);
        let lb = seal(
            self.method,
            &self.key,
            &nonce_of(self.nonce),
            &(n as u16).to_be_bytes(),
        );
        self.nonce += 1;
        let payload = seal(self.method, &self.key, &nonce_of(self.nonce), &buf[..n]);
        self.nonce += 1;
        self.inner.write_all(&lb)?;
        self.inner.write_all(&payload)?;
        self.inner.flush()?;
        Ok(n)
    }

    fn write_2022(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.ss2022_first {
            self.ss2022_first = false;
            // 首块 = 请求「变量长头」：目标地址 + 非零随机填充（无初始 payload 时）。
            let padding = random_padding();
            let mut var = Vec::with_capacity(buf.len() + 2 + padding.len());
            var.extend_from_slice(buf);
            var.extend_from_slice(&(padding.len() as u16).to_be_bytes());
            var.extend_from_slice(&padding);
            if var.len() > u16::MAX as usize {
                return Err(invalid("ss2022: 请求变量头过长"));
            }
            // 固定头：type=0（client stream）+ timestamp + 变量头长度。
            let mut fixed = Vec::with_capacity(11);
            fixed.push(0u8);
            fixed.extend_from_slice(&now_unix().to_be_bytes());
            fixed.extend_from_slice(&(var.len() as u16).to_be_bytes());

            // salt + 固定头 + 变量头：一次 write（SIP022 §3.1.3）。
            let mut out = std::mem::take(&mut self.pending_salt);
            out.extend_from_slice(&seal(self.method, &self.key, &nonce_of(self.nonce), &fixed));
            self.nonce += 1;
            out.extend_from_slice(&seal(self.method, &self.key, &nonce_of(self.nonce), &var));
            self.nonce += 1;
            self.inner.write_all(&out)?;
            self.inner.flush()?;
            return Ok(buf.len());
        }

        let n = buf.len().min(MAX_CHUNK_2022);
        let mut out = seal(
            self.method,
            &self.key,
            &nonce_of(self.nonce),
            &(n as u16).to_be_bytes(),
        );
        self.nonce += 1;
        out.extend_from_slice(&seal(
            self.method,
            &self.key,
            &nonce_of(self.nonce),
            &buf[..n],
        ));
        self.nonce += 1;
        self.inner.write_all(&out)?;
        self.inner.flush()?;
        Ok(n)
    }
}

impl Read for SsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.buf.len() {
            if self.method.is_2022() {
                self.read_chunk_2022()?;
            } else {
                self.read_chunk_classic()?;
            }
        }
        let n = buf.len().min(self.buf.len() - self.pos);
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl SsReader {
    fn read_chunk_classic(&mut self) -> io::Result<()> {
        // 读服务器 salt（每方向一次）
        if self.key.is_none() {
            let mut salt = vec![0u8; self.method.salt_len()];
            self.inner.read_exact(&mut salt)?;
            self.key = Some(derive_subkey(&self.master, &salt).to_vec());
        }
        let payload = {
            let key = self.key.as_ref().expect("recv key");
            // 长度块：2 字节明文 + 16 字节 tag
            let mut lb = [0u8; 2 + TAG_LEN];
            self.inner.read_exact(&mut lb)?;
            let plain_len = open(self.method, key, &nonce_of(self.nonce), &lb)?;
            if plain_len.len() != 2 {
                return Err(invalid("ss: 长度块非法"));
            }
            self.nonce += 1;
            let len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
            if len == 0 || len > MAX_CHUNK {
                return Err(invalid("ss: 分块长度非法"));
            }
            let mut payload = vec![0u8; len + TAG_LEN];
            self.inner.read_exact(&mut payload)?;
            open(self.method, key, &nonce_of(self.nonce), &payload)?
        };
        self.nonce += 1;
        self.buf = payload;
        self.pos = 0;
        Ok(())
    }

    /// SIP022 分块读取：首选固定头，然后按长度/载荷块循环（跳过 0 长块）。
    fn read_chunk_2022(&mut self) -> io::Result<()> {
        // 调用方在 pos >= buf.len() 时才进来；先丢弃已读完的旧块。
        self.buf.clear();
        self.pos = 0;
        if !self.ss2022_header_done {
            let sl = self.method.salt_len();
            let fixed_plain_len = 1 + 8 + sl + 2;
            // 一次读出 salt + 固定头（SIP022 §3.1.3 建议一次 read）。
            let mut raw = vec![0u8; sl + fixed_plain_len + TAG_LEN];
            self.inner.read_exact(&mut raw)?;
            let key = derive_subkey_2022(self.method, &self.master, &raw[..sl]);
            let fixed = open(self.method, &key, &nonce_of(0), &raw[sl..])?;
            if fixed.len() != fixed_plain_len {
                return Err(invalid("ss2022: 响应固定头长度非法"));
            }
            if fixed[0] != 1 {
                return Err(invalid("ss2022: 响应流 type 非 1"));
            }
            let ts = u64::from_be_bytes(fixed[1..9].try_into().expect("ts"));
            if now_unix().abs_diff(ts) > SS2022_TIMESTAMP_TOLERANCE {
                return Err(invalid("ss2022: 响应头时间戳超出 30s 容差"));
            }
            if fixed[9..9 + sl] != self.request_salt[..] {
                return Err(invalid("ss2022: 响应 request salt 不匹配"));
            }
            let len = u16::from_be_bytes([fixed[9 + sl], fixed[10 + sl]]) as usize;
            self.key = Some(key);
            self.nonce = 1;
            self.ss2022_header_done = true;
            self.buf = self.read_payload_2022(len)?;
        }
        while self.buf.is_empty() {
            let plain = {
                let key = self.key.as_ref().expect("2022 recv key");
                let mut lb = [0u8; 2 + TAG_LEN];
                self.inner.read_exact(&mut lb)?;
                let plain = open(self.method, key, &nonce_of(self.nonce), &lb)?;
                plain
            };
            self.nonce += 1;
            if plain.len() != 2 {
                return Err(invalid("ss2022: 长度块非法"));
            }
            let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
            self.buf = self.read_payload_2022(len)?;
        }
        Ok(())
    }

    fn read_payload_2022(&mut self, len: usize) -> io::Result<Vec<u8>> {
        if len > MAX_CHUNK_2022 {
            return Err(invalid("ss2022: 分块长度非法"));
        }
        let key = self.key.as_ref().expect("2022 recv key");
        let mut ct = vec![0u8; len + TAG_LEN];
        self.inner.read_exact(&mut ct)?;
        let out = open(self.method, key, &nonce_of(self.nonce), &ct)?;
        self.nonce += 1;
        Ok(out)
    }
}

impl Write for SsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.method.is_2022() {
            self.write_2022(buf)
        } else {
            self.write_classic(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------- classic UDP

/// UDP：`[salt][AEAD(payload)]`（每个包独立 salt，仅 classic 方法）。
pub fn udp_seal(method: SsMethod, master: &[u8], payload: &[u8]) -> Vec<u8> {
    assert!(!method.is_2022(), "SS2022 UDP 请使用 Ss2022UdpSession");
    let salt = random_salt(method.salt_len());
    let key = derive_subkey(master, &salt);
    let mut out = salt;
    out.extend_from_slice(&seal(method, &key, &nonce_of(0), payload));
    out
}

pub fn udp_open(method: SsMethod, master: &[u8], datagram: &[u8]) -> io::Result<Vec<u8>> {
    assert!(!method.is_2022(), "SS2022 UDP 请使用 Ss2022UdpSession");
    let sl = method.salt_len();
    if datagram.len() <= sl {
        return Err(invalid("ss udp: 包太短"));
    }
    let key = derive_subkey(master, &datagram[..sl]);
    open(method, &key, &nonce_of(0), &datagram[sl..])
}

// ---------------------------------------------------------------- SIP022 UDP

/// 收包滑动窗口（WireGuard 风格；SIP022 §3.2.4 要求按 relay session 去重）。
#[derive(Default)]
struct ReplayWindow {
    /// 已接收的最大 packet id。
    max: u64,
    /// 位图：bit 0 = max，bit k = max-k（k < 64）。
    bitmap: u64,
}

impl ReplayWindow {
    /// 校验并更新；false = 重复包或窗口外陈旧包。
    fn accept(&mut self, id: u64) -> bool {
        if id > self.max {
            let shift = id - self.max;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.max = id;
            true
        } else {
            let diff = self.max - id;
            if diff >= 64 {
                return false;
            }
            let bit = 1u64 << diff;
            if self.bitmap & bit != 0 {
                return false;
            }
            self.bitmap |= bit;
            true
        }
    }
}

/// SIP022 UDP 客户端会话（单用户、无 EIH）。
///
/// - AES 方法：`[AES-ECB(PSK, session id|packet id)]` + AES-GCM(子密钥, nonce=明文头 `[4..16]`)；
/// - ChaCha20：`[24B 随机 nonce]` + XChaCha20-Poly1305(PSK)，session/packet id 在明文主头里；
/// - `frame` 与 classic 路径一致 = SOCKS5 目标地址 + 载荷；`open` 返回去掉地址的载荷。
pub struct Ss2022UdpSession {
    method: SsMethod,
    psk: Vec<u8>,
    client_session_id: u64,
    packet_id: u64,
    /// server session id -> 收包滑动窗口。
    replay: HashMap<u64, ReplayWindow>,
}

impl Ss2022UdpSession {
    pub fn new(method: SsMethod, psk: &[u8]) -> io::Result<Self> {
        if !method.is_2022() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Ss2022UdpSession 仅用于 SS2022 方法",
            ));
        }
        if psk.len() != method.key_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ss2022: PSK 长度 {} != {}", psk.len(), method.key_len()),
            ));
        }
        let mut sid = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut sid);
        Ok(Self {
            method,
            psk: psk.to_vec(),
            client_session_id: u64::from_be_bytes(sid),
            packet_id: 0,
            replay: HashMap::new(),
        })
    }

    /// 封装客户端 → 服务端报文；`frame` = SOCKS5 目标地址 + 载荷。
    pub fn seal(&mut self, frame: &[u8]) -> Vec<u8> {
        let pid = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);
        let ts = now_unix().to_be_bytes();

        if self.method.is_2022_aes() {
            // separate header：AES-ECB(PSK) 加密的 [client session id | packet id]。
            let mut sep = [0u8; 16];
            sep[..8].copy_from_slice(&self.client_session_id.to_be_bytes());
            sep[8..].copy_from_slice(&pid.to_be_bytes());
            let subkey = derive_subkey_2022(self.method, &self.psk, &sep[..8]);
            let nonce: [u8; 12] = sep[4..16].try_into().expect("nonce");
            // 主头：type=0（client）+ timestamp + padding length=0（载荷非空无需填充）。
            let mut plain = Vec::with_capacity(11 + frame.len());
            plain.push(0u8);
            plain.extend_from_slice(&ts);
            plain.extend_from_slice(&0u16.to_be_bytes());
            plain.extend_from_slice(frame);
            let body = seal(self.method, &subkey, &nonce, &plain);
            aes_ecb_encrypt(self.method, &self.psk, &mut sep);
            let mut out = Vec::with_capacity(16 + body.len());
            out.extend_from_slice(&sep);
            out.extend_from_slice(&body);
            return out;
        }

        // ChaCha20：XChaCha20-Poly1305(PSK)，24B 随机 nonce；主头含 session/packet id。
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut plain = Vec::with_capacity(27 + frame.len());
        plain.extend_from_slice(&self.client_session_id.to_be_bytes());
        plain.extend_from_slice(&pid.to_be_bytes());
        plain.push(0u8);
        plain.extend_from_slice(&ts);
        plain.extend_from_slice(&0u16.to_be_bytes());
        plain.extend_from_slice(frame);
        let mut out = nonce.to_vec();
        out.extend_from_slice(&xchacha_seal(&self.psk, &nonce, &plain));
        out
    }

    /// 解封装服务端 → 客户端报文，返回去掉 SOCKS5 地址后的载荷。
    pub fn open(&mut self, datagram: &[u8]) -> io::Result<Vec<u8>> {
        if self.method.is_2022_aes() {
            if datagram.len() < 16 + TAG_LEN {
                return Err(invalid("ss2022 udp: 包太短"));
            }
            let mut sep = [0u8; 16];
            sep.copy_from_slice(&datagram[..16]);
            aes_ecb_decrypt(self.method, &self.psk, &mut sep);
            let server_session_id = u64::from_be_bytes(sep[..8].try_into().expect("sid"));
            let packet_id = u64::from_be_bytes(sep[8..].try_into().expect("pid"));
            let subkey = derive_subkey_2022(self.method, &self.psk, &sep[..8]);
            let nonce: [u8; 12] = sep[4..16].try_into().expect("nonce");
            let body = open(self.method, &subkey, &nonce, &datagram[16..])?;
            return self.finish_open(server_session_id, packet_id, &body);
        }

        if datagram.len() < 24 + TAG_LEN {
            return Err(invalid("ss2022 udp: 包太短"));
        }
        let nonce: [u8; 24] = datagram[..24].try_into().expect("nonce");
        let plain = xchacha_open(&self.psk, &nonce, &datagram[24..])?;
        if plain.len() < 16 {
            return Err(invalid("ss2022 udp: 主头截断"));
        }
        let server_session_id = u64::from_be_bytes(plain[..8].try_into().expect("sid"));
        let packet_id = u64::from_be_bytes(plain[8..16].try_into().expect("pid"));
        self.finish_open(server_session_id, packet_id, &plain[16..])
    }

    /// 校验服务端主头（type/timestamp/client session id/padding），再更新滑动窗口。
    /// `body` 从 type 开始：`type(1) | ts(8) | client sid(8) | padlen(2) | padding | addr | payload`。
    fn finish_open(
        &mut self,
        server_session_id: u64,
        packet_id: u64,
        body: &[u8],
    ) -> io::Result<Vec<u8>> {
        if body.len() < 1 + 8 + 8 + 2 {
            return Err(invalid("ss2022 udp: 主头截断"));
        }
        if body[0] != 1 {
            return Err(invalid("ss2022 udp: 回包 type 非 1"));
        }
        let ts = u64::from_be_bytes(body[1..9].try_into().expect("ts"));
        if now_unix().abs_diff(ts) > SS2022_TIMESTAMP_TOLERANCE {
            return Err(invalid("ss2022 udp: 时间戳超出 30s 容差"));
        }
        let client_sid = u64::from_be_bytes(body[9..17].try_into().expect("csid"));
        if client_sid != self.client_session_id {
            return Err(invalid("ss2022 udp: client session id 不匹配"));
        }
        let pad_len = u16::from_be_bytes(body[17..19].try_into().expect("pad")) as usize;
        let off = 19 + pad_len;
        if body.len() < off {
            return Err(invalid("ss2022 udp: padding 截断"));
        }

        // 头部全部通过校验后才更新滑动窗口状态（SIP022 §3.2.4）。
        if self.replay.len() >= SS2022_MAX_SERVER_SESSIONS
            && !self.replay.contains_key(&server_session_id)
        {
            if let Some(k) = self.replay.keys().next().copied() {
                self.replay.remove(&k);
            }
        }
        let window = self.replay.entry(server_session_id).or_default();
        if !window.accept(packet_id) {
            return Err(invalid("ss2022 udp: 重放或窗口外 packet id"));
        }

        let frame = &body[off..];
        let addr_len = socks_addr_len(frame)?;
        Ok(frame[addr_len..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// 参考向量：由 Python `cryptography`/hashlib 独立计算（EVP_BytesToKey 等价实现）。
    #[test]
    fn evp_bytes_to_key_reference_vector() {
        let k = evp_bytes_to_key(b"password", 32);
        assert_eq!(
            k,
            vec![
                0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82,
                0xcf, 0x99, 0x2b, 0x95, 0x99, 0x0a, 0x91, 0x51, 0x37, 0x4a, 0xbd, 0x8f, 0xf8, 0xc5,
                0xa7, 0xa0, 0xfe, 0x08
            ]
        );
        let k2 = evp_bytes_to_key(b"secret", 32);
        assert_eq!(
            k2,
            vec![
                0x5e, 0xbe, 0x22, 0x94, 0xec, 0xd0, 0xe0, 0xf0, 0x8e, 0xab, 0x76, 0x90, 0xd2, 0xa6,
                0xee, 0x69, 0x26, 0xae, 0x5c, 0xc8, 0x54, 0xe3, 0x6b, 0x6b, 0xdf, 0xca, 0x36, 0x68,
                0x48, 0xde, 0xa6, 0xbb
            ]
        );
    }

    #[test]
    fn ss_stream_roundtrip_with_echo_key() {
        // 用同一主密钥模拟两端（与 Python 服务端的互操作由 lab e2e 覆盖）
        let method = SsMethod::Chacha20IetfPoly1305;
        let master = evp_bytes_to_key(b"secret", KEY_LEN);
        // 手工验证：seal → open 回环
        let salt = random_salt(method.salt_len());
        let key = derive_subkey(&master, &salt);
        let sealed = seal(method, &key, &nonce_of(7), b"hello");
        assert_eq!(
            open(method, &key, &nonce_of(7), &sealed).unwrap(),
            b"hello".to_vec()
        );
        assert!(
            open(method, &key, &nonce_of(8), &sealed).is_err(),
            "nonce 不符应失败"
        );
    }

    #[test]
    fn ss_udp_roundtrip() {
        let method = SsMethod::Aes256Gcm;
        let master = evp_bytes_to_key(b"p@ss", KEY_LEN);
        let sealed = udp_seal(method, &master, b"payload");
        assert_eq!(
            udp_open(method, &master, &sealed).unwrap(),
            b"payload".to_vec()
        );
        // 篡改必须被检出
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(udp_open(method, &master, &bad).is_err());
    }

    #[test]
    fn method_parse() {
        assert_eq!(SsMethod::parse("aes-256-gcm"), Some(SsMethod::Aes256Gcm));
        assert_eq!(
            SsMethod::parse("chacha20-ietf-poly1305"),
            Some(SsMethod::Chacha20IetfPoly1305)
        );
        assert_eq!(SsMethod::parse("aes-128-gcm"), None);
    }

    // ------------------------------------------------------------ SIP022

    const M_128: SsMethod = SsMethod::Ss2022Aes128Gcm;
    const M_256: SsMethod = SsMethod::Ss2022Aes256Gcm;
    const M_CHACHA: SsMethod = SsMethod::Ss2022Chacha20Poly1305;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn ss2022_method_parse_and_lengths() {
        assert_eq!(SsMethod::parse("2022-blake3-aes-128-gcm"), Some(M_128));
        assert_eq!(SsMethod::parse("2022-blake3-aes-256-gcm"), Some(M_256));
        assert_eq!(
            SsMethod::parse("2022-blake3-chacha20-poly1305"),
            Some(M_CHACHA)
        );
        assert_eq!(SsMethod::parse("2022-blake3-chacha8-poly1305"), None);
        assert_eq!((M_128.key_len(), M_128.salt_len()), (16, 16));
        assert_eq!((M_256.key_len(), M_256.salt_len()), (32, 32));
        assert_eq!((M_CHACHA.key_len(), M_CHACHA.salt_len()), (32, 32));
        assert!(M_128.is_2022() && M_256.is_2022() && M_CHACHA.is_2022());
        assert!(!SsMethod::Aes256Gcm.is_2022());
    }

    /// KAT：由 shadowsocks-crypto 0.8.0（shadowsocks-rust 官方密码库）现场生成，
    /// 覆盖 BLAKE3 子密钥派生 + TCP/UDP 的 AEAD 与 nonce 约定。
    #[test]
    fn ss2022_cipher_reference_vectors() {
        // TcpCipher::new(method, key, salt).encrypt_packet(fixed_plain) → 密文
        let fixed_plain: [u8; 11] = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x2a,
        ];
        let tcp: [(SsMethod, [u8; 32], [u8; 32], &str); 3] = [
            (
                M_128,
                [0x11; 32],
                [0x22; 32],
                "d51913c99d422b716e96f8e5bac45c526521ae14b98e48f3849650",
            ),
            (
                M_256,
                [0x11; 32],
                [0x22; 32],
                "242655921dd61d18a5245dda3d7ada08178be65527a24acb62373d",
            ),
            (
                M_CHACHA,
                [0x11; 32],
                [0x22; 32],
                "05a74b9d6d6e2f8073f07af6cb2fc14a2c014fabb16df392a21cc1",
            ),
        ];
        for (method, key, salt, want) in tcp {
            let sub =
                derive_subkey_2022(method, &key[..method.key_len()], &salt[..method.salt_len()]);
            assert_eq!(
                hex(&seal(method, &sub, &nonce_of(0), &fixed_plain)),
                want,
                "TCP {method:?} KAT"
            );
        }

        // UdpCipher::new(method, key, session_id).encrypt_packet(nonce, plain) → 密文
        let sid: u64 = 0x0102030405060708;
        let plain: [u8; 10] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let nonce12 = [0xaa; 12];
        let nonce24 = [0xbb; 24];
        let aes128_sub = derive_subkey_2022(M_128, &[0x11; 16], &sid.to_be_bytes());
        assert_eq!(
            hex(&seal(M_128, &aes128_sub, &nonce12, &plain)),
            "4f8e5b16065da359c7f0a029afd33bd930792935511413f72eff",
            "UDP aes-128 KAT"
        );
        let aes256_sub = derive_subkey_2022(M_256, &[0x11; 32], &sid.to_be_bytes());
        assert_eq!(
            hex(&seal(M_256, &aes256_sub, &nonce12, &plain)),
            "86e5c0ca536170d61b63d78b5a5131cd296f2c778b0f089f357f",
            "UDP aes-256 KAT"
        );
        assert_eq!(
            hex(&xchacha_seal(&[0x11; 32], &nonce24, &plain)),
            "693ecf9c4e5fa56aed927bcf7b84c17c47f47992f661e9efe902",
            "UDP chacha KAT"
        );
    }

    /// 测试内的「最小服务端」：解析客户端请求头，校验 type/时间戳/填充，
    /// 返回（会话子密钥, 变量头, 请求 salt）。
    fn server_read_request(
        method: SsMethod,
        psk: &[u8],
        sock: &mut TcpStream,
    ) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let sl = method.salt_len();
        let mut raw = vec![0u8; sl + 1 + 8 + 2 + TAG_LEN];
        sock.read_exact(&mut raw)?;
        let request_salt = raw[..sl].to_vec();
        let key = derive_subkey_2022(method, psk, &raw[..sl]);
        let fixed = open(method, &key, &nonce_of(0), &raw[sl..])?;
        if fixed.len() != 11 || fixed[0] != 0 {
            return Err(invalid("server: 固定头非法"));
        }
        let ts = u64::from_be_bytes(fixed[1..9].try_into().expect("ts"));
        assert!(now_unix().abs_diff(ts) <= SS2022_TIMESTAMP_TOLERANCE);
        let vlen = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut vct = vec![0u8; vlen + TAG_LEN];
        sock.read_exact(&mut vct)?;
        let var = open(method, &key, &nonce_of(1), &vct)?;
        Ok((key, var, request_salt))
    }

    #[test]
    fn ss2022_tcp_request_roundtrip_and_response() {
        for method in [M_128, M_256, M_CHACHA] {
            let psk = vec![0x33u8; method.key_len()];
            let addr: [u8; 15] = [
                0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00,
                0x50,
            ];
            let payload1 = b"hello-2022".to_vec();
            let payload2 = b"second-frame".to_vec();

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let server_addr = listener.local_addr().unwrap();
            let psk_srv = psk.clone();
            let (p1, p2) = (payload1.clone(), payload2.clone());
            let server = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let (key, var, request_salt) =
                    server_read_request(method, &psk_srv, &mut sock).unwrap();
                // 变量头 = 地址 + 填充长度 + 填充（无 initial payload）。
                assert_eq!(&var[..addr.len()], &addr);
                let pad_len = u16::from_be_bytes([var[addr.len()], var[addr.len() + 1]]) as usize;
                assert!((1..=SS2022_MAX_PADDING).contains(&pad_len), "pad={pad_len}");
                assert_eq!(var.len(), addr.len() + 2 + pad_len, "首块不应含 payload");

                // 读第一个数据块（len 块 + 载荷块），nonce 2/3。
                let mut lb = [0u8; 2 + TAG_LEN];
                sock.read_exact(&mut lb).unwrap();
                let len = u16::from_be_bytes(
                    open(method, &key, &nonce_of(2), &lb)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ) as usize;
                let mut ct = vec![0u8; len + TAG_LEN];
                sock.read_exact(&mut ct).unwrap();
                let got1 = open(method, &key, &nonce_of(3), &ct).unwrap();
                assert_eq!(got1, p1);

                // 服务端响应：salt | AEAD(type=1,ts,request_salt,len) | AEAD(payload) |
                //             AEAD(len) | AEAD(payload) ...
                let rsalt = random_salt(method.salt_len());
                let rkey = derive_subkey_2022(method, &psk_srv, &rsalt);
                let mut fixed = vec![1u8];
                fixed.extend_from_slice(&now_unix().to_be_bytes());
                fixed.extend_from_slice(&request_salt);
                fixed.extend_from_slice(&(p1.len() as u16).to_be_bytes());
                let mut out = rsalt;
                out.extend_from_slice(&seal(method, &rkey, &nonce_of(0), &fixed));
                out.extend_from_slice(&seal(method, &rkey, &nonce_of(1), &p1));
                out.extend_from_slice(&seal(
                    method,
                    &rkey,
                    &nonce_of(2),
                    &(p2.len() as u16).to_be_bytes(),
                ));
                out.extend_from_slice(&seal(method, &rkey, &nonce_of(3), &p2));
                sock.write_all(&out).unwrap();
            });

            // 客户端：connect_split → 首块写地址 → 数据块。
            let sock = TcpStream::connect(server_addr).unwrap();
            let (mut reader, mut writer) = connect_split(sock, method, &psk).unwrap();
            writer.write_all(&addr).unwrap();
            writer.write_all(&payload1).unwrap();
            let mut got1 = vec![0u8; payload1.len()];
            reader.read_exact(&mut got1).unwrap();
            assert_eq!(got1, payload1, "{method:?}");
            let mut got2 = vec![0u8; payload2.len()];
            reader.read_exact(&mut got2).unwrap();
            assert_eq!(got2, payload2, "{method:?}");
            server.join().unwrap();
        }
    }

    /// 时间戳超限 / request salt 不匹配必须被拒绝（响应头方向）。
    #[test]
    fn ss2022_tcp_rejects_stale_timestamp_and_wrong_salt() {
        let method = M_256;
        let psk = vec![0x55u8; method.key_len()];
        for bad in ["ts", "salt"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let server_addr = listener.local_addr().unwrap();
            let psk_srv = psk.clone();
            let server = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let (_, _, request_salt) =
                    server_read_request(method, &psk_srv, &mut sock).unwrap();
                let rsalt = random_salt(method.salt_len());
                let rkey = derive_subkey_2022(method, &psk_srv, &rsalt);
                let mut fixed = vec![1u8];
                let ts = if bad == "ts" {
                    now_unix() - 3600
                } else {
                    now_unix()
                };
                fixed.extend_from_slice(&ts.to_be_bytes());
                if bad == "salt" {
                    let mut wrong = request_salt.clone();
                    wrong[0] ^= 0xff;
                    fixed.extend_from_slice(&wrong);
                } else {
                    fixed.extend_from_slice(&request_salt);
                }
                fixed.extend_from_slice(&0u16.to_be_bytes());
                let mut out = rsalt;
                out.extend_from_slice(&seal(method, &rkey, &nonce_of(0), &fixed));
                sock.write_all(&out).unwrap();
            });
            let sock = TcpStream::connect(server_addr).unwrap();
            let (mut reader, mut writer) = connect_split(sock, method, &psk).unwrap();
            writer.write_all(&[0x01, 127, 0, 0, 1, 0x00, 0x50]).unwrap();
            let mut b = [0u8; 1];
            assert!(reader.read_exact(&mut b).is_err(), "应拒绝（{bad}）");
            server.join().unwrap();
        }
    }

    // ------------------------------------------------------------ SIP022 UDP

    /// 测试内的「最小服务端」：解封装客户端报文为 (server 视角 client_sid, packet_id, 载荷)。
    fn server_udp_open(method: SsMethod, psk: &[u8], dg: &[u8]) -> (u64, u64, Vec<u8>) {
        let (client_sid, packet_id, plain) = if method.is_2022_aes() {
            let mut sep = [0u8; 16];
            sep.copy_from_slice(&dg[..16]);
            aes_ecb_decrypt(method, psk, &mut sep);
            let sid = u64::from_be_bytes(sep[..8].try_into().unwrap());
            let pid = u64::from_be_bytes(sep[8..].try_into().unwrap());
            let sub = derive_subkey_2022(method, psk, &sep[..8]);
            let nonce: [u8; 12] = sep[4..16].try_into().unwrap();
            (sid, pid, open(method, &sub, &nonce, &dg[16..]).unwrap())
        } else {
            let nonce: [u8; 24] = dg[..24].try_into().unwrap();
            let plain = xchacha_open(psk, &nonce, &dg[24..]).unwrap();
            (
                u64::from_be_bytes(plain[..8].try_into().unwrap()),
                u64::from_be_bytes(plain[8..16].try_into().unwrap()),
                plain[16..].to_vec(),
            )
        };
        assert_eq!(plain[0], 0, "client type");
        let ts = u64::from_be_bytes(plain[1..9].try_into().unwrap());
        assert!(now_unix().abs_diff(ts) <= SS2022_TIMESTAMP_TOLERANCE);
        let pad_len = u16::from_be_bytes(plain[9..11].try_into().unwrap()) as usize;
        let frame = plain[11 + pad_len..].to_vec();
        let addr_len = socks_addr_len(&frame).unwrap();
        (client_sid, packet_id, frame[addr_len..].to_vec())
    }

    /// 测试内的「最小服务端」：按 SIP022 构造服务端回包。
    fn server_udp_seal(method: SsMethod, psk: &[u8], client_sid: u64, frame: &[u8]) -> Vec<u8> {
        let ts = now_unix().to_be_bytes();
        if method.is_2022_aes() {
            let server_sid: u64 = 0xdead_beef_1234_5678;
            let pid: u64 = 0;
            let mut sep = [0u8; 16];
            sep[..8].copy_from_slice(&server_sid.to_be_bytes());
            sep[8..].copy_from_slice(&pid.to_be_bytes());
            let sub = derive_subkey_2022(method, psk, &sep[..8]);
            let nonce: [u8; 12] = sep[4..16].try_into().unwrap();
            let mut plain = vec![1u8];
            plain.extend_from_slice(&ts);
            plain.extend_from_slice(&client_sid.to_be_bytes());
            plain.extend_from_slice(&0u16.to_be_bytes());
            plain.extend_from_slice(frame);
            let body = seal(method, &sub, &nonce, &plain);
            aes_ecb_encrypt(method, psk, &mut sep);
            let mut out = sep.to_vec();
            out.extend_from_slice(&body);
            out
        } else {
            let server_sid: u64 = 0xdead_beef_1234_5678;
            let pid: u64 = 0;
            let mut nonce = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut nonce);
            let mut plain = Vec::new();
            plain.extend_from_slice(&server_sid.to_be_bytes());
            plain.extend_from_slice(&pid.to_be_bytes());
            plain.push(1u8);
            plain.extend_from_slice(&ts);
            plain.extend_from_slice(&client_sid.to_be_bytes());
            plain.extend_from_slice(&0u16.to_be_bytes());
            plain.extend_from_slice(frame);
            let mut out = nonce.to_vec();
            out.extend_from_slice(&xchacha_seal(psk, &nonce, &plain));
            out
        }
    }

    #[test]
    fn ss2022_udp_roundtrip_with_minimal_server() {
        for method in [M_128, M_256, M_CHACHA] {
            let psk = vec![0x44u8; method.key_len()];
            let mut client = Ss2022UdpSession::new(method, &psk).unwrap();
            let frame = [0x01, 127, 0, 0, 1, 0x1f, 0x90, b'h', b'i'];
            let dg = client.seal(&frame);
            let (client_sid, _pid, got) = server_udp_open(method, &psk, &dg);
            assert_eq!(got, b"hi", "{method:?}");

            // 服务端回包（含地址，open 应剥掉）→ 客户端解出载荷。
            let mut resp_frame = vec![0x03, 0x0b];
            resp_frame.extend_from_slice(b"example.com");
            resp_frame.extend_from_slice(&0x1f90u16.to_be_bytes());
            resp_frame.extend_from_slice(b"pong");
            let resp = server_udp_seal(method, &psk, client_sid, &resp_frame);
            assert_eq!(client.open(&resp).unwrap(), b"pong", "{method:?}");

            // 篡改/重放必须被拒绝。
            let mut bad = resp.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(client.open(&bad).is_err(), "{method:?} 篡改未检出");
            assert!(client.open(&resp).is_err(), "{method:?} 重放未检出");
        }
    }

    #[test]
    fn ss2022_udp_rejects_wrong_client_sid_and_stale_ts() {
        let method = M_256;
        let psk = vec![0x66u8; method.key_len()];
        let mut client = Ss2022UdpSession::new(method, &psk).unwrap();
        let mut frame = vec![0x01, 127, 0, 0, 1, 0x00, 0x35];
        frame.extend_from_slice(b"x");
        let dg = client.seal(&frame);
        let (client_sid, _pid, _) = server_udp_open(method, &psk, &dg);

        // 回包里的 client session id 不匹配必须拒绝。
        let resp_for_other = server_udp_seal(method, &psk, client_sid.wrapping_add(1), b".");
        assert!(
            client.open(&resp_for_other).is_err(),
            "client sid 不匹配应拒绝"
        );
        assert!(
            client.open(&resp_for_other).is_err(),
            "client sid 不匹配应拒绝"
        );

        // 时间戳超限：手工构造（用服务端 helper 的变体）。
        let mut plain = vec![1u8];
        plain.extend_from_slice(&(now_unix() - 3600).to_be_bytes());
        plain.extend_from_slice(&client_sid.to_be_bytes());
        plain.extend_from_slice(&0u16.to_be_bytes());
        plain.push(0x01); // addr
        plain.extend_from_slice(&[127, 0, 0, 1]);
        let server_sid: u64 = 7;
        let pid: u64 = 9;
        let mut sep = [0u8; 16];
        sep[..8].copy_from_slice(&server_sid.to_be_bytes());
        sep[8..].copy_from_slice(&pid.to_be_bytes());
        let sub = derive_subkey_2022(method, &psk, &sep[..8]);
        let nonce: [u8; 12] = sep[4..16].try_into().unwrap();
        let body = seal(method, &sub, &nonce, &plain);
        aes_ecb_encrypt(method, &psk, &mut sep);
        let mut stale = sep.to_vec();
        stale.extend_from_slice(&body);
        assert!(client.open(&stale).is_err(), "陈旧时间戳应拒绝");
    }

    #[test]
    fn replay_window_boundaries() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(1)); // 乱序但在窗口内
        assert!(!w.accept(1));
        assert!(w.accept(63));
        assert!(!w.accept(0)); // 63-0 >= 64? 不，63-0=63 <64，且 bit 已被 set
        assert!(w.accept(64));
        assert!(!w.accept(0)); // 64-0 >= 64 → 窗口外
        let mut w2 = ReplayWindow::default();
        assert!(w2.accept(1000));
        assert!(w2.accept(999));
        assert!(w2.accept(937)); // 1000-937 = 63 → 窗口内且未收到
        assert!(!w2.accept(937)); // 重复
        assert!(!w2.accept(936)); // 窗口外
    }

    #[test]
    fn ss2022_udp_session_rejects_classic_and_bad_psk_len() {
        assert!(Ss2022UdpSession::new(SsMethod::Aes256Gcm, &[0u8; 32]).is_err());
        assert!(Ss2022UdpSession::new(M_128, &[0u8; 32]).is_err());
        assert!(Ss2022UdpSession::new(M_128, &[0u8; 16]).is_ok());
    }
}

// SPDX-License-Identifier: GPL-2.0
//! P5 G1：Shadowsocks classic AEAD（SIP004）——TCP 流 + UDP 包。
//!
//! 范围与边界（ADR-0016）：
//! - 支持 `aes-256-gcm` 与 `chacha20-ietf-poly1305` 两种 AEAD；
//! - 主密钥 = OpenSSL EVP_BytesToKey(MD5, 无盐, 1 轮)（经典实现，对照 Python
//!   `cryptography` 独立计算验证）；子密钥 = HKDF-SHA1(salt, info="ss-subkey")；
//! - TCP：`[salt][AEAD(len 2B)][AEAD(payload)]...`，nonce 为小端递增计数器；
//! - UDP：每个包 `[salt][AEAD(payload)]`（独立 salt）；
//! - **不做 SIP022（shadowsocks 2022）**、不做插件、不做 stream ciphers（rc4 等）。

use std::io::{self, Read, Write};
use std::net::TcpStream;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest as _, Md5};
use rand::RngCore;
use sha1::Sha1;

pub const KEY_LEN: usize = 32;
const MAX_CHUNK: usize = 0x3fff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsMethod {
    Aes256Gcm,
    Chacha20IetfPoly1305,
}

impl SsMethod {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Some(Self::Chacha20IetfPoly1305),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        }
    }

    pub const fn salt_len(&self) -> usize {
        32
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

fn nonce_of(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

fn seal(method: SsMethod, key: &[u8], nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
    match method {
        SsMethod::Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .expect("key len")
            .encrypt(nonce.into(), plain)
            .expect("seal"),
        SsMethod::Chacha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
            .expect("key len")
            .encrypt(nonce.into(), plain)
            .expect("seal"),
    }
}

fn open(method: SsMethod, key: &[u8], nonce: &[u8; 12], cipher: &[u8]) -> io::Result<Vec<u8>> {
    let r = match method {
        SsMethod::Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .expect("key len")
            .decrypt(nonce.into(), cipher),
        SsMethod::Chacha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
            .expect("key len")
            .decrypt(nonce.into(), cipher),
    };
    r.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ss: AEAD 校验失败"))
}

fn random_salt(n: usize) -> Vec<u8> {
    let mut s = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// 客户端方向的 TCP 流（对端为 ss 服务端），建流时发送 salt 并拆成读写两半。
pub struct SsReader {
    inner: TcpStream,
    method: SsMethod,
    master: Vec<u8>,
    key: Option<[u8; KEY_LEN]>,
    nonce: u64,
    buf: Vec<u8>,
    pos: usize,
}

pub struct SsWriter {
    inner: TcpStream,
    method: SsMethod,
    key: [u8; KEY_LEN],
    nonce: u64,
}

/// 建流（发送 salt）并拆分：读半/写半各持一个 fd 副本，可并发。
pub fn connect_split(
    mut inner: TcpStream,
    method: SsMethod,
    master: &[u8],
) -> io::Result<(SsReader, SsWriter)> {
    let salt = random_salt(method.salt_len());
    inner.write_all(&salt)?;
    let send_key = derive_subkey(master, &salt);
    let reader = SsReader {
        inner: inner.try_clone()?,
        method,
        master: master.to_vec(),
        key: None,
        nonce: 0,
        buf: Vec::new(),
        pos: 0,
    };
    let writer = SsWriter {
        inner,
        method,
        key: send_key,
        nonce: 0,
    };
    Ok((reader, writer))
}

impl SsWriter {
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown(std::net::Shutdown::Write)
    }
}

impl Read for SsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.buf.len() {
            // 读服务器 salt（每方向一次）
            if self.key.is_none() {
                let mut salt = vec![0u8; self.method.salt_len()];
                self.inner.read_exact(&mut salt)?;
                self.key = Some(derive_subkey(&self.master, &salt));
            }
            let key = self.key.expect("recv key");
            // 长度块：2 字节明文 + 16 字节 tag
            let mut lb = [0u8; 2 + 16];
            self.inner.read_exact(&mut lb)?;
            let plain_len = open(self.method, &key, &nonce_of(self.nonce), &lb)?;
            if plain_len.len() != 2 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "ss: 长度块非法"));
            }
            self.nonce += 1;
            let len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
            if len == 0 || len > MAX_CHUNK {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ss: 分块长度非法",
                ));
            }
            let mut payload = vec![0u8; len + 16];
            self.inner.read_exact(&mut payload)?;
            self.buf = open(self.method, &key, &nonce_of(self.nonce), &payload)?;
            self.nonce += 1;
            self.pos = 0;
        }
        let n = buf.len().min(self.buf.len() - self.pos);
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for SsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
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

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// UDP：`[salt][AEAD(payload)]`（每个包独立 salt）。
pub fn udp_seal(method: SsMethod, master: &[u8], payload: &[u8]) -> Vec<u8> {
    let salt = random_salt(method.salt_len());
    let key = derive_subkey(master, &salt);
    let mut out = salt;
    out.extend_from_slice(&seal(method, &key, &nonce_of(0), payload));
    out
}

pub fn udp_open(method: SsMethod, master: &[u8], datagram: &[u8]) -> io::Result<Vec<u8>> {
    let sl = method.salt_len();
    if datagram.len() <= sl {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ss udp: 包太短"));
    }
    let key = derive_subkey(master, &datagram[..sl]);
    open(method, &key, &nonce_of(0), &datagram[sl..])
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

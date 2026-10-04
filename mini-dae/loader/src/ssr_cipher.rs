// SPDX-License-Identifier: GPL-2.0
//! P30：SSR（shadowsocksr-stream）流密码层。
//!
//! 对齐 Go 参考实现 `olicesx/outbound/ciphers/stream_cipher.go`：
//! - key 用 OpenSSL EVP_BytesToKey(MD5, 无盐) 派生：d_i = MD5(d_{i-1} || password)；
//! - CFB-128 / CTR 在 AES 块加密上自实现，跨 encrypt/decrypt 调用保持流状态；
//! - rc4-md5(-6)：key' = MD5(key || iv)，再 RC4；chacha20-ietf 用 RustCrypto `chacha20`。

use std::io;

use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use md5::{Digest, Md5};
use rand::RngCore;

const BLOCK: usize = 16;

type Block16 = Block<Aes128>;

fn err_invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn err_unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

fn err_len<E: std::fmt::Display>(e: E) -> io::Error {
    err_invalid(format!("SSR cipher: {e}"))
}

/// OpenSSL EVP_BytesToKey(MD5, 无盐)：d_i = MD5(d_{i-1} || password)，拼接后截断。
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev = [0u8; BLOCK];
    let mut first = true;
    while key.len() < key_len {
        let mut h = Md5::new();
        if !first {
            h.update(prev);
        }
        h.update(password);
        let digest = h.finalize();
        key.extend_from_slice(&digest);
        prev.copy_from_slice(&digest);
        first = false;
    }
    key.truncate(key_len);
    key
}

/// AES 块加密器（CFB/CTR 共用）。
enum AesBlock {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl AesBlock {
    fn new(key: &[u8]) -> io::Result<Self> {
        Ok(match key.len() {
            16 => Self::A128(Aes128::new_from_slice(key).map_err(err_len)?),
            24 => Self::A192(Aes192::new_from_slice(key).map_err(err_len)?),
            32 => Self::A256(Aes256::new_from_slice(key).map_err(err_len)?),
            n => return Err(err_invalid(format!("SSR cipher: bad AES key length {n}"))),
        })
    }

    #[inline]
    fn encrypt(&self, block: &mut Block16) {
        match self {
            Self::A128(c) => c.encrypt_block(block),
            Self::A192(c) => c.encrypt_block(block),
            Self::A256(c) => c.encrypt_block(block),
        }
    }
}

/// Go `cipher.NewCFBEncrypter/Decrypter`：全块 CFB-128。
/// 加密反馈密文输出，解密反馈密文输入。
struct Cfb {
    block: AesBlock,
    /// 反馈块（Go 的 next）：初始为 IV，之后为最近一个密文块。
    feedback: [u8; BLOCK],
    /// 当前密钥流块（Go 的 out）。
    keystream: [u8; BLOCK],
    used: usize,
    decrypt: bool,
}

impl Cfb {
    fn new(block: AesBlock, iv: &[u8], decrypt: bool) -> Self {
        let mut feedback = [0u8; BLOCK];
        feedback.copy_from_slice(iv);
        Self {
            block,
            feedback,
            keystream: [0u8; BLOCK],
            // Go 初始 outUsed = blockSize，首次调用即生成密钥流。
            used: BLOCK,
            decrypt,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        let mut off = 0;
        while off < data.len() {
            if self.used == BLOCK {
                let mut ks = Block16::clone_from_slice(&self.feedback);
                self.block.encrypt(&mut ks);
                self.keystream.copy_from_slice(&ks);
                self.used = 0;
            }
            let n = (BLOCK - self.used).min(data.len() - off);
            let ks = &self.keystream[self.used..self.used + n];
            let dst = &mut data[off..off + n];
            let fb = &mut self.feedback[self.used..self.used + n];
            if self.decrypt {
                fb.copy_from_slice(dst);
                for (b, k) in dst.iter_mut().zip(ks.iter()) {
                    *b ^= *k;
                }
            } else {
                for (b, k) in dst.iter_mut().zip(ks.iter()) {
                    *b ^= *k;
                }
                fb.copy_from_slice(dst);
            }
            self.used += n;
            off += n;
        }
    }
}

/// Go `cipher.NewCTR`：128-bit 大端计数器从 IV 起，每块 E(counter) 后 +1（溢出回绕）。
struct Ctr {
    block: AesBlock,
    ctr: [u8; BLOCK],
    keystream: [u8; BLOCK],
    used: usize,
}

impl Ctr {
    fn new(block: AesBlock, iv: &[u8]) -> Self {
        let mut ctr = [0u8; BLOCK];
        ctr.copy_from_slice(iv);
        Self {
            block,
            ctr,
            keystream: [0u8; BLOCK],
            used: BLOCK,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        let mut off = 0;
        while off < data.len() {
            if self.used == BLOCK {
                let mut ks = Block16::clone_from_slice(&self.ctr);
                self.block.encrypt(&mut ks);
                self.keystream.copy_from_slice(&ks);
                for b in self.ctr.iter_mut().rev() {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                }
                self.used = 0;
            }
            let n = (BLOCK - self.used).min(data.len() - off);
            for i in 0..n {
                data[off + i] ^= self.keystream[self.used + i];
            }
            self.used += n;
            off += n;
        }
    }
}

/// RC4（KSA + PRGA）。
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

enum Stream {
    Cfb(Cfb),
    Ctr(Ctr),
    ChaCha20(ChaCha20),
    Rc4(Rc4),
}

impl Stream {
    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::Cfb(s) => s.apply(data),
            Self::Ctr(s) => s.apply(data),
            Self::ChaCha20(s) => s.apply_keystream(data),
            Self::Rc4(s) => s.apply(data),
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Cfb,
    Ctr,
    ChaCha20Ietf,
    Rc4Md5,
}

struct Info {
    key_len: usize,
    iv_len: usize,
    kind: Kind,
}

fn cipher_info(method: &str) -> Option<Info> {
    let (key_len, iv_len, kind) = match method {
        "aes-128-cfb" => (16, 16, Kind::Cfb),
        "aes-192-cfb" => (24, 16, Kind::Cfb),
        "aes-256-cfb" => (32, 16, Kind::Cfb),
        "aes-128-ctr" => (16, 16, Kind::Ctr),
        "aes-192-ctr" => (24, 16, Kind::Ctr),
        "aes-256-ctr" => (32, 16, Kind::Ctr),
        "chacha20-ietf" => (32, 12, Kind::ChaCha20Ietf),
        "rc4-md5" => (16, 16, Kind::Rc4Md5),
        "rc4-md5-6" => (16, 6, Kind::Rc4Md5),
        _ => return None,
    };
    Some(Info {
        key_len,
        iv_len,
        kind,
    })
}

fn new_stream(info: &Info, key: &[u8], iv: &[u8], encrypt: bool) -> io::Result<Stream> {
    match info.kind {
        Kind::Cfb => Ok(Stream::Cfb(Cfb::new(AesBlock::new(key)?, iv, !encrypt))),
        Kind::Ctr => Ok(Stream::Ctr(Ctr::new(AesBlock::new(key)?, iv))),
        Kind::ChaCha20Ietf => {
            let c = ChaCha20::new_from_slices(key, iv).map_err(err_len)?;
            Ok(Stream::ChaCha20(c))
        }
        Kind::Rc4Md5 => {
            let mut h = Md5::new();
            h.update(key);
            h.update(iv);
            Ok(Stream::Rc4(Rc4::new(&h.finalize())))
        }
    }
}

pub struct SsrCipher {
    info: Info,
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
    enc: Option<Stream>,
    dec: Option<Stream>,
}

impl SsrCipher {
    /// `method` 为空时与 Go 一致默认为 `rc4-md5`。
    pub fn new(method: &str, password: &str) -> io::Result<SsrCipher> {
        if password.is_empty() {
            return Err(err_invalid("SSR cipher: empty password"));
        }
        let method = if method.is_empty() { "rc4-md5" } else { method };
        let info = cipher_info(method)
            .ok_or_else(|| err_unsupported(format!("SSR cipher: unsupported method: {method}")))?;
        let key = evp_bytes_to_key(password.as_bytes(), info.key_len);
        Ok(SsrCipher {
            info,
            key,
            iv: None,
            enc: None,
            dec: None,
        })
    }

    pub fn iv_len(&self) -> usize {
        self.info.iv_len
    }

    pub fn encrypt_inited(&self) -> bool {
        self.enc.is_some()
    }

    /// 新连接调用：首次随机生成 IV（之后返回既有 IV），初始化加密流。
    pub fn init_encrypt(&mut self) -> io::Result<Vec<u8>> {
        if self.enc.is_some() {
            return Ok(self.iv.clone().unwrap());
        }
        if self.iv.is_none() {
            let mut iv = vec![0u8; self.info.iv_len];
            rand::thread_rng().fill_bytes(&mut iv);
            self.iv = Some(iv);
        }
        let iv = self.iv.clone().unwrap();
        self.enc = Some(new_stream(&self.info, &self.key, &iv, true)?);
        Ok(iv)
    }

    pub fn init_decrypt(&mut self, iv: &[u8]) -> io::Result<()> {
        if iv.len() != self.info.iv_len {
            return Err(err_invalid(format!(
                "SSR cipher: IV must be exactly {} bytes, got {}",
                self.info.iv_len,
                iv.len()
            )));
        }
        self.dec = Some(new_stream(&self.info, &self.key, iv, false)?);
        Ok(())
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        match &mut self.enc {
            Some(s) => s.apply(data),
            None => panic!("SSR cipher: encrypt stream not initialized"),
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        match &mut self.dec {
            Some(s) => s.apply(data),
            None => panic!("SSR cipher: decrypt stream not initialized"),
        }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P1: &[u8] = b"ssr-vector-1:";
    const P2: &[u8] = b"0123456789abcdef0123456789abcdef";

    /// Go 参考实现（password=testpass，IV=全 0x11，P1/P2 连续两次 Encrypt）生成的黄金向量。
    /// 每项：(method, key_len, iv_len, ct1_hex, ct2_hex)。
    const VECTORS: &[(&str, usize, usize, &str, &str)] = &[
        (
            "aes-128-cfb",
            16,
            16,
            "3aef84ee9b687f72c4329dc415",
            "f24bd11578f3d961b05d597252208339f864fce48020087e29daee9c91193ecf",
        ),
        (
            "aes-192-cfb",
            24,
            16,
            "bfe6e16a75a80189ae47375260",
            "43a7302c1a9cf0542216ad1ade697430fb6d35ecb407760ba8022b60b541d3b0",
        ),
        (
            "aes-256-cfb",
            32,
            16,
            "a4138fed99087a7f129e234da6",
            "c7fd602f7e51fce3875dc4b583eb47bf2f6b5057865be078af434b10e4744f8f",
        ),
        (
            "aes-128-ctr",
            16,
            16,
            "3aef84ee9b687f72c4329dc415",
            "f24bd16186edfd201d9e2f4bc6ac83555eab5ffce5120b67e4bd6fe8f560387e",
        ),
        (
            "aes-192-ctr",
            24,
            16,
            "bfe6e16a75a80189ae47375260",
            "43a730733b3642e3d4b6709f56dba1ec342a8a9338122da94ebbcea8bfbfb6e6",
        ),
        (
            "aes-256-ctr",
            32,
            16,
            "a4138fed99087a7f129e234da6",
            "c7fd605bbe1faf5caf069127d51482a97d88dbdc5bcf2434508a46eb402e3b5b",
        ),
        (
            "chacha20-ietf",
            32,
            12,
            "0c124abdd7db37ec38d8581d36",
            "8b7cdf84f4875498882a68663894be4c1321a4f63d7a0b0ed07d47e0ba674018",
        ),
        (
            "rc4-md5",
            16,
            16,
            "ec612edcdbdd9a47934937c1b3",
            "2af662330fddf0f5df236b893c2b171f3ea174d5c7daee03b39f67a33bdc097d",
        ),
        (
            "rc4-md5-6",
            16,
            6,
            "3f1d976ce9ce3fb3b6c66315c5",
            "d9200a766bb5f31577825fd0167d2fa53fd4ecf6e46273a3b5b992f11e2912bc",
        ),
    ];

    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn md5_and_evp_bytes_to_key_vectors() {
        // 标准 MD5 测试向量。
        assert_eq!(hex(&Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(&Md5::digest(b"testpass")),
            "179ad45c6ce2cb97cf1029e212046e81"
        );
        // password=testpass 的 EVP_BytesToKey 派生结果（Go 生成）。
        assert_eq!(
            hex(&evp_bytes_to_key(b"testpass", 16)),
            "179ad45c6ce2cb97cf1029e212046e81"
        );
        assert_eq!(
            hex(&evp_bytes_to_key(b"testpass", 24)),
            "179ad45c6ce2cb97cf1029e212046e819c8f2c7095d28bf6"
        );
        assert_eq!(
            hex(&evp_bytes_to_key(b"testpass", 32)),
            "179ad45c6ce2cb97cf1029e212046e819c8f2c7095d28bf624ab97143b51ac4b"
        );
    }

    #[test]
    fn go_parity_vectors() {
        for &(method, key_len, iv_len, ct1, ct2) in VECTORS {
            let iv = vec![0x11u8; iv_len];
            let mut enc = SsrCipher::new(method, "testpass").unwrap();
            assert_eq!(enc.iv_len(), iv_len, "{method}");
            assert_eq!(enc.key().len(), key_len, "{method}");
            assert!(!enc.encrypt_inited(), "{method}");
            // 对齐 Go：SetIV(iv) 后 InitEncrypt 使用固定 IV。
            enc.iv = Some(iv.clone());
            assert_eq!(enc.init_encrypt().unwrap(), iv, "{method}");
            assert!(enc.encrypt_inited(), "{method}");

            let (mut b1, mut b2) = (P1.to_vec(), P2.to_vec());
            enc.encrypt(&mut b1);
            enc.encrypt(&mut b2);
            assert_eq!(hex(&b1), ct1, "{method} ct1");
            assert_eq!(hex(&b2), ct2, "{method} ct2");

            let mut dec = SsrCipher::new(method, "testpass").unwrap();
            dec.init_decrypt(&iv).unwrap();
            dec.decrypt(&mut b1);
            dec.decrypt(&mut b2);
            assert_eq!(b1, P1, "{method} pt1");
            assert_eq!(b2, P2, "{method} pt2");
        }
    }

    #[test]
    fn chunked_equals_contiguous() {
        for &(method, _, iv_len, ct1, ct2) in VECTORS {
            let iv = vec![0x11u8; iv_len];
            let mut c = SsrCipher::new(method, "testpass").unwrap();
            c.iv = Some(iv);
            c.init_encrypt().unwrap();
            let mut combined = [P1, P2].concat();
            c.encrypt(&mut combined);
            assert_eq!(hex(&combined), format!("{ct1}{ct2}"), "{method}");
        }
    }

    #[test]
    fn random_iv_roundtrip_and_reuse() {
        for &(method, _, iv_len, _, _) in VECTORS {
            let mut enc = SsrCipher::new(method, "testpass").unwrap();
            let iv = enc.init_encrypt().unwrap();
            assert_eq!(iv.len(), iv_len, "{method}");
            // 已初始化时再次调用返回既有 IV，不重建流。
            assert_eq!(enc.init_encrypt().unwrap(), iv, "{method}");

            let mut data = [P1, P2].concat();
            enc.encrypt(&mut data);

            let mut dec = SsrCipher::new(method, "testpass").unwrap();
            dec.init_decrypt(&iv).unwrap();
            dec.decrypt(&mut data);
            assert_eq!(data, [P1, P2].concat(), "{method}");
        }
    }

    #[test]
    fn errors() {
        assert!(SsrCipher::new("aes-128-ofb", "pass").is_err());
        assert!(SsrCipher::new("aes-128-cfb", "").is_err());
        let mut c = SsrCipher::new("aes-128-cfb", "pass").unwrap();
        assert!(c.init_decrypt(&[0u8; 15]).is_err());
        // 空 method 对齐 Go：默认 rc4-md5。
        assert_eq!(SsrCipher::new("", "pass").unwrap().iv_len(), 16);
    }
}

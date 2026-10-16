// SPDX-License-Identifier: GPL-2.0
//! P18c+：最小 TLS 1.3 客户端（REALITY / Vision 专用，自实现）。
//!
//! 为什么不用 rustls：REALITY 要求自定义 ClientHello（32B session_id 密封值、
//! X25519MLKEM768 混合 key share）并取用 ECDHE 私钥派生 authKey，rustls 不暴露
//! 这些钩子；Vision splice 还要求「解密一个记录、交付、随时可切到裸 TCP 直通」。
//!
//! 范围（够用即止）：TLS 1.3 only；AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305；
//! X25519 与 X25519MLKEM768；证书校验由 `CertPolicy` 决定（REALITY 用 HMAC 绑定
//! `Custom`；shadow-tls 伪装站握手用 `WebPki` 或 `Insecure`）。
//! 不支持：HRR、early data、client cert、PSK 恢复。
//!
//! 线程模型：`handshake` 在分裂前同步跑完；之后读半/写半共享 `Shared`（短锁），
//! 读半阻塞 socket 读在锁外；`raw_read` 开关由 Vision 层置位后读半直通裸 TCP。

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256, Sha384};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

// ---------------------------------------------------------------- 常量 / 套件

pub const CS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const CS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const CS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;

const CT_CHANGE_CIPHER_SPEC: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPLICATION_DATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_KEY_UPDATE: u8 = 24;
const HS_NEW_SESSION_TICKET: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl Suite {
    fn from_id(id: u16) -> io::Result<Self> {
        match id {
            CS_AES_128_GCM_SHA256 => Ok(Suite::Aes128GcmSha256),
            CS_AES_256_GCM_SHA384 => Ok(Suite::Aes256GcmSha384),
            CS_CHACHA20_POLY1305_SHA256 => Ok(Suite::ChaCha20Poly1305Sha256),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tls13: 服务端选择的套件 {other:#06x} 不支持"),
            )),
        }
    }

    fn hash_len(&self) -> usize {
        match self {
            Suite::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Suite::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
            _ => Sha256::digest(data).to_vec(),
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Suite::Aes128GcmSha256 => 16,
            _ => 32,
        }
    }
}

// ---------------------------------------------------------------- HKDF / 密钥表

/// HKDF-Extract（RFC 5869）：PRK = HMAC-Hash(salt, IKM)。
fn hkdf_extract(suite: Suite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match suite {
        Suite::Aes256GcmSha384 => {
            let mut m = <Hmac<Sha384> as hmac::Mac>::new_from_slice(salt).expect("hmac key");
            m.update(ikm);
            m.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut m = <Hmac<Sha256> as hmac::Mac>::new_from_slice(salt).expect("hmac key");
            m.update(ikm);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// HKDF-Expand（RFC 5869）。
fn hkdf_expand(suite: Suite, prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = match suite {
            Suite::Aes256GcmSha384 => {
                let mut m = <Hmac<Sha384> as hmac::Mac>::new_from_slice(prk).expect("hmac key");
                m.update(&input);
                m.finalize().into_bytes().to_vec()
            }
            _ => {
                let mut m = <Hmac<Sha256> as hmac::Mac>::new_from_slice(prk).expect("hmac key");
                m.update(&input);
                m.finalize().into_bytes().to_vec()
            }
        };
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

/// TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）。
fn hkdf_expand_label(
    suite: Suite,
    secret: &[u8],
    label: &str,
    ctx: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + ctx.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(ctx.len() as u8);
    info.extend_from_slice(ctx);
    hkdf_expand(suite, secret, &info, out_len)
}

/// Derive-Secret(secret, label, messages)。
fn derive_secret(suite: Suite, secret: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
    hkdf_expand_label(
        suite,
        secret,
        label,
        &suite.hash(transcript),
        suite.hash_len(),
    )
}

/// HMAC-Hash（完成键/FINISHED 校验用）。
fn hmac_hash(suite: Suite, key: &[u8], data: &[u8]) -> Vec<u8> {
    match suite {
        Suite::Aes256GcmSha384 => {
            let mut m = <Hmac<Sha384> as hmac::Mac>::new_from_slice(key).expect("hmac key");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut m = <Hmac<Sha256> as hmac::Mac>::new_from_slice(key).expect("hmac key");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

// ---------------------------------------------------------------- AEAD 记录层

enum AeadKey {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl AeadKey {
    fn new(suite: Suite, key: &[u8]) -> io::Result<Self> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, "tls13: AEAD 密钥长度错误");
        Ok(match suite {
            Suite::Aes128GcmSha256 => {
                AeadKey::Aes128(Box::new(Aes128Gcm::new_from_slice(key).map_err(|_| bad())?))
            }
            Suite::Aes256GcmSha384 => {
                AeadKey::Aes256(Box::new(Aes256Gcm::new_from_slice(key).map_err(|_| bad())?))
            }
            Suite::ChaCha20Poly1305Sha256 => AeadKey::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| bad())?,
            )),
        })
    }

    fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        let err = |_| io::Error::other("tls13: 记录加密失败");
        match self {
            AeadKey::Aes128(c) => c
                .encrypt_in_place(aes_gcm::Nonce::from_slice(nonce), aad, buf)
                .map_err(err),
            AeadKey::Aes256(c) => c
                .encrypt_in_place(aes_gcm::Nonce::from_slice(nonce), aad, buf)
                .map_err(err),
            AeadKey::ChaCha(c) => c
                .encrypt_in_place(chacha20poly1305::Nonce::from_slice(nonce), aad, buf)
                .map_err(err),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        let err = |_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "tls13: 记录解密失败（密钥不同步或对端未加密）",
            )
        };
        match self {
            AeadKey::Aes128(c) => c
                .decrypt_in_place(aes_gcm::Nonce::from_slice(nonce), aad, buf)
                .map_err(err),
            AeadKey::Aes256(c) => c
                .decrypt_in_place(aes_gcm::Nonce::from_slice(nonce), aad, buf)
                .map_err(err),
            AeadKey::ChaCha(c) => c
                .decrypt_in_place(chacha20poly1305::Nonce::from_slice(nonce), aad, buf)
                .map_err(err),
        }
    }
}

/// 单向记录层密钥（含流量密钥，支持 KeyUpdate）。
pub struct RecordKeys {
    suite: Suite,
    secret: Vec<u8>,
    key: AeadKey,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKeys {
    fn new(suite: Suite, secret: Vec<u8>) -> io::Result<Self> {
        let key = hkdf_expand_label(suite, &secret, "key", &[], suite.key_len());
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&hkdf_expand_label(suite, &secret, "iv", &[], 12));
        Ok(RecordKeys {
            suite,
            secret,
            key: AeadKey::new(suite, &key)?,
            iv,
            seq: 0,
        })
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= seq[i];
        }
        n
    }

    /// 加密一条记录（TLS 1.3：外记录恒为 0x17，真实类型在明文尾部）。
    fn seal(&mut self, content_type: u8, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(data);
        inner.push(content_type);
        let mut hdr = [CT_APPLICATION_DATA, 0x03, 0x03, 0, 0];
        let total = inner.len() + 16;
        hdr[3..5].copy_from_slice(&(total as u16).to_be_bytes());
        let nonce = self.nonce();
        self.key.encrypt(&nonce, &hdr, &mut inner)?;
        self.seq += 1;
        let mut out = Vec::with_capacity(5 + inner.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&inner);
        Ok(out)
    }

    /// 解密一条记录（hdr 为 5 字节记录头，ct 为其余部分）；返回（内容类型, 明文）。
    /// P31：shadow-tls v2 读半用它识别「伪装站握手后的真实 TLS 记录」并跳过。
    pub(crate) fn open(&mut self, hdr: &[u8], ct: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        let mut buf = ct.to_vec();
        let nonce = self.nonce();
        self.key.decrypt(&nonce, hdr, &mut buf)?;
        self.seq += 1;
        // 去填充（零字节），最后一个非零字节是真实内容类型。
        while let Some(&0) = buf.last() {
            buf.pop();
        }
        let ct = buf
            .pop()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "tls13: 内层明文为空"))?;
        Ok((ct, buf))
    }

    /// traffic upd（RFC 8446 §7.2 KeyUpdate）。
    fn update(&mut self) -> io::Result<()> {
        self.secret = hkdf_expand_label(
            self.suite,
            &self.secret,
            "traffic upd",
            &[],
            self.suite.hash_len(),
        );
        self.key = AeadKey::new(
            self.suite,
            &hkdf_expand_label(self.suite, &self.secret, "key", &[], self.suite.key_len()),
        )?;
        self.iv
            .copy_from_slice(&hkdf_expand_label(self.suite, &self.secret, "iv", &[], 12));
        self.seq = 0;
        Ok(())
    }
}

// ---------------------------------------------------------------- A2 #6：CH 分片
/// A2 #6：`tls_fragment*` 配置（None = 关；`(len_min, len_max, int_min_ms, int_max_ms)`）。
/// 解析在 `main.rs` 完成（`tls_fragment_length` = `50-100` 字节区间；
/// `tls_fragment_interval` = `10-20` 毫秒区间，对照 dae 全局配置默认值）。
static TLS_FRAGMENT: std::sync::OnceLock<(usize, usize, u64, u64)> = std::sync::OnceLock::new();

/// A2 #6：设置 CH 分片参数（进程内一次；仅影响自实现 TLS 路径 = REALITY/自实现 TLS1.3）。
pub fn configure_fragment(len_min: usize, len_max: usize, int_min_ms: u64, int_max_ms: u64) {
    let _ = TLS_FRAGMENT.set((
        len_min.clamp(1, 8192),
        len_max.clamp(len_min, 8192),
        int_min_ms,
        int_max_ms,
    ));
}

fn fragment_config() -> Option<(usize, usize, u64, u64)> {
    TLS_FRAGMENT.get().copied()
}

// ---------------------------------------------------------------- ClientHello

/// ClientHello 构造参数（绕开 rustls 的可控字段）。
pub struct ClientHelloSpec {
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    /// 32 字节 legacy_session_id（REALITY 会先填密封值；TLS 要求服务端回显）。
    pub session_id: [u8; 32],
    /// 32 字节 client random（REALITY 用前 20B 作 HKDF salt、后 12B 作 AEAD nonce）。
    pub random: [u8; 32],
    /// 是否发送 X25519MLKEM768 混合 key share（当前 REALITY 服务端强制要求）。
    pub hybrid: bool,
}

struct Ext {
    t: u16,
    body: Vec<u8>,
}

fn push_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn build_extensions(entries: &[Ext], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    for e in entries {
        push_u16(&mut body, e.t);
        push_u16(&mut body, e.body.len() as u16);
        body.extend_from_slice(&e.body);
    }
    push_u16(out, body.len() as u16);
    out.extend_from_slice(&body);
}

fn grease_pool() -> [u16; 16] {
    [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ]
}

fn rand_u16() -> u16 {
    use rand::RngCore;
    (rand::thread_rng().next_u32() & 0xffff) as u16
}

/// 构造 Chrome 风格 ClientHello（GREASE + X25519MLKEM768/x25519 key share）。
pub fn build_client_hello(spec: &ClientHelloSpec, kx: &ClientKx) -> Vec<u8> {
    build_full_hello(spec, kx)
}

fn build_full_hello(spec: &ClientHelloSpec, kx: &ClientKx) -> Vec<u8> {
    // GREASE（uTLS greaseSeed 语义：同一次 CH 内各位置取**不同**值；
    // 全部相同或任意两个扩展类型相撞都会被严格解析器拒收）。
    let grease_head = grease_pool()[(rand_u16() % 16) as usize];
    let mut gi = (rand_u16() % 16) as usize;
    if grease_pool()[gi] == grease_head {
        gi = (gi + 5) % 16;
    }
    let grease_tail = grease_pool()[gi];
    let grease_group = grease_head;

    let mut body = Vec::with_capacity(2048);
    // legacy_version / random / session_id
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&spec.random);
    body.push(32);
    body.extend_from_slice(&spec.session_id);
    // cipher suites（Chrome 顺序，含 GREASE）
    let suites: Vec<u16> = vec![
        grease_head,
        CS_AES_128_GCM_SHA256,
        CS_AES_256_GCM_SHA384,
        CS_CHACHA20_POLY1305_SHA256,
        0xc02b,
        0xc02f,
        0xc02c,
        0xc030,
        0xcca9,
        0xcca8,
        0xc013,
        0xc014,
        0x009c,
        0x009d,
        0x002f,
        0x0035,
    ];
    push_u16(&mut body, (suites.len() * 2) as u16);
    for s in &suites {
        push_u16(&mut body, *s);
    }
    body.push(1); // compression methods
    body.push(0); // null

    // extensions（Chrome 近似顺序；GREASE 兜头兜尾）
    let mut exts: Vec<Ext> = Vec::new();
    exts.push(Ext {
        t: grease_head,
        body: Vec::new(),
    });

    let mut sni = Vec::new();
    push_u16(&mut sni, (spec.server_name.len() + 3) as u16);
    sni.push(0);
    push_u16(&mut sni, spec.server_name.len() as u16);
    sni.extend_from_slice(spec.server_name.as_bytes());
    exts.push(Ext {
        t: 0x0000,
        body: sni,
    });

    exts.push(Ext {
        t: 0x0017,
        body: Vec::new(),
    }); // extended_master_secret
    exts.push(Ext {
        t: 0xff01,
        body: vec![0],
    }); // renegotiation_info

    let mut group_ids: Vec<u16> = Vec::new();
    group_ids.push(grease_group);
    if spec.hybrid {
        group_ids.push(GROUP_X25519_MLKEM768);
    }
    group_ids.push(GROUP_X25519);
    group_ids.push(0x0017); // secp256r1
    group_ids.push(0x0018); // secp384r1
    let mut groups = Vec::new();
    push_u16(&mut groups, (group_ids.len() * 2) as u16);
    for g in &group_ids {
        push_u16(&mut groups, *g);
    }
    exts.push(Ext {
        t: 0x000a,
        body: groups,
    });

    exts.push(Ext {
        t: 0x000b,
        body: vec![1, 0],
    }); // ec_point_formats
    exts.push(Ext {
        t: 0x0023,
        body: Vec::new(),
    }); // session_ticket

    let mut alpn = Vec::new();
    let mut list = Vec::new();
    for a in &spec.alpn {
        list.push(a.len() as u8);
        list.extend_from_slice(a);
    }
    push_u16(&mut alpn, list.len() as u16);
    alpn.extend_from_slice(&list);
    exts.push(Ext {
        t: 0x0010,
        body: alpn,
    });

    exts.push(Ext {
        t: 0x0005,
        body: vec![1, 0, 0, 0, 0],
    }); // status_request

    let sigalgs: Vec<u16> = vec![
        // Chrome 120（uTLS HelloChrome_120）的签名算法顺序/集合，逐项对齐：
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut sa = Vec::new();
    push_u16(&mut sa, (sigalgs.len() * 2) as u16);
    for s in &sigalgs {
        push_u16(&mut sa, *s);
    }
    exts.push(Ext {
        t: 0x000d,
        body: sa.clone(),
    });
    exts.push(Ext {
        t: 0x0012,
        body: Vec::new(),
    }); // signed_certificate_timestamp

    let mut ks = Vec::new();
    let mut shares = Vec::new();
    {
        // GREASE 空 share：解析器不允许 len(data)==0，需 1 字节占位；
        // 组 id 与 supported_groups 中的 GREASE 一致。
        push_u16(&mut shares, grease_group);
        push_u16(&mut shares, 1);
        shares.push(0);
        if spec.hybrid {
            let ek = kx.mlkem_ek.as_ref().expect("hybrid 需要 ML-KEM 封装密钥");
            let x = X25519Public::from(&kx.x25519);
            push_u16(&mut shares, GROUP_X25519_MLKEM768);
            push_u16(&mut shares, (ek.len() + 32) as u16);
            shares.extend_from_slice(ek);
            shares.extend_from_slice(x.as_bytes());
        }
        let x = X25519Public::from(&kx.x25519);
        push_u16(&mut shares, GROUP_X25519);
        push_u16(&mut shares, 32);
        shares.extend_from_slice(x.as_bytes());
    }
    push_u16(&mut ks, shares.len() as u16);
    ks.extend_from_slice(&shares);
    exts.push(Ext {
        t: 0x0033,
        body: ks,
    });

    exts.push(Ext {
        t: 0x002d,
        body: vec![1, 1],
    }); // psk_key_exchange_modes

    // supported_versions：GREASE + TLS1.3 + TLS1.2（uTLS HelloChrome_120）。
    // 注意：ClientHello 里列表长度是 **u8**（ServerHello 才是 u16）。
    let grease_ver = grease_head;
    let mut sv = Vec::new();
    sv.push(6);
    push_u16(&mut sv, grease_ver);
    push_u16(&mut sv, 0x0304);
    push_u16(&mut sv, 0x0303);
    exts.push(Ext {
        t: 0x002b,
        body: sv,
    });
    exts.push(Ext {
        t: 0x001b,
        body: vec![2, 0, 2],
    }); // compress_certificate（Chrome：仅 brotli=2）

    // application_settings / ALPS（uTLS ApplicationSettingsExtension，Chrome 120）
    exts.push(Ext {
        t: 0x4469,
        body: vec![0, 3, 2, b'h', b'2'],
    });

    // GREASE ECH（uTLS BoringGREASEECH 形状：outer=0 / HKDF-SHA256+AES-128-GCM /
    // 随机 config_id / 随机 enc / 随机 payload（长度取 144/176/208/240））。
    // GREASE ECH（uTLS BoringGREASEECH 形状：扩展类型固定 0xfe0d（draft-17 ECH），
    // outer=0 / HKDF-SHA256+AES-128-GCM / 随机 config_id / 随机 enc / 随机 payload
    // （长度取 144/176/208/240））。
    {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut e = Vec::with_capacity(16 + 256);
        e.push(0); // outer ClientHello
        push_u16(&mut e, 0x0001); // kdf = HKDF-SHA256
        push_u16(&mut e, 0x0001); // aead = AES-128-GCM
        e.push((rng.next_u32() & 0xff) as u8); // config_id
        let enc_len = 32usize;
        push_u16(&mut e, enc_len as u16);
        let mut enc = vec![0u8; enc_len];
        rng.fill_bytes(&mut enc);
        e.extend_from_slice(&enc);
        let payload_lens = [144usize, 176, 208, 240];
        let plen = payload_lens[(rng.next_u32() as usize) % 4];
        push_u16(&mut e, plen as u16);
        let mut payload = vec![0u8; plen];
        rng.fill_bytes(&mut payload);
        e.extend_from_slice(&payload);
        exts.push(Ext { t: 0xfe0d, body: e });
    }

    exts.push(Ext {
        t: grease_tail,
        body: vec![0],
    });

    // padding：BoringSSL 风格——仅当当前长度在 (0xff, 0x200) 时垫到 0x200
    // （uTLS BoringPaddingStyle；否则不发送 padding 扩展）。
    {
        let base: usize = 4 + body.len() + 2 + exts.iter().map(|e| 4 + e.body.len()).sum::<usize>();
        if base > 0xff && base < 0x200 {
            // 目标：base + 4（padding 扩展头）+ body = 0x200
            let mut pad = 0x200 - base - 4;
            if pad < 5 {
                pad = 1; // 逼近 0x200（Boring 同）
            }
            exts.push(Ext {
                t: 0x0015,
                body: vec![0; pad],
            });
        }
    }

    build_extensions(&exts, &mut body);

    let mut ch = Vec::with_capacity(body.len() + 4);
    ch.push(HS_CLIENT_HELLO);
    ch.push(((body.len() >> 16) & 0xff) as u8);
    ch.push(((body.len() >> 8) & 0xff) as u8);
    ch.push((body.len() & 0xff) as u8);
    ch.extend_from_slice(&body);
    ch
}

/// 客户端密钥材料：X25519 临时密钥 + （可选）ML-KEM-768 解封装密钥。
pub struct ClientKx {
    pub x25519: StaticSecret,
    pub mlkem_ek: Option<Vec<u8>>,
    pub mlkem_dk: Option<ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>>,
}

impl ClientKx {
    /// 生成 X25519（+ 可选 ML-KEM-768）密钥对。
    pub fn generate(hybrid: bool) -> Self {
        use ml_kem::EncodedSizeUser as _;
        use ml_kem::KemCore;
        let x25519 = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let (mlkem_ek, mlkem_dk) = if hybrid {
            let (dk, ek) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
            (Some(ek.as_bytes().to_vec()), Some(dk))
        } else {
            (None, None)
        };
        ClientKx {
            x25519,
            mlkem_ek,
            mlkem_dk,
        }
    }
}

// ---------------------------------------------------------------- 握手

/// 证书钩子：拿到叶证书 DER（Finished 之前调用）。返回 Some(ed25519 公钥) 时，
/// 后续 CertificateVerify 会用该公钥验签（REALITY）；None 表示跳过。
pub type CertHook<'a> = &'a mut dyn FnMut(&[u8]) -> io::Result<Option<Vec<u8>>>;

/// P31：证书/CertificateVerify 校验策略。
pub enum CertPolicy<'a> {
    /// REALITY：hook 返回 Some(ed25519 公钥) 则验 CV，None 跳过（自签对端+HMAC 绑定）。
    Custom(CertHook<'a>),
    /// WebPKI：链 + 主机名校验（Certificate 阶段）+ CV 验签（webpki-roots 系统根）。
    /// shadow-tls 伪装站握手用（严格模式，等价生态默认 allowInsecure=false）。
    WebPki { sni: String },
    /// 跳过证书与 CV 校验（allowInsecure=1）。
    Insecure,
}

pub struct HsOut {
    pub suite: Suite,
    pub read: RecordKeys,
    pub write: RecordKeys,
    /// 握手期间已从 socket 读入、尚未消费的原始字节（后续走记录层解析）。
    pub pending: Vec<u8>,
    pub transcript: Vec<u8>,
}

struct HsIo {
    hs_buf: Vec<u8>,
    pending: Vec<u8>,
}

impl HsIo {
    /// 明文记录读取（握手前半段）。
    fn read_plain_record<S: Read>(&mut self, s: &mut S) -> io::Result<(u8, Vec<u8>)> {
        let mut hdr = [0u8; 5];
        s.read_exact(&mut hdr)?;
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if len > 18432 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls13: 记录长度异常",
            ));
        }
        let mut body = vec![0u8; len];
        s.read_exact(&mut body)?;
        Ok((hdr[0], body))
    }

    /// 从已缓冲的原始字节里取一条完整记录（不阻塞）。
    fn take_record(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.pending.len() < 5 {
            return None;
        }
        let len = u16::from_be_bytes([self.pending[3], self.pending[4]]) as usize;
        if self.pending.len() < 5 + len {
            return None;
        }
        let typ = self.pending[0];
        let body = self.pending[5..5 + len].to_vec();
        self.pending.drain(..5 + len);
        Some((typ, body))
    }

    /// 取下一个握手消息（跨记录重组）。
    fn next_handshake_msg(&mut self) -> Option<(u8, Vec<u8>)> {
        // P38：原为 `loop { … return None; }`（首轮必退出；clippy::never_loop）。语义不变。
        if self.hs_buf.len() >= 4 {
            let len = ((self.hs_buf[1] as usize) << 16)
                | ((self.hs_buf[2] as usize) << 8)
                | (self.hs_buf[3] as usize);
            if self.hs_buf.len() >= 4 + len {
                let typ = self.hs_buf[0];
                let body = self.hs_buf[4..4 + len].to_vec();
                self.hs_buf.drain(..4 + len);
                return Some((typ, body));
            }
        }
        None
    }
}

fn alert_error(body: &[u8]) -> io::Error {
    let level = body.first().copied().unwrap_or(0);
    let desc = body.get(1).copied().unwrap_or(0);
    let name = match desc {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        70 => "protocol_version",
        80 => "internal_error",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        116 => "certificate_required",
        _ => "unknown",
    };
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!("tls13: 收到 alert level={level} desc={desc}({name})"),
    )
}

/// 跑完客户端握手（TLS 1.3 only），返回记录层密钥与握手后余量。
pub fn client_handshake<S: Read + Write>(
    s: &mut S,
    client_hello: &[u8],
    kx: &ClientKx,
    mut policy: CertPolicy,
) -> io::Result<HsOut> {
    let mut io_hs = HsIo {
        hs_buf: Vec::new(),
        pending: Vec::new(),
    };

    // 发送 ClientHello。A2 #6：`tls_fragment` 开启时按 `tls_fragment_length`
    // （字节范围）把 CH 切成多个明文记录、按 `tls_fragment_interval`（毫秒范围）
    // 间隔发送（对照 dae/utls 的 SNI 分片抗阻断；TLS 允许握手消息跨多条记录）。
    // 未开启时保持单记录（本实现 CH <16KB）。
    let ch_len = client_hello.len();
    let frag = fragment_config();
    match frag {
        Some((len_min, len_max, int_min_ms, int_max_ms)) if ch_len > 0 => {
            let mut off = 0usize;
            let mut first = true;
            while off < ch_len {
                let want = len_min + (rand_u16() as usize) % (len_max - len_min + 1).max(1);
                let end = (off + want).min(ch_len);
                let part = &client_hello[off..end];
                let mut rec = Vec::with_capacity(5 + part.len());
                rec.extend_from_slice(&[CT_HANDSHAKE, 0x03, 0x01]);
                rec.extend_from_slice(&(part.len() as u16).to_be_bytes());
                rec.extend_from_slice(part);
                s.write_all(&rec)?;
                s.flush()?;
                off = end;
                if !first || off < ch_len {
                    // 首片后（或仍有后续片）按区间随机间隔——乱序/分片观测更自然。
                    if int_max_ms > 0 {
                        let wait =
                            int_min_ms + (rand_u16() as u64) % (int_max_ms - int_min_ms + 1).max(1);
                        std::thread::sleep(std::time::Duration::from_millis(wait));
                    }
                }
                first = false;
            }
        }
        _ => {
            let mut rec = Vec::with_capacity(5 + ch_len);
            rec.extend_from_slice(&[CT_HANDSHAKE, 0x03, 0x01]);
            rec.extend_from_slice(&(ch_len as u16).to_be_bytes());
            rec.extend_from_slice(client_hello);
            s.write_all(&rec)?;
            s.flush()?;
        }
    }

    let mut transcript = client_hello.to_vec();
    let mut suite: Option<Suite> = None;
    let mut server_random = [0u8; 32];
    let mut key_share_group: u16 = 0;
    let mut key_share_data: Vec<u8> = Vec::new();
    let mut got_server_hello = false;

    // 1) 读 ServerHello（明文记录流；跳过 CCS）。
    while !got_server_hello {
        let (typ, body) = io_hs.read_plain_record(s)?;
        match typ {
            CT_CHANGE_CIPHER_SPEC => continue,
            CT_ALERT => {
                let e = alert_error(&body);
                return Err(io::Error::new(
                    e.kind(),
                    format!("tls13（等待 ServerHello）: {e}"),
                ));
            }
            CT_HANDSHAKE => {
                io_hs.hs_buf.extend_from_slice(&body);
                // P38：原 `while let Some(…) { … break; }` 首轮必 break（clippy::never_loop）。
                if let Some((mtyp, mbody)) = io_hs.next_handshake_msg() {
                    if mtyp != HS_SERVER_HELLO {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("tls13: 握手首消息类型 {mtyp} 非 ServerHello"),
                        ));
                    }
                    parse_server_hello(
                        &mbody,
                        client_hello,
                        &mut suite,
                        &mut server_random,
                        &mut key_share_group,
                        &mut key_share_data,
                    )?;
                    transcript.extend_from_slice(&wrap_handshake(HS_SERVER_HELLO, &mbody));
                    got_server_hello = true;
                }
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("tls13: 未预期记录类型 {other}"),
                ))
            }
        }
    }
    let suite = suite.expect("suite");

    // 2) 计算 ECDHE 共享密钥（hybrid：ML-KEM ss || X25519 ss）。
    let shared = derive_shared(suite, kx, key_share_group, &key_share_data)?;

    // 3) 握手密钥表。
    let zeros = vec![0u8; suite.hash_len()];
    let early = hkdf_extract(suite, &zeros, &zeros);
    let derived1 = derive_secret(suite, &early, "derived", &[]);
    let hs_secret = hkdf_extract(suite, &derived1, &shared);
    let c_hs = derive_secret(suite, &hs_secret, "c hs traffic", &transcript);
    let s_hs = derive_secret(suite, &hs_secret, "s hs traffic", &transcript);
    let mut read_keys = RecordKeys::new(suite, s_hs.clone())?;
    let mut write_keys = RecordKeys::new(suite, c_hs.clone())?;

    // 4) 解密服务端握手飞行：EE / Cert / CV / Fin。
    let server_hs_secret = s_hs;
    let mut cert_pub: Option<Vec<u8>> = None;
    let mut webpki_certs: Option<(Vec<u8>, Vec<Vec<u8>>)> = None;
    let mut server_finished: Option<Vec<u8>> = None;
    while server_finished.is_none() {
        // 需要时补读 socket（一次可能仅得部分记录：读完必须回到循环顶重判）。
        if io_hs.pending.len() < 5
            || (io_hs.pending.len() >= 5
                && io_hs.pending.len()
                    < 5 + u16::from_be_bytes([io_hs.pending[3], io_hs.pending[4]]) as usize)
        {
            let mut tmp = [0u8; 16384];
            let n = s.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls13: 握手期间连接关闭",
                ));
            }
            io_hs.pending.extend_from_slice(&tmp[..n]);
            continue;
        }
        let Some((typ, body)) = io_hs.take_record() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls13: 握手记录不完整（内部不变量被破坏）",
            ));
        };
        match typ {
            CT_CHANGE_CIPHER_SPEC => continue,
            CT_ALERT => {
                let e = alert_error(&body);
                return Err(io::Error::new(
                    e.kind(),
                    format!("tls13（服务端飞行阶段）: {e}"),
                ));
            }
            CT_APPLICATION_DATA => {
                let hdr: [u8; 5] = [
                    CT_APPLICATION_DATA,
                    0x03,
                    0x03,
                    (body.len() >> 8) as u8,
                    body.len() as u8,
                ];
                let (ct, plain) = read_keys.open(&hdr, &body)?;
                if ct != CT_HANDSHAKE {
                    // 0.5-RTT 应用数据：握手未完成前不收。
                    continue;
                }
                io_hs.hs_buf.extend_from_slice(&plain);
                while let Some((mtyp, mbody)) = io_hs.next_handshake_msg() {
                    match mtyp {
                        HS_ENCRYPTED_EXTENSIONS => {
                            transcript.extend_from_slice(&wrap_handshake(mtyp, &mbody));
                        }
                        HS_CERTIFICATE => {
                            transcript.extend_from_slice(&wrap_handshake(mtyp, &mbody));
                            match &mut policy {
                                CertPolicy::Custom(hook) => {
                                    if let Some(leaf) = first_certificate(&mbody)? {
                                        cert_pub = hook(&leaf)?;
                                    }
                                }
                                CertPolicy::WebPki { sni } => {
                                    let certs = all_certificates(&mbody)?;
                                    if certs.is_empty() {
                                        return Err(bad("证书链为空"));
                                    }
                                    verify_webpki_chain(&certs, sni)?;
                                    webpki_certs = Some((certs[0].clone(), certs[1..].to_vec()));
                                }
                                CertPolicy::Insecure => {}
                            }
                        }
                        HS_CERTIFICATE_VERIFY => {
                            match &policy {
                                CertPolicy::Custom(_) => {
                                    if let Some(pk) = &cert_pub {
                                        verify_certificate_verify_ed25519(
                                            suite,
                                            pk,
                                            &mbody,
                                            &transcript,
                                        )?;
                                    }
                                }
                                CertPolicy::WebPki { .. } => {
                                    let (leaf, inters) =
                                        webpki_certs.as_ref().ok_or_else(|| {
                                            bad("CV 前未收到证书（内部不变量被破坏）")
                                        })?;
                                    verify_certificate_verify_webpki(
                                        suite,
                                        leaf,
                                        inters,
                                        &mbody,
                                        &transcript,
                                    )?;
                                }
                                CertPolicy::Insecure => {}
                            }
                            transcript.extend_from_slice(&wrap_handshake(mtyp, &mbody));
                        }
                        HS_FINISHED => {
                            // 校验服务端 Finished（transcript 不含本条）。
                            let key = hkdf_expand_label(
                                suite,
                                &server_hs_secret,
                                "finished",
                                &[],
                                suite.hash_len(),
                            );
                            let expect = hmac_hash(suite, &key, &suite.hash(&transcript));
                            if mbody.len() != expect.len() {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "tls13: 服务端 Finished 长度异常",
                                ));
                            }
                            if !constant_time_eq(&mbody, &expect) {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "tls13: 服务端 Finished 校验失败",
                                ));
                            }
                            transcript.extend_from_slice(&wrap_handshake(mtyp, &mbody));
                            server_finished = Some(mbody);
                        }
                        HS_NEW_SESSION_TICKET => { /* 握手后才会来，忽略 */ }
                        other => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("tls13: 未预期握手消息类型 {other}"),
                            ))
                        }
                    }
                }
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("tls13: 握手阶段未预期记录类型 {other}"),
                ))
            }
        }
    }
    let _ = server_finished;

    // 5) 客户端 Finished。
    let c_fin_key = hkdf_expand_label(suite, &c_hs, "finished", &[], suite.hash_len());
    let client_verify = hmac_hash(suite, &c_fin_key, &suite.hash(&transcript));
    let mut fin_msg = Vec::with_capacity(4 + client_verify.len());
    fin_msg.push(HS_FINISHED);
    fin_msg.push(0);
    fin_msg.push(0);
    fin_msg.push(client_verify.len() as u8);
    fin_msg.extend_from_slice(&client_verify);
    let fin_rec = write_keys.seal(CT_HANDSHAKE, &fin_msg)?;
    s.write_all(&fin_rec)?;
    s.flush()?;
    transcript.extend_from_slice(&fin_msg);

    // 6) 应用数据密钥（transcript: CH..server Finished，不含 client Finished）。
    let master = hkdf_extract(
        suite,
        &derive_secret(suite, &hs_secret, "derived", &[]),
        &zeros,
    );
    // 注意：master 的 transcript 是「CH..server Finished」，即当前 transcript 去掉尾部 client Finished。
    let mut tr_app = transcript.clone();
    tr_app.truncate(tr_app.len() - fin_msg.len());
    let c_ap = derive_secret(suite, &master, "c ap traffic", &tr_app);
    let s_ap = derive_secret(suite, &master, "s ap traffic", &tr_app);
    let read = RecordKeys::new(suite, s_ap)?;
    let write = RecordKeys::new(suite, c_ap)?;

    Ok(HsOut {
        suite,
        read,
        write,
        pending: io_hs.pending,
        transcript,
    })
}

fn wrap_handshake(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.push(typ);
    v.push(((body.len() >> 16) & 0xff) as u8);
    v.push(((body.len() >> 8) & 0xff) as u8);
    v.push((body.len() & 0xff) as u8);
    v.extend_from_slice(body);
    v
}

fn parse_server_hello(
    body: &[u8],
    client_hello: &[u8],
    suite: &mut Option<Suite>,
    server_random: &mut [u8; 32],
    key_share_group: &mut u16,
    key_share_data: &mut Vec<u8>,
) -> io::Result<()> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("tls13: {m}"));
    if body.len() < 38 {
        return Err(bad("ServerHello 过短"));
    }
    server_random.copy_from_slice(&body[2..34]);
    // HRR 检测
    if *server_random == [0xcf; 32] {
        return Err(bad("服务端要求 HelloRetryRequest（本实现不支持）"));
    }
    let sid_len = body[34] as usize;
    if body.len() < 35 + sid_len + 3 {
        return Err(bad("ServerHello session_id 越界"));
    }
    if sid_len != 32 || body[35..35 + 32] != client_hello[39..39 + 32] {
        return Err(bad("ServerHello session_id 未按 REALITY 回显"));
    }
    let cs = u16::from_be_bytes([body[35 + sid_len], body[35 + sid_len + 1]]);
    *suite = Some(Suite::from_id(cs)?);
    let comp = body[35 + sid_len + 2];
    if comp != 0 {
        return Err(bad("ServerHello 压缩方法非 0"));
    }
    let mut pos = 35 + sid_len + 3;
    if pos + 2 > body.len() {
        return Err(bad("ServerHello 缺 extensions"));
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + ext_total > body.len() {
        return Err(bad("ServerHello extensions 越界"));
    }
    let ext_end = pos + ext_total;
    while pos + 4 <= ext_end {
        let t = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let l = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + l > ext_end {
            return Err(bad("ServerHello 扩展越界"));
        }
        let v = &body[pos..pos + l];
        match t {
            0x002b => {
                if v.len() != 2 || u16::from_be_bytes([v[0], v[1]]) != 0x0304 {
                    return Err(bad("服务端未选择 TLS 1.3"));
                }
            }
            0x0033 => {
                if v.len() < 4 {
                    return Err(bad("ServerHello key_share 过短"));
                }
                *key_share_group = u16::from_be_bytes([v[0], v[1]]);
                let kl = u16::from_be_bytes([v[2], v[3]]) as usize;
                if v.len() < 4 + kl {
                    return Err(bad("ServerHello key_share 越界"));
                }
                *key_share_data = v[4..4 + kl].to_vec();
            }
            _ => {}
        }
        pos += l;
    }
    Ok(())
}

fn derive_shared(_suite: Suite, kx: &ClientKx, group: u16, data: &[u8]) -> io::Result<Vec<u8>> {
    use ml_kem::kem::Decapsulate as _;
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("tls13: {m}"));
    match group {
        GROUP_X25519 => {
            if data.len() != 32 {
                return Err(bad("X25519 服务端 share 长度错误"));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(data);
            let peer = X25519Public::from(pk);
            Ok(kx.x25519.diffie_hellman(&peer).as_bytes().to_vec())
        }
        GROUP_X25519_MLKEM768 => {
            if data.len() != 1088 + 32 {
                return Err(bad("X25519MLKEM768 服务端 share 长度错误"));
            }
            let dk = kx
                .mlkem_dk
                .as_ref()
                .ok_or_else(|| bad("服务端选择 hybrid 但客户端未生成 ML-KEM 密钥"))?;
            let ct: ml_kem::Ciphertext<ml_kem::MlKem768> = data[..1088]
                .try_into()
                .map_err(|_| bad("ML-KEM 密文解析失败"))?;
            let ss = dk.decapsulate(&ct).map_err(|_| bad("ML-KEM 解封装失败"))?;
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data[1088..1120]);
            let peer = X25519Public::from(pk);
            let x = kx.x25519.diffie_hellman(&peer);
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(&ss);
            out.extend_from_slice(x.as_bytes());
            Ok(out)
        }
        other => Err(bad(&format!("服务端 key_share 组 {other:#06x} 不支持"))),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for i in 0..a.len() {
        v |= a[i] ^ b[i];
    }
    v == 0
}

/// 取握手消息里第一个证书的 DER。
fn first_certificate(body: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("tls13: {m}"));
    // body: [ctx_len 1B][ctx][list_len 3B][cert_len 3B][cert][exts...]...
    if body.len() < 4 {
        return Ok(None);
    }
    let ctx_len = body[0] as usize;
    let mut pos = 1 + ctx_len;
    if pos + 3 > body.len() {
        return Ok(None);
    }
    let list_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | (body[pos + 2] as usize);
    pos += 3;
    if pos + 3 > body.len() {
        return Ok(None);
    }
    let cert_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | (body[pos + 2] as usize);
    pos += 3;
    if pos + cert_len > body.len() {
        return Err(bad("Certificate 越界"));
    }
    let _ = list_len;
    Ok(Some(body[pos..pos + cert_len].to_vec()))
}

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("tls13: {}", m.into()))
}

/// 全量证书链解析（P31 WebPKI 用）：返回 `[叶, 中间...]`（DER）。
fn all_certificates(body: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    // body: [ctx_len 1B][ctx][list_len 3B][cert_len 3B][cert][exts]...
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let ctx_len = body[0] as usize;
    let mut pos = 1 + ctx_len;
    if pos + 3 > body.len() {
        return Err(bad("Certificate 越界（list）"));
    }
    let list_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | (body[pos + 2] as usize);
    pos += 3;
    let end = (pos + list_len).min(body.len());
    let mut out = Vec::new();
    while pos + 3 <= end {
        let cert_len = ((body[pos] as usize) << 16)
            | ((body[pos + 1] as usize) << 8)
            | (body[pos + 2] as usize);
        pos += 3;
        if pos + cert_len > end {
            return Err(bad("Certificate 越界（entry）"));
        }
        out.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
        if pos + 2 > end {
            break;
        }
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2 + ext_len;
    }
    Ok(out)
}

/// P31：WebPKI 链 + 主机名校验（在 Certificate 消息阶段执行）。
fn verify_webpki_chain(certs: &[Vec<u8>], sni: &str) -> io::Result<()> {
    let leaf = CertificateDer::from(certs[0].as_slice());
    let inters: Vec<CertificateDer<'_>> = certs[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let ee =
        webpki::EndEntityCert::try_from(&leaf).map_err(|e| bad(format!("叶证书解析失败: {e}")))?;
    let name = ServerName::try_from(sni.to_string())
        .map_err(|e| bad(format!("SNI 非法（{sni}）: {e}")))?;
    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        webpki_roots::TLS_SERVER_ROOTS,
        &inters,
        UnixTime::now(),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|e| bad(format!("证书链校验失败（{sni}）: {e}")))?;
    ee.verify_is_valid_for_subject_name(&name)
        .map_err(|e| bad(format!("证书主机名不匹配（{sni}）: {e}")))?;
    Ok(())
}

/// P31：WebPKI CertificateVerify 验签（按 CV 内的签名算法选 ring 实现）。
fn verify_certificate_verify_webpki(
    suite: Suite,
    leaf_der: &[u8],
    _intermediates: &[Vec<u8>],
    body: &[u8],
    transcript: &[u8],
) -> io::Result<()> {
    if body.len() < 4 {
        return Err(bad("CertificateVerify 过短"));
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sig_len {
        return Err(bad("CertificateVerify 签名越界"));
    }
    let alg = match scheme {
        0x0403 => webpki::ring::ECDSA_P256_SHA256,
        0x0503 => webpki::ring::ECDSA_P384_SHA384,
        0x0804 => webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0807 => webpki::ring::ED25519,
        _ => {
            return Err(bad(format!("CV 签名算法 {scheme:#06x} 不支持")));
        }
    };
    // TLS 1.3 签名输入：64 空格 + 上下文串 + 0x00 + transcript 哈希。
    let hash = suite.hash(transcript);
    let mut msg = vec![0x20u8; 64];
    msg.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    msg.push(0);
    msg.extend_from_slice(&hash);
    let leaf = CertificateDer::from(leaf_der);
    let ee =
        webpki::EndEntityCert::try_from(&leaf).map_err(|e| bad(format!("叶证书解析失败: {e}")))?;
    ee.verify_signature(alg, &msg, &body[4..4 + sig_len])
        .map_err(|e| bad(format!("CertificateVerify 验签失败: {e}")))?;
    Ok(())
}

/// TLS 1.3 CertificateVerify：用证书公钥（REALITY 下为服务端静态 ed25519 公钥）验签。
/// `transcript` 为「本条之前」的握手消息流；验签哈希按套件选 SHA-256/SHA-384。
fn verify_certificate_verify_ed25519(
    suite: Suite,
    pubkey: &[u8],
    body: &[u8],
    transcript: &[u8],
) -> io::Result<()> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("tls13: {m}"));
    if body.len() < 4 {
        return Err(bad("CertificateVerify 过短"));
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sig_len {
        return Err(bad("CertificateVerify 签名越界"));
    }
    if scheme != 0x0807 {
        return Err(bad(&format!(
            "CertificateVerify 签名算法 {scheme:#06x} 不支持（REALITY 只做 ed25519）"
        )));
    }
    let sig = &body[4..4 + sig_len];
    // TLS 1.3 签名输入：64 空格 + 上下文串 + 0x00 + transcript 哈希。
    let hash = suite.hash(transcript);
    let mut msg = vec![0x20u8; 64];
    msg.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    msg.push(0);
    msg.extend_from_slice(&hash);
    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey);
    key.verify(&msg, sig)
        .map_err(|_| bad("CertificateVerify 验签失败"))
}

// ---------------------------------------------------------------- 分裂读写半

struct Shared {
    read: RecordKeys,
    write: RecordKeys,
    pending: Vec<u8>,
    want_key_update: bool,
    /// 写半已更新密钥（由写线程执行）；读半只置 want_key_update。
    /// P38：握手状态记账——写入后由读写线程消费，保留字段为调试/后续扩展用途。
    #[allow(dead_code)]
    closed_read: bool,
}

/// TLS 1.3 读半；`raw` 置位后直接读裸 TCP（Vision splice）。
pub struct Tls13Reader {
    core: Arc<Mutex<Shared>>,
    sock: TcpStream,
    raw: Arc<AtomicBool>,
    plain: Vec<u8>,
    plain_pos: usize,
    eof: bool,
    /// P38：协商套件（建立后不再读；保留供调试/扩展，`#[allow(dead_code)]`）。
    #[allow(dead_code)]
    suite: Suite,
}

/// TLS 1.3 写半。
/// stage 2：记录先密封入 `out` 再部分写出——非阻塞 WO 不丢进度、不重复加密。
pub struct Tls13Writer {
    core: Arc<Mutex<Shared>>,
    sock: TcpStream,
    /// P38：同 Tls13Reader::suite（保留字段，建立后不再读）。
    #[allow(dead_code)]
    suite: Suite,
    /// M3：Vision 上行 DIRECT——置位后裸写 TCP（不再封外层 TLS 记录）。
    raw: Arc<AtomicBool>,
    /// 已密封待写出的记录（含偏移，WO 后从断点续写）。
    out: Vec<u8>,
    out_off: usize,
}

impl Tls13Reader {
    /// P15：短连接/超时场景设置底层 socket 读超时。
    /// P38：当前调用方未使用（`#[allow(dead_code)]`，保留为对称 API）。
    #[allow(dead_code)]
    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(d)
    }

    /// Vision 层用：切到裸 TCP 读（幂等）。
    /// P38：当前调用方未使用（Vision 路径切读在协议层完成）；保留为对称 API。
    #[allow(dead_code)]
    pub fn set_raw_read(&self) {
        self.raw.store(true, Ordering::SeqCst);
    }
}

impl Tls13Writer {
    /// 半关闭：直接 FIN（不写 close_notify，splice 后写加密记录会打扰对端直通）。
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.sock.shutdown(Shutdown::Write)
    }
}

impl Read for Tls13Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // 1) 明文缓存优先。
            if self.plain_pos < self.plain.len() {
                let n = (self.plain.len() - self.plain_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
                self.plain_pos += n;
                if self.plain_pos == self.plain.len() {
                    self.plain.clear();
                    self.plain_pos = 0;
                }
                return Ok(n);
            }
            // 2) 裸直通（Vision splice）：先交付记录层前多读的裸字节。
            if self.raw.load(Ordering::SeqCst) {
                let leftover = {
                    let mut c = self.core.lock().map_err(poisoned)?;
                    std::mem::take(&mut c.pending)
                };
                if !leftover.is_empty() {
                    let n = leftover.len().min(buf.len());
                    buf[..n].copy_from_slice(&leftover[..n]);
                    if n < leftover.len() {
                        let mut c = self.core.lock().map_err(poisoned)?;
                        let mut rest = leftover[n..].to_vec();
                        rest.extend_from_slice(&c.pending);
                        c.pending = rest;
                    }
                    return Ok(n);
                }
                return self.sock.read(buf);
            }
            // 3) 需要时补读 socket（阻塞读在锁外）。
            let need_more = {
                let c = self.core.lock().map_err(poisoned)?;
                c.pending.len() < 5
                    || (c.pending.len() >= 5
                        && c.pending.len()
                            < 5 + u16::from_be_bytes([c.pending[3], c.pending[4]]) as usize)
            };
            if need_more {
                if self.eof {
                    return Ok(0);
                }
                let mut tmp = [0u8; 16384];
                let n = self.sock.read(&mut tmp)?;
                if n == 0 {
                    self.eof = true;
                    return Ok(0);
                }
                let mut c = self.core.lock().map_err(poisoned)?;
                c.pending.extend_from_slice(&tmp[..n]);
            }
            // 4) 解析一条记录。
            let rec = {
                let mut c = self.core.lock().map_err(poisoned)?;
                let len = u16::from_be_bytes([c.pending[3], c.pending[4]]) as usize;
                if c.pending.len() < 5 + len {
                    None
                } else {
                    let typ = c.pending[0];
                    let hdr = [
                        c.pending[0],
                        c.pending[1],
                        c.pending[2],
                        c.pending[3],
                        c.pending[4],
                    ];
                    let body = c.pending[5..5 + len].to_vec();
                    c.pending.drain(..5 + len);
                    Some((typ, hdr, body))
                }
            };
            let Some((typ, hdr, body)) = rec else {
                continue;
            };
            match typ {
                CT_CHANGE_CIPHER_SPEC => continue,
                CT_ALERT => {
                    let plain = {
                        let mut c = self.core.lock().map_err(poisoned)?;
                        c.read.open(&hdr, &body).map(|(_, p)| p)
                    };
                    {
                        let p = plain?;
                        if p.first() == Some(&1) {
                            // warning: close_notify → EOF
                            return Ok(0);
                        }
                        return Err(alert_error(&p));
                    }
                }
                CT_APPLICATION_DATA => {
                    let opened = {
                        let mut c = self.core.lock().map_err(poisoned)?;
                        c.read.open(&hdr, &body)
                    };
                    let (ct, plain) = match opened {
                        Ok(v) => v,
                        Err(e) => {
                            if self.raw.load(Ordering::SeqCst) {
                                // splice 已开始：这些字节其实是裸 TCP 数据，退回 pending。
                                let mut c = self.core.lock().map_err(poisoned)?;
                                let mut rest = body;
                                rest.extend_from_slice(&c.pending);
                                c.pending = rest;
                                continue;
                            }
                            return Err(e);
                        }
                    };
                    match ct {
                        CT_APPLICATION_DATA => {
                            self.plain = plain;
                            self.plain_pos = 0;
                            continue;
                        }
                        CT_HANDSHAKE => {
                            self.handle_post_handshake(&plain)?;
                            continue;
                        }
                        CT_ALERT => {
                            if plain.first() == Some(&1) {
                                return Ok(0);
                            }
                            return Err(alert_error(&plain));
                        }
                        _ => continue,
                    }
                }
                _ => continue,
            }
        }
    }
}

impl Tls13Reader {
    /// 握手后消息：KeyUpdate / NewSessionTicket。
    fn handle_post_handshake(&mut self, plain: &[u8]) -> io::Result<()> {
        let mut pos = 0usize;
        while pos + 4 <= plain.len() {
            let typ = plain[pos];
            let len = ((plain[pos + 1] as usize) << 16)
                | ((plain[pos + 2] as usize) << 8)
                | (plain[pos + 3] as usize);
            if pos + 4 + len > plain.len() {
                break;
            }
            let body = &plain[pos + 4..pos + 4 + len];
            pos += 4 + len;
            match typ {
                HS_KEY_UPDATE => {
                    let mut c = self.core.lock().map_err(poisoned)?;
                    c.read.update()?;
                    if body.first() == Some(&1) {
                        c.want_key_update = true;
                    }
                }
                HS_NEW_SESSION_TICKET => { /* 不恢复会话 */ }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Write for Tls13Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // 先冲刷上次未写完的记录；非阻塞下 WO 在消费新明文前上抛（重试幂等）。
        self.drain_out()?;
        // M3：Vision 上行 DIRECT——裸写 TCP（允许部分写，返回实写字节）。
        if self.raw.load(Ordering::SeqCst) {
            return self.sock.write(buf);
        }
        let mut c = self.core.lock().map_err(poisoned)?;
        if c.want_key_update {
            let ku = [HS_KEY_UPDATE, 0, 0, 1, 0];
            let rec = c.write.seal(CT_HANDSHAKE, &ku)?;
            self.out.extend_from_slice(&rec);
            c.write.update()?;
            c.want_key_update = false;
        }
        let mut off = 0usize;
        while off < buf.len() {
            let n = (buf.len() - off).min(16000);
            let rec = c.write.seal(CT_APPLICATION_DATA, &buf[off..off + n])?;
            self.out.extend_from_slice(&rec);
            off += n;
        }
        drop(c);
        // 尽力写出；WO 时密文留在 out，由 flush()/下次 write 续写（明文已“接受”）。
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

impl Tls13Writer {
    /// 把 `out` 中未写出的密文写到 socket；WO/EINTR 时保留偏移（可重入）。
    fn drain_out(&mut self) -> io::Result<()> {
        while self.out_off < self.out.len() {
            match self.sock.write(&self.out[self.out_off..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls13: socket 写 0",
                    ))
                }
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

fn poisoned<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("tls13: 锁中毒")
}

/// 用 TcpStream 跑握手并拆出读写半。返回（读半, 写半, 裸读开关, 裸写开关）。
pub fn connect(
    sock: TcpStream,
    client_hello: &[u8],
    kx: &ClientKx,
    cert_hook: CertHook,
    timeout: Option<Duration>,
) -> io::Result<(Tls13Reader, Tls13Writer, Arc<AtomicBool>, Arc<AtomicBool>)> {
    let _ = timeout; // 超时由调用方在 socket 上设置
    let mut s = sock.try_clone()?;
    let out = client_handshake(&mut s, client_hello, kx, CertPolicy::Custom(cert_hook))?;
    let suite = out.suite;
    let core = Arc::new(Mutex::new(Shared {
        read: out.read,
        write: out.write,
        pending: out.pending,
        want_key_update: false,
        closed_read: false,
    }));
    let raw = Arc::new(AtomicBool::new(false));
    let raw_write = Arc::new(AtomicBool::new(false));
    let reader = Tls13Reader {
        core: core.clone(),
        sock,
        raw: raw.clone(),
        plain: Vec::new(),
        plain_pos: 0,
        eof: false,
        suite,
    };
    let writer = Tls13Writer {
        core,
        sock: s,
        suite,
        raw: raw_write.clone(),
        out: Vec::new(),
        out_off: 0,
    };
    Ok((reader, writer, raw, raw_write))
}

// ---------------------------------------------------------------- 单元测试

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case1() {
        // RFC 5869 A.1：SHA-256
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..13).collect();
        let info: Vec<u8> = (0xf0..0xfa).collect();
        let prk = hkdf_extract(Suite::Aes128GcmSha256, &salt, &ikm);
        assert_eq!(
            prk.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hkdf_expand(Suite::Aes128GcmSha256, &prk, &info, 42);
        assert_eq!(
            okm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn client_hello_layout() {
        let kx = ClientKx::generate(true);
        let spec = ClientHelloSpec {
            server_name: "www.example.com".into(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            session_id: [0x41; 32],
            random: [0x42; 32],
            hybrid: true,
        };
        let ch = build_client_hello(&spec, &kx);
        assert_eq!(ch[0], HS_CLIENT_HELLO);
        let len = ((ch[1] as usize) << 16) | ((ch[2] as usize) << 8) | ch[3] as usize;
        assert_eq!(len + 4, ch.len());
        // session_id 在偏移 39，32 字节
        assert_eq!(ch[38], 32);
        assert_eq!(&ch[39..71], &[0x41; 32]);
        assert_eq!(&ch[6..38], &[0x42; 32]);
        // 包含 SNI
        let needle = b"www.example.com";
        assert!(ch.windows(needle.len()).any(|w| w == needle));
        // 包含 hybrid key share 组
        assert!(ch
            .windows(2)
            .any(|w| w == GROUP_X25519_MLKEM768.to_be_bytes()));
    }

    #[test]
    fn record_seal_open_roundtrip() {
        let mut a = RecordKeys::new(Suite::Aes128GcmSha256, vec![7u8; 32]).unwrap();
        let mut b = RecordKeys::new(Suite::Aes128GcmSha256, vec![7u8; 32]).unwrap();
        let rec = a.seal(CT_APPLICATION_DATA, b"hello world").unwrap();
        let hdr = &rec[..5];
        let (ct, plain) = b.open(hdr, &rec[5..]).unwrap();
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(plain, b"hello world");
        // 序号推进后仍一致
        let rec2 = a.seal(CT_HANDSHAKE, b"x").unwrap();
        let (ct2, p2) = b.open(&rec2[..5], &rec2[5..]).unwrap();
        assert_eq!(ct2, CT_HANDSHAKE);
        assert_eq!(p2, b"x");
    }

    #[test]
    fn key_update_roundtrip() {
        let mut a = RecordKeys::new(Suite::ChaCha20Poly1305Sha256, vec![9u8; 32]).unwrap();
        let mut b = RecordKeys::new(Suite::ChaCha20Poly1305Sha256, vec![9u8; 32]).unwrap();
        let r1 = a.seal(CT_APPLICATION_DATA, b"one").unwrap();
        let _ = b.open(&r1[..5], &r1[5..]).unwrap();
        a.update().unwrap();
        b.update().unwrap();
        let r2 = a.seal(CT_APPLICATION_DATA, b"two").unwrap();
        let (_, p) = b.open(&r2[..5], &r2[5..]).unwrap();
        assert_eq!(p, b"two");
    }

    #[test]
    fn hs_io_take_record_partial() {
        // 回归：分片到达时 take_record 必须返回 None（调用方需继续读，不得 panic）。
        let mut io = HsIo {
            hs_buf: Vec::new(),
            pending: Vec::new(),
        };
        io.pending
            .extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2]);
        assert!(io.take_record().is_none());
        io.pending.extend_from_slice(&[3, 4, 5]);
        let (t, b) = io.take_record().unwrap();
        assert_eq!(t, 0x17);
        assert_eq!(b, vec![1, 2, 3, 4, 5]);
        assert!(io.pending.is_empty());
    }

    /// 真站对拍：用本 TLS13 客户端握手 www.microsoft.com:443（验证 CH 被严格解析器接受）。
    /// `cargo test --release -- --ignored tls13_real_server`。
    #[test]
    #[ignore = "需要外网可达 www.microsoft.com:443"]
    fn tls13_real_server_handshake() {
        use std::net::{TcpStream, ToSocketAddrs as _};
        use std::time::Duration;
        // 可用 SODAMA_DAE_TLS13_TARGET 指向本地严格服务端（如 openssl s_server）
        let target = std::env::var("SODAMA_DAE_TLS13_TARGET")
            .unwrap_or_else(|_| "www.microsoft.com:443".to_string());
        let kx = ClientKx::generate(true);
        let spec = ClientHelloSpec {
            server_name: "www.microsoft.com".into(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            session_id: [0x11; 32],
            random: [0x22; 32],
            hybrid: true,
        };
        let hello = build_client_hello(&spec, &kx);
        let mut sock = TcpStream::connect_timeout(
            &target.to_socket_addrs().unwrap().next().unwrap(),
            Duration::from_secs(10),
        )
        .expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut hook = |_leaf: &[u8]| -> std::io::Result<Option<Vec<u8>>> { Ok(None) };
        let out = client_handshake(&mut sock, &hello, &kx, CertPolicy::Custom(&mut hook))
            .expect("与真站握手");
        eprintln!("tls13 真站握手成功，suite={:?}", out.suite);
    }

    /// P31：WebPKI 策略（shadow-tls 严格模式）对真实站点握手——验证链+主机名+CV
    /// 验签链路。`cargo test --release -- --ignored tls13_real_server_webpki`。
    #[test]
    #[ignore = "需要外网可达 www.microsoft.com:443"]
    fn tls13_real_server_webpki() {
        use std::net::{TcpStream, ToSocketAddrs as _};
        use std::time::Duration;
        let target = "www.microsoft.com:443";
        let kx = ClientKx::generate(true);
        let spec = ClientHelloSpec {
            server_name: "www.microsoft.com".into(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            session_id: [0x33; 32],
            random: [0x44; 32],
            hybrid: true,
        };
        let hello = build_client_hello(&spec, &kx);
        let mut sock = TcpStream::connect_timeout(
            &target.to_socket_addrs().unwrap().next().unwrap(),
            Duration::from_secs(10),
        )
        .expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let out = client_handshake(
            &mut sock,
            &hello,
            &kx,
            CertPolicy::WebPki {
                sni: "www.microsoft.com".into(),
            },
        )
        .expect("WebPKI 握手");
        eprintln!("tls13 WebPKI 真站握手成功，suite={:?}", out.suite);
    }
}

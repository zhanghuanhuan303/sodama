// SPDX-License-Identifier: GPL-2.0
//! P5-G2：VMess（AEAD，alterId=0）客户端。
//!
//! wire 格式（对照 olicesx/outbound `protocol/vmess/{cipher,conn}.go`）：
//! ```text
//! 请求头：eAuthID(16) ‖ AES-GCM(BE16(L_instr), aad=eAuthID)(18) ‖ connNonce(8) ‖ AES-GCM(instr)(L+16)
//!   eAuthID = AES-128-ECB(KDF(cmdKey,"AES Auth ID Encryption")[:16],
//!                         BE64(unix)‖rand4‖BE32(crc32(前12B)))
//!   KDF = 嵌套 HMAC-SHA256（最内层密钥 "VMess AEAD KDF"，逐层 path 作 HMAC 密钥）
//!   instr = [1B ver=1][16B bodyIV][16B bodyKey][1B V][1B options=0x0D][1B P<<4|scy]
//!           [1B 0][1B cmd][2B port BE][1B ATYP+ADDR][P 字节随机填充][4B FNV-1a-32]
//! 响应头：AES-GCM(KDF(respKey,"AEAD Resp Header Len Key")[:16],
//!                 KDF(respIV,"AEAD Resp Header Len IV")[:12], aad=∅)(BE16(L))
//!         ‖ AES-GCM(KDF(respKey,"AEAD Resp Header Key")…, payload=[V,0,0,0])
//!   respKey = SHA256(bodyKey)[..16]，respIV = SHA256(bodyIV)[..16]
//! 数据块：BE16(size XOR mask) ‖ AEAD(payload) ‖ padding
//!   size = payload + 16 + padding；padding = SHAKE128(dirIV) 抽 2B % 64
//!   mask = SHAKE128(dirIV) 下一抽 2B（先抽 padding 再抽 mask）
//!   nonce = BE16(counter) ‖ dirIV[2:12]；终止块 = size == 16+padding
//! ```
//! 边界（ADR-0017）：alterId=0、net=tcp、type=none、security∈{3,4}；IPv4 目标；
//! UDP 走固定目标模式（command=2，一块一数据报），不做 packetaddr。

use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sha3::Shake128;

type HmacSha256 = Hmac<Sha256>;

const KDF_SALT: &[u8] = b"VMess AEAD KDF";
const AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const REQ_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const REQ_LEN_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const REQ_KEY: &[u8] = b"VMess Header AEAD Key";
const REQ_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const RESP_IV: &[u8] = b"AEAD Resp Header IV";
const CMD_KEY_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// 数据块上限：16384 - AEAD tag(16) - size(2) - 最大 padding(64)（对照 Go `chunks`）。
const MAX_PAYLOAD_PER_CHUNK: usize = 16384 - 16 - 2 - 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl VmessSecurity {
    pub fn byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
        }
    }

    /// 解码安全字节（服务端/测试方向会用到；客户端只编码）。
    #[allow(dead_code)]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            3 => Some(Self::Aes128Gcm),
            4 => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }

    /// 链接里的 `scy`：auto→aes-128-gcm；none/zero/未知 → None（显式拒绝）。
    pub fn from_scy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "auto" | "aes-128-gcm" | "aes128gcm" => Some(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
}

/// cmdKey = MD5(uuid16 ‖ magic)（对照 Go `protocol/vmess/id.go`）。
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(CMD_KEY_MAGIC);
    h.finalize().into()
}

/// VMess AEAD KDF：嵌套 HMAC-SHA256。
/// `nest(paths, msg)`：最内层 HMAC 用固定盐做密钥；每加一层 path，就以上一层
/// HMAC 实例作为 hash 函数、该 path 作密钥（不是朴素迭代）。
fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
    fn nest(paths: &[&[u8]], msg: &[u8]) -> Vec<u8> {
        let Some((last, rest)) = paths.split_last() else {
            return hmac(KDF_SALT, msg);
        };
        const BLOCK: usize = 64;
        let mut k = if last.len() > BLOCK {
            nest(rest, last)
        } else {
            last.to_vec()
        };
        k.resize(BLOCK, 0);
        let mut ipad = vec![0u8; BLOCK];
        let mut opad = vec![0u8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        let mut inner_msg = ipad;
        inner_msg.extend_from_slice(msg);
        let inner = nest(rest, &inner_msg);
        let mut outer_msg = opad;
        outer_msg.extend_from_slice(&inner);
        nest(rest, &outer_msg)
    }
    let out = nest(paths, key);
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in data {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// eAuthID：时间戳‖随机‖CRC32，用 KDF(cmdKey,"AES Auth ID Encryption") 的
/// AES-128-ECB 加密。
pub fn put_e_auth_id(cmd_key: &[u8; 16]) -> [u8; 16] {
    let mut b = [0u8; 16];
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    b[..8].copy_from_slice(&ts.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut b[8..12]);
    let crc = crc32fast::hash(&b[..12]);
    b[12..].copy_from_slice(&crc.to_be_bytes());
    let key = kdf(cmd_key, &[AUTH_ID_KEY]);
    let cipher = Aes128::new_from_slice(&key[..16]).expect("aes key");
    let mut blk = aes::cipher::Block::<Aes128>::clone_from_slice(&b);
    cipher.encrypt_block(&mut blk);
    blk.into()
}

fn aes128gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], msg: &[u8]) -> io::Result<Vec<u8>> {
    let c = Aes128Gcm::new_from_slice(key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("aes key: {e}")))?;
    c.encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "vmess: aes-gcm 加密失败"))
}

fn aes128gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> io::Result<Vec<u8>> {
    let c = Aes128Gcm::new_from_slice(key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("aes key: {e}")))?;
    c.decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "vmess: aes-gcm 解密失败"))
}

/// 请求头构造的产物：body 密钥材料 + 响应认证字节 V。
#[derive(Clone)]
pub struct RequestKeys {
    pub body_iv: [u8; 16],
    pub body_key: [u8; 16],
    pub response_auth: u8,
}

/// 构造并加密请求头（返回完整 wire 字节 + 会话密钥材料）。
pub fn build_request_header(
    cmd_key: &[u8; 16],
    security: VmessSecurity,
    target: SocketAddr,
    udp: bool,
) -> io::Result<(Vec<u8>, RequestKeys)> {
    let p = (rand::random::<u8>() % 16) as usize;
    let mut instr = Vec::with_capacity(45 + p);
    instr.push(1); // version
    let mut rnd = [0u8; 33];
    rand::thread_rng().fill_bytes(&mut rnd);
    let mut body_iv = [0u8; 16];
    body_iv.copy_from_slice(&rnd[..16]);
    let mut body_key = [0u8; 16];
    body_key.copy_from_slice(&rnd[16..32]);
    let v = rnd[32];
    instr.extend_from_slice(&rnd);
    instr.push(0x0D); // ChunkStream | ChunkLengthMasking | GlobalPadding
    instr.push(((p as u8) << 4) | security.byte());
    instr.push(0);
    instr.push(if udp { 2 } else { 1 });
    instr.extend_from_slice(&target.port().to_be_bytes());
    match target {
        SocketAddr::V4(v4) => {
            instr.push(0x01);
            instr.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(_) => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "vmess 只支持 IPv4 目标",
            ))
        }
    }
    let mut pad = vec![0u8; p];
    rand::thread_rng().fill_bytes(&mut pad);
    instr.extend_from_slice(&pad);
    let sum = fnv1a32(&instr);
    instr.extend_from_slice(&sum.to_be_bytes());

    let e_auth = put_e_auth_id(cmd_key);
    let mut conn_nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut conn_nonce);

    let len_key = kdf(cmd_key, &[REQ_LEN_KEY, &e_auth, &conn_nonce]);
    let len_nonce = kdf(cmd_key, &[REQ_LEN_NONCE, &e_auth, &conn_nonce]);
    let instr_key = kdf(cmd_key, &[REQ_KEY, &e_auth, &conn_nonce]);
    let instr_nonce = kdf(cmd_key, &[REQ_NONCE, &e_auth, &conn_nonce]);

    let mut out = Vec::with_capacity(58 + instr.len());
    out.extend_from_slice(&e_auth);
    out.extend_from_slice(&aes128gcm_seal(
        &len_key[..16],
        &len_nonce[..12],
        &e_auth,
        &(instr.len() as u16).to_be_bytes(),
    )?);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&aes128gcm_seal(
        &instr_key[..16],
        &instr_nonce[..12],
        &e_auth,
        &instr,
    )?);
    Ok((
        out,
        RequestKeys {
            body_iv,
            body_key,
            response_auth: v,
        },
    ))
}

// ---------------------------------------------------------------- 数据块加解密

enum BodyCipher {
    Aes(Aes128Gcm),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl BodyCipher {
    fn new(security: VmessSecurity, key16: &[u8; 16]) -> io::Result<Self> {
        Ok(match security {
            VmessSecurity::Aes128Gcm => {
                Self::Aes(Aes128Gcm::new_from_slice(key16).map_err(|e| {
                    io::Error::new(ErrorKind::InvalidInput, format!("aes key: {e}"))
                })?)
            }
            VmessSecurity::Chacha20Poly1305 => {
                // Go：16 字节会话密钥先做 md5 链扩成 32 字节
                let t1 = Md5::digest(key16);
                let t2 = Md5::digest(t1);
                let mut k32 = [0u8; 32];
                k32[..16].copy_from_slice(&t1);
                k32[16..].copy_from_slice(&t2);
                Self::ChaCha(Box::new(ChaCha20Poly1305::new_from_slice(&k32).map_err(
                    |e| io::Error::new(ErrorKind::InvalidInput, format!("chacha key: {e}")),
                )?))
            }
        })
    }

    fn overhead(&self) -> usize {
        16
    }

    fn seal(&self, nonce: &[u8; 12], msg: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Aes(c) => c
                .encrypt(aes_gcm::Nonce::from_slice(nonce), msg)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "vmess: 加密失败")),
            Self::ChaCha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), msg)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "vmess: 加密失败")),
        }
    }

    fn open(&self, nonce: &[u8; 12], ct: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Aes(c) => c
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ct)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "vmess: 解密失败")),
            Self::ChaCha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ct)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "vmess: 解密失败")),
        }
    }
}

/// nonce = BE16(counter) ‖ dirIV[2:12]（counter 随每块 +1）。
struct ChunkNonce {
    iv: [u8; 16],
    counter: u16,
}

impl ChunkNonce {
    fn next(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.counter.to_be_bytes());
        n[2..].copy_from_slice(&self.iv[2..12]);
        self.counter = self.counter.wrapping_add(1);
        n
    }
}

/// SHAKE128 长度掩码/填充流（顺序：先抽 padding，再抽 mask）。
struct ShakeSizeParser {
    xof: sha3::Shake128Reader,
    max_padding: usize,
}

impl ShakeSizeParser {
    fn new(iv: &[u8; 16]) -> Self {
        let mut h = Shake128::default();
        sha3::digest::Update::update(&mut h, iv);
        Self {
            xof: sha3::digest::ExtendableOutput::finalize_xof(h),
            max_padding: 64,
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        sha3::digest::XofReader::read(&mut self.xof, &mut b);
        u16::from_be_bytes(b)
    }

    fn next_padding(&mut self) -> usize {
        self.next_u16() as usize % self.max_padding
    }

    fn encode_size(&mut self, size: u16) -> [u8; 2] {
        (size ^ self.next_u16()).to_be_bytes()
    }

    fn decode_size(&mut self, wire: [u8; 2]) -> u16 {
        u16::from_be_bytes(wire) ^ self.next_u16()
    }
}

/// 数据块发送器（一个方向一套：请求方向用 body 密钥，响应方向用 resp 密钥）。
struct ChunkSealer {
    cipher: BodyCipher,
    nonce: ChunkNonce,
    shake: ShakeSizeParser,
}

impl ChunkSealer {
    fn new(security: VmessSecurity, iv: &[u8; 16], key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            cipher: BodyCipher::new(security, key)?,
            nonce: ChunkNonce {
                iv: *iv,
                counter: 0,
            },
            shake: ShakeSizeParser::new(iv),
        })
    }

    /// 一个数据块（TCP 分片或一个 UDP 数据报）；空 payload 即终止块。
    fn seal(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let padding = self.shake.next_padding();
        let ct = self.cipher.seal(&self.nonce.next(), payload)?;
        let size = ct.len() + padding;
        if size > u16::MAX as usize {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "vmess: 块超过 65535",
            ));
        }
        let mut out = Vec::with_capacity(2 + size);
        out.extend_from_slice(&self.shake.encode_size(size as u16));
        out.extend_from_slice(&ct);
        let mut pad = vec![0u8; padding];
        rand::thread_rng().fill_bytes(&mut pad);
        out.extend_from_slice(&pad);
        Ok(out)
    }
}

/// 待收块的中间状态：头已解析（shake 已抽取），等 body 字节。
struct PendingChunk {
    size: usize,
    padding: usize,
    need: usize, // 2 + size：整帧长度
}

enum ChunkStep {
    Data(Vec<u8>),
    Terminator,
}

/// 数据块接收器：持有已解析的块头，缓冲不足时状态可跨调用保留。
struct ChunkReceiver {
    cipher: BodyCipher,
    nonce: ChunkNonce,
    shake: ShakeSizeParser,
    head: Option<PendingChunk>,
}

impl ChunkReceiver {
    fn new(security: VmessSecurity, iv: &[u8; 16], key: &[u8; 16]) -> io::Result<Self> {
        Ok(Self {
            cipher: BodyCipher::new(security, key)?,
            nonce: ChunkNonce {
                iv: *iv,
                counter: 0,
            },
            shake: ShakeSizeParser::new(iv),
            head: None,
        })
    }

    fn overhead(&self) -> usize {
        self.cipher.overhead()
    }

    /// 若缓冲里有完整块则解析并返回，否则 Ok(None)（状态可安全跨调用保留）。
    fn try_take(&mut self, buf: &[u8], pos: &mut usize) -> io::Result<Option<ChunkStep>> {
        if self.head.is_none() {
            if buf.len() - *pos < 2 {
                return Ok(None);
            }
            let padding = self.shake.next_padding();
            let size = self.shake.decode_size([buf[*pos], buf[*pos + 1]]) as usize;
            if size < padding {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("vmess: 块大小 {size} 小于填充 {padding}"),
                ));
            }
            if size == self.overhead() + padding {
                // 终止块：连同其 tag+padding 一起消费，保持流位置精确
                *pos += 2 + size;
                return Ok(Some(ChunkStep::Terminator));
            }
            self.head = Some(PendingChunk {
                size,
                padding,
                need: 2 + size,
            });
        }
        let h = self.head.as_ref().expect("head");
        let (size, padding, need) = (h.size, h.padding, h.need);
        if buf.len() - *pos < need {
            return Ok(None);
        }
        let ct = &buf[*pos + 2..*pos + 2 + size - padding];
        let plain = self.cipher.open(&self.nonce.next(), ct)?;
        *pos += need;
        self.head = None;
        Ok(Some(ChunkStep::Data(plain)))
    }
}

// ---------------------------------------------------------------- 响应头

fn read_response_header_into(buf: &[u8], pos: &mut usize, req: &RequestKeys) -> io::Result<bool> {
    let resp_key_full = Sha256::digest(req.body_key);
    let resp_iv_full = Sha256::digest(req.body_iv);
    let resp_key = &resp_key_full[..16];
    let resp_iv = &resp_iv_full[..16];

    if buf.len() - *pos < 18 {
        return Ok(false);
    }
    let len_key = kdf(resp_key, &[RESP_LEN_KEY]);
    let len_iv = kdf(resp_iv, &[RESP_LEN_IV]);
    let len_plain = aes128gcm_open(&len_key[..16], &len_iv[..12], &[], &buf[*pos..*pos + 18])?;
    if len_plain.len() != 2 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "vmess: 响应长度块非法",
        ));
    }
    let l = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    if l == 0 || l > 1024 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("vmess: 响应头长度 {l} 不合理"),
        ));
    }
    if buf.len() - *pos < 18 + l + 16 {
        return Ok(false);
    }
    let key = kdf(resp_key, &[RESP_KEY]);
    let iv = kdf(resp_iv, &[RESP_IV]);
    let payload = aes128gcm_open(
        &key[..16],
        &iv[..12],
        &[],
        &buf[*pos + 18..*pos + 18 + l + 16],
    )?;
    if payload.len() != l || payload[0] != req.response_auth {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "vmess: 响应认证不匹配",
        ));
    }
    if payload.get(2).copied().unwrap_or(1) != 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "vmess: 响应命令非 0",
        ));
    }
    *pos += 18 + l + 16;
    Ok(true)
}

// ---------------------------------------------------------------- TCP 读写

pub struct VmessReader<R> {
    inner: R,
    req: RequestKeys,
    security: VmessSecurity,
    state: Option<ChunkReceiver>,
    buf: Vec<u8>,
    pos: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    eof: bool,
}

impl<R: Read> VmessReader<R> {
    fn fill(&mut self) -> io::Result<usize> {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        let mut tmp = [0u8; 16384];
        let n = self.inner.read(&mut tmp)?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    fn ensure_state(&mut self) -> io::Result<()> {
        if self.state.is_some() {
            return Ok(());
        }
        loop {
            if read_response_header_into(&self.buf, &mut self.pos, &self.req)? {
                let resp_key = Sha256::digest(self.req.body_key);
                let resp_iv = Sha256::digest(self.req.body_iv);
                let mut key16 = [0u8; 16];
                key16.copy_from_slice(&resp_key[..16]);
                let mut iv16 = [0u8; 16];
                iv16.copy_from_slice(&resp_iv[..16]);
                self.state = Some(ChunkReceiver::new(self.security, &iv16, &key16)?);
                return Ok(());
            }
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "vmess: 响应头前 EOF",
                ));
            }
        }
    }

    fn take_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.ensure_state()?;
        loop {
            let st = self.state.as_mut().expect("state");
            let mut pos = self.pos;
            match st.try_take(&self.buf, &mut pos)? {
                Some(ChunkStep::Data(d)) => {
                    self.pos = pos;
                    return Ok(Some(d));
                }
                Some(ChunkStep::Terminator) => {
                    self.pos = pos;
                    self.eof = true;
                    return Ok(None);
                }
                None => {
                    if self.fill()? == 0 {
                        return Err(io::Error::new(ErrorKind::UnexpectedEof, "vmess: 流结束"));
                    }
                }
            }
        }
    }
}

impl<R: Read> Read for VmessReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.plain_pos >= self.plain.len() {
            if self.eof {
                return Ok(0);
            }
            match self.take_chunk()? {
                Some(d) => {
                    self.plain = d;
                    self.plain_pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.plain.len() - self.plain_pos);
        out[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
        self.plain_pos += n;
        Ok(n)
    }
}

pub struct VmessWriter<W> {
    inner: Mutex<W>,
    sealer: Mutex<ChunkSealer>,
}

impl<W: Write> VmessWriter<W> {
    /// 终止块（空 payload）：协议层的半关闭信号。
    pub fn send_terminator(&self) -> io::Result<()> {
        let frame = {
            let mut s = self
                .sealer
                .lock()
                .map_err(|_| io::Error::other("vmess: 锁中毒"))?;
            s.seal(&[])?
        };
        self.inner
            .lock()
            .map_err(|_| io::Error::other("vmess: 锁中毒"))?
            .write_all(&frame)
    }

    /// 暴露底层写半（outbound 的 `WriteHalf::shutdown_write` 需要）。
    pub fn inner(&self) -> &Mutex<W> {
        &self.inner
    }
}

impl<W: Write> Write for VmessWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(MAX_PAYLOAD_PER_CHUNK);
        let frame = {
            let mut s = self
                .sealer
                .lock()
                .map_err(|_| io::Error::other("vmess: 锁中毒"))?;
            s.seal(&buf[..n])?
        };
        self.inner
            .lock()
            .map_err(|_| io::Error::other("vmess: 锁中毒"))?
            .write_all(&frame)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("vmess: 锁中毒"))?
            .flush()
    }
}

/// 写请求头并拆出 TCP 两半。
pub fn connect_split<R, W>(
    read: R,
    mut write: W,
    cmd_key: &[u8; 16],
    security: VmessSecurity,
    target: SocketAddr,
) -> io::Result<(VmessReader<R>, VmessWriter<W>)>
where
    R: Read,
    W: Write,
{
    let (head, req) = build_request_header(cmd_key, security, target, false)?;
    write.write_all(&head)?;
    write.flush()?;
    let sealer = ChunkSealer::new(security, &req.body_iv, &req.body_key)?;
    Ok((
        VmessReader {
            inner: read,
            req,
            security,
            state: None,
            buf: Vec::new(),
            pos: 0,
            plain: Vec::new(),
            plain_pos: 0,
            eof: false,
        },
        VmessWriter {
            inner: Mutex::new(write),
            sealer: Mutex::new(sealer),
        },
    ))
}

// ---------------------------------------------------------------- UDP over stream

pub struct VmessUdpReader<R> {
    inner: R,
    req: RequestKeys,
    security: VmessSecurity,
    state: Option<ChunkReceiver>,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: Read> VmessUdpReader<R> {
    fn fill(&mut self) -> io::Result<usize> {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        let mut tmp = [0u8; 16384];
        let n = self.inner.read(&mut tmp)?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    /// 收一个数据报；空闲时返回 WouldBlock/TimedOut（保留半帧进度）。
    pub fn recv_datagram(&mut self) -> io::Result<Vec<u8>> {
        if self.state.is_none() {
            loop {
                if read_response_header_into(&self.buf, &mut self.pos, &self.req)? {
                    let resp_key = Sha256::digest(self.req.body_key);
                    let resp_iv = Sha256::digest(self.req.body_iv);
                    let mut key16 = [0u8; 16];
                    key16.copy_from_slice(&resp_key[..16]);
                    let mut iv16 = [0u8; 16];
                    iv16.copy_from_slice(&resp_iv[..16]);
                    self.state = Some(ChunkReceiver::new(self.security, &iv16, &key16)?);
                    break;
                }
                if self.fill()? == 0 {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "vmess: 响应头前 EOF",
                    ));
                }
            }
        }
        loop {
            let st = self.state.as_mut().expect("state");
            let mut pos = self.pos;
            match st.try_take(&self.buf, &mut pos)? {
                Some(ChunkStep::Data(d)) => {
                    self.pos = pos;
                    return Ok(d);
                }
                Some(ChunkStep::Terminator) => {
                    self.pos = pos;
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "vmess: udp 流终止块",
                    ));
                }
                None => {
                    if self.fill()? == 0 {
                        return Err(io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "vmess: udp 流结束",
                        ));
                    }
                }
            }
        }
    }
}

pub struct VmessUdpWriter<W> {
    inner: W,
    sealer: ChunkSealer,
}

impl<W: Write> VmessUdpWriter<W> {
    /// 一个 UDP 数据报一个块（不切分）。
    pub fn send_datagram(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = self.sealer.seal(payload)?;
        self.inner.write_all(&frame)?;
        self.inner.flush()
    }
}

/// 写请求头并拆出 UDP 两半（固定目标模式）。
pub fn connect_split_udp<R, W>(
    read: R,
    mut write: W,
    cmd_key: &[u8; 16],
    security: VmessSecurity,
    target: SocketAddr,
) -> io::Result<(VmessUdpReader<R>, VmessUdpWriter<W>)>
where
    R: Read,
    W: Write,
{
    let (head, req) = build_request_header(cmd_key, security, target, true)?;
    write.write_all(&head)?;
    write.flush()?;
    let sealer = ChunkSealer::new(security, &req.body_iv, &req.body_key)?;
    Ok((
        VmessUdpReader {
            inner: read,
            req,
            security,
            state: None,
            buf: Vec::new(),
            pos: 0,
        },
        VmessUdpWriter {
            inner: write,
            sealer,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn cmd_key_matches_md5() {
        let uuid = *b"0123456789abcdef";
        let k = cmd_key(&uuid);
        let mut h = Md5::new();
        h.update(uuid);
        h.update(CMD_KEY_MAGIC);
        assert_eq!(k, <[u8; 16]>::from(h.finalize()));
    }

    #[test]
    fn kdf_reference_vector() {
        // 参考向量由独立 Python 实现生成（嵌套 HMAC-SHA256，与 Go 语义一致）
        let key = b"0123456789abcdef";
        let hex = |v: [u8; 32]| -> String { v.iter().map(|b| format!("{b:02x}")).collect() };
        assert_eq!(
            hex(kdf(key, &[b"VMess Header AEAD Key"])),
            "17b65723e96be5b365fdbeae4de71ff805d4d14ef9434c20969998d41daaf52b"
        );
        assert_eq!(
            hex(kdf(
                key,
                &[
                    b"VMess Header AEAD Key_Length",
                    &[0u8, 1, 2, 3, 4, 5, 6, 7],
                    &[0u8; 16]
                ]
            )),
            "e617e529cfd213a43827f2a5c1a99d18d87d59e973b90becde2084dde4eeb7f1"
        );
    }

    #[test]
    fn auth_id_decrypts_and_checks_crc() {
        use aes::cipher::BlockDecrypt as _;
        let k = [9u8; 16];
        let e = put_e_auth_id(&k);
        let key = kdf(&k, &[AUTH_ID_KEY]);
        let cipher = Aes128::new_from_slice(&key[..16]).unwrap();
        let mut blk = aes::cipher::Block::<Aes128>::clone_from_slice(&e);
        cipher.decrypt_block(&mut blk);
        let plain: [u8; 16] = blk.into();
        assert_eq!(
            crc32fast::hash(&plain[..12]),
            u32::from_be_bytes([plain[12], plain[13], plain[14], plain[15]])
        );
    }

    #[test]
    fn chunk_roundtrip_and_terminator() {
        let iv = [3u8; 16];
        let key = [4u8; 16];
        for sec in [VmessSecurity::Aes128Gcm, VmessSecurity::Chacha20Poly1305] {
            let mut sealer = ChunkSealer::new(sec, &iv, &key).unwrap();
            let mut recv = ChunkReceiver::new(sec, &iv, &key).unwrap();
            let mut wire = Vec::new();
            wire.extend_from_slice(&sealer.seal(b"hello").unwrap());
            wire.extend_from_slice(&sealer.seal(b"world!").unwrap());
            wire.extend_from_slice(&sealer.seal(b"").unwrap()); // terminator
            let mut pos = 0usize;
            let mut got = Vec::new();
            loop {
                match recv.try_take(&wire, &mut pos).unwrap() {
                    Some(ChunkStep::Data(d)) => got.push(d),
                    Some(ChunkStep::Terminator) => break,
                    None => panic!("不应缺数据"),
                }
            }
            assert_eq!(got, vec![b"hello".to_vec(), b"world!".to_vec()]);
            assert_eq!(pos, wire.len());
        }
    }

    #[test]
    fn chunk_parse_survives_byte_by_byte() {
        let iv = [5u8; 16];
        let key = [6u8; 16];
        let mut sealer = ChunkSealer::new(VmessSecurity::Aes128Gcm, &iv, &key).unwrap();
        let wire = sealer.seal(b"payload").unwrap();
        // 模拟分片到达：每喂 1 字节就尝试解析一次
        let mut recv = ChunkReceiver::new(VmessSecurity::Aes128Gcm, &iv, &key).unwrap();
        let mut buf = Vec::new();
        let mut pos = 0usize;
        let mut done = None;
        for b in wire {
            buf.push(b);
            if let Some(step) = recv.try_take(&buf, &mut pos).unwrap() {
                match step {
                    ChunkStep::Data(d) => done = Some(d),
                    ChunkStep::Terminator => unreachable!(),
                }
                break;
            }
        }
        assert_eq!(done, Some(b"payload".to_vec()));
    }

    #[test]
    fn request_header_is_parseable_by_server_side_logic() {
        // 模拟服务端解析：解长度块 → 解指令 → 校验 FNV/目标/选项
        let cmd_key = cmd_key(b"0011223344556677");
        let target: SocketAddr = "1.1.1.1:8080".parse().unwrap();
        let (wire, req) =
            build_request_header(&cmd_key, VmessSecurity::Aes128Gcm, target, false).unwrap();
        let e_auth = &wire[..16];
        let conn_nonce = &wire[34..42];
        let len_key = kdf(&cmd_key, &[REQ_LEN_KEY, e_auth, conn_nonce]);
        let len_nonce = kdf(&cmd_key, &[REQ_LEN_NONCE, e_auth, conn_nonce]);
        let l = aes128gcm_open(&len_key[..16], &len_nonce[..12], e_auth, &wire[16..34]).unwrap();
        let l = u16::from_be_bytes([l[0], l[1]]) as usize;
        assert_eq!(wire.len(), 42 + l + 16);
        let key = kdf(&cmd_key, &[REQ_KEY, e_auth, conn_nonce]);
        let nonce = kdf(&cmd_key, &[REQ_NONCE, e_auth, conn_nonce]);
        let instr = aes128gcm_open(&key[..16], &nonce[..12], e_auth, &wire[42..]).unwrap();
        assert_eq!(instr.len(), l);
        assert_eq!(instr[0], 1);
        assert_eq!(instr[34], 0x0D);
        assert_eq!(instr[35] & 0x0f, 3);
        assert_eq!(instr[37], 1);
        assert_eq!(u16::from_be_bytes([instr[38], instr[39]]), 8080);
        assert_eq!(instr[40], 1);
        assert_eq!(&instr[41..45], &[1, 1, 1, 1]);
        let (body, sum) = instr.split_at(instr.len() - 4);
        assert_eq!(
            fnv1a32(body),
            u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]])
        );
        assert_eq!(req.response_auth, instr[33]);
    }

    #[test]
    fn udp_datagram_roundtrip_through_writer_and_reader() {
        // 用内存管道模拟：writer 的字节 → 当成“服务端回包”用同密钥的 receiver 读回
        let cmd_key = [1u8; 16];
        let target: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let (head, req) =
            build_request_header(&cmd_key, VmessSecurity::Aes128Gcm, target, true).unwrap();
        assert!(!head.is_empty());
        // 反向（server→client）密钥 = SHA256(请求密钥)
        let rk = Sha256::digest(req.body_key);
        let ri = Sha256::digest(req.body_iv);
        let mut key16 = [0u8; 16];
        key16.copy_from_slice(&rk[..16]);
        let mut iv16 = [0u8; 16];
        iv16.copy_from_slice(&ri[..16]);
        let mut sealer = ChunkSealer::new(VmessSecurity::Aes128Gcm, &iv16, &key16).unwrap();
        // 响应头
        let mut wire = Vec::new();
        let len_key = kdf(&key16, &[RESP_LEN_KEY]);
        let len_iv = kdf(&iv16, &[RESP_LEN_IV]);
        wire.extend_from_slice(
            &aes128gcm_seal(&len_key[..16], &len_iv[..12], &[], &4u16.to_be_bytes()).unwrap(),
        );
        let pk = kdf(&key16, &[RESP_KEY]);
        let pi = kdf(&iv16, &[RESP_IV]);
        let payload = vec![req.response_auth, 0, 0, 0];
        wire.extend_from_slice(&aes128gcm_seal(&pk[..16], &pi[..12], &[], &payload).unwrap());
        wire.extend_from_slice(&sealer.seal(b"pong").unwrap());
        let (mut r, _w) = (
            VmessUdpReader {
                inner: Cursor::new(wire),
                req,
                security: VmessSecurity::Aes128Gcm,
                state: None,
                buf: Vec::new(),
                pos: 0,
            },
            (),
        );
        assert_eq!(r.recv_datagram().unwrap(), b"pong".to_vec());
    }
}

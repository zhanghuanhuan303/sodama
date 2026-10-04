// SPDX-License-Identifier: GPL-2.0
//! P18c+：REALITY 客户端（在自实现 TLS 1.3 之上，与 xtls/reality 服务端对齐）。
//!
//! 协议要点（对照 XTLS/REALITY 与 dae `transport/tls/reality.go`）：
//! - ClientHello 的 key_share 内含 X25519MLKEM768 混合 share（当前服务端强制要求）；
//! - 客户端用自己的 X25519 临时私钥与服务端**静态**公钥做 ECDH，再
//!   HKDF-SHA256(salt=random[:20], info="REALITY") 得 authKey；
//! - 32B session_id 明文 = [1,8,10,0][unix 秒 u32 BE][shortId 8B][全 0 8B]，
//!   用 AES-256-GCM(authKey) 密封（nonce=random[20:32]，AD=session_id 置零的 ClientHello）
//!   后放回 ClientHello 偏移 39；
//! - 服务端证书的 Ed25519 签名域被替换为 HMAC-SHA512(authKey, 证书公钥)：
//!   客户端校验通过 ⇒ 证明对端持有静态私钥；否则连接必然是被转发到真站的“未认证”
//!   会话，必须中断（dae 同款行为）。

use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use x25519_dalek::PublicKey as X25519Public;

use crate::tls13;

/// REALITY 客户端参数（来自订阅 URL 的 `pbk/sid/sni/fp/spx`）。
#[derive(Clone, Debug)]
pub struct RealityConfig {
    pub server_name: String,
    /// 服务端静态 X25519 公钥（`pbk`，base64url 无填充，32B）。
    pub public_key: [u8; 32],
    /// `sid`（hex，≤8B，右补零）。
    pub short_id: [u8; 8],
    /// `fp`（目前仅 chrome；影响 ClientHello 形状）。
    pub fingerprint: String,
    /// ALPN（Chrome 风格默认 h2/http1.1）。
    pub alpn: Vec<Vec<u8>>,
}

impl RealityConfig {
    pub fn new(
        server_name: &str,
        public_key: [u8; 32],
        short_id: [u8; 8],
        fingerprint: &str,
    ) -> Self {
        RealityConfig {
            server_name: server_name.to_string(),
            public_key,
            short_id,
            fingerprint: if fingerprint.is_empty() {
                "chrome".to_string()
            } else {
                fingerprint.to_string()
            },
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }

    /// 解析 `sid`（hex，可 0..=16 个 hex 字符；右补零）。
    pub fn parse_short_id(s: &str) -> io::Result<[u8; 8]> {
        let mut out = [0u8; 8];
        let bytes = s.as_bytes();
        let mut hex = String::with_capacity(bytes.len());
        for &b in bytes {
            if !(b as char).is_ascii_hexdigit() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("reality: sid 含非 hex 字符: {s}"),
                ));
            }
            hex.push(b as char);
        }
        if hex.len() % 2 != 0 {
            // dae 直接 hex.Decode：奇数长度会报错——保持一致。
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("reality: sid 长度必须为偶数个 hex 字符: {s}"),
            ));
        }
        let n = (hex.len() / 2).min(8);
        for i in 0..n {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("reality: sid 解析失败: {e}"),
                )
            })?;
        }
        Ok(out)
    }

    /// 解析 `pbk`（base64url 无填充，32B）。
    pub fn parse_public_key(s: &str) -> io::Result<[u8; 32]> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim_end_matches('='))
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("reality: pbk 解析失败: {e}"),
                )
            })?;
        if raw.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("reality: pbk 长度 {} != 32", raw.len()),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// 与服务端 REALITY 握手（含 TLS 1.3），返回记录层读写半与裸读开关。
pub fn connect(
    sock: TcpStream,
    cfg: &RealityConfig,
    timeout: Option<Duration>,
) -> io::Result<(
    tls13::Tls13Reader,
    tls13::Tls13Writer,
    Arc<std::sync::atomic::AtomicBool>,
)> {
    if cfg.fingerprint != "chrome" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "reality: fingerprint={} 未实现（只做 chrome 形状）",
                cfg.fingerprint
            ),
        ));
    }

    // 1) 客户端临时密钥：X25519（AuthKey 与 TLS ECDHE 共用）+ ML-KEM-768。
    let kx = tls13::ClientKx::generate(true);
    let mut random = [0u8; 32];
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut random);
    }

    // 2) 构造 ClientHello（session_id 先留零，密封后回填）。
    let spec = tls13::ClientHelloSpec {
        server_name: cfg.server_name.clone(),
        alpn: cfg.alpn.clone(),
        session_id: [0u8; 32],
        random,
        hybrid: true,
    };
    let mut hello = tls13::build_client_hello(&spec, &kx);

    // 3) authKey = HKDF-SHA256(ikm = X25519(client_priv, server_static_pub),
    //    salt = random[:20], info = "REALITY")。
    let server_pub = X25519Public::from(cfg.public_key);
    let ecdh = kx.x25519.diffie_hellman(&server_pub);
    if ecdh.as_bytes().iter().all(|b| *b == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reality: 与服务端静态公钥的 ECDH 结果为全零",
        ));
    }
    let auth_key = {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(&random[..20]), ecdh.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"REALITY", &mut okm)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "reality: HKDF 失败"))?;
        okm
    };

    // 4) 密封 session_id：明文 = [1,8,10,0][unix][sid 8][0*8]。
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut sid_plain = [0u8; 32];
    sid_plain[0] = 1; // Version_x
    sid_plain[1] = 8; // Version_y
    sid_plain[2] = 10; // Version_z
    sid_plain[3] = 0; // reserved
    sid_plain[4..8].copy_from_slice(&now.to_be_bytes());
    sid_plain[8..16].copy_from_slice(&cfg.short_id);
    let mut sealed = sid_plain[..16].to_vec();
    {
        let cipher = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "reality: AES-GCM 初始化失败"))?;
        let nonce = aes_gcm::Nonce::from_slice(&random[20..32]);
        // AD = session_id 置零的完整 ClientHello（当前 hello 字节）；
        // 明文仅前 16B（[ver][unix][sid]，后 16B 本就是 GCM tag 位置）。
        cipher
            .encrypt_in_place(nonce, &hello, &mut sealed)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "reality: session_id 密封失败"))?;
    }
    if sealed.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "reality: session_id 密封长度异常",
        ));
    }
    hello[39..71].copy_from_slice(&sealed);

    // 5) TLS 握手 + 证书校验（HMAC-SHA512(authKey, ed25519 公钥) == 证书签名域）。
    let mut cert_hook = |leaf: &[u8]| -> io::Result<Option<Vec<u8>>> {
        let (pubkey, signature) = parse_ed25519_cert(leaf)?;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "reality: HMAC 初始化失败"))?;
        mac.update(&pubkey);
        let expect = mac.finalize().into_bytes();
        if signature.len() != expect.len() || !ct_eq(&signature, &expect) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY 验证失败：服务端未通过 authKey 绑定（可能被转发到真站）",
            ));
        }
        // 返回公钥：TLS 层继续用它验 CertificateVerify（证明握手未被篡改）。
        Ok(Some(pubkey.to_vec()))
    };
    let out = tls13::connect(sock, &hello, &kx, &mut cert_hook, timeout)?;
    Ok(out)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for i in 0..a.len() {
        v |= a[i] ^ b[i];
    }
    v == 0
}

// ---------------------------------------------------------------- DER 解析

/// 极简 DER：读一个 TLV，返回（tag, contents, 新位置）。
fn der_tlv(b: &[u8], pos: &mut usize) -> io::Result<(u8, Vec<u8>)> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("reality: 证书 {m}"));
    if *pos + 2 > b.len() {
        return Err(bad("TLV 越界"));
    }
    let tag = b[*pos];
    let mut len = b[*pos + 1] as usize;
    let mut hdr = 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || *pos + 2 + n > b.len() {
            return Err(bad("长度域非法"));
        }
        len = 0;
        for i in 0..n {
            len = (len << 8) | b[*pos + 2 + i] as usize;
        }
        hdr = 2 + n;
    }
    if *pos + hdr + len > b.len() {
        return Err(bad("内容越界"));
    }
    let contents = b[*pos + hdr..*pos + hdr + len].to_vec();
    *pos += hdr + len;
    Ok((tag, contents))
}

/// 从 X.509 叶证书里取出（ed25519 SPKI 公钥, 64B 签名域）。
fn parse_ed25519_cert(der: &[u8]) -> io::Result<([u8; 32], Vec<u8>)> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("reality: 证书 {m}"));
    let mut pos = 0usize;
    let (tag, cert) = der_tlv(der, &mut pos)?;
    if tag != 0x30 {
        return Err(bad("外层非 SEQUENCE"));
    }
    // tbsCertificate
    let mut p = 0usize;
    let (tag, tbs) = der_tlv(&cert, &mut p)?;
    if tag != 0x30 {
        return Err(bad("tbsCertificate 非 SEQUENCE"));
    }
    // signatureAlgorithm + signatureValue
    let (_t, _alg) = der_tlv(&cert, &mut p)?;
    let (tag, sig) = der_tlv(&cert, &mut p)?;
    if tag != 0x03 || sig.first() != Some(&0) {
        return Err(bad("签名域非 BIT STRING"));
    }
    let signature = sig[1..].to_vec();
    // tbs：version([0] 可选) / serial / sigalg / issuer / validity / subject / SPKI
    let mut q = 0usize;
    let (tag0, _v) = der_tlv(&tbs, &mut q)?;
    if tag0 == 0xa0 {
        let (_t, _v) = der_tlv(&tbs, &mut q)?; // serialNumber
    } else {
        // tag0 就是 serialNumber；继续按序
    }
    // 此时剩余顺序固定：sigalg, issuer, validity, subject, SPKI
    for _ in 0..4 {
        let (_t, _v) = der_tlv(&tbs, &mut q)?;
    }
    let (tag_spki, spki) = der_tlv(&tbs, &mut q)?;
    if tag_spki != 0x30 {
        return Err(bad("SPKI 非 SEQUENCE"));
    }
    let mut r = 0usize;
    let (t_alg, alg) = der_tlv(&spki, &mut r)?;
    if t_alg != 0x30 {
        return Err(bad("SPKI 算法域非 SEQUENCE"));
    }
    // ed25519 OID: 06 03 2B 65 70
    if alg.len() < 5 || alg[0] != 0x06 || alg[1] != 0x03 || &alg[2..5] != &[0x2b, 0x65, 0x70] {
        return Err(bad("公钥非 Ed25519"));
    }
    let (t_bits, bits) = der_tlv(&spki, &mut r)?;
    if t_bits != 0x03 || bits.first() != Some(&0) || bits.len() != 33 {
        return Err(bad("公钥 BIT STRING 形态异常"));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&bits[1..]);
    if signature.len() != 64 {
        return Err(bad("签名域长度非 64（可能是 ML-DSA 变体，暂不支持）"));
    }
    Ok((pubkey, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_and_pbk_parse() {
        let sid = RealityConfig::parse_short_id("41b9cb10b696").unwrap();
        assert_eq!(&sid[..6], &[0x41, 0xb9, 0xcb, 0x10, 0xb6, 0x96]);
        assert_eq!(&sid[6..], &[0, 0]);
        assert!(RealityConfig::parse_short_id("xyz").is_err());
        assert!(RealityConfig::parse_short_id("abc").is_err());
        let pk =
            RealityConfig::parse_public_key("AavBPGGJUpyGWiriV_Fbx-SrAvR5t-9mHeQY8uIltyo").unwrap();
        assert_eq!(pk.len(), 32);
        assert!(RealityConfig::parse_public_key("short").is_err());
    }

    fn spawn_echo() -> std::net::SocketAddr {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let addr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in echo.incoming() {
                let Ok(mut c) = c else { break };
                std::thread::spawn(move || {
                    let mut b = [0u8; 16384];
                    loop {
                        match c.read(&mut b) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if c.write_all(&b[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    fn roundtrip(ob: &crate::outbound::Outbound, echo_addr: std::net::SocketAddr) {
        use std::io::{Read as _, Write as _};
        use std::time::Duration;
        let target = crate::target::Target::from_socket_addr(echo_addr).unwrap();
        let mut ds = ob
            .dial_tcp(&target, Duration::from_secs(10))
            .expect("reality+vision 拨号");
        ds.to_remote.write_all(b"hello-reality").unwrap();
        ds.to_remote.flush().unwrap();
        let mut buf = [0u8; 64];
        let n = ds.from_remote.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-reality");
        let blob: Vec<u8> = (0..131072u32).map(|i| (i % 251) as u8).collect();
        ds.to_remote.write_all(&blob).unwrap();
        ds.to_remote.flush().unwrap();
        let mut got = Vec::with_capacity(blob.len());
        while got.len() < blob.len() {
            let mut tmp = [0u8; 16384];
            let n = ds.from_remote.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(got.len(), blob.len());
        assert_eq!(got, blob);
    }

    /// 真机节点 HTTP 检查：经 reality+vision 拨号到 `host:port`，发 HTTP/1.0 GET。
    /// 用于把订阅里的真实节点喂给本实现（不接管系统网络）。
    fn http_check(ob: &crate::outbound::Outbound, target: &str) {
        use std::io::{Read as _, Write as _};
        use std::time::Duration;
        let (host, port) = target.rsplit_once(':').expect("target 应为 host:port");
        let port: u16 = port.parse().expect("端口");
        let t = crate::target::Target::domain(host, port);
        let mut ds = ob
            .dial_tcp(&t, Duration::from_secs(15))
            .expect("reality 拨号");
        let req = format!("GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: sodama-test\r\n\r\n");
        ds.to_remote.write_all(req.as_bytes()).unwrap();
        ds.to_remote.flush().unwrap();
        let mut got = Vec::new();
        let mut tmp = [0u8; 4096];
        while got.len() < 8 {
            let n = ds.from_remote.read(&mut tmp).expect("读 HTTP 响应");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&tmp[..n]);
        }
        assert!(
            got.starts_with(b"HTTP/"),
            "预期 HTTP 响应，实得: {:?}",
            String::from_utf8_lossy(&got[..got.len().min(80)])
        );
    }

    /// HTTPS 直通检查（Vision splice 下行）：经 reality+vision 对 `host:443` 发 HTTPS 请求。
    /// 内层 TLS 1.3 会触发服务端下行 splice（paddingDirect → 裸 TCP 直通）。
    fn https_splice_check(ob: &crate::outbound::Outbound, host: &str) {
        use std::io::{Read, Write};
        use std::time::Duration;

        struct Combined {
            r: Box<dyn crate::outbound::ReadHalf>,
            w: Box<dyn crate::outbound::WriteHalf>,
        }
        impl Read for Combined {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.r.read(buf)
            }
        }
        impl Write for Combined {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.w.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.w.flush()
            }
        }

        let t = crate::target::Target::domain(host, 443);
        let mut ds = ob
            .dial_tcp(&t, Duration::from_secs(15))
            .expect("reality 拨号");
        ds.to_remote.write_all(b"").unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name).unwrap();
        let combined = Combined {
            r: ds.from_remote,
            w: ds.to_remote,
        };
        let mut tls = rustls::StreamOwned::new(conn, combined);
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sodama-test\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).unwrap();
        tls.flush().unwrap();
        let mut got = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match tls.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    got.extend_from_slice(&tmp[..n]);
                    if got.len() > 16 || got.starts_with(b"HTTP/") {
                        break;
                    }
                }
                Err(e) => panic!("HTTPS 读取: {e}"),
            }
        }
        assert!(
            got.starts_with(b"HTTP/"),
            "预期 HTTPS 响应，实得: {:?}",
            String::from_utf8_lossy(&got[..got.len().min(80)])
        );
    }

    /// 端到端：sing-box（REALITY+Vision 参考服务端）→ 本实现的 REALITY 客户端。
    /// 需要本机安装 sing-box；用 `cargo test --release -- --ignored reality` 运行。
    /// `SODAMA_DAE_E2E_URL` 可指向既有服务端（跳过 spawn，仅跑客户端）。
    #[test]
    #[ignore = "需要本机 sing-box（REALITY+Vision 参考服务端）"]
    fn e2e_reality_vision_with_sing_box() {
        use std::net::{TcpListener, TcpStream};
        use std::process::{Command, Stdio};
        use std::time::Duration;

        let echo_addr = spawn_echo();

        // 调试旁路：SODAMA_DAE_E2E_URL 指向既有服务端/真实节点（跳过 spawn，仅跑客户端）；
        // 若同时给 SODAMA_DAE_E2E_TARGET=host:port，则做 HTTP 检查。
        if let Ok(url) = std::env::var("SODAMA_DAE_E2E_URL") {
            let ob = crate::outbound::parse(&url).expect("解析 reality URL");
            let mut did = false;
            if let Ok(target) = std::env::var("SODAMA_DAE_E2E_TARGET") {
                http_check(&ob, &target);
                did = true;
            }
            if let Ok(host) = std::env::var("SODAMA_DAE_E2E_HTTPS") {
                https_splice_check(&ob, &host);
                did = true;
            }
            if !did {
                roundtrip(&ob, echo_addr);
            }
            return;
        }

        // 0) 依赖检查 + 生成服务端密钥/UUID
        let gen_key = Command::new("sing-box")
            .args(["generate", "reality-keypair"])
            .output();
        let Ok(gen_key) = gen_key else {
            eprintln!("skip: sing-box 不可用");
            return;
        };
        let key_text = String::from_utf8_lossy(&gen_key.stdout);
        let priv_key = key_text
            .lines()
            .find_map(|l| l.strip_prefix("PrivateKey: "))
            .expect("sing-box 未输出 PrivateKey")
            .trim()
            .to_string();
        let pub_key = key_text
            .lines()
            .find_map(|l| l.strip_prefix("PublicKey: "))
            .expect("sing-box 未输出 PublicKey")
            .trim()
            .to_string();
        let uuid = String::from_utf8_lossy(
            &Command::new("sing-box")
                .args(["generate", "uuid"])
                .output()
                .expect("generate uuid")
                .stdout,
        )
        .trim()
        .to_string();

        // 1) 空闲端口 + sing-box 配置 + 启动
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let cfg_path = "/tmp/sodama-sb-reality-test.json";
        let cfg = format!(
            r#"{{
  "log": {{"level": "warn", "output": "/tmp/sodama-sb-reality-test.log"}},
  "inbounds": [{{
    "type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": {port},
    "users": [{{"uuid": "{uuid}", "flow": "xtls-rprx-vision"}}],
    "tls": {{
      "enabled": true,
      "server_name": "www.microsoft.com",
      "reality": {{
        "enabled": true,
        "handshake": {{"server": "www.microsoft.com", "server_port": 443}},
        "private_key": "{priv_key}",
        "short_id": ["41b9cb10b696"]
      }}
    }}
  }}],
  "outbounds": [{{"type": "direct"}}]
}}
"#
        );
        std::fs::write(cfg_path, cfg).unwrap();
        let mut child = Command::new("sing-box")
            .args(["run", "-c", cfg_path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("启动 sing-box");
        let mut up = false;
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                up = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !up {
            let _ = child.kill();
            panic!("sing-box 未监听 127.0.0.1:{port}");
        }

        // 2) 客户端：REALITY + Vision 拨号到 echo + 大小数据往返
        let url = format!(
            "vless://{uuid}@127.0.0.1:{port}?type=tcp&security=reality&sni=www.microsoft.com\
             &pbk={pub_key}&sid=41b9cb10b696&fp=chrome&flow=xtls-rprx-vision"
        );
        let ob = crate::outbound::parse(&url).expect("解析 reality URL");
        roundtrip(&ob, echo_addr);

        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(cfg_path);
    }
}

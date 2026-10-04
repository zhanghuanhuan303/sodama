# ADR-0041：REALITY + Vision（自实现 TLS 1.3 + ML-KEM 混合 + splice 直通）

- **状态**：已采纳（2026-10-04）
- **对应**：缺口 #6 第一段「REALITY/Vision/uTLS」；解锁订阅#2 的 48 条 REALITY 节点
- **相关**：ADR-0016/0017（vless）、ADR-0031（订阅/节点组）、
  ADR-0039/0040（前一阶段）、NOTES §11.32；
  对照实现：dae `transport/tls/reality.go`（utls）、
  XTLS `reality`/`mc-utls` 服务端、`proxy/vless/inbound/vision` 帧格式

## 背景

- 订阅#2 共 66 条：**48 条 `vless + security=reality + flow=xtls-rprx-vision +
  fp=chrome`** 此前被显式跳过（解析层拒绝），只有 18 条 anytls 可用。
- 服务端（xray/sing-box）行为：
  - REALITY 服务端当前**要求 ClientHello 携带 X25519MLKEM768 混合 key share**；
    用会话 id 的 AES-GCM 密封值判定授权；证书签名域被替换为
    `HMAC-SHA512(authKey, ed25519 pubkey)`；
  - 用户配置 `flow: xtls-rprx-vision` 时，**空 flow 客户端会被拒绝**，
    因此 Vision 帧层是使用这些节点的必要条件；
  - Vision 下行会在识别到内层 TLS 1.3 后**单方面 splice**（发 `command=0x02`
    之后裸 TCP 输出），客户端必须支持。
- rustls 无法满足：不能自定义 session_id/key_share、拿不到 ECDHE 私钥、
  无法按记录粒度切换裸直通。

## 决策

在 loader 内新增三个模块（零新运行时依赖，仅新增 `ring`/`x25519-dalek`/`ml-kem`
三个密码学 crate）：

1. **`tls13.rs`：最小 TLS 1.3 客户端**（专用，不做通用 TLS）：
   - 手写 Chrome 形状 ClientHello（GREASE、16 套件、扩展顺序、ALPN h2/http1.1）；
     session_id/random 由调用方注入，key share 支持 X25519 与
     **X25519MLKEM768（ek 1184B || X25519 32B）**；
   - 记录层 AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305；HKDF-SHA256/384、
     Finished 校验、Post-handshake KeyUpdate、close_notify/alert 处理；
   - 证书链不校验 PKI；`CertHook` 返回公钥时用 ed25519 校验 CertificateVerify
     （REALITY 场景）；
   - 分裂读写半（Arc<Mutex> 短锁、阻塞读在锁外），并暴露 **`raw_read` 开关**：
     Vision splice 后读半直接交付裸 TCP 字节。
2. **`reality.rs`：REALITY 客户端**：
   - authKey = HKDF-SHA256(ikm = X25519(clientEph, serverStaticPub),
     salt = random[:20], info = "REALITY")；
   - session_id 明文 `[1,8,10,0][unix u32][sid 8B][0*8]` 取前 16B，用 AES-256-GCM
     密封（nonce=random[20:32]，AD=session_id 置零的 ClientHello）回填 offset 39；
   - 校验叶证书：签名域（64B）== HMAC-SHA512(authKey, SPKI 公钥)；不通过即
     判定「被转发到真站」并报 `PermissionDenied`（防探测语义与 dae 一致）；
   - 极简 DER 解析（含长长度域）提取 SPKI ed25519 公钥与 signature。
3. **`vision.rs`：`xtls-rprx-vision` 客户端帧层**：
   - 帧格式 `[UUID 16B（仅首帧）][cmd 1B][contentLen u16BE][paddingLen u16BE]
     [content][padding]`；cmd 0x00/0x01/0x02；
   - 首帧长填充（TLS 首包垫到 ~900B+）；非 TLS 流量发 0x01 后直通；
   - 下行遇 0x02 切换 `raw_read`（含记录层已多读字节的移交）；
   - **上行不做 splice**（只发 0x00/0x01；服务端兼容，仅少一项优化）。
4. **接入**：
   - `vless.rs`：请求头 addons 支持 flow（protobuf field1）；
   - `outbound.rs`：`Outbound::Vless` 增 `reality`/`flow` 字段；
     `parse_vless` 支持 `security=reality&pbk&sid&fp&flow=xtls-rprx-vision`
     （reality 仅 tcp；vision 仅 reality 传输，非 reality 的 vision 仍拒绝）；
   - 订阅解析无需改动：link 解析成功后 48 条节点自动入组；
   - UDP over stream 对 reality 返回「不支持」→ 调用方直连回退（vision 为
     TCP 直通设计）。

## 与 dae 的差异（如实）

- **uTLS 指纹**：只实现 Chrome 形状的近似（扩展集合/顺序/长度接近 Chrome），
  不做 uTLS 的逐字节指纹库；`fp != chrome` 明确报错。
- 上行 splice 未实现（dae 在检测到内层 TLS 1.3 后会上行 direct）。
- 服务端启用 ML-DSA-65 附加签名时（证书签名域长度 != 64）本实现报错退出。
- 不触发 spider（未认证连接的伪装抓取）；未认证即失败并记录。

## 互操作踩坑（实测，供后人）

1. **key_share 的 GREASE 组必须同时出现在 supported_groups**——OpenSSL
   `extract_keyshares` 对不在 supported_groups 里的 share 直接
   `illegal_parameter`（Chrome 用同一 GREASE 值占两处）；
2. GREASE key share 的 data **不能为空**（utls/mc-utls 解析直接拒绝），
   Chrome/utls 均为 1 字节；
3. `compress_certificate` 用 Chrome 实际值 `[02 00 02]`（仅 brotli）；
4. REALITY 的 session_id **只密封前 16 字节**（GCM 输出 32B = 16 密文 + 16 tag）；
   AD 为「session_id 置零」的完整 ClientHello；
5. `MiniTuple.sport` 为网络序原始 u16（见 ADR-0040 第 3 条教训）。

## 后果

- **正面（实测）**：
  - `cargo test --release` **154/154**（新增 tls13/reality/vision 单测与
    `parse_vless_reality_ok_and_bad_fields_rejected` 等）；3 个 ignored 端到端：
    - `e2e_reality_vision_with_sing_box`：本机起 sing-box（REALITY+Vision
      参考服务端）→ 本实现拨号 echo，小数据+128KB 往返逐字节一致；
    - `tls13_real_server_handshake`：本 TLS13 客户端直接握手
      www.microsoft.com:443（严格栈）+ 本机 openssl s_server，多次重跑稳定；
    - `MINI_DAE_E2E_URL` 旁路：真实订阅节点 HTTP 200、HTTPS（内层 TLS 1.3，
      触发服务端下行 splice）成功；
  - 真机：loader `--listen-socks`（SO_MARK 生效）经真实 REALITY 节点
    `example.com` 200 / 0.64s；网关模式订阅#2：**66/66 节点入组**，
    `gateway.sh test` PASS、curl http/https 正常；lab `verify` 9/9 无回归。
- **负面/代价**：自维护 TLS 1.3 客户端（~1.6k 行）承担密码学正确性风险；
  限定 TLS 1.3-only、无 HRR/PSK/0-RTT。
- **风险**：REALITY 服务端演进（如强制 ML-DSA）需要跟进；Chrome 指纹仅近似，
  极端主动探测场景不保证等价。

## 验证方式（实测）

1. 单测：`cargo test --release`；密码学锚点：HKDF RFC 5869 向量、
   记录层加解密/KeyUpdate 往返、ClientHello 布局断言。
2. 参考实现对拍：`cargo test --release -- --ignored`（sing-box 服务端 e2e；
   `MINI_DAE_E2E_URL`/`MINI_DAE_E2E_TARGET`/`MINI_DAE_E2E_HTTPS` 可指向真实节点）。
3. 真机：`mini-dae --listen-socks 127.0.0.1:1083 --dialer '<reality url>'`
   + `curl -x socks5h://…`；网关订阅#2 + `gateway.sh test`。

## 修订条件

- 需要更多指纹（firefox/safari/随机化）或逐字节 uTLS 保真时；
- 需要上行 splice / XUDP(vision) / ECH 时；
- 节点生态大量迁移到 ML-DSA 证书时；
- 需要 TLS 1.2 回退或 HRR 支持时。

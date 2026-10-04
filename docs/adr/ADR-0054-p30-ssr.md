# ADR-0054：P30 SSR 出站（shadowsocksr-stream，origin+plain 首段）

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #6 余项「ssr」——12 个出站协议家族全部落地（SSR 为 v0 形态）
- **相关**：ADR-0004（Dialer 梯度推进）；NOTES §11.45；
  对照 dae `outbound` 的 `protocol/shadowsocks_stream`（链接解析 / origin proto / plain obfs）
  与 `ciphers/stream_cipher.go`（流密码）

## 背景

- dae 出站 12 家族（ss/ssr/trojan/vmess/vless/tuic/hysteria2/juicity/naive/http/socks5/anytls）
  中，mini-dae 此前已完成 11 个，**SSR 是最后一个未覆盖家族**。
- SSR 的复杂度与 SS classic 不同：链接格式为
  `ssr://base64(server:port:proto:method:obfs:urlbase64(password)/?params)`；
  协议层分 proto（`origin` / 各 `auth_*`）与 obfs（`plain` / 各 `obfs_*`），
  流密码含 OpenSSL EVP_BytesToKey(MD5) 密钥派生与 CFB/CTR/RC4/ChaCha 状态流。
- 参考实现 `olicesx/outbound` 中，`origin` proto + `plain` obfs 即「SS classic 风格
  流密码 + 首段目标地址」，是 SSR 的最小可用子集；`auth_*`/`obfs_*` 需要各自
  握手与填充协议，体量接近再写一个协议栈。

## 决策

1. **流密码层独立成模块（`ssr_cipher.rs`）**，对齐 Go `ciphers/stream_cipher.go`：
   - 方法集：`aes-128/192/256-cfb`、`aes-128/192/256-ctr`、`chacha20-ietf`、
     `rc4-md5`、`rc4-md5-6`（CFB-128/CTR 在 AES 块加密上自实现并跨调用保持状态；
     `rc4-md5(-6)` 用 `key' = MD5(key || iv)` 后 RC4）；
   - key 派生：OpenSSL `EVP_BytesToKey(MD5, 无盐)`——`d_i = MD5(d_{i-1} || password)`；
   - API：`SsrCipher::new(method, password)` / `iv_len()` / `init_encrypt()`
     （首调用生成随机 IV，Connection 内复用）/ `init_decrypt(iv)` /
     `encrypt()`/`decrypt()`（原位、有状态）；`chacha20` 采用 RustCrypto。
2. **SSR 连接层（`ssr.rs`）**，本版只做 **origin proto + plain obfs + TCP**：
   - 线格式：客户端→服务端 `[IV(ivLen)][E(目标地址 SOCKS5 风格 || 载荷…)]`，
     服务端→客户端 `[IV(ivLen)][E(载荷…)]`；读写各持一个流密码状态对象；
   - 首段写目标地址（`Target::encode_socks_addr_port`），读半首读先取对端 IV；
   - 链接解析同时接受 base64 外层与内层明文（生态里两种都有），
     password 字段为 URL-safe base64；`/??params` 截断；
   - `proto`/`obfs` 只接受 `origin`/`plain`（或空）：**其余值解析即显式报错**
     （不静默降级）；UDP 不做。
3. **接入 `outbound.rs`**：`Outbound::Ssr{dialer}`（`name()`/`server_addr()`/
   `dial_tcp` 分支）+ `parse()` 支持 `ssr://`（剥 `#fragment`）。
4. **lab 跨实现**：从 `olicesx/outbound` 移植 Go 参考服务端
   （`lab/proto-check/ssr-server/main.go`，origin+plain+流密码；上游 socket 打
   `SO_MARK=0x233`）；`ssr-up`/`test-ssr` 用例：交互探针 + 512KB 逐字节 +
   服务端 `SSR connect target=` 日志 + 状态面断言（offload 互斥）。

## 理由

- SSR 的 `auth_*`/`obfs_*` 是历史包袱最重的部分，且真实订阅中占比低；先以
  origin+plain 闭合「家族存在性」，把体量花在与 dae 出站清单的**结构对齐**上，
  比一次性移植全部插件变体更符合渐变式推进（ADR-0004）。
- 显式报错（而非静默按 origin 处理）保证配置作者立刻发现能力边界。
- 流密码与连接层分离，后续若要加 `auth_aes128_*`/`obfs_*`，握手层可插在
  `ssr.rs` 的 `connect()` 之上，不必动 `ssr_cipher.rs`。

## 后果

- 正面：出站 12 家族全有（SSR 为 origin+plain 子集）；`.dae` 中 `ssr://` 链接
  可直接使用；`ssr://` 解析和流密码有单测黄金向量。
- 负面/边界：`auth_*`（auth_aes128_md5/sha1、auth_sha1_v4、auth_chain_a/b）与
  `obfs_*`（http_simple/http_post/random_head/tls1.2_ticket_auth）**解析即报错**；
  UDP 未做；无插件（如 shadow-tls）组合。SSR 每连接独立流密码，
  不可与 TCP offload 拼接（lab 断言 `offloaded_total == 0`）。

## 验证方式

- 单测：`ssr_cipher` 5 例（Go 参考黄金向量、分块=连续、随机 IV 往返与复用、
  key 派生向量、错误面）+ `ssr` 3 例（base64 链接、内层明文、插件显式拒绝）——
  `cargo test` **225/225**。
- lab：`ssr-up` + `test-ssr` PASS——交互 `wan-echo-ok data=ping`、512KB
  `stream-ok bytes=524288`、Go 服务端日志见 `SSR connect target=...`、
  状态面 `conns_total>=2`/`dial_errors==0`/`bytes_up/down>=512KiB`/`offloaded==0`。
- 回归：`up`+`verify` 9/9；`test-juicity`/`test-tuic`/`test-dns-options` PASS；
  真机网关 down→up 自检通过 + `gateway.sh test` PASS（出口 IP + DNS）+ 日志 0 panic。
- 文档：本 ADR + parity v2.7 + HTML v2.38 + NOTES §11.45。

# ADR-0048：P24 协议细项——uTLS Chrome-120 对齐、Vision 上行 splice、TUIC 0-RTT（+ 边界清单）

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #6 余项的第一批（其余显式列出边界）
- **相关**：ADR-0041（REALITY+Vision）、NOTES §11.39；对照 uTLS `HelloChrome_120`、
  dae `tls_implementation/utls_imitate`、Xray Vision、quinn 0-RTT

## 背景

- REALITY 走自实现 TLS 1.3（tls13.rs），ClientHello 可字节级控制——但此前是「Chrome 形状
  近似」（签名算法集合/顺序与 uTLS 有出入、无 ALPS、无 GREASE-ECH、padding 固定 8 字节）。
- Vision 代码注释写「不做上行 splice」，但实现自 P18d 起已具备（窗口结束/非 TLS 帧发
  CMD_END 后裸写），注释与代码不一致。
- TUIC 未尝试 quinn 的 0-RTT。
- 其余：ECH、SIP003 插件（shadow-tls）、juicity/naive/ssr 属独立协议栈。

## 决策

1. **uTLS Chrome-120 对齐**（tls13.rs `build_full_hello`，仅 REALITY 路径）：
   - 签名算法集合/顺序改为 uTLS 的 8 项（0x0403/0x0804/0x0401/0x0503/0x0805/0x0501/0x0806/0x0601）；
   - `supported_versions` = GREASE + TLS1.3 + TLS1.2（原仅 1.3）；
   - 新增 ALPS/`application_settings`(0x4469, h2) 与 GREASE-ECH（BoringGREASEECH 形状：
     outer=0、HKDF-SHA256+AES-128-GCM、随机 config_id/enc、payload 144/176/208/240 随机）；
   - padding 改 BoringPaddingStyle（仅 `0xff < 长度 < 0x200` 时垫到 0x200，否则不发）。
2. **Vision 上行 splice**：确认实现（过滤窗口结束/非 TLS 数据发 CMD_END 后 `finished`，
   后续字节裸写 TLS 应用数据，即 Xray 的 uplink splice）；修正过时注释并加回归测试。
3. **TUIC 0-RTT**：`connect_and_auth` 优先 `Connecting::into_0rtt()`——早数据上发认证与
   首流；认证失败或服务端无票据（`Err(connecting)`）无痛回退 1-RTT。
4. **显式边界（本轮不做，原因如实）**：
   - **ECH**：rustls 无客户端 ECH；自实现需 HPKE + ECHConfig 获取/轮换，超出本轮；
   - **shadow-tls 插件**：其 v3 协议依赖 fork 过的 rustls 暴露 TLS randoms 与
     session_id 生成器（HMAC 于 client/server random）；在 rustls 路径不可实现，
     需以自实现 TLS 栈重做（独立立项）；
   - **juicity / naive / ssr**：各自独立协议栈（QUIC 变体、h2/h3 CONNECT、SSR 认证），
     非「收尾」量级；
   - **uTLS 逐字节（rustls 路径）**：rustls 不暴露 ClientHello 构造，只能对 REALITY
     自实现栈做逐字节；其余 TLS 出站仍为 rustls 形态（文档化差异）。

## 理由

- Chrome-120 对齐以 uTLS 源码为基准逐项核对（集合而非顺序——Chrome 自身对非 GREASE
  扩展随机洗牌，JA3 族指纹看集合/GREASE 数），投入小、对真实 REALITY 服务端更友好。
- 上行 splice 与 0-RTT 都是「已有实现/API 上的补齐」，风险低；0-RTT 必须可无痛降级，
  否则会因服务端未开而断流。

## 后果

- 正面：REALITY 指纹更贴近真实 Chrome 120；Vision 上行少一层帧开销（与服务端直通）；
  TUIC 复用票据时省 1-RTT。真机订阅 48 条 REALITY 全部健康（见验证）。
- 负面/边界：上述清单（ECH/shadowtls/juicity/naive/ssr、rustls 路径 uTLS）仍未做，
  已在 parity 表与 README 显式列出；Chrome 版本会演进（当前对齐 uTLS HelloChrome_120，
  与 dae 的 `HelloChrome_Auto` 可能随上游更新漂移）。

## 验证方式

- 单测：tls13 6 项（含 ClientHello 结构/字段回归）、vision 3 项（新增 END 后裸字节断言）、
  tuic 7 项；`cargo test --release` **202/202**。
- lab：`test-tuic`（Go/quic-go 服务端）PASS（0-RTT 不可用场景走 1-RTT 回退）；
  `verify` 9/9。
- 真机（P24 关键）：新二进制重启网关，启动自检通过；订阅含 **48 条 REALITY** 的组
  66/66 alive（健康检查逐一握手，等价逐节点 REALITY 互操作验证）、代理路径
  generate_204 → 204、出口 IP 正常、日志 0 panic/Error。
- 文档：本 ADR + parity v2.2 + HTML v2.33 + NOTES §11.39。

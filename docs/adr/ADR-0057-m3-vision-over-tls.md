# ADR-0057：M3 Vision-over-TLS——XTLS DIRECT 双向直通（rustls 无反射实现）

- **状态**：已采纳（2026-10-05）
- **对应决策点**：M3（`docs/vless-proposal.html` 提案）
- **相关**：ADR-0017（VLESS 子集）、ADR-0022（P7 收口）、ADR-0041/0048（REALITY+Vision）、`docs/optimization-roadmap.md` O9

## 背景

M2 后 VLESS+TLS 是主链路，但生态主流节点组合还差两块：

1. `flow=xtls-rprx-vision` 只在 REALITY 外层实现（且仅下行 raw、上行 END），
   `security=tls` 直接解析报错——而 Xray 节点普遍是「TLS/REALITY + Vision」；
2. 对照 dae（`olicesx/outbound protocol/vless/vision`）：完整 XTLS DIRECT 是**双向**的——
   过滤窗口内嗅探**内层**流量，确认 TLS 1.3（受支持 cipher）后发 `0x02` 并**双向切裸 TCP**
   （外层加解密停用，内层 TLS 端到端保障安全）。dae 的实现用 `unsafe` 反射读 Go TLS
   内部 `rawInput`（多读的裸字节）来交接；我们此前既没有内层嗅探，也没有上行 raw 写。

## 决策

1. **实现完整 XTLS DIRECT（双向）**，外层支持 `security=tls` 与 `security=reality`：
   - 新增 `vision::TlsSniffer`（移植 dae `FilterTLS`）：过滤窗口 6 包内双向观察，
     识别内层 ServerHello 的 TLS 1.3 supported_versions + 受支持 cipher（0x1305 除外）；
   - 写半：窗口结束/应用数据开始且 `enable_xtls` → 发 `0x02`（DIRECT）并置
     `write_raw`；否则发 `0x01`（END，保持原协议）；
   - 读半：收到 `0x02` 置 `read_raw`；`0x01` 仅停止 Vision 分帧。
2. **不用 unsafe/反射**。rustls 读半提供「逐记录有界喂入」模式（`record_mode`）：
   按 TLS 记录边界精确读取，切换点前一个字节都不多读；置位 `raw` 后先交付 rustls
   残留明文，再裸读 TCP。REALITY 自研 tls13 本就有 `raw_read`，补齐 `raw_write`。
3. **边界与拒绝**：vision 需外层 TLS 1.3（tls 或 reality；rustls 协商结果校验）；
   仅 TCP（ws+vision 解析即报错，Xray 同义）；vision 连接**不启用 kTLS**
   （DIRECT 需中途停用外层加解密，内核 kTLS 无法动态撤销）。
4. 解析层开放 `security=tls&flow=xtls-rprx-vision`（此前显式拒绝）。

## 理由

- 与 Xray/dae 行为对齐；DIRECT 后内层 TLS 不再双重加密，且两端可内核 splice，
  是内层 TLS 流量（HTTPS 浏览）在代理链路上的关键省 CPU/降延迟路径；
- 逐记录有界读替代反射：无 unsafe、无版本耦合，且 rustls 侧语义可单测；
- 嗅探保守失败（解析失败/低版本/不支持 cipher → END），不会静默降级为不兼容流量。

## 后果

- 正面：`tls|reality` × `vision` 全组合可用；`flow=...` 不再限定 reality；
  内层 TLS 1.3 流量走 DIRECT（双向裸 TCP）；TLS1.2/明文自动 END，互通不回退。
- 负面/代价：vision 连接读路径逐记录（少批量）、不参与 kTLS/relay splice
  （DIRECT 本身即数据面直通，无需 splice）；依赖对端 Xray 实现 DIRECT 语义
  （非 Xray 的 vision 服务端按 END 兼容处理）。
- 需警惕：外层 TLS1.2 + vision 明确报错（不静默）；`xray` 服务端在 DIRECT 后
  发送的裸字节绝不能落入 rustls（有界读保证）；`--ktls` 与 vision 组合时 vision
  连接自动旁路 kTLS。

## 验证方式

- 单测 240/240（新增 5：嗅探 TLS1.3/TLS1.2 外层门控/ClientHello、DIRECT 写切换、
  END 非 TLS）；`cargo test reality`（sing-box REALITY+Vision 往返）通过；
- 集成（新增 `lab/vision/`，Xray 25.9.11 服务端 + 内层 TLS 靶站）：
  - `security=tls|reality`：内层 TLS1.3 2MB **逐字节一致** + 上行/下行 DIRECT 各触发；
    内层 TLS1.2 与明文 HTTP 走 END 互通；
  - `security=ws|wss`：分别明文 HTTP 与 2MB HTTPS 逐字节通过；
- 真实订阅 e2e：48 条 reality+vision 节点加入组，5MB 下载完整、
  日志出现双向上/下行 DIRECT 切换（6/6），lab `verify` 9/9 无回归。

## 相关

- 实现：`loader/src/vision.rs`（嗅探/状态机）、`loader/src/tls.rs`
  （`connect_vision`/`record_mode`/raw 开关）、`loader/src/tls13.rs`（raw 写）、
  `loader/src/outbound.rs`（tls/reality 两路装配 + URL 约束）；
- 测试：`lab/vision/run.sh`（Xray 夹具）、`docs/vless-proposal.html` M3 行。

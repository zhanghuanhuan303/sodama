# 安全策略

## 支持范围

安全修复优先进入 `main` 分支的最新版本。历史 tag 是否回移取决于影响范围与维护成本。

## 报告漏洞

请使用 GitHub 的 **Security Advisories**（仓库页面 → Security → Report a vulnerability）私下报告，不要开公开 issue。

报告中请尽量包含：

- 受影响版本/commit；
- 复现步骤或最小配置；
- 影响范围（本机 / LAN / 上游节点 / 面板）；
- 是否涉及 root/特权、eBPF、面板鉴权或订阅拉取；
- 你希望采用的署名方式（可选）。

我们会在确认后尽快给出处置计划。修复发布前，请不要公开漏洞细节。

## 威胁模型与默认面

sodama 以 root/特权运行，加载 eBPF、接管流量并解析来自 LAN 与上游节点的数据。请把以下输入视为不可信：

- 客户端 TLS/QUIC/HTTP 握手与 DNS 查询；
- 上游节点回包（可能被劫持或恶意）；
- 订阅正文与规则集文本；
- geodata 文件；
- 配置与面板 HTTP API。

当前默认值：

- Web 面板默认只监听 `127.0.0.1:8080`；**绑定非回环地址且未设置 token 时拒绝启动**。
- 控制类动作（reload / suspend / resume）在 Arch 模板中默认关闭，按需开启。
- 状态面 socket 建议放在 `/run` 下并限制权限；生产部署请按 `docs/deploy.md` 与 systemd 单元注释收紧。
- 订阅拉取限制正文大小、重定向次数与 Content-Length 精确校验；仍建议只使用可信订阅源。

## 加固建议

- 不要在公网暴露面板；需要远程访问时使用 SSH 隧道或带鉴权的反向代理。
- 使用最小权限的 systemd 单元，并保持内核对 BTF/eBPF 的更新。
- 定期运行 `cargo audit` / `cargo deny`（见 `deny.toml`）并关注依赖公告。
- 对生产配置与订阅 URL 设置严格文件权限；不要写入 shell 历史或提交到 git。
- 通过 [`docs/methodology.md`](./docs/methodology.md) 的 lab 流程验证改动，不要在唯一生产网关上直接试验。

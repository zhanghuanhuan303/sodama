# Changelog

本文件记录面向用户的变更。历史开发记录（逐轮侦查/修复/验收）见 [`docs/phase2-devlog.md`](docs/phase2-devlog.md)，架构决策见 [`docs/adr/`](docs/adr/)。

## v1.0.0 — 2026-10-24

首个公开源码版本（由私有研究仓库整理）。

- 数据面：Rust/aya-ebpf 全量实现，14 个 TC 程序（7 角色 × 2 种链路头）+ 1 个 `sk_skb` offload verdict，无 C 数据面。
- 控制面：`.dae` 配置解析/规则编译、DNS 接管与 `dns.routing`、TCP relay / UDP NAT / TCP offload、状态面/热重载/指标。
- 协议：shadowsocks / trojan / vless（tcp/ws）/ vmess / tuic / hysteria2 / anytls / naive / juicity / SSR / shadow-tls 等。
- 部署：systemd、Arch/AUR 打包、OpenWrt 打包、Web 控制面板（axum + Leptos/WASM）。
- 方法：与 dae Go 规则编译器逐字节对拍；netns lab、真实节点/真网关验收、双内核矩阵、性能与内存口径。
- 公开整理：订阅/节点/生产环境信息脱敏；源码头统一为 `AGPL-3.0-only`；补充 `SECURITY.md`、`CONTRIBUTING.md`、`NOTICE`、`THIRD_PARTY_LICENSES.md` 与本 changelog。
- 安全默认值：Web 面板默认仅监听 `127.0.0.1:8080`；非回环绑定且未设置 token 时拒绝启动。

## Unreleased

- 待补：发行 CI（tag 构建 + SHA256SUMS）、`cargo-deny` 接入 CI、Docker 镜像、更多 fuzz 目标。

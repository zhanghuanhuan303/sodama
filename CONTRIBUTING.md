# 贡献指南

感谢你关注 sodama。这个仓库首先是一个**研究方法论仓库**：代码、实验、数据和结论都要能追溯、能复现。提交前请先读 [`README.md`](./README.md)、[`docs/methodology.md`](./docs/methodology.md) 与 [`SECURITY.md`](./SECURITY.md)。

## 开始之前

- sodama 是**以 root/特权运行**的网络软件（eBPF、tproxy、netns）。请优先在虚拟机或专用测试机中开发，不要把实验配置直接部署到生产网关。
- 不要提交真实订阅 URL、token、节点域名、节点 IP、生产路由器地址或任何凭据。示例统一使用 `example.com`、`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`。
- 如果你发现了安全问题，请不要开公开 issue，按 [`SECURITY.md`](./SECURITY.md) 私下报告。

## 构建

```bash
# 引擎用户态 + eBPF 数据面（按需安装 nightly + rust-src + bpf-linker）
cd sodama
lab/lab.sh build

# 仅用户态
cargo build --release --locked

# Web 面板
cd panel
wasm-pack build frontend --target web --release --out-dir dist/pkg --out-name panel
cargo build --release --locked -p backend
```

eBPF 目标需要 nightly + `rust-src` + `bpf-linker`；具体版本与 CI 一致（见 `.github/workflows/ci.yml`）。

## 测试与验收

提交前至少跑：

```bash
cd sodama
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --release --locked --workspace
```

涉及数据面/转发的改动，还需要在 netns lab 中跑对应专项（`lab/lab.sh`），并在 PR 中贴出命令与关键结果。需要 root/netns 的用例不进 GitHub Actions，这是明示边界。

## 代码风格

- 保持现有模块边界与错误处理风格；优先复用已有解析器、规则编译器和测试夹具。
- 不为了通过 lint 而删除有意义的分支；如果确实需要放行 lint，写明理由。
- 注释只解释非显而易见的意图、约束或取舍，不重复代码。
- 新增协议实现时，优先补跨实现测试或黄金向量，而不是只测自家实现。

## 提交与 PR

- 一个 PR 聚焦一件事；较大的改动先开 issue 说明设计与验收标准。
- 提交信息建议使用 `type(scope): summary`（如 `fix(panel): ...`、`docs(adr): ...`）。
- PR 描述中写明：改了什么、为什么、如何验证、已知边界。
- 更新相关文档：ADR、`docs/config-reference.md`、README 或测试说明。
- 不要在 PR 中提交构建产物、日志、真实配置或脱敏前的截图。

## 许可证

本项目以 **AGPL-3.0-only** 发布（见 [`LICENSE`](./LICENSE)）。提交 PR 即表示你同意将贡献以同一许可证发布，并确认你有权提交该代码/数据。

如果你移植了第三方代码或数据，请在 PR 中注明来源与许可证，并同步更新 [`NOTICE`](./NOTICE) 与 [`THIRD_PARTY_LICENSES.md`](./THIRD_PARTY_LICENSES.md)。

## 行为准则

请遵守 [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)。

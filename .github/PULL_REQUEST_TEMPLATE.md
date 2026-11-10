## 改动说明

<!-- 改了什么、为什么、关联 issue/ADR -->

## 验证

<!-- 勾选并补充命令/结果；需要 root/netns 的用例请说明环境 -->

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --release --locked --workspace`
- [ ] lab 专项 / 真实节点 / 面板冒烟（按需，附命令与关键结果）

## 边界与风险

<!-- 已知未覆盖项、兼容性影响、迁移/回滚方式 -->

## 检查清单

- [ ] 没有提交真实订阅 URL、token、节点域名/IP、路由器地址或凭据
- [ ] 新增/修改的第三方代码或数据已更新 `NOTICE` / `THIRD_PARTY_LICENSES.md`
- [ ] 相关文档/ADR/README 已同步
- [ ] 我同意将本贡献以 AGPL-3.0-only 发布

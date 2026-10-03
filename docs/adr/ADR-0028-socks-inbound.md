# ADR-0028：本地 SOCKS5 入口模式（桌面/浏览器测试，P12）

- **状态**：已采纳（2026-10-04）
- **对应**：P12；为"用真实节点做浏览器验收"提供最小接入面
- **相关**：ADR-0008（部署形态）、ADR-0027（anytls）、NOTES §11.19

## 背景

真实节点验收此前只能靠 lab netns 客户端、`lab/real-node-e2e.sh` 或绕道 socks5 桥接；
用户要用**浏览器**实测 mini-dae，需要一个本机可指向的入口。dae 的常态是路由器网关
（透明代理），但单机桌面测试最简的是 SOCKS5。

## 决策

1. 新增 `--listen-socks <addr>`：本地 SOCKS5 服务（CONNECT、无认证；目标支持 IPv4/域名；
   UDP ASSOCIATE、BIND、IPv6 目标显式拒绝）。目标经既有 dialer（真实节点）出网；
   中继泵直接复用 relay 的 `pump`（含半关闭语义）。
2. **该模式不加载 eBPF、不需要 root**：在 `main` 的 `compile_dump` 分支之后短路返回，
   避免在用户的真实网卡上挂钩子（安全第一）；纯用户态进程。
3. 域名目标在**本地解析**（远端解析需要 dial 层引入 domain target，留作后续）。
4. 顺手修复 `resolve()`：**优先 IPv4**（真实节点域名常为双栈 VPS，AAAA 记录优先会让
   "只支持 IPv4"的协议栈直接误拒——实测踩到）。

## 理由

- 与 lab 完整性测试共用同一套协议栈与 dialer，验收价值等同，但接入成本降到一条命令；
- 不碰 eBPF/iptables，用户机器零风险面；
- 复用 `pump` 与 WriteHalf 体系，不新增转发路径。

## 后果

- 正面：浏览器指向 `socks5://127.0.0.1:11080` 即走真实节点；实测 gstatic 204、
  YouTube 200（单连接 down 918KB）；零 root、零 netns。
- 负面/代价：DNS 本地解析（泄露/污染风险；v1 边界）；无 UDP（对 anytls 节点本就无 UDP）；
  无认证（必须在文档中建议只绑 127.0.0.1）。
- 风险：若绑定到非回环地址即成为开放代理，文档与帮助文本明示默认回环。

## 验证方式（实测）

- 单元：`socksin` 6 项——IPv4 解析、域名解析、UDP ASSOCIATE 拒绝、IPv6 目标拒绝、
  域名本地解析、应答字节布局；
- 端到端（本机真机，用户桌面）：`--listen-socks 127.0.0.1:11080
  --dialer anytls://<订阅#2节点> --dial-timeout 15`：
  `curl --socks5-hostname` gstatic **204**、`curl --socks5`（本地解析路径）**204**、
  YouTube **200**（relay 日志 down=918589B）；
- 回归：`cargo test --release` **95/95**；标准 verify 9/9（数据面未改）。

## 修订条件

需要远端 DNS（domain target）、UDP ASSOCIATE 或认证时扩展本 ADR；
若要做桌面常驻，可加 user systemd unit 与订阅热更新（另开 ADR）。

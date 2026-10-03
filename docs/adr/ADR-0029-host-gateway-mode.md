# ADR-0029：真网关模式——宿主流量透明接管（host gateway，P13）

- **状态**：已采纳（2026-10-04）
- **对应**：P13；用户选定「方案 4」：整机流量 eBPF 透明代理，浏览器零配置
- **相关**：ADR-0008（部署形态）、ADR-0012/0014（DNS 接管）、ADR-0015（转发面）、ADR-0028（SOCKS 入口）、NOTES §11.20

## 背景

P12 之后，mini-dae 已能在 netns lab、`real-node-e2e.sh` 与本地 SOCKS5 入口三种方式下
跑真实节点；但 SOCKS5 入口要求浏览器配置代理，与 dae 的真实形态（透明网关）仍有距离。
用户希望在本机（Arch 桌面，`wlan0` 默认路由，有 root）验证「真网关」体验：
**浏览器/系统零配置，整机 TCP 流量被 eBPF 接管并经真实节点出网**。

约束与目标：

- 不移动物理网卡（避免 Wi-Fi 闪断、不惊扰 NetworkManager）；
- 一键启停、可回滚、失败不影响原有网络；
- 节点 URL 等敏感信息不进仓库。

## 决策

1. **新增 `--lan none`**（loader）：显式声明不挂任何 LAN ingress 钩子，保留 `landae` 默认行为
   不变；宿主网关只需 `--wan <iface>`（egress 分流 + ingress 状态刷新）。
2. **新增 `lab/rules.gateway.dae` 与 `lab/gateway.sh`**（`up|down|status|test`，含 `--dry-run`）：
   - `up` 前置幂等 `down`，建控制面对（netns `gwdae` + veth `dae0gw/dae0gwpeer`，
     169.254.0.11/32 + 静态邻居 + `fwmark 0x8000000 → table 2023`，与 lab 拓扑一致），
     放宽 `rp_filter`，启动 loader 并做存活检查；
   - `down` 杀进程、删 netns/veth、按 state 文件恢复 sysctl；
   - 节点 URL 仅从 `--node <文件|URL>` 读取（默认 `/tmp/mini-dae-node.url`，建议 600），
     日志与 status 输出对 `--dialer` 做 redact。
3. **拓扑：物理网卡留在宿主 netns**，只挂 `mini_wan_egress` / `mini_wan_ingress`；
   被判 proxy 的 TCP 由 `bpf_redirect` 进 `dae0gw` → `dae0gwpeer` ingress → tproxy（daens），
   回程由 dae0 ingress 按 `redirect_track` 还原 MAC 后 `BPF_F_INGRESS` 注回 WAN。
   这正是实验室 `test-host-proxy` 已验证过的宿主流量路径。
4. **规则约束（实测得来）**：
   - **禁止写任何 `sip(...)` 规则**：宿主机流量源地址就是本机私网地址，
     `sip(192.168.0.0/16) -> direct` 会把全部出站流量判成直连（首轮实测表现：
     TCP 直连被墙、只有 DNS 因数据面自动 override 进入控制面）；
   - DNS(53/udp|tcp) 用 `direct(must)` 并放在私网 `dip` 规则之前——eBPF 数据面对任何
     命中的非 must 规则会自动把 53 端口改成送控制面 DNS 模块，`must` 才能保住系统解析路径
     （同时避免缺省上游 `8.8.8.8:53` 在受限网络不可达）；
   - QUIC(443/udp) 显式 `block`，促使浏览器回落 TCP（UDP 暂不做代理）；
   - 私网/组播/广播按 `dip` 直连；`fallback -> proxy`。
5. **防自环沿用 `SO_MARK=0x233`**：relay/upstream socket 全部打标，数据面见 mark 直接放行。
6. **回滚安全**：tcx 钩子随进程退出自动拆除（loader 崩溃 = 网络立即恢复直连）；
   `gateway.sh down` 再清理 netns/veth/sysctl。

## 理由

- 复用已验证路径（`lab.sh test_host_proxy`：wan egress 分流 + dae0 ingress from_wan 回程），
  零新增数据面代码；物理网卡不移动，风险面最小；
- DNS 直连（must）与系统行为完全一致，避免把"解析可用性"绑在控制面 DNS 模块的
  上游可达性上；控制面 DNS 模块仍可被 `.dae` 配置路径使用；
- QUIC block 让"只代理 TCP"的边界对浏览器表现为确定性回落，而不是半直连半代理的分裂体验。

## 后果

- **正面（已实测）**：`up` 后浏览器零配置；`generate_204` **204**、YouTube **200**、
  出口 IP 为节点侧（203.0.113.45）；relay 计数 `conns_total=4 / active=1 / dial_errors=0`、
  下行 931KB；`down` 后钩子/网卡状态全清、直连恢复（baidu 200）；`--dry-run` 零副作用。
- **负面/边界（如实标注）**：
  - 数据面只解析 IPv4，**IPv6 不代理**（提供 `--no-ipv6`：临时 `disable_ipv6=1`，down 恢复）；
  - UDP 暂不做代理（除 53 直连外全部直连，QUIC 显式阻断）；
  - 被 DNS 污染影响的域名依赖浏览器 Secure DNS/DoH（DoH 走 TCP:443 会被代理）；
  - Docker/容器流量同样经 wlan0 egress 被接管；
  - Wi-Fi 重连或重启后钩子状态：重启丢失（未做 systemd unit/自愈，留作后续）。
- **风险**：`rp_filter` 放宽是全机设置（state 文件记录原值，down 恢复）；
  脚本需要 root；节点凭据只在 `/tmp` 与进程 argv。

## 验证方式（实测，2026-10-04，本机 Arch / 6.18.54-lts / wlan0 192.0.2.254）

1. `sudo lab/gateway.sh up --node /tmp/mini-dae-node.url` → 钩子 4 个
   （`mini_wan_egress@wlan0`、`mini_wan_ingress@wlan0`、`mini_dae0_ingress@dae0gw`、
   `mini_dae0peer_ingress@dae0gwpeer`），规则 15 条 match_set 下发；
2. `lab/gateway.sh test`：204 / 出口 IP=节点侧 / DNS ok；
   `curl -4 https://www.youtube.com` 200；relay 931KB down、0 dial error；
3. `sudo lab/gateway.sh down`：`bpftool net show dev wlan0` 无钩子、netns/veth 已删、
   `curl baidu` 200；再次 `up` 幂等成功；
4. `bash -n` 语法检查、`--dry-run` 全命令预览（实测时注意：`up --dry-run` 不产生任何变更）。

未验证/未做：开机自启与崩溃自愈（systemd）、IPv6 代理、UDP 代理、DNS over proxy。

## 修订条件

需要「开机常驻」、多网卡/有线切换、UDP 代理、IPv6 代理或 DNS over proxy 时，
新写 ADR 扩展；若数据面将来能自动区分「宿主自身」与「转发流量」，可放宽对规则
（尤其 `sip`）的约束说明。

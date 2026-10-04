# ADR-0046：UDP over IPv6 全链（P22）——sockmap key 3 + v6 透明 UDP + v6 DNS 接管

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #3「IPv6」——UDP v6（含 DNS over UDP6）
- **相关**：ADR-0032（IPv6 TCP 全链）、ADR-0034（透明 DNS）、NOTES §11.23/§11.37

## 背景

- P16 完成 TCP 全链（v6 解析/tproxy/sockmap key 2/协议目标 v6 编码/direct/v6 嗅探），
  但 UDP v6 未做：eBPF `progs.rs` 早已计算 sockmap key 3（v6 UDP），`listen_socket_map`
  却只有 3 个槽且 loader 未注册 v6 UDP socket；DNS over UDP6 落到 key 3 后无监听、
  被内核按本机投递失败。
- 协议侧：ss UDP 载荷对 v6 目标直接返回「仅支持 IPv4」。

## 决策

1. **eBPF（最小改动）**：`listen_socket_map: SockMap<3> → SockMap<4>`（key 3 = IPv6 UDP；
   key 0/1/2 保持 TCP v4 / UDP v4 / TCP v6），progs.rs 的 key 计算零改动。
2. **loader UDP socket 家族化**（`main.rs`）：
   - `sockaddr_any_of`（v4/v6 → sockaddr_storage+len）与 `sockaddr_to_std` v6 分支；
   - `new_udp_socket(family)`：AF_INET6 时置 `IPV6_TRANSPARENT`，v4 保持 `IP_TRANSPARENT`；
   - `make_transparent_udp6`：`IPV6_V6ONLY=1` + `IPV6_RECVORIGDSTADDR` + bind `[::]:tproxy_port`；
   - `recv_with_orig_dst` 解析 `IPV6_ORIGDSTADDR` cmsg；回包 socket 按族绑定
     （`make_transparent_udp_bound`，源地址=原始目的，与 v4 同语义）；
   - main 注册 sockmap key 3 并起**第二个 `dns_loop` 线程**（同一处理逻辑：orig_dst 端口
     53 → DNS 接管；其余 → UDP NAT 会话表；失败降级为仅 v4 并日志）。
3. **协议侧**：ss UDP 目标支持 IPv6（RFC1928 ATYP=0x04 + 16 字节地址 + port）；
   `outbound::new_marked_udp_for(peer)` 按对端地址族建 socket（direct UDP 回退与
   ss UDP 出口都吃 v6 目标）。
4. **lab 夹具**：`wan_echo.py` UDP 双栈（V6ONLY 并存）；`ss_server.py` UDP 出口按族
   懒建（移除 v6 unsupported 分支）；`udp_probe.py`/`dns_probe.py` 按 server 字面量选族；
   `rules.v6.dae` 增 `dip(2001:db8:aa::1) && dport(9998) -> proxy`；`test-v6` 追加
   v6 UDP relay 与 v6 DNS 断言。

## 理由

- eBPF 侧只差一个 map 容量：sockmap key 语义在 P16 已按「(TCP?0:1)+(v6?2:0)」写好，
  沿用该约定（key 3）改动最小、语义最清晰。
- 独立 v6 监听 + 独立线程：与 v4 完全对称，`SIGUSR2` 挂起语义/回滚不受影响；V6ONLY
  避免与 v4 socket 抢同一端口（两者都在 daens）。
- 回包透明绑定原始目的地址：客户端 DNS 校验/连接五元组与 v4 行为一致（lab 断言
  `from=2001:db8:aa::1:53`）。

## 后果

- 正面：v6 DNS 查询经控制面解析（可套用 dns.routing/缓存/位图）；v6 UDP NAT 会话
  全链可用（跨实现：Python ss 服务端 v6 出口）；IPv6 数据面覆盖从「TCP 全链」变为
  「TCP+UDP 全链」。
- 负面/边界：ICMPv6/分片仍不处理；UDP v6 域名拨号（按嗅探 SNI）未做（UDP 侧仅观
  测，同 P20）；v6-only 的 tproxy 端口不可用时降级为仅 v4（日志提示）。

## 验证方式

- 单测：`cargo test --release` 202/202（含 sockaddr/回包路径重构后的全量回归）。
- lab `v6-up` + `test-v6`：
  1) TCP 代理路径（tproxy v6 → ss ATYP=4 → v6 echo）与 v6 direct 回归；
  2) `[2001:db8:aa::1]:9998` UDP 2/2 回显，ss 日志出现 `UDP target=2001:db8:aa::1:9998`
     （SS v6 目标跨实现）；3) `[2001:db8:aa::1]:53` DNS：rcode=0、answer=10.9.10.35、
     回包源=原始目的、假上游恰好 1 次；`udp v6 listener registered … key 3` 日志存在。
- 回归：`udp-up` + `test-udp-relay`/`test-quic-sniff` PASS；`verify` 9/9。
- 文档：本 ADR + parity v2.2 + HTML v2.31 + NOTES §11.37。

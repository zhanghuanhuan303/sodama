# ADR-0032：IPv6 数据面（TCP 全链，P16）

- **状态**：已采纳（2026-10-04）
- **对应**：P16；补对标表缺口 #3「IPv6 数据面」
- **相关**：ADR-0024（数据面 Rust 化）、ADR-0029（真网关）、ADR-0030（嗅探）、ADR-0031（订阅）、NOTES §11.23

## 背景

- 对标清点里 IPv6 是显式边界：eBPF 只解析 IPv4，`dip()` 只接受 v4 前缀，
  协议目标编码只有 v4；`--no-ipv6` 只是"关掉网卡 IPv6"的规避，不是支持（覆盖度 ≈5%）。
- dae 原版的 IPv6 支持是完整数据面的一部分：`netns_utils.go` 的 `setupIPv6Datapath`
  给 daens 配 fe80 网关 + IPv6 默认路由 + `fwmark→table 2023 local`；
  tproxy.c 的解析、redirect、连接跟踪、L4 交付都是 v4/v6 同构（`redirect_tuple` 本来就是 16 字节地址）。
- 真机环境（本机 Arch）有原生 IPv6（RA 下发的 GUA + 默认路由），具备实测条件。

## 决策

1. **五元组统一 16 字节**（`ebpf-rs/common.rs` + loader 镜像 `MiniTuple`）：
   `sip[16] / dip[16] / sport / dport / l4proto / is_v6 / pad`。IPv4 以
   **v4-mapped**（`::ffff:a.b.c.d`，与上游 `redirect_tuple` 的注释一致）存入，
   v6 存原始 16 字节。`conn_state_map` / `redirect_track` / `fast_sock` 的 key
   全部换成该结构（对拍工具、rebind 工具同步 40 字节布局）。
2. **解析**（`parse.rs`）：新增 `parse_v6` —— 固定头 + 跳过 hop-by-hop(0)/routing(43)/
   dest-opts(60)（最多 4 个）；**分片(44)不处理**（返回 None 交内核原路径）；
   统一入口 `parse_ip`。v4/v6/`parse_ip`/`load_l4` 必须 `#[inline(always)]`
   （verifier：嵌套调用返回大结构体会报 `cannot return stack pointer to the caller`）。
   `MiniParseResult.is_v4` 驱动 `ipversion` 规则与 sockmap key。
3. **交付路径**：`flow.rs` 在 cb 里带 `is_v6`（cb[3]）；`progs.rs` 的
   `dae0peer_ingress` 用 `key = tcp?0:1 + (v6?2:0)` 选择 listener
   （0/1=TCP/UDP v4，2=TCP v6，3=UDP v6 预留未注册）；loader 侧新增
   `make_transparent_listener6`（`AF_INET6` + `IPV6_TRANSPARENT` + `V6ONLY` +
   `SO_MARK`，bind `[::]:port`）注册到 sockmap key 2，`serve` 线程在 daens 内创建。
   回程 `dae0_ingress` 的 rev 元组补 `is_v6`（否则查不到 redirect_track）。
4. **控制对 IPv6**（lab.sh / gateway.sh，对照 `setupIPv6Datapath`）：
   - host：`ip -6 addr add fe80::ecee:eeff:feee:eeee/128 dev <dae0> scope link nodad`、
     `net.ipv6.conf.<dae0>.forwarding=1`；
   - daens：`ip -6 route add default via fe80::ecee:eeff:feee:eeee dev <dae0peer>`、
     `ip -6 neigh add fe80::... lladdr <dae0 MAC> dev <dae0peer> nud permanent`、
     `fwmark 0x8000000 → table 2023` + `local default dev lo`；
   - **静态邻居是硬要求**：靠动态 NDP 时，host 的 NA 回包进入 daens 会被
     `dae0peer_ingress` 的「cb[0] != TPROXY_MARK → SHOT」丢掉（与上游 C 相同），
     邻居永远 INCOMPLETE，tproxy 的 SYN-ACK 发不出去。上游同样写静态邻居，照搬。
5. **规则**：LPM 键 16 字节（v4 前缀前缀长度 +96），`dip/sip` 接受 v4/v6 CIDR；
   手写 mini 规则里 v6 前缀含 `:` 必须加引号（`dip('fe80::/10')`），`.dae` 提取器自动加。
6. **协议目标**：`Target::Ip(IpAddr)`；RFC1928 风格 0x04（ss/trojan/anytls/socks5）、
   vless/vmess 0x03、tuic 0x02、hysteria2 用 `[v6]:port` 字符串；`marked_tcp_connect`
   支持 v6 sockaddr（`[u8;128]` 栈缓冲 + `copy_nonoverlapping`）；SOCKS5 入口接受 ATYP=6。
7. **DNS**：AAAA 应答与 A 一样发布到域位图（v6 目的地址也能被 `domain(...)` 规则命中）；
   上游解析/订阅拉取仍**优先 IPv4**（节点主机双栈时的旧坑，不回退）。
8. **默认策略**：v6 数据面默认开启；环境无 IPv6 时 loader 自动降级（listener 注册失败
   只记日志）、脚本侧 `--no-ipv6` 仍可显式关闭网卡 IPv6。

## 理由

- 16 字节统一元组让 v4/v6 共用全部下游机制（conn_state、redirect_track、LPM、
  offload 的 SockHash key），避免两套平行数据结构——这也正是上游的做法。
- 交付按 listener 拆分（key 2）而不是 dual-stack socket：`V6ONLY` + 独立 sockmap key
  与上游 C 的 `assign_listener` 语义一致，回程/自环判定不混淆。
- 控制对静态邻居属于"隐性契约"（架构文档 §3.2 早已把 v4-mapped 归一化列为重写必搬项），
  实测证明动态 NDP 在当前 datapath 下不可用。

## 与 dae 的差异（如实）

- **UDP v6 未做**：sockmap key 3 预留但未注册（透明 UDP6 socket）；IPv6 的 UDP
  流量（含 DNS over UDP6）不会进控制面；UDP relay 的目标仍是 `SocketAddr`（v4）。
- **ICMPv6 / 分片未处理**：按原路径放行（与 mini 的 v4 ICMP 边界一致，上游有 ICMP 回包改写）。
- 解析跳过扩展头但不做分片重组，超范围直接放行（非 tproxy 语义）。
- 控制对用 veth（上游新版用 netkit），静态邻居/路由配方等价。

## 后果

- **正面（实测）**：
  - `cargo test --release` **122/122**（新增 v6 编码/解析单测）；
  - lab `test-v6`：① client→landae v6→tproxy v6→relay→ss(ATYP=4)→v6 echo
    `wan-echo-ok`；② v6 direct 内核转发对照；③ `sockmap key 2, IPv6` 注册证据；
  - 无回归：`verify` **9/9**、DNS **6/6**、订阅组 **3/3**；规则对拍 `parity.sh` **3/3
    逐字节一致**（新增 `rules.v6.dae`：v6 前缀的 16B LPM 键与 dae Go 编译器一致）；
  - 真机网关（gwdae，原生 v6）：嗅探 `[2001::1]:443 → www.google.com`
    `RELAY（远端解析）` → **204**；字面量目标 `[2606:4700:4700::1111]:443` → **200**。
- **负面/代价**：eBPF 对象变大（解析分支 + 16B 元组）；调试一次典型 v6 故障需要
  同时看 TC 钩子、neigh 状态与 tproxy 监听（NDP 陷阱即由此暴露）。
- **风险**：v6 地址在规则/订阅/trace 输出里含 `:`，多处需引号/格式化（已在
  `config.rs` 自动处理、工具输出用 `[addr]:port`）。

## 验证方式（实测）

1. 单测：`MiniTuple` v4-mapped 生成、`encode_socks_addr`/`encode_v2ray_addr`/
   `encode_tuic_addr` 的 v6 形式、`Target` 解析 `[v6]:port`、SOCKS5 入口 ATYP=6。
   规则对拍：`lab/parity.sh`（含 `rules.v6.dae`）与 dae Go 编译器逐字节一致。
2. lab：`sudo lab/lab.sh v6-up && sudo lab/lab.sh test-v6`（3 断言，独立 Python
   ss 服务端走 ATYP=4；v6 目的由 `wan_echo.py` 双栈监听）。
3. 回归（P16 后全量复跑）：`verify` 9/9、`dns-up` 系 6/6、`subscribe-up` 组 3/3。
4. 真机：`gateway.sh up --subscribe /tmp/mini-dae-sub.url` 后浏览器/curl 实测
   （v6 域名嗅探链路 + v6 字面量链路，见「正面」）。

## 修订条件

做 UDP v6（sockmap key 3 + 透明 UDP6 socket + UDP relay 的 v6 目标）、ICMPv6 会话或
分片重组时，新写 ADR 扩展本条；届时 `Target` 的 UDP 目标才从 `SocketAddr` 放开为 `Target`。

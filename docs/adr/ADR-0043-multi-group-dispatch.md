# ADR-0043：多组分派（P19）——规则按组名选组 + 启动期 DNS 自我阻塞修复

- **状态**：已采纳（2026-10-04）
- **对应**：对标表缺口 #2 剩余项「按规则分派不同组（数据面 outbound id）」——最后一个结构性缺口
- **相关**：ADR-0011（K3 单代理槽边界）、ADR-0031（订阅/组）、ADR-0034/0035（DNS 上游）、
  ADR-0042（P18e）；NOTES §11.22/§11.34

## 背景

1. **单代理槽**：K3 起 `-> <组名>` 全部编译为 `OUTBOUND_PROXY=0x02`，组只在**拨号层**
   选择；规则无法把不同流量分给不同组（`group.rs` 头部边界、ADR-0031 遗留项）。
2. **数据面已具备条件**：规则 VM 把 outbound u8（`match_set.outbound`）写入
   `conn_state_map`（`MiniConnState.outbound`），用户态可用 raw lookup 回读——
   本阶段**eBPF 零改动**。
3. **真机启动断网（排查所得）**：重启后网关 `up` 必现全机断网。根因链：
   - 启动期 `do_reload`（initial）在 **eBPF 钩子已挂、DNS 监听线程尚未 spawn** 时
     调 `reload_group_members` 重拉订阅 → 解析 66 个节点域名 → 查询被自己的数据面
     拦截进透明 DNS socket → **无人应答**（线程还没起）→ getaddrinfo 超时，
     主线程卡死在启动流程 → 钩子空挂、无任何服务线程 = 断网；
   - 放大器：`build_upstream_set_core` 中**任一** `dns.upstream` 构造失败即整体放弃
     （`?` 冒泡），回退到初始 `8.8.8.8:53`（部分网络不可达）→ DNS 全域失败；
     `gateway.dae` 的 `quic://dns.alidns.com` 恰是这种域名条目；
   - 重启后 systemd-resolved 缓存为空 → 解析必失败 → 必现（此前有缓存时侥幸通过）。

## 决策

### 1. 组索引与编译（rules.rs / config.rs）

- 编码（对齐 dae）：`direct=0`、`block=1`、**用户组从 `GROUP_INDEX_BASE=2` 起**、
  `must_rules=0xFC`；上限 0xFB（250 组）。
- `resolve_outbound_id(名称→索引)`：built-in 直用；用户组按 config `group` 段**顺序**
  分配；**未定义组名回退 "proxy"（再退最小索引）**——保留 K3「其余组名映射到唯一组」
  的兼容行为（不静默直连）。
- `extract_routing`：已定义组名**直通**（不再改写为 proxy）；未定义仍改写为 proxy 并在
  `outbound_map` 标注。

### 2. 运行时分派（loader）

- `GROUP_SET: RwLock<GroupSet>`：全部组（索引 = outbound − 2）+ 默认组
  （`--group` > proxy > 第一个）；`build_groups` 一次建全部组（**空组也注册**，
  保索引稳定，订阅热更新可后续补成员）。
- 每个 relay 连接 / UDP 会话：按 5 元组 raw lookup `conn_state_map`
  （fd dup，`bpf_map_lookup_raw`；DNS 路径除外）→ `by_outbound` 选组；
  **查不到/非用户组（direct/block/must_rules/control）→ 默认组**（行为回退安全）。
- SIGHUP：逐组 `replace_members`（同名+tag 继承健康）；config 组集合变更时整体重建
  （不继承健康，日志明示）。

### 3. 启动期修复（本次一并收口）

- `do_reload(..., startup: bool)`：**startup 跳过订阅重拉**（`build_groups` 刚拉过；
  且避免自我阻塞——SIGHUP/状态面 reload 时 DNS 线程已在跑，正常热更新）。
- `build_upstream_set_core` **容错**：单个上游构造失败 → 跳过 + 告警，其余照常生效；
  legacy 取第一个**可用**上游；CLI `--dns-upstream` 显式给定时仍为硬错误。
- `gateway.dae`：`ali_quic` 改 `quic://223.5.5.5?sni=dns.alidns.com`（IP 字面量 + SNI，
  同 DoH 纪律，不依赖自身解析）。
- 健康探测并发 8 → **24**（66 节点首轮收敛 ~70s → ~20s）。
- `gateway.sh up` **启动自检 + 失败自动回滚**：等「组内任一成员探测成功 + wget 204」
  （默认最长 75s；`--wait <秒>`/`--no-wait`/`GATEWAY_WAIT_SECS`），超时自动
  `down` 恢复直连并报错——up 要么返回可用代理，要么回滚，绝不再把机器晾在断网态。

## 理由

- 用 `conn_state_map` 而非 `skb->mark`：mark 已被用户 `mark:` 规则与 fwmark 策略使用，
  且 cb 不落用户态；conn_state 是数据面既有事实来源（真相在数据面），回读零额外写入。
- 组索引静态可预测（config 顺序），编译与构建两边由同一 config 顺序生成，避免映射漂移。
- 启动期不重复拉订阅：启动时 `build_groups` 已拉取解析完成，initial reload 再拉一次
  纯属冗余，却是「自我阻塞」的唯一触发点——直接删掉比给 DNS 线程提前起更简单可靠。

## 后果

- 正面：规则可任选组（lab 双 ss 交叉日志为证）；三类断网根因（启动自我阻塞、
  单上游拖垮、启动窗口卡顿）闭环；网关启动具备「要么可用要么回滚」语义。
- 边界（如实）：
  - 组集合变更（config 编辑后 SIGHUP）重建，不继承健康；
  - conn_state 缺失（如极端的表项清理竞态）回退默认组；
  - UDP 分派依赖 conn_state（DNS 端口 53 走独立 DNS 路径，不参与）；
  - 未定义组名静默回退 proxy（无告警）；
  - 其它 config 若仍给出域名型上游，启动期该解析仍可能阻塞数秒
    （被拦截但 DNS 线程未起，失败后跳过、不再致命）；
    bootstrap_resolver 仍是后续项。

## 验证方式

- 单测：`cargo test --release` **176/176**（+2：组名→索引与未定义回退；坏上游跳过）。
- lab：`groups-up`/`test-groups`（8080→node-a、8082→node-b，双 ss 服务端日志交叉 +
  SIGHUP 复测）；`verify` 9/9；订阅/热更新/config/dnsroute 回归全过。
- 真机：启动自检通过（~20s）、`gateway.sh test` PASS（204 / 出口 IP / DNS ok）、
  SIGHUP「组 proxy 66 成员（继承 44 健康）」、66/66 alive、0 panic。
- 文档：本 ADR + `docs/parity-status.md` v2.0 + `architecture-decision.html` v2.28 +
  `mini-dae/NOTES.md` §11.34。

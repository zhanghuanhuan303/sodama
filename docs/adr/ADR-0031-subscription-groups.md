# ADR-0031：订阅 / 节点组 / 健康检查（多节点选路，P15）

- **状态**：已采纳（2026-10-04）
- **对应**：P15；补对标表缺口 #2「多节点·订阅·健康检查」
- **相关**：ADR-0004（Dialer 梯度）、ADR-0029（真网关）、ADR-0030（嗅探）、NOTES §11.22

## 背景

- 对标清点中「多节点/订阅/组」是最大缺口：此前只有单个 `--dialer URL`，
  配置里的 `subscription/node/group` 段只解析校验、不生效。
- dae 的形态：`subscription { tag: 'url' }` 拉取节点池 + `node { name: 'link' }` 内联节点
  + `group { name { filter: …; policy: … } }` 选路，带健康检查与延迟策略。

## 决策

1. **配置提取**（`config.rs`）：`subscriptions()` / `inline_nodes()` / `groups()`
   （filter 行、policy、组级 `tcp_check_url`/`check_interval`/`check_tolerance`）。
2. **订阅拉取**（`subscribe.rs`）：`file://`/裸路径/`http://`/`https://`；
   极小 HTTP 客户端（HTTP/1.0 GET、3 跳重定向、chunked 解码、webpki 根 TLS、
   `marked_tcp_connect` 防钩子自环、**优先 IPv4**）；正文 base64（标准/URL-safe/无 pad）
   或明文；逐行链接解析，**单行失败逐条报告、不中断**（REALITY 等边界外协议显式列出）。
3. **节点组**（`group.rs`）：
   - filter：`name(精确/keyword:/regex:)`、`subtag(...)`、函数 `!` 取反、
     行内 AND、多行 filter 之间 OR、空 filter = 全部；
   - policy：`min` / `min_moving_avg`（EMA 0.7/0.3）/ `min_avg10` / `random` / `fixed(i)`；
   - 健康检查：每成员经节点连接 check 目标（默认 `http://cp.cloudflare.com`，可被
     global/组级覆盖），成功计延迟（last/EMA/hist10），失败按 tolerance 标死；并发 8/批；
   - 拨号：按 policy+健康排序，**失败自动切换**（最多 3 名成员）；UDP 选择支持 UDP 的成员。
4. **CLI/配置**：`--subscribe <url>`（可重复，tag=cliN）/ `--group <name>`；
   活动组选择：`--group` > 组名 `proxy` > 唯一/第一个非空组；无 config 组时默认单组 `proxy`。
5. **可观测**：状态面新增 `group`（name/policy/members/alive/dials/failovers/probes/nodes 明细）；
   `lab/gateway.sh` 支持 `--subscribe/--group`。

## 理由

- 数据面仍把全部用户组映射到 proxy（K3 边界，ADR-0011）：拨号层选路可完全复用既有
  tproxy/relay 路径，零数据面改动；CLI/`listen-socks`/网关三种入口同时获得多节点能力。
- 订阅解析与链接解析复用 `outbound::parse`，边界外协议不静默吞掉（逐行报错）。

## 与 dae 的差异（如实）

- **按规则分派到不同组未做**：`pname/geo/sub()` 等规则、或 `-> group2` 的不同出口，
  需要数据面在重定向时报出 outbound id（dae 在 mark 中携带）；当前所有用户组同槽位。
- 订阅**只在启动时拉取**：无 `update_interval` 定时更新，SIGHUP 不重拉。
- gzip/br 压缩订阅显式报错（未引入解压依赖）；`add_latency` 注解、`region(...)`、
  `udp_check_dns`、tcp_check 多 URL 轮询未实现；check 判定为「拨号成功 + 任意响应」。

## 后果

- **正面（实测）**：
  - lab（2×ss + 本地订阅服务器）：拉取→组构建→首探成功；kill 节点 A 后 4s 内
    健康检查标死（interval 1s / tolerance 1），failover 后经 B 成功；
  - 真机（Arch/wlan0，订阅#2）：48×REALITY 逐行显式跳过 + **18×anytls 入组**，
    `alive 18/18`、`probes_ok 18 / fail 0`、EMA 最快 SG02 287ms；gstatic **204**、
    YouTube **200**、出口 IP=节点侧；`dials=5 failovers=0`。
- **负面/代价**：启动时同步拉取（15s 超时；失败则回退无组）；check 目标为公网
  （受限网络下需可经节点到达）；组内节点变化需重启/重载进程（同上边界）。
- **风险**：订阅 URL 含 token（只经 /tmp 文件与 argv，不入库）；畸形订阅逐行容错。

## 验证方式（实测）

1. 单测：filter 形式/OR/NOT、policy 解析、select_order（min 先快后慢、dead 最后）、
   Health tolerance/recovery、**probe dial 失败必须记失败**（回归 bug）、订阅解码
   （base64/URL-safe/明文）、HTTP 响应（plain/chunked/redirect/gzip 拒绝）、本地 HTTP 拉取；
   `cargo test --release` **121/121**。
2. lab：`sudo lab/lab.sh subscribe-up && sudo lab/lab.sh test-subscribe` 全 PASS
   （含状态面断言 group.members=2 / alive 2→1 与 failover 后探测）。
3. 真机订阅#2：`gateway.sh up --subscribe /tmp/mini-dae-sub.url`（见「正面」）。

## 修订条件

做按规则分派（数据面 outbound id）、订阅定时热更新、`add_latency`/`region`/多 check URL、
或把 health 判定升级为完整 HTTP 语义时，新写 ADR 扩展本条。

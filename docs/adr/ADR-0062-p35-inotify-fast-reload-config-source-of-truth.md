# ADR-0062：P35——inotify 毫秒级配置热驱动、订阅缓存 fast reload、配置即唯一事实来源、无 home 兜底

- **状态**：已采纳（2026-10-05）
- **对应**：用户决策「生效更优雅更快（Rust/内核级，类似 niri）」「配置文件作为唯一事实来源」「软路由没有 home 目录怎么办」
- **相关**：ADR-0060（P33 轮询式 `--watch-config`；本 ADR 取代其传输层）、ADR-0061（P34 多订阅顺序回退；fast reload 让「改顺序即切换」亚秒级）、ADR-0031/0042（订阅热更新语义）

## 背景

1. **P33 轮询的固有延迟**：`--watch-config <秒>` 是 sleep-poll（典型 10s），改配置最坏要等一个周期；
   且持续 `stat` 与「周期性噪声」不符合「事件驱动」的直觉（用户点名 niri 式即时生效）。
2. **reload 本身的开销**：`do_reload` 会重拉订阅（HTTPS + 解析），真实 66 节点订阅约 0.5–2s；
   「改一行订阅顺序」被迫重新走网络，切换不够优雅。
3. **配置不是唯一事实来源**：`dial_mode/dial_timeout/sniffing_timeout/watch_config/geodata_dir/
   log_file/status_socket` 只能由命令行注入（gateway.sh 每次拼一串参数），改一项就得改启动器；
   与「配置文件热驱动」的目标冲突。
4. **无 home 环境**：软路由/OpenWrt/容器里 `$HOME` 可能不存在或不可写，`~/.config/sodama/config.dae`
   的默认发现失效；且 `/etc/sodama/config.dae`（install/OpenWrt 的标准位置）无人问津。

## 决策

1. **inotify 事件驱动**（新模块 `loader/src/watch.rs`）：
   - 监听**父目录**（编辑器普遍「临时文件 + rename 覆盖」，文件级 watch 会被 rename 失效），
     事件掩码 `IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE_SELF|IN_MOVE_SELF`；
   - **事件名过滤**：只关心目标文件名（含 include 集合，随配置动态重挂），
     `/tmp` 这类繁忙目录的无关事件不触发；
   - **100ms 去抖**：一次保存产生的事件串合并成一次 reload；
   - `IN_Q_OVERFLOW`/目录自身被删改名 = 可疑事件，交给上层；
   - **正确性仍由 (mtime,size) 快照保证**；`CONFIG_WATCH_INTERVAL`（`--watch-config`/`watch_config`）
     退化为**慢速兜底扫描**间隔（网络文件系统不触发 inotify 时仍能发现变更）；
     inotify 初始化失败（权限/资源）自动降级为纯轮询并在日志/状态面如实标注。
2. **fast reload + 订阅节点缓存**：watch 线程发 `reload-fast`（状态面命令，与手动 `reload` 区分）：
   - `SUB_NODE_CACHE`（url → (抓取时刻, 节点)）在 `global { sub_cache_ttl }`（默认 60s）内直接复用，
     「改顺序/开关源」不再走网络（毫秒级生效）；命中日志 `订阅 X: 命中缓存（Ns 前抓取，N 节点）`；
   - **手动 `reload`/SIGHUP 始终强制重拉**（P18e 语义不变，`test-sub-reload` 等回归不受影响）。
3. **配置即唯一事实来源**：`global` 新增 `watch_config / sub_cache_ttl / log_file / status_socket /
   geodata_dir`（后四者此前仅 CLI）；启动时把 config 值回填到未显式给出的 CLI 项
   （CLI 仍可覆盖，定位为调试/一次性使用）。`gateway.sh` 不再注入 `--dial-timeout/--dial-mode/
   --sniffing-timeout-ms/--geodata-dir/--watch-config`（config 提供；rules 模式保持旧默认），
   真网关可 `sudo lab/gateway.sh up` 零行为参数启动。
4. **无 home 兜底**：默认配置候选（顺序即优先级）
   `$XDG_CONFIG_HOME/sodama/config.dae` → `~/.config/sodama/config.dae` → `/etc/sodama/config.dae`；
   `/etc` 候选额外要求**可读**（非 root 读到 640 root:root 时当作不存在，避免普通用户被系统文件挡死；
   root/软路由/OpenWrt 不受影响）。gateway.sh 同序查找（`GATEWAY_USER_CONFIG` 最高优先，
   sudo 下取 `SUDO_USER` 家目录）。

## 理由

- inotify 是 Linux 原生事件面：改文件到察觉是**事件驱动**（毫秒级），不需要为「快」而把轮询间隔调小
  （那会带来无谓的周期唤醒）；去抖 + 快照复核把「事件语义」（可能重复/丢失）与「正确性」解耦。
- fast reload 只改「怎么拿到节点」：节点缓存命中时 group 重建/规则编译/DNS 热切换都仍是完整语义，
  坏配置同样保留旧槽；把「改订阅顺序」的成本从网络往返降到内存操作，是「切换优雅」的关键。
- 把行为参数收进 config 后，网关运维只剩「改文件」一个动作（配合事件热驱动立即生效），
  也天然适配 systemd/OpenWrt（无命令行注入）；CLI 覆盖保留为调试逃生门。
- `/etc` 兜底与 install/OpenWrt 既有布局一致；可读性门槛解决了「普通用户被系统配置权限挡死」的陷阱。

## 后果

- **正面（实测，2026-10-05）**：
  - lab `sub-order-up`/`test-sub-order`（`watch_config: 30` 写进 config，证明走的是事件而非兜底扫描）：
    重排 sub1/sub2 顺序 → **2s 内** `active_tag` 双向切换（sub1→sub2→sub1），日志可见
    `检测到配置变更（inotify）` + `订阅…命中缓存`；kill 首源仍 4s 内故障切换；
  - 真网关：`sudo lab/gateway.sh up` **零行为参数**启动（config 提供订阅/拨号/嗅探/geodata/watch），
    66/66 alive、`active_tag=main`；实测在配置末尾追加注释 → **0.5s 内**完成
    `检测到配置变更（inotify）→ fast reload → 命中缓存（25s 前抓取）→ ok=true`；还原同样 0.5s；
  - 无 home：`env -u HOME -u XDG_CONFIG_HOME` root 运行 → 选中 `/etc/sodama/config.dae`；
    普通用户同样条件 → 不误选不可读的 `/etc`（回落为无默认配置）；
  - `cargo test` **261/261**（新增 watch 目录事件/过滤/rename 用例、默认配置候选顺序与无 home 兜底用例）；
  - `gateway.sh test` PASS、`config_watch` 状态面 `{transport: inotify, debounce_ms: 100, interval_secs: 10, sub_cache_ttl_secs: 60}`。
- **代价/边界**：
  - inotify 对网络文件系统（NFS/SMB/部分 FUSE）不可靠 → 依赖兜底扫描间隔（默认值即最大漏检窗口）；
  - fast reload 的节点缓存 TTL 内不会看到订阅站更新（默认 60s；`sub_cache_ttl: 0` 可关）；
  - `watch_config` 在启动时决定线程是否创建（运行中改 0 只是把兜底扫描拉长，线程常驻）；
  - `geodata_dir` 热更新不重扫（geodata 为 OnceLock 缓存，改目录需重启进程）。
- **文档化的边界**：命令行仍保留进程级参数（接口/netns/socket/log/ebpf 路径）与调试覆盖；
  「唯一事实来源」指**行为参数**。

## 验证方式

- `cargo test --release` **261/261**（含 `watch::tests::dir_watch_catches_write_and_ignores_other_names`、
  `default_config_candidates_order_and_no_home_fallback`）；
- lab：`sudo lab/lab.sh sub-order-up && sudo lab/lab.sh test-sub-order`（含 inotify 重排双向断言）；
- 真网关：`sudo lab/gateway.sh up`（零参数）→ `gateway.sh test` PASS；配置追加/还原注释
  各 0.5s 内完成 fast reload 且命中缓存（日志证据）；
- 无 home：`env -u HOME -u XDG_CONFIG_HOME` 分别以 root/普通用户运行 `--listen-socks` 观察默认配置选择。

## 相关

- 实现：`loader/src/watch.rs`（新增）、`loader/src/main.rs`（`config_watch_loop` 重写、`reload-fast`、
  `SUB_NODE_CACHE`、`default_config_candidates`、启动回填）、`loader/src/config.rs`（GLOBAL_KEYS）、
  `loader/src/subscribe.rs`（`ParsedNode: Clone`）；
- 部署：`lab/gateway.sh`（默认配置链 + 不再注入行为参数）、`lab/gateway.dae`（global 模板）、
  `lab/lab.sh`（sub-order 用例扩展）、`install/openwrt`（/etc/sodama 布局一致）。

# ADR-0060：P33——运行参数热更新与 `--watch-config` 配置热驱动

- **状态**：已采纳（2026-10-05）
- **对应**：用户决策「内核得可以命令行操控和配置文件热驱动」（无人值守/软路由场景）
- **相关**：ADR-0021（状态面/运维 CLI）、ADR-0042（SIGHUP 订阅热更新）、ADR-0043（启动期不做二次订阅重拉）

## 背景

1. P6 已支持 `SIGHUP` / `sodama reload` **整配置热重载**：规则走双 epoch 槽切换、DNS 上游热切换、
   订阅组整体替换，失败保留旧槽（ADR-0042/0043）。但**运行参数**（relay/udp idle、dial_timeout、
   max_conns、dial_mode、sniffing_timeout、sniff-punt）只在启动时决定：改配置文件中的这些键，
   要么重启进程，要么等下一次 SIGHUP——且 SIGHUP 原先也不会重读它们。
2. 变更有两个触发面：**手动**（CLI `sodama reload` / `systemctl reload`）与**自动**（文件一变即生效）。
   真网关/软路由是长驻服务，后者的价值在于「编辑器保存即生效」且不依赖调用方记住敲信号。
3. config `global` 段此前只把运维所需键列入白名单（`tproxy_port` 等），新增的运行参数键
   会触发 `validate` 的 unexpected key 诊断。

## 决策

1. **运行参数三源优先级**（启动与 reload 同口径）：**CLI 显式值 > config `global` 键 > 保持现值**。
   `global_value` 取值支持 `"300s"` / `"300"` 形式。reload/SIGHUP 成功分支调用
   `apply_runtime_params` 热更新，仅当值变化时打 `热更新: <key> <old> -> <new>` 日志。
2. **`--watch-config <秒>` 配置热驱动**（默认关，0=关）：专用线程每 N 秒对
   `--config`/`--rules` 及 `CONFIG_STATE` 记录的所有 include 文件做 (mtime, size) 快照，
   有变化即经状态面通道向主循环发 `reload`（等价自动 SIGHUP），同步等结果（60s 超时）并记日志；
   reload 后重新取快照，避免「reload 自身写回/触碰文件」造成循环触发。
3. **按 include 集合轮询而非 inotify**：include 文件集合本身会随配置变化而变，轮询快照对
   「编辑器原子替换（rename）/写一半」天然容错——一次失败的 reload 保留旧槽，下一次变更即重试。
   不引入新 crate、不依赖 inotify wd 失效重建逻辑。
4. **部署集成**：`lab/gateway.sh` 以 `GATEWAY_WATCH_CONFIG=<秒>` 启用（默认 0=关，显式开启才传参）；
   `lab/lab.sh` 以 `USE_WATCH_CONFIG=<秒>` 透传做回归。状态面新增
   `config_watch {enabled, interval_secs}`，`--help`/usage 同步说明。

## 理由

- 复用既有 reload 路径（槽切换、订阅热替换、DNS 热切换、失败回滚、`sticky::reset`），
  不引入第二条变更通道；watch 线程只负责「发现变更 + 转成控制命令」，语义与人工 SIGHUP 完全一致。
- 运行参数集中在少数 `AtomicU64/U8` + `DIAL_MODE` 上，热更新是单次原子写，数据面/relay
  在下一连接或下一轮循环即可读到，无需加锁。
- 轮询间隔即最大生效延迟；网关场景 10s、lab 测试 2s 都远小于人工操作时延，收益/成本比高。

## 后果

- **正面（实测，2026-10-05）**：
  - lab（`USE_CONFIG=/tmp/sodama-watch.dae USE_WATCH_CONFIG=2 USE_DIALER=direct`）：
    `status --json` 显示 `config_watch={enabled:true,interval_secs:2}`；
    改 `relay_idle_timeout: 60 → 7` 后 6s 内日志出现
    `config-watch: 检测到 1 个配置文件变更 → 自动 reload` → `热更新: relay_idle_timeout 60s -> 7s`
    → `自动 reload 完成（ok=true match_sets=3 error=null）`，状态面读数同步为 7；
  - 坏配置（`global { this is broken`）：reload `ok=false` 并回带解析诊断，**运行值保持 7**
    （不切槽、参数不变）；恢复合法配置后 `7 → 9` 热更新成功；
  - 真网关：`GATEWAY_WATCH_CONFIG=10` 启动，`status` 显示 `enabled/10s`，`gateway.sh test` PASS。
- **代价/边界**：每 N 秒对少量文件做 `stat`（微秒级）；自动 reload 失败只记日志、不自动重试
  （等下一次文件变更）；`--watch-config` 不替代订阅定时刷新（订阅仅在 reload/SIGHUP 时重拉）。

## 验证方式

- `cargo build --release` / `cargo test --release`（**257/257**）；
- lab 冒烟（自动 reload 生效/参数热更新/坏配置回滚/恢复），命令见 README「P33：配置热驱动」；
- 真网关回归：`gateway.sh test` PASS，看护在岗，状态面 `config_watch` 可见。

## 相关

- 实现：`loader/src/main.rs`（`CONFIG_WATCH_INTERVAL`、`config_watch_loop`、`apply_runtime_params`、
  `status_json.config_watch`、usage）、`loader/src/config.rs`（`GLOBAL_KEYS` 增运行参数键）；
- 部署/实验：`lab/gateway.sh`（`GATEWAY_WATCH_CONFIG`）、`lab/lab.sh`（`USE_WATCH_CONFIG`）。

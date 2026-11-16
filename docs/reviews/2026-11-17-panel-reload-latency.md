# 2026-11-17 · 面板保存配置耗时 59 秒复盘

**平台**：Arch Linux x86_64（`10.0.0.x`），systemd；引擎与面板同机运行
**引擎**：`sodama.service`，`--config /etc/sodama/config.dae --status-socket /run/sodama/status.sock`
**面板**：`sodama-panel.service`，`bind=127.0.0.1:8080`，root 运行，`actions=true`
**现象**：在面板里保存配置（写 `config.dae`）后要等很久才生效，偶尔报错；`sodama` 启动也慢。

**结论**：面板保存慢**不是引擎慢**（`status` 5 ms、`reload` 4 ms），而是**面板依赖 config-watch、而 config-watch 默认关闭**，每次保存都跑满 60 秒等待窗口后超时；文件已落盘但未生效，于是表现为「时好时坏」。启动慢则来自**数据面就绪前同步拉订阅**。

---

## 1. 面板保存：60 秒超时的完整链条

### 1.1 代码路径

面板保存引擎配置走 `apply_config_text`（`panel/backend/src/main.rs:1861`）：

```rust
let prev_at = current_reload_at(ctx, engine).await;       // 读 reload.at_sec
write_preserving(&engine.engine_config, text)?;           // 原地写文件
let reload_ok = wait_reload(ctx, engine, prev_at, 60).await;  // 等 60 秒
```

关键点：**它自己不调用 `sodama reload`**，完全依赖引擎的 config-watch（inotify）发现文件变化。对比规则集保存路径（`panel/backend/src/configapi.rs:1003`）是显式调用 `run_cmd(reload)` 的——两条路径行为不一致。

### 1.2 config-watch 实际是关闭的

```
"config_watch": {"debounce_ms":100, "enabled":false, "interval_secs":0, "transport":"poll"}
```

- 引擎默认值 `watch_config = "0"`（`sodama/loader/src/config.rs:2418`）；
- 该机 `config.dae` 的 `global` 段没有写 `watch_config`；
- 全量日志里 `config-watch` 出现 **0 次**。

于是每次保存：写盘 → 无任何重载 → `wait_reload` 轮询到 60 秒上限 → 返回 `reload_ok: null`，面板提示「引擎回执超时（可能仍在处理，请稍后刷新状态确认）」。

**文件在盘上，引擎没重载**——这就是「有时候生效、有时候不生效」的来源。

### 1.3 实测

| 测量 | 结果 |
|---|---|
| `sodama status --json` | **5 ms** |
| `sodama reload --socket ...` | **4 ms**，返回 `ok:true` |
| 面板 `GET /api/v1/status` | 5–7 ms |
| 面板 `GET /api/v1/config` | 0.3–0.6 ms |
| **面板保存 `config.dae`（修复前）** | **59.37 s**，`{"ok":true,...,"reload_ok":null}` |

### 1.4 修复与验收

```diff
 global {
     ...
     check_interval: 10s
+    watch_config: 10
 }
```

**只改配置不够**：watcher 线程只在启动时创建（`sodama/loader/src/main.rs:8143`），SIGHUP 热更新只修改兜底扫描间隔（`main.rs:7335`），不会新建线程。必须重启一次。

| | 修复前 | 修复后 |
|---|---|---|
| 保存耗时 | **59.37 s** | **0.61 s** ×2 |
| `reload_ok` | `null`（超时） | `true` |
| 引擎日志 | 无 `config-watch` 行 | `config-watch: 已启用（inotify 事件驱动 + 10s 兜底）` |

---

## 2. 启动慢：20 秒 → 3 秒

修复前的启动时间线（`/var/log/sodama.log`）：

| 时刻 | 事件 |
|---|---|
| 02:22:09 | 进程启动，写内核参数 |
| 02:22:10–11 | 订阅 2 连续两次 **HTTP 403** 重试 |
| **02:22:11–02:22:26** | **同步拉取订阅 1，阻塞 15 秒** |
| 02:22:26–27 | 粘滞 IP 固定（70+ 条） |
| 02:22:29 | 加载 eBPF、状态面就绪 |

订阅在**数据面就绪前同步拉取**，订阅服务器慢或返回 403 会直接拉长启动。删除那个 403 源后，重启实测：

```
ExecMainStartTimestamp = 02:54:59
ActiveEnterTimestamp   = 02:55:02   → 3 秒
```

建议（代码层）：启动时先用磁盘缓存填充节点组，订阅刷新放到后台，与周期性刷新复用同一条路径。

---

## 3. 关联的代码问题

| # | 位置 | 问题 | 建议 |
|---:|---|---|---|
| 1 | `panel/backend/src/main.rs:1861` `apply_config_text` | 只写文件、等 watch，不显式 reload | 写盘后显式 `run_cmd(reload)`（与规则集路径一致）；watch 只作加速 |
| 2 | 配置模板注释第 6 行 | 写「watch_config 默认开 inotify 热驱动」，实际默认 `0` | 改成「默认关闭；开启需 `watch_config: <秒>` 并重启」 |
| 3 | `sodama/loader/src/main.rs:7335` | 热更新只改扫描间隔，watcher 线程不会新建 | 检测到 `0 → 非 0` 且线程未启动时打印「需重启生效」告警 |

---

## 4. 现场

- 备份：`/etc/sodama/config.dae.bak-20261117-0300`
- 回滚：删除 `watch_config: 10` 后 `systemctl restart sodama`
- 服务状态：`active`，`config-watch` 已启用（inotify + 10 s 兜底）

## 5. 数据源

- 引擎状态：`sodama status --socket /run/sodama/status.sock --json`
- 面板日志：`journalctl -u sodama-panel`
- 引擎日志：`/var/log/sodama.log`
- 代码：`panel/backend/src/main.rs`、`panel/backend/src/configapi.rs`、`sodama/loader/src/main.rs`、`sodama/loader/src/config.rs`

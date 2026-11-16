# 2026-11-06 · 节点自动切换卡顿复盘

**平台**：OpenWrt x86_64，内核 `6.12.92`；引擎 `1.0.0-g76f6d25a677b`
**启动参数**：`--dial-mode domain --dial-timeout 15 --sniffing-timeout-ms 100`
**分组**：`group proxy { policy: min_moving_avg }`，88 成员，`subscription_failover` 默认开启
**现象**：节点自动切换过程中出现卡顿，不能无缝衔接；面板可见「当前节点」频繁变化。

**结论**：不是「切换动作」本身慢，而是三个问题叠加——**串行拨号 + 15 s 单次超时**、**健康状态无滞回导致高频抖动**、**旧连接不迁移**。当前未修改生产配置，本文只做记录与建议。

---

## 1. 代码机制（`sodama/loader/src/group.rs`）

### 1.1 每次新连接重新排序

`select_order()`（`group.rs:551`）在**每次拨号时**重新计算：

1. `alive` 优先，`dead` 一律最后；
2. 活动订阅层（rank 最小）优先；
3. 同层内按 policy 排序（`min_moving_avg` = EMA 延迟最低）；
4. 同延迟时优先 AES-GCM。

因此引擎没有「全局当前节点」这个状态——新连接各自选当时的最优节点。

### 1.2 串行重试，每次等满超时

`dial_tcp()`（`group.rs:666`）：

```rust
for &i in order.iter().take(3) {
    match inner.members[i].outbound.dial_tcp(target, timeout) {
        Ok(d) => return Ok(d),
        Err(e) => { note_dial(false); failovers += 1; }
    }
}
```

- 最多尝试 **3** 个成员，**串行**；
- 每次尝试使用完整的 `timeout`；
- 生产上 `timeout = 15 s`（引擎默认 **5 s**，被 UCI 与 config 同时覆盖成 15）；
- 最坏情况：`3 × 15 = 45 s` 才返回失败。

### 1.3 健康判定无滞回

```rust
fn note_probe(&mut self, ok: bool, ms: u64, tolerance: u32) {
    if ok {
        self.alive = true;          // 一次成功立刻复活
        self.fails = 0;
        ...
    } else {
        self.fails += 1;
        if self.fails > tolerance { // 默认 tolerance=1 → 连续 2 次失败标死
            self.alive = false;
        }
    }
}
```

- 默认 `check_tolerance = 1`（`config.rs:2387`）；
- `note_dial` 与 `note_probe` **共用同一个 `fails` 计数**：一次拨号失败会被下一次探测成功立刻抹掉；
- 没有「连续 N 次成功才复活」的滞回。

---

## 2. 现场数据（2026-11-06 02:39–02:40 CST）

| 指标 | 值 | 含义 |
|---|---|---|
| `alive`（20 秒内） | **37 → 40 → 59** | 20 多个节点在一轮探测内翻状态 |
| `probes_ok` / `probes_fail` | 37 345 / 6 391 | **失败率 17.1%** |
| `failovers` | 60 | 重试次数（相对 9 672 次拨号 ≈ 0.6%） |
| `dial_errors` | 26 | 集中在两个时间窗 |
| 存活节点最低 EMA | **1 007 ms** | 59 个存活节点**全部在 1 秒级** |
| 香港节点 EMA（22:14 采样） | 606–617 ms | 同样偏高 |
| 拨号失败聚集 | 22:31–22:32 两分钟 9 次 `connect timeout`；20:08–20:09 7 次 | 典型「坏节点被反复首选」 |

探测参数（均为默认值，未显式覆盖）：

| 参数 | 值 |
|---|---|
| `check_interval` | 30 s |
| `check_tolerance` | 1 |
| `probe_idle_cap` | 600 s（空闲时健康数据最多陈旧 10 分钟） |
| `tcp_check_url` | `http://cp.cloudflare.com` |
| `PROBE_BATCH_DEADLINE` | 30 s（`group.rs:199`） |

---

## 3. 根因分析

### 3.1 长超时 + 串行 = 惊群式卡顿

当排名第一的节点被黑洞（不拒绝、只丢包）时：

1. 第一条新连接等 **15 s**；
2. `note_dial(false)` 只加 1 次失败，`tolerance=1` 需要 **2 次** 才标死；
3. 这 30 s 内所有新连接都按同一顺序首选该节点，全部等 15 s；
4. 第二条失败后节点才被标死，后续连接才绕过。

日志中的 `connect timeout` 聚集（9 次/2 分钟）正是这个形态。

### 3.2 健康状态抖动放大「切换」观感

`alive` 在 20 秒内 37 → 59，说明：

- 上一轮探测有一批节点连续失败被标死；
- 下一轮一次成功又全部复活；
- 每次 `alive` 变化都会改变 `select_order()` 的排序，于是「当前最优节点」跟着跳。

`min_moving_avg` 进一步放大：59 个存活节点的 EMA 全在 **1 秒级**，彼此差异小于探测噪声，排序结果基本由抖动决定。

### 3.3 旧连接不迁移

已有 TCP 会话固定走建立时的节点；节点死亡后连接不会迁移，只能等 TCP 自身超时。这是 userspace relay 架构的边界，无法靠配置消除。

---

## 4. 建议

### 4.1 配置（不改代码）

| 项 | 现值 | 建议 | 效果 / 代价 |
|---|---:|---:|---|
| `dial_timeout` | 15 s | **3 s** | 最坏 45 s → 9 s；坏节点在 2 次失败（≤6 s）内被排除。**需重启服务** |
| `check_tolerance` | 1 | **2** | 减少抖动；真死节点多留一轮（~30 s）。可热重载 |
| `probe_idle_cap` | 600 s | 120 s（可选） | 空闲后健康数据更准；需先把 `tcp_check_url` 换成非 CF 目标，避免 2026-10-13 的额度事故重演 |

### 4.2 代码（clean-room 项目必须规避）

1. **对冲拨号（hedged dial）**：首选节点 200–300 ms 未建连就并行拨下一个，取先成功者。这是让失败切换真正无缝的唯一手段。
2. **健康状态滞回**：复活需连续 N 次成功；拨号失败与探测失败分开计数。
3. **节点级熔断**：失败后进入短冷却（如 30 s），冷却期内不参与排序。
4. **指标健全性检查**：若全体节点 EMA 同处一个数量级且方差极小，视为「指标失真」，降级为轮询/随机而不是按噪声排序。
5. **旧连接边界**：明确写入文档——节点死亡时长连接不可迁移，只能重连。

---

## 5. 当前状态

**未修改生产配置。** 本轮只做只读观测与代码分析。待确认后再执行 4.1 的两项改动。

## 6. 数据源

- 状态面：`/usr/bin/sodama status --socket /var/run/sodama.sock --json`（`group` 段）
- 运行参数：`/proc/5856/cmdline`、`uci show sodama`
- 日志：`/var/log/sodama.log`（`relay: dial ... connect timeout`）
- 代码：`sodama/loader/src/group.rs`、`sodama/loader/src/config.rs`

# ADR-0061：P34——多订阅按声明顺序回退（pacman 镜像风格）与默认配置目录

- **状态**：已采纳（2026-10-05）
- **对应**：用户决策「配置文件里能切换订阅，根据订阅的顺序，像 pacman 源；配置文件默认放 `~/.config/sodama`」
- **相关**：ADR-0031（订阅/节点组/健康检查）、ADR-0042（SIGHUP 订阅热更新）、ADR-0059/0060（P33 配置热驱动；本文档与其组合成「改文件即切换」）

## 背景

1. **多订阅语义空白**：config 允许声明多个 `subscription { tag: 'url' }`，但此前所有来源的节点
   混成一个池按 policy（延迟）挑——「订阅顺序」不表达任何优先级。用户要 pacman 镜像列表
   那样的语义：**列表有顺序，前面的源能用就不看后面的**。
2. **默认路径缺失**：订阅 URL 常以文件形式保存（如 `~/.config/sodama/sub2.url`），此前必须
   显式 `--subscribe <文件|URL>` / `--config <path>`；用户要求配置文件默认放 `~/.config/sodama`。
   且裸路径在 `config` 里此前按 CWD 解析，不便于 config 与 `subN.url` 同目录自包含。
3. **切换体验**：手动「切换订阅」不应是重启进程或敲信号；期望是编辑 config（调顺序/注释行）
   即生效——正好可复用 P33 的 `--watch-config` 自动 reload。

## 决策

1. **来源顺序 `rank`**：`ParsedNode.rank` / `Member.rank`（0 = 最高优先），顺序为
   **内联 `node`（0）→ CLI `--subscribe`（按给出顺序）→ config `subscription`（声明顺序）**
   （CLI 显式参数优先于配置文件，与其他 CLI 选项一致）。
2. **顺序回退选路**：`subscription_failover`（`global` 键，默认开）开启时，
   `GroupRuntime::select_order` 取 **alive 成员中 rank 最小者**为「活动层」：
   - 层内按既有 policy（min/min_moving_avg/min_avg10/random）排序；
   - 其余来源作兜底但排在活动层之后（层键在健康之后、延迟之前）；dead 一律最后；
   - `Policy::Fixed(k)` 是显式点名，不做分层；
   - 活动层全部被健康检查标死 → 下一来源自动成为活动层（拨号失败切换仍在 3 次尝试内跨层兜底）；
   - `subscription_failover: false` = 旧行为（全池按 policy）。
3. **可观测**：状态面 `group_json.active_tag`（活动层来源 tag）+ `GroupStats.active_rank`
   （rank+1 编码）；活动层变化在 `select_order` 与**健康探测周期**（一轮探测后）都会检查并记
   `组 <name>: 活动订阅 -> <tag>（顺序回退 rank N）`——空闲期也能看到切换。
4. **默认配置目录**：未显式给 `--config`/`--rules`（`--compile-dump` 对拍除外）且
   `$XDG_CONFIG_HOME/sodama/config.dae`（缺省 `~/.config/sodama/config.dae`）存在时自动使用；
   `--help`/日志明示。config 内**相对订阅路径按配置目录解析**（`resolve_sub_url`）；
   **订阅 URL 文件**（`file://` 或裸路径的内容是单行 http(s) URL，如 `sub2.url`）自动按该 URL
   抓取（一层间接，`url_file_target`；空/多行/非 URL 内容仍按订阅正文处理）。
5. **gateway.sh 集成**：未显式给 `--rules/--config` 时默认用 `~/.config/sodama/config.dae`
   （存在时；sudo 下取 `SUDO_USER` 家目录，`GATEWAY_USER_CONFIG` 可覆盖）；config 提供订阅时
   不再要求 `--node/--subscribe`。repo 的 `lab/gateway.dae` 仍是模板/无 home 配置时的回退。

## 理由

- pacman 镜像列表的语义正是「顺序即优先级，首个可用者胜」；对代理订阅而言，健康探测已存在，
  「可用」= alive（全部节点被标死才轮到下一源），无需新增探测机制，选择路径只多一个 rank 分层。
- 自动回退 + `--watch-config` 覆盖两种切换：**故障切换**（首源节点死）与**人工切换**
  （调顺序/注释行，保存即 reload），不需要新 CLI/状态面命令；`subscription_failover: false`
  保留旧池化行为，兼容多源混用场景。
- 相对路径按配置目录解析 + URL 文件间接收敛，让 `~/.config/sodama/` 成为自包含的运维单元
  （config + subN.url + blocklist），token 不与 config 混写。

## 后果

- **正面（实测，2026-10-05）**：
  - lab `sub-order-up`/`test-sub-order`（两个订阅源各 1 节点；`sub2` 用相对路径 URL 文件）：
    初始 `active_tag=sub1`；kill 第一源节点后 4s 内标死并切 `active_tag=sub2`，
    日志出现「活动订阅 -> sub2」，切换后端到端 204 成功；
  - 真网关以默认配置启动（`~/.config/sodama/config.dae`，含 `main: 'sub2.url'` 与
    `GATEWAY_WATCH_CONFIG=10`）：订阅 66/66 alive、`active_tag=main`、`config_watch=10s`、
    `gateway.sh test` PASS；
  - 单测 **259/259**（新增 rank 分层与 URL 文件识别两组用例）。
- **代价/边界**：顺序回退开启时，前一源存活即独占出口（即使后续源延迟更低）——按用户要求
  的 pacman 语义；需要混用时显式 `subscription_failover: false`。回退层不参与拨号（仅健康
  探测维持 alive），切源发生在活动层全死/失败切换窗口内（探测周期 + 容忍度决定时延）。
  默认配置只对「未给 --config/--rules」生效；`--compile-dump` 明确排除以保对拍可复现。
  systemd 场景 `HOME` 常为 `/`，建议 drop-in 显式 `--config`（见 `docs/deploy.md`）。

## 验证方式

- `cargo test --release` **259/259**；
- lab：`sudo lab/lab.sh sub-order-up && sudo lab/lab.sh test-sub-order`；
- 真网关：默认配置启动 + `lab/gateway.sh test` + `sodama status --json` 查
  `group.active_tag` / `group.subscription_failover` / `config_watch`；
- 回归：`lab.sh verify` 9/9、`test-subscribe`（单源路径不受影响）、P33 watch 冒烟。

## 相关

- 实现：`loader/src/group.rs`（`Member.rank`、`note_active_layer`、分层 `select_order`）、
  `loader/src/subscribe.rs`（`ParsedNode.rank`、`url_file_target`）、
  `loader/src/main.rs`（`resolve_sub_url`、`default_config_path`、`fetch_one_sub`、
  `group_json.active_tag`）、`loader/src/config.rs`（`GLOBAL_KEYS` 增 `subscription_failover`）；
- 部署：`lab/gateway.sh`（默认配置目录 / `RULES_GIVEN` / 无节点参数启动）、
  `lab/lab.sh`（`sub-order-up`/`test-sub-order`）、`lab/sub_server.py`（`/sub2`）。

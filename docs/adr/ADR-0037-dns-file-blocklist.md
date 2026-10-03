# ADR-0037：`qname(file:)` 自定义域名名单（mini 扩展）+ 分流命中观测

- **状态**：已采纳（2026-10-04）
- **对应**：P18c 的实用化扩展（真网关默认配置：国内域走本地明文 / 其余走 DoH / 名单拦截）
- **相关**：ADR-0036（P18c `dns.routing`）、NOTES §11.27/§11.28；
  与 dae 的对照：dae 用 geosite 数据集 + `qname(geosite:…)`，没有「用户文本名单文件」

## 背景

- 真网关切到 `--config`（DoH + `dns.routing`）后，用户提出两点需求：
  1. **按域名分流**：国内域走本地路由器明文 DNS（快、CDN 解析准），海外域走加密 DoH；
  2. **自定义拦截名单**：手工维护一份域名清单（而不是让用户去构建 v2ray `.dat`）。
- 分流用 dae 原生语法即可（`qname(geosite:cn) -> router` + fallback）；
  自定义名单在 dae 里没有对应的友好形态（geosite 数据集的构建链对个人用户过重）。

## 决策

1. **新键 `file:`**（`qname` 请求/应答两侧都可用，mini 扩展）：
   `qname(file: 'blocklist.txt') -> reject`。
   - 文件格式：每行一条；空行/`#` 注释忽略，支持行尾注释；
   - 默认 suffix 语义（`example.com` 匹配自身与子域）；行首可用
     `full:` / `keyword:` / `regex:` 覆盖类型（与列表内混合）；
   - 相对路径按**规则所在源文件**的目录解析（`Loc.file` → `cfg.files[..]`；
     对 `include` 合并进来的规则同样正确）；
   - 文件不存在/行无域名 = **编译期硬失败**（保持「不静默丢失」原则）；
     空名单合法（匹配零条，便于先建骨架再填）；
   - 编译日志/状态面 notes 记录 `qname(file: <解析后绝对路径>) → N 条域名`。
2. **命中观测**：`dns.routing.upstream_hits{tag|asis|legacy|reject: 次数}` 计数
   （请求阶段选路），状态面可见——用于验证分流策略真的按预期生效
   （真机：`{alidns: 92, router: 13}` = 海外走 DoH、国内走本地）。
3. **真网关默认配置**（`lab/gateway.dae`）：
   ```
   request {
       qname(geosite:category-ads-all) -> reject   # 数据集广告域
       qname(file: 'blocklist.txt') -> reject      # 用户自定义名单（随配置目录）
       qname(geosite:cn) -> router                 # 国内 → 本地路由器明文
       fallback: alidns                            # 其余 → DoH
   }
   ```
   随仓库附带 `lab/blocklist.txt`（只有注释与示例，默认不拦任何域）。

## 理由

- 域名名单是用户最长尾的需求；文本文件比 `.dat` 构建链低一个数量级的门槛，
  且与 `file:` 语义在配置里自洽（不引入新 section/新语法形态）。
- 分流与观测配合：没有 per-tag 命中计数时，「国内走本地」只能靠推断；
  有了 `upstream_hits` 才能作为验收证据（也便于排障：为什么某域走了 DoH）。
- 相对路径按声明文件解析，避免「cwd 不同行为不同」的隐蔽坑（lab 会话把配置
  复制到 /tmp 运行也验证了该语义）。

## 与 dae 的差异（如实）

- dae 没有 `qname(file:)`；等价能力需要自建 geosite `.dat` 或把域名写进配置。
  本键是**纯 mini 扩展**，只影响 mini 的配置方言；dae 原版配置不受影响
  （含 `file:` 的配置在 dae 上会报不认识的 key）。
- `upstream_hits` 为状态面扩展（dae 无对应字段）。

## 后果

- **正面（实测）**：
  - `cargo test --release` **143/143**（新增：名单解析——默认 suffix/`full:`/
    `keyword:`/`regex:`/行内注释/相对路径/缺失文件硬失败；lab `test-dnsroute`
    的 5 条请求规则矩阵含名单断言）；
  - lab：`fileblocked.test`/`sub.fileblocked.test`/`fullblocked.test` 空应答且
    不上行；`x.fullblocked.test`（full 不匹配子域）正常解析；`upstream_hits`
    断言 up1/up2 均命中；
  - 真机网关（订阅#2）：3 条请求规则（911 数据集域 + 6623 国内域 + 用户名单），
    `upstream_hits {alidns: 92, router: 13}`、105 查询 0 错误；
    **名单热加载实测**：追加 `example.com` → reload → `getent` 空应答
    （rejects+2）→ 移除 → reload → 立刻恢复解析。
- **负面/代价**：名单在每次编译（启动/reload）时整读；万行级文本 <1ms，
  无需缓存。文件变更需 `reload`（有意的显式动作）。
- **风险**：`regex:` 行由用户提供，非法正则在编译期硬失败（不静默）；
  空名单不会告警（notes 显示 0 条，属可见状态）。

## 验证方式（实测）

1. 单测：`cargo test --release`（`dnsroute::tests::qname_file_list`、
   `qname_file_missing_is_error`）。
2. lab：`sudo lab/lab.sh dnsroute-up && sudo lab/lab.sh test-dnsroute`。
3. 真机：`sudo lab/gateway.sh up --config lab/gateway.dae --geodata-dir /usr/share/v2ray
   --subscribe /tmp/mini-dae-sub.url`；`status` 看 `upstream_hits`；
   临时往 `lab/blocklist.txt` 加一行 + `reload` 验证拦截与恢复。

## 修订条件

- 名单需要通配符/正则批量导入、目录递归、或热更新（watch 文件）时；
- 需要 `ip(file:)` 名单（应答路由 CIDR 文件）时；
- 上游选择需要更细的路由（如按 ECS/客户端子网）时。

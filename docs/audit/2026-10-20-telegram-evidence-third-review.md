# TG 执行核验第三轮复审

线上复核时间：2026-10-20T06:21:07.660173+00:00。

## 结论与次要发现

本轮独立代码复审未确认新增 Critical / Important；发现两项次要限制，保留记录，不将其描述为已经修复。当前 VPS 未出现相关故障，本轮未修改或重新部署产品代码。

1. **set-only 的 inet 表支持缺口。** `lib/crowdsec_execution.py` 按来源地址族固定查询 `ip` / `ip6` 表；官方 v0.0.36 的 `initSetOnly → lookupTable` 按表名选表，允许使用 `inet`。因此仅配置 `inet` 表的合法 set-only 安装可能显示“查询不可用”。若将来支持该模式，还需考虑跨地址族同名表，不能简单增加一次 inet 回退。此 VPS 只读核对为普通模式，配置表仅分别属于 `ip` 与 `ip6`，没有跨地址族同名表，不受该支持缺口影响。
2. **nft 输出没有严格字节上限。** 现有实现限制共享 5 秒截止时间、最多 32 个匹配集合，并用 `-t` 排除集合元素，但 `capture_output` 没有硬输出字节限制。不能声称严格限制了子进程输出占用的内存；本轮未观察到相关故障。

官方选表语义参考：[v0.0.36 lookupTable](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/v0.0.36/pkg/nftables/nftables_context.go#L260)。

## 新运行的验证

- 218 项测试通过，零跳过：执行证据 21、机器人 162、Telegram 22、真实 Nginx/Lua 集成 13。已为系统 Python 子进程补齐测试环境中的 PyYAML 和项目 lib 导入路径，没有修改产品来绕过环境问题。
- `git diff --check` 通过；本地与线上 8 个机器人 Python 文件哈希一致。
- CrowdSec、Firewall Bouncer、TG Bot 均 active，NRestarts 均为 0；与前次部署后的 PID 相同。只有一个机器人进程，轮询 healthy；自前次启动以来未查到 traceback 或 Telegram API 错误。
- AppSec 故障策略仍为 `deny`；配置、凭据、官方通知模板和 3×3 菜单校验保持。
- 28 项 Web 安装资源校验有效；有效 Nginx 配置包含请求与日志 Lua 钩子，关键 Lua 文件宿主机与容器内容一致，无 satisfy-any 绕过配置。

| 样本 | Web 拒绝回执 | 防火墙配置集合 |
| --- | --- | --- |
| Alert #1982 | 17 条 | 查询时存在 |
| Alert #1983 | 本次未找到 | 查询时存在 |
| 192.0.2.199 | 未进行告警查询 | 未查到，表与集合内核身份复核通过 |

两个告警均读取 33 个日志尾部、5 个文件截尾、0 个读取错误，未达到文件/目录扫描数量上限。结果是当前查询快照。

本轮没有发送 Telegram 消息、重启服务、重载 Nginx，或修改防火墙规则及决策。首次真实 Telegram 发送与编辑验证见[首次验收](2026-10-20-telegram-evidence-copy.md)，不能当作本轮重测或真实用户点击证据。

集合成员状态不能证明实际丢包；本轮没有独立验证生产防火墙丢包，也未将“未找到 Web 回执”解释为漏防。真实 Nginx/Lua 集成测试运行于本地隔离环境，不替代生产防火墙验证。

机器可读结果见[本轮结果](2026-10-20-telegram-evidence-third-review-results.json)。

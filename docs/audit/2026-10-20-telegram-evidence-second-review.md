# TG 执行核验再次复审

部署后复核时间：2026-10-20T05:35:48.163707+00:00。

## 发现及处理

本轮采用另一独立代码复审视角，发现 1 项 Important 和 1 项 Minor，均已补失败回归测试、修复并更新 VPS。修正后的独立复审无未解决的 Critical/Important。

- **Important：set-only 集合选择。** 原代码同时接受精确名称和来源后缀；在共享表的 `set-only: true` 配置中，会将同名前缀的无关集合成员误报成已进入配置集合。官方 v0.0.36 的 [initSetOnly](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/v0.0.36/pkg/nftables/nftables_context.go#L132) 只采用精确配置名称。现 `set-only` 仅查询精确名，普通模式仅查询非空来源后缀集合。测试复现配置集合不含 IP、无关前缀集合含 IP 的误报并确认修复。此 VPS 使用普通模式，原有两个真实样本的判断未受该问题影响。
- **Minor：空名称默认值。** 官方允许空 `table` / `blacklists_ipv4/6` 并填入默认名称；原代码保守返回查询不可用。现空字符串及 null 使用官方默认值，覆盖 IPv4/IPv6；无效类型仍返回未知。

未改动拦截策略、防火墙规则或决策。

## 验证

218 项测试通过且无跳过：21 项执行证据、162 项机器人、22 项 Telegram 路由/回执/官方渲染、13 项真实 Nginx/Lua 集成测试。首次运行新增集成范围时，测试进程缺少项目 `lib` 导入路径；补齐测试环境 `PYTHONPATH` 后全部通过，没有为此修改产品代码。

真实 Nginx/Lua 测试在本地隔离环境发出 HTTP 请求，检查最终响应、业务上游计数与回执：LAPI/AppSec 拒绝和故障拒绝不访问业务上游并生成回执；放行及业务自身 403 不生成 Bouncer 拒绝回执。也覆盖客户端伪造标识、首次安装和旧安装升级。这些测试不冒充生产全入口验证。

VPS 只读检查确认 28 项资源清单有效，请求与日志钩子已进入有效 Nginx 配置，关键 Lua 文件的宿主机/容器内容一致；没有为此重载 Nginx。部署前隔离候选及部署后实际读取均确认：

| 样本 | Web 回执 | 配置集合 |
| --- | --- | --- |
| Alert #1982 | 17 条 | 存在 |
| Alert #1983 | 未找到记录 | 存在 |
| 192.0.2.199 | 不涉及告警查询 | 未查到，内核身份复核通过 |

两个告警仍是 33 个日志尾部、截尾 5、读取错误 0。结果仅代表查询快照。

本次备份：`/var/backups/crowdbastion/telegram-update-20261020T053458Z`，包含原文件、哈希及独立回滚脚本。仅核验模块内容改变，机器人新 PID 2061827，轮询 healthy；三个服务 active、NRestarts 均为 0，CrowdSec/Firewall Bouncer PID 保持。新启动后的日志无 traceback 或 Telegram API 错误，getMe 验证通过。上线文件哈希与候选一致，AppSec 仍为 `deny`，凭据、设置、防火墙配置、Web 配置、官方通知模板和 3×3 菜单保持。

本轮未重复向 Telegram 发送消息；已有真实发送/编辑证据见[首次验收](2026-10-20-telegram-evidence-copy.md)。实际用户回调和防火墙实际丢包仍未在本轮独立验证，不能由集合成员或 API 接受推断。

机器可读结果见[本轮结果](2026-10-20-telegram-evidence-second-review-results.json)。

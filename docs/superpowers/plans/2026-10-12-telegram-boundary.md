# Telegram 通知职责收敛实施计划

**Goal:** 保留配置、测试、检查、停用四项菜单，准确区分配置、路由、API 回执与真实攻击证据，并提供官方插件支持的可选批量通知。

**Architecture:** 延续现有 HTTP 通知通道与模板，在独立 `lib/crowdsec_telegram.py` 中实现只读诊断及官方插件测试回执校验。模板负责展示已有告警数据；封禁和拦截保持 CrowdSec/Bouncer 所有权。当前分支及工作区包含既有待提交修改，本次只修改 TG 相关内容，不提交或覆盖其他工作。

**Tech Stack:** Bash、Python 3/PyYAML、官方 CrowdSec 1.8.1 HTTP 插件。

**Spec:** 本会话已获用户批准的四项建议，以及 docs/2026-10-12-telegram-fix.md 的取证/迁移边界。

## 1. 消息语义与可选降噪

- [x] 在 tests/test_telegram.py 添加零 ID、无决策、模拟告警、批量多规则计数和长度回归，先运行确认失败。
- [x] lib/crowdsec_config.py 的 telegram_template：仅展示正数 ID；明确决策不证明 Bouncer 实际拦截；无决策和模拟告警分别说明。批量模板统计所有规则/总数，最多 3 条详细告警及每条 1 组取证；其余记录给出 cscli 查询提示。
- [x] telegram 配置操作增加 preserve/immediate/batch 模式：保留模式沿用现有时序，新配置默认即时；batch 使用 group_wait=30s、group_threshold=10。菜单配置可选模式，维持四项功能。
- [x] 官方插件真实单条/批量渲染与运行时分组验证，确认没有靠截断隐瞒规则或数量。

## 2. 只读状态与重复来源诊断

- [x] 添加 tests/test_telegram_status.py：实际有效路径和 local 顺序、未配置/无路由、重复通道、继续匹配 profile、动态目标保留、候选服务与 cron、凭据不输出、测试证据失效。
- [x] 新增 lib/crowdsec_telegram.py status：只读取配置、私有测试证据及候选服务/cron 信息，按正常/异常/尚未验证逐项报告。返回 1 为异常，2 为证据不足，0 为检查范围内全部验证。
- [x] 独立机器人只列出来源候选，无法证明名称不匹配的程序不存在，不卸载、不停止、不输出进程参数或 cron 内容。
- [x] check_telegram_settings 保留 crowdsec -t，使用新诊断替代混合的 notifications list；检查不发送消息。

## 3. 官方插件测试与 API 回执

- [x] 添加失败回归：HTTP 401/429、HTTP 200 且 ok=false、CLI 成功但没有通知、成功后配置变化使证据失效。
- [x] test 使用私有临时配置，将官方插件的测试目标指向临时 loopback 接收器，由接收器转发一次实际生成的测试消息至原 API 并检查 HTTP 和 JSON ok。不输出 URL/Token，不添加额外测试消息，不修改生产配置。
- [x] 成功保存 600 权限证据，仅含配置指纹、时间与回执结果；失败覆盖成功证据。明确“API 接受”不能证明使用者已读或真实攻击取证。
- [x] 测试运行后关闭接收器及清理临时配置；停用本工具通道后证据因指纹变化失效。

## 4. 验收与文档

- [x] 新增测试及 TG/运维工作流回归通过；官方 CrowdSec 单条和批量通知、AppSec 实际路径/UA 端到端通过。
- [x] Bash 语法、Python 编译、ShellCheck 和 diff 空白检查通过；运行完整 unittest 并记录结果。
- [x] 独立代码复审并修复有依据的问题。
- [x] readme.md、docs/optimization-boundary.md、TG 修复记录更新职责、状态码、批量展示范围、API 测试边界和 VPS 加载方法。

验收：TG 专项 29/29；完整回归 451 项（450 通过、1 可选跳过）；官方 1.8.1 单条及批量引擎验证通过。批量规则摘要最多 10 种，超出显示未展开数量；路径/UA 取证有明确展示限额。动态目标保留回归沿用 tests/test_telegram.py。独立复审发现的停用删除失败回滚已补齐，旧实现 RED / 修复 GREEN。未部署 VPS 或发送真实 TG 消息。

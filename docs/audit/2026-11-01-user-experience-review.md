# 2026-11-01 使用体验改动循环复审与修复

本轮按用户“循环复审加修复”的要求，在当前工作区增量检查使用体验改动及其维护、健康检查、中转验收接线。保留原有修改；不提交、推送或部署，不操作真实 VPS，不发送 Telegram 消息或真实攻击请求。

四轮先复现再修复，共处理七类问题。第五轮复核新实现、失败路径、既有接口及文档，并运行最终回归。当前会话没有独立 reviewer 工具；本报告记录当前会话的顺序自查，不代表独立审查结论。

## 发现与修复

| 轮次 | 问题与触发条件 | 修复后行为 |
| --- | --- | --- |
| 1 | 托管维护副本的 `lib` 缺失时，状态读取返回不可恢复错误，`--sync-runtime` 在安装前直接退出 | 区分源码不可读与部署副本不完整；后者提示修复并允许在确认后重新同步，仍受原维护锁及托管目录预检约束 |
| 1 | cron 文件存在，但任务指向其他命令或整行被注释，仍报告维护副本已同步 | 只解析、不执行 cron 文本；确认存在未注释的 root 维护命令且指向该副本后才允许同步，保留 cron 原文及执行时间 |
| 2 | 报告及配置写入仅检查直接父目录，未拒绝可被其他用户替换的上级目录；验收记录还会先创建子目录 | 写入或创建目录前检查整个已有目录链的类型、所有权、写权限和链接；直接父目录须归当前运行用户所有且无其他用户写权限，祖先允许可信 sticky 临时目录 |
| 2 | 配置根目录为悬空链接时被当作不存在；遍历遇到目录读取失败时静默跳过，仍生成部分指纹 | 悬空根链接报错，遍历错误向上传递；无法完整读取时不生成有效指纹或用它记录验收 |
| 3 | `API Key`、Cookie 及字段名被控制字符拆开的凭据可能留在导出报告中 | 先规范终端控制字符，再匹配凭据字段；支持带空格的 API Key、Cookie 和 Set-Cookie，继续整行隐藏凭据 |
| 3 | 使用 ST 终止的 OSC 终端超链接可能令清理表达式吞掉后续诊断 | 分别识别 BEL、ST 和未闭合控制码的边界；删除超链接控制码并保留可见标签及后续检查证据 |
| 4 | 维护代码指纹使用的 `Path.rglob` 也会静默跳过不可读目录，使不完整副本仍可能被比较 | 改用传播遍历错误的扫描，保留稳定排序、兼容入口链接和忽略 `__pycache__` 的行为；副本读取不完整时进入修复提示 |

实现主要位于 [UX Python helper](../../lib/crowdbastion_ux.py) 和 [Shell 维护入口](../../lib/user_experience.sh)，新增回归位于 [使用体验测试](../../tests/test_user_experience.py)。使用说明已同步到 [使用指南](../usage-guide.md)、[V2bX 指南](../v2bx-guide.md) 和 [中转模式](../relay-mode.md)。

## 修复前证据

七个新增测试方法先在旧实现上失败，再在修复后通过。子场景使用合成凭据，避免因测试值本身含有 `secret` 等敏感关键词而产生假通过。目录读取错误通过向 `os.scandir` 注入 `PermissionError` 复现，因为以 root 运行时 chmod 不能可靠模拟读取失败；该检查验证真实遍历器的错误处理行为。

- 第一轮：失败（本地归档：`2026-11-01-user-experience-review/round1-red.txt`）、通过（本地归档：`2026-11-01-user-experience-review/round1-green.txt`）。
- 第二轮：失败（本地归档：`2026-11-01-user-experience-review/round2-red.txt`）、通过（本地归档：`2026-11-01-user-experience-review/round2-green.txt`）。
- 第三轮：失败（本地归档：`2026-11-01-user-experience-review/round3-red.txt`）、通过（本地归档：`2026-11-01-user-experience-review/round3-green.txt`）。
- 第四轮：失败（本地归档：`2026-11-01-user-experience-review/round4-red.txt`）、通过（本地归档：`2026-11-01-user-experience-review/round4-green.txt`）。

证据使用 `.txt` 保存，避免仓库全局 `*.log` 忽略规则遗漏新增验收文件。

## 最终验证

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 最终全仓回归 | 1363 项：1274 通过、89 条件跳过、零失败；431.007 秒 | 完整输出（本地归档：`2026-11-01-user-experience-review/full.txt`） |
| 最终交互与接线组合 | 230 项全部通过；70.910 秒 | 完整输出（本地归档：`2026-11-01-user-experience-review/interaction.txt`） |
| 最终 UX 专项 | 28 项全部通过；2.761 秒，包含本轮新增的七个测试方法 | 完整输出（本地归档：`2026-11-01-user-experience-review/ux.txt`） |
| 隔离命令入口冒烟 | `main --sync-runtime` 修复、拒绝无关任务、取消三条路径通过；均保留 cron 原文 | 记录（本地归档：`2026-11-01-user-experience-review/cli-smoke.txt`） |
| 语法、编译和 ShellCheck | 18 个 Bash 语法、146 个 Python 无缓存编译、相关 8 个 Bash 的 warning 级 ShellCheck 通过 | 检查摘要（本地归档：`2026-11-01-user-experience-review/checks.txt`） |
| 帮助、文档和改动检查 | 完整帮助含四个 UX 参数；相关文档本地目标和最终 `git diff --check` 通过 | 帮助（本地归档：`2026-11-01-user-experience-review/help.txt`）、检查摘要（本地归档：`2026-11-01-user-experience-review/checks.txt`） |

跳过项取决于官方程序、真实 Nginx/Lua 和客机介质等可选条件。日志中的 Telegram 429/5xx、队列失败、迁移回退和异常状态是预期失败场景的输出，不代表操作了生产服务或发送了真实消息。所有测试结果以对应日志的 unittest 汇总为准。

最终全仓命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests:lib python3 -m unittest discover -s tests
```

交互及接线组合覆盖 `test_user_experience`、`test_relay_verification`、`test_firewall_runtime.StartupTransactions`、`test_guided_interaction`、`test_menu_convergence`、`test_node_guidance`、`test_health_summary`、`test_maintenance`、`test_hub_maintenance`。第四轮修改发生在较早全仓启动之后，因此重新运行最终全仓和组合测试；最终记录对应第四轮修复后的代码。

## 适用范围

以上均为本地源码、隔离文件系统、系统命令替身及交互回归。目录保护不代替操作系统的访问控制，脱敏仍要求分享前人工核对域名、路径与业务信息。cron 关联检查不证明 cron 服务正在运行；维护目录无法确认托管归属或权限不安全时仍会拒绝写入。

历史验收不改变健康结论；配置指纹不能捕获全部网络、内核规则或业务变化。真实防护仍须按目标入口、协议、地址族和新连接分别验收。第五轮在上述检查范围内未发现新的可复现问题，不构成全系统无缺陷或已取得独立复审的声明。

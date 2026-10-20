# Telegram 执行核验更新整理与发布前验证

2026-10-20，以 `main` 的 `8b45528` 为基线整理现有代码、回归测试和历史审计材料。本轮没有追加产品行为修改。

## 整理范围

- 通知、取证页和执行卡统一说明查询状态，区分已有 Web 拒绝记录、未找到记录和查询不可用。
- 日志查询分别统计截尾文件、读取错误和扫描上限。
- 防火墙只读查询遵循配置及 `.local` 覆盖，核对地址族开关、集合选择、默认名称及负结果的内核对象身份；集合同步不代表已验证实际丢包。
- 保留生产复核及三轮修正记录，各报告中的测试和部署数字属于当时快照。

历史材料按顺序参阅：[反馈解释与只读复核](2026-10-20-telegram-execution-interpretation.md)、[首次上线验收](2026-10-20-telegram-evidence-copy.md)、[首轮复审修正](2026-10-20-telegram-evidence-review.md)、[再次复审修正](2026-10-20-telegram-evidence-second-review.md)、[第三轮复审与已知限制](2026-10-20-telegram-evidence-third-review.md)。每篇均附对应机器可读结果。

## 本轮新运行的检查

| 检查 | 结果 |
| --- | --- |
| 全量 unittest | 1063 项，1024 通过、39 可选跳过、0 失败；289.424 秒 |
| 执行证据、执行卡、Telegram、Nginx/Lua 专项 | 74 项全部通过、无跳过；129.337 秒 |
| 全量跳过项目补验 | 专项覆盖其中 34 项，累计 1058 个不同用例通过；剩余 1 项官方 gost、4 项 ISO 媒体检查缺少可选依赖 |
| 独立只读代码复核 | 未发现新增 Critical / Important；两项已知次要限制保留记录 |
| 静态与材料检查 | 6 个改动 Python 文件 AST、主脚本 Bash 语法、差异空白、5 个新增 JSON 解析及改动文档相对链接通过；新增审计材料常见凭据模式扫描无匹配 |

全量测试使用项目 `.venv`，通过 `PYTHONPATH` 向系统 Python 子进程提供同一 PyYAML 依赖。专项另加入 `tests`、`lib` 导入路径，使用已有固定版本运行时，设置 `CROWDBASTION_TEST_NGINX`、`CROWDBASTION_TEST_LUA_PREFIX` 和 `CROWDSEC_TEST_RELEASE`。专项包含 21 项执行证据、7 项执行卡、22 项 Telegram、13 项 Web Bouncer 运行时及 11 项 Nginx 重载测试；部分用例与全量重复，不能将两轮总数直接相加。

本轮仅进行本地验证与仓库整理，没有重新部署 VPS 或发送 Telegram 消息。生产部署和 API 回执以历史验收报告为准。set-only 的 `inet` 表支持缺口及 nft 子进程输出缺少硬字节上限仍按第三轮复审记录保留；没有据本轮回归推断生产实际丢包。

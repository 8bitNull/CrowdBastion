# Telegram 分级降噪循环复审

在[初次验收](2026-10-29-telegram-noise-control.md)之后，完成四轮“复审 → 失败复现 → 修复 → 回归”，共复现并修复 12 个问题，新增 17 项回归与进程集成测试。收尾复核检查了告警排队、监测状态变化、失败重试与安装回滚之间的影响，未发现新的阻断问题。使用说明已更新至[分级降噪指南](../telegram-noise-control.md)。

本轮保留工作区原有机器人卡片改动。未部署 VPS，未发送真实 Telegram 消息，也未安装或变更宿主机服务；安装验证使用临时文件树和 systemctl 替身。

## 逐轮复现与修复

| 轮次 | 已复现的问题 | 修复后的专项结果 |
| --- | --- | --- |
| 1 | 可选机器人配置不是对象时阻断紧急发送；主配置不是对象时未受控报错；新故障未撤销旧待发恢复消息；退出监测后仍催办；更新未检查通知路由；首次安装回滚删除 unit 后无法 disable | 41 项，39 通过、2 项官方集成暂未配置而跳过 |
| 2 | 可选诊断文件写失败导致丢失 429 等待时间；健康采集过期仍显示正常；无法读取原服务状态却继续更新 | 48 项全部通过，已配置官方集成环境 |
| 3 | 未完成的本地 HTTP 请求无限创建处理线程 | 50 项全部通过 |
| 4 | 恢复监测后旧“停止监测”通知仍待发送；失败待重试消息被正常状态或另一条成功消息掩盖 | 52 项全部通过 |

原始失败及修复后结果：第 [1 轮失败](telegram-noise-review-2026-10-29/round1-before.txt)／[通过](telegram-noise-review-2026-10-29/round1-after.txt)、第 [2 轮失败](telegram-noise-review-2026-10-29/round2-before.txt)／[通过](telegram-noise-review-2026-10-29/round2-after.txt)、第 [3 轮失败](telegram-noise-review-2026-10-29/round3-before.txt)／[通过](telegram-noise-review-2026-10-29/round3-after.txt)、第 [4 轮失败](telegram-noise-review-2026-10-29/round4-before.txt)／[通过](telegram-noise-review-2026-10-29/round4-after.txt)。

关键行为变化：

- 配置读取限制为 64 KiB 内的普通 JSON 对象文件，拒绝符号链接和 FIFO；可选机器人配置异常只影响操作按钮。主通知配置异常会明确失败。
- 新确认的组件故障撤销旧待发恢复通知。组件退出监测时关闭事件并停止催办，发送“停止监测”；重新纳入监测则撤销尚未发出的范围退出通知。
- 429 的等待时间直接取自内存中的 API 结果，由 SQLite 队列持久化；可选诊断文件写入失败不会丢失限流信息。
- 状态同时检查发送与健康采集心跳，区分首次健康检查尚未完成和检查过期；失败队列项在成功或撤销前始终计入待重试。接收或采集线程停止时进程退出，交由 systemd 重启。
- 本地接收端最多同时处理 16 个请求，满载返回 HTTP 503；释放容量后可继续接收。
- 启用与更新均预先校验通知目标及 profiles 中的通道引用。无法确认原服务状态时停止修改；回滚先 disable 再恢复文件，并保留原来的 runtime 启用方式。

## 验证范围

最终[全仓回归](telegram-noise-review-2026-10-29/full.txt)：**1135 项，1069 通过、66 可选跳过、0 失败**，298.969 秒。66 项跳过不计入通过证据。Bash 语法、ShellCheck、Python 编译及 `git diff --check` 均通过，见[静态检查](telegram-noise-review-2026-10-29/static.txt)。归档文件的 [SHA256SUMS](telegram-noise-review-2026-10-29/SHA256SUMS) 用于核对证据内容。初次验收的 1118 项结果保留为历史，不作为本轮结果。

最终通知专项 52 项全部通过，包含 2 项官方 CrowdSec 1.8.1 插件集成和 1 项真实 worker 进程测试。现有机器人回归 [179 项全部通过](telegram-noise-review-2026-10-29/bot.txt)。各项数量与全仓覆盖重叠，不相加作为独立测试数。

真实进程测试启动实际通知 worker 与本地 TLS 模拟 Telegram API，使用临时证书信任而不关闭 HTTPS 证书验证，隔离节点用途文件和健康采集命令。实测首次 429 后停止并重启 worker，第二次请求仍至少等待 4 秒，然后完成紧急发送、事件确认、同一告警重放去重、组件故障及一次恢复通知；普通事件保留在汇总窗口内。[独立运行记录](telegram-noise-review-2026-10-29/runtime.txt)。

官方插件测试验证实际生成的有限字段投影、持久化接收和本地模拟 API 成功回执；不证明公网 Telegram 送达或使用者已读。profiles 校验仅确认通道引用，不执行任意过滤表达式。外部 API 成功后、SQLite 提交前崩溃仍可能重复发送，不保证严格恰好一次。

## 复现

安装 `tests/requirements.txt` 中依赖，并将 `CROWDSEC_TEST_RELEASE` 指向官方 CrowdSec 1.8.1 解压目录：

```bash
CROWDSEC_TEST_RELEASE=/path/to/crowdsec-v1.8.1 python3 -m unittest discover -s tests -p 'test_notify*.py'
CROWDSEC_TEST_RELEASE=/path/to/crowdsec-v1.8.1 python3 -m unittest discover -s tests
shellcheck -x -e SC2317,SC2329,SC2120,SC2119 crowdbastion.sh lib/notify.sh lib/custom_bot.sh
python3 -m py_compile lib/crowdsec_notify.py lib/crowdsec_notify_client.py lib/crowdsec_notify_setup.py lib/crowdsec_bot_api.py lib/crowdsec_telegram.py tests/test_notify_review.py tests/test_notify_runtime.py
git diff --check
```

真实进程 TLS 测试需要 `openssl`。本轮 PyYAML、官方 release 和 ShellCheck 使用 `/tmp/crowdbastion-notify-*` 下既有依赖；全仓测试配置与专项一致。失败及通过日志保留当时输出，包括故障注入产生的预期错误诊断。

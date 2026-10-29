# Telegram 分级降噪验收

新增独立 `crowdbastion-notify.service`：官方 HTTP 插件投递有限字段，SQLite 持久化去重、事件、确认、待发队列和重试；普通告警每小时静默汇总，未知规则首次提醒，持续防护组件故障紧急通知并在稳定恢复后通知一次。配置迁移可回滚，停用可恢复原即时/批量模式。使用入口与监测范围见 [分级降噪指南](../telegram-noise-control.md)。

本轮在已有未提交的机器人卡片改动之上增加通知接入，未撤销原有改动。未部署 VPS，未调用真实 Telegram 公网目标，未修改实际防火墙或生产服务。

## 验证结果

- 全仓 unittest：**1118 项，1052 通过、66 可选跳过、0 失败**，279.370 秒。设置 `CROWDSEC_TEST_RELEASE` 使用官方 CrowdSec **1.8.1**。
- 新增通知专项：**35 项**，涵盖普通汇总、不同 IP 合并、未知规则限频、模拟隔离、攻击量升级、紧急优先、冷却绕过、故障消抖、确认和恢复、重启去重、失败重试、429、入队期间新事件、目标隔离、本地认证、磁盘失败、安装回滚和机器人身份验证；包含 2 项官方插件集成检查。
- 现有 Telegram 专项 **32 项全部通过**；交互机器人专项 **179 项全部通过**。这些数量与整仓及新增专项有包含关系，不能相加作为独立覆盖数。
- Bash/Python 语法、ShellCheck、`git diff --check` 通过；生成的 systemd unit 经 `systemd-analyze --man=no verify` 校验通过。安装启停和回滚使用临时文件树与 systemctl 替身。
- 状态命令走只读分支，不占管理锁；主机服务状态不代表已核验公网站点实际拦截。

官方插件集成使用真实 `cscli` 和 `notification-http`，把实际生成的投影发送到 loopback 通知服务，再通过真实 Telegram 传输实现投递至本地模拟 API。核验原始请求日志不会转发、同一实际请求重放可去重、普通告警等待汇总，以及测试只有取得 API 成功回执才报告通过。该结果不证明公网 Telegram 送达或使用者已读。

## 首轮失败与修正

首轮全仓 1118 项有 1 项集成测试失败：重复调用 `cscli notifications test` 后，测试期望 1 条去重事件，实际为 2 条。隔离重现确认官方测试命令会在每次调用时将 `start_at` 改写为当前时间，跨秒调用实际生成不同时间的告警；同一数据库 ID 配合新时间保留为新事件符合预期。

集成测试改为重放官方插件实际发送的同一份请求，返回 `accepted=0`，随后全仓通过。未通过弱化生产去重标识掩盖测试差异。

## 复现

```bash
python3 -m pip install -r tests/requirements.txt
CROWDSEC_TEST_RELEASE=/path/to/crowdsec-v1.8.1 python3 -m unittest discover -s tests
CROWDSEC_TEST_RELEASE=/path/to/crowdsec-v1.8.1 python3 -m unittest discover -s tests -p 'test_notify*.py'
shellcheck -x -e SC2317,SC2329,SC2120,SC2119 crowdbastion.sh lib/notify.sh lib/custom_bot.sh
```

工作环境将 PyYAML 和 ShellCheck 装入临时目录，测试使用 `PYTHONPATH` 指向该依赖目录；未安装系统服务。66 项可选检查未作为本轮通过证据，真实 VPS 安装、公网 Telegram、业务 URL 探测与整机离线的外部监控均不在本轮验收范围内。

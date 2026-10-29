# Telegram 分级降噪 VPS 更新

2026-10-29 已通过 SSH 公钥登录 `179.255.121.95:53322`，完成分级通知部署和交互机器人更新。系统为 Debian 13，CrowdSec 为 `v1.8.1-debian-pragmatic-amd64-909b5157`。部署使用[四轮复审](2026-10-29-telegram-noise-review.md)后的工作区候选，全仓此前已验证 1135 项（1069 通过、66 跳过、0 失败）；本次没有改动产品源码。

## 已生效的行为

- 普通告警每小时静默汇总；未知规则首次提醒并合并同类事件。
- CrowdSec、LAPI、已配置防火墙 Bouncer 连续异常至少 60 秒后产生紧急通知，实际时限包含采样及检查耗时；连续正常至少 120 秒后通知恢复。
- 交互机器人支持紧急卡片“已知晓”和“查看详情”。原 Token、聊天、管理员及其他机器人配置保持，唯一配置字段变化为增加 `notification_callbacks=1`。
- 官方通知从直接发送切换到本地持久化队列。现有两个 profiles 仍只引用托管通道，两个旧通道文件没有被路由引用；没有修改 profiles 的过滤或封禁决策。

## 实际验证

| 检查 | 结果 |
| --- | --- |
| CrowdSec | active/enabled，加载新通知配置后 PID 为 2172093 |
| 防火墙 Bouncer | active/enabled，保持原 PID 1170352 |
| 交互机器人 | active/enabled，唯一 PID 2171787，更新后的实际轮询 healthy |
| 分级通知 | active/enabled，唯一 PID 2171912，发送与组件采集心跳正常 |
| 运行稳定性 | 上述服务 NRestarts 均为 0；本次启动期间未发现已检查的错误标记，核心 journal 错误行数为 0 |
| 本地接收端 | 仅监听 `127.0.0.1:7423`；未认证状态请求返回 HTTP 403 |
| Telegram API | 真实 `getMe` 成功，`getWebhookInfo` 确认没有 webhook；未创建第二个轮询消费者 |
| 实际告警接入 | 已接收 1 条真实普通告警，记录尚未报告，按小时汇总窗口保留；核验时没有发送失败记录 |
| 配置与文件 | 58 个发行包文件哈希核对通过；安装后的通知与机器人模块与候选一致；原核心、防火墙、节点用途及所核对管理配置哈希保持 |
| 私有权限 | 通知配置 600，通知代码和队列目录 700；systemd unit 校验通过 |

核验时待发消息 0、失败重试 0、未恢复紧急事件 0。普通告警尚未到汇总时间，因此记录已经入库，但尚未生成待发送消息。

本次没有额外发送 Telegram 测试消息，没有人为制造生产故障。真实告警接入、API 只读访问与服务运行已验证；尚未将本次生产的小时汇总送达、紧急消息送达或管理员点击按钮标为实测通过。相关策略的隔离测试见复审报告。

## 运行入口与恢复

新版本目录：`/opt/crowdbastion/releases/telegram-noise-20261029`。在 VPS 查询状态：

```bash
bash /opt/crowdbastion/releases/telegram-noise-20261029/crowdbastion.sh --telegram-smart-status
```

备份目录：`/var/backups/crowdbastion/telegram-noise-update-20261029T133222Z`。其中包含部署前文件、前后哈希清单、私有安装日志和 `rollback.py`。完整恢复本次部署前版本：

```bash
python3 /var/backups/crowdbastion/telegram-noise-update-20261029T133222Z/rollback.py
```

恢复脚本先核对备份和当前文件哈希，发现后续外部修改时拒绝覆盖；在管理锁内恢复原通知模式及机器人文件和配置，保留队列、机器人 offset 和操作状态。成功部署未触发回滚，本次未在生产执行上述恢复命令。

只停用分级并恢复原即时通知，可运行新目录下脚本的 `--telegram-smart-disable`。源码发行目录和备份保留在 VPS，便于后续管理。

[机器可读验证结果](2026-10-29-telegram-noise-vps-update-results.json)。记录不包含 Token、聊天 ID、私钥或完整告警内容。

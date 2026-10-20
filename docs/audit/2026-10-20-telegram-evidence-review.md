# TG 核验上线后的复审

复核时间：2026-10-20T05:25:45.648456+00:00。范围为本次核验文案、防火墙成员查询、测试和 VPS 上线状态。

后续另一独立视角发现并修正了 `set-only` 集合选择及空名称默认值兼容，详见[再次复审记录](2026-10-20-telegram-evidence-second-review.md)。本文及配套 JSON 保留本轮当时的快照。

## 发现及修复

发现两项 Important，均已补失败回归测试、修复并部署；独立复审确认没有未解决的 Critical/Important。

1. 地址族配置优先级不完全符合官方 Bouncer。原实现无条件优先处理 `disable_ipv6`，且遗漏 `disable_ipv4` 的默认值。根据[官方 v0.0.36 配置实现](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/v0.0.36/pkg/cfg/config.go#L173-L181)，应先采用显式 `nftables.<family>.enabled`，仅在未设置时取 `!disable_<family>`。现已修正两族并拒绝无效布尔配置。VPS 现有配置的查询结果未受该缺陷影响。
2. 负结果此前只复核集合名称，不能识别删除后同名重建。现同时比较查询前后的 table/set handle；身份变化或缺失均返回查询不可用，避免把未查询的新集合当成负证据。用受控 nft 命令响应复现并验证了集合重建、表重建及缺失身份的情况，未在生产上执行删除/重建操作。

区间元素查询另核对内核源码，支持查询区间内 IP。部分日志读取失败通过真实临时文件验证：仍明确显示抽样、读取错误与覆盖有限，不推断拦截成功或漏防。

## 验证

201 项测试通过：17 项执行证据、162 项机器人、22 项 Telegram 路由/回执/官方渲染；`git diff --check` 通过。

部署前隔离候选在 VPS 直接读取真实 nftables 和日志，部署后再次读取确认：

| 来源 | Web 回执 | 集合成员 |
| --- | --- | --- |
| Alert #1982 | 17 条拒绝记录 | 存在 |
| Alert #1983 | 本次未找到拒绝记录 | 存在 |
| 192.0.2.199 | 不查询 Web 告警 | 不存在，表/集合身份复核通过 |

两个告警均读取 33 个日志尾部，截尾 5 个文件、读取错误 0，未达到数量扫描上限。这是查询快照。

修正版部署备份：`/var/backups/crowdbastion/telegram-update-20261020T052459Z`，内含原文件、哈希清单及 `rollback.py`。实际仅核验模块内容发生改变；机器人重启后新 PID 为 2061335，单实例轮询 healthy。CrowdSec 和 Firewall Bouncer PID 保持，三个服务均 active，NRestarts 均为 0。新启动后的机器人日志无 traceback 或 Telegram API 错误，部署探针 getMe 成功、webhook 为空。

生产文件哈希与候选一致。AppSec 故障策略仍为 `deny`，机器人凭据与设置、防火墙配置、Web 配置、官方通知模板和 3×3 菜单保持。本轮未执行封禁、解封或防火墙规则变更。

真实 Telegram 发送/编辑测试证据见[首次上线验收](2026-10-20-telegram-evidence-copy.md)；本轮未重复发送消息，重新核对了服务实际轮询和真实数据读取。用户真实点击回调、消息已读及防火墙实际丢包仍不是本轮已验证内容。集合成员及 Web 回执的证据边界保持。

机器可读结果见[复审结果](2026-10-20-telegram-evidence-review-results.json)。

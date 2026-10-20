# 2026-10-19 第二台 VPS AppSec 故障策略更正

根据用户对故障放行的明确异议，已将生产 Web Bouncer 的 `APPSEC_FAILURE_ACTION` 从 `passthrough` 改为 **`deny`**，并于 2026-10-19 13:23:39 UTC 完成验收。此前保留放行属于可用性优先的选择，不是用户已明确选择的安全策略。本次结果取代[前次整改报告](2026-10-19-second-vps-remediation.md)中的 AppSec 故障策略；前次 JSON 保留为当时快照。

生产配置仅改变这一行，同时更新托管安装记录中 `bouncer.conf` 的资源摘要。现有 HTTP 403 回退修复、API 凭据、超时、原 WAF 钩子及其他策略字节均保留。经配置校验后平滑重载 OpenResty：主进程保持不变，新 worker 已接替旧 worker；CrowdSec 和 Firewall Bouncer 的服务状态及 PID 均保持不变。

故障测试复制当前生产配置和实际安装的 Lua 到独立 OpenResty 实例，只替换为环回测试端点和虚拟 API 凭据；保留所读取的故障策略及原有超时，使用可计数的业务后端。没有停止生产 AppSec。

| AppSec 状态 | 修改前 HTTP／业务后端命中 | 修改后 HTTP／业务后端命中 |
| --- | --- | --- |
| 拒绝连接 | 200／1 | 403／0 |
| 超时 | 200／1 | 403／0 |
| HTTP 503 | 200／1 | 403／0 |
| 健康响应 | 200／1 | 200／1 |

验收时配置回读为 `deny`，无 `.local` 覆盖，26 个托管资源完整，两个变更文件摘要匹配，`nginx -t` 通过，AppSec 环回端口可连接。故障测试前后的生产配置、Lua 和进程一致，临时实例均已清理。生产商店、结账、账户及商品页的顺序只读探测全部返回 200，响应约 0.51～1.25 秒。详细结果见[脱敏证据](2026-10-19-second-vps-appsec-failure-policy-evidence.json)。

代价是 AppSec 不可用或超时时，需要送检且进入该故障分支的正常请求也会返回 403。这次更正覆盖 AppSec 故障动作；LAPI 查询失败的既有放行行为没有调整，`APPSEC_DROP_UNREADABLE_BODY=false` 也保持原值，不能据此声称所有错误都拒绝。

VPS 备份目录：`/var/backups/crowdbastion/second-vps-remediation-20261019/appsec-failure-policy-20261019T132255Z/`。目录权限 0700，配置前后字节副本权限 0600，包含摘要、原文件元数据和受摘要保护的 `rollback.py`。回滚会恢复原 `passthrough` 策略；若完整撤销此前 AppSec 改动，应先回滚本次策略，再回滚 `appsec-status-20261019T125857Z`，因为二者修改同一托管安装记录。已核对回滚脚本语法，未在生产执行回滚演练。

# 2026-10-19 第三台 VPS 优化与故障拒绝验收

用户确认后，已在第三台 VPS 启用 **AppSec 与 LAPI 查询故障拒绝（403）**，补齐 6 个站点的日志采集，并将 3 套 Hub 更新任务合并为 1 套。部署开始于 **13:14:30 UTC**，复核采样开始于 **13:15:41 UTC**（服务器本地时间分别为 21:14、21:15 CST）。

原问题见[只读检查](2026-10-19-third-vps-readonly-acceptance.md)，本次结构化结果见[脱敏证据](2026-10-19-third-vps-remediation-evidence.json)。本次只操作已确认的第三台 VPS；公网地址、域名、密钥和原始命令输出保留在私有证据目录。

## 已完成变更

| 项目 | 结果 |
| --- | --- |
| AppSec 故障策略 | `APPSEC_FAILURE_ACTION=deny`，修正 v1.2.3 原拒绝分支携带 HTTP 200 的问题，故障拒绝返回 403 |
| LAPI 故障策略 | 新增独立 `LAPI_FAILURE_ACTION=deny`；live 查询失败时立即返回 403，后续 AppSec 或验证码处理不能覆盖该结果 |
| 日志覆盖 | 保留原有采集，新增 6 个站点的访问／错误日志，共 12 个文件；10 个站点的 20 个日志文件均恰好匹配一个采集入口 |
| 自动更新 | 保留本地时间每日 03:30 的托管 cron，具备锁、快照和失败回滚；注释 root 的重复更新行，停用并禁用系统 Hub timer |
| 安装记录 | 同步变更后的资源摘要，26 个受管资源及挂载／请求钩子核验通过，保留后续撤销检查能力 |

实际配置为 `MODE=live`、`FALLBACK_REMEDIATION=ban`、`CACHE_EXPIRATION=1`、`ALWAYS_SEND_TO_APPSEC=false`，没有 `bouncer.conf.local` 覆盖。仓库默认值仍为 `passthrough`，本次在目标服务器上明确选择两项 `deny`。

**可用性取舍：相应检查故障期间，正常访客也会被拒绝。** 已有允许缓存仍在剩余有效期内生效，当前配置的有效期为 1 秒；新增策略只处理 live 模式的查询错误，不处理 stream 后台同步故障，也不覆盖显式跳过检查的路径或内部子请求行为。

## 验证依据

故障注入使用该 VPS 的实际 OpenResty 二进制，启动独立环回监听的临时 Nginx 实例；未停止生产 LAPI／AppSec 或修改生产端点来模拟故障。8 个运行时测试方法全部通过，覆盖：

- AppSec 和 LAPI 分别连接失败、超时、返回 HTTP 错误时，`deny` 得到 403，业务后端请求计数为 0。
- `passthrough` 及未配置 LAPI 策略时保留兼容行为；两端健康且均设 `deny` 时正常放行。
- LAPI 拒绝立即终止，即使设置始终发送到 AppSec，也不会继续调用它；无效主配置策略会使启动失败。

旧 LAPI 实现在同组测试中出现 5 项断言失败；修正后通过。生产进程在隔离故障测试前后保持一致，临时运行目录已清理。工作区最终运行时 8 项和安装器 17 项测试通过；部署回滚另外验证了重载失败后的重试顺序及并发修改保护，共 3 项通过。补丁和部署脚本均经过独立审查。

生产发布前、CrowdSec 重载后及 OpenResty 重载后，均使用已安装 Bouncer 的真实密钥验证：LAPI 返回 200，AppSec 返回 200／`allow`。已建立的受保护 HTTPS 页面基线为 200，发布后仍为 200。10 个站点的本地 HTTPS HEAD 响应均与发布前一致：8 个 200、1 个 302、1 个 405；405 为原有 HEAD 行为，不代表该站点 GET 失败。

对全部 10 个站点发送正常 HTTP HEAD 后，访问日志均有成功解析指标；HTTP 301 仅用于验证日志采集，受保护链路另用 HTTPS 验证。错误日志已配置采集，未人为制造错误来增加计数。

`crowdsec -t`、`nginx -t` 均通过。CrowdSec、Firewall Bouncer、Fail2Ban 和 cron 均运行；前三项服务 PID 与部署前相同，所查 `NRestarts=0`。OpenResty master 保持不变，新 worker 已出现。当前 1 个既有本地 IPv4 ban 仍在本地来源 nftables 集合中。root 的两条无关 `@reboot` 防火墙恢复任务原样保留。

## CPU 结论

前轮 `codeg-server` 容器 CPU 约 361.24%；本次最终采样降至 **6.38%**，主机三个间隔样本空闲为 90%、87%、64%，负载为 1.12／0.94／1.72。当时的开发测试任务已经结束或回落，最初的高占用 Python 进程也已消失；没有足够证据把容器全部高占用归因于单个进程。

因此本次没有终止其他工作区任务或增加容器资源上限。短时回落不等于长期容量保证，持续限流应依据后续长期曲线和业务优先级决定。

## 备份与恢复

目标服务器备份目录：

```text
/var/backups/crowdbastion/third-vps-remediation-20261019T131430Z
```

目录权限为 0700，包含 5 个原文件、原 root crontab、保留的托管 cron 副本、变更清单、执行结果和恢复脚本。需要撤回本次变更时，在目标服务器以 root 执行：

```bash
python3 /var/backups/crowdbastion/third-vps-remediation-20261019T131430Z/rollback.py \
  --rollback /var/backups/crowdbastion/third-vps-remediation-20261019T131430Z
```

恢复脚本持有同一管理锁，并核对当前文件必须匹配本次变更前或变更后摘要；遇到后续人工修改会停止，保留冲突内容。先恢复 Web Bouncer 并重载 OpenResty，再恢复采集并重载 CrowdSec，最后恢复原调度。重载失败的标记会保留，下次重试仍会执行必要的重载。恢复调度会恢复原先的三套更新入口。

生产故障注入、CDN 真实 IP 全链路、独立外部来源的封禁／撤销、IPv6／UDP 和重启验收均未在本次执行。未主动构造攻击、增删决策或发送通知。SSH、管理端口暴露和其他服务器未纳入本轮修改。

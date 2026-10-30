# 第三台 VPS：仓库修复复核与部署追加复审

目标 `167.17.74.78:53322`。接续[上一轮部署](2026-10-30-vps3-cycle-repair.md)，本轮先复核仓库修复及回归，再检查现场部署、修复新增发现，最后追加一次运行复查。

## 仓库修复复核

复核最近提交 `ab0af70` 及工作区已有的后续修复，重点检查 Nginx 重载证据、真实 IP 应用和诊断恢复、Web Bouncer 安装/撤销/升级的回滚，以及通知事务、远端预检和健康摘要。未新增产品源码修改，未覆盖工作区已有改动，未创建提交。

远端日常目录 `/root/crowdsec-1key` 和发行目录 `/opt/crowdbastion/releases/review-20261030` 的 **56 个源码文件均与当前仓库逐项 SHA256 一致**，因此没有重复部署相同代码。

使用项目虚拟环境和 `PYTHONPATH` 运行全仓测试，发现 **1169 项**：首次 1077 通过、3 失败、89 跳过，耗时 357.065 秒。三项失败均来自本地缺少 `journalctl` 可执行文件；补齐本地依赖后，原三项逐项复测全部通过，累计 **1080 通过、89 跳过、无未解决失败**。补齐依赖后没有重复运行整个测试集，不将第一次结果写成完整通过。最初用系统 Python 的启动尝试还缺少 PyYAML，未作为有效回归结果。

89 项跳过包括固定官方归档相关 45 项、Lua Nginx 18 项、官方通知插件 16 项、官方回执 5 项、gost 1 项、pycdlib 4 项。本机补齐的工具只用于本地验证，未在 VPS 安装软件包。132 个 Python 文件 AST、17 个 Bash 脚本语法、ShellCheck warning/error（沿用回调排除项）均通过。

## 新发现：旧开机快照会覆盖动态防火墙

root crontab 存在以下两条无启动顺序约束的任务：

```cron
@reboot iptables-restore < /etc/iptables/rules.v4
@reboot ip6tables-restore < /etc/iptables/rules.v6
```

两份快照创建于 2026-10-05，仅包含 ACCEPT 基础链和 TCP/UDP 53322 放行，缺少当前的 CrowdSec、Docker 和 1Panel 链。默认 restore 会清空 filter 表；如果 cron 在动态规则创建后执行，就可能删除防护跳转和 Docker 转发规则。已有 Bouncer `After=docker.service` 无法约束这个 cron 任务。

在独立网络命名空间分别建立 IPv4/IPv6 的 `CROWDSEC_CHAIN`、`DOCKER-USER` 及入口跳转，加载对应旧快照后，两类链及跳转均消失，确认覆盖风险。此复现没有向生产网络发送流量，也没有在生产命名空间恢复快照。

备份后仅将上述两条 root cron 任务注释，保留原命令和停用原因。其他 cron 行及两份旧快照内容保持。修复前后线上 IPv4/IPv6 规则内容和顺序一致；核心、Bouncer、Docker 进程及启动时间均保持。网络命名空间已清理。同步在[使用指南](../usage-guide.md)补充排查说明。

## 部署核验与第二轮复查

| 检查 | 结果 |
| --- | --- |
| CrowdSec、OpenResty 配置 | 通过 |
| CrowdSec、Firewall Bouncer、Docker | active，未重启 |
| systemd failed units | 0 |
| 有效封禁覆盖 | 首轮 16478 条应生效网络，内核缺失 0；追加复查见 JSON 动态快照 |
| IPv4/IPv6 INPUT、FORWARD、DOCKER-USER | CrowdSec 跳转仍在首位，线上规则保持 |
| Web Bouncer 托管资源及有效钩子 | 校验通过 |
| Bouncer 凭据及 AppSec/LAPI 策略 | 与上一轮修改前摘要一致 |
| 三个抽查站点源站 | aomway.com、shop.node2api.com、www.zhishangsheng.com 均 200 |
| 三站公网 HTTPS | 系统 CA 校验通过，均 200 |
| 既有容器 | 均运行，已有健康检查的容器仍 healthy |
| 废弃开机任务 | 第二轮仍停用，快照文件未变化 |
| 临时网络命名空间及隔离容器 | 已清理 |

使用现场相同镜像 ID 启动独立 OpenResty 容器，禁用网络，不挂载业务目录，实测三种重载路径：正常重载有新 worker 和 master 日志证据；`nginx -t` 通过但 Lua 初始化主动失败时，确认函数返回失败并保留原 worker（整次调用约 10.309 秒）；移除失败条件后重载确认成功。测试容器随后删除，生产 OpenResty 未重载。

修复后健康检查仍为 **2（运行检查通过，实际拦截待验证）**。第二轮再次确认线上规则、服务身份、封禁覆盖、任务停用和清理结果，未发现新的已确认异常。

## 证据、恢复及边界

私有备份目录：`/var/backups/crowdbastion/vps3-rereview-20261030/`，目录 0700、文件 0600。保存原 root crontab、两份旧快照、线上规则及服务状态、隔离复现结果和本轮验证脚本。原 crontab 在 `crontab.before`，用于人工核对恢复；完整恢复会重新启用本轮确认有覆盖风险的任务，不能作为常规维护操作。

本轮没有重启宿主机或 Docker 做冷启动演练；修复结论来自已复现的规则覆盖行为、任务停用及运行复查。源站检查使用 loopback 和 `-k`，公网 HTTPS 检查使用正常证书校验；两者均为正常页面可用性检查，不代表各站点公网攻击阻断验收。没有发送 Telegram 消息或新增生产封禁决策。

上一轮已记录的三份 `vpatch-CVE-2026-96652/96655/96656` 不在本地 Hub 索引中的提示继续保留，未擅自删除规则，也未将其声明为已验证的官方规则。此前防火墙续封/到期流量结果仍属上一轮证据，本轮没有重新执行该组流量实验。

证据：[测试汇总](2026-10-30-vps3-rereview/regression-summary.json)、[首次完整回归](2026-10-30-vps3-rereview/full-regression-initial.txt)、[环境补齐后的复测](2026-10-30-vps3-rereview/environment-rerun.txt)、[隔离复现](2026-10-30-vps3-rereview/reproduction.json)、[修复结果](2026-10-30-vps3-rereview/startup-fix.json)、[部署核验](2026-10-30-vps3-rereview/verification-final.json)、[第二轮复查](2026-10-30-vps3-rereview/second-review.json)。同目录 `SHA256SUMS` 记录报告及证据摘要。

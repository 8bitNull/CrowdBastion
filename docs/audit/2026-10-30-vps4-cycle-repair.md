# 第四台 VPS：部署复审、修复与流量验收

目标 `216.238.52.230:53322`，root 专用公钥认证。现场 Debian 12、CrowdSec 1.8.1、Firewall Bouncer 0.0.36、Alpine Nginx、gost、OpenList 和 V2bX。本轮先读取现场，修复已确认问题，再作完整运行复查，未创建 git 提交。

## 发现与修复

### nftables 续封失效

原 Firewall Bouncer 使用原生 nftables，IPv4/IPv6 均有 input、forward hook。临时命名空间中，使用专用测试来源分别封禁 40 秒再续期至 120 秒；原期限过去后，决策仍有效约 82 秒，但 IPv4/IPv6 × TCP/UDP × 主机输入/转发的 **8 条测试流均已恢复可达**，确认续封缺陷。`flow-before.json` 的 `passed: true` 表示成功复现原故障。

安装 `ipset` 及所需依赖，以新建 `.yaml.local` 覆盖设置 `mode: iptables` 和 `iptables_chains: [INPUT, FORWARD, DOCKER-USER]`。基础 Bouncer YAML、API 凭据及 CrowdSec 配置文件字节保持。新增 systemd `After=docker.service`。iptables 使用 nf_tables 兼容层，与原生 nftables Bouncer 后端不同。

切换前准备有效封禁快照保护、当前 SSH 来源保护及独立 8 分钟回退定时器。一次迁移成功，新建独立 SSH 连接成功。迁移后实测：

| 项目 | 结果 |
| --- | --- |
| IPv4/IPv6、TCP/UDP、输入/转发共 8 条测试流 | 新封禁均阻断 |
| 续封越过原到期时间 | 全部保持阻断 |
| 删除测试决策 | 全部恢复 |
| 自然到期 | 全部恢复 |
| 不封禁的对照来源 | 全程可达 |
| 最终应覆盖网络（决策剩余超过 15 秒） | 16179 条，内核缺失 0 |
| 既有业务规则 | 内容和顺序保持，三个入口新增 CrowdSec 首位跳转 |

流量通过且配置、覆盖复查完成后提交迁移，停止回退定时器并移除临时保护。测试决策、命名空间、网卡、18080 监听、临时规则及清理定时器均已清理。

### 旧开机恢复会覆盖当前规则

root crontab 存在 `@reboot iptables-restore < /etc/iptables/rules.v4`。快照创建于 2026-04-19，缺少当前 CrowdSec、Docker 转发链，且包含过期 Docker bridge 引用。在独立命名空间恢复该快照，确认会删除新建的 CrowdSec 和 Docker filter 路径。

备份后仅注释该条任务，保留旧快照；证书续期及 Nginx logrotate 两条任务保持。没有将旧快照加载到生产。原有在线 raw、nat、filter 规则保持，包括已有旧 bridge 引用，没有将历史规则批量改写。

### sysctl 服务失败

`systemd-sysctl` 原处于 failed 状态。现有 `/etc/sysctl.d/99-network-optimize.conf` 配置 `net.core.netdev_budget_usecs = 6000`，内核拒绝该设置；现场有效值为 8000。将这一个配置值改为 8000 后重新加载，服务变为 `active (exited)`，没有 failed unit。

**检查过程中的命令错误：** 我最初将 `--dry-run` 放在 `--system` 后。此处 procps 在处理 `--system` 时已加载配置，导致原本计划的只读检查实际重载了既有 sysctl 参数。随后停止此用法，使用正确顺序 `sysctl --dry-run --system` 核对，并向用户说明。没有完整的操作前运行时 sysctl 快照，因此不能宣称全部内核参数与初始状态一致；最终配置文件仅改动上述一个值，正常业务进程及可用性复查通过。修复前文件已保存在完整备份中。

### HTTP 代理端口冲突

正常运行的 `gost` 已占用宿主机 51080；host 网络的 `gost-http-proxy` 也尝试监听 51080，日志持续报 `bind: address already in use`，现场重启计数已达 40904。

向用户提供“保留现有 51080，停用冲突容器”和“HTTP 改到 51081”选项，等待期间继续独立检查。未收到选择后按推荐项保留原业务：停止冲突容器，将其运行时和 Compose `restart` 改为 `no`，增加 `disabled-port-conflict` profile，避免默认 Compose 操作再次启动冲突服务。原命令、账号密码和端口保持；正常 gost 没有重启。该操作消除反复重启，**不表示 HTTP 代理已经恢复提供服务**；如需 HTTP 服务，应明确分配空闲端口或安排替换原服务。

## 管理脚本与最终复查

现场原本没有本工具日常管理目录。本轮将当前仓库完整部署到 `/root/crowdsec-1key`，发行副本为 `/opt/crowdbastion/releases/review-20261030-vps4`，保留兼容入口链接。两处 **56 个源码文件均与本地 SHA256 一致**。首次部署遇到远端旧 Python 不支持 `tarfile` 的 `filter` 参数，尚未解压即退出；随后逐项校验归档成员及唯一兼容链接后完成部署。

本地相关回归 **74/74 通过**，覆盖防火墙启动检查、中转及健康摘要；远端源码 Python AST、Bash 语法和摘要核对通过。沿用上一轮已完成的全仓回归证据，本轮没有再次运行全仓测试集，未新增产品源码改动。

| 最终复查 | 结果 |
| --- | --- |
| CrowdSec / Nginx 配置 | 通过 |
| CrowdSec、Firewall Bouncer、Docker、V2bX、sysctl | active |
| systemd failed units | 0 |
| CrowdSec、Docker、V2bX | PID、启动时间及重启次数保持 |
| Nginx、正常 gost、OpenList | 继续运行，PID 及启动时间保持 |
| 冲突 HTTP 代理 | 已停止，自动重启及默认 Compose 启动均禁用 |
| 原核心 / 基础 Bouncer 配置与凭据 | 字节保持 |
| 网站检查 / V2bX 诊断 | 均退出 2：运行检查通过，实际拦截待验证 |
| down-us1.354555.xyz 源站及公网 HTTPS | 均 200 |
| 临时资源 | 全部清理 |

只为迁移重启 Firewall Bouncer，以及为修复重载 sysctl；没有重启 CrowdSec、Docker、Nginx 或 V2bX。既有用途偏好保持未设置，分别执行网站和落地诊断，没有启用新的 Telegram、V2bX 观察或告警服务。

## 恢复资料与验证边界

远端私有备份目录 `/var/backups/crowdbastion/vps4-cycle-20261030/`，目录 0700。包含 `before.tar.gz`、原 cron、原业务 Compose、规则及服务快照、受保护文件摘要、迁移配置和所有验证脚本。含凭据资料仅保留在 VPS，未下载到仓库。新建 Bouncer `.local` 和 systemd drop-in 的原状态为不存在，迁移脚本记录其恢复方式。

自动回退适用于未提交事务；本轮迁移已提交并解除定时器，脚本的常规 `rollback` 入口此后不会覆盖已提交状态。需要恢复时应人工核对完整备份及配置漂移，旧原生 nftables 后端有已复现缺陷，不能作为常规维护回退目标。

短暂 SSH 握手超时发生在只读检查阶段，恢复后建立复用连接，迁移后另建独立连接验证通过。没有修改 sshd 配置。

未重启宿主机、重建业务容器或演练冷启动。源站请求通过 loopback、`--resolve` 和 `-k`，公网 HTTPS 请求正常校验证书。公网正常页面可用不等于站点攻击拦截验收。现有 Alpine Nginx 不因本轮管理脚本部署自动具备 Lua Web Bouncer/AppSec；未更换镜像或擅自安装网站拦截组件。默认站点的原有代理信任范围及所有站点真实访客 IP 仍需逐项核验。本地命名空间的防火墙流量实测不代表 CDN、真实 Docker 业务端口或 V2bX 协议流量已完成外部攻击验收。

证据：[最终验证](2026-10-30-vps4-cycle-repair/verification-final.json)、[修复前复现](2026-10-30-vps4-cycle-repair/flow-before.json)、[修复后流量](2026-10-30-vps4-cycle-repair/flow-after.json)、[旧快照复现](2026-10-30-vps4-cycle-repair/restore-reproduction.json)、[其他修复](2026-10-30-vps4-cycle-repair/aux-fixes.json)、[sysctl 修复](2026-10-30-vps4-cycle-repair/sysctl-fix.json)、[本地回归](2026-10-30-vps4-cycle-repair/local-focused-tests.txt)。同目录 `SHA256SUMS` 记录报告、证据及验证脚本摘要。

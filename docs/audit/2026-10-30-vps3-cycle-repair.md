# 第三台 VPS：复审、更新与实测

目标 `167.17.74.78:53322`。用户添加专用公钥后连接成功。现场为 Debian 13、CrowdSec 1.8.1、host 网络 OpenResty，以及已部署的 WebUI、网站及数据库容器。

## 完成的更新

- 现场没有 `/root/crowdsec-1key` 日常管理目录。备份配置后部署当前修复版完整入口，保留 `install-crowdsec-1panel.sh` 兼容链接。发行目录为 `/opt/crowdbastion/releases/review-20261030`，日常入口与发行目录的 56 个源码文件摘要一致。
- 升级已托管的 OpenResty Web Bouncer，补齐真实拒绝记录、AppSec 403、LAPI 故障策略支持及可靠重载验证。原账号与 `bouncer.conf` 字节保持，原 AppSec `deny`、LAPI `passthrough` 策略保持。
- 补充 `/etc/systemd/system/crowdsec-firewall-bouncer.service.d/20-crowdbastion-docker-order.conf`，设置 `After=docker.service`，避免启动时先于 Docker 创建所需链。执行 daemon-reload 后确认依赖生效，Bouncer 进程不变。
- 原 cron 中禁用的重复 Hub 更新任务保持。没有启用额外机器人或通知服务，没有创建 git 提交。

第三台原本已经使用 iptables/ipset，INPUT、FORWARD、DOCKER-USER 均已接入，因此没有切换后端或替换 Bouncer。现有 OpenResty notice 日志已满足验证条件，也没有修改日志配置。

## 实际验证

| 项目 | 结果 |
| --- | --- |
| IPv4/IPv6 × TCP/UDP × 输入/转发 | 8 条测试流的封禁、续封、删除和自然到期均通过 |
| 未封禁的对照来源 | 全程可达 |
| 有效网络与内核集合（剩余有效期超过 15 秒） | 16,477 条，缺失 0 |
| CrowdSec / OpenResty 配置 | 通过 |
| Web Bouncer 升级后的 master 日志与稳定新 worker | 确认重载生效 |
| 托管配置、资源、账号及策略 | 校验通过 |
| 重复安装 | 成功，进程身份未变，没有多余重载 |
| aomway.com、shop.node2api.com、www.zhishangsheng.com 源站 | 升级阶段抽查及最终检查均 200 |
| CrowdSec、Bouncer、Docker | active，PID、启动时间和重启计数与操作前一致 |
| 原健康容器及 WebUI | 仍 healthy；其他既有容器运行 |

流量实测在临时命名空间中使用专用测试地址，先封禁 40 秒再续期至 120 秒，越过原期限后仍阻断；删除恢复通行，另一次 25 秒封禁自然到期后也恢复。没有封禁管理出口。测试决策、网卡、命名空间、18080 监听、临时放行规则与清理定时器均已清理。

首次使用 `cscli` 来源后，官方 Bouncer 新增并保留两个空分区 `crowdsec-blacklists-2`、`crowdsec6-blacklists-2` 及对应 DROP 引用。最终确认两集合均无成员，原有规则及顺序保持。最初的“所有规则逐字不变”校验因此失败；核对差异后将其修正为精确允许这两个 Bouncer 自管空分区，其余规则必须不变。没有直接删除运行中 Bouncer 管理的集合。

正常请求访问 `https://www.zhishangsheng.com/`，经过 Cloudflare 回源；连接对端为 `172.69.64.143`，CF-Connecting-IP、X-Forwarded-For、访问日志 IP 和 Bouncer IP 均为预期来源 `167.17.74.78`。临时诊断 Lua 恢复及重载确认成功，完整命令退出 0。

本轮使用前两台已回归验证的修复版，没有新增产品源码改动；远端执行了 Bash 语法检查、36 个 Python 模块编译检查、CLI 帮助检查和上述生产验证，没有重复运行全仓测试集。

## 边界与既有状态

健康检查更新前后均为 **2（运行检查通过，实际拦截待验证）**，不能将本轮升级说成修复了原先并不存在的防火墙续封故障。源站可用性检查使用 loopback `--resolve` 和 `-k`，不代表公网 TLS 验收；正常 CDN 请求的真实 IP 核验也不等于公网攻击阻断验收。其他域名仍需逐项完成外部流量验证。

现场有三份既有 `vpatch-CVE-2026-96652/96655/96656` 规则不在本地 Hub 索引中，`cscli` 因此打印忽略索引条目的提示。本轮保留原规则、索引和 AppSec 配置，没有把这些文件宣称为已确认的官方 Hub 项，也没有单独验证三条规则的攻击命中效果。整体 CrowdSec 配置校验及 AppSec 运行检查通过。

启动顺序通过 systemd 依赖检查确认，本轮没有重启宿主机或 Docker 来做冷启动演练。核心既有 `NRestarts=2` 在操作前就存在，操作后未增加。

## 备份和证据

私有备份目录 `/var/backups/crowdbastion/vps3-cycle-20261030/`（目录 0700、文件 0600）包含 `before.tar.gz`、修改前摘要、规则快照、流量工具与结果、部署验证脚本和过程日志。含凭据备份保留在 VPS，没有下载到仓库。

Web Bouncer 事务备份为 `/var/backups/crowdsec-1key/change.SprXibLC`；真实 IP 临时诊断备份为 `change.wTnNXc7w`。新增 systemd drop-in 的原状态为不存在，记录在 `docker-order.json`。这些恢复资料已保留，未在生产执行回退演练。

证据：[最终核验](2026-10-30-vps3-cycle-repair/verification-final.json)、[防火墙流量实测](2026-10-30-vps3-cycle-repair/flow-after.json)、[Web 升级](2026-10-30-vps3-cycle-repair/web-upgrade.txt)、[真实 IP 核验](2026-10-30-vps3-cycle-repair/real-ip-verification.txt)、[健康结论](2026-10-30-vps3-cycle-repair/health-final.txt)。证据目录的 `SHA256SUMS` 包含报告、证据和部署源码清单摘要。

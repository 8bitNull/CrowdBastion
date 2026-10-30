# 第二台 VPS：部署后的追加复审

目标 `179.255.121.95:53322`，接续[上一轮修复](2026-10-30-vps2-cycle-repair.md)。本轮复查上一轮部署的有效性、规则覆盖、持久化配置和健康检查展示，并修复一项检查指引遗漏。

## 新发现与修复

现场节点用途配置为 `relay`，但已有 NPM、Web Bouncer 和 AppSec。脚本原本会自动发现并检查网站组件，摘要却只按用途配置显示“本地中转”；验证帮助也只给中转验证入口，遗漏网站入口。

- `crowdbastion_health.py`：整体检查的事件明确包含网站检查时，摘要范围同时显示“网站、本地中转”。仅改变报告展示，不把网站检查自动判定为通过，也不修改用途配置。
- `health_summary.sh`：发现已部署网站时，验证指引包含 `--verify-appsec`，同时保留 `--verify-relay`。
- 现场验证：新摘要范围正确，两个验证指引均出现；节点用途文件字节不变，退出码仍为 **2（运行检查通过，实际拦截待验证）**。

健康摘要及节点用途相关 **60 项回归全部通过**；Python/Bash 语法、ShellCheck warning/error 级别和差异格式检查通过。没有重跑全仓测试集。

## 追加运行检查

| 检查 | 结果 |
| --- | --- |
| 最终有效网络封禁（剩余有效期超过 15 秒） | 16,467 条，内核覆盖缺失 0 |
| IPv4/IPv6 INPUT、FORWARD、DOCKER-USER | CrowdSec 入口规则保持，原业务规则不变 |
| 基础防火墙配置、API 凭据、Web Bouncer 策略及账号 | 保持 |
| 托管网站资源 | 校验通过，无临时诊断残留 |
| CrowdSec、Bouncer、Docker、机器人、通知服务 | 全部 active，本轮未重启服务 |
| 机器人 / 通知队列 | healthy / ready，待发与重试均为 0 |
| 源站抽查 | shop.688600.xyz 301；32byte.cn、waf.688600.xyz 200，与前轮一致 |
| 临时命名空间、监听、测试决策、容器、快照表、定时器 | 无残留 |

确认 Bouncer 已启用，systemd 启动顺序包含 Docker；NPM notice 日志位于持久化挂载中，`logrotate -d` 能识别该文件和现有轮转规则，日志所属用户与容器内 `npm` 用户一致。本轮是配置与运行核验，没有通过重启宿主机、重建容器或强制轮转生产日志来验收持久性。

源站抽查继续使用 loopback `--resolve` 和 `-k`，不等于公网 TLS 或公网拦截验收。本轮没有创建新的封禁测试或发送 Telegram 测试消息；上一轮的流量验收仍为历史证据。各域名的外部真实拦截验收仍待完成。

## 部署与证据

最终发行目录：`/opt/crowdbastion/releases/review-20261030-followup`。日常入口 `/root/crowdsec-1key` 同步更新两个模块，56 个源码文件与新发行目录摘要一致。运行中的机器人与通知服务未重装；修复位于管理 CLI 的报告渲染及指引入口。

旧发行目录 `/opt/crowdbastion/releases/review-20261030-cycle-npm-final` 保留。修改前模块及源码清单位于 `/var/backups/crowdbastion/vps2-followup-20261030/`，文件 0600、目录 0700。本轮没有创建 git 提交。

证据：[部署核验](2026-10-30-vps2-followup/deployment.json)、[最终运行检查](2026-10-30-vps2-followup/verification-final.json)、[修复后的摘要](2026-10-30-vps2-followup/health-after.txt)、[验证指引](2026-10-30-vps2-followup/verification-help.txt)、[回归测试](2026-10-30-vps2-followup/health-tests.txt)。`SHA256SUMS` 包含报告、证据与本轮改动源码摘要。

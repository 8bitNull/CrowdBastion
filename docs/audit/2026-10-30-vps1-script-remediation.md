# 第一台 VPS：按复审修复版脚本更新

目标：`45.82.122.6:53322`，root 公钥认证。使用已存在的身份及已知主机密钥完成连接；未修改 SSH 配置或授权密钥。部署源码提交为 `ab0af70`，对应前一轮 1156 项测试（1112 通过、44 跳过）的修复版本。

## 已完成

1. 读取现有部署、服务、配置及托管记录。系统 Debian 13；CrowdSec v1.8.1、Firewall Bouncer v0.0.36、OpenResty 官方 Web Bouncer v1.2.3 已安装。分级通知、V2bX 发布/观察服务和远端中转覆盖配置未安装，因此没有启用这些功能或人为执行故障回滚。
2. 部署完整脚本、全部 lib 和 rules，共 57 个源码文件；核对 SHA256，执行远端 Bash/Python 语法检查和 CLI 帮助检查。
3. 更新日常入口 `/root/crowdsec-1key/crowdbastion.sh`，兼容入口 `/root/crowdsec-1key/install-crowdsec-1panel.sh` 指向该脚本。维护运行目录的 `current` 原子切换到新 release，现有 cron 仍使用原路径和调度。
4. 调用修复版的 `--install-web-bouncer` 复用现有 `openresty` 安装，升级真实拒绝记录、AppSec 故障 403 修复及 LAPI 故障策略支持。Nginx master 接受重载的日志和稳定新 worker 均由脚本验证成功。
5. 对日常目录和维护 release 的全部源码再次核对摘要；检查升级后的资源摘要和有效请求钩子；重复运行安装入口成功且 worker 列表未变化，确认没有重复重载。

## 保留及备份

- 完整修改前备份：`/var/backups/crowdsec-1key/remediation-20261030-ab0af70/before.tar.gz`。
- 备份目录包含原核心配置、网站受管配置/资源、管理目录、维护链接和 cron，以及元数据、升级日志、前后诊断及最终验证 JSON。目录仅 root 可访问，文件权限 0600；含凭据的完整备份保留在 VPS，没有下载到仓库。
- Web Bouncer 自身事务备份：`/var/backups/crowdsec-1key/change.Z2cVktbj`。
- 原日常管理目录：`/root/crowdsec-1key.before-20261030-ab0af70`。
- 原维护 release：`/usr/local/lib/crowdsec-1key/release-1791727791-7637`，未删除。
- 新维护 release：`/usr/local/lib/crowdsec-1key/release-review-20261030-ab0af70`。
- 原 Bouncer 账号未变；`bouncer.conf` SHA256 与修改前完全相同，保留 API 密钥及 AppSec/LAPI `deny` 策略。没有重启 CrowdSec 核心或业务容器。

## 上线验证

| 检查 | 结果 |
| --- | --- |
| `crowdsec -t` | 通过 |
| OpenResty `nginx -t` | 通过 |
| CrowdSec / Firewall Bouncer 服务 | active |
| 既有健康容器 | 仍 healthy；其他容器仍运行 |
| 托管资源摘要、挂载与请求钩子 | 通过 |
| 重复安装、账号和配置保持 | 通过 |
| codeg-x.688600.xyz 源站首页 | 修改前/后均 200 |
| test.688600.xyz 源站首页 | 修改前/后均 200 |
| waf.860525.xyz 源站首页 | 修改前/后均 200 |

首页冒烟检查通过 `--resolve` 直连本机源站，没有经过公网 CDN。后两站现有源站证书不受系统 CA 信任，因此对这一组 loopback 检查使用 `curl -k`；没有修改 TLS 配置，也没有据此宣称公网证书验证通过。没有发送攻击探针、Telegram 消息或新增封禁决策。

## 尚未解决的独立问题

修复版整体健康检查在更新前后均返回 **1**：本机 Firewall Bouncer **0.0.36 + nftables** 命中已确认的续封缺陷，决策仍有效时内核封禁条目可能提前到期。这不属于前轮七项脚本缺陷，部署脚本不会自动修复正在运行的防火墙后端。

本机尚未安装 ipset，现有 `iptables_chains` 也只有 INPUT。迁移需按 `docs/usage-guide.md` 的后端迁移边界，准备管理员来源保护与独立恢复入口，备份有效决策/规则，再验证 IPv4/IPv6、Docker 转发路径、续封、到期和撤销。此次未切换后端，不能宣称该风险已消除。

真实公网阻断与各站点真实 IP 的逐请求关联仍标记为尚未验证；此次源站可用性检查不能替代这些验收。

证据：[验证 JSON](2026-10-30-vps1-script-remediation/verification.json)、[升级日志](2026-10-30-vps1-script-remediation/web-upgrade.txt)、[重复运行日志](2026-10-30-vps1-script-remediation/web-repeat.txt)。

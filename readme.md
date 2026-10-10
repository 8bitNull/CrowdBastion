# CrowdSec 防护管理脚本

面向 1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）和宿主机 Nginx 的 Bash 管理工具，集中管理 CrowdSec、防火墙 Bouncer、日志采集、规则库、WebUI 和 Telegram 告警。

## 环境要求

- 使用 root 权限，在由 systemd 管理的 Linux 宿主机上运行。
- 脚本包含 Debian、Ubuntu、CentOS、RHEL、AlmaLinux、Rocky Linux 和 Fedora 的软件包安装分支；实际可安装性取决于系统版本及 CrowdSec 软件源。
- 需要访问 CrowdSec 软件源和 Hub；部署 WebUI 还需要访问 GitHub Container Registry。
- WebUI 需要预先安装 Docker，优先使用 `docker compose`，其次使用 `docker-compose`，均不可用时使用 `docker run`。
- 定时更新需要运行中的 cron 服务；SQLite 调优使用 `sqlite3` 或 Python 3。

## 开始使用

在包含脚本的目录执行：

```bash
sudo bash install-crowdsec-1panel.sh
```

建议先选择菜单 `1` 安装核心与 Firewall Bouncer，再用菜单 `9` 检查服务和配置，按需配置规则、定时任务、WebUI 与告警。

## 主菜单

| 选项 | 功能 |
| --- | --- |
| 1 | 安装或重装 CrowdSec 与 Firewall Bouncer，优先尝试 nftables，回退到 iptables；配置日志采集、基础规则和管理员白名单 |
| 2 | 部署或更新 WebUI、删除 WebUI、查看容器日志、重新生成 LAPI 连接凭据 |
| 3 | 安装 Web、WordPress、网络扫描场景规则，查看和升级规则集合 |
| 4 | 开启、调整或关闭每日 Hub 更新任务 |
| 5 | 查看封禁与警报、手动封禁或解封 IP、查看防火墙状态与解析指标 |
| 6 | 使用 Enrollment Key 绑定 CrowdSec Console |
| 7 | 配置、测试、检查或关闭 Telegram 告警，支持自定义 Telegram API 端点 |
| 8 | 诊断资源与 Web 环境，执行 SQLite WAL 调优、采集配置重建、规则补齐和指标配置 |
| 9 | 检查核心服务、Bouncer、WebUI 和 CrowdSec 配置 |
| 10 | 完全卸载 CrowdSec、防火墙 Bouncer、WebUI 及相关配置和数据 |
| 0 | 退出 |

管理员 IP 从 `SSH_CLIENT`、`SSH_CONNECTION` 或当前登录信息提取；无法识别时会要求手工输入。白名单包含回环地址、私有 IPv4 网段及 `100.64.0.0/10`。

## 命令行入口

```bash
sudo bash install-crowdsec-1panel.sh --install-core
sudo bash install-crowdsec-1panel.sh --install-webui
sudo bash install-crowdsec-1panel.sh --install-waf
sudo bash install-crowdsec-1panel.sh --enable-cron
sudo bash install-crowdsec-1panel.sh --telegram
sudo bash install-crowdsec-1panel.sh --telegram-test
sudo bash install-crowdsec-1panel.sh --optimize
sudo bash install-crowdsec-1panel.sh --uninstall
```

这些参数用于直接进入对应功能，多数仍包含交互提示，不适合作为完全无人值守的部署接口。`--install-waf` 安装 Nginx、HTTP-CVE、基础 HTTP 场景及良性行为白名单，菜单中的 Web 套件另包含 NPM 集合。

## 日志采集范围

脚本将以下常见路径写入 `/etc/crowdsec/acquis.d/web-sites.yaml`：

| 环境 | 日志路径 |
| --- | --- |
| 1Panel OpenResty | `/opt/1panel/apps/openresty/openresty/logs/*.log`、`/opt/1panel/apps/openresty/openresty/data/sites/*/log/*.log` |
| 科技lion LDNMP | `/home/web/log/nginx/*.log`、`/home/web/log/nginx/*/*.log` |
| 宿主机 Nginx | `/var/log/nginx/*.log` |
| NPM | `/home/docker/npm/data/logs/*.log`、`/opt/npm/data/logs/*.log`、`/opt/nginx-proxy-manager/data/logs/*.log`、`/data/logs/*.log`、`/var/log/nginx-proxy-manager/*.log` |
| SSH / 系统认证 | `/var/log/auth.log`、`/var/log/secure` |

Nginx 日志使用 `nginx` 标签，NPM 使用 `nginx-proxy-manager`，认证日志使用 `syslog`。自定义挂载目录需要自行调整采集配置，并通过 `cscli metrics` 确认日志确实被读取和解析。

## WebUI、指标与告警

WebUI 使用镜像 `ghcr.io/theduffman85/crowdsec-web-ui:latest`，采用宿主机网络。访问端口默认 `3000`，部署时可修改；LAPI 端口默认 `8080`，脚本会尝试从 CrowdSec 配置读取实际端口。Prometheus 指标端口为 `6060`，供 WebUI 展示解析器和组件指标。

脚本会注册独立的 LAPI Machine 账号，并将配置与持久化数据放入 `/opt/crowdsec-web-ui`。脚本提示该 WebUI 默认没有登录密码页面，因此应限制访问，并通过反向代理配置 HTTPS 和身份认证。

Telegram 配置需要 Bot Token、Chat ID，可指定 API 代理端点。配置保存在 `/etc/crowdsec/notifications/http.yaml`，告警路由涉及 `/etc/crowdsec/profiles.yaml`，Telegram 网段白名单保存在 `/etc/crowdsec/parsers/s02-enrich/tg-whitelist.yaml`。这些运行时配置可能含有凭据，不应提交到源码仓库。

## 自动更新与运维

默认定时任务在服务器本地时间每天 `03:30` 执行：

```bash
cscli hub update && cscli hub upgrade && systemctl reload crowdsec
```

任务文件为 `/etc/cron.d/crowdsec-autoupdate`。它更新 Hub 规则并重载服务；社区封禁名单同步由 CrowdSec 自身机制负责。

常用检查命令：

```bash
sudo crowdsec -t
sudo systemctl status crowdsec --no-pager
sudo cscli bouncers list
sudo cscli collections list
sudo cscli metrics
sudo cscli decisions list
sudo cscli alerts list
sudo journalctl -u crowdsec -n 100 --no-pager
sudo docker logs --tail 100 crowdsec-web-ui
```

## 操作影响与注意事项

- 安装、调优和告警配置会修改系统配置并可能重启服务；操作前应备份 `/etc/crowdsec` 及相关数据。
- 本脚本主要通过日志检测和 Firewall Bouncer 执行 IP 封禁；安装 Web 场景集合并不等同于部署在线请求检查的 AppSec WAF。
- 白名单用于降低管理员误封风险，部署后仍应检查实际封禁决策和 Bouncer 状态。
- 脚本多处使用 `|| true` 继续执行，完成提示不能替代服务、配置和日志验证。
- 调优会重建采集配置，并可能修复或隔离损坏的白名单解析器文件。
- 完全卸载需输入确认，并会删除 `/etc/crowdsec`、`/var/lib/crowdsec`、WebUI 数据及定时任务；仅卸载 WebUI 也会删除其持久化目录。

## 源码与检查

核心源码：[`install-crowdsec-1panel.sh`](install-crowdsec-1panel.sh)。

只检查 Bash 语法，不执行安装或修改防火墙：

```bash
bash -n install-crowdsec-1panel.sh
```

相关项目：[CrowdSec](https://github.com/crowdsecurity/crowdsec)、[CrowdSec Hub](https://hub.crowdsec.net/)、[CrowdSec Web UI](https://github.com/TheDuffman85/crowdsec-web-ui)。

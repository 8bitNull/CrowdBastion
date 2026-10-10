# CrowdSec 防护管理中心

面向 1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）和宿主机 Nginx/OpenResty 的管理工具。提供 CrowdSec 安装、日志检测规则、Firewall Bouncer、AppSec 接入、WebUI、Telegram 告警与日常运维菜单。

## 开始使用

下载完整仓库后运行，配置辅助程序 `lib/crowdsec_config.py` 必须与脚本一起保留：

```bash
# 私有仓库需要先配置 GitHub 访问凭据
git clone https://github.com/8bitNull/crowdsec-1key.git
cd crowdsec-1key
sudo bash install-crowdsec-1panel.sh
```

首次使用建议依次选择：

1. 菜单 `1` 安装 CrowdSec 与 Firewall Bouncer，确认管理员公网 IP。
2. 菜单 `9` 检查服务、LAPI、日志解析指标与防火墙资源。
3. 菜单 `3` 按网站类型安装日志规则；需要在线请求检查时另行配置 AppSec。
4. 按需配置菜单 `4` 的规则更新、菜单 `2` 的 WebUI 和菜单 `7` 的 Telegram。

子菜单在操作后保留，输入 `0` 返回；输入结束或 `Ctrl+D` 可退出菜单。删除、注销、停用和卸载操作默认取消，需要明确输入 `y`。命令行操作失败返回非零状态，交互菜单会保留供继续操作。

## 环境要求

- root 权限、Bash 和由 systemd 管理的 Linux 宿主机。
- 核心安装包含 Debian/Ubuntu 及 CentOS/RHEL/AlmaLinux/Rocky/Fedora 分支；软件包可用性取决于发行版版本与官方软件源。
- 配置编辑需要 Python 3 与 PyYAML；核心安装会安装相应系统软件包。已装 CrowdSec 的机器可先安装 `python3-yaml`（Debian/Ubuntu）或 `python3-pyyaml`（RHEL 系列）。
- WebUI 需要预装 Docker 和 Docker Compose；支持 `docker compose` 或旧版 `docker-compose`。
- 定时更新需要运行中的 `cron`/`crond` 服务。
- 需要访问 CrowdSec 软件源、Hub；WebUI 需要访问 `ghcr.io`，Telegram 需要访问所配置的 HTTPS 端点。

若提示缺少 PyYAML，Debian/Ubuntu 执行 `sudo apt-get update && sudo apt-get install -y python3-yaml`，RHEL 系列使用 `sudo dnf install -y python3-pyyaml`（旧系统使用 yum），随后执行 `sudo python3 -c 'import yaml; print(yaml.__version__)'` 验证。若系统软件包已安装但验证仍失败，应检查当前 `python3` 是否来自自定义安装或虚拟环境；安装包必须与脚本实际使用的解释器对应。无需为补齐此依赖重新安装 CrowdSec。

菜单 `8` 先执行只读诊断，确认应用配置后才检查 PyYAML；缺少依赖时会在任何配置修改前停止，并显示安装命令。菜单 `9` 不要求先安装该依赖，但缺少依赖时无法额外解析 Bouncer 配置中的自定义防火墙表。

## 主菜单

| 选项 | 功能 |
| --- | --- |
| 1 | 安装核心和官方 Firewall Bouncer，写入常见日志采集、管理员白名单及基础规则 |
| 2 | 部署/更新 WebUI、卸载本工具 WebUI、查看日志、检查/轮换其独立凭据、查看并选择注销 Machine |
| 3 | 管理日志检测规则、补齐基础集合，以及配置、检查、验证或停用 AppSec |
| 4 | 设置、查看或关闭每天的 Hub 规则更新任务 |
| 5 | 查看警报和决策、手动封禁/解封 IP、检查防火墙、修复 Bouncer 连接配置 |
| 6 | 提交 Console 注册；成功后仍需在官方控制台接受注册 |
| 7 | 配置、测试、检查或停用本工具 Telegram 通道 |
| 8 | 只读诊断后选择补齐基础规则和启用指标 |
| 9 | 只读健康检查，检查服务、LAPI、配置、注册节点、采集指标和防火墙资源 |
| 10 | 明确确认后卸载，或执行只读残留检查 |

Machine 是 LAPI 客户端凭据，名字相似不代表重复的防御引擎；脚本不会根据名称、日期或版本自动重建宿主机身份，也不会批量删除所有 `webui-*` 或其他 Bouncer。

## 日志检测与 AppSec WAF

日志检测读取访问日志、识别行为并形成决策，由 Bouncer 执行相应阻断。安装 `http-cve`、`base-http-scenarios` 等日志集合不会自动建立在线请求检查链路。

根据 [官方 AppSec 介绍](https://docs.crowdsec.net/docs/next/appsec/intro/) 和 [Nginx/OpenResty quickstart](https://docs.crowdsec.net/docs/next/appsec/quickstart/nginxopenresty/)，AppSec 需要三个部分：

1. 官方集合 `crowdsecurity/appsec-virtual-patching` 和 `crowdsecurity/appsec-generic-rules`。
2. 启用 `source: appsec` 数据源，并重启 CrowdSec。
3. 已安装、注册并在网站中启用的 AppSec 兼容 Web Bouncer，将 HTTP 请求转发给 AppSec。

菜单 `3 → 9` 或 `--install-appsec` 安装集合，并创建：

```yaml
source: appsec
listen_addr: 127.0.0.1:7422
appsec_configs:
  - crowdsecurity/appsec-default
labels:
  type: appsec
```

随后可选择接入已有的宿主机 Nginx/OpenResty Bouncer，将其 `APPSEC_URL` 设置为 `http://127.0.0.1:7422`。脚本不代替安装 Web Bouncer 和启用网站内的 Bouncer 集成；缺少对应配置时会明确报告。已有外部 AppSec 数据源时不会创建重复监听。

Firewall Bouncer 支持 IP 封禁，但[不支持 AppSec HTTP 转发](https://docs.crowdsec.net/u/bouncers/firewall/)。1Panel/NPM 容器内部的 `127.0.0.1` 通常不是宿主机；容器部署需按上游文档配置专用网络和兼容组件。脚本不会自动修改容器内部 Nginx，也不会将 AppSec 端口直接暴露到公网。

验证方式：菜单 `3 → 11` 或 `--verify-appsec` 输入自己管理的网站根地址，比较 `cscli metrics show appsec` 的前后计数，并检查 `/.env` 请求响应。预期是 HTTP 403、Processed/Blocked 增加，以及对应规则命中。单独一个 403 不能证明 AppSec 生效。

停用入口只处理本工具数据源和记录过的 Web Bouncer 接入，并恢复接入前的 `APPSEC_URL`；外部配置和 AppSec 集合保留。容器/外部代理需要自行同步停用转发。

## 日志采集与防火墙

采集配置为 `/etc/crowdsec/acquis.d/web-sites.yaml`：

| 环境 | 常见日志路径 |
| --- | --- |
| 1Panel OpenResty | `/opt/1panel/apps/openresty/openresty/log/{access,error}.log`、`/opt/1panel/www/sites/*/log/{access,error}.log`、`/opt/1panel/1panel/www/sites/*/log/{access,error}.log`；兼容旧版 `logs/` 和 `data/sites/` 布局 |
| 科技lion LDNMP | 已核对上游默认 `/home/web/log/nginx/access.log`、`error.log`；配置兼容该目录及下一级目录的 `.log` 文件 |
| 宿主机 Nginx | `/var/log/nginx/*.log` |
| 科技lion NPM | 已核对上游默认宿主机目录 `/home/docker/npm/data/logs/`，采集下述 HTTP 日志 |
| 其他 NPM 部署 | 预设候选目录 `/opt/npm/data/logs/`、`/opt/nginx-proxy-manager/data/logs/`、`/data/logs/`、`/var/log/nginx-proxy-manager/`；须按实际 Docker 挂载调整 |
| SSH 认证 | `/var/log/auth.log`、`/var/log/secure` |

Nginx、NPM、系统日志分别使用 `nginx`、`nginx-proxy-manager`、`syslog` 标签。表中的 `{access,error}` 表示两个独立文件，生成的 YAML 不使用花括号展开。1Panel 只采集上述 HTTP access/error 日志，避免把 TCP/UDP 的 `stream-access.log` 或 PHP 日志交给 HTTP 解析器。采集不重复列出已被通配符覆盖的文件。实际日志位置、格式、自定义挂载目录和仅使用 journald 的系统需要按部署调整。用 `cscli metrics` 核查采集和解析；存在配置文件不等于实际采集成功。

1Panel 的站点日志应结合容器的 `nginx -T` 和 `docker inspect` 挂载确定，不能仅按域名推定宿主机目录。用户部署中已确认 `/www` 的宿主机 Source 为 `/opt/1panel/1panel/www`，所以容器日志 `/www/sites/<站点目录>/log/access.log` 对应 `/opt/1panel/1panel/www/sites/<站点目录>/log/access.log`。站点配置了自己的 `access_log` 时，全局 `/var/log/nginx/access.log` 不一定包含该站点请求。其他安装目录仍需按挂载 Source 调整预设。

上游依据：[科技lion 安装脚本](https://github.com/kejilion/sh/blob/main/kejilion.sh)、[LDNMP Compose](https://github.com/kejilion/docker/blob/main/LNMP-docker-compose-10.yml)、[Nginx 日志配置](https://github.com/kejilion/nginx/blob/main/nginx10.conf)。默认 LDNMP 将 `/home/web/log/nginx` 挂载到容器 `/var/log/nginx`；访问日志配置了 `buffer=512k flush=10s`，低流量下新访问可能需要约 10 秒才写入文件。

[NPM 官方部署示例](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/docs/src/setup/index.md) 使用 `./data:/data`，所以容器 `/data/logs` 不等于宿主机 `/data/logs`。科技lion 的 NPM 将 `/home/docker/npm/data` 挂载到 `/data`，其宿主机日志路径可确认；其他部署应使用 `sudo docker inspect <容器名> --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'` 查看实际挂载。若 `/data` 对应 `/srv/npm/data`，采集应写 `/srv/npm/data/logs/...`；命名卷使用 Docker 返回的实际 Source，并按部署确认可读性。

NPM 根据[官方模板](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/templates)仅预设 HTTP 日志：`*host*_access.log`、`*host*_error.log`（代理、重定向、dead/default host）、`fallback_http_access.log`、`fallback_http_error.log`、`letsencrypt-requests_access.log`、`letsencrypt-requests_error.log`。不再用整个目录的 `*.log`，避免采集格式不同的 `stream-*`、`fallback_stream_*` 和主进程 `fallback_error.log`。自定义文件名需要自行添加采集。

### 解析成功率为 0% 的排查

先查看 `sudo cscli metrics` 的 Acquisition Metrics。如果没有 Web 文件来源，在确认网站产生新访问日志后，核对实际文件路径与采集配置；1Panel 的 `log/` 与 `logs/`、`www/sites/` 与 `data/sites/` 是不同目录。更新仓库本身不会修改服务器上已有的采集 YAML，需备份并调整配置，执行 `sudo crowdsec -t`，校验成功后重启 CrowdSec，再访问网站观察读取和解析计数。

若只有 SSH journal 来源，且 `syslog-logs` 成功、`sshd-logs` 全部未解析，说明外层日志格式已识别，内部消息没有匹配已加载的 SSH 事件解析器。`Accepted password` 属于成功登录，不能用失败登录解析器是否匹配来判断 SSH 防护是否失效。核查时官方 `sshd-logs` 已支持 `sshd-session`，但 `sshd-success-logs` 的过滤器仍仅匹配 `sshd`；因此新版 OpenSSH 的成功登录和普通会话消息可能显示为未解析。应结合日志样本与 `cscli explain --file /path/to/sample.log --type syslog` 判断，不应把所有会话消息强行转换成失败登录事件。

防火墙执行 CAPI 社区名单、日志检测产生本机决策、AppSec 检查在线请求分别有独立指标；社区名单有阻断并不能证明本机 Web 日志已接入，日志解析率也不能单独证明 AppSec 是否生效。

管理员 IP 从 `SSH_CLIENT` 或 `SSH_CONNECTION` 提取，无法识别时手工输入；白名单包含回环和常见内网网段。手动封禁接受 IPv4/IPv6，会规范化地址并拒绝封禁当前 SSH IP。时长使用 Go duration，如 `4h`、`24h`、`168h`；7 天应填写 `168h`。

Docker 转发流量需要正确的防火墙链/钩子。修复入口保留官方软件包配置及其他凭据，在 `.yaml.local` 中更新 LAPI 地址和密钥；iptables 模式检测到 `DOCKER-USER` 时加入对应链。核验会检查 IPv4、IPv6、配置中的 nftables 表及默认 IPSet 资源，但仍需在实际主机上确认 Bouncer 拉取和流量阻断。

## WebUI、Telegram 与更新

WebUI 使用 `ghcr.io/theduffman85/crowdsec-web-ui:latest`，宿主机网络，端口默认 `3000`。LAPI 地址从宿主机凭据读取；指标配置为 `127.0.0.1:6060`。已有有效独立 Machine 会被复用；凭据检查真正验证 WebUI 账号，轮换成功后才注销旧账号。镜像拉取失败保留现有部署；更新失败会恢复配置并尝试用原镜像恢复旧容器。数据在 `/opt/crowdsec-web-ui`，应按镜像实际认证功能设置访问保护并使用 HTTPS 反向代理。

Telegram 使用独立通知名称 `crowdsec_1key_telegram` 和 `/etc/crowdsec/notifications/crowdsec-1key-telegram.yaml`，保留既有通道。模板先转换模型字段为实际值，再使用 `toJson` 生成请求体，支持多条告警和没有决策的告警；测试走官方 `cscli notifications test`，会真实向所配置机器人发送消息。告警发送是出站请求，不添加 Telegram 来源网段白名单。旧脚本写入的 `http_default` 通道和白名单不会自动删除，升级后应人工确认是否继续保留，避免重复通知。

默认规则更新使用服务器时区的每天 `03:30`，写入 `/etc/cron.d/crowdsec-autoupdate`，依次执行 Hub 更新、升级、配置校验和服务重载。自定义时分会验证范围。此任务更新 Hub 规则，CAPI 社区名单由 CrowdSec 引擎自身同步。

SQLite 优化使用官方 `db_config.use_wal: true`，通过 `--enable-wal` 在确认数据库位于本地磁盘后启用。网络共享盘不适合 WAL。本工具不直接对运行中的数据库执行临时 PRAGMA 或 VACUUM，不承诺固定性能倍数。

## 命令行入口

```bash
bash install-crowdsec-1panel.sh --help
```

| 参数 | 功能 |
| --- | --- |
| `--install-core` | 安装核心和 Firewall Bouncer |
| `--install-webui` | 部署/更新 WebUI |
| `--reset-webui-credentials` | 检查并选择轮换 WebUI 凭据 |
| `--install-waf` | 安装 Web 日志检测集合 |
| `--install-appsec` | 配置 AppSec 并选择接入 Web Bouncer |
| `--appsec-status` | AppSec 状态与指标 |
| `--verify-appsec` | 对指定网站执行官方验证请求 |
| `--disable-appsec` | 停用本工具 AppSec |
| `--enable-cron` | 每天 03:30 更新 Hub |
| `--clean-redundant` | 查看节点并选择注销，保留受保护账号 |
| `--repair-bouncer` | 修复 Firewall Bouncer 连接配置 |
| `--reset-baseline`、`--reset-56` | 补齐基础集合；兼容旧参数，保留自定义/AppSec，不保证固定场景数 |
| `--uninstall-waf` | 确认后移除已知 Web 日志扩展 |
| `--check-clean` | 只读残留检查 |
| `--deep-clean`、`--purge`、`--uninstall` | 确认后卸载和删除数据 |
| `--telegram` | Telegram 管理菜单 |
| `--telegram-test` | 官方通知插件测试 |
| `--optimize` | 诊断并选择应用基础配置 |
| `--enable-wal` | 确认本地 SQLite 后启用官方 WAL 配置 |
| `--status` | 只读健康检查 |
| `--help`、`-h` | 帮助，不需要 root |

每次仅指定一个操作。命令行仍保留必要的输入与确认，不能直接当作无人值守部署接口。

## 备份、失败恢复与卸载

配置修改前备份保存在 `/var/backups/crowdsec-1key/change.*`，目录权限为 `700`，含凭据的配置文件权限为 `600`。结构化 YAML 编辑保留无关配置值，可能重排格式或去除注释；原始文件保留在备份中。

配置校验失败不重启核心；服务启动失败会恢复配置并尝试恢复原服务。Hub 集合下载/安装不属于配置文件回滚范围；失败时保留诊断输出，修复后可重新执行。

卸载需要明确确认，会停止服务、卸载检测到的软件包并删除 CrowdSec 数据和本工具 WebUI。若仍存在宿主机 Web Bouncer 集成，需先按上游文档移除集成并验证网站，否则核心卸载会中止。服务停止后仍有防火墙资源时会中止清理，保留配置供排查。备份、系统日志及软件源不自动删除；其他容器和不属于本工具的目录不进行广泛匹配清理。

## 验证与官方参考

```bash
bash -n install-crowdsec-1panel.sh
shellcheck install-crowdsec-1panel.sh
python3 -m pip install -r tests/requirements.txt
python3 -m unittest discover -s tests -v

# 可选：下载并解压官方 CrowdSec Linux 发布包后运行真实引擎检查
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1
```

测试覆盖与部署验证边界详见 [验证记录](docs/verification.md)。真实引擎检查会下载 Hub 集合，在临时目录和 loopback 端口运行，不安装系统服务、不修改防火墙、不向真实 Telegram 发送消息。

参考：[AppSec 数据源](https://docs.crowdsec.net/docs/next/log_processor/data_sources/appsec/)、[HTTP 通知插件](https://docs.crowdsec.net/docs/next/local_api/notification_plugins/http/)、[Profiles](https://docs.crowdsec.net/docs/next/local_api/profiles/intro/)、[CrowdSec 配置与 WAL](https://docs.crowdsec.net/docs/next/configuration/crowdsec_configuration/)、[Firewall Bouncer](https://docs.crowdsec.net/u/bouncers/firewall/)、[WebUI 上游](https://github.com/TheDuffman85/crowdsec-web-ui)。

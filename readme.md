# CrowdSec 防护管理中心

面向 1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）和宿主机 Nginx/OpenResty 的管理工具。提供 CrowdSec 安装、日志检测规则、Firewall Bouncer、AppSec 接入、WebUI、Telegram 告警与日常运维菜单。

## 开始使用

下载完整仓库后运行，整个 `lib/` 目录必须与脚本一起保留：

```bash
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
| 8 | 只读诊断后选择补齐基础规则、修复 HTTP 日志采集和启用指标 |
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

配置写入实际启用的 `crowdsec_service.acquisition_dir`（读取 `config.yaml` 与 `.local`），校验并重启后检查 `127.0.0.1:7422` 是否存在监听。监听未出现时返回失败并提示查看日志；存在监听也只代表引擎连接入口可用，网站接入还需单独验证。已有外部 AppSec 数据源时不会创建重复监听。

接入菜单显示已安装且命令可用的宿主机 Bouncer，并提供 `3：接入已有 Docker Web Bouncer`、`4：首次安装 Web Bouncer`。首次安装也可单独执行 `sudo bash install-crowdsec-1panel.sh --install-web-bouncer`，前提是 AppSec 已监听。Docker 已有接入会核对 `host` 网络、有效 CrowdSec 请求调用和真实 bind/volume 配置挂载，备份后修改 `APPSEC_URL`、执行 `nginx -t` 并重载。首次安装生成的持久化配置也支持该入口。

| 环境 | 首次安装适配与前提 |
| --- | --- |
| 1Panel OpenResty | 支持已确认的 `1pwaf/data/conf/waf.conf` 布局及 `host` 网络；从实际 Mounts 定位配置，不依赖固定宿主机目录 |
| 科技lion LDNMP | 上游默认 `nginx:alpine` 不具备 Lua 能力，脚本会解释原因并停止；已有兼容 Lua 运行时、HTTP 层 `conf.d` 持久化入口及 `host` 网络时可安装 |
| Nginx Proxy Manager | 检测实际 Lua 能力，使用持久化 `/data/nginx/custom/http_top.conf`；要求 `host` 网络，存在 `satisfy any` 或其他 Lua 请求钩子时先人工处理冲突 |
| 宿主机 Nginx/OpenResty | Debian/Ubuntu 标准软件包环境使用官方 Bouncer 包；要求 CrowdSec apt 候选版本和已准备好的依赖，安装计划涉及其他软件包时停止，保留现有服务 |

容器安装使用 SHA256 校验的官方 OpenResty Bouncer `v1.2.3` 和 lua-resty-http `v0.17.1`。库、模板、私有配置及钩子保存在同一持久化挂载中，并注册独立 Bouncer 账号。1Panel 原初始化、请求、worker 脚本先执行，再调用 CrowdSec，保留日志钩子、共享字典和原 Lua 搜索路径。使用 `loadfile` 后直接调用 Lua 函数以兼容 WAF 的 `ngx.exit`/协程行为；CrowdSec 及 HTTP 依赖单独命名，避免替换原 WAF 的 `resty.http`。

Firewall Bouncer 支持 IP 封禁，但[不支持 AppSec HTTP 转发](https://docs.crowdsec.net/u/bouncers/firewall/)。Docker 的 `host` 网络共享宿主机网络，可以连接宿主机 `127.0.0.1:7422`；bridge 等网络下该地址指向容器自身，脚本会停止自动接入并提示配置私有网络。AppSec 端口保持本机监听。

未知 Lua 钩子、子级请求钩子覆盖、只读/非持久化挂载以及网络不满足前提时会停止安装。安装失败恢复原配置；确认原运行配置重载成功后才移除资源并注销新账号。恢复重载失败则保留资源和账号，记录 `recovery-required` 供后续恢复，避免删除仍被运行中 worker 使用的依赖。`--appsec-status` 同时检查数据源、监听、容器网络及请求处理组件。

验证方式：菜单 `3 → 11` 或 `--verify-appsec` 输入自己管理的网站根地址。明确确认后发送带唯一标识的 GET `/.env` 请求，读取 HTTP 状态及 AppSec 指标，输出通过（返回 0）、失败（1）或无法判断（2）。通过条件包括 403、Processed/Blocked 增量和 `crowdsecurity/vpatch-env-access` 命中；累计增量可能来自其他请求，仍需按唯一标识关联日志。优先从另一台设备验证，单独一个 403 不能证明 AppSec 生效。

停用入口只处理本工具数据源和记录过的 Web Bouncer 接入，并恢复接入前的 `APPSEC_URL`；外部配置和 AppSec 集合保留。管理的 Docker 接入按容器名称与实际持久化挂载核对，支持容器重建后安全恢复；手工改过地址、挂载或网络时先停止并要求核对。失败时恢复配置并重载已变更的服务/容器。未由本工具接入的容器和外部代理需要自行同步停用转发。

`3 → 13` 或 `--remove-web-bouncer` 撤销本工具首次安装的原生容器 Bouncer：核对挂载和文件内容，先恢复原网站/WAF 配置并重载，再注销账号、清理资源。清理失败保留 `cleanup-pending` 记录，可重复执行；已经删除的账号/资源不会阻止重试。手工修改过的配置或资源会保留并要求核对。宿主机官方软件包的撤销请按[官方 Nginx](https://docs.crowdsec.net/u/bouncers/nginx/)或 [OpenResty](https://docs.crowdsec.net/u/bouncers/openresty/)文档进行，先确认网站正常再卸载核心。

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

先查看 `sudo cscli metrics` 的 Acquisition Metrics。如果没有 Web 文件来源，在确认网站产生新访问日志后，核对实际文件路径与采集配置；1Panel 的 `log/` 与 `logs/`、`www/sites/`、`1panel/www/sites/` 与 `data/sites/` 是不同目录。更新仓库本身不会修改服务器上已有的采集 YAML；可通过下面的修复入口补齐，再访问网站观察读取和解析计数。

若只有 SSH journal 来源，且 `syslog-logs` 成功、`sshd-logs` 全部未解析，说明外层日志格式已识别，内部消息没有匹配已加载的 SSH 事件解析器。`Accepted password` 属于成功登录，不能用失败登录解析器是否匹配来判断 SSH 防护是否失效。核查时官方 `sshd-logs` 已支持 `sshd-session`，但 `sshd-success-logs` 的过滤器仍仅匹配 `sshd`；因此新版 OpenSSH 的成功登录和普通会话消息可能显示为未解析。应结合日志样本与 `cscli explain --file /path/to/sample.log --type syslog` 判断，不应把所有会话消息强行转换成失败登录事件。

真实 IP 与低解析率的只读核查可执行 `sudo bash tools/diagnose-detection.sh`。追加 `--window 10` 可采样 10 秒 counter 指标增量（允许 1–60 秒）；重置、新增或消失的序列标记为无法判断，并发流量不能归因到某一次请求。脚本输出当前指标、白名单命中原因、宿主机/容器的 real-IP 配置和实际挂载 HTTP 日志客户端 IP（标准/NPM 格式），并用最近 SSH 失败样本执行离线 `cscli explain`；另提供明确标记的离线 `sshd-session` 兼容性样本。读取 `config.yaml` 与 `.local` 中实际启用的 Prometheus 端点；默认配置路径为 `/etc/crowdsec/config.yaml`，自定义可通过 `CROWDSEC_CONFIG` 指定。SSH 检查最近 24 小时内最多 1,000 条 journal。没有失败样本不能证明 SSH 防护失效，日志首字段不是 IP 时需按实际 log_format 判断。该入口不修改采集、白名单或服务；AppSec 的真实网站请求验证仍使用 `--verify-appsec`。若来源列表只有 unknown 的白名单计数，应先查看原始指标的 name/reason，不应因此删掉日志采集。Cloudflare Tunnel 的信任范围应按实际代理来源设置，配置证据和日志首字段不能替代同一次访客请求的 IP 对照。

防火墙执行 CAPI 社区名单、日志检测产生本机决策、AppSec 检查在线请求分别有独立指标；社区名单有阻断并不能证明本机 Web 日志已接入，日志解析率也不能单独证明 AppSec 是否生效。

### 修复日志采集路径

菜单 `8` 确认应用修复时，会同时检查日志目录和 Docker 实际挂载；也可单独执行：

```bash
sudo bash install-crowdsec-1panel.sh --repair-logs
```

修复扫描预设目录，以及运行中的 Nginx/OpenResty 镜像的 `/www`、`/www/sites`、`/var/log/nginx` 挂载和 NPM 的 `/data`、`/data/logs` 挂载。它按映射找到宿主机上实际存在的 HTTP 日志，包括 `/opt/1panel/1panel/www` 和其他自定义 Source。Docker 不可用时提示并仅扫描预设；忽略不相关的挂载和被子挂载遮住的旧文件。自定义镜像名或其他容器日志布局需要手工核对。

修复读取 `config.yaml` 与 `.local` 合并后的 `crowdsec_service.acquisition_path`、`acquisition_dir`，跳过已被现有配置采集的同一文件（含 `filename`、通配符和符号链接别名）。新增日志写入实际 `acquisition_dir` 下的 `crowdsec-1key-log-repair.yaml`，默认是 `/etc/crowdsec/acquis.d/crowdsec-1key-log-repair.yaml`；原有采集文件、标签和其他数据源保留。日志处理服务或目录采集未启用，或修复文件本身是符号链接时，会停止并说明原因。

单独修复会列出待补齐文件并请求确认；备份后写入，运行 `crowdsec -t`，成功后重启 CrowdSec，失败则恢复配置。重复执行跳过已采集文件；没有新增时单独修复不重启服务。修复只添加当前实际存在的日志文件，新建站点后可再次执行；它不改变日志格式、权限、已有过滤规则，也不会把不存在或无法读取的日志描述为修复成功。完成后访问网站，用 `cscli metrics` 核实计数。

管理员 IP 从 `SSH_CLIENT` 或 `SSH_CONNECTION` 提取，无法识别时手工输入；白名单包含回环和常见内网网段。手动封禁接受 IPv4/IPv6，会规范化地址并拒绝封禁当前 SSH IP。时长使用 Go duration，如 `4h`、`24h`、`168h`；7 天应填写 `168h`。

Docker 转发流量需要正确的防火墙链/钩子。修复入口保留官方软件包配置及其他凭据，在 `.yaml.local` 中更新 LAPI 地址和密钥；iptables 模式检测到 `DOCKER-USER` 时加入对应链。核验会检查 IPv4、IPv6、配置中的 nftables 表及默认 IPSet 资源，但仍需在实际主机上确认 Bouncer 拉取和流量阻断。

### 按可信 CDN/代理还原真实访客 IP

若访问日志首字段是 Cloudflare 节点 IP，且 `nginx -T` 没有真实 IP 配置，单独设置 `proxy_set_header X-Real-IP` 不能改变日志和 Web Bouncer 使用的 `$remote_addr`。Docker 部署可运行以下入口，或选择菜单 `3 → 14`：

```bash
sudo bash install-crowdsec-1panel.sh --repair-real-ip
```

入口先列出现有 `real_ip_header`、可信来源条目数和候选 Header，再要求选择实际接入方式。Cloudflare 公网节点直接接入使用官方 HTTPS IPv4/IPv6 网段和固定 `CF-Connecting-IP`；配置线索仅用于提示，不等于自动确认网络拓扑。其他 CDN/反向代理需明确输入上游约定的 Header 和可信 IP/CIDR。不会从请求头内容或 Header 出现顺序推断可信来源。

上游不确定时，选择接入菜单 `3`，或单独执行 `sudo bash install-crowdsec-1panel.sh --diagnose-real-ip`（管理菜单 `3 → 16`）。独立诊断不要求 CrowdSec 核心、curl 或 HTTP real-IP 模块，只读取当前容器配置、挂载和近期日志；支持标准 Nginx 首字段与 NPM `[Client …]`，显示最近日志时间，排除 stream 日志。每份日志只读取最后最多 64KiB / 20 行，最多检查 12 份，无法识别的格式明确标记为待核对。它不输出完整请求或 Header 值，也不会访问站点、下载 CDN 网段、写配置或重载。

诊断给出唯一查询参数和按实际日志路径生成的关联命令。请从另一台设备访问实际站点正常页面，将该次日志 IP 与设备公网 IP 对照，再检查 CDN 面板和代理部署。已有 real-IP 可能改写日志中的客户端字段，它不等于原始 TCP 对端；配置默认信任列表、DNS 与 Header 名称不能单独证明正在使用某 CDN。确认后重新选择修复方式；未确认时保持只读。选择 `4：已确认客户端直连` 时不新增或自动删除真实 IP 配置，已有规则保留，必要时单独使用撤销入口。

支持作为 IP Header 的候选：`X-Forwarded-For`、`X-Real-IP`、`X-Forwarded`、`Forwarded-For`、`True-Client-IP`、`Client-IP`、`Ali-CDN-Real-IP`、`CDN-Src-IP`、`CDN-Real-IP`、`CF-Connecting-IP`、`X-Cluster-Client-IP`、`WL-Proxy-Client-IP`、`Proxy-Client-IP`。非标准字段必须由上游明确保证内容为客户端 IP 或约定的地址链；支持其名称不代表认可来源。`Forwarded` 的 RFC 格式不能直接交给 Nginx real-IP 模块，应在可信上游规范化成 IP Header。

修复要求 HTTP real-IP 模块、已加载入口和可写持久化目录挂载。一般 Nginx/OpenResty 在 HTTP include 目录创建管理文件；NPM 则保留并合并 `/data/nginx/custom/server_proxy.conf`，作用于加载该入口的全部 Proxy Host。在 NPM 站点层明确设置可信网段，替代继承的 HTTP 层信任列表；保留原 HTTP 配置、`http_top.conf` 及 Web Bouncer。已有站点/自定义真实 IP 指令、同名未管理文件、单文件 bind 或手工修改过的管理文件会导致停止并要求核对，不自动覆盖。

确认前显示 Header、全部可信网段和作用范围。自定义模式拒绝空网段、全网信任和过宽的内网网段；内网需 IPv4 `/24` 或更窄、IPv6 `/64` 或更窄，loopback 需单个地址。Header 缺失、无法提取有效 IP 或连接来源不可信时，Nginx 保留连接来源 IP，不尝试其他 Header；`X-Forwarded-For` 从右向左跳过可信代理。确认后备份、校验并重载，失败恢复。重复执行可更新配置；`--restore-real-ip` 或菜单 `3 → 15` 恢复原自定义文件内容及权限，原文件不存在时移除生成文件。旧版 Cloudflare 管理记录兼容，核心卸载要求先撤销。

Cloudflare 模式仅信任官方公网节点，不自动信任 loopback 或内网代理。Cloudflare Tunnel 需核对其连接来源和 Header 后再选择自定义模式；宿主机 Nginx 尚无此自动修复适配器。修复后从外部访问当前 `server_name` 对应站点，用独特查询参数关联该次请求的新访问日志，核对访问设备公网 IP。日志中的 IP 与 Web Bouncer 使用的 IP 仍需在实际部署中核验；旧日志和累计计数不会改写。保留 CDN 白名单、SSH 采集和现有 WAF。

`tools/diagnose-detection.sh` 的 SSH 离线失败认证样本成功解析，只能证明该样本兼容；大量正常会话日志未解析不等于防护失效。AppSec 验证需同时检查 HTTP 响应与规则计数增量，经过 Cloudflare 返回 403 本身不能证明请求到达本机 AppSec。

`--verify-appsec` 会在发送请求前提示 Self-Report 风险并要求确认；取消或 EOF 不发送验证请求。该命令从当前主机访问 `/.env`，即使使用公网域名，也可能绕回本机并产生针对本机地址的告警。推荐从另一台设备验证；定时健康检查使用正常页面或专用 `/healthz`。验证入口不删除历史告警、封禁决策或修改白名单。

## WebUI、Telegram 与更新

WebUI 从 `ghcr.io/theduffman85/crowdsec-web-ui:latest` 拉取后，以实际镜像 ID 固定本次部署。使用宿主机网络、端口默认 `3000`；上游不支持设置 loopback 监听，因此部署前须明确确认已通过现有防火墙限制端口并配置 HTTPS 反代。SSH 隧道本身不会隐藏公开端口。脚本显式启用认证，首次访问仍需创建管理员。HTTP `/api/health`、容器与独立 LAPI 凭据均就绪后，才报告部署就绪或注销轮换前账号；这些检查不能替代 WebUI 实际同步验证。拉取失败保留已有部署，应用检查失败尝试恢复原镜像和配置。数据在 `/opt/crowdsec-web-ui`。

Telegram 使用独立名称 `crowdsec_1key_telegram`，读取实际 `notification_dir`、`api.server.profiles_path` 及优先执行的 `.local` profiles。默认通知文件为 `/etc/crowdsec/notifications/crowdsec-1key-telegram.yaml`。配置时显示将调整的 profile 文件，通知覆盖其中匹配的告警，保留既有通道；停用只移除本工具通道。官方 `cscli notifications test` 会向所配置机器人发送真实消息；确认测试失败会返回非零，并说明配置已加载但投递验证失败。出站请求不需 Telegram 来源白名单。旧 `http_default` 通道不会自动删除，需核对是否重复通知。

默认规则更新使用服务器时区每天 `03:30`，写入 `/etc/cron.d/crowdsec-autoupdate`。需 `flock`、Python3/PyYAML 和运行中的 cron/crond。独立维护程序安装到 `/opt/crowdsec-1key-maintenance`，不依赖项目 checkout 一直存在；手动 Hub 更新、移除和集合安装共享 `/run/lock/crowdsec-1key-hub.lock`。更新/移除先快照，再执行、校验和重载，失败尝试恢复；命令输出与结果记录在 `/var/log/crowdsec-1key-hub.log`，未完整恢复的快照保留并打印路径。未知归属或软链接的维护目录不会覆盖；软链接形式的 Hub 根/祖先或 Hub 内部文件在修改前拒绝，需核对后配置真实目录路径。不会恢复 Hub 外的非托管自定义规则；外部工具在更新期间改动 Hub 文件无法准确归因，维护时请避免并发。集合首次安装仍由官方 Hub 管理，配置备份不等于安装事务回滚。CAPI 名单由引擎自身同步。

AppSec 正文/故障策略可用 `--appsec-policy` 或菜单 `3 → 17` 检查并明确设置。支持标准宿主机 Bouncer，或输入 `docker` 选择持久化容器配置；不修改原 `APPSEC_URL`。`APPSEC_DROP_UNREADABLE_BODY=true` 会拒绝无法分析的正文，`APPSEC_FAILURE_ACTION=deny` 会按上游故障策略拒绝请求，需先评估业务。真实验证发现官方 OpenResty Bouncer 1.2.3 在连接失败时的 deny 页面可能返回 HTTP 200，需结合响应内容及后端是否收到请求确认阻断。保留默认值直到明确选择，修改前备份、校验重载，原生安装记录同步更新以保留撤销能力。

已有 Web Bouncer 接入、停用和状态检查会检查 `.local` 覆盖、重复 AppSec 键以及非规范 `APPSEC_URL` 赋值，遇到未明确解释的覆盖会停止；容器内无法检查的 `.local` 也不会当成不存在。请先核对配置并规范为 `APPSEC_URL=...`，不要为了通过检查直接删掉已有覆盖。

`--self-report-status`（菜单 `5 → 9`）只读核对回环、本机接口和明确记录的地址对应的告警/决策；不查询外部服务猜出口 IP，也不自动解封或加白。NAT 的自身公网地址可明确记录到 `/etc/crowdsec/crowdsec-1key-own-addresses.json`，格式为 IP 字符串列表，例如 `["203.0.113.10"]`，实际使用自己的地址。手动封禁拒绝回环、未指定地址、本机接口、管理员 parser 白名单地址及这些记录，包括 IPv4-mapped IPv6。

`--admin-allowlist`（菜单 `5 → 8`）管理明确选择的单个管理员 IP。中央 AllowList 与 parser whitelist 不同，**会使来源跳过 AppSec**并影响决策过滤；不会自动迁移私网或代理网段。需要支持 AllowLists 的 CrowdSec 版本。自己的公网出口地址无法仅由本机接口推出，必须核对并明确记录。

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
| `--install-appsec` | 配置 AppSec、检查部署方式并接入已有宿主机/Docker Web Bouncer |
| `--appsec-status` | 只读检查 AppSec 数据源、监听、容器接入组件与指标 |
| `--verify-appsec` | 确认后以标记请求检查 HTTP/AppSec 指标，返回通过/失败/无法判断 |
| `--appsec-policy` | 检查并明确设置宿主机/容器 AppSec 正文与故障策略 |
| `--disable-appsec` | 停用本工具 AppSec |
| `--enable-cron` | 每天 03:30 更新 Hub |
| `--clean-redundant` | 查看节点并选择注销，保留受保护账号 |
| `--repair-bouncer` | 修复 Firewall Bouncer 连接配置 |
| `--self-report-status` | 只读核对已知自身地址的告警和决策 |
| `--admin-allowlist` | 明确管理中央管理员 AllowList（旁路 AppSec） |
| `--repair-logs` | 按实际日志与 Docker 挂载补齐 HTTP 采集，保留现有配置 |
| `--repair-real-ip` | 按可信 CDN/代理、指定 Header 和网段修复 Docker Nginx/OpenResty/NPM 真实 IP |
| `--diagnose-real-ip` | 上游不确定时只读检查配置、挂载日志并提供外部请求核对指引 |
| `--restore-real-ip` | 撤销本工具的真实 IP 配置 |
| `--reset-baseline`、`--reset-56` | 补齐基础集合；兼容旧参数，保留自定义/AppSec，不保证固定场景数 |
| `--uninstall-waf` | 确认后移除已知 Web 日志扩展 |
| `--check-clean` | 只读残留检查 |
| `--deep-clean`、`--purge`、`--uninstall` | 确认后卸载和删除数据 |
| `--telegram` | Telegram 管理菜单 |
| `--telegram-test` | 官方通知插件测试 |
| `--optimize` | 诊断后选择修复日志采集、基础规则与指标配置 |
| `--enable-wal` | 确认本地 SQLite 后启用官方 WAL 配置 |
| `--status` | 只读健康检查 |
| `--help`、`-h` | 帮助，不需要 root |

每次仅指定一个操作。命令行仍保留必要的输入与确认，不能直接当作无人值守部署接口。

## 备份、失败恢复与卸载

配置修改前备份保存在 `/var/backups/crowdsec-1key/change.*`，目录权限为 `700`，含凭据的配置文件权限为 `600`。结构化 YAML 编辑保留无关配置值，可能重排格式或去除注释；原始文件保留在备份中。

配置校验失败不重启核心；服务启动失败会恢复配置并尝试恢复原服务。Hub 集合下载/安装不属于配置文件回滚范围；失败时保留诊断输出，修复后可重新执行。

卸载需要明确确认，会停止服务、卸载检测到的软件包并删除 CrowdSec 数据和本工具 WebUI。若仍存在宿主机 Web Bouncer 集成，需先按上游文档移除集成并验证网站，否则核心卸载会中止。发行版、包管理器、配置与防火墙检查在停止服务前预检。防火墙状态分为存在、确认不存在、无法判断；无法检查时中止卸载，停止服务后仍有资源也保留配置。软件包移除前保留有效自定义资源名称用于复查，不能只检查默认表名。本工具的独立 Hub 维护程序会随明确卸载清理，备份、系统日志及软件源不自动删除；其他容器和不属于本工具的目录不进行广泛匹配清理。

## 验证与官方参考

```bash
bash -n install-crowdsec-1panel.sh
shellcheck install-crowdsec-1panel.sh
python3 -m pip install -r tests/requirements.txt
python3 -m unittest discover -s tests -v

# 可选：下载并解压官方 CrowdSec Linux 发布包后运行真实引擎检查
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1
```

全功能审查见 [审查报告](docs/feature-audit-2026-10-11.md)，该报告记录优化前基线；最新优化与部署验证边界详见 [验证记录](docs/verification.md)。真实引擎检查会下载 Hub 集合，在临时目录和 loopback 端口运行，不安装系统服务、不修改防火墙、不向真实 Telegram 发送消息。

参考：[AppSec 数据源](https://docs.crowdsec.net/docs/next/log_processor/data_sources/appsec/)、[HTTP 通知插件](https://docs.crowdsec.net/docs/next/local_api/notification_plugins/http/)、[Profiles](https://docs.crowdsec.net/docs/next/local_api/profiles/intro/)、[CrowdSec 配置与 WAL](https://docs.crowdsec.net/docs/next/configuration/crowdsec_configuration/)、[Firewall Bouncer](https://docs.crowdsec.net/u/bouncers/firewall/)、[WebUI 上游](https://github.com/TheDuffman85/crowdsec-web-ui)。

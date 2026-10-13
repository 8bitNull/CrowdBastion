# 日志、防火墙与真实 IP 排查参考

[返回 README](../readme.md) · [使用说明](usage-guide.md) · [命令参考](cli-reference.md)

用于日志未采集、解析率异常、代理来源识别和防火墙证据排查。首次安装步骤见使用说明；中转节点的流量路径另见[中转模式](relay-mode.md)。

## 目录

- [日志发现与采集](#日志发现与采集)
- [解析成功率为 0% 的排查](#解析成功率为-0-的排查)
- [修复日志采集路径](#修复日志采集路径)
- [按可信 CDN/代理还原真实访客 IP](#按可信-cdn代理还原真实访客-ip)
- [正常请求的真实 IP 核验](#正常请求的真实-ip-核验)
- [管理员 AllowList 与 Self-Report](#管理员-allowlist-与-self-report)

## 日志发现与采集

安装和修复读取实际启用的采集目录及 Docker 挂载，将当前存在且尚未采集的日志写入 `crowdsec-1key-log-repair.yaml`。以下路径是发现日志的候选，不会全部写进运行配置：

| 环境 | 常见日志路径 |
| --- | --- |
| 1Panel OpenResty | `/opt/1panel/apps/openresty/openresty/log/{access,error}.log`、`/opt/1panel/www/sites/*/log/{access,error}.log`、`/opt/1panel/1panel/www/sites/*/log/{access,error}.log`；兼容旧版 `logs/` 和 `data/sites/` 布局 |
| 科技lion LDNMP | 已核对上游默认 `/home/web/log/nginx/access.log`、`error.log`；配置兼容该目录及下一级目录的 `.log` 文件 |
| 宿主机 Nginx | `/var/log/nginx/*.log` |
| 科技lion NPM | 已核对上游默认宿主机目录 `/home/docker/npm/data/logs/`，采集下述 HTTP 日志 |
| 其他 NPM 部署 | 预设候选目录 `/opt/npm/data/logs/`、`/opt/nginx-proxy-manager/data/logs/`、`/data/logs/`、`/var/log/nginx-proxy-manager/`；须按实际 Docker 挂载调整 |
| SSH 认证 | `/var/log/auth.log`、`/var/log/secure` |

Nginx、NPM、系统日志分别使用 `nginx`、`nginx-proxy-manager`、`syslog` 标签。表中的 `{access,error}` 表示两个独立文件，生成的 YAML 不使用花括号展开。1Panel 只采集上述 HTTP access/error 日志，避免把 TCP/UDP 的 `stream-access.log` 或 PHP 日志交给 HTTP 解析器。采集不重复列出已被通配符覆盖的文件。

实际日志位置、格式、自定义挂载目录和仅使用 journald 的系统需要按部署调整。用 `cscli metrics` 核查采集和解析；存在配置文件不等于实际采集成功。新建站点或更改日志挂载后，应重新执行 `--repair-logs`；当前修复记录使用发现的具体文件路径。

若旧 `web-sites.yaml` 的 YAML 内容与本工具原始预设完全一致，安装/修复会在备份后迁移到实际日志采集，消除不存在路径的告警和与软件包 SSH 采集的重叠。修改过的用户配置保留。修复还会去掉本工具修复文件中已被其他采集配置覆盖的条目；失败时一起恢复旧预设和修复文件。重复安装保留管理员白名单中的原有 IP、CIDR、表达式，以及已有 Firewall Bouncer 的后端类型。

`--check-logs` 或菜单 `4 → 2 → 1` 只读列出漏采、待调整和重复采集；结合容器有效 HTTP 日志指令与实际挂载，以及宿主机 nginx/openresty 的默认 `-T` 配置发现自定义日志。发现待调整项目返回 `2`，异常/重复采集返回 `1`；修复使用 `--repair-logs`。重复安装只补缺失软件包和规则，已有核心保留软件源及版本；配置内容没有变化且服务已运行时跳过重启。保留已有指标端口，修改前核对占用进程。

1Panel 的站点日志应结合容器的 `nginx -T` 和 `docker inspect` 挂载确定，不能仅按域名推定宿主机目录。用户部署中已确认 `/www` 的宿主机 Source 为 `/opt/1panel/1panel/www`，所以容器日志 `/www/sites/<站点目录>/log/access.log` 对应 `/opt/1panel/1panel/www/sites/<站点目录>/log/access.log`。

站点配置了自己的 `access_log` 时，全局 `/var/log/nginx/access.log` 不一定包含该站点请求。其他安装目录仍需按挂载 Source 调整预设。

上游依据：[科技lion 安装脚本](https://github.com/kejilion/sh/blob/main/kejilion.sh)、[LDNMP Compose](https://github.com/kejilion/docker/blob/main/LNMP-docker-compose-10.yml)、[Nginx 日志配置](https://github.com/kejilion/nginx/blob/main/nginx10.conf)。

默认 LDNMP 将 `/home/web/log/nginx` 挂载到容器 `/var/log/nginx`；访问日志配置了 `buffer=512k flush=10s`，低流量下新访问可能需要约 10 秒才写入文件。

[NPM 官方部署示例](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/docs/src/setup/index.md) 使用 `./data:/data`，所以容器 `/data/logs` 不等于宿主机 `/data/logs`。科技lion 的 NPM 将 `/home/docker/npm/data` 挂载到 `/data`，其宿主机日志路径可确认；其他部署应使用 `sudo docker inspect <容器名> --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'` 查看实际挂载。

若 `/data` 对应 `/srv/npm/data`，采集应写 `/srv/npm/data/logs/...`；命名卷使用 Docker 返回的实际 Source，并按部署确认可读性。

NPM 根据[官方模板](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/templates)仅预设 HTTP 日志：`*host*_access.log`、`*host*_error.log`（代理、重定向、dead/default host）、`fallback_http_access.log`、`fallback_http_error.log`、`letsencrypt-requests_access.log`、`letsencrypt-requests_error.log`。

不再用整个目录的 `*.log`，避免采集格式不同的 `stream-*`、`fallback_stream_*` 和主进程 `fallback_error.log`。自定义文件名需要自行添加采集。

## 解析成功率为 0% 的排查

先查看 `sudo cscli metrics` 的 Acquisition Metrics。如果没有 Web 文件来源，在确认网站产生新访问日志后，核对实际文件路径与采集配置；1Panel 的 `log/` 与 `logs/`、`www/sites/`、`1panel/www/sites/` 与 `data/sites/` 是不同目录。更新仓库本身不会修改服务器上已有的采集 YAML；可通过下面的修复入口补齐，再访问网站观察读取和解析计数。

若只有 SSH journal 来源，且 `syslog-logs` 成功、`sshd-logs` 全部未解析，说明外层日志格式已识别，内部消息没有匹配已加载的 SSH 事件解析器。`Accepted password` 属于成功登录，不能用失败登录解析器是否匹配来判断 SSH 防护是否失效。核查时官方 `sshd-logs` 已支持 `sshd-session`，但 `sshd-success-logs` 的过滤器仍仅匹配 `sshd`；因此新版 OpenSSH 的成功登录和普通会话消息可能显示为未解析。

应结合日志样本与 `cscli explain --file /path/to/sample.log --type syslog` 判断，不应把所有会话消息强行转换成失败登录事件。

真实 IP 与低解析率的只读核查可执行 `sudo bash tools/diagnose-detection.sh`。追加 `--window 10` 可采样 10 秒 counter 指标增量（允许 1–60 秒）；重置、新增或消失的序列标记为无法判断，并发流量不能归因到某一次请求。脚本输出当前指标、白名单命中原因、宿主机/容器的 real-IP 配置和实际挂载 HTTP 日志客户端 IP（标准/NPM 格式），并用最近 SSH 失败样本执行离线 `cscli explain`；另提供明确标记的离线 `sshd-session` 兼容性样本。

读取 `config.yaml` 与 `.local` 中实际启用的 Prometheus 端点；默认配置路径为 `/etc/crowdsec/config.yaml`，自定义可通过 `CROWDSEC_CONFIG` 指定。SSH 检查最近 24 小时内最多 1,000 条 journal。没有失败样本不能证明 SSH 防护失效，日志首字段不是 IP 时需按实际 log_format 判断。该入口不修改采集、白名单或服务；AppSec 的真实网站请求验证仍使用 `--verify-appsec`。

若来源列表只有 unknown 的白名单计数，应先查看原始指标的 name/reason，不应因此删掉日志采集。Cloudflare Tunnel 的信任范围应按实际代理来源设置，配置证据和日志首字段不能替代同一次访客请求的 IP 对照。

防火墙执行 CAPI 社区名单、日志检测产生本机决策、AppSec 检查在线请求分别有独立指标；社区名单有阻断并不能证明本机 Web 日志已接入，日志解析率也不能单独证明 AppSec 是否生效。

## 修复日志采集路径

菜单 `4 → 5 → 3` 选择 HTTP 日志修复后，会检查日志目录和 Docker 实际挂载，汇总确认后应用；也可使用菜单 `4 → 2 → 4` 或单独执行：

```bash
sudo bash crowdbastion.sh --repair-logs
```

修复扫描预设目录，以及运行中的 Nginx/OpenResty 镜像的 `/www`、`/www/sites`、`/var/log/nginx` 挂载和 NPM 的 `/data`、`/data/logs` 挂载。它按映射找到宿主机上实际存在的 HTTP 日志，包括 `/opt/1panel/1panel/www` 和其他自定义 Source。Docker 不可用时提示并仅扫描预设；忽略不相关的挂载和被子挂载遮住的旧文件。自定义镜像名或其他容器日志布局需要手工核对。

修复读取 `config.yaml` 与 `.local` 合并后的 `crowdsec_service.acquisition_path`、`acquisition_dir`，跳过已被现有配置采集的同一文件（含 `filename`、通配符和符号链接别名）。新增日志写入实际 `acquisition_dir` 下的 `crowdsec-1key-log-repair.yaml`，默认是 `/etc/crowdsec/acquis.d/crowdsec-1key-log-repair.yaml`；原有采集文件、标签和其他数据源保留。

日志处理服务或目录采集未启用，或修复文件本身是符号链接时，会停止并说明原因。

单独修复会列出待补齐文件并请求确认；备份后写入，运行 `crowdsec -t`，成功后重启 CrowdSec，失败则恢复配置。重复执行跳过已采集文件；没有新增时单独修复不重启服务。修复只添加当前实际存在的日志文件，新建站点后可再次执行；它不改变日志格式、权限、已有过滤规则，也不会把不存在或无法读取的日志描述为修复成功。完成后访问网站，用 `cscli metrics` 核实计数。

管理员 IP 从 `SSH_CLIENT` 或 `SSH_CONNECTION` 提取，无法识别时手工输入；白名单包含回环和常见内网网段。手动封禁接受 IPv4/IPv6，会规范化地址并拒绝封禁当前 SSH IP。时长使用 Go duration，如 `4h`、`24h`、`168h`；7 天应填写 `168h`。

Docker 转发流量需要正确的防火墙链/钩子。修复入口保留官方软件包配置及其他凭据，在 `.yaml.local` 中更新 LAPI 地址和密钥；iptables 模式检测到 `DOCKER-USER` 时加入对应链。核验会检查 IPv4、IPv6、配置中的 nftables 表及默认 IPSet 资源，但仍需在实际主机上确认 Bouncer 拉取和流量阻断。

## 按可信 CDN/代理还原真实访客 IP

若访问日志首字段是 Cloudflare 节点 IP，且 `nginx -T` 没有真实 IP 配置，单独设置 `proxy_set_header X-Real-IP` 不能改变日志和 Web Bouncer 使用的 `$remote_addr`。Docker 部署可运行以下入口，或选择菜单 `4 → 2 → 3 → 1 → 2`：

```bash
sudo bash crowdbastion.sh --repair-real-ip
```

入口先列出现有 `real_ip_header`、可信来源条目数和候选 Header，再要求选择实际接入方式。Cloudflare 公网节点直接接入默认使用官方 HTTPS IPv4/IPv6 网段和 `CF-Connecting-IP`；若已关联请求确认该 Header 缺失、XFF 链可靠，可明确选择接入类型 `5`，使用同样官方网段和 `X-Forwarded-For`，从右向左递归解析。不会自动尝试其他 Header，也不扩大信任范围。配置线索仅用于提示，不等于自动确认网络拓扑。其他 CDN/反向代理需明确输入上游约定的 Header 和可信 IP/CIDR。

上游不确定时，选择接入菜单 `3`，或单独执行 `sudo bash crowdbastion.sh --diagnose-real-ip`（管理菜单 `4 → 2 → 3 → 1 → 1`）。独立诊断不要求 CrowdSec 核心、curl 或 HTTP real-IP 模块，只读取当前容器配置、挂载和近期日志；支持标准 Nginx 首字段与 NPM `[Client …]`，显示最近日志时间，排除 stream 日志。

每份日志只读取最后最多 64KiB / 20 行，最多检查 12 份，无法识别的格式明确标记为待核对。它不输出完整请求或 Header 值，也不会访问站点、下载 CDN 网段、写配置或重载。

诊断给出唯一查询参数和按实际日志路径生成的关联命令。请从另一台设备访问实际站点正常页面，将该次日志 IP 与设备公网 IP 对照，再检查 CDN 面板和代理部署。已有 real-IP 可能改写日志中的客户端字段，它不等于原始 TCP 对端；配置默认信任列表、DNS 与 Header 名称不能单独证明正在使用某 CDN。确认后重新选择修复方式；未确认时保持只读。选择 `4：已确认客户端直连` 时不新增或自动删除真实 IP 配置，已有规则保留，必要时单独使用撤销入口。

支持作为 IP Header 的候选：`X-Forwarded-For`、`X-Real-IP`、`X-Forwarded`、`Forwarded-For`、`True-Client-IP`、`Client-IP`、`Ali-CDN-Real-IP`、`CDN-Src-IP`、`CDN-Real-IP`、`CF-Connecting-IP`、`X-Cluster-Client-IP`、`WL-Proxy-Client-IP`、`Proxy-Client-IP`。

非标准字段必须由上游明确保证内容为客户端 IP 或约定的地址链；支持其名称不代表认可来源。`Forwarded` 的 RFC 格式不能直接交给 Nginx real-IP 模块，应在可信上游规范化成 IP Header。

修复要求 HTTP real-IP 模块、已加载入口和可写持久化目录挂载。一般 Nginx/OpenResty 在 HTTP include 目录创建管理文件；NPM 则保留并合并 `/data/nginx/custom/server_proxy.conf`，作用于加载该入口的全部 Proxy Host。在 NPM 站点层明确设置可信网段，替代继承的 HTTP 层信任列表；保留原 HTTP 配置、`http_top.conf` 及 Web Bouncer。已有站点/自定义真实 IP 指令、同名未管理文件、单文件 bind 或手工修改过的管理文件会导致停止并要求核对，不自动覆盖。

确认前显示 Header、全部可信网段和作用范围。自定义模式拒绝空网段、全网信任和过宽的内网网段；内网需 IPv4 `/24` 或更窄、IPv6 `/64` 或更窄，loopback 需单个地址。Header 缺失、无法提取有效 IP 或连接来源不可信时，Nginx 保留连接来源 IP，不尝试其他 Header；`X-Forwarded-For` 从右向左跳过可信代理。确认后备份、校验并重载，失败恢复。

重复执行可更新配置；`--restore-real-ip` 或菜单 `4 → 2 → 3 → 1 → 4` 恢复原自定义文件内容及权限，原文件不存在时移除生成文件。旧版 Cloudflare 管理记录兼容，核心卸载要求先撤销。

Cloudflare 模式仅信任官方公网节点，不自动信任 loopback 或内网代理。Cloudflare Tunnel 需核对其连接来源和 Header 后再选择自定义模式；宿主机 Nginx/OpenResty 使用对应的宿主机修复入口。修复后从外部访问当前 `server_name` 对应站点，用独特查询参数关联该次请求的新访问日志，核对访问设备公网 IP。日志中的 IP 与 Web Bouncer 使用的 IP 仍需在实际部署中核验；旧日志和累计计数不会改写。保留 CDN 白名单、SSH 采集和现有 WAF。

`tools/diagnose-detection.sh` 的 SSH 离线失败认证样本成功解析，只能证明该样本兼容；大量正常会话日志未解析不等于防护失效。AppSec 验证需同时检查 HTTP 响应与规则计数增量，经过 Cloudflare 返回 403 本身不能证明请求到达本机 AppSec。

## 正常请求的真实 IP 核验

`--verify-real-ip` 或菜单 `4 → 2 → 3 → 1 → 3` 支持本工具完整管理、共用访问钩子的原生 Docker Web Bouncer。输入站点根地址和请求设备的已知公网 IP；从本机或外部设备访问带随机标记的正常页面，关联访问日志、连接对端、CF/XFF 与实际传给 `cs.Allow` 的 IP。只为该标记临时记录诊断，原 WAF 仍先执行；失败、中断和成功均恢复原 Lua 并校验/重载。

不记录 Cookie、Authorization 或完整 Header。验证通过才保存私有证明；超过 24 小时、Nginx 配置或 Lua 改变时重新标为“尚未验证”。有 buffer 的日志需明确 flush，最长支持 115 秒 flush、120 秒核验等待；缺少 flush 或超时配置时停止。普通页面验证不代表攻击路径阻断验证。

宿主机使用 `--diagnose-host-real-ip`、`--repair-host-real-ip`、`--verify-host-real-ip` 和 `--restore-host-real-ip`（菜单 `4 → 2 → 3 → 2` 后分别选择诊断、修复、核验或撤销）。修复要求 real-IP 模块与已加载标准 HTTP conf.d；不自动插入新的主配置入口。请求核验要求已接入的官方 Bouncer、唯一 inline 访问钩子和可读取的 access/error 日志，拒绝站点钩子覆盖、satisfy any 和 AppSec 本地覆盖；证明同时绑定 Bouncer 配置哈希。

重复宿主机接入与真实 IP 修复不变时跳过重载。

## 管理员 AllowList 与 Self-Report

`--self-report-status`（菜单 `4 → 5 → 1`，或 `3 → 9`）只读核对回环、本机接口和明确记录的地址对应的告警/决策；不查询外部服务猜出口 IP，也不自动解封或加白。NAT 的自身公网地址可明确记录到 `/etc/crowdsec/crowdsec-1key-own-addresses.json`，格式为 IP 字符串列表，例如 `["203.0.113.10"]`，实际使用自己的地址。手动封禁拒绝回环、未指定地址、本机接口、管理员 parser 白名单地址及这些记录，包括 IPv4-mapped IPv6。

`--admin-allowlist`（菜单 `3 → 8`）管理明确选择的单个管理员 IP。中央 AllowList 与 parser whitelist 不同，**会使来源跳过 AppSec**并影响决策过滤；不会自动迁移私网或代理网段。需要支持 AllowLists 的 CrowdSec 版本。自己的公网出口地址无法仅由本机接口推出，必须核对并明确记录。

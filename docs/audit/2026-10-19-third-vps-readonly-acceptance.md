# 2026-10-19 新增 VPS 只读检查（第三台）

后续已按用户确认完成优化，见[变更与验收](2026-10-19-third-vps-remediation-acceptance.md)；本页保留变更前快照。

已使用用户添加的专用 SSH 公钥登录。主要发现是 **6 个业务站点的访问日志未纳入 CrowdSec 采集**，以及代码工作区容器在后续采样中占用大部分 CPU。CrowdSec、Firewall Bouncer 和 Web Bouncer 有运行及近期拉取记录；当前唯一有效的本地 IPv4 封禁两轮均在防火墙集合中。

采样时间为 **2026-10-19 12:49–12:54 UTC**，服务器本地时间为 20:49–20:54 CST。命令、分轮数据、源码核对和检查边界见[脱敏证据](2026-10-19-third-vps-readonly-evidence.json)。目标公网地址、业务域名和凭据不写入本报告，站点以 site-A 至 site-J 表示。

## 1. 优先补齐：10 个站点仅 4 个站点的访问日志被配置采集

`nginx -T` 展开的配置包含 10 个业务站点，均有现存访问日志；CrowdSec 当前采集配置仅列出其中 4 个站点的日志，现有采集指标也只出现这 4 个站点。采集路径位于 `/opt/1panel/1panel/www/sites/`，应使用实际挂载路径。

| 未采集站点 | 有限日志样本中最近 1 小时记录 | 最近 15 分钟记录 |
| --- | ---: | ---: |
| site-A（通配子域入口） | 8 | 0 |
| site-E | 546 | 131 |
| site-F | 0 | 0 |
| site-G | 0 | 0 |
| site-H | 256 | 0 |
| site-J | 88 | 14 |

这会使这些站点的请求无法通过所核对的访问日志进入 CrowdSec 日志解析和行为场景。建议先补齐采集列表，并在新增站点后重新发现、核验采集覆盖。

OpenResty 的 HTTP 级配置仍接入 Web Bouncer：原有 1Panel WAF 执行后调用 `cs.Allow(ngx.var.remote_addr)`，AppSec 地址也已配置。日志遗漏不等于这些站点完全没有防护；实际站点调用、真实 IP 和拦截仍需受控请求关联验证。

## 2. CPU 压力主要出现在代码工作区容器

服务器为 Debian 13.7、4 vCPU、约 19.53 GiB 内存。初轮三个间隔样本的 CPU 空闲为 56%、60%、77%；后续明显升高，12:53 轮的三个间隔样本空闲为 **9%、8%、7%**。

12:53 轮 `docker stats --no-stream` 中，`codeg-server` 占用 **361.24% CPU**、约 **2.98 GiB 内存**，对应约 3.6 个核心。随后另一个约 2 秒的进程采样发现一个 Python 进程占用约 93% 单核，结束时通过 cgroup 确认其属于该容器；这两个采样窗口不同，不能把容器全部占用归到该单一进程。

末轮一分钟负载为 5.77，两个 CPU 空闲样本为 20%、28%，说明压力存在波动。建议优先核对代码工作区内正在运行的任务、并发和长期 CPU 曲线；本轮没有确定具体 Python 任务，也没有停止进程或调整容器资源限制。

内存可用约 **13.26 GiB**，根分区使用率 **36%**；约 4 GiB Swap 使用 285 MiB，所采 `vmstat` 间隔未见换入换出或明显 I/O 等待。最近 7 天保留的内核 journal 中，OOM 定向查询返回 `-- No entries --`。这些短时数据不构成长期容量保证。

## 3. 三套规则更新任务并存

- root crontab：每天本地时间 **04:30**，执行 Hub 更新、升级，前两步成功后重载 CrowdSec。
- `/etc/cron.d/crowdsec-autoupdate`：每天 **03:30**，调用托管管理器 `--update-hub`。
- 系统 `crowdsec-hubupdate.timer`：enabled/active，上次执行成功；下次为 **2026-10-20 00:03:38 CST**。其脚本在有升级输出时重载服务。

建议合并更新入口，减少重复更新及重载窗口。应用文件日志的有限尾部在最近 24 小时过滤窗口中包含 1 条 `SIGHUP received, reloading` 和重复注册 grok、缺少 `/var/log/messages`、`/var/log/secure` 等告警；不能将这些记录直接当成当前 CPU 压力的原因。后两种文件在 Debian 上缺失也不能证明 SSH 日志漏采，现有 `/var/log/auth.log` 已配置采集。

## 4. 网站故障策略和旧版状态码问题仍需处理

Web Bouncer v1.2.3 的配置为 `MODE=live`、`APPSEC_FAILURE_ACTION=passthrough`；未发现 `bouncer.conf.local` 覆盖。已安装源码在 AppSec 请求失败时依此策略放行；LAPI 请求失败及非 200 响应也存在独立的允许分支。

已安装 AppSec `deny` 分支仍只改变拒绝标记及处置类型，没有把初始 `status_code=200` 改为 403。本机尚未包含另一台服务器已发布的该项修正。当前策略不进入此拒绝分支；本轮只核对源码，没有切换策略或在生产注入故障。若后续选用故障拒绝，应先修正并验证状态码及是否回源。

网站错误日志的有限读取中，最近 24 小时过滤窗口没有匹配到 AppSec/LAPI 调用失败；更早的历史记录存在。site-E 同窗口有 2 条上游连接失败和 2 条上游超时。不能把历史 AppSec 失败计数当作本轮持续故障，也不能把空的 systemd warning 查询代替应用日志检查。

## 正常状态与检查边界

- CrowdSec v1.8.1、Firewall Bouncer v0.0.36 为 active/running；两类 Bouncer 均有近期认证拉取记录。Fail2Ban 的 sshd jail 运行，快照中没有当前封禁。
- 12:51、12:52 两轮各有 1 个有效本地 IPv4 IP ban，均位于本地来源 nftables 集合中。IPv4/IPv6 的 INPUT、FORWARD 基础链及现有集合 DROP 引用已核对；没有当前本地 IPv6 决策样本。未据此声称全部 CAPI、网段决策或实际流量拦截均通过。
- LAPI、AppSec、Prometheus 监听环回地址。静态真实 IP 配置使用 X-Forwarded-For、递归解析和 22 个 Cloudflare CIDR；本轮没有执行 CDN 请求关联。
- Web UI 的 TCP/3000 及 Hermes 的 TCP/9119 绑定所有接口；本地 Web UI 返回 HTTP 200。当前工作区经目标公网地址访问两端口均超时，公网可达性尚未确认。HTTP 200 本身不证明管理接口缺少认证。SSH 仍允许 root 密码登录。
- `nginx -t` 通过。7 个 CrowdSec 配置／采集／托管记录文件的哈希在首末轮一致；26 个 Web Bouncer 资源在两轮间一致，并通过托管记录摘要核对。相关服务 PID 和 `NRestarts=0` 保持一致，该计数不代表全部历史启动记录。
- 本轮通过 SSH 标准输入执行只读采集，没有安装诊断源码、修改生产配置、增删决策、请求服务重载／重启或发送 Telegram 消息。专用公钥由用户在检查前添加，授权保留供后续使用。
- 访问日志每文件最多读取末尾 4 MiB，错误／应用日志最多 2 MiB；时间过滤不等于完整历史覆盖。没有取得当前本地 ban 创建 120 秒后的合格访问样本，也没有执行独立来源的封禁／撤销、CDN 全链路、IPv6/UDP、升级或重启验收。

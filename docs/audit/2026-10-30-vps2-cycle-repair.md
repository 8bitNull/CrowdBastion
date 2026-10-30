# 第二台 VPS：循环复审、修复与部署

目标 `179.255.121.95:53322`。用户补充公钥授权后登录成功，沿用已固定的 SSH 主机密钥。现场为 Debian 13、CrowdSec 1.8.1、Firewall Bouncer 0.0.36，以及 host 网络的 Nginx Proxy Manager（`npm`）。本次按现场状态核验，未将历史报告直接当作当前部署状态。

## 已完成的修复

### 防火墙续封失效

现场原生 nftables 后端仍存在续封缺陷。临时命名空间中，先封禁 40 秒再延长至 120 秒；原期限结束后，LAPI 决策仍有效约 81 秒，IPv4/IPv6、TCP/UDP、主机输入/转发的 8 条测试流已经全部恢复可达。`flow-before.json` 的 `passed: true` 表示故障成功复现。

安装 `ipset` 和 `libipset13t64`，没有升级其他包。通过原 `.yaml.local` 追加 `mode: iptables` 与 `iptables_chains: [INPUT, FORWARD, DOCKER-USER]`，保留其中的 API 地址和密钥，基础 YAML 字节不变。新增 Bouncer 的 `After=docker.service` 启动顺序。iptables 使用 nf_tables 兼容层，不是原来有缺陷的原生 nftables 后端。

切换受到当前封禁快照、当前 SSH 来源保护及独立回退定时器保护。一次迁移成功；IPv4/IPv6 三个入口均先跳转 CrowdSec 链，原有 Docker 规则和 NPM 管理端口 81 的限制保持不变。新 SSH 连接成功后，再通过以下流量验收并提交迁移：

| 检查 | 结果 |
| --- | --- |
| 新封禁 | 8 条测试流正确阻断 |
| 续封越过原到期时间 | 仍保持阻断 |
| 删除决策 | 恢复通行 |
| 自然到期 | 恢复通行 |
| 不封禁的对照来源 | 始终可达 |
| 最终有效网络覆盖（剩余有效期超过 15 秒） | 16,465 条，内核缺失 0 |

测试只对专用本地测试地址创建决策，没有封禁管理出口。测试决策、命名空间、网卡、监听、临时规则、快照表及恢复定时器均已清理。迁移已提交，自动回退已解除。

### 管理脚本与 NPM 重载验证

旧 `/root/crowdsec-1key` 仍停留在 `c70c167`。已备份整个旧目录，将当前修复版完整部署到日常管理入口，并保留 `install-crowdsec-1panel.sh` 兼容链接。最终发行目录为：

`/opt/crowdbastion/releases/review-20261030-cycle-npm-final`

现场没有使用 `/usr/local/lib/crowdsec-1key/current` 维护运行目录；原禁用的重复 cron 更新任务保持不变，未新建调度。最终发行目录及日常入口的 56 个源码文件摘要一致。

NPM 原主日志级别为 warn，不具备重载接受证据；持久化自定义配置又通过主作用域 include 引入。为避免改动容器镜像主配置，本轮补充 `crowdsec_nginx_reload.py` 对 **主作用域绝对路径 include** 的解析：只追踪从主配置可达的 include，支持 NPM 的 `[.]` 模式；不把 HTTP/server 日志、未引用文件或通配符不应匹配的隐藏文件误认成 master 日志。循环、重复配置段和遍历超限均拒绝确认。

新增持久化 `/home/docker/npm/data/nginx/custom/root_top.conf`，记录 notice 级别到 `/data/logs/crowdbastion_reload_error.log`，匹配 NPM 既有错误日志轮转规则。首次加载只增加日志配置，检查语法及稳定新 worker；随后立即完成一次包含 master 日志证据的完整重载验证。未重建或重启 NPM 容器。

相关回归 70 项全部通过；最后补充通配符隐藏文件边界后，重跑日志验证 12 项全部通过。Bash/Python 语法、ShellCheck warning/error 级别及 `git diff --check` 通过。本轮没有重跑全仓测试集。

使用相同 NPM 镜像、无网络及无业务挂载的隔离容器实测：主作用域 include 日志可以确认正常重载；语法检查成功但 Lua 初始化失败时返回失败，旧 worker 保持；恢复后重载成功。前两份夹具因镜像没有默认 `nginx` 用户而失败，明确指定隔离进程用户后通过，失败记录保留。最终部署模块另在生产完成一次完整重载验证。

### Web Bouncer 与真实 IP

使用新版安装入口升级现有托管 Web Bouncer，补齐真实拒绝记录、AppSec 403 与 LAPI 故障策略支持。沿用原账号，`bouncer.conf` 摘要不变；原策略仍为 AppSec `deny`、LAPI `passthrough`。没有擅自改变可用性策略。

升级后托管资源校验通过。再次运行安装成功且进程身份不变，没有多余重载。一次菜单输入错误和一次管理锁繁忙均在实际修改前退出，纠正输入并等待事务结束后升级成功，日志保留。

`https://32byte.cn/` 正常标记请求的连接对端、访问日志 IP、Bouncer IP 与预期来源均为 `179.255.121.95`，完整核验及临时 Lua 恢复重载退出 0。首次请求遇到 DNS 超时，恢复成功；后续 DNS 查询正常，重试通过，未改变 DNS 设置。这是本机通过公网域名访问直连源站的核验，不能冒充外部设备或 CDN 全链路验收。

## 最终状态与验收边界

- CrowdSec、Firewall Bouncer、Docker、交互机器人、通知服务均 active。核心和 Nginx 配置检查通过。
- CrowdSec、Docker、交互机器人、通知服务的 PID、启动时间及重启次数保持不变；仅 Bouncer 为后端迁移重启。NPM 容器继续运行。
- 通知服务 ready，待发和重试为 0；机器人 healthy，没有轮询、发送或 API 错误。没有发送人工 Telegram 测试消息。
- 源站抽查与修改前一致：`shop.688600.xyz` 为 301，`32byte.cn` 和 `waf.688600.xyz` 为 200。使用 loopback `--resolve` 与 `-k`，不表示公网 TLS 已验收。
- 健康检查由 **1（存在故障）** 变为 **2（运行检查通过，公网实际拦截待验证）**。没有宣称所有域名、业务转发或公网 CDN 攻击阻断已经逐项通过。
- 机器人/通知运行代码原本已与本轮源码相同，因此没有重装或重启这些服务。

## 备份与恢复资料

远端私有备份：`/var/backups/crowdbastion/vps2-cycle-20261030/`，目录 0700、文件 0600。包含修改前完整配置和源码归档 `before.tar.gz`、文件摘要、旧防火墙覆盖配置、规则快照、迁移脚本和过程证据。含密钥的备份没有下载到仓库。

旧日常源码（包括原 git 元数据）完整保留在 `/root/crowdsec-1key.before-20261030-cycle`。Web 升级自身备份为 `/var/backups/crowdsec-1key/change.hpUvbNJa`；最终真实 IP 核验恢复备份为 `change.VYBx3zD5`。未创建 git 提交。

防火墙人工恢复入口：`python3 /var/backups/crowdbastion/vps2-cycle-20261030/migrate.py manual-rollback`。它检查配置漂移，使用临时封禁快照，并恢复原 `.yaml.local`（包括其凭据）。该入口已检查语法，提交后没有执行；恢复将回到已知存在续封缺陷的旧后端，不能当作日常维护步骤。

证据：[最终验证](2026-10-30-vps2-cycle-repair/verification-final.json)、[修复前复现](2026-10-30-vps2-cycle-repair/flow-before.json)、[修复后流量验收](2026-10-30-vps2-cycle-repair/flow-after.json)、[隔离重载验证](2026-10-30-vps2-cycle-repair/isolated-reload.json)、[真实 IP 核验](2026-10-30-vps2-cycle-repair/real-ip-verification-r2.txt)、[健康结论](2026-10-30-vps2-cycle-repair/health-final.txt)。证据目录的 `SHA256SUMS` 包含本轮报告、证据及相关源码摘要。

# VPS 45：登录后只读复查

目标 `root@192.0.2.22:53322`，检查时间 2026-11-02 02:10–02:20 UTC 左右。用户添加专用公钥后，公钥认证成功；使用已有 known_hosts 严格校验，禁用密码与键盘交互认证。本轮范围为只读检查，没有更新远端程序、配置、cron 或防火墙，没有重启服务。

**结论：当前采样未发现封禁集合遗漏，网站防护资源与钩子正常；存在已确认的开机整表恢复风险，旧版健康摘要未覆盖这一风险。实际公网业务阻断仍待验收。**

## 当前运行状态

| 项目 | 本轮结果 |
| --- | --- |
| 系统与用途 | Debian 13，网站节点，1Panel/OpenResty；OpenResty 容器使用 host 网络 |
| CrowdSec | v1.8.2，active/enabled，PID 274799，NRestarts=0，配置检查通过 |
| Firewall Bouncer | v0.0.36，active/enabled，PID 1479440，NRestarts=0 |
| 生效后端 | `.yaml.local` 覆盖主 YAML，实际为 iptables/ipset；未退回旧 nftables 后端 |
| Docker | active/enabled，PID 279713，NRestarts=0；现有 10 个容器运行，有健康检查的 7 个均 healthy |
| LAPI 与同步 | LAPI 检查通过；仅列注册信息的观察期间，防火墙客户端 last_pull 从 02:19:48 推进到 02:19:58 UTC |
| 决策与集合 | 排除临近到期决策后，16,701 条适用网络全部存在于实际引用的内核集合，遗漏 0 |
| Web Bouncer | v1.2.3，资源摘要及挂载校验通过；init/access/worker/log 四个解析后的指令及相应模块调用均存在，目标配置已被 Nginx 加载 |
| Web 故障策略 | AppSec/LAPI 均为 deny；bouncer.conf 摘要与 10 月 30 日记录相同 |
| 业务可用性采样 | site-04.example.com、site-14.example.com、site-17.example.com 的本机源站首页均 HTTP 200 |
| Telegram 与 V2bX | 分级通知、交互 bot、V2bX observer 未安装，与此前部署记录一致；没有待迁移的通知队列或 bot 消费进度 |

决策入核使用只读 LAPI 查询及 ipset 快照；上述 last_pull 观察不包含向该防火墙账号发起的决策查询，能独立说明其自主同步仍在推进。源站首页检查使用 loopback `--resolve`、`--insecure`，只说明这三个请求的本机可用性，不证明公网 TLS、真实 IP 或恶意请求阻断。

## 已确认的风险与版本差异

1. **root 的两条 `@reboot` 任务仍调用 `iptables-restore` 和 `ip6tables-restore`。** 当前位于 `/var/spool/cron/crontabs/root` 第 4、5 行，分别读取 `/etc/iptables/rules.v4`、`rules.v6`。保存文件包含旧 Docker 规则，均没有 CrowdSec 链；开机执行与 Docker/Bouncer 缺少顺序约束，可能覆盖动态规则。本轮没有执行恢复命令或重启演练，不能据此认定过去发生过覆盖。netfilter-persistent 未安装，nftables.service 为 disabled/inactive，当前确认的入口是上述 cron。
2. **管理程序仍是 10 月 30 日版本。** 日常目录与维护 current 的 54 个共同文件摘要相同，current 指向 `release-review-20261030-cycle4-d75639c0`；日常目录另有兼容入口。按本地 main `ce8e8677a18bfe7df6ef5262c0139935afadb57f` 的 62 个管理入口和直接 lib 源文件比较：31 个相同、22 个不同、9 个未部署。未部署文件包含已有部署检查、防火墙检查和 UX/bot runtime 等新模块；这是版本差异，不能把未启用功能的辅助文件视为现有守护进程的依赖故障。
3. **旧版网站健康摘要没有反映开机风险。** 现场 `--status` 退出 2，显示“运行检查通过，实际拦截待验证”；内存运行新版只读审计则识别了两条 cron。后续更新应使摘要覆盖已确认风险。

当前每日 Asia/Shanghai 03:30 的维护任务是 `--update-hub`，并非更新管理脚本。本轮保留原任务、时间与配置，未启用其他更新功能。

## 转发路径与检查器限制

双栈实际首段路径均为：

```text
INPUT → CROWDSEC_CHAIN
FORWARD → DOCKER-USER → CROWDSEC_CHAIN
```

这些跳转均无额外匹配条件，CrowdSec 链的规则均为来源集合 DROP。FORWARD 后续还保留直接 CrowdSec 跳转，但 Docker 自有规则排在它之前；由于第一条已无条件进入受保护的 DOCKER-USER，不能仅据后续直跳位置判定存在绕过。

当前新版 `crowdsec_firewall_runtime.py` 要求每个入口的第一条直接跳入 CrowdSec，故将上述间接路径判为 fault，连带使其组合入核检查停止。此结果与开机风险分开解释：开机风险已确认；当前间接路径的静态检查通过，随后以同一只读成员比对算法核对 16,701 条网络，遗漏为 0。该独立静态分析没有替代真实流量测试，也没有修改产品检查器。后续更新前应补充这种无条件间接跳转的回归，继续拒绝前置 ACCEPT、条件跳转及真正绕过路径。

## 日志与本次采集修正

网站访问日志已有读取、解析和场景消费计数。通用 kern.log/syslog 在采样中全部未解析，会使不区分来源的全局分类器返回 fault；尾部分类主要是内核常规信息和 systemd 消息，不能据此认定全部网站采集失效。OpenResty 错误日志存在既有 recaptcha 提示，本轮未更改相关策略。

Bouncer 文件日志初次尾部统计包含历史错误；扩展至最后 512 KiB 并解析时间后，236 条错误均早于最近 24 小时，最后一条为 2026-10-31 13:40:38 UTC 的 LAPI 连接拒绝。当前 LAPI、集合采样及自主同步正常。统计只覆盖该文件尾部及相关 journal，不代表全量归档日志审计。

保留了采集工具的初始判定及纠正证据：`health.json` 中 `/usr/local/bin` 版本探针未找到文件，后续 `/usr/bin/crowdsec-firewall-bouncer` 版本检查成功；固定候选执行日志路径未命中，实际主 error_log 为 `/var/log/nginx/error.log notice`；`final.json` 的未处理引号的字符串钩子检查返回 false，后续使用既有 Nginx 指令解析器核对，四个阶段全部通过，见 `hooks-and-source-recheck.json`。这些初始结果不作为安装缺失或钩子失效的依据。一次本地展示命令误用 inventory 的不存在键 `files`，随后使用实际 `source_roots`；未影响远端采集。

## 后续修复范围

先备份原 cron、配置和当前静态策略，明确保留 SSH、1Panel 及网站的现有端口保护，再精确停用两条开机整表恢复任务。随后处理管理程序更新及上述间接跳转检查问题，保留正常 iptables/ipset 后端、现有 Web Bouncer 资源、账号与站点配置。此次没有安装 TG 功能的需求，也不应直接套用 VPS179 的管理端口静态策略。

本轮没有修改生产配置或实施上述修复，没有新增封禁决策、发送攻击探针或 Telegram 消息，没有进行冷启动和外部业务阻断验收。检查前后管理源码摘要、四份可前后比较的现存配置摘要和三个服务 PID 均保持不变。

证据目录 2026-11-02-vps45-readonly（本地归档：`2026-11-02-vps45-readonly/`） 为 0700，文件 0600；保存脱敏摘要、只读采集脚本及清单。归档前使用远端四份配置中的 5 项实际凭据，对当时的 27 份证据／脚本／报告／索引执行精确匹配检查（含 JSON 转义形式），无匹配；没有导出凭据值，见 扫描结果（本地归档：`2026-11-02-vps45-readonly/credential-scan.json`）。主要证据：初始清单（本地归档：`2026-11-02-vps45-readonly/inventory.json`）、健康与 Web 资源（本地归档：`2026-11-02-vps45-readonly/health.json`）、路径及独立入核核对（本地归档：`2026-11-02-vps45-readonly/followup.json`）、源站与最终配置（本地归档：`2026-11-02-vps45-readonly/final.json`）、钩子及源码复查（本地归档：`2026-11-02-vps45-readonly/hooks-and-source-recheck.json`）、独立自主同步观察（本地归档：`2026-11-02-vps45-readonly/autonomous-sync.json`）、错误时间线（本地归档：`2026-11-02-vps45-readonly/error-timeline.json`）、源码比较（本地归档：`2026-11-02-vps45-readonly/code-comparison.json`）。历史修复的具体范围见 [10 月 30 日循环修复](2026-10-30-vps1-cycle-repair.md)。本轮只增加审计资料与索引，未修改产品代码，未重跑全仓测试，未创建提交或推送。

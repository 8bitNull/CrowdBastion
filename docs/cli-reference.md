# CrowdBastion 命令行参考

[返回 README](../readme.md) · [使用说明](usage-guide.md)

按参数查找操作；首次使用请先按使用说明选择部署场景。安装与配置入口仍有交互输入。

主入口为 `crowdbastion.sh`；旧入口 `install-crowdsec-1panel.sh` 为兼容链接，参数与退出码一致。服务名和配置路径的兼容说明见 [更名与升级](project-rename.md)。

## 目录

- [参数](#参数)
- [菜单交互与并发](#菜单交互与并发)
- [状态与退出码](#状态与退出码)
- [账号与兼容参数](#账号与兼容参数)

## 参数

```bash
bash crowdbastion.sh --help
```

| 参数 | 功能 |
| --- | --- |
| `--install-core` | 安装核心和 Firewall Bouncer |
| `--install-relay-bouncer` | 安装/接入独立远端 Firewall Bouncer，不安装本地核心 |
| `--configure-relay-bouncer` | 交互修改远端 URL 与隐藏密钥 |
| `--relay-bouncer-status` | 只读检查托管远端配置和服务，不验证远端认证或业务阻断 |
| `--remove-relay-bouncer` | 移除托管远端配置并停用，保留基础配置、包、二进制和 unit |
| `--install-relay` | 纯中转节点精简安装：系统/SSH 规则与采集，保留已有 Web/AppSec |
| `--relay-status` | 只读检查中转 INPUT/FORWARD、IPv4/IPv6 规则引用，输出简短结论 |
| `--relay-status-details` | 显示中转结论和完整技术详情；退出码与简短模式一致 |
| `--relay-path` | 交互声明节点角色/流量路径，选择 TCP/UDP 端口，读取 socket/NAT 与 Bouncer 证据 |
| `--verify-relay` | 中转入口引导验收；外部连接结果人工确认，本机只读 nftables 或 iptables/ipset；保存本次入口验收摘要，详见 [验收流程](relay-mode.md#中转入口引导验收) |
| `--verify-relay-lifecycle` | 本机只读，引导续封跨原期限、精确删除和自然到期；外部结果及决策操作由操作者确认 |
| `--relay-acceptance` | 只读查看上次中转验收的入口、时间、结果及配置适用性；历史记录不提升当前健康结论 |
| `--diagnose-v2bx-details` | 显示 V2bX 检查结论和完整技术详情 |
| `--diagnose-v2bx` | 只读核查 V2bX 三内核配置、日志、混合入口声明和本地 Bouncer；详见 [V2bX 指南](v2bx-guide.md)，未验证端到端保护返回 2 |
| `--v2bx-log-check` | 只读检查三内核日志样本；菜单 `4 → 4 → 4 → 2`，用 `V2BX_LOG_FILE/CORE/TIMEZONE`、`V2BX_RELAY_CIDRS`、`V2BX_UNIT` 指定输入；返回 2 表示生产未验证，见 [V2bX 指南](v2bx-guide.md) |
| `--v2bx-observe` | 持久保存固定观察投影、恢复游标与采集指标，可导出一次性快照；仅命令行，不安装常驻服务或规则；参数见下方说明及 [V2bX 指南](v2bx-guide.md) |
| `--prepare-v2bx-observer` | 交互预览、校验并生成单日志源私有配置，不启动服务；持续记录菜单 `5` 也可进入 |
| `--install-v2bx-observer` | 安装落地常驻仅观察服务，需私有 JSON 配置文件（命令行用 `V2BX_OBSERVER_CONFIG`，菜单可输入路径）；菜单 `4 → 4 → 4 → 3 → 1` |
| `--v2bx-observer-status` | 只读服务、心跳及指标，业务保护未验证返回 2 |
| `--disable-v2bx-observer` | 停止并禁用本工具观察服务，保留配置、数据库与游标 |
| `--enable-v2bx-alerts` | 接入仅观察规则／采集与 profiles guard，重启核心并启动增量发布；菜单 `4 → 4 → 4 → 4 → 1` |
| `--v2bx-alerts-status` | 只读核查规则／guard、核心、源采集器及发布状态；未验证业务保护返回 2 |
| `--disable-v2bx-alerts` | 停止发布并撤销本工具接入，保留证据；会重启核心 |
| `--install-webui` | 部署/更新 WebUI |
| `--reset-webui-credentials` | 检查并选择轮换 WebUI 凭据 |
| `--install-waf` | 安装 Web 日志检测集合 |
| `--install-appsec` | 配置 AppSec、检查部署方式并接入已有宿主机/Docker Web Bouncer |
| `--install-web-bouncer` | AppSec 就绪后首次安装兼容的 Web Bouncer |
| `--remove-web-bouncer` | 撤销本工具原生容器 Web Bouncer，保留原 WAF |
| `--appsec-status` | 只读检查 AppSec 数据源、监听、容器接入组件与指标；已登记 bridge 端点核验失败时返回 1 |
| `--verify-appsec` | 确认后以标记请求检查 HTTP/AppSec 指标，返回通过/失败/无法判断 |
| `--appsec-policy` | 检查并明确设置宿主机/容器 AppSec 正文与故障策略 |
| `--disable-appsec` | 停用本工具 AppSec |
| `--enable-cron` | 每天 03:30 更新 Hub |
| `--runtime-status` | 只读比较当前源码与定时任务维护副本的内容指纹；相同返回 0，不同/未安装返回 2 |
| `--environment-status` | 只读输出宿主机环境 JSON；3 次 `/proc` 采样、间隔 0.25 秒，区分持续压力、单次尖峰与计数器不可用；stable/unstable/unknown 分别返回 0/1/2 |
| `--sync-runtime` | 预览后确认同步脚本和 lib；须已有 cron，保留原文与原执行时间 |
| `--update-hub` | 带锁、快照、校验及失败回滚的 Hub 更新 |
| `--check-logs` | 只读检查新增/漏采日志和重复采集 |
| `--clean-redundant` | 查看节点并选择注销，保留受保护账号 |
| `--firewall-check` | 只读检查开机规则覆盖、Docker 顺序和双栈链 |
| `--repair-existing` | 检查并修复已有 iptables 部署；逐项确认旧 root 开机恢复任务，备份、配置失败恢复、限时等待决策同步 |
| `--firewall-maintenance` | 启动修复、带回退定时器的后端迁移与本机流量验收；见[防火墙维护](firewall-maintenance.md) |
| `--repair-bouncer` | 修复 Firewall Bouncer 连接配置 |
| `--self-report-status` | 只读核对已知自身地址的告警和决策 |
| `--admin-allowlist` | 明确管理中央管理员 AllowList（旁路 AppSec） |
| `--repair-logs` | 按实际日志与 Docker 挂载补齐 HTTP 采集，保留现有配置 |
| `--repair-real-ip` | 按可信 CDN/代理、指定 Header 和网段修复 Docker Nginx/OpenResty/NPM 真实 IP |
| `--diagnose-real-ip` | 上游不确定时只读检查配置、挂载日志并提供外部请求核对指引 |
| `--verify-real-ip` | 关联正常请求的日志 IP 和实际 Bouncer IP |
| `--restore-real-ip` | 撤销本工具的真实 IP 配置 |
| `--configure-docker-endpoints` | 核验并登记 bridge 容器已准备好的私有网关端点 |
| `--repair-host-real-ip` | 修复宿主机 Nginx/OpenResty 的真实 IP |
| `--diagnose-host-real-ip` | 只读检查宿主机代理信任与日志 |
| `--verify-host-real-ip` | 关联宿主机普通请求的日志和官方 Bouncer IP |
| `--restore-host-real-ip` | 撤销本工具宿主机真实 IP 配置 |
| `--reset-baseline`、`--reset-56` | 补齐基础集合；兼容旧参数，保留自定义/AppSec，不保证固定场景数 |
| `--uninstall-waf` | 确认后移除已知 Web 日志扩展 |
| `--check-clean` | 只读残留检查 |
| `--deep-clean`、`--purge`、`--uninstall` | 确认后卸载和删除数据 |
| `--telegram` | Telegram 管理菜单 |
| `--telegram-test` | 官方插件测试并核对 Telegram API 回执 |
| `--telegram-smart` | 启用/更新分级降噪通知，需已有 TG 目标；[策略与范围](telegram-noise-control.md) |
| `--telegram-smart-status` | 只读查看待发队列、紧急事件与检查心跳 |
| `--telegram-smart-disable` | 停用分级服务并恢复原即时/批量模式，保留队列 |
| `--custom-bot` | 可选交互机器人配置/启用、状态检查、停用；菜单 `4` 代码指纹检查、`5` 保留配置更新，见 [机器人说明](2026-10-13-custom-telegram-bot.md#代码版本检查与更新2026-11-01) |
| `--optimize` | 诊断后逐项选择基础规则、日志采集和指标，汇总确认后统一加载 |
| `--enable-wal` | 确认本地 SQLite 后启用官方 WAL 配置 |
| `--status` | 按用途只读检查，显示一个结论与一个推荐下一步；不显示交互菜单 |
| `--status-details` | 显示整体检查结论与完整技术详情；未选择用途时检查网站范围 |
| `--status-json` | 同源只读检查，输出版本 1 JSON：检查项、范围、采样时间、配置路径与统一结论，不含原始诊断 |
| `--help`、`-h` | 帮助，不需要 root |

每次仅指定一个操作。`--update-hub` 可无人值守执行；其他安装/配置入口仍保留必要的输入与确认。

## 菜单交互与并发

通用代理协议导航：首页 `4 → 11`、检查与修复 `4 → 4 → 10` 或安装/调整页 `8`；V2bX 专项菜单 `5` 直接选择程序/协议/传输。该选择只影响本次只读指导，旧 `--protocol-status` 不新增提示或修改声明画像退出码。专项日志检测的范围不因协议导航扩展，详见[使用导航](usage-guide.md#代理协议使用导航)。

| 首页 | 功能 |
| --- | --- |
| 1 | 当前推荐任务：根据实际状态继续设置、排查或验证 |
| 2 | 日常管理：封禁、通知、规则、维护副本与备份说明 |
| 3 | 调整防护目标：业务目标、网站检查范围，只保存偏好 |
| 4 | 高级工具与检查详情：保留原高级管理内部 1–8，新增 9–11 |

任务页：`1` 开始/明确重试，`2` 详情，`3` 待办与恢复暂缓项，`4` 暂缓，`5` 重新检查，`0` 返回。启动不自动安装，不强制问卷；已有故障和未完成变更优先。状态未知、命令返回 0 和配置变化都不能单独证明任务完成。

| 高级管理路径（从首页起） | 功能 |
| --- | --- |
| `4 → 1` | 安装与接入：核心、网站防护、真实 IP、Docker 私有端点、中转模式 |
| `4 → 2` | 检测规则：集合安装／移除、基础规则、手动与定时 Hub 更新 |
| `4 → 3` | IP 封禁与放行：告警／决策、封禁／解封、防火墙、AllowList、Self-Report；日常管理 `2 → 1` 也可进入 |
| `4 → 4` | 检查与修复：健康、日志、AppSec、真实 IP、中转与 V2bX、基础修复和 WAL |
| `4 → 5` | 控制台与通知：WebUI、Console、Telegram |
| `4 → 6` | 卸载与清理：卸载／清理、只读残留检查 |
| `4 → 7` | 设置节点用途：网站、本地中转、远端执行、V2bX 落地，可组合 |
| `4 → 8` | 原用途专项检查与脱敏报告导出 |
| `4 → 9` | 查看本次智能流程已采集的详情 |
| `4 → 10` | 查看待办并恢复暂缓项 |
| `4 → 11` | 通用代理协议导航 |

检查与修复保留原五个入口，依次为：整体运行情况、网站问题、中转节点、V2bX 落地节点、基础配置修复。V2bX 入口统一提供配置检查、日志检查、持续记录和异常告警。新增 `4 → 4 → 6` 环境压力、`7` TCP 配置、`8` 端口策略、`9` 协议声明；TCP／端口子菜单均为 1 状态、2 计划、3 应用暂存、4 核验、5 提交、6 回退。基础修复菜单保留 1–5，新增 6 TCP、7 端口。

中转节点入口的第 3 项为基础引导验收，第 4 项为续封、精确删除和自然到期验收。`--install-relay` 和 `--install-relay-bouncer` 成功后自动只读检查服务与防火墙，终端中可选择进入向导；检查结果单独说明，不把后续检查异常改写成安装失败。

智能流程偏好保存在 `/var/lib/crowdbastion/user-flow.json`（版本 1、0600），包括业务目标、网站实例选择、暂缓和尝试记录，不含密钥或原始日志。首页 `3` 确认目标时同步适用的旧用途；旧 `node-roles.json` v1 和高级 `4 → 7` 保留。`remote` 与 `web`/`relay` 仍互斥，允许 `remote node`。内容损坏可以明确重设；不安全的权限、归属或链接须先人工修正。读取不创建状态，目标调整不执行部署迁移，退出后先重新检查再续办。

网站用途引导提供 Docker bridge 私有端点登记步骤，网站防护接入子菜单的第 `8` 项也可登记。先准备可达的私有 LAPI/AppSec 地址，登记后再安装 bridge 网站拦截组件；宿主机和 host 网络可跳过。沿用 `--configure-docker-endpoints` 的核验及确认流程。

原用途专项检查页（`4 → 8`）提供 `1` 推荐操作、`2` 查看技术详情、`3` 重新检查、`4` 导出脱敏报告、`0` 返回。操作后仍留在流程，详情展示本次已采集的输出；成功修改配置或服务后自动只读复查，取消或失败保留本页，仍可选 `3` 手动重查。服务排查读取状态和日志，核心还校验配置；对明确停止或失败的 core／Firewall Bouncer，经确认后可尝试启动。核心配置校验失败时不启动，V2bX 仅排查。CLI 参数、输出方式和退出码保持不变。

子菜单在操作后保留，输入 `0` 返回；返回菜单和无效选项不再额外暂停，叶子操作最多保留一次阅读暂停。输入结束或 `Ctrl+D` 可退出菜单。删除、注销、停用和卸载操作默认取消，需要明确输入 `y`。命令行操作失败返回非零状态，交互菜单会保留供继续操作。

修改操作之前必须已有 Python 3；安全锁检查依赖标准库，缺少时在打开锁或业务写入前停止，包括首次安装，不提供绕过锁的自举。安装、修复、更新等修改操作使用同一把 `flock` 锁，并发操作返回 `75`。TG 机器人确认后的修改也使用这把锁；占用、迁移未完成或维护路径不安全时明确反馈未执行，需重新发起。日常管理 `2 → 1/2/3` 以及高级管理 `4 → 1`、`4 → 2`、`4 → 3`、`4 → 5`、`4 → 6` 沿用原菜单持锁方式。智能首页、推荐与只读检查不持续持锁；偏好/进度保存和实际修改单独取得现有锁。基础安装和远端连接的输入与确认在锁外，写入前锁内复核计划、目标与不可跳过的前提；现有专项多步骤工具继续保留其预检和确认。确认启动服务后，锁内复验 unit 已加载、状态查询正常且仍为 `inactive`／`failed`；核心还重新执行 `crowdsec -t`，Firewall Bouncer 执行原有后端 guard，检查通过后才启动并核对运行状态。

## 状态与退出码

`--environment-status` 不读取 API 凭据、不修改服务或配置。版本 1 JSON 包含 `state`、`phase`、`error_code`、`duration_seconds`、`retryable`、`windows`、`unavailable` 与固定操作建议 `reason`。I/O 等待使用相邻 CPU 计数器差值，PSI 使用 stall total 的采样差值，不将历史平均当作本次持续压力；PSI 不可用只列入可选信号缺失。此短时观察不代表性能测试或后续命令耗时保证。`--repair-existing` 与 `--optimize` 在已有管理锁内、确认后写入前执行同源检查，环境不稳定或无法确认时返回 `75` 并暂停修改；可先排查宿主机存储和内存，再重试。环境菜单和已有修改门禁显示同一次报告的短理由，不再打印 windows JSON；显式状态输出完整 JSON。其他安装入口不新增压力门禁，但都遵守 Python 3 安全锁前提。

防火墙决策入核详情提供脱敏的 `phase/error_code/duration_seconds/retryable` 及 `phases` 阶段耗时：分别记录配置、规则引用、API、内核集合和成员比对，失败保留已完成与失败阶段；空链检查内嵌 API 失败标为 `nested`，与父阶段重叠，不应相加。API 401/403 为 `api_auth_failed`，超时为 `api_timeout`，响应格式为 `api_response_invalid`，规则/集合读取分别为 `rules_read_failed/ipset_read_failed`。单次超时不表示认证失败；原有 state 与退出码保持兼容。

`--status`、`--relay-status`、`--diagnose-v2bx` 默认显示简短总结，区分运行通过但拦截待验证、发现问题、部署未完成与检查未完成。退出 `1` 表示发现异常或读取失败，`2` 表示部署／证据不全或实际拦截待验证；组合用途中 `1` 优先。详情参数沿用相同判断和退出码。服务、规则引用和累计 AppSec 计数不代表所有公网站点已验证阻断。

`--status-json` 使用相同采集和结论规则，正常输出单个 JSON 对象，字段包括 `version=1`、`checked_at`（Unix 秒）、`config_path`、`roles`、`scope`、`checks`、`required`（原始采集中的必检项）和 `summary`；进程退出码与 `summary.status` 一致。无 root、依赖缺失或初始化失败时可能没有有效 JSON，调用方应视为检查未完成。只读状态不会把历史验收或服务 active 当作当前流量阻断通过。

健康检查与专项 AppSec 状态共用有效数据源检查，每次读取一次监听列表；WebUI 共用部署就绪检查，每次只核对一次容器健康、实际端口的 HTTP 健康响应及独立 LAPI 登录，未配置端口时使用默认 3000。可选组件未部署不会作为异常。

`--verify-relay` 与 `--verify-relay-lifecycle` 返回 `0` 表示本次入口的人工连接对照与本机证据全部齐全，`1` 表示已确认连接对照失败，`2` 表示未完成／证据不足／取消，Ctrl+C 返回 `130`。它只验证声明的新连接入口，不更改静态健康检查的结论。

具体状态入口的退出码见[使用说明：安装后的验证](usage-guide.md#安装后的验证)。

## 账号与兼容参数

Machine 是 LAPI 客户端凭据，名字相似不代表重复的防御引擎；脚本不会根据名称、日期或版本自动重建宿主机身份，也不会批量删除所有 `webui-*` 或其他 Bouncer。

Machine 清理、WebUI 部署／卸载及防火墙 Bouncer 修复按 `config.yaml` 与 `.local` 合并后的 `api.client.credentials_path` 读取宿主机身份和 LAPI 地址。凭据路径须为绝对路径；配置覆盖或所需凭据无法读取时停止操作，避免误注销宿主机身份或连接旧 LAPI。

菜单编号已调整，原命令行操作参数保持兼容。`--reset-56` 和卸载别名仍可使用。

## V2bX 持久观察样本

`--v2bx-observe` 使用 `V2BX_LOG_FILE`、`V2BX_LOG_CORE`、`V2BX_OBSERVE_DB` 指定源和私有数据库，沿用 `V2BX_LOG_TIMEZONE`、`V2BX_RELAY_CIDRS`、`V2BX_UNIT`。可设 `V2BX_OBSERVE_DURATION`（默认60秒）、`V2BX_OBSERVE_MAX_EVENTS`（默认100000）、`V2BX_OBSERVE_EXPORT`（新的快照路径）。它只保存脱敏投影与采集指标，不安装服务／CrowdSec acquisition 或产生决策。完成返回2；错误返回1，Ctrl-C返回130。

快照覆盖全部已保存事件，不适合作为反复更新的实时tail文件。轮转与截断的连续性风险、同一源重复采集的限制及具体命令见 [V2bX 指南](v2bx-guide.md)。

## 可选入口端口策略

`--port-policy-plan`、`--port-policy-status` 只读；`--port-policy-apply` 从固定私有文件 `/var/lib/crowdbastion/port-policy.json` 规划并确认后暂存，15 分钟未提交自动回退。`--port-policy-verify` 核验规则与持久化文件，`--port-policy-commit` 重新核验并提交，`--port-policy-rollback` 恢复未提交事务。仍然每次只能指定一个操作。外部客户端验收需要独立完成；规则通过不表示实际流量已经验证。JSON 格式、自动化 Python 参数、host-only/Docker 覆盖边界及回退恢复接口见 [端口策略说明](port-policy.md)。

## 独立可选的 TCP 配置

`--network-status`、`--network-plan` 只读审计网络配置归属、链接别名、systemd/procps 加载顺序、运行值和真实维护副本。`--network-apply` 从私有 `/var/lib/crowdbastion/network.json` 读取显式选定的 TCP 项，确认后恢复本机临时网络命名空间读取的内核默认值并暂存；15 分钟未提交自动回退。`--network-verify`、`--network-commit`、`--network-rollback` 仅选择网络事务，端口事务保持独立。默认安装及 `--optimize` 不调内核参数。支持范围、覆盖归属、错误码与实际中转验收边界见[网络配置说明](network-configuration.md)。

## 只读程序／协议／传输画像

`--protocol-status` 读取声明 `NODE_PROGRAM`（v2bx/v2node）、`NODE_PROTOCOL`、`NODE_TRANSPORT`、`NODE_TOPOLOGY`（direct/shared-relay/unknown）；不保存用途偏好、不发现配置或验证版本，返回 2 表示运行证据尚未验证。程序名不能作为协议名。V2Node 仓库归属尚未确认时只给候选说明，不声称配置解析支持。传输不明保持未知；内核 TCP BBR 不设置用户态 QUIC 拥塞控制。`--diagnose-v2bx` 保留原接口与三内核诊断。官方来源、精确边界和示例见[协议能力说明](protocol-capabilities.md)。

`--optimize` 先校验已有用途：明确仅落地／远端执行／中转且无托管网站时跳过 HTTP 修复；未选择用途保留旧提示顺序，存在托管网站仍保留网站检查。独立网站请使用网站专项命令。

## 可选变更输出与自动化

`--network-status/plan`、`--port-policy-status/plan` 保留完整 JSON；`--environment-status` 始终输出采样 JSON。菜单中的状态／计划及 shell apply/verify/commit/rollback 显示简短结论。需要完整变更结果的自动化使用各指南中的直接 Python 命令；Python 入口不弹确认框，apply 即授权执行。

无变化显示“无需变更”，不创建新事务；已有未提交事务会提示在原期限内提交；`apply_failed` 即使 `state=rolled_back` 仍返回 `1`。核验失败或过期提交不会取消恢复机会。JSON 的 `pending_change` 与 `pending_kind` 指明应先处理的事务类型；过期 commit 返回 `state=verification_failed/refusal_code=transaction_expired`。其他未知错误保持固定拒绝信息，不从异常文本推断原因。环境／锁暂缓保留 `75`，格式化结果不掩盖原失败码。

Python 同源环境入口也可 `python3 lib/crowdbastion_environment.py --guard --human`：同一次有界采样的短理由，稳定返回 `0`，未知或持续压力返回 `75`；此展示选项不替调用方取得管理锁。

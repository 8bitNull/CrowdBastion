# 命令行参考

[返回 README](../readme.md) · [使用说明](usage-guide.md)

按参数查找操作；首次使用请先按使用说明选择部署场景。安装与配置入口仍有交互输入。

## 目录

- [参数](#参数)
- [菜单交互与并发](#菜单交互与并发)
- [状态与退出码](#状态与退出码)
- [账号与兼容参数](#账号与兼容参数)

## 参数

```bash
bash install-crowdsec-1panel.sh --help
```

| 参数 | 功能 |
| --- | --- |
| `--install-core` | 安装核心和 Firewall Bouncer |
| `--install-relay-bouncer` | 安装/接入独立远端 Firewall Bouncer，不安装本地核心 |
| `--configure-relay-bouncer` | 交互修改远端 URL 与隐藏密钥 |
| `--relay-bouncer-status` | 只读检查托管远端配置和服务，不验证远端认证或业务阻断 |
| `--remove-relay-bouncer` | 移除托管远端配置并停用，保留基础配置、包、二进制和 unit |
| `--install-relay` | 纯中转节点精简安装：系统/SSH 规则与采集，保留已有 Web/AppSec |
| `--relay-status` | 只读检查中转 INPUT/FORWARD、IPv4/IPv6 规则引用；异常 1、尚未验证 2 |
| `--relay-path` | 交互声明节点角色/流量路径，选择 TCP/UDP 端口，读取 socket/NAT 与 Bouncer 证据 |
| `--diagnose-v2bx` | 只读核查 V2bX 三内核配置、日志、混合入口声明和本地 Bouncer；详见 [V2bX 指南](v2bx-guide.md)，未验证端到端保护返回 2 |
| `--v2bx-log-check` | 只读检查三内核日志样本；菜单 `4 → 4 → 2`，用 `V2BX_LOG_FILE/CORE/TIMEZONE`、`V2BX_RELAY_CIDRS`、`V2BX_UNIT` 指定输入；返回 2 表示生产未验证，见 [V2bX 指南](v2bx-guide.md) |
| `--v2bx-observe` | 持久保存固定观察投影、恢复游标与采集指标，可导出一次性快照；仅命令行，不安装常驻服务或规则；参数见下方说明及 [V2bX 指南](v2bx-guide.md) |
| `--install-v2bx-observer` | 安装落地常驻仅观察服务，需私有 JSON 配置文件（命令行用 `V2BX_OBSERVER_CONFIG`，菜单可输入路径）；菜单 `4 → 4 → 3 → 1` |
| `--v2bx-observer-status` | 只读服务、心跳及指标，业务保护未验证返回 2 |
| `--disable-v2bx-observer` | 停止并禁用本工具观察服务，保留配置、数据库与游标 |
| `--enable-v2bx-alerts` | 接入仅观察规则／采集与 profiles guard，重启核心并启动增量发布；菜单 `4 → 4 → 4 → 1` |
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
| `--update-hub` | 带锁、快照、校验及失败回滚的 Hub 更新 |
| `--check-logs` | 只读检查新增/漏采日志和重复采集 |
| `--clean-redundant` | 查看节点并选择注销，保留受保护账号 |
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
| `--custom-bot` | 可选交互机器人配置/更新、只读检查及独立停用 |
| `--optimize` | 诊断后逐项选择基础规则、日志采集和指标，汇总确认后统一加载 |
| `--enable-wal` | 确认本地 SQLite 后启用官方 WAL 配置 |
| `--status` | 只读健康检查 |
| `--help`、`-h` | 帮助，不需要 root |

每次仅指定一个操作。`--update-hub` 可无人值守执行；其他安装/配置入口仍保留必要的输入与确认。

## 菜单交互与并发

| 主菜单 | 功能 |
| --- | --- |
| 1 | 安装与接入：核心、网站防护、真实 IP、Docker 私有端点、中转模式 |
| 2 | 检测规则：集合安装／移除、基础规则、手动与定时 Hub 更新 |
| 3 | IP 封禁与放行：告警／决策、封禁／解封、防火墙、AllowList、Self-Report |
| 4 | 检查与修复：健康、日志、AppSec、真实 IP、中转与 V2bX、基础修复和 WAL |
| 5 | 控制台与通知：WebUI、Console、Telegram |
| 6 | 卸载与清理：卸载／清理、只读残留检查 |

检查与修复的五个入口依次为：整体运行情况、网站问题、中转节点、V2bX 落地节点、基础配置修复。V2bX 入口统一提供配置检查、日志检查、持续记录和异常告警。

子菜单在操作后保留，输入 `0` 返回；输入结束或 `Ctrl+D` 可退出菜单。删除、注销、停用和卸载操作默认取消，需要明确输入 `y`。命令行操作失败返回非零状态，交互菜单会保留供继续操作。

安装、修复、更新等修改操作使用同一把 `flock` 锁，并发操作返回 `75`；安装与接入、检测规则、IP 封禁与放行、控制台与通知、卸载与清理菜单持锁直到返回主菜单；检查与修复菜单按具体修改动作持锁，只读检查不获取管理锁。

## 状态与退出码

`--status` 用“正常 / 异常 / 尚未验证”区分已有证据与未验证链路：退出 `1` 表示异常，`2` 表示仍有未验证项目。正常运行的服务和累计 AppSec 计数不代表所有公网站点已验证阻断。

健康检查与专项 AppSec 状态共用有效数据源检查，每次读取一次监听列表；WebUI 共用部署就绪检查，每次只核对一次容器健康、实际端口的 HTTP 健康响应及独立 LAPI 登录，未配置端口时使用默认 3000。可选组件未部署不会作为异常。

具体状态入口的退出码见[使用说明：安装后的验证](usage-guide.md#安装后的验证)。

## 账号与兼容参数

Machine 是 LAPI 客户端凭据，名字相似不代表重复的防御引擎；脚本不会根据名称、日期或版本自动重建宿主机身份，也不会批量删除所有 `webui-*` 或其他 Bouncer。

菜单编号已调整，原命令行操作参数保持兼容。`--reset-56` 和卸载别名仍可使用。

## V2bX 持久观察样本

`--v2bx-observe` 使用 `V2BX_LOG_FILE`、`V2BX_LOG_CORE`、`V2BX_OBSERVE_DB` 指定源和私有数据库，沿用 `V2BX_LOG_TIMEZONE`、`V2BX_RELAY_CIDRS`、`V2BX_UNIT`。可设 `V2BX_OBSERVE_DURATION`（默认60秒）、`V2BX_OBSERVE_MAX_EVENTS`（默认100000）、`V2BX_OBSERVE_EXPORT`（新的快照路径）。它只保存脱敏投影与采集指标，不安装服务／CrowdSec acquisition 或产生决策。完成返回2；错误返回1，Ctrl-C返回130。

快照覆盖全部已保存事件，不适合作为反复更新的实时tail文件。轮转与截断的连续性风险、同一源重复采集的限制及具体命令见 [V2bX 指南](v2bx-guide.md)。

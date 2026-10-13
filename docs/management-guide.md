# WebUI、Telegram 与维护参考

[返回 README](../readme.md) · [使用说明](usage-guide.md) · [命令参考](cli-reference.md)

本页说明可选组件的接入条件、通知证据、更新事务与恢复范围。常用操作步骤见使用说明；AppSec 策略见[接入参考](appsec-guide.md#正文与故障策略)。

## 目录

- [WebUI](#webui)
- [Telegram](#telegram)
- [Hub 更新与维护副本](#hub-更新与维护副本)
- [SQLite WAL](#sqlite-wal)
- [备份、失败恢复与卸载](#备份失败恢复与卸载)
- [官方参考](#官方参考)

## WebUI

WebUI 从官方 `latest` 拉取目标镜像，部署固定为已拉取镜像的 `@sha256` 摘要，并记录旧镜像用于失败恢复。采用宿主机网络，端口默认 `3000`；部署前须明确确认已通过现有防火墙限制端口并配置 HTTPS 反向代理。SSH 隧道本身不会隐藏公开端口。脚本显式启用认证，首次访问仍需创建管理员。LAPI 使用独立 Machine，指标读取有效 loopback 端点；已有有效账号会复用，轮换后只有新账号就绪才注销旧账号。

成功要求容器健康、实际端口 `/api/health` 和独立 LAPI 登录全部通过；端口占用须确认进程属于该容器。拉取失败保留部署，更新失败尝试恢复原配置和镜像。数据保存在 `/opt/crowdsec-web-ui`。

## Telegram

经用户批准，增加可选自定义交互机器人：`--custom-bot` 或 TG 菜单第 5 项。官方通道继续负责自动告警，新机器人默认只处理九宫格查询和按钮操作；旧 `/usr/local/bin/crowdsec_bot.py` 不自动覆盖，先核对并停用旧轮询服务/cron。机器人私有配置、同 Token 单实例、服务归属检查及失败回滚与官方通知启停独立。路径/UA 通过官方 JSON 取证修复，使用方法和权限边界见 [自定义机器人修复与接入](2026-10-13-custom-telegram-bot.md)。

Telegram 使用独立名称 `crowdsec_1key_telegram`，读取实际 `notification_dir`、`api.server.profiles_path` 及优先执行的 `.local` profiles。默认通知文件为 `/etc/crowdsec/notifications/crowdsec-1key-telegram.yaml`。重复配置会原位更新；配置前扫描实际通知目录，将同一 Bot Token / Chat ID 的旧 HTTP 通知（例如 `http_default`）从 base / `.local` profile 路由中替换，并去重本工具路由，其他目标的通知保留。

API 代理的路径前缀同样支持；动态 Chat ID 或多目标模板无法确定归属时保留，须手工核对。旧插件文件不删除，以免影响同文件中的其他通道；修改前备份，校验或加载失败回滚。停用只移除本工具通道。官方通知保留配置/更新、官方插件/API 回执测试、只读检查和停用四项，交互机器人为独立子菜单。

### 官方插件与 API 回执测试

测试会向所配置机器人发送一条真实测试消息：在私有临时配置中经 loopback 接收器转发官方插件生成的消息，检查 HTTP 响应和 Telegram JSON `ok` 回执，而非只凭 `cscli` 退出码判断成功。测试不会改写生产通知配置；失败返回 `1`，未收到插件通知返回 `2`。成功回执仅证明 API 接受，不能证明使用者已读或真实攻击取证。回执记录绑定配置和 profiles 的指纹，权限 `600`，24 小时后或配置变化后失效。出站请求不需 Telegram 来源白名单。

### 即时与批量通知

配置中可选择即时或批量通知；首次默认即时，留空保留当前模式。批量使用官方插件 `group_wait=30s` / `group_threshold=10`，达到 10 条或等待窗口结束后发送，汇总规则及数量，详细取证仅展示前 3 条告警、每条 1 个请求样本，完整记录保留在 CrowdSec。即时模式下不同规则会分别通知；HTTP 重试仍可能重复，无法保证严格只投递一次。独立 Python TG 机器人、systemd/cron 推送程序不受通知路由迁移控制，仍需核对其归属；带解封/白名单按钮的卡片不由本工具 HTTP 通道生成。

### 请求样本与消息字段

通知优先遍历 `.Events[].Meta` 的 `key/value` 列表提取 `http_path`、`http_user_agent`、`http_verb`，即时消息最多展示 3 组去重后的请求样本，保持路径与 UA 对应；无请求样本时回退到告警 `.Meta` 上下文。AppSec 兼容事件 `uri`，并解码告警 `target_uri` / `user_agent` / `method` 的 JSON 数组字符串；仅当单一上下文路径与事件一致时补齐 UA 和方法，避免混配。

没有原始字段时说明未记录，空 UA / `-` 显示“请求未提供 UA”，不再笼统显示未知。未获得正数 Alert ID 时显示“实时告警”，模拟告警及无决策告警单独标识；处置决策不代表已验证 Bouncer 实际拦截。消息采用 JSON 转义的纯文本并限制长度，避免攻击者的引号、换行、HTML 和超长字段造成发送失败。更新脚本后运行 `sudo bash install-crowdsec-1panel.sh --telegram`，选择 `1. 配置/更新` 加载新模板；已有配置不会仅因仓库文件更新而自动变化。

### 只读检查与重复来源

TG 只读检查分别报告配置、有效 profile 路由、API 测试回执和真实攻击取证，并列出同目标旧通道、重复路由、可能继续匹配的 profiles，以及按名称和 cron 内容识别的独立机器人候选；不输出 Token 或 cron 命令，不停止或删除其他服务。多个 profiles 可能互斥，诊断不擅自推断其过滤表达式。异常返回 `1`，证据不足返回 `2`；真实攻击取证未另行核验时保持“尚未验证”，即使配置和 API 测试正常也不能据此标记防护通过。

## Hub 更新与维护副本

启用后默认规则更新使用服务器时区的每天 `03:30`，写入 `/etc/cron.d/crowdsec-autoupdate`；将管理脚本和依赖复制到 `/usr/local/lib/crowdsec-1key/current`，cron 不依赖原仓库位置。手动更新使用 `--update-hub`，与安装/修复互斥；先校验、备份规则及下载数据，再更新/升级 Hub 并校验，只有内容变化才重载。

更新、校验或加载失败时恢复规则与下载数据，再校验/重载，回滚失败明确提示手工恢复。快照不备份/恢复运行中的 SQLite 数据库及 WAL。新建快照采用 format 3：文件内容以分块方式保存到快照目录的 `files/`，`transaction.json` 只保存元数据及校验值；复制或保留备份时必须保留整个快照目录。旧 format 2 快照仍可恢复，但其内嵌内容读取仍需较多内存。保留最近 14 次成功快照；失败快照保留供排查。

日志位于 `/var/log/crowdsec-1key-update.log`，权限 `600`，使用系统 logrotate 保留 8 份轮转文件。自定义时分会验证范围。此任务更新 Hub 规则，CAPI 社区名单由引擎自身同步。

维护副本仅写入本工具管理、归 root 所有且不能由其他用户写入的目录；拒绝符号链接目录及祖先路径。更新、移除和集合安装共用事务、持久快照及维护日志，使用 `/run/lock/crowdsec-1key-hub.lock`，与旧版维护入口互斥；集合安装持锁到最终核心配置校验和加载成功才提交。Hub 根、祖先和 Hub 内部符号链接在修改前拒绝，普通规则指向 Hub 的受管理链接仍可保存恢复。快照不能归因并行外部工具的改动，维护时请避免外部并发写入；首次集合安装不承诺软件包安装全流程回滚。

## SQLite WAL

SQLite 优化使用官方 `db_config.use_wal: true`，通过 `--enable-wal` 在确认数据库位于本地磁盘后启用。网络共享盘不适合 WAL。本工具不直接对运行中的数据库执行临时 PRAGMA 或 VACUUM，不承诺固定性能倍数。

## 备份、失败恢复与卸载

配置修改前备份保存在 `/var/backups/crowdsec-1key/change.*`，目录权限为 `700`，含凭据的配置文件权限为 `600`。结构化 YAML 编辑保留无关配置值，可能重排格式或去除注释；原始文件保留在备份中。

配置校验失败不重启核心；服务启动失败会恢复配置并尝试恢复原服务。逐项基础修复仅备份所选配置；取消、失败或中断时清理日志暂存文件，配置写入失败或加载失败会尝试恢复。基础集合安装、Hub 更新和集合移除共用回滚事务；部分安装、校验、加载失败或中断时尝试恢复受管理规则及下载文件，再恢复服务。恢复前检查快照完整性及外部改动，冲突时保留现场并报告人工恢复路径。`--update-hub` 的快照位于 `/var/backups/crowdsec-1key/hub.*`，不包含实时数据库；必要时可使用 `python3 lib/crowdsec_maintenance.py restore /var/backups/crowdsec-1key/hub.具体目录` 恢复，再执行 `crowdsec -t` 与 `systemctl reload crowdsec`。

系统软件包及依赖不属于该文件事务的回滚范围；失败时保留诊断输出，修复后可重新执行。

卸载需要明确确认，会停止服务、卸载检测到的软件包并删除 CrowdSec 数据、本工具 WebUI、cron 及带管理标记的维护目录。仍有宿主机 Web Bouncer 集成时，须先按上游文档移除集成并验证网站。发行版、包管理器、配置与防火墙检查在停止服务前预检；防火墙状态分为存在、确认不存在、无法判断，无法检查时中止卸载，停止服务后仍有资源也保留配置。软件包移除前保留自定义资源名称用于复查。备份、系统日志、日志轮转及软件源不自动删除；其他容器和不属于本工具的目录不进行广泛匹配清理。

手动恢复命令与操作顺序见[使用说明：备份与失败恢复](usage-guide.md#备份与失败恢复)。

## 官方参考

[AppSec 数据源](https://docs.crowdsec.net/docs/next/log_processor/data_sources/appsec/)、[HTTP 通知插件](https://docs.crowdsec.net/docs/next/local_api/notification_plugins/http/)、[Profiles](https://docs.crowdsec.net/docs/next/local_api/profiles/intro/)、[CrowdSec 配置与 WAL](https://docs.crowdsec.net/docs/next/configuration/crowdsec_configuration/)、[Firewall Bouncer](https://docs.crowdsec.net/u/bouncers/firewall/)、[WebUI 上游](https://github.com/TheDuffman85/crowdsec-web-ui)。

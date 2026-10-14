# 使用流程与官方配置验证记录

截至 2026-10-14，最新完整源码回归见[普通用户检查总结](audit/2026-10-14-health-summary.md)：796 项，775 通过、21 跳过、0 失败；健康总结专项 26 项通过，最后的旧安装清单补强另经落地服务 19 项验证。此前[节点用途与检查引导](audit/2026-10-14-node-guidance.md)记录 769 项与终端交互专项 32 项。检查总结和源码回归不代表目标 VPS 的业务阻断验收。

2026-10-13 的[常驻仅观察告警闭环](audit/2026-10-13-v2bx-observation-alerts.md)记录 730 项，710 通过、20 跳过、0 失败；新增发布器／管理器专项 23 项通过。真实采集进程、SQLite、增量发布器接入官方私有引擎，synthetic 三内核日志形成 10 组观察告警／0 观察决策，独立对照保留 1 决策。真实 VPS 尚未部署；此前[协议混合入口验收](audit/2026-10-13-v2bx-mixed-ingress.md)独立保留。各轮证据见[验收索引](audit/README.md)，使用入口见[文档索引](README.md)。

此前[本地整合](audit/2026-10-13-local-integration.md)将 README 收敛为 70 行，核验索引内 Markdown 目标、134 个归档文件哈希及 diff 空白；旧工作区另作完整私有备份。该轮后来已按用户要求推送远端；本次新增服务未生产部署。

试用前修复已开始，当前验收设施改动、客机轮次与阻断项见 [修复执行记录](audit/2026-10-12-vps-repair-progress.md)。历史“通过”不追加本轮的三次重启或长测保证。

VPS 系统、架构及防火墙的分层验收见 [2026-10-12 兼容性矩阵](audit/2026-10-12-vps-compatibility.md)。其中真实 systemd 客机、分支 fixture 和既有资源模拟分别记录，不能将全仓回归数量当作每种 VPS 的功能验收数量。 Debian/Ubuntu 包配置失败的后续修复与 1 GiB 实测见 [定位报告](audit/2026-10-12-core-install-diagnosis.md)。

## 纯中转节点精简模式（2026-10-12）

- 新增中转回归 **28 项通过**：首次/已有核心安装、文件日志/journalctl、有效路径、通配符与较宽 journal unit 过滤去重、额外过滤条件提示、完整版共存、重复执行、校验/重启失败恢复、符号链接拒绝、菜单/CLI、只读免锁、iptables/nftables/ipset、IPv6 禁用和密钥不泄露。
- 最终全量 unittest **397 项**：392 项通过、5 项需要官方插件的可选检查跳过；随后配置 `CROWDSEC_TEST_RELEASE` 单独运行这 5 项，全部通过。隔离测试依赖 PyYAML；测试进程强制使用系统 Python 的旧诊断用例通过 `PYTHONPATH` 指向已有虚拟环境依赖复验通过。
- 官方 CrowdSec **1.8.1**：`tests/verify_relay.py` 用临时配置和 loopback LAPI 验证生成的 SSH journalctl/文件数据源均通过 `crowdsec -t`，合成 SSH 失败认证文件行实际读取与解析通过。journalctl 只验证配置，未宣称目标 VPS 的真实 SSH journal 事件已验证。
- Bash 语法、Python 编译、ShellCheck（既有排除项）和 `git diff --check` 通过。独立复审发现并修复较宽 journal unit 过滤产生重复采集的问题；修复后无剩余 Important 问题。
- 未部署/重载生产服务，未操作真实 Firewall Bouncer、防火墙或 Forwardx。只读检查提供规则引用证据；TCP/UDP、IPv4/IPv6、NAT/Docker、多跳隧道共存与实际业务阻断仍需在目标节点分别验证。

功能与参考来源见 [中转模式与防护边界](relay-mode.md)。

## 分支整合验证（2026-10-12）

整合宿主机检查、真实 IP 请求关联、维护副本及私有 bridge 适配，并保留主分支已有的 AppSec 策略/证据判定、Telegram 有效配置路径、WebUI 认证、自封保护和卸载三态预检。修复维护目录归属/权限、共享 Hub 锁、Hub 根/祖先/内部符号链接快照边界，以及已有宽权限密钥文件的写入权限。独立代码复审无剩余 Critical/Important 问题。

- 完整 unittest **326 项全部通过，无跳过**；全量 Bash 语法、Python 编译、ShellCheck（沿用已说明的排除项）及 `git diff --check` 通过。
- 官方 CrowdSec 1.8.1 / Firewall Bouncer 0.0.36：隔离引擎、采集、通知 JSON、独立凭据、AppSec 请求/指标和防火墙配置检查通过。
- 官方 OpenResty 1.25.3.2 / Lua Bouncer 1.2.3：正常请求、原 WAF、AppSec 阻断、HTTP2 无长度正文、连接失败策略和真实 IP 继承通过。
- NPM、宿主机 Nginx/OpenResty 隔离适配器：正常请求 200、AppSec 403、攻击未到后端、缓冲日志与 Bouncer IP 关联通过。
- 本轮没有执行真实 Docker bridge 运行时测试，自动回归覆盖其接入/登记/漂移/诊断边界；2026-10-11 真实部署记录作为历史证据保留。本轮没有部署或重载生产服务。

输出与检查摘要见 [整合验证结果](audit/2026-10-12-integration-results.json)。下列测试数量、主机状态及部署观察均为各自日期的历史记录。

## 审查优化验证（2026-10-11，历史记录）

本节记录审查建议实施后的结果；后续章节保留历史验证，不代表当前测试数量。实施分支为 `fix/audit-optimizations-20261011`，未部署到用户 VPS。

本轮组件版本、结果摘要与运行输出保存于 [优化验证结果](audit/2026-10-11-optimization-results.json)。

- 完整 unittest：**245 项**，涵盖正常、失败、取消、重复执行，以及有效配置、`.local` 冲突、卸载未知状态、自封地址、Hub 快照/互斥/回滚和凭据保护。
- Bash 语法、全量 ShellCheck、`git diff --check`。
- 官方 CrowdSec 1.8.1：Hub 集合、配置校验、实际采集文件、独立 LAPI 凭据、决策增删、HTTP 通知插件向本地接收器投递合法 JSON。
- 官方 Firewall Bouncer 0.0.36：`-T` 配置校验，验证 nftables/iptables 覆盖保留默认值。
- 官方 OpenResty 1.25.3.2 + Lua Bouncer 1.2.3：正常请求到达后端；原 WAF 与 AppSec 分别阻断；原 Lua 依赖和钩子保留；指标读取匹配真实规则。
- 实际 HTTP2 POST 无 Content-Length：`APPSEC_DROP_UNREADABLE_BODY=false` 放行，`true` 返回 403，后端未收到请求。AppSec 连接拒绝：passthrough 放行，deny 阻止后端请求；该版本 deny 拒绝模板实际返回 **HTTP 200**，不能只用状态码判断故障阻断。
- 真实 IP 运行时：不可信来源不能伪造 CF Header，可信来源改写日志和 Lua 访客 IP；缺失/非法 Header 保留原连接地址；NPM 子级信任覆盖及可信 XFF 链验证通过。
- 诊断窗口：只比较明确声明为 counter 的 CrowdSec 序列，重置或序列变化报告无法判断；默认只读诊断不等待。流量归因仍须关联唯一请求标识。

关键审查修正已复验：隐藏 `.local` 冲突、原生策略变更后的撤销记录哈希、Hub 符号链接边界及失败恢复证据保留。

| 环境/功能 | 本轮证据 | 仍需实际部署确认 |
| --- | --- | --- |
| Debian/Ubuntu、RHEL 安装/卸载 | 模拟包管理器和服务流程、失败边界 | 真实系统升级、systemd、重启/卸载 |
| 1Panel、NPM、宿主机 Web | 配置/挂载回归及真实 OpenResty 请求 | 目标 Docker 镜像、网络、重建与原 WAF |
| Firewall | 官方配置校验、残留检查回归 | 内核 IPv4/IPv6、Docker 转发与规则释放 |
| Telegram、Console | 本地通知投递、注册流程与错误传播 | 真实 Telegram 收件、Console 接受及同步 |
| WebUI | 认证环境配置、镜像 ID 固定、readiness/凭据流程 | 真实镜像未登录保护、端口防火墙及 HTTPS |
| AppSec | URI、HTTP2 无长度正文、连接故障策略 | HTTP3、慢响应/超时、业务正文兼容 |

WebUI 的 host 网络监听范围由上游决定，脚本要求明确确认已限制入口，不承诺自动将端口绑定到 loopback。管理员 AllowList 会旁路 AppSec，只允许明确选择单个管理员地址。Hub 维护不归因并行外部工具对 Hub 文件的写入；基础集合首次安装使用同一互斥锁，但不承诺软件包安装全流程事务回滚。

验证日期：2026-10-10。依据用户指定的 CrowdSec Next AppSec 文档，使用官方稳定发布 CrowdSec **1.8.1** 和 Firewall Bouncer **0.0.36** 进行核查。

2026-10-11 后续本机优化：完整回归扩展至 **221 项**，新增 Hub 快照/回滚/互斥、WebUI 实际健康和镜像摘要、只读日志盘点、重复操作及真实请求 IP 关联。实际部署和最新验证结果见 [本机优化记录](2026-10-11-host-audit.md)。以下保留 2026-10-10 初次验证范围。

同日第二轮适配后完整回归 **241 项全部通过**，补齐宿主机动态日志与真实 IP/官方 inline Bouncer 核验、重复接入和中断回滚，NPM 配置重建/新站点继承，以及 LDNMP/NPM 的私有 IPv4 bridge 端点接入。最终支持前提与维护验收线见 [最终优化边界](optimization-boundary.md)。最新实际运行时结果记录在本机检查文档末尾，以下历史数字不作为当前总数。

同日 Bridge 缺陷修复后完整回归 **251 项全部通过**。新增只读诊断覆盖已登记/未登记端点、网络重建、监听丢失/通配监听、损坏登记及 host 网络不受影响；失败传递至 AppSec 状态检查。实际 Docker internal bridge 的容器 `Gateway` 为空，修正为在 NetworkID、IPAM 网关与容器子网均匹配时接受；普通 bridge 不使用此回退。真实临时 Docker bridge 验证登记有效、未登记、网络记录失效和监听停止的诊断结果与只读性，并复查正常请求 200、AppSec 阻断 403、攻击未到业务后端。测试资源及临时规则均已清理。

## 已发现并处理的问题

| 原行为 | 当前行为 |
| --- | --- |
| 软件包、配置、封禁或注册失败后仍显示成功 | 关键操作保留错误输出并返回非零状态；仅成功后给出对应提示 |
| 菜单 8 在只读诊断前因缺少 PyYAML 退出 | 先诊断和确认，再校验配置编辑依赖；缺少依赖时显示系统安装命令，在修改前停止 |
| 主菜单/Telegram 菜单遇到 EOF 反复循环，其他子菜单每次回到主菜单 | 菜单操作后保留，0 返回，EOF 退出；删除类操作默认取消 |
| `--help` 不支持，命令行函数失败被末尾 `exit 0` 掩盖 | 提供完整帮助，每次只接受一个操作，传播操作状态 |
| 无效 IP、时分和时长直接交给后续命令；IPv6 不同写法绕过防自封 | 验证输入，规范化 IP，拒绝当前 SSH IP，使用 Go duration |
| 通配符和具体 access/error 路径同时采集 | 去除被通配符覆盖的重复条目，保留用户其他采集文件 |
| 1Panel 真实目录为 `log/` 与 `www/sites/`，原预设仅包含 `logs/` 与 `data/sites/` | 补齐用户反馈的真实 HTTP 日志路径，保留旧布局兼容；不采集 `stream-access.log` 或 PHP 日志 |
| 同一 1Panel 容器的 `/www` 实际挂载为 `/opt/1panel/1panel/www`，站点访问不写全局日志 | 补齐该已确认的挂载布局；回归覆盖两个宿主机站点根目录，文档要求按 nginx -T 与实际 Mounts 对照路径 |
| 已安装配置无法通过菜单修复实际 Docker 日志挂载 | 菜单 8 与 `--repair-logs` 根据现有 HTTP 文件及实际 Mounts 补齐独立采集文件；读取实际启用的采集目录，去重并保留其他配置，校验失败回滚 |
| NPM 目录使用 `*.log`，会把 stream 日志当成 HTTP 日志；候选宿主机路径容易被当作官方固定路径 | 核对科技lion 的 LDNMP/NPM 上游挂载与 NPM 官方模板，收窄 NPM 到 HTTP 文件，文档明确默认和候选目录及 Docker 挂载验证方法 |
| 日志集合被描述为已部署完整 WAF | 区分日志检测、Firewall Bouncer 和 AppSec；补全官方数据源及 Web Bouncer 接入流程 |
| Docker 1Panel OpenResty 被引导选择宿主机 Bouncer；未核验监听就提示引擎已加载 | 按实际安装展示宿主机选项，检查实际监听；识别容器网络与 1Panel WAF，支持接入已安装且有持久化配置的 host 网络 Docker Web Bouncer；缺少组件时说明安装前提 |
| 1Panel 仅有原 WAF，没有 CrowdSec Web Bouncer，AppSec 一直无请求 | 增加首次安装入口，持久化官方 Lua 库与私有配置，原 WAF 先执行、日志钩子保留；按运行时 Lua 能力适配 LDNMP/NPM 与宿主机包安装 |
| 原 WAF 用 dofile 组合时 ngx.exit 跨 C 调用边界报错 | 真实 OpenResty 复现后改用 loadfile 加载并直接调用 Lua 函数；原 WAF 阻断与 AppSec 阻断均通过真实请求验证 |
| 回滚重载失败后删除仍可能被运行中 worker 使用的依赖；已注销账号阻止清理重试 | 回滚运行失败保留账号和资源并记录恢复状态；重载成功后清理提交，失败可重试，核对账号不存在后继续 |
| 宣称固定“56 个黄金规则”，回退时清空 collections/scenarios | 补齐官方基础集合，保留自定义及 AppSec，不宣称固定数量 |
| 名称、版本、日期导致宿主机凭据“异常”误判，检查会重建账号 | 用真实 LAPI 登录判断；健康检查只读，身份修复不自动覆盖 |
| WebUI 更新先注销所有 webui-* 并删除旧容器 | 复用并校验独立凭据，先拉取镜像；失败恢复配置和旧镜像容器，轮换成功后才注销旧凭据 |
| Bouncer 修复批量删除其他账号、手写非官方配置 | 保留软件包默认配置与其他账号，用 .yaml.local 覆盖，先验证 LAPI 密钥访问 |
| IPv6 crowdsec6 和自定义 nft 表漏检，卸载后残留阻断 | 检查默认及配置的表；在软件包删掉配置前核验残留，未清除则中止 |
| AppSec 停用会断开外部接入，回滚后网站仍使用错误运行配置 | 记录本工具改动的接入和原 URL，仅恢复这些接入；失败回滚后同步重载网站 |
| Telegram 模板把 Meta 当字典且直接拼接 JSON、Profiles 可能缩进错误 | 使用官方模型可用字段和 toJson，结构化设置顶层 notifications，保留其他通道 |
| Telegram 测试仅用 curl，未检验实际通知模板 | 使用官方 cscli notifications test；真实引擎验证模板已完成 |
| 发出站告警却添加宽泛 Telegram 来源白名单 | 本工具不添加该白名单；旧配置由用户确认是否保留 |
| 定时更新描述混淆 Hub 规则与 CAPI 名单 | 明确 cron 只更新 Hub 并校验/重载，名单同步由引擎负责 |
| 对运行中的 SQLite 执行临时 PRAGMA/VACUUM 并承诺性能倍数 | 明确确认本地 SQLite 后设置官方 db_config.use_wal，不执行 VACUUM |
| pkill -f 可匹配管理脚本自身，卸载广泛匹配所有容器/目录 | 停止明确服务和本工具容器，禁止广泛进程清理；残留检查保持只读 |
| 卸载核心仍留下需要 /etc/crowdsec 配置的 Web Bouncer | 发现宿主机 Web Bouncer 集成时先中止卸载，要求先移除集成并验证网站 |

## 模拟用户操作

`tests/test_workflows.py` 共 **99 项**测试全部通过，覆盖主菜单和全部子菜单的流程，以及关键正常、失败、取消、重复操作：

- 核心安装成功/软件包失败、管理员白名单、配置验证失败恢复。
- 复现用户反馈的 1Panel 文件目录及 `/opt/1panel/1panel/www` 挂载变体，验证生成的采集配置匹配全部 HTTP access/error 文件且每个文件只匹配一次，排除 stream/PHP 日志；两次路径修复前对应回归均失败，修复后通过。
- 核对 LDNMP 默认文件的 nginx 标签；NPM 五个预设目录中的官方 HTTP 文件均匹配一次，排除 stream/fallback stream/主进程日志。NPM 回归修复前失败、修复后通过；这些文件匹配测试不替代真实部署日志解析验证。
- 菜单 8 和独立日志修复：实际 1Panel/NPM 自定义挂载、含空格和通配符特殊字符的路径、父子挂载遮蔽、单文件/Go 通配符/符号链接别名去重、Docker 不可用回退、原配置保留、取消、重复运行、校验失败恢复。读取 `.local` 指定的采集目录；日志处理服务禁用、目录未配置、修复文件是符号链接或挂载数据无效时，在写入及重启前停止。
- WebUI 首次部署、凭据复用、独立登录检查、轮换、拉取失败、运行失败恢复、原镜像固定与定向卸载。
- 日志规则安装失败、基础集合补齐、自定义规则保留、指定卸载取消。
- 官方 AppSec YAML、外部监听保留、Web Bouncer 缺失、接入前 URL 恢复、停用失败时恢复运行配置。
- AppSec 新增部署回归：用户反馈的 Docker OpenResty/host 网络/1Panel WAF/缺少 Web Bouncer 组合，不再展示缺失的宿主机选项；无监听不报告引擎已加载；实际 `.local` 采集目录生效。Docker 已有 Bouncer 接入、凭据保留、取消、重复运行、bridge/缺少钩子/非持久化/子 tmpfs 遮蔽时停止，以及重载失败恢复均覆盖。
- Docker AppSec 生命周期：停用恢复接入前地址并重载；手工修改过的地址不覆盖；通过名称和挂载核对支持容器重建及重新接入后的容器配置路径变化；停用时的临时文件创建、数据源删除、核心校验失败恢复文件与已变更的运行配置。存在管理的容器接入时阻止卸载核心。
- 默认/自定义 cron、无效时分、十进制前导零、服务前提。
- 封禁成功/失败、非法地址、IPv4/IPv6 SSH 自封保护。
- Console 注册成功/失败与身份保留。
- Telegram 输入验证、Profiles 顶层配置、重复配置、停用、官方插件错误传播。
- 核心诊断只读、取消优化、官方 SQLite WAL 配置。
- 缺少 PyYAML 时仍完成菜单 8 的只读诊断；取消正常返回，确认应用时在修改配置、规则或服务之前停止，不隐式安装依赖。
- 注销节点的宿主机保护、残留检查只读、卸载取消、确认删除范围、Web Bouncer 保护和自定义防火墙资源保护。

完整回归共 **148 项**全部通过。首次安装测试另覆盖真实 Mounts、已知 WAF 三阶段与日志保留、依赖隔离/私有密钥、无 Lua/未知钩子/子钩子/satisfy any/bridge/只读或 tmpfs 遮蔽拒绝、持久化 HTTP 入口、取消、重复安装、下载校验/注册失败、重载回滚、恢复失败保留运行依赖、撤销与清理重试、资源手工修改保护，以及 Lua 文件钩子的诊断与重新接入。宿主机模拟测试覆盖官方包候选版本/安装计划、标准配置路径、已有账号保留、Lua 冲突拒绝和失败恢复。固定资源集成测试需要校验过的官方归档；未提供时会明确 skip。

测试使用临时目录和模拟的系统命令。它验证脚本的流程与配置产物，不等同于安装真实系统软件包或运行真实 Docker 容器。

验证命令：

```bash
bash -n install-crowdsec-1panel.sh lib/native_web_bouncer.sh lib/host_web_bouncer.sh
shellcheck -x install-crowdsec-1panel.sh lib/native_web_bouncer.sh lib/host_web_bouncer.sh
python3 -m unittest discover -s tests -v
```

## 官方程序验证

`tests/verify_engine.py` 在临时目录运行官方 CrowdSec 1.8.1，使用隔离的 loopback 端口及本地 HTTP 测试接收端，完成以下检查：

- 官方 Hub 接受全部 11 个使用到的集合：Linux、SSH、Nginx、NPM、HTTP-CVE、基础 HTTP、良性行为白名单、WordPress、iptables、AppSec 虚拟补丁与通用规则。
- 官方 HTTP 通知插件真实渲染本工具模板并向本地接收端发送有效 JSON；特殊引号、换行、空 Source 和空 Decisions 的告警检查通过。字段先以 toJson/fromJson 转为实际值，避免输出 Go 指针信息。
- `crowdsec -t` 接受修复生成的文件采集、AppSec 数据源、Profiles、通知、管理员白名单及 `db_config.use_wal`。
- 日志修复的真实引擎回归：模拟 `/www` 的宿主机挂载来源，路径包含空格、方括号与反斜杠；修复生成正确的 Go 转义路径。引擎实际启动后追加 HTTP 日志，对应文件出现在 Acquisition Metrics 中。
- 引擎实际启动后，按官方 AppSec 协议发送 `/.env` 请求，得到 **HTTP 403 / action=ban**；普通 `/` 请求得到 **HTTP 200 / action=allow**。
- AppSec 指标包含 `crowdsecurity/vpatch-env-access` 规则命中。
- LAPI 登录、手动添加及删除封禁决策成功。
- 独立 WebUI 凭据可以登录，注销该 Machine 后同一凭据登录失败，宿主机仍可登录。

官方 Firewall Bouncer 0.0.36 使用 `-T` 成功读取软件包原始 YAML 和本工具生成的 `.yaml.local` 合并结果，保留 IPv6 默认表 `crowdsec6`。其 `-t` 还会初始化防火墙后端，在当前环境因缺少 netlink 权限失败；因此不将该项列为实际阻断通过。

同时核验两种官方程序：

```bash
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1 /path/to/crowdsec-firewall-bouncer-v0.0.36
```

`tests/verify_web.py` 下载并核验官方 OpenResty **1.25.3.2** Debian 包，使用 `dpkg-deb -x` 隔离解包，不安装系统服务；与真实 CrowdSec **1.8.1**、OpenResty Bouncer **1.2.3**、lua-resty-http **0.17.1** 联合验证：

- 生成配置通过真实 `nginx -t`；普通 `/` 请求到达后端。
- 原 WAF 的 `/waf-block` 返回 403，AppSec 计数不增加，证明原 WAF 在 CrowdSec 前执行并可阻断。
- `/.env` 请求被 AppSec 阻断，未到达后端；真实 `cs_appsec_reqs_total` 从 **0 → 2**，规则 `crowdsecurity/vpatch-env-access` 命中。
- 原 init/access/worker/log 脚本实际执行，原 `resty.http` 已加载模块和磁盘文件保持原值。

```bash
python3 tests/verify_web.py /path/to/crowdsec-v1.8.1 \
  /path/to/crowdsec-openresty-bouncer-v1.2.3.tgz /path/to/lua-resty-http-v0.17.1.tgz
```

测试使用模拟原 WAF 行为的 Lua 脚本，验证组合机制，不替代 1Panel 专有 WAF、各版本 NPM/LDNMP 的生产兼容性验证。

## 真实部署验证边界

2026-10-11 新增 Cloudflare 真实 IP 修复测试：覆盖持久化 HTTP include、拒绝过宽/私有网段与已有信任规则、拒绝单文件 bind、重复更新、撤销、取消、下载异常、重载失败恢复及卸载保护。SSH 离线样本改用 UTC 时间。

同日增加 AppSec 验证的 Self-Report 提示与发送前确认：回归覆盖取消和 EOF 不发送请求，明确确认后仍读取请求前后指标。该提示不检测目标是否实际绕回本机，不声称自动消除 Console 历史问题。

可信代理扩展增加 NPM server_proxy.conf 合并、更新与撤销，保留原自定义内容和文件模式；拒绝站点已有真实 IP 覆盖。自定义模式验证明确 Header/CIDR、拒绝 RFC Forwarded/未知字段/过宽网段，并确认不下载或猜测 CDN 来源。Cloudflare 继续使用固定官方 HTTPS 来源和固定 Header，兼容原管理记录。

未知上游扩展覆盖只读诊断和确认直连分支：没有核心/curl/real-IP 模块时仍能诊断，已有管理文件和记录保持原样，不发送请求、下载网段或重载。日志证据测试覆盖 Nginx/NPM 格式、时间、空/自定义格式、读取上限和去重，跳过 stream、变量路径、未挂载路径和符号链接。诊断的外部请求标识用于人工关联证据，不自动推断可信 CDN 或完整代理链路。

独立审查发现并复现了请求内容伪造 `[Client …]` 干扰诊断和 include 文件丢失 stream 父级上下文的问题。修复后优先解析标准首字段 IP，仅在固定 NPM 日志布局中读取 Client 字段；按绝对/相对/glob include 传播 stream 上下文，跳过跨 HTTP/stream 共用或上下文不明的文件。相关伪造文本、嵌套及共享 include 回归通过。

真实 OpenResty 请求还验证了：选定 Header 缺失或无效时不尝试其他候选；IPv6 客户端地址传入日志及 Lua；NPM 站点层信任列表替代 HTTP 层继承，未受信任的 loopback 即使被父层信任也无法伪造 IP；X-Forwarded-For 从右向左跳过可信代理，保留遇到的首个不可信地址。该测试验证 Nginx 机制，不替代目标 NPM 镜像、具体代理链路的生产核验。

`tests/verify_real_ip.py` 使用隔离解包的官方 OpenResty 1.25.3.2 实际请求验证：生产生成的官方网段配置不接受 localhost 伪造的 `CF-Connecting-IP`；仅在隔离测试中额外信任 loopback 后，访问日志和 Lua access 阶段均使用 `CF-Connecting-IP`，而非伪造的 X-Forwarded-For。测试用 loopback 信任不会写入生产生成配置。

```bash
python3 tests/verify_real_ip.py --metadata /path/to/openresty-packages-metadata
```

2026-10-10 初次验证环境没有可用于部署测试的 Docker/systemd 服务，也缺少 netlink 管理权限和真实 Telegram/Console 凭据。2026-10-11 已在本机执行真实服务检查、1Panel 普通请求关联和临时 Docker bridge 验证；最新覆盖范围见本机检查记录。以下未覆盖的目标部署仍需分别核验：

1. 各发行版软件源、安装/升级、服务启动及 cron 实际执行。
2. Docker 镜像运行、反向代理认证、1Panel/NPM 容器网络与真实访问日志路径。
3. Firewall Bouncer 的 IPv4/IPv6、Docker 转发流量阻断与卸载后规则释放。
4. 已安装 Web Bouncer 对实际网站请求的转发、阻断页面和指标增长。
5. Telegram 实际机器人接收与官方 Console 接受注册后的同步。

这些项目保留了诊断及验证入口，不声称已在当前环境完成全部生产端到端验证。

## 中转路径与隔离网络验收

`--relay-path` / 菜单 `4 → 11` 只读采集本地 socket/NAT 与 Bouncer 引用；声明的节点角色不能替代来源和阻断实测。回归覆盖交互取消、EOF、端口选择、输出脱敏及 NAT 取反/不支持条件不被误报为正向证据。

`tests/verify_relay_network.py` 将完整验收限制在私有网络和挂载命名空间，先检查两种隔离，再在私有 `/run` 创建客户端/后端子命名空间。回归还覆盖相同命名空间拒绝、缺少依赖返回结构化未验证、UDP 端口占用保护、SIGTERM 及嵌套进程回收、命名 DROP 计数器不混入普通处理计数。

```bash
python3 -m unittest discover -s tests -p 'test_relay*.py'
sudo python3 tests/verify_relay_network.py --gost /path/to/gost \
  --realm /path/to/realm --bouncer /path/to/crowdsec-firewall-bouncer \
  --output /tmp/relay-results.json
```

官方 Bouncer 对接本地合成决策流 API，验收聚焦内核执行；实际日志采集另由 `tests/verify_relay.py` 验证。`--forward-only` 只证明 loopback 转发，不证明封禁。仅测试新会话；不覆盖 Docker bridge、iptables Bouncer、生产链路或性能容量。

2026-10-12 在无外部网卡、无宿主机共享目录的 QEMU TCG 客体中完成真实 nftables 验收：Debian Linux **6.1.0-47-amd64**、gost **3.3.0**、realm **2.9.6**、官方 Firewall Bouncer **0.0.36**。gost/realm/NAT × IPv4/IPv6 × TCP/UDP **12/12 通过**，每项均验证封禁来源不可达、未封禁来源仍可达、真实 DROP 计数增加和解封恢复。后端来源全部为中转节点 `10.231.3.1` 或 `fd42:231:3::1`，说明用户态转发及本次 MASQUERADE 拓扑会隐藏原始客户端地址。

原始报告：[隔离中转验收结果](audit/2026-10-12-relay-network-results.json)。精简客体先后缺少 `nft_objref`、`nft_nat`，各自独立复现缺失模块错误并补齐后重跑；这不是生产脚本自动调整内核模块的功能。测试使用真实程序和内核规则，但决策 API 为合成 fixture，不证明目标 VPS 的规则顺序、日志检测、既有长连接或防攻击容量。

同阶段完整回归 **422 项：415 通过、7 项可选跳过**；另行启用官方通知插件的 **7 项通过**。中转专项 **51/51**、loopback 真实转发 **8/8**、Bash/Python 语法与 ShellCheck 通过。

## 中转性能工具验证

2026-10-12 新增 `tests/benchmark_relay.py` 与性能指标文档。真实 loopback 测量 **8/8 无错误**；无外部网卡/共享目录的 QEMU TCG 客体中，gost/realm × TCP/UDP × 无 Bouncer/空决策/1000 决策 × 2 重复，共 **24 次测量无错误**，生成 **8 组、每组 2 个 block 的配对比较**。这些数据验证工具流程，不是低配 VPS 的开销或容量结论。原始数据及客体标记见 [性能工具烟雾报告](audit/2026-10-12-relay-benchmark-smoke.json)，定义和目标节点测量方法见 [性能测量](relay-benchmark.md)。

独立复核修正了负载 JSON 超过 pipe 容量可能挂起、失败条件丢失、未按事务数加权延迟样本的问题。gost UDP 默认响应后关闭虚拟会话的持续负载错误独立复现，基准明确启用并记录 `keepAlive=true`；原来的新会话阻断验收配置未改动。10 项基准测试（含实际官方 gost 回归和 PyYAML 缺失预检）通过，中转专项 61/61 通过。

本阶段最终全仓回归 **448 项：434 通过、14 项可选跳过，无失败**。中转专项 **61/61** 通过，Bash/Python 语法、ShellCheck 和 diff-check 通过。测试期间工作区其他任务新增的 Telegram 状态辅助脚本补齐后，重新运行完整回归确认通过；该任务的代码未由本次性能工作修改。

## Telegram 职责收敛验收

后续完成 [TG 模拟 VPS 验收](2026-10-12-telegram-vps-acceptance.md)：31 项专项/停用回归无跳过，真实 OpenResty/Bouncer 拦截与同请求 TG 卡片关联通过，即时及 10 条批量通知通过。模拟 API 不代表真实 Telegram 公网送达，临时进程实验室不代表 systemd/包管理安装验收。

2026-10-12 保留 TG 配置、官方插件/API 回执测试、只读状态与重复来源检查、停用四项功能。增加可选原生批量通知，纠正实时告警编号、模拟状态和未核验实际拦截的消息语义；官方测试检查真实 API HTTP/JSON 回执，私有证据绑定配置并在 24 小时后失效。复审发现的停用删除失败未恢复路由问题已复现并修复。

TG 专项 **29/29 通过**；完整回归 **451 项：450 通过、1 项可选跳过，无失败**。使用官方 CrowdSec **1.8.1** 的单条/批量真实引擎隔离验证通过：`/.env` 路径与实际 UA 显示、10 条告警分组、两个规则各 5 条的统计、模拟数量和 3 组有限取证；Bash/Python 语法、ShellCheck 和 diff-check 通过。停用失败回归在临时配置树中确认旧实现失败、新实现恢复全部原始配置字节。

仅使用临时配置与 loopback 接收器，未部署 VPS、未向真实 Telegram 发消息。API 接受不等于使用者已读，插件测试不验证真实攻击取证或生产 Bouncer 拦截。独立按钮机器人不属于本工具；服务/cron 扫描只给候选，不能排除其他名称的进程。详情见 [TG 修复与职责记录](2026-10-12-telegram-fix.md)。

进一步的低配模拟使用独立虚拟磁盘与 1 vCPU，不再把完整根文件系统放在 RAM 中；真实核心共存的 512 MiB 短矩阵 12/12 无错误、最低可用内存 236.1 MiB，256 MiB 共存未完成且最低可用内存 10.6 MiB；256 MiB 无核心对照 12/12 无错误、最低可用内存 88.0 MiB。三次均未观察 OOM，不能将它等同长期资源充足。首轮 512 MiB 较长测试超时保留，没有以短矩阵重跑抹去失败。详见 [低配资源模拟与原始证据](audit/2026-10-12-low-spec-simulation.md)。

ARM64 后续实际客机诊断：见 [Debian 13 ARM64 启动诊断](audit/2026-10-12-arm64-followup.md)。原生包安装与重启前远程决策同步通过；重启核心超时及后续未验证案例单独记录，不计完整验收。


### 2026-10-12 试用前修复：快照内存与严格验收

最新源码回归 581 项全部通过、无跳过（启用已验证的官方 CrowdSec 插件和 gost 可选检查）；ShellCheck、Bash 语法、Python 编译、diff 检查通过。新增快照将内容分块写入私有备份文件，防止下载文件 Base64 副本导致安装 OOM；恢复仍检查备份完整性、外部变更及数据库排除。旧内嵌快照保持兼容，其旧内容读取不宣称同样的内存上限。

61 MiB + 11 MiB 下载文件的完整快照、修改记录、恢复在 160 MiB 地址空间限制下完成，峰值 RSS 19424 KiB；这是资源受限 fixture。新快照版本的 CentOS 空白本地核心生命周期已通过；512 MiB 默认安装和三次重启通过，但旧 120 秒负载失败，整轮不计通过。新的就绪/采样观察器在独立 512 MiB 客机完成整轮短测：三次重启同步、120 秒四路径各 121 成功/0 错误、未观察到 OOM、QEMU 0。独立 1 小时轮次曾启动，但 2026-10-13 复核时进程不存在、最终报告和退出证据缺失；24 小时尚无执行证据，两者均未通过验收。详见 [内存修复与证据](audit/2026-10-12-hub-blob-memory-repair.md)和[最新修复进度](audit/2026-10-12-vps-repair-progress.md)。ARM64 原生验证、独立恢复及全时长稳定性尚未关闭，目前没有新增试用放行组合。


### 2026-10-13 文档发布前回归

在实际准备发布的检出目录重新执行全仓 unittest：**581 项全部通过、无跳过**，166.984 秒；ShellCheck、Bash 语法、Python 编译及暂存区 diff 检查通过。README、新使用说明和相关状态文档的 91 个本地链接及说明中的 29 个脚本参数核对通过。公开归档串口日志按原始字节保存，避免换行转换破坏 SHA256；新增文档和归档进行了凭据模式检查。

[发布前检查记录](audit/2026-10-13-documentation-publication.json)记录源码和主说明文档 hashes。上述是源码与文档发布检查，不授予长期稳定性、独立恢复或原生 ARM64试用资格；长测最新状态见[修复进度](audit/2026-10-12-vps-repair-progress.md)。

## 菜单、维护与 Bridge 修复历史摘要

以下从旧 README 迁入，记录各轮当时的结果；当前部署资格仍以修复进度和兼容性矩阵为准。

2026-10-12 合并边界审计：修复集合移除吞掉锁冲突退出码、已有全部集合时配置中断恢复遗漏，以及成功加载/Hub 提交后快照清理中断导致误恢复旧配置的问题；核心安装中断会清理日志暂存。删除未引用的内部函数与常量，保留历史维护路径及 CLI 别名。完整自动回归 **360 项全部通过**，独立 Hub 专项 **23 项通过**；独立审查、ShellCheck、Bash 语法及 diff 检查通过。详见 [合并后的边界审计](2026-10-12-consolidation-audit.md)。本轮未修改生产服务。

2026-10-12 状态检查收敛：健康检查与专项 AppSec 状态共用数据源检查，多个地址共用一次监听读取；WebUI 状态复用部署就绪检查，去除重复 HTTP 和 LAPI 登录检查，修复未配置端口时的默认 3000 误报。保留只读入口和异常/尚未验证退出码，补充默认端口、重复检查、多个监听和异常 HTTP 响应回归。完整自动回归 **355 项全部通过**；独立代码审查、ShellCheck、Bash 语法和 diff 检查通过。本轮验证使用隔离模拟，未修改生产服务。

2026-10-12 Hub 事务统一：更新、集合安装及移除共用锁、持久快照、变化检测、校验、加载和失败恢复；集合安装延迟到最终核心加载成功才提交，组合基础修复仍只加载一次。补充部分安装失败、后续校验/加载失败、锁竞争、中断恢复、下载文件恢复、数据库排除、快照损坏及外部改动冲突回归，完整自动回归 **351 项全部通过**；独立代码审查、Bash 语法、ShellCheck 和 diff 检查通过。本轮验证使用隔离模拟，未执行生产修改。

2026-10-12 逐项基础修复：默认不选任何项目，基础规则、日志采集和指标分别选择，汇总确认后统一加载。新增单项隔离、组合仅加载一次、取消/EOF、重复执行、端口冲突、校验/服务失败及中断恢复回归，完整自动回归 **340 项全部通过**；独立审查、Bash 语法和 ShellCheck 检查通过。本轮未执行生产修改；当时集合安装的完整 Hub 回滚限制已由后续统一事务处理。

2026-10-12 菜单收敛：主菜单调整为六类，增加嵌套返回、真实 IP 目标/动作、单一卸载入口及只读诊断锁边界回归，完整自动回归 **330 项全部通过**；Bash 语法与 ShellCheck 检查通过。原命令行分发及执行函数保持兼容，本轮未执行生产安装、重载或请求验证。

2026-10-11 最新修复包含 Bridge 登记状态诊断和 internal bridge 空默认网关判定，完整自动回归 **251 项全部通过**。真实隔离 Docker bridge 验证已登记/未登记、网络记录失效、监听停止及诊断只读性；普通请求返回 200，AppSec 攻击请求返回 403，攻击未到业务后端，测试资源和临时防火墙规则均已清理。

## 开发检查与官方引擎验证

在完整仓库根目录执行：

```bash
for script in install-crowdsec-1panel.sh lib/*.sh; do
    bash -n "$script" || exit 1
done
shellcheck -x -e SC2317,SC2329,SC2120,SC2119 install-crowdsec-1panel.sh lib/*.sh
python3 -m pip install -r tests/requirements.txt
python3 -m unittest discover -s tests -v

# 可选：下载并解压官方 CrowdSec Linux 发布包后运行真实引擎检查
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1
```

ShellCheck 排除项对应 trap/间接函数调用与默认可选参数的已知静态误报；其余检查仍启用。固定资源集成测试需要已核验的官方归档，缺少时会明确跳过，不能把跳过结果视为完整验证通过。

真实引擎检查会下载 Hub 集合，在临时目录和 loopback 端口运行，不安装系统服务、不修改防火墙、不向真实 Telegram 发送消息。
全功能审查见 [审查报告](feature-audit-2026-10-11.md)，该报告记录优化前基线。

## 自定义交互机器人接入（2026-10-13）

用户确认后接入上传的 `crowdsec_bot.py`：官方通道保留自动推送，交互机器人默认只查询/按钮操作。修复不受支持的 `--no-metrics`、人类可读正则取证、固定 DROP 描述、失败误报、用户输入 shell 拼接和白名单首次创建；加入用户/聊天双重校验、单实例、私有 offset、独立配置与服务回滚、归属检查及核心卸载清理。

机器人专项 **26/26**；全仓 **607 项：603 通过、4 项可选跳过，无失败**。官方 CrowdSec **1.8.1** 临时引擎的真实 LAPI/SQLite/CLI 验证告警事件路径/UA/按钮及保留的查询菜单，白名单通过真实 `crowdsec -t`；系统重载为模拟，未调用真实 Telegram API。Bash/Python 语法、ShellCheck、diff-check 与独立复审通过。复审发现的四项重要问题均有修复及回归。

原上传文件及 VPS `/usr/local/bin/crowdsec_bot.py` 未覆盖；新服务安装入口为 `--custom-bot` 或 TG 菜单第 5 项。迁移需先核对并停用旧轮询服务/cron，不能同时轮询同一 Token。说明见 [自定义机器人修复与接入](2026-10-13-custom-telegram-bot.md)，原始输出见 [验收记录](audit/2026-10-13-custom-telegram-bot-results.json)。

## V2bX 只读诊断第一阶段（2026-10-13）

新增 `--diagnose-v2bx`、菜单 `4 → 12`、三个内核的配置/日志核查，以及按节点声明直连/中转/混合入口的条件性封禁位置。实际解析、来源信任和端到端阻断始终保持未验证。

专项 **25 项通过**；完整回归 **646 项：626 通过、20 项按环境条件跳过，无失败**。Bash/Python 语法、ShellCheck（既有排除项）、已跟踪 diff 与新文件空白检查通过。独立审查的 scoped IPv6 输出、未解析 Include 默认地址、sing Disable、Hysteria2 未支持的 Log.Output、非普通 CrowdSec 配置阻塞均用失败回归复现后修复；另验证复用的 Bouncer INPUT/FORWARD 引用不会被解释为业务阻断。

可复现命令：

```bash
PATH="$PWD/.venv/bin:$PATH" python3 -m unittest discover -s tests -p test_v2bx_diagnosis.py -q
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=/tmp/v2bx-test-python-deps python3 -m unittest discover -s tests -q
bash -n install-crowdsec-1panel.sh lib/v2bx.sh
python3 -m py_compile lib/crowdsec_v2bx.py tests/test_v2bx_diagnosis.py
shellcheck -x -e SC2317,SC2329,SC2120,SC2119 install-crowdsec-1panel.sh lib/*.sh
git diff --check
```

本次环境的系统 `/usr/bin/python3` 缺少 PyYAML，而既有检测脚本测试将 PATH 固定为 `/usr/bin:/bin`。首次直接使用虚拟环境解释器时，shell 子进程仍使用系统 Python；将虚拟环境加入 PATH 后，基线 621 项仅剩这一项依赖失败。本次将已有 PyYAML 复制到临时 `/tmp/v2bx-test-python-deps`，通过 PYTHONPATH 提供给该子进程后完成全仓验证，没有修改系统 Python 或已有测试。正常环境在系统 Python 安装 `tests/requirements.txt` 后不需要临时 PYTHONPATH。ShellCheck 使用临时下载/解压的 Debian 0.9.0 软件包，未安装系统包。

另用用户指定的 `wyx2685/V2bX` 仓库 `71277de` 的 `example/config.json` 检查真实 CLI 和 JSON 输出；当前环境没有 V2bX/systemd 服务证据，正确报告本机查询失败/未验证，未输出原始配置凭据。全部新防护验证均为隔离样本，未向生产创建决策、重启服务或修改防火墙。真实 VPS 版本、入口来源与协议失败日志仍是第二阶段的前置证据，说明见 [V2bX 指南](v2bx-guide.md)。

## V2bX 日志观察第二阶段：离线部分（2026-10-13）

新增 `--v2bx-log-check` 与菜单 `4 → 13`、固定字段日志投影、中转 CIDR 排除、显式时间依据、未安装的观察 parser/scenario 和官方临时引擎验证脚本。适配源码来自 V2bX 71277de 的替换依赖；样本为 synthetic/source-backed，未获取目标 VPS 真实日志。

独立审查核实并修复 Xray Trojan fallback 误分类，以及 `str.splitlines()` 对控制字符/Unicode separators 分行导致的伪造事件。两项新增回归在修正前出现预期失败，修正后通过。Xray Trojan 保持 fallback_candidate，Hysteria2 仅连接事件；不宣称三内核全部协议已有认证检测。

本轮实际验证：

```bash
PATH="$PWD/.venv/bin:$PATH" python3 -m unittest discover -s tests -p 'test_v2bx*.py' -q
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=/tmp/v2bx-test-python-deps python3 -m unittest discover -s tests -q
for script in install-crowdsec-1panel.sh lib/*.sh; do bash -n "$script" || exit; done
python3 -m py_compile lib/crowdsec_v2bx.py lib/crowdsec_v2bx_logs.py tests/test_v2bx_diagnosis.py tests/test_v2bx_logs.py tests/verify_v2bx_observation.py
/tmp/v2bx-test-notes/shellcheck/usr/bin/shellcheck -x -e SC2317,SC2329,SC2120,SC2119 install-crowdsec-1panel.sh lib/*.sh
PATH="$PWD/.venv/bin:$PATH" python3 tests/verify_v2bx_observation.py /tmp/crowdsec-qa-engine/crowdsec-v1.8.1 docs/audit/2026-10-13-v2bx-observation-results.json
git diff --check
```

结果：V2bX 专项 41 项通过（诊断 25 + 日志 16）；全仓 662 项，642 通过、20 跳过，0 失败，耗时 162.844 秒。Bash/Python 语法、ShellCheck、已跟踪 diff 与新增文件尾空白检查均通过。Python 依赖与临时 ShellCheck 的环境处理同上一节，没有安装系统包。

官方 CrowdSec 1.8.1 `-t` 通过，临时引擎实际读取全部 13 条规范化构造事件，产生 5 条观察告警，逐告警和全局 decisions 均为空。场景加载 `remediation: false`；`cscli alerts list -o json` 没有 Remediation 字段，验收没有将缺失字段误判为 false。使用发行包默认 profiles；自定义 profiles 行为仍需另行验证。

源码与发行包校验值、事件范围和实际结果见 [隔离验收记录](audit/2026-10-13-v2bx-observation.md)。规则没有生产安装入口；目标 VPS 的版本、日志、来源信任、误报、重复采集、轮转和封禁/恢复仍未验证，没有修改生产采集、防火墙、服务或决策。


## V2bX 混合入口网络模拟（2026-10-13）

独立 QEMU TCG 客机，1 vCPU/1024 MiB、Linux 6.1.0-47、无外网 NIC、无宿主目录共享、快照磁盘。使用真实 CrowdSec 1.8.1 LAPI、Firewall Bouncer 0.0.36、gost 3.3.0、realm 2.9.6。没有在宿主修改防火墙/路由，没有运行真实 V2bX，不能算作三内核协议认证/日志验收。

首轮使用原有 5 秒探针进程预算失败，保留失败结果。并发启动对照实测约 12.22 秒；仅客机测试副本改用 20 秒进程等待，套接字 1.5 秒超时不变，正式测试代码与生产默认没有修改。调整后实际运行 326.67 秒，任务和 QEMU 均退出 0，无超时；12 个中转矩阵和 12 个落地矩阵的全部断言符合预期，10 条远端故障/恢复条件均通过。

实测来源对照：直连/保源 DNAT 在落地可见客户端地址并可阻断；gost 代理在落地可见中转地址，落地客户端 IP 决策不能阻断代理，正确位置由中转入口矩阵验证。健康来源和解封恢复均有实际新会话及 DROP 计数证据。

本轮定向运行 `test_relay_network.py` 10 项与 `test_remote_bouncer_lab.py` 7 项，均通过；归档脚本 Python/Bash 语法、JSON、链接和 diff 检查通过。仅文档/临时验收脚本归档变更，未重复全仓测试。详见 [实验记录](audit/2026-10-13-v2bx-vps-simulation.md)，其中保留首轮失败、时限对照、调整后全部断言、版本及实际磁盘二进制校验值。

## V2bX 真实三内核协议与日志模拟（2026-10-13）

官方 V2bX v0.4.0、sing-box 1.12.0、受控 UniProxy fixture，运行于无外网 NIC 的独立 QEMU（2 vCPU／1536 MiB）。13 个基础内核／协议组合 × 直连／gost 代理中转 = 26 案例，正常／错误凭据／恢复共 78 阶段通过；核验随机业务响应、真实日志来源及进程存活。最终 guest task 0、QEMU 0、无超时、226.13 秒。UDP 中转显式 keepalive=true、ttl=30s，原失败轮次和诊断一并归档。

实际日志揭示 sing 嵌套节点标签、Xray VMess 明确认证理由前 drain/read-timeout 包装两处漏检，已通过两个先失败后通过的回归测试修正。全部仓库测试 664 项，644 通过、20 跳过、0 失败，155.534 秒；Bash/Python 语法、ShellCheck 与 diff 空白检查通过。临时 Python/ShellCheck 环境同前述处理，不安装系统包。

真实日志投影在官方 CrowdSec 1.8.1 临时引擎回放，严格核对告警的实际来源／内核／协议组，5 个观察告警、0 决策；正常／恢复无 eligible 失败、中转来源不 eligible。另重跑原 synthetic 13 条／5 告警／0 决策测试，二者证据分开。具体条数、每协议的失败事件缺口、版本与 hashes 见 [真实验收记录](audit/2026-10-13-v2bx-real-protocol-simulation.md)。

这不是所有传输、IPv6 真实协议、UDP 应用载荷、并发压力或生产防护验收；业务通过不等于每个协议的行为检测可用。规则未接入生产，未创建生产决策，未更改宿主路由／防火墙。

## V2bX 日志覆盖与持久观察稳定性（2026-10-13）

sing AnyTLS明确认证拒绝新增观察；Shadowsocks AEAD错误仅记integrity_failure，不触发认证场景。新增`--v2bx-observe`／SQLite原子投影与游标，源和数据库单实例锁、轮转／截断风险计数和一次性私有快照。未创建生产采集或服务。

官方V2bX v0.4.0、sing-box1.12.0在native loopback完成66/66真实连接／故障对照：13组合正常／错误／恢复／目标不可达，7组合TLS名称错误，目标响应超时，以及轮转／程序重启／采样器重启／截断。不是新的QEMU或IPv6真实协议矩阵。

真实投影回放到官方CrowdSec1.8.1：严格核对6组观察告警、0决策，其他非eligible事件排除；另有16条synthetic反例／6告警／0决策，两种证据独立。最终全仓687项，667通过、20跳过、0失败，169.466秒；Bash/Python语法、ShellCheck和diff检查通过。旧fd晚写和copytruncate仍可能漏采，不能声称所有轮转无损或端到端恰好一次。

完整结果、采集指标、独立审查修正、源码版本与缺失来源的QUIC检测条件见 [本阶段验收](audit/2026-10-13-v2bx-observation-stability.md)。

## V2bX hysteria2实验拒绝事件（2026-10-13）

固定v0.4.0源码的临时fork新增hysteria2 core明确认证拒绝事件；Go两个测试及-race、Python日志23项通过。真实客户端专项13/13、完整build tags三内核回归66/66通过；实际投影官方CrowdSec1.8.1回放严格核对7组观察告警、0决策，独立synthetic18条／7告警／0决策。最终全仓688项，668通过、20跳过、0失败，155.228秒。首次并发编译期间的一项原有5秒超时、复测和范围限制均保留，见 [本轮报告](audit/2026-10-13-v2bx-hy2-structured-events.md)。实验补丁未生产部署；sing QUIC日志缺口未关闭。

## V2bX sing QUIC实验事件（2026-10-13）

固定sing-quic v0.5.0与sing-box_mod v1.13.0-alpha.5本地副本补齐TUIC/Hysteria1/2明确拒绝，专用安全logger移除新增事件的面板URL前缀。最终版本Go集成依赖图6测试-race、Python日志24项通过；真实客户端36/36、QUIC边界5/5、三内核回归66/66通过。实际三内核投影35条，分组去重后32条进入官方引擎，严格核对10组观察告警、0决策；独立synthetic24条／10告警／0决策。最终全仓689项，669通过、20跳过、0失败，165.433秒；Bash/Python语法、ShellCheck、diff和补丁适用检查通过。初版隐私失败、最终重跑与其他范围限制见 [本轮报告](audit/2026-10-13-v2bx-sing-quic-events.md)。仍未生产部署或启用自动封禁。

## V2bX 多账号、IPv6 与 UDP 应用验收（2026-10-13）

固定实验构建在 QEMU 中完成 13 基础组合 × 两地址族的配置对照，156 次健康 TCP、156 次健康 UDP 随机载荷验证通过，错误账号未取得载荷；请求区间重叠及健康／中转 peer 核查通过。原 `::` 主矩阵 25/26，hysteria2 core IPv4 另用显式 IPv4 监听对照通过，原失败保留。实际 157 投影进入官方引擎前按组去重，严格核对 20 告警／0 决策；新增探针 5 测试与现有日志 24 测试通过。详见 [本轮验收](audit/2026-10-13-v2bx-mixed-ingress.md)。没有重新运行整仓测试、生产部署、压力阈值或自动封禁。

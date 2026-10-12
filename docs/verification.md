# 使用流程与官方配置验证记录

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

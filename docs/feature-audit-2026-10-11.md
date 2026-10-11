# CrowdSec 一键脚本全功能审查与优化建议

审查日期：2026-10-11。代码基线：`c70c1672a6ab4fc26762c9d59f3a0b363f8a93e5`。本轮只增加审查记录，没有修改脚本行为。

## 结论与验证范围

现有脚本的基本结构符合官方部署思路：日志检测、LAPI、Firewall Bouncer、AppSec 与 Web Bouncer 已明确区分；真实 IP 采用明确的 Header 与可信来源，未知上游进入只读诊断；取消、配置校验、备份和撤销已有较好的覆盖。仍有有效配置读取不统一、成功判定偏弱和自封保护不完整的问题，建议先修复这些问题，再扩展自动化。

本轮逐项检查全部 CLI 和菜单入口，执行已有流程测试，并对关键遗漏分支进行临时隔离复现。“完整体验”在当前环境只能做到隔离流程和部分真实组件运行，不能等同于每个功能已在真实 VPS 部署成功。

本轮新执行的证据：

- `python3 -m unittest discover -s tests -q`：**178 项通过，33.499 秒**。系统命令替身把软件包、systemd、Docker 等操作限制在临时目录，不能证明真实安装过程。
- `bash -n` 与 ShellCheck：主脚本、`lib/*.sh`、`tools/*.sh` 全部通过。
- 额外 **75 次隔离流程实验**；其中 71 次预设退出码全部匹配，另外 4 次用于采集异常行为证据。匹配退出码不代表功能没有缺陷。精简记录见 [workflow-results.json](audit/2026-10-11-workflow-results.json)。
- 另完成 **10 次隔离卸载实验**和 3 次 PTY 菜单交互（EOF、cron 查看/返回、无效选项/返回）。卸载实验发现未知检查状态被当成无残留，见下文；[卸载记录](audit/2026-10-11-uninstall-results.json)。
- 官方 CrowdSec **1.8.1**：Hub 集合名称、配置校验、实际日志采集、LAPI 登录、独立 Machine 凭据、手动决策添加/删除、通知插件向本地测试 HTTP 接收器发送 JSON 均通过。
- 真实 AppSec：`/.env` 返回 **403 / action=ban**，正常 `/` 返回 **200 / action=allow**，规则指标命中。
- 官方 OpenResty **1.25.3.2** + OpenResty Bouncer **1.2.3**：生成配置通过 `nginx -t`，正常请求到达后端，原模拟 WAF 阻断仍生效，AppSec 阻断发生在后端之前，Processed 从 **0 → 2**。
- 真实 OpenResty real-IP：未信任的来源无法伪造 Cloudflare Header；可信测试来源下日志和 Lua 使用访客地址；缺失/无效 Header 保留连接地址；NPM 站点信任替代父层继承；XFF 从右向左处理可信代理链，全部通过。
- 官方 Firewall Bouncer **0.0.36** 的 `-T` 合并配置验证通过，包含 nftables/iptables、IPv6 默认表和 Docker IPv4 链覆盖。**未进行真实内核防火墙阻断测试**。

测试未向 Telegram/Console 发送消息，未安装生产服务。真实 Web 测试使用模拟原 WAF，不能替代 1Panel 专有 WAF 与目标 NPM 镜像测试。

## 功能逐项体验清单

“流程”指真实执行 shell/Python 逻辑、替代系统边界；“组件”指官方程序在临时配置下运行；“审查”指阅读入口及其依赖。以下结果不表示每个功能的所有失败分支都已覆盖。

| 功能与入口 | 本轮验证证据 | 结果及剩余边界 |
| --- | --- | --- |
| 主菜单、帮助、全部命令分派、非法参数、EOF | 流程测试、语法与静态检查 | 通过；子菜单可返回，EOF 可退出，CLI 失败传播已有覆盖 |
| 核心 + Firewall 安装 `--install-core` | 成功、软件包失败、无效 IP、EOF 流程；官方组件配置 | 常规流程通过；真实 apt/dnf/systemd 未体验；自定义采集目录存在遗漏 |
| WebUI 部署/更新 `--install-webui` | 凭据复用、新账号、拉取失败、容器失败、旧镜像回滚流程 | 流程通过；实际镜像的认证、HTTP 就绪与 LAPI 同步未验证 |
| WebUI 凭据检查/轮换 `--reset-webui-credentials` | 新凭据、旧账号延后删除、失败回滚；真实 Machine 登录/撤销 | 基础流程通过；成功标准需从容器 Running 升级为应用就绪 |
| WebUI 卸载、日志查看、节点清理 `--clean-redundant` | 确认/取消、只删本工具 Machine、保护宿主机账号；日志入口审查 | 不自动按相似名称删账号；生产日志查看未运行 |
| Web 日志集合 `--install-waf` | 流程、官方 Hub 安装与配置校验 | 集合有效；安装集合不能证明已有正确日志来源 |
| WordPress、iptables 集合菜单 | 官方 Hub 接受集合、菜单调用审查 | 需核验站点日志与内核日志真实采集，iptables 集合本身不创建阻断规则 |
| 集合列表、手动 Hub 更新 | 流程与真实 Hub 更新 | 常规通过；升级后验证失败缺少 Hub 状态事务回滚 |
| 基础集合 `--reset-baseline` / `--reset-56` | 自定义与 AppSec 保留流程、官方 Hub | 通过；正确地不保证固定场景数量 |
| 指定移除集合、`--uninstall-waf` | 取消、已知集合操作与依赖审查 | 保留 AppSec；移除失败/配置失败后恢复机制仍需加强 |
| 日志修复 `--repair-logs` | 实际 Mounts、路径别名去重、活动配置覆盖、特殊字符、只读/遮蔽挂载、取消/回滚 | 流程与真实采集通过；自定义格式和动态日志仍需人工核验 |
| AppSec 引擎 `--install-appsec` | 官方数据源、监听检查、外部配置保留、实际正常/攻击请求 | 引擎通过；网站是否接入需单独证明 |
| 接入已有宿主机/容器 Web Bouncer | host/bridge、钩子、持久化、重复接入、重载失败、配置变化流程 | 有 `.local` 优先级遗漏，可出现接入假成功 |
| 首次 Web Bouncer `--install-web-bouncer` | Docker/NPM/宿主机流程、摘要校验、原 WAF 保留、失败回滚、依赖安装计划检查；真实 OpenResty | 支持范围内流程通过；真实宿主机包安装、目标容器镜像未验证；bridge/无 Lua 的拒绝是明确边界 |
| Web Bouncer 撤销 `--remove-web-bouncer` | 恢复原钩子、手工修改保护、清理失败重试、已撤销账号重试 | 容器流程通过；宿主机官方包撤销仍需按上游手工完成 |
| AppSec 状态 `--appsec-status` | 缺源、监听、组件审查与流程 | 不能仅凭监听/组件存在证明网站防护生效 |
| 网站验证 `--verify-appsec` | 取消/EOF 无请求、确认后请求；额外失败样本复现 | HTTP 200 且计数不变仍返回 0，需要自动结果判定 |
| 停用 AppSec `--disable-appsec` | URL 恢复、外部配置保留、重复接入、容器重建、核心失败与重载回滚 | 常规流程通过；应与接入共用有效配置解析 |
| 真实 IP 修复 `--repair-real-ip` | Cloudflare/自定义 CIDR、候选 Header、NPM 合并、冲突拒绝、取消/回滚；真实请求 | 通过；不应改为从任意 Header 自动信任。可信来源和 Header 约定仍必须明确 |
| 未知上游诊断 `--diagnose-real-ip`、确认直连分支 | 无核心/curl/模块、有限日志、标准/NPM 格式、伪造 Client 文本、stream include 排除 | 通过；输出是证据而非代理身份认证，直连分支保留现有规则 |
| 真实 IP 撤销 `--restore-real-ip` | 更新/撤销、备份、手工变化、挂载变化与卸载保护 | 通过；实际容器升级/重建后需复核挂载和站点访问 |
| Hub cron `--enable-cron`；自定义时间、查看、停用 | 时分验证、前导零、文件写入、菜单审查 | 配置通过；未体验 cron 实际执行；缺少锁、结果日志和升级回滚 |
| 决策、告警、防火墙、指标菜单 | 真实 LAPI 决策；只读命令审查；IPv6/自定义 table 流程 | 决策通过；规则存在不等于真实流量阻断；默认决策列表不代表 CAPI 列表为空 |
| 手动封禁/解封 | 无效 IP、Go duration、当前 SSH IP 及 IPv6 规范化保护、API 失败；额外自封复现 | 仍允许 `127.0.0.1` / `::1`，也未完整保护本机地址 |
| Firewall 修复 `--repair-bouncer` | 凭据鉴权、保留其他 Bouncer、`.local`、重启回滚；官方 `-T` | 配置通过；实际 IPv4/IPv6 与 Docker 转发阻断需 VPS 验证 |
| Console 注册 | 失败不改身份、成功不删除节点流程、官方步骤核对 | 提交请求流程正确；未使用真实账号接受注册，建议注册后增加 status 核验 |
| Telegram 配置/更新/检查/测试/停用 | JSON 模板真实本地接收、幂等与其他通知保留、输入失败、配置回滚、测试失败复现 | 存在有效 profiles 路径与退出码问题；真实 Telegram 收件未体验 |
| 诊断与优化 `--optimize` | 取消、缺 PyYAML、日志补齐、配置校验 | 基础修复可用；“优化”实际是补集合/采集/指标，应明确展示具体变更 |
| SQLite `--enable-wal` | 官方 `db_config.use_wal`、非 SQLite 拒绝、实际引擎配置 | 常规通过；网络盘/备份恢复和空 `.local` 仍需处理 |
| 健康 `--status`、残留 `--check-clean` | 无修改检查、配置/LAPI/Bouncer、残留流程 | 健康返回码可能漏掉已退出的 WebUI；可选组件不应一概判失败 |
| 深度卸载 `--deep-clean` / `--purge` / `--uninstall` | 取消、活动 Web/real-IP 保护、禁止 pkill、自定义防火墙资源检查、已确认清理流程、未知 OS/检查失败 | 常规流程通过，新增异常实验发现检查失败仍继续清理；真实软件包卸载、内核规则释放、生产数据删除未执行 |
| `tools/diagnose-detection.sh` | 静态检查、入口与日志分析审查、所调用引擎解析机制验证 | 仍固定 metrics 6060，NPM 格式识别落后于新诊断工具；没有独立全流程回归证据 |

## 优先修复：已复现的问题

### P1：卸载把防火墙检查失败当成无残留

位置：`install-crowdsec-1panel.sh:990`、`:1267`、`:1288`。读取自定义表名失败被转为空列表；卸载又把 `firewall_status` 的任意非零结果当成可以继续。隔离模拟自定义表仍存在、配置读取失败，脚本未查询该表，返回 0 并删除配置目录。

建议残留检查明确区分“存在 / 不存在 / 无法判断”，检查工具缺失、配置读取失败或权限不足时停止破坏性清理。先完成发行版、包管理器和检查依赖预检，再停止服务。另复现未知 OS 在报错前已停止/禁用服务并移除本工具 WebUI，说明预检顺序也需调整。依据：[官方 Firewall Bouncer](https://docs.crowdsec.net/u/bouncers/firewall/) 的可配置后端与表/链；不能只检查默认名称。

### P1：手动决策缺少本机保护

位置：`install-crowdsec-1panel.sh:1049` 起的封禁分支。只拒绝当前 SSH 管理 IP。隔离菜单输入 `127.0.0.1` 或 `::1`，均调用 `cscli decisions add` 并返回成功。

建议拒绝 loopback、未指定地址、本机接口地址和已确认的出口公网 IP；管理员地址列表应独立管理，不能只依赖当前 SSH 环境变量。出口公网 IP 不能仅靠本机接口推断，NAT 节点需明确记录。提供只读 Self-Report 诊断，列出相关告警/决策，由用户选择删除确有问题的决策。不要自动清空全部告警或关闭 WAF。

官方说明：[Security Engine Self-Report](https://docs.crowdsec.net/u/troubleshooting/issue_se_self_report/)。现有 parser whitelist 不等于 AppSec 旁路或 CAPI 决策保护；如增加中央 AllowList，应说明其**会使该来源跳过 AppSec**，不能自动把全部代理网段加入。

### P1：已有 Web Bouncer 接入可被 `.local` 覆盖

位置：`install-crowdsec-1panel.sh:688`、`:779`。宿主机和已有 Docker 接入只更新主配置。隔离配置中 `.conf.local` 的 `APPSEC_URL` 指向另一引擎，接入返回 0/SUCCESS，主文件已更新，但有效 URL 仍是旧值。首次宿主机安装已有 `.local` 检查，未被所有入口复用。

建议统一读取主文件及 `.local` 的有效值，所有安装、接入、停用、状态入口共用；明确覆盖冲突、重复键、空白格式和恢复规则，并验证生效 URL 与请求指标。依据：[Nginx](https://docs.crowdsec.net/u/bouncers/nginx/)、[OpenResty](https://docs.crowdsec.net/u/bouncers/openresty/) 的 `.local` 优先级。

### P2：验证命令不能判定通过/失败

位置：`install-crowdsec-1panel.sh:829`。复现 HTTP 200、前后 Processed/Blocked 都为 0，返回码仍为 0。`curl` 默认不会把 HTTP 200/404 等当传输失败，HEAD 返回 403 也可能来自其他 WAF。

建议优先给出另一台设备执行的唯一请求标识；自动验证时读取状态码、规则命中及指标增量，短暂轮询，输出“通过 / 失败 / 无法判断”。同一时间其他流量的累计增量只能作为辅助证据，不能证明这一次请求经过 AppSec。依据：[官方 quickstart](https://docs.crowdsec.net/docs/next/appsec/quickstart/nginxopenresty/)。

### P2：Telegram 可修改无效配置，测试失败仍返回 0

位置：`install-crowdsec-1panel.sh:12`、`:1093`、`:1102`。有效 `api.server.profiles_path` 使用自定义文件时，脚本修改默认 profiles 并报成功，实际文件未变。`profiles.yaml.local` 先执行且可 `on_success: break`，也可能使默认路由无效。另复现用户确认测试、插件失败后，setup 最终仍返回 0。

建议解析有效 profiles/notification 路径和匹配顺序；展示通知将覆盖哪些 profiles；测试失败传播非零状态，并明确“配置已加载，投递验证失败”。不能把所有 profiles 无差别增加通知后就认为每种告警都已覆盖。依据：[Profiles](https://docs.crowdsec.net/docs/next/local_api/profiles/intro/)、[配置](https://docs.crowdsec.net/docs/next/configuration/crowdsec_configuration/)、[HTTP 通知插件](https://docs.crowdsec.net/docs/next/local_api/notification_plugins/http/)。

### P2：核心安装与日志修复的有效路径逻辑不一致

位置：`install-crowdsec-1panel.sh:221`、`:237`。有效 `config.yaml.local` 设置自定义 `acquisition_dir` 时，核心安装仍写默认 `acquis.d/web-sites.yaml`，返回成功，活动目录为空。已有 `--repair-logs` 会读取有效路径。

建议核心安装复用日志修复的路径解析与实际挂载发现，并以真实新增日志和 acquisition 指标验收。复用逻辑能减少“安装成功，未读网站日志”。

### P2：空 `.local` 导致配置工具异常

位置：`lib/crowdsec_config.py:328` 及配置合并逻辑。空或仅注释的 `config.yaml.local` 被 YAML 读取为 None，指标配置复现 `AttributeError`；WAL 的有效配置合并同类处理也需覆盖。

建议把空配置规范为 `{}`，对非 mapping 提供清晰错误；主配置和 override 共用校验。不要把合法空覆盖文件当损坏配置删除。

### P2：健康检查漏掉已退出的 WebUI

位置：`install-crowdsec-1panel.sh:1171`。其他检查健康的隔离场景下，Docker 输出 `Exited (1)`，`--status` 仍返回 0。只列表不能影响整体判断。

建议已部署的可选组件核查状态、HTTP readiness 与独立凭据；未安装的可选组件标记“未部署”。WebUI 轮换也应在新凭据和应用就绪后再注销旧 Machine。

## 需要设计完善的运维项

1. **WebUI 默认访问保护。** `lib/crowdsec_config.py:389` 使用 host 网络、latest 镜像，未显式启用认证。上游当前 `auth:auto` 可能保留旧数据库的禁用认证状态；这是条件性风险，未在本轮运行真实镜像复现。建议显式认证、限制公开端口、HTTPS 反代，部署后验证未登录访问；固定版本/摘要，并为自定义端口配置对应 healthcheck。[上游认证说明](https://github.com/TheDuffman85/crowdsec-web-ui#authentication)。
2. **管理员保护模型。** parser whitelist 只保护日志处理链，不能承诺管理员不会被已有 blocklist 或 AppSec 阻断。增加 AllowList 查询/管理与分层说明，迁移必须明确其旁路范围。[官方 AllowLists](https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists/)。
3. **Hub 更新与集合移除的事务。** 手动与 cron 都是在 Hub 内容修改后才执行 `crowdsec -t`。校验失败虽不重载，磁盘内容可能已变。建议 flock 互斥、更新前快照、失败恢复并再次校验、专用结果日志。cron 配置备份不等于 Hub 更新可回滚。
4. **AppSec 正文与故障策略。** 官方默认允许无法读取正文或 AppSec 不可用时按配置透传。官方特别提示 HTTP2/HTTP3 无 Content-Length 的正文可能未被分析。建议显示 `APPSEC_DROP_UNREADABLE_BODY` 与故障策略并让管理员选择；不要无条件改为全部拒绝。补 HTTP2 正文、超时、引擎不可用及正常业务兼容测试。[官方限制说明](https://docs.crowdsec.net/u/bouncers/openresty/)。
5. **统一诊断工具。** `diagnose-detection.sh` 应复用 `crowdsec_realip_diagnose.py` 的 NPM/标准格式、stream 上下文和有限读取逻辑，读取有效 Prometheus 地址；避免新诊断支持 NPM 而旧工具仍把它输出为“首字段不可识别”。指标按时间窗口增量展示，区分预期无关日志与解析失败，不应仅凭 error.log 未解析比例删除采集。
6. **未知上游坚持先取证。** 保留明确 Header + 来源 CIDR；关联外部唯一请求、访客 IP、日志与 Bouncer IP。不能因 Header 名称存在就自动相信，也不应按优先级尝试全部 Header。Cloudflare 网段更新展示差异和来源时间；Tunnel、混合站点与多层代理单独建模。
7. **验收与文档统一。** `docs/verification.md` 保留不同阶段的历史测试数量，应增加清晰“当前基线”与兼容矩阵。健康输出区分：未部署、已配置、组件运行、请求验证通过。Console 注册后展示接受注册与 `cscli console status` 检查步骤。

## 生产补测顺序

1. 在可恢复的 Debian/Ubuntu、RHEL 系测试 VPS 验证安装/升级、非默认配置路径、重启与卸载；保留独立 SSH 会话和管理访问。
2. 验证 Firewall IPv4/IPv6、Docker 转发、CAPI/本地决策拉取及停止后的规则释放；不用服务器自身地址制造封禁。
3. 对真实 1Panel、NPM、宿主机 nginx/OpenResty 分别验证安装、容器重建、原 WAF 共存、撤销与正常访问；包含目标镜像版本、网络模式和挂载证据。
4. 从另一台设备关联正常请求的客户端 IP，再验证 AppSec URI/正文规则、故障策略和停用恢复；避免本机攻击路径反复触发 Self-Report。
5. 使用真实账号补 Telegram 收件、Console 接受/同步、WebUI 未登录保护与轮换，以及 cron 实际成功/失败/回滚。

建议实施顺序：卸载检查边界、本机保护与有效配置统一 → AppSec/通知/健康验收 → WebUI 访问保护 → 更新事务与诊断统一 → 部署矩阵。先修复“操作成功但配置未生效”，再扩展更多自动识别。

## 本轮真实组件复验命令

```bash
python3 -m unittest discover -s tests -q
bash -n install-crowdsec-1panel.sh lib/*.sh tools/*.sh
shellcheck -x install-crowdsec-1panel.sh lib/*.sh tools/*.sh
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1 /path/to/crowdsec-firewall-bouncer-v0.0.36
python3 tests/verify_web.py /path/to/crowdsec-v1.8.1 /path/to/openresty-bouncer.tgz /path/to/lua-resty-http.tgz --metadata /path/to/Packages
python3 tests/verify_real_ip.py --metadata /path/to/Packages
```

需安装 PyYAML；真实组件测试使用临时目录及本机端口，可能下载官方 Hub/包文件。报告中的官方依据在本轮通过 CrowdSec 官方文档仓库重新读取，WebUI 认证依据为其项目上游，不能混为 CrowdSec 官方组件。

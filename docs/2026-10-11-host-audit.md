# 2026-10-11 本机脚本检查与优化

检查对象：`install-crowdsec-1panel.sh` 及其 `lib/` 配置、Web Bouncer 和真实 IP 辅助程序。

## 检查结论

本机核心服务、LAPI、Firewall Bouncer、WebUI 及 AppSec 引擎均可运行。检查发现并修复了重复安装、采集配置、账号清理和回滚方面的问题；不能据此承诺所有功能在所有部署中没有 bug。

本机环境：

- Debian 13.7，x86_64，systemd。
- CrowdSec 1.8.1，Firewall Bouncer 0.0.36，使用 nftables；iptables 命令也使用 nf_tables 后端。
- 1Panel 服务名称为 `1panel-agent.service`。
- OpenResty 镜像 `1panel/openresty:1.31.1.1-2-4-noble`，host 网络，原 1Panel WAF 与本工具 Lua Bouncer 已接入。
- 容器 `/www` 对应 `/opt/1panel/1panel/www`；容器 `/var/log/nginx` 对应 `/opt/1panel/apps/openresty/openresty/log`。
- WebUI 使用 host 网络，3000 端口；Docker Compose、Python 3 / PyYAML 和 cron 可用。
- LAPI、AppSec 和指标分别在 loopback 的 8080、7422、6060 监听。

## 已修复的问题

| 问题 | 修复 |
| --- | --- |
| 核心安装覆盖原有管理员白名单 | 合并 IP/CIDR，保留原表达式、原因及其他字段 |
| 已有 iptables Bouncer 的机器因存在 nft 命令而改装后端 | 从主配置和 `.local` 读取有效 mode，保留已有后端 |
| 安装写固定采集目录并覆盖旧 `web-sites.yaml` | 读取有效 acquisition_dir，按现存日志和 Docker 挂载补齐，不覆盖自定义采集 |
| 旧预设包含大量不存在路径，并与官方 SSH 采集、修复文件重叠 | 仅迁移内容完全匹配原始预设的旧文件；对管理文件去重，备份后校验、重启，失败恢复 |
| YAML 原子替换使既有文件的权限/属组变成 mkstemp 默认值 | 保存原权限、属主和属组；新配置仍采用私有权限 |
| 空或只有注释的 `.local` 导致配置合并/编辑失败 | 将空 YAML 视为空覆盖映射 |
| Firewall Bouncer 新账号在备份/编辑失败时遗留 | 使用退出清理处理失败及中断；回滚成功后清理新增账号，回滚失败保留账号供恢复 |
| WebUI 创建新 Machine 后的 chmod、配置生成、标记写入等失败没有完整回滚 | 在独立子进程中统一退出清理，恢复配置/旧容器并清理新增 Machine |
| 悬空符号链接被误判为不存在，恢复时不能正确还原符号链接 | 备份包含悬空链接，恢复链接时替换目标，检查移除失败 |
| AppSec 菜单宿主机接入绕过 `.local` APPSEC_URL 检查 | 复用宿主机接入预检和回滚逻辑 |
| 健康检查仅查看默认路径的本工具 AppSec 文件 | 从有效配置读取全部 AppSec 数据源，包含自定义目录与外部配置 |
| nft 状态输出大量名单元素并重复输出同一表 | 使用 terse 输出，保留表/链/计数器和规则，跳过已显示的默认表 |
| 回归测试继承当前 SSH 环境，导致白名单测试使用真实 SSH 来源 | 隔离 SSH_CLIENT / SSH_CONNECTION，需要测试 SSH 行为时显式设置 |
| 本机没有 rg，但真实 IP 诊断生成 rg 查找命令 | 检测可用命令，无 rg 时生成 grep 命令 |

## 本机实际变更

执行优化后的 `--repair-logs`，备份路径：

`/var/backups/crowdsec-1key/change.PUD5MA5A`

迁移了未经自定义修改的 `/etc/crowdsec/acquis.d/web-sites.yaml`，补齐全局 HTTP access/error 日志，保留站点日志及软件包提供的系统/SSH 采集。迁移后按实际文件展开检查，13 个文件均只有一个采集入口。CrowdSec 校验通过并重启，Firewall Bouncer、Docker、1Panel agent 和 OpenResty 均保持运行；WebUI 独立凭据可登录 LAPI，容器健康。

重启后已观察到站点新日志全部解析成功，AppSec Processed 随正常业务请求增加。服务重启会重置内存指标；空闲文件没有新行时不一定出现在采集指标表中。

## 验证

1. `python3 -m unittest discover -s tests`：221 项全部通过，无跳过。本机兼容性测试覆盖预设迁移/失败恢复、重复采集、权限、符号链接、账号清理、有效 AppSec 配置读取和诊断命令回退；本轮另增加 29 项维护/请求核验测试，覆盖 Hub 失败回滚及锁、实时数据库排除、快照保留、WebUI 实际 HTTP 健康/摘要/端口归属、重复操作与请求 IP 证明。原生安装测试使用官方固定版本归档并校验 SHA256。
2. 所有 shell 文件通过 `bash -n`。ShellCheck 0.10.0 检查通过；排除 SC2317/SC2329（通过 trap 调用的函数误报）及 SC2119/SC2120（有意使用默认值的可选参数）。检查工具仅下载并解包，没有安装系统软件包。
3. `tests/verify_engine.py`：官方 CrowdSec 1.8.1 的临时配置校验、带特殊字符的真实日志采集、HTTP 通知插件 JSON 渲染、独立 Machine 凭据、临时引擎决策增删，以及 AppSec 正常请求 allow 和 `/.env` ban 全部通过。
4. `tests/verify_web.py`：隔离的官方 OpenResty 1.25.3.2、Lua Bouncer 1.2.3 和 AppSec 实际请求通过。正常请求到达后端，原 WAF 测试路径仍被阻断，`/.env` 被 AppSec 阻断；原 init/access/worker/log 钩子及已有 Lua HTTP 模块保留。
5. `tests/verify_real_ip.py`：隔离 OpenResty 的可信来源、非可信来源、无效/缺失 Header、IPv6、NPM 子级信任和 XFF 代理链测试通过。
6. 优化后在本机执行 `--status`、OpenResty `nginx -t`、WebUI 凭据登录检查和采集文件去重检查。SSH 的 `sshd-session` 离线样本可命中官方 sshd parser 和暴力破解场景；普通登录/退出行未解析不等于 SSH 防护失效。

隔离测试使用临时目录、独立引擎及临时端口，未对本机防火墙添加测试封禁。安装/卸载、失败注入等工作流测试使用模拟命令；没有在生产机重新安装核心或实际卸载现有组件。Telegram 通知仅发送到隔离测试 HTTP 接收器，没有向真实聊天发送消息。

## 六项后续优化及生产验证

| 优化 | 完成结果 |
| --- | --- |
| 真实 IP 关联 | `--verify-real-ip` 将同一标记请求的连接对端、访客 Header、日志首字段和 Lua Bouncer 入参关联；临时钩子在成功/失败/中断时恢复，成功证明保留 24 小时并与配置/钩子哈希绑定 |
| 健康检查 | 输出正常、异常和尚未验证；区分日志读取/解析、AppSec 已处理请求与公网站点阻断，异常退出 1，尚未验证退出 2 |
| Hub 更新 | 全部修改入口共用锁；更新前备份规则、符号链接及规则下载数据，失败恢复并校验/重载，实时 SQLite/WAL 不进入快照；内容不变不重载，保留 14 次成功快照及失败快照 |
| WebUI | Compose 固定官方镜像摘要，自定义端口健康检查匹配；部署需容器健康、HTTP 健康与独立 LAPI 登录同时通过，检查监听 PID 归属并保留原镜像回滚 |
| 新站点日志 | `--check-logs` 只读检查新增、漏采和重复采集，同时从有效 HTTP 日志指令与挂载识别自定义路径，使用现有 `--repair-logs` 修复 |
| 重复安装 | 保留既有核心软件源及版本，仅安装缺失包/集合，保留指标端口并检查占用；相同 YAML 保留原注释/文件，不因 WebUI 配置变化而重启核心 |

关联本机正常公网请求发现：`codeg-x.688600.xyz` 和 `down.688600.xyz` 到源站时 **CF-Connecting-IP 缺失**，但 X-Forwarded-For 为已知出口 `45.82.122.6`；连接对端属于 Cloudflare 官方网段。原先固定读取缺失 Header，导致日志与 Bouncer 使用 Cloudflare 节点 IP。已新增明确选择的 Cloudflare XFF 模式，维持全部官方 IPv4/IPv6 信任范围，使用右向左递归处理；没有信任整个内网或 loopback。修复前备份：`/var/backups/crowdsec-1key/change.e5bjPHv8`。

修复后通过 Cloudflare 正常访问 `codeg-x.688600.xyz`、`bob.898786.xyz`、`down.688600.xyz`、`waf.860525.xyz`，四站访问日志和 Bouncer 入参均为 `45.82.122.6`。证明保存在 `/etc/crowdsec/crowdsec-1key-ip-verifications.json`，全部临时 Lua 已恢复。隔离真实 OpenResty 补充证明：非可信连接伪造 XFF 不会生效，可信链中伪造左端地址不能覆盖最右非可信客户端。

Header 被移除的云端具体原因尚不能从源站确定；Cloudflare 的 Remove visitor IP headers 设置可产生相似表现，但未登录账号检查，因此这只是排查线索。[Cloudflare Managed Transforms](https://developers.cloudflare.com/rules/transform/managed-transforms/reference/)、[Cloudflare HTTP Headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/)。

生产 WebUI 使用已运行版本的同一摘要重新生成健康检查并部署，避免额外跨版本变化。当前固定镜像为 `ghcr.io/theduffman85/crowdsec-web-ui@sha256:5d3ef6c46ce08d8c53cb774f8429103d2571986db93517715cc691756c07ce66`，Docker healthy、`http://127.0.0.1:3000/api/health` 返回 `status=ok`，独立 Machine 登录成功。再执行相同部署后，核心 PID `2554128` 与 WebUI 启动时间均未变化。

已启用服务器时区每天 **03:30** 的 Hub 更新；cron 使用 `/usr/local/lib/crowdsec-1key/current/manager.sh --update-hub`。更新日志和 logrotate 配置已验证。实际执行仓库入口和从 `/`、仅保留 cron PATH 的维护副本入口均成功；Hub 与下载数据未变化时跳过重载。实际互斥并发返回 `75`。成功备份示例：`/var/backups/crowdsec-1key/hub.ugtvHgOp`、`hub.IUcEEAyK`。

最终本机检查：13 个现存采集文件、0 重复、0 待补齐；CrowdSec、Firewall Bouncer、Docker、1Panel agent、OpenResty 与 WebUI 均正常运行，AppSec 处理计数持续增加。健康检查退出 `2`，原因是实际公网攻击路径阻断仍为“尚未验证”，不将正常服务误报为完整防护通过。

生产 AppSec 指标证明正常请求进入引擎；每条公网攻击链路仍需另一台受控设备核验。隔离测试证明官方组件可阻断 `/.env` 并保留原 WAF，但不代表所有生产站点已做攻击验证。生产 Telegram 送达、Console 绑定及破坏性卸载未执行。

依据：[官方 Firewall Bouncer 文档](https://docs.crowdsec.net/docs/bouncers/firewall/)、[官方 sshd parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/sshd-logs.yaml)。运行状态和验证结果来自本机检查与隔离测试日志。

## LDNMP、NPM 与宿主机同步优化

- 宿主机日志发现新增默认 `nginx -T` / `openresty -T` HTTP 日志解析，支持预设目录之外的普通文件；符号链接、变量路径、stream 和未明确加载的 include 保持排除。
- 新增宿主机真实 IP 诊断、修复、撤销与正常请求核验；复用可信代理校验和事务回滚，要求已加载的标准 HTTP conf.d。官方 inline 钩子核验拒绝站点覆盖与 satisfy any，证明同时绑定 Bouncer 配置。
- 宿主机已有接入、Docker 已有接入与真实 IP 修复在配置未变化时跳过重载；宿主机安装/接入增加 INT/TERM 恢复处理，包安装中断后只尝试撤销本次包创建的账号，恢复失败时保留依赖。
- Docker private bridge 接入登记明确的 IPv4 网关端点，匹配实际 NetworkID/IPAM、精确监听和容器连通性；首次接入用新 Bouncer Key 验证 LAPI，已有接入核对 API_URL 并认证。密钥通过标准输入的 curl 配置传递，不进入命令参数。核心 loopback、生产镜像和网络保持原状。
- NPM 继续使用持久化 custom 入口，新增站点配置重建/钩子继承及被站点覆盖时停止的回归；重复安装同时核对有效请求钩子，避免仅凭安装记录报告成功。真实 IP 原子更新保留现有文件所有者。
- 日志 buffer 核验读取 flush，最长支持 115 秒 flush 与 120 秒等待；没有明确 flush 时停止自动核验。已有 Docker Bouncer 的只读挂载、父目录符号链接和生效的 .local 地址/密钥覆盖均受保护。

真实运行时复查：`verify_web.py` 的原 WAF 顺序、AppSec 阻断和依赖隔离通过；`verify_real_ip.py` 的 Cloudflare/XFF/IPv6/缺失 Header/NPM 继承检查通过。新增 `verify_adapters.py` 使用真实 CrowdSec 1.8.1 与隔离解包 OpenResty，NPM 和宿主机 nginx/openresty 两种布局均得到普通请求 200、`/.env` 403、业务后端未收到攻击请求，缓冲日志与 Bouncer IP 均为测试地址 8.8.8.8。NPM 增加生成站点后，持久化 Web 钩子仍被加载。

LDNMP 的 Lua 兼容布局还在临时 Docker bridge 中执行实际请求，使用本机缓存镜像的隔离配置访问私有网关转发，再到隔离的 loopback CrowdSec，普通请求/IP/AppSec 阻断均通过。该测试使用已有 1Panel OpenResty 镜像 ID，未升级或替换生产容器；不等同于重建科技lion PHP/MySQL 栈。宿主机 nginx 布局在具有 Lua 的 OpenResty 上运行，不等同于本机实际安装发行版 Nginx Lua 包。NPM 测试没有启动其数据库或管理界面。

隔离 bridge 首次探测发现本机 1Panel 的 INPUT 后置链默认丢弃非允许 TCP 端口。QA 通过显式参数临时加入一条仅匹配测试 bridge 接口、测试容器 /32 来源、私有网关 /32 目标和三个临时 TCP 端口的放行规则；结束后按完整规则精确删除并比较 INPUT 前后内容，没有改变生产放行范围。容器、网络与转发监听均在 finally 中清理。产品脚本不自动管理该放行，真实 bridge 部署需自行准备私有端点和对应防火墙规则。

复现命令（默认不会拉取 Docker 镜像；临时防火墙规则必须显式启用）：

```bash
python3 tests/verify_adapters.py /path/to/crowdsec-v1.8.1 \
  /path/to/crowdsec-openresty-bouncer-v1.2.3.tgz /path/to/lua-resty-http-v0.17.1.tgz \
  --bridge-image <already-cached-Lua-compatible-image> --allow-test-bridge
```

最终优化边界已落地为 [optimization-boundary.md](optimization-boundary.md)：支持范围按实际能力而非品牌确定，自动修改限于可核对的受管理配置，真实 IP 信任需明确授权与证据，防护验证按实际入口分层完成。后续进入缺陷/兼容维护，不承诺任意环境零 bug，也不扩展为面板或网站架构管理器。

本轮最终完整自动回归 **241 项通过**；Bash 语法、Python 编译、ShellCheck（排除已说明的 trap/可选参数静态误报）与 `git diff --check` 通过。真实原 WAF 集成、real-IP 继承测试和四种适配布局的 HTTP/IP/AppSec 集成均通过。已同步每天 03:30 的稳定维护副本，源码与副本哈希一致。本机复查仍为 13 个采集文件、0 重复、0 待补齐，四站 IP 证明有效，WebUI healthy，核心 PID 2554128 保持不变。健康检查返回 2，仅保留生产公网攻击阻断尚未逐入口验证的事实；QA 标签容器/网络和测试 INPUT 规则无残留。

## Bridge 缺陷修复

后续按用户要求修复 Bridge 诊断：不再对所有非 host 容器统一提示“请配置私有地址”，而是读取对应容器登记并重新核对真实 NetworkID/IPAM 和两个私有端点的精确监听。未登记时提示准备端点并使用登记入口；登记损坏、网络漂移或监听缺失时报告失败并让 AppSec 状态检查返回 1，同时继续检查网站钩子。有效登记只报告网络/监听匹配，不宣称连通性、认证或实际防护通过。

真实测试另外发现 internal bridge 的容器检查结果 `Gateway` 为空。原判定误拒绝这种网络，现仅在实际 internal bridge、NetworkID 一致、端点等于 IPAM 网关且容器 IP 属于同一 IPAM 子网时接受空默认网关；普通 bridge、错误网关、非 bridge 或网络 ID 不符仍停止接入。测试不再用人工构造的非空 Gateway 掩盖实际 Docker 元数据。

新增 10 项回归，完整 **251 项通过**；Bash 语法、Python 编译、ShellCheck 和 `git diff --check` 通过。`verify_adapters.py --bridge-only --allow-test-bridge` 实际核验已登记/未登记、失效网络记录和停止监听的诊断结果及只读性；普通请求 200、AppSec 攻击请求 403、后端未收到攻击请求及 Bouncer IP 关联均通过。QA 容器、网络和临时 INPUT 规则已清理，INPUT 保留原有三条 1Panel 跳转。

本机仓库与稳定维护副本的 `--appsec-status` 均返回 0，生产仍使用 host 网络，核心 PID 2554128 保持不变。维护副本已原子切换至修复版本，14 个脚本/模块与源码 SHA256 一致；没有触发 Hub 更新或重载生产服务。此次隔离测试不补齐生产公网攻击阻断证据。

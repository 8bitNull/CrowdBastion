# 使用流程与官方配置验证记录

验证日期：2026-10-10。依据用户指定的 CrowdSec Next AppSec 文档，使用官方稳定发布 CrowdSec **1.8.1** 和 Firewall Bouncer **0.0.36** 进行核查。

## 已发现并处理的问题

| 原行为 | 当前行为 |
| --- | --- |
| 软件包、配置、封禁或注册失败后仍显示成功 | 关键操作保留错误输出并返回非零状态；仅成功后给出对应提示 |
| 主菜单/Telegram 菜单遇到 EOF 反复循环，其他子菜单每次回到主菜单 | 菜单操作后保留，0 返回，EOF 退出；删除类操作默认取消 |
| `--help` 不支持，命令行函数失败被末尾 `exit 0` 掩盖 | 提供完整帮助，每次只接受一个操作，传播操作状态 |
| 无效 IP、时分和时长直接交给后续命令；IPv6 不同写法绕过防自封 | 验证输入，规范化 IP，拒绝当前 SSH IP，使用 Go duration |
| 通配符和具体 access/error 路径同时采集 | 去除被通配符覆盖的重复条目，保留用户其他采集文件 |
| 日志集合被描述为已部署完整 WAF | 区分日志检测、Firewall Bouncer 和 AppSec；补全官方数据源及 Web Bouncer 接入流程 |
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

`tests/test_workflows.py` 共 **58 项**测试全部通过，覆盖主菜单和全部子菜单的流程，以及关键正常、失败、取消、重复操作：

- 核心安装成功/软件包失败、管理员白名单、配置验证失败恢复。
- WebUI 首次部署、凭据复用、独立登录检查、轮换、拉取失败、运行失败恢复、原镜像固定与定向卸载。
- 日志规则安装失败、基础集合补齐、自定义规则保留、指定卸载取消。
- 官方 AppSec YAML、外部监听保留、Web Bouncer 缺失、接入前 URL 恢复、停用失败时恢复运行配置。
- 默认/自定义 cron、无效时分、十进制前导零、服务前提。
- 封禁成功/失败、非法地址、IPv4/IPv6 SSH 自封保护。
- Console 注册成功/失败与身份保留。
- Telegram 输入验证、Profiles 顶层配置、重复配置、停用、官方插件错误传播。
- 核心诊断只读、取消优化、官方 SQLite WAL 配置。
- 注销节点的宿主机保护、残留检查只读、卸载取消、确认删除范围、Web Bouncer 保护和自定义防火墙资源保护。

测试使用临时目录和模拟的系统命令。它验证脚本的流程与配置产物，不等同于安装真实系统软件包或运行真实 Docker 容器。

验证命令：

```bash
bash -n install-crowdsec-1panel.sh
shellcheck install-crowdsec-1panel.sh
python3 -m unittest discover -s tests -v
```

## 官方程序验证

`tests/verify_engine.py` 在临时目录运行官方 CrowdSec 1.8.1，使用隔离的 loopback 端口及本地 HTTP 测试接收端，完成以下检查：

- 官方 Hub 接受全部 11 个使用到的集合：Linux、SSH、Nginx、NPM、HTTP-CVE、基础 HTTP、良性行为白名单、WordPress、iptables、AppSec 虚拟补丁与通用规则。
- 官方 HTTP 通知插件真实渲染本工具模板并向本地接收端发送有效 JSON；特殊引号、换行、空 Source 和空 Decisions 的告警检查通过。字段先以 toJson/fromJson 转为实际值，避免输出 Go 指针信息。
- `crowdsec -t` 接受 AppSec 数据源、Profiles、通知、管理员白名单及 `db_config.use_wal`。
- 引擎实际启动后，按官方 AppSec 协议发送 `/.env` 请求，得到 **HTTP 403 / action=ban**；普通 `/` 请求得到 **HTTP 200 / action=allow**。
- AppSec 指标包含 `crowdsecurity/vpatch-env-access` 规则命中。
- LAPI 登录、手动添加及删除封禁决策成功。
- 独立 WebUI 凭据可以登录，注销该 Machine 后同一凭据登录失败，宿主机仍可登录。

官方 Firewall Bouncer 0.0.36 使用 `-T` 成功读取软件包原始 YAML 和本工具生成的 `.yaml.local` 合并结果，保留 IPv6 默认表 `crowdsec6`。其 `-t` 还会初始化防火墙后端，在当前环境因缺少 netlink 权限失败；因此不将该项列为实际阻断通过。

同时核验两种官方程序：

```bash
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1 /path/to/crowdsec-firewall-bouncer-v0.0.36
```

## 真实部署验证边界

当前环境没有可用于部署测试的 Docker/systemd 服务，也缺少 netlink 管理权限和真实 Telegram/Console 凭据。以下需要在目标服务器上核验：

1. 各发行版软件源、安装/升级、服务启动及 cron 实际执行。
2. Docker 镜像运行、反向代理认证、1Panel/NPM 容器网络与真实访问日志路径。
3. Firewall Bouncer 的 IPv4/IPv6、Docker 转发流量阻断与卸载后规则释放。
4. 已安装 Web Bouncer 对实际网站请求的转发、阻断页面和指标增长。
5. Telegram 实际机器人接收与官方 Console 接受注册后的同步。

这些项目保留了诊断及验证入口，不声称已在当前环境完成全部生产端到端验证。

# 2026-10-19 真实 VPS 只读验收

已通过专用 SSH 公钥连接用户授权的 VPS。现有部署的运行检查通过；完整生产验收尚不能放行：运行中的交互机器人缺少当前工作区已有的地址保护，受控流量拦截与恢复也尚未验证。

检查时间为 2026-10-19 09:36–09:41 UTC。脱敏后的命令、状态、源码指纹及边界见 [JSON 证据](2026-10-19-vps-readonly-evidence.json)。报告省略目标公网地址、业务域名、管理员地址和凭据。

## 环境与版本

- Debian GNU/Linux 13.7，amd64；956 MiB 内存，约 1 GiB Swap，根分区使用率 34%。
- 已部署本地 CrowdSec、nftables Firewall Bouncer、Nginx Proxy Manager、OpenResty Web Bouncer、交互机器人和 realm 中转；节点用途偏好为本地中转。
- CrowdSec `v1.8.1`，Firewall Bouncer `v0.0.36`，OpenResty Bouncer `v1.2.3`，均按实际运行信息记录。
- 服务器 `/root/crowdsec-1key` 仓库 HEAD 为 `c70c1672a6ab4fc26762c9d59f3a0b363f8a93e5`（2026-10-11）。运行文件独立核查，不能用仓库 HEAD 代替其版本。
- 当前工作区包含未提交修改。本轮将主入口和 `lib/` 的 41 个源码文件复制到 root 私有临时目录，仅运行只读诊断；文件 SHA256 与工作区一致，结束后已删除临时目录。未将当前工作区安装为生产版本。

## 已取得的证据

| 项目 | 结果与范围 |
| --- | --- |
| 核心、防火墙 Bouncer、机器人服务 | 均为 `active/running`、`Result=success`、`NRestarts=0`；结束时主 PID 与检查快照一致。该计数不代表全部历史启动记录。 |
| LAPI 与 Bouncer | LAPI 认证成功；防火墙和网站 Bouncer 均有效，有近期 API 拉取记录。LAPI 和 Prometheus 配置绑定环回地址。 |
| 日志采集 | 当前诊断发现 63 个现存文件，重复 0 个，待补齐采集 0 项；SSH journal 与网站日志均有解析记录。范围限本次发现的日志。 |
| 防火墙规则 | IPv4、IPv6 均存在 INPUT/FORWARD 基础链、来源地址集合和 DROP 引用，hook 优先级为 `-10`。 |
| 已有决策同步 | 查询返回 9 个本地 IPv4 封禁地址，逐个使用 `nft get element` 核查，9/9 已在本地决策集合中。未创建测试决策；无当前 IPv6 本地决策样本。 |
| 网站与 AppSec | NPM 容器运行；当前工具识别到 Web Bouncer 调用和 AppSec 环回监听。两个自然流量快照中 AppSec Processed 从 127528 增至 127544，Blocked 为 1237。累计计数不能替代指定站点的受控请求关联。 |
| 当前工作区诊断 | `--status-details`、`--relay-status-details` 均返回 `2`，含义为运行检查通过、实际拦截待验证；`--check-logs` 返回 `0`。未把 `2` 计为完整业务通过。 |

## 需要处理：运行中的机器人缺少地址保护

安装位置：`/usr/local/lib/crowdsec-1key-bot/crowdsec_bot.py`。

实际文件中 `validated_ip()` 仅调用 `ipaddress.ip_address(value.strip())`。第 678 行的 `action_ban()` 校验 IP 和时长后直接调用 `cscli decisions add`，未调用当前工作区的保护检查；相邻的 `crowdsec_safety.py` 也不存在。

为避免真实封禁，将该文件的 `validated_ip()`、`esc()` 和 `action_ban()` 用 AST 提取到本地，并用内存记录器替换 `run_cmd`。输入目标 VPS 自身公网 IPv4 后，记录器收到一次添加决策调用，函数返回成功。此复现没有执行真实 `cscli` 或发送 Telegram 消息。

这证明实际安装版本没有当前新增的本机／管理员地址防误封检查，不能据此认为聊天机器人已具备该保护。当前工作区 `lib/crowdsec_bot.py` 第 686 行已引入 `crowdsec_safety.guard`，安装流程也包含该模块；部署和实际运行验收仍未完成。应先按已有升级、备份与回滚流程部署该修复，再进行真实手动封禁验收。

## 资源与记录限制

一次快照中内存可用约 323 MiB，Swap 已用 681 MiB；随后两次一秒间隔的 `vmstat` 采样未见换入／换出。资源存在余量限制，这些短时数据不能证明容量充足、没有泄漏或长期稳定。

三个相关 unit 的最近 24 小时、最多 1000 条 warning 及更高优先级 journal 查询未返回条目；最近 7 天、最多 3000 条内核 journal 查询未匹配 OOM。应用写入独立日志文件的记录不包含在这一结论内。当前内核不提供 `/proc/pressure/`，未取得 PSI 指标。

## 尚未完成的验收

- 独立测试来源与正常对照来源的封禁前可达、封禁中新连接阻断、正常来源不受影响及撤销／到期恢复。
- realm 实际入口的 TCP、UDP、IPv4、IPv6 分项流量和真实来源对照；静态规则及既有封禁同步不能替代这些结果。
- 指定网站真实 IP、Web Bouncer 和 AppSec 处理计数的受控请求关联。
- 当前工作区的升级、安装／卸载、服务重启、系统重启、故障恢复及持续稳定性验证。
- Telegram 消息交互与真实封禁行为。当前运行问题通过源码核查和本地替代命令复现，不构成修复已部署的证据。

## 操作与结束核查

本轮读取生产状态，在私有临时目录运行当前诊断源码；没有请求修改生产配置、重启服务、增删决策、修改防火墙或发送 Telegram 消息。

结束时核对 41 个临时源码文件与初始清单一致。诊断之后建立的快照中，8 个配置／运行文件的哈希在结束时一致；三个服务保持运行且 PID 一致。该哈希比较的起点是诊断后的快照，不冒充诊断前后全量文件一致性检查。远程临时源码目录已删除，专用 SSH 授权仍保留，供后续用户授权的检查使用。

# CrowdSec 防护管理中心

面向 1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）、宿主机 Nginx/OpenResty 和纯中转节点的 Linux 管理工具。提供 CrowdSec 安装、日志检测、IP 封禁、AppSec 接入，以及 WebUI、Telegram 和日常维护菜单。

**首次使用请看[使用说明](docs/usage-guide.md)，按节点职责选择部署方式。**

## 选择部署方式

| 场景 | 安装入口 | 节点职责 |
| --- | --- | --- |
| 网站服务器 | 菜单 `1 → 1` / `--install-core` | 本地日志检测与 IP 阻断；在线请求检查另从 `1 → 2` 接入 AppSec 和 Web Bouncer |
| 需要本地 SSH 检测的中转 VPS | 菜单 `1 → 5` / `--install-relay` | 本地 CrowdSec + Firewall Bouncer，补齐系统/SSH 规则与采集 |
| 已有独立 CrowdSec 中心的中转 VPS | 菜单 `1 → 6 → 1` / `--install-relay-bouncer` | 只同步中心决策并执行 IP 阻断；SSH 日志集中采集另行配置 |

中转模式适用于 gost、realm、socat、Nginx Stream 或 NAT 节点。精简入口保留已有 Web/AppSec 组件；远端模式需要中心 LAPI、独立 Bouncer 账号和可信通信路径。详见[中转模式](docs/relay-mode.md)与[中心运维](docs/remote-bouncer-operations.md)。

## 环境要求

- root 权限、Bash、由 systemd 管理的 Linux 宿主机。
- 核心安装包含 Debian/Ubuntu 和 CentOS/RHEL/AlmaLinux/Rocky/Fedora 分支；具体系统、架构及验证范围见[VPS 兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md)。
- 配置编辑需要 Python 3 与 PyYAML，核心安装会准备对应系统软件包。
- WebUI 另需 Docker/Compose；定时更新另需运行中的 cron/crond。
- 可访问 CrowdSec 软件源和 Hub；WebUI 还需访问 `ghcr.io`，Telegram 需访问所配置的 HTTPS 端点。

安装前保存现有 CrowdSec/防火墙配置，确认管理员公网来源 IP，并准备可用的 VPS 控制台或恢复入口。依赖安装与排查见[准备环境](docs/usage-guide.md#准备环境与下载)。

## 下载与启动

使用 `main` 分支。下载完整仓库后运行：

```bash
git clone --branch main https://github.com/8bitNull/crowdsec-1key.git
cd crowdsec-1key
bash install-crowdsec-1panel.sh --help
sudo bash install-crowdsec-1panel.sh
```

**脚本必须与完整 `lib/` 目录一起保留。** 也可下载同一分支的源码压缩包，解压到独立工作目录；若发布包提供校验文件，先执行对应的 `sha256sum -c`。软件包、规则和镜像仍需按环境准备或下载。

菜单输入 `0` 返回，`Ctrl+D` 或输入结束退出；删除、注销、停用和卸载默认取消，需要明确输入 `y`。命令行每次只指定一个操作，安装与配置入口仍保留交互输入。

## 首次安装与检查

网站服务器建议依次完成：

1. 菜单 `1 → 1` 安装核心与 Firewall Bouncer，核对管理员 IP。
2. 菜单 `4 → 1` 检查服务、LAPI、日志指标与防火墙资源。
3. 菜单 `2` 按网站类型安装日志规则，核对实际日志和客户端 IP；需要在线请求检查时进入 `1 → 2` 接入 AppSec 与 Web Bouncer，并逐网站验证。
4. 按需配置 `2 → 9` 的定时规则更新、`5 → 1` 的 WebUI 和 `5 → 3` 的 Telegram。

中转节点按上表安装，再使用对应状态入口：

```bash
# 本地系统/SSH 检测节点
sudo bash install-crowdsec-1panel.sh --relay-status

# 只执行中心决策的远端节点
sudo bash install-crowdsec-1panel.sh --relay-bouncer-status
```

服务状态、日志解析、决策同步和实际业务阻断分别核验。状态输出包含“异常”和“尚未验证”时，请按[安装后的验证](docs/usage-guide.md#安装后的验证)继续检查。

## 主菜单

| 选项 | 功能 |
| --- | --- |
| 1 | 安装与接入：核心、网站防护、真实 IP、Docker 私有端点、中转模式 |
| 2 | 规则与更新：集合安装/移除、基础规则补齐、手动与定时 Hub 更新 |
| 3 | 封禁与访问保护：警报/决策、封禁/解封、防火墙、管理员 AllowList、Self-Report |
| 4 | 诊断与修复：健康、日志、AppSec、真实 IP、中转路径、基础修复与 WAL |
| 5 | 管理与通知：WebUI、Console、Telegram |
| 6 | 卸载与恢复：卸载/清理、只读残留检查；[备份恢复步骤](docs/usage-guide.md#备份与失败恢复) |

完整参数与退出码见[命令行参考](docs/cli-reference.md)，日常操作见[使用说明](docs/usage-guide.md)。

## 防护边界

- **Firewall Bouncer 执行 IP 阻断；AppSec 在线请求检查需要兼容的 Web Bouncer。** 安装日志规则或 AppSec 集合不会自动完成网站接入。
- **服务 active、监听存在或累计计数增长，不能代替实际业务阻断验证。** 网站、IPv4/IPv6、INPUT/FORWARD 与 Docker 路径需按实际部署分别核验。
- CDN/反向代理需明确可信来源并核对真实客户端 IP；管理员中央 AllowList 会让该来源跳过 AppSec。
- Docker bridge 接入需要先准备私有 LAPI/AppSec 端点，再登记；脚本不会自动更改网络、发布端口或安装转发器。远端 Bouncer 仅接受可信私网 HTTP 或证书有效的 HTTPS。
- 中转模式提供系统/SSH 检测或中心决策阻断，不管理转发器、NAT 或带宽清洗；上游带宽耗尽需要上游防护。
- 配置修改有备份与失败恢复，但文件事务不包含系统软件包及实时数据库。卸载会删除 CrowdSec 数据，先撤销网站接入并核对[卸载步骤](docs/usage-guide.md#移除与卸载)。

支持条件、配置所有权及验收标准见[维护边界](docs/optimization-boundary.md)。

## 当前验证状态

截至 **2026-10-13**，已有记录的最近源码回归为 **581 项通过、无跳过**；Debian 12 / 512 MiB 独立客机完成安装、三次重启与 120 秒四路径负载短测，未观察到 OOM。CentOS 本地核心和 Debian 已有核心集成的对应范围也有通过记录。

**独立 1 小时轮次缺少最终报告与退出证据，24 小时轮次尚无执行证据；断线恢复、其他资源组合和原生 ARM64 默认启动仍未关闭，尚无本轮新增试用放行组合。** 短测与 TCG 仿真不代表真实 VPS 吞吐或线路可用性。

上述为历史验证摘要；最新验收状态以[修复进度](docs/audit/2026-10-12-vps-repair-progress.md)和[VPS 兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md)为准，测试明细见[验证记录](docs/verification.md)。

## 文档导航

| 文档 | 内容 |
| --- | --- |
| [使用说明](docs/usage-guide.md) | 场景选择、安装、验证、更新、备份恢复、卸载与常见问题 |
| [命令行参考](docs/cli-reference.md) | 完整参数、菜单交互、并发与退出码 |
| [AppSec 接入参考](docs/appsec-guide.md) | 环境适配、Web Bouncer、Docker 网络、网站验证与故障策略 |
| [日志与真实 IP 排查](docs/detection-guide.md) | 日志路径、低解析率、防火墙、CDN/代理、AllowList 与 Self-Report |
| [管理与维护参考](docs/management-guide.md) | WebUI、Telegram、Hub 更新、WAL 与失败恢复范围 |
| [自定义 TG 机器人](docs/2026-10-13-custom-telegram-bot.md) | 可选九宫格/按钮接入、路径与 UA 修复、服务迁移和回滚；官方通道负责自动告警 |
| [中转模式](docs/relay-mode.md) / [中心运维](docs/remote-bouncer-operations.md) | 本地精简、远端 Bouncer、流量路径与迁移边界 |
| [性能测量](docs/relay-benchmark.md) | 目标节点的测量方法与数据解释 |
| [验证记录](docs/verification.md) / [兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md) | 测试方法、历史证据、实际覆盖范围与未完成项目 |

# CrowdSec 防护管理中心

面向网站服务器、中转 VPS 和 V2bX 落地节点的 Linux 管理工具。提供 CrowdSec 安装、日志检测、IP 阻断、AppSec 接入，以及 WebUI、Telegram 和日常维护菜单。

适用于 1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）及宿主机 Nginx/OpenResty。首次使用请看 [使用说明](docs/usage-guide.md)，按节点职责选择入口。

## 选择部署方式

| 场景 | 入口 | 职责 |
| --- | --- | --- |
| 网站服务器 | `1 → 1` / `--install-core` | 本地日志检测与 IP 阻断；AppSec 在线检查另从 `1 → 2` 接入 |
| 需要本地 SSH 检测的中转 VPS | `1 → 5` / `--install-relay` | 本地 CrowdSec + Firewall Bouncer，补齐系统／SSH 采集 |
| 已有独立 CrowdSec 中心的中转 VPS | `1 → 6 → 1` / `--install-relay-bouncer` | 同步中心决策并执行 IP 阻断 |
| V2bX 三内核落地，直连／中转并存 | `4 → 12` / `--diagnose-v2bx` | 核查配置、日志与来源路径，业务检测保持仅观察 |

中转模式适用于 gost、realm、socat、Nginx Stream 或 NAT 节点。部署条件见 [中转模式](docs/relay-mode.md)和 [中心运维](docs/remote-bouncer-operations.md)。

## 下载与启动

需要 root、Bash、systemd，以及 Python 3／PyYAML。支持分支和实际验收范围见 [VPS 兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md)；WebUI 另需 Docker/Compose，定时更新另需 cron/crond。软件源、Hub 和所需镜像须可访问。

```bash
git clone --branch main https://github.com/8bitNull/crowdsec-1key.git
cd crowdsec-1key
bash install-crowdsec-1panel.sh --help
sudo bash install-crowdsec-1panel.sh
```

**主脚本必须与完整 `lib/` 目录一起保留。** 所需入口以实际版本的 `--help` 为准；环境准备及源码包使用见 [下载说明](docs/usage-guide.md#准备环境与下载)。

安装前保存 CrowdSec／防火墙配置，核对管理员来源 IP，并准备 VPS 控制台或恢复入口。菜单 `0` 返回，`Ctrl+D` 退出；删除、停用和卸载需明确确认。

## 常用入口

网站首次安装后，使用 `4 → 1` 核查服务、LAPI 和日志，再从菜单 `2` 选择日志规则；需要 AppSec 时完成 Web Bouncer 接入和逐站验证。详细步骤见 [安装后的验证](docs/usage-guide.md#安装后的验证)。

| 命令行参数 | 用途 |
| --- | --- |
| `--status` | 核心健康检查 |
| `--relay-status` | 本地中转检测节点状态 |
| `--relay-bouncer-status` | 远端决策执行节点状态 |
| `--diagnose-v2bx` | 三内核配置、日志与混合入口只读诊断 |
| `--v2bx-log-check` | 日志样本分类、固定字段投影及声明的中转来源排除 |
| `--v2bx-observe` | 保存观察事件与恢复游标，导出一次性快照 |

运行方式为 `sudo bash install-crowdsec-1panel.sh 参数`。完整菜单、参数及退出码见 [命令行参考](docs/cli-reference.md)。V2bX 输入配置、采样容量与轮转风险见 [V2bX 指南](docs/v2bx-guide.md)。

## 防护边界与当前状态

- Firewall Bouncer 执行 IP 阻断；AppSec 在线请求检查需要兼容的 Web Bouncer。安装规则不等于完成网站接入。
- 服务 active 或规则存在不能代替业务验证。真实 IP、IPv4/IPv6、INPUT/FORWARD 和 Docker 路径按实际部署核验。
- 共享中转 peer 不能代替用户 IP 作为业务封禁对象；连接限速和带宽清洗不属于当前中转管理功能，链路耗尽需要上游防护。
- 配置修改提供备份与恢复；系统软件包、实时数据库和网站数据不属于完整事务备份。卸载前先核对 [恢复与卸载流程](docs/usage-guide.md#备份与失败恢复)。

V2bX 的 xray、sing、hysteria2 已有基础协议、双账号混合入口、IPv4/IPv6 和 TCP/UDP 应用载荷的隔离证据。QUIC 认证事件依赖 [固定版本实验补丁](experimental/README.md)，官方未打补丁包不能沿用该覆盖；Shadowsocks 和 xray Trojan 仍有专用检测缺口。新增 `4 → 14` / `--install-v2bx-observer` 可安装独立文件日志的常驻仅观察服务；不自动接入业务规则、告警、封禁或限速。

真实 VPS 的仅观察试点仍待 [部署验收](docs/v2bx-deployment-acceptance.md)。系统长测、恢复及部分架构／资源组合尚未关闭；源码回归和 QEMU 结果不代表公网吞吐或生产放行。具体测试数量、配置对照与失败记录见 [验证记录](docs/verification.md)、[验收索引](docs/audit/README.md)和 [修复进度](docs/audit/2026-10-12-vps-repair-progress.md)。

## 文档导航

| 文档 | 内容 |
| --- | --- |
| [文档索引](docs/README.md) | 完整导航、仓库结构、历史与计划 |
| [使用说明](docs/usage-guide.md) / [命令行参考](docs/cli-reference.md) | 安装、菜单、参数、备份与卸载 |
| [AppSec 指南](docs/appsec-guide.md) / [日志与真实 IP](docs/detection-guide.md) | 网站接入、来源信任与检测排查 |
| [管理与维护](docs/management-guide.md) | WebUI、Telegram、Hub 更新与恢复 |
| [中转模式](docs/relay-mode.md) / [中心运维](docs/remote-bouncer-operations.md) | 本地检测与远端执行的职责和迁移 |
| [V2bX 指南](docs/v2bx-guide.md) / [部署验收](docs/v2bx-deployment-acceptance.md) | 三内核日志观察、混合入口与生产试点 |
| [实验补丁](experimental/README.md) / [规则样板](rules/v2bx/README.md) | 固定版本源码实验与未安装的仅观察规则 |
| [验证记录](docs/verification.md) / [兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md) | 历史结果、实际覆盖范围与未完成项目 |

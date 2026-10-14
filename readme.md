<div align="center">
<pre>   ______                        ______             __  _&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;
  / ____/________ _      _______/ __  /____ ______/ /_(_)___  ____&#32;
 / /   / ___/ __ \ | /| / / __  / __  / __ `/ ___/ __/ / __ \/ __ \
/ /___/ /  / /_/ / |/ |/ / /_/ / /_/ / /_/ (__  ) /_/ / /_/ / / / /
\____/_/   \____/|__/|__/\__,_/_____/\__,_/____/\__/_/\____/_/ /_/&#32;</pre>
</div>

<p align="center">
  <strong>基于 CrowdSec 的服务器防护与运维管理工具</strong><br />
  网站 · 中转 VPS · V2bX 落地节点
</p>

<p align="center">
  <a href="docs/audit/2026-10-12-vps-compatibility.md"><img src="https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&amp;logoColor=black" alt="Platform: Linux" /></a>
  <a href="docs/cli-reference.md"><img src="https://img.shields.io/badge/shell-Bash-4EAA25?logo=gnubash&amp;logoColor=white" alt="Shell: Bash" /></a>
  <a href="docs/usage-guide.md#准备环境与下载"><img src="https://img.shields.io/badge/Python-3-3776AB?logo=python&amp;logoColor=white" alt="Python: 3" /></a>
  <a href="https://www.crowdsec.net/"><img src="https://img.shields.io/badge/powered_by-CrowdSec-6E43E7" alt="Powered by CrowdSec" /></a>
  <a href="https://github.com/8bitNull/CrowdBastion/stargazers"><img src="https://img.shields.io/github/stars/8bitNull/CrowdBastion?style=flat" alt="GitHub Stars" /></a>
  <a href="https://github.com/8bitNull/CrowdBastion/commits/main/"><img src="https://img.shields.io/github/last-commit/8bitNull/CrowdBastion/main" alt="Last Commit" /></a>
</p>

<p align="center">
  <a href="#功能概览">功能概览</a> ·
  <a href="#选择部署方式">选择部署</a> ·
  <a href="#下载与启动">快速开始</a> ·
  <a href="docs/usage-guide.md">使用指南</a> ·
  <a href="#文档导航">全部文档</a>
</p>

CrowdBastion 将 CrowdSec 安装、日志检测、IP 阻断、AppSec 接入和日常维护汇集到一个交互菜单。适用于 **1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）及宿主机 Nginx/OpenResty**，也提供中转与 V2bX 落地节点的专用入口。

## 功能概览

| 方向 | 提供的能力 | 使用指南 |
| --- | --- | --- |
| **Web · 网站防护** | 日志检测、IP 阻断、AppSec 与 Web Bouncer 接入、真实 IP 排查 | [网站接入](docs/appsec-guide.md) |
| **Relay · 中转防护** | 本地系统／SSH 检测，或通过远端 Bouncer 执行中心决策 | [中转部署](docs/relay-mode.md) |
| **Node · 落地观察** | V2bX 三内核配置诊断、日志核查、持久观察与仅观察告警 | [V2bX 指南](docs/v2bx-guide.md) |
| **Operations · 日常运维** | 健康检查、规则更新、备份恢复、WebUI 与 Telegram 接入 | [管理维护](docs/management-guide.md) |

## 选择部署方式

| 场景 | 入口 | 职责 |
| --- | --- | --- |
| 网站服务器 | `1 → 1` / `--install-core` | 本地日志检测与 IP 阻断；AppSec 在线检查另从 `1 → 2` 接入 |
| 需要本地 SSH 检测的中转 VPS | `1 → 5` / `--install-relay` | 本地 CrowdSec + Firewall Bouncer，补齐系统／SSH 采集 |
| 已有独立 CrowdSec 中心的中转 VPS | `1 → 6 → 1` / `--install-relay-bouncer` | 同步中心决策并执行 IP 阻断 |
| V2bX 三内核落地，直连／中转并存 | `4 → 4 → 1` / `--diagnose-v2bx` | 核查配置、日志与来源路径，业务检测保持仅观察 |

中转模式适用于 gost、realm、socat、Nginx Stream 或 NAT 节点。部署条件见 [中转模式](docs/relay-mode.md)和 [中心运维](docs/remote-bouncer-operations.md)。

## 下载与启动

**运行环境：** systemd Linux、root 权限、Bash、Python 3／PyYAML。软件源、CrowdSec Hub 和所需镜像须可访问；WebUI 另需 Docker/Compose，定时更新另需 cron/crond。

```bash
git clone --branch main https://github.com/8bitNull/CrowdBastion.git
cd CrowdBastion
bash crowdbastion.sh --help
sudo bash crowdbastion.sh
```

> **完整下载：** 主脚本必须与完整 `lib/` 目录一起保留。环境准备、依赖安装及源码包使用见 [下载说明](docs/usage-guide.md#准备环境与下载)；实际支持范围见 [VPS 兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md)。

安装前保存 CrowdSec／防火墙配置，核对管理员来源 IP，并准备 VPS 控制台或恢复入口。菜单 `0` 返回，`Ctrl+D` 退出；删除、停用和卸载需明确确认。

### 首次使用

1. **选择用途** — 首次终端启动显示用途引导：网站、本地中转、远端执行、V2bX 落地。可以组合，例如输入 `2 4` 选择本地中转＋落地；选择只保存偏好。以后从主菜单 `7` 调整。
2. **按用途检查** — 主菜单 `8`（或 `4 → 1`）检查相关组件并给出下一步入口。纯中转检查系统／SSH 指标，远端执行无需本地 CrowdSec，落地可独立诊断 V2bX；先看简短结论，再选择推荐操作或查看详情。
3. **验证业务** — 规则存在仍不代表实际阻断通过。按真实来源和转发路径核验；需要 AppSec 时完成 Web Bouncer 接入与逐站验证。详见 [安装后的验证](docs/usage-guide.md#安装后的验证)。

用途偏好保存于 `/var/lib/crowdbastion/node-roles.json`，不保存密钥；远端执行不能与网站／本地中转同选，可与落地组合。`--status` 按保存用途只读检查，不弹出引导或下一步选择；尚未选择用途时沿用原网站检查。

检查默认先告诉你是否需要处理。例如中转节点的服务、日志和规则都通过时：

```text
检查结论：运行检查通过，实际拦截待验证
已确认：本地检测服务运行、防火墙防护服务运行、日志读取与解析正常、已发现来源 IP 封禁规则。
待确认：外部连接是否确实被拦截。
本次未发现需要修复的问题。
```

发现故障时显示原因、影响和一个推荐操作；缺少配置与无法读取状态会分别说明。菜单提供“查看检查详情”，命令行使用 `--status-details`；未安装的可选 AppSec／WebUI 不占据总结。服务和规则通过仍需一次实际流量验证。

<details>
<summary><strong>已有安装：更名与升级说明</strong></summary>

项目原名 `crowdsec-1key`。旧入口 `install-crowdsec-1panel.sh` 保留为指向 `crowdbastion.sh` 的兼容链接；已有安装的服务名、配置、备份和规则标识继续沿用。已有检出的更新方式和升级步骤见 [更名与升级](docs/project-rename.md)。

</details>

## 常用入口

<details>
<summary><strong>展开命令行速查</strong></summary>

网站首次安装后，使用 `4 → 1` 核查服务、LAPI 和日志，再从菜单 `2` 选择日志规则；需要 AppSec 时完成 Web Bouncer 接入和逐站验证。详细步骤见 [安装后的验证](docs/usage-guide.md#安装后的验证)。

| 命令行参数 | 用途 |
| --- | --- |
| `--status` / `--status-details` | 按用途显示简短结论 / 完整检查详情 |
| `--relay-status` / `--relay-status-details` | 中转防火墙简短结论 / 详情 |
| `--relay-bouncer-status` | 远端决策执行节点状态 |
| `--diagnose-v2bx` / `--diagnose-v2bx-details` | 三内核配置、日志与混合入口只读诊断 |
| `--v2bx-log-check` | 日志样本分类、固定字段投影及声明的中转来源排除 |
| `--v2bx-observe` | 保存观察事件与恢复游标，导出一次性快照 |

运行方式为 `sudo bash crowdbastion.sh 参数`。完整菜单、参数及退出码见 [命令行参考](docs/cli-reference.md)。V2bX 输入配置、采样容量与轮转风险见 [V2bX 指南](docs/v2bx-guide.md)。

</details>

## 防护边界与当前状态

- Firewall Bouncer 执行 IP 阻断；AppSec 在线请求检查需要兼容的 Web Bouncer。安装规则不等于完成网站接入。
- 服务 active 或规则存在不能代替业务验证。真实 IP、IPv4/IPv6、INPUT/FORWARD 和 Docker 路径按实际部署核验。
- 共享中转 peer 不能代替用户 IP 作为业务封禁对象；连接限速和带宽清洗不属于当前中转管理功能，链路耗尽需要上游防护。
- 配置修改提供备份与恢复；系统软件包、实时数据库和网站数据不属于完整事务备份。卸载前先核对 [恢复与卸载流程](docs/usage-guide.md#备份与失败恢复)。

> **V2bX 当前定位：诊断与仅观察。** 常驻观察与告警不启用自动封禁或限速；生产节点仍需完成 [部署验收](docs/v2bx-deployment-acceptance.md)。

<details>
<summary><strong>展开兼容性、实验覆盖与待验收项目</strong></summary>

V2bX 的 xray、sing、hysteria2 已有基础协议、双账号混合入口、IPv4/IPv6 和 TCP/UDP 应用载荷的隔离证据。QUIC 认证事件依赖 [固定版本实验补丁](experimental/README.md)，官方未打补丁包不能沿用该覆盖；Shadowsocks 和 xray Trojan 仍有专用检测缺口。菜单 `4 → 4` 支持独立文件日志常驻观察和 `--enable-v2bx-alerts` 仅观察告警接入；专用 profiles guard 隔离决策，不启用自动封禁或限速。

真实 VPS 的仅观察试点仍待 [部署验收](docs/v2bx-deployment-acceptance.md)。系统长测、恢复及部分架构／资源组合尚未关闭；源码回归和 QEMU 结果不代表公网吞吐或生产放行。具体测试数量、配置对照与失败记录见 [验证记录](docs/verification.md)、[验收索引](docs/audit/README.md)和 [修复进度](docs/audit/2026-10-12-vps-repair-progress.md)。

</details>

## 文档导航

| 主题 | 文档 |
| --- | --- |
| **开始使用** | [使用说明](docs/usage-guide.md) · [命令行参考](docs/cli-reference.md) · [更名与升级](docs/project-rename.md) |
| **网站防护** | [AppSec 指南](docs/appsec-guide.md) · [日志与真实 IP](docs/detection-guide.md) |
| **日常运维** | [管理与维护](docs/management-guide.md) · [Telegram 机器人](docs/2026-10-13-custom-telegram-bot.md) |
| **中转部署** | [中转模式](docs/relay-mode.md) · [中心运维](docs/remote-bouncer-operations.md) |
| **落地观察** | [V2bX 指南](docs/v2bx-guide.md) · [部署验收](docs/v2bx-deployment-acceptance.md) |
| **实验与规则** | [实验补丁](experimental/README.md) · [规则样板](rules/v2bx/README.md) |
| **验证与兼容性** | [验证记录](docs/verification.md) · [验收索引](docs/audit/README.md) · [兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md) |

<p align="center">
  <a href="docs/README.md">完整文档索引</a> ·
  <a href="https://github.com/8bitNull/CrowdBastion">GitHub 仓库</a> ·
  <a href="https://www.crowdsec.net/">CrowdSec</a>
</p>

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
  <a href="#适用场景">适用场景</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#检查结果怎么看">检查结果</a> ·
  <a href="#常用操作">常用操作</a> ·
  <a href="#文档导航">详细文档</a>
</p>

CrowdBastion 把 CrowdSec 安装、日志检测、IP 封禁和日常维护集中到一个中文菜单。选择服务器用途后，可以按用途检查运行情况，查看原因和推荐的下一步操作。

## 适用场景

表中的 `1 → 1` 表示先在主菜单选择 `1`，再在子菜单选择 `1`。

| 你的服务器用途 | 提供的能力 | 从哪里开始 |
| --- | --- | --- |
| **网站服务器** | 分析访问日志、封禁攻击来源；按需接入 AppSec 网站请求检查 | `1 → 1` 安装基础防护，`1 → 2` 接入网站防护 |
| **中转 VPS，需要本机检测** | 检测本机系统／SSH 日志中的攻击，执行 IP 封禁 | `1 → 5` 安装中转基础防护 |
| **中转 VPS，已有检测中心** | 接收中心的封禁决策，在本机防火墙执行 | `1 → 6 → 1` 连接远端检测中心 |
| **V2bX 落地节点** | 检查配置、日志与连接来源，支持持续观察和告警；业务检测仅观察 | `4 → 4 → 1` 检查节点，详见 [落地指南](docs/v2bx-guide.md) |

网站接入覆盖 **1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）及宿主机 Nginx/OpenResty**，具体条件见 [AppSec 指南](docs/appsec-guide.md)。中转模式适用于 gost、realm、socat、Nginx Stream 或 NAT 节点，详见 [中转部署](docs/relay-mode.md)和 [中心运维](docs/remote-bouncer-operations.md)。

日常管理还提供规则更新、配置备份恢复，以及可选的 WebUI 管理界面和 Telegram 通知，按部署的组件使用。

## 快速开始

**运行环境：** systemd Linux、root／sudo 权限、Git、Bash 和 Python 3。配置操作还需 PyYAML，安装入口会准备该依赖；手动准备方法见 [环境说明](docs/usage-guide.md#准备环境与下载)。

```bash
git clone --branch main https://github.com/8bitNull/CrowdBastion.git
cd CrowdBastion
sudo bash crowdbastion.sh
```

> 请下载完整仓库，并保留主脚本旁的 `lib/` 目录。

安装前保存现有 CrowdSec／防火墙配置，核对管理员来源 IP，并准备 VPS 控制台或恢复入口。

### 首次使用

1. **选择用途。** 首次在终端启动时，按提示选择网站、本地中转、远端执行或 V2bX 落地。选择只保存偏好，之后可从主菜单 `7` 调整。
2. **安装或接入。** 按上面的场景表进入对应入口。网站安装后从菜单 `2` 选择适合日志的检测规则；落地节点先做配置与日志诊断。
3. **检查运行。** 从主菜单 `8`（或 `4 → 1`）检查，先看结论，再按推荐操作处理。下方说明每种结论代表什么。

菜单输入 `0` 返回，`Ctrl+D` 退出；删除、停用和卸载需明确确认。

<details>
<summary><strong>环境要求与用途组合</strong></summary>

软件源、CrowdSec Hub 和所需镜像须可访问。WebUI 另需 Docker/Compose，定时更新另需 cron/crond；系统版本与实际测试范围见 [VPS 兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md)。

用途可以组合，例如输入 `2 4` 选择本地中转＋落地。远端执行不能与网站／本地中转同选，可与落地组合。偏好保存于 `/var/lib/crowdbastion/node-roles.json`，不保存密钥；尚未选择用途时，`--status` 沿用网站检查范围。

V2bX 落地可以独立诊断，不要求安装本地 CrowdSec；纯远端执行节点也无需本地检测核心。完整步骤见 [使用指南](docs/usage-guide.md)。

</details>

## 检查结果怎么看

**先看“检查结论”，再看“需要关注”和“下一步”。** 检查本身只读取状态，处理操作由你另行选择。

| 检查结论 | 是什么意思 | 你该怎么做 |
| --- | --- | --- |
| **运行检查通过，实际拦截待验证** | 本次运行检查未发现需要修复的问题，实际拦截效果还需验证 | 无需根据本次结果修复；按“下一步”完成业务验证 |
| **发现问题，需要处理** | 已确认服务、配置或日志处理存在问题 | 优先处理“需要关注”中的问题，再检查一次 |
| **部署尚未完成** | 当前用途所需的组件或配置还没有准备齐 | 按推荐入口补齐安装或接入 |
| **检查未完成，暂时无法判断** | 状态无法读取，或暂时没有足够的日志样本 | 查看详情，按原因补充样本或解决读取问题 |

例如，本地中转节点的服务、日志和规则检查通过后，会显示：

```text
检查结论：运行检查通过，实际拦截待验证
检查范围：本地中转
已确认：本地检测服务运行、防火墙防护服务运行、日志读取与解析正常、已发现来源 IP 封禁规则。
待确认：外部连接是否确实被拦截。
本次未发现需要修复的问题。
下一步：按实际流量路径完成一次外部拦截验证。
```

服务运行、规则存在和累计计数，不能证明实际连接已被拦截。业务验证需要使用自己控制的测试来源，核对实际入口和转发路径；具体步骤见 [安装后的验证](docs/usage-guide.md#安装后的验证)。

中转节点可运行 `--verify-relay`，按 [引导验收](docs/relay-mode.md#中转入口引导验收)完成连接对照与恢复检查。向导给出本次入口的通过／未通过／未完成结论，注明外部测试由操作者确认；中转安装完成后也会自动检查并提供验证入口。

菜单可选择“查看检查详情”；命令行用 `--status` 查看短结论，用 `--status-details` 查看完整输出。未安装的可选 AppSec／WebUI 不影响运行检查；已部署组件仍会被检查。

## 常用操作

在下载的 `CrowdBastion` 目录内运行：

```bash
# 按保存的节点用途检查
sudo bash crowdbastion.sh --status

# 查看完整检查详情
sudo bash crowdbastion.sh --status-details

# 查看所有命令行入口
bash crowdbastion.sh --help
```

| 想做什么 | 入口 |
| --- | --- |
| 调整服务器用途 | 主菜单 `7` |
| 检查并选择下一步 | 主菜单 `8` 或 `4 → 1` |
| 管理 IP 封禁与放行 | 主菜单 `3` |
| 更新检测规则 | `--update-hub`，在本地核心或检测中心执行 |
| 验证中转入口实际拦截 | `--verify-relay` 或 `4 → 3 → 3` |
| 查看中转防火墙状态 | `--relay-status`；详情用 `--relay-status-details` |
| 查看远端决策执行节点状态 | `--relay-bouncer-status` |
| 检查 V2bX 配置与日志 | `--diagnose-v2bx`；详情用 `--diagnose-v2bx-details` |
| 配置管理界面或通知 | 主菜单 `5` |

命令行入口的运行方式为 `sudo bash crowdbastion.sh 参数`。更多操作见 [命令行参考](docs/cli-reference.md)和 [管理维护](docs/management-guide.md)。

<details>
<summary><strong>已有安装：更新与更名说明</strong></summary>

在已下载的仓库目录中，先结束修改操作，保存本地源码改动，再更新：

```bash
git pull --ff-only origin main
bash crowdbastion.sh --help
```

项目原名 `crowdsec-1key`。旧入口 `install-crowdsec-1panel.sh` 保留为指向 `crowdbastion.sh` 的兼容链接；已有安装的服务名、配置、备份和规则标识继续沿用。旧仓库地址、分支切换和升级步骤见 [更名与升级](docs/project-rename.md)。

已配置定时更新的安装，更新仓库后还需同步其脚本副本，详见 [日常维护与更新](docs/usage-guide.md#日常维护与更新)。

</details>

## 文档导航

| 你需要了解什么 | 文档 |
| --- | --- |
| **安装与基本使用** | [使用指南](docs/usage-guide.md) · [命令行参考](docs/cli-reference.md) · [更名与升级](docs/project-rename.md) |
| **网站防护与日志排查** | [AppSec 指南](docs/appsec-guide.md) · [日志与真实 IP](docs/detection-guide.md) |
| **中转与检测中心部署** | [中转模式](docs/relay-mode.md) · [中心运维](docs/remote-bouncer-operations.md) |
| **V2bX 落地观察** | [落地指南](docs/v2bx-guide.md) · [部署验收](docs/v2bx-deployment-acceptance.md) |
| **维护、恢复与通知** | [管理维护](docs/management-guide.md) · [备份与恢复](docs/usage-guide.md#备份与失败恢复) · [Telegram 机器人](docs/2026-10-13-custom-telegram-bot.md) |
| **兼容性与测试记录** | [兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md) · [验证记录](docs/verification.md) · [验收索引](docs/audit/README.md) |

<details>
<summary><strong>防护范围与使用边界</strong></summary>

- Firewall Bouncer 执行 IP 封禁；AppSec 在线请求检查需要兼容的 Web Bouncer，并完成各网站接入。
- 核验实际启用的 IPv4/IPv6、INPUT/FORWARD 和 Docker 路径。CDN、代理和多跳中转还需确认真实来源 IP；共享中转来源不能代替用户 IP 作为业务封禁对象。
- 当前中转管理不提供 gost/realm 专用行为检测、连接限速或带宽型 DDoS 清洗；链路带宽耗尽需要上游防护。
- V2bX 的常驻观察与告警不启用自动封禁或限速；生产节点仍需完成 [部署验收](docs/v2bx-deployment-acceptance.md)。
- 配置修改提供备份与恢复；系统软件包、实时数据库和网站数据不属于完整事务备份。卸载前核对 [恢复与卸载流程](docs/usage-guide.md#备份与失败恢复)。

</details>

<details>
<summary><strong>实验覆盖与待验收项目</strong></summary>

V2bX 的 xray、sing、hysteria2 已有基础协议、双账号混合入口、IPv4/IPv6 和 TCP/UDP 应用载荷的隔离证据。QUIC 认证事件依赖 [固定版本实验补丁](experimental/README.md)，官方未打补丁包不能沿用该覆盖；Shadowsocks 和 xray Trojan 仍有专用检测缺口。

菜单 `4 → 4` 支持独立文件日志常驻观察和 `--enable-v2bx-alerts` 仅观察告警接入，专用 profiles guard 隔离决策。日志样本检查与快照导出入口为 `--v2bx-log-check`、`--v2bx-observe`；采样容量与轮转风险见 [V2bX 指南](docs/v2bx-guide.md)，规则样板见 [落地规则说明](rules/v2bx/README.md)。

真实 VPS 的仅观察试点仍待验收。系统长测、恢复及部分架构／资源组合尚未关闭；源码回归和 QEMU 结果不代表公网吞吐或生产放行。具体测试数量、配置对照与失败记录见 [验证记录](docs/verification.md)、[验收索引](docs/audit/README.md)和 [修复进度](docs/audit/2026-10-12-vps-repair-progress.md)。

</details>

<p align="center">
  <a href="docs/README.md">完整文档索引</a> ·
  <a href="https://github.com/8bitNull/CrowdBastion">GitHub 仓库</a> ·
  <a href="https://www.crowdsec.net/">CrowdSec</a>
</p>

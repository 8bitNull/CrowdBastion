<div align="center">
<h1>CrowdBastion</h1>
<p>服务器防护 · 运维管理<br />基于 CrowdSec，面向网站、中转 VPS 与 V2bX 落地节点</p>
</div>

<p align="center">
  <a href="docs/audit/2026-10-12-vps-compatibility.md"><img src="https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&amp;logoColor=black" alt="Platform: Linux" /></a>
  <a href="docs/cli-reference.md"><img src="https://img.shields.io/badge/shell-Bash-4EAA25?logo=gnubash&amp;logoColor=white" alt="Shell: Bash" /></a>
  <a href="docs/usage-guide.md#准备环境与下载"><img src="https://img.shields.io/badge/Python-3-3776AB?logo=python&amp;logoColor=white" alt="Python: 3" /></a>
  <a href="https://www.crowdsec.net/"><img src="https://img.shields.io/badge/powered_by-CrowdSec-6E43E7" alt="Powered by CrowdSec" /></a>
  <a href="https://github.com/8bitNull/CrowdBastion/stargazers"><img src="https://img.shields.io/github/stars/8bitNull/CrowdBastion?style=flat" alt="GitHub Stars" /></a>
  <a href="https://github.com/8bitNull/CrowdBastion/commits/main/"><img src="https://img.shields.io/github/last-commit/8bitNull/CrowdBastion/main" alt="Last Commit" /></a>
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> ·
  <a href="#首页导航">首页导航</a> ·
  <a href="#适用场景">适用场景</a> ·
  <a href="#检查结果怎么看">检查结果</a> ·
  <a href="#常用操作">常用操作</a> ·
  <a href="#更新与维护">更新维护</a> ·
  <a href="#文档导航">详细文档</a>
</p>

CrowdBastion 将 CrowdSec 安装、日志检测、IP 封禁和日常维护集中到一个中文终端菜单。启动后先只读识别已有部署，再按你的防护目标推荐当前一步；执行后复查，退出后可继续处理待办。

## 快速开始

需要使用 systemd 的 Linux、root／sudo 权限，以及 Git、Bash 和 Python 3。软件源、CrowdSec Hub 与所需镜像应可访问；系统与架构的实测范围见 [兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md)。

```bash
git clone --branch main https://github.com/8bitNull/CrowdBastion.git
cd CrowdBastion
sudo bash crowdbastion.sh
```

请下载完整仓库，保留主脚本旁的 `lib/` 目录。Python 3 必须在首次运行前安装，管理锁依赖它；配置操作还需 PyYAML，安装入口会准备该依赖。手动准备方法见 [环境与依赖](docs/usage-guide.md#准备环境与下载)。

安装前保存现有 CrowdSec／防火墙配置，核对管理员来源 IP，并准备 VPS 控制台或恢复入口。

### 首次使用

1. **先看现状。** 启动只读检查已有配置、组件和运行情况，不会自动重装。检查超时或证据不足会保留为未知。
2. **确认目标。** 首页 `3` 用“保护服务器登录”“保护网站”“检查代理/中转”“接收中心封禁结果”确认目标；网站可选择日志检测或同时接入在线请求检查。保存目标不安装组件。
3. **跟着推荐处理。** 首页 `1` 展示当前任务、原因和下一步。修改仍须预览确认，完成后只读复查；取消、失败或仅返回成功不代表任务完成。
4. **按需暂缓和续办。** 任务页 `4` 暂缓，`3` 查看待办并恢复；重新启动先核对现状，再决定从哪里继续。未做的外部验证始终保留“待验证”。

目标和续办记录保存在 `/var/lib/crowdbastion/user-flow.json`（0600），不保存密钥或原始日志。确认目标时会同步适用的旧用途偏好；旧 `/var/lib/crowdbastion/node-roles.json` v1 与高级菜单 `4 → 7` 保留。新旧范围冲突时需重新确认，不自动迁移已有部署。

独立 AnyTLS／Hysteria／TUIC 等代理程序可从 `4 → 11` 查看协议导航，无需选择 V2bX 用途或设置环境变量。

## 首页导航

首页显示本次范围、检查时间、已确认事实和一个推荐动作：

```text
当前情况：有待完成的防护设置
[1] 继续当前推荐任务
[2] 日常管理
[3] 调整防护目标
[4] 高级工具与检查详情
[0] 退出
```

- `1` 的任务随证据变化：优先处理未完成变更和已部署故障，再补齐适用设置、引导实际验证。
- 任务页提供开始/明确重试、详情、全部待办、暂缓和重查；不会自动反复重试失败操作。
- `2` 集中封禁与放行、通知、规则、维护副本及备份说明。`4` 保留原高级管理内部编号，新增 `9` 详情、`10` 待办、`11` 协议导航。
- 输入 `0` 返回，`Ctrl+D` 退出；删除、停用和卸载仍需明确确认。旧首页键序列已调整，专项 CLI 参数和输出约定保持兼容。

网站按实际运行实例选择；一个 Nginx/OpenResty 实例可能承载多个域名，接入会明确这个范围。网站接入配置、真实 IP 核验和实际请求阻断是不同证据，不能相互替代。现有专项多步骤工具继续保留各自的输入、预检、确认和恢复方式。

## 适用场景

| 服务器用途 | 提供的能力 | 开始位置 |
| --- | --- | --- |
| 网站服务器 | 访问日志检测、IP 封禁，按需接入 AppSec 网站请求检查 | 首页 `3` 选择网站目标，再按 `1` 推荐任务 |
| 本地中转 VPS | 检测本机系统／SSH 日志，执行防火墙封禁 | 首页 `3` 选择系统安全目标，再按 `1` 推荐任务 |
| 远端决策执行节点 | 连接已有检测中心，在本机执行中心封禁决策 | 首页 `3` 选择接收中心结果，再按 `1` 推荐任务 |
| V2bX 落地节点 | 检查配置、日志与连接来源，按需持续观察和告警 | 首页 `3` 选择代理/中转检查及 V2bX；[落地指南](docs/v2bx-guide.md) |
| 独立代理程序 | 按程序、协议、实际传输和拓扑提供只读指导 | 首页 `4 → 11`；[协议导航](docs/usage-guide.md#代理协议使用导航) |

网站接入支持 1Panel、科技lion LDNMP、Nginx Proxy Manager（NPM）及宿主机 Nginx/OpenResty，具体前提见 [AppSec 指南](docs/appsec-guide.md)。向导按宿主机、Docker host 或 bridge 分支接入；bridge 所需私有网关须先自行准备。

中转适用于 gost、realm、socat、Nginx Stream 或 NAT 节点，部署方式见 [中转指南](docs/relay-mode.md)与 [中心运维](docs/remote-bouncer-operations.md)。纯远端执行节点无需本地检测核心；V2bX 也可独立诊断，不要求安装本地 CrowdSec。

协议导航不自动安装代理程序，也不等于专项日志检测或运行验证。程序、协议与传输的区别，以及 AnyTLS、VMess/VLESS、Shadowsocks、Trojan、Hysteria、TUIC 的能力范围，见 [协议能力与官方来源](docs/protocol-capabilities.md)。

## 检查结果怎么看

先看“检查结论”，再看“需要关注”和“下一步”。检查本身只读取状态，处理操作由你另行选择。

| 检查结论 | 含义 | 下一步 |
| --- | --- | --- |
| 运行检查通过，实际拦截待验证 | 本次未发现运行问题，尚未确认实际连接被拦截 | 按实际流量路径完成业务验证 |
| 发现问题，需要处理 | 已确认服务、配置或日志处理存在问题 | 处理“需要关注”中的问题，再检查 |
| 部署尚未完成 | 当前用途所需组件或配置尚未齐备 | 按引导补齐安装或接入 |
| 检查未完成，暂时无法判断 | 状态读取失败，或缺少足够日志样本 | 查看详情，解决读取问题或补充样本 |

服务运行、规则存在和累计计数不能证明实际连接已被拦截。应使用自己控制的测试来源，核对 IPv4/IPv6、入口、转发路径和恢复情况，详见 [安装后的验证](docs/usage-guide.md#安装后的验证)。

中转节点可通过 `--verify-relay` 执行 [入口引导验收](docs/relay-mode.md#中转入口引导验收)，外部连接结果由操作者确认；续封、精确删除和自然到期使用 `--verify-relay-lifecycle`。验收记录仅适用于本次核对的入口与范围。

未安装的可选 AppSec／WebUI 不影响运行检查，已部署组件仍会被检查。尚未选择用途时，`--status` 沿用网站检查范围。

## 常用操作

在仓库目录运行，每次指定一个操作；命令行仍保留所需的交互确认。

```bash
# 按保存的用途查看检查结论与下一步
sudo bash crowdbastion.sh --status

# 查看完整检查详情
sudo bash crowdbastion.sh --status-details

# 查看全部命令行入口，无需 root
bash crowdbastion.sh --help
```

| 想做什么 | 入口 |
| --- | --- |
| 设置防护目标 | 首页 `3`；旧用途兼容入口 `4 → 7` |
| 管理 IP 封禁与放行 | 菜单 `2 → 1` |
| 更新检测规则 | `--update-hub`，在本地核心或检测中心执行 |
| 检查中转防火墙 | `--relay-status`；详情用 `--relay-status-details` |
| 查看远端执行节点状态 | `--relay-bouncer-status` |
| 验证中转入口拦截 | `--verify-relay` 或菜单 `4 → 4 → 3 → 3` |
| 检查 V2bX 配置与日志 | `--diagnose-v2bx`；详情用 `--diagnose-v2bx-details` |
| 排查网站与真实 IP | 菜单 `4 → 1 → 3`；[排查指南](docs/detection-guide.md) |
| 管理网页面板、在线控制台与通知 | 菜单 `4 → 5` |
| 防火墙检查与修复 | 菜单 `4 → 4 → 5 → 5`；[维护与迁移](docs/firewall-maintenance.md) |
| 查看短时环境压力 | `--environment-status`（JSON）或菜单 `4 → 4 → 6` |
| 审计 TCP 配置归属与维护副本 | `--network-status`；[网络配置](docs/network-configuration.md) |
| 管理选定入口端口 | 菜单 `4 → 4 → 8`；[端口策略](docs/port-policy.md) |
| 查看程序／协议／传输声明 | `--protocol-status`；交互指导用菜单 `4 → 11` |

更多参数、退出码和菜单路径见 [命令行参考](docs/cli-reference.md)。WebUI 另需 Docker/Compose；通知与机器人按需配置，见 [管理维护](docs/management-guide.md)。

## 更新与维护

### 更新源码

先结束正在进行的修改操作，保存本地源码改动，再在仓库目录执行：

```bash
git pull --ff-only origin main
bash crowdbastion.sh --help
```

### 同步定时任务维护副本

已经启用定时更新时，`git pull` 不会更新 cron 使用的脚本副本，还需比较并确认同步：

```bash
sudo bash crowdbastion.sh --runtime-status
sudo bash crowdbastion.sh --sync-runtime
```

也可使用菜单 `2 → 4` 查看版本、`2 → 5` 同步。同步保留原执行时间；首次设置定时更新用 `--enable-cron`，需要 cron/crond。Hub 规则更新、源码更新和软件包升级是不同操作，详见 [日常维护与更新](docs/usage-guide.md#日常维护与更新)。已部署的 Telegram 交互机器人需在其管理菜单单独检查并更新代码，见 [机器人说明](docs/2026-10-13-custom-telegram-bot.md)。

### 兼容旧版安装

项目原名 `crowdsec-1key`。旧入口 `install-crowdsec-1panel.sh` 保留为指向 `crowdbastion.sh` 的兼容链接，已有服务名、配置、备份和规则标识继续沿用。旧仓库地址、分支与升级步骤见 [更名与升级](docs/project-rename.md)。

## 防护范围与使用边界

- Firewall Bouncer 执行 IP 封禁；AppSec 在线请求检查需要兼容的 Web Bouncer，并完成各网站接入。CDN、反代和多跳中转还需核对真实客户端 IP，不能用共享中转来源代替用户 IP。
- 中转管理不提供 gost/realm 专用行为检测、连接限速或带宽型 DDoS 清洗；链路带宽耗尽需要上游防护。
- V2bX 业务日志的持续观察与告警不自动封禁或限速。QUIC 认证事件依赖 [固定版本实验补丁](experimental/README.md)，官方未打补丁包不能沿用该覆盖；Shadowsocks 和 xray Trojan 仍有专用检测缺口。生产试点条件见 [落地部署验收](docs/v2bx-deployment-acceptance.md)，规则样板见 [落地规则说明](rules/v2bx/README.md)。
- TCP 配置与端口策略是独立可选操作，默认安装和状态检查不调整策略。暂存变更需独立验收，并在 15 分钟期限内提交，否则自动回退；本地核验不等于公网阻断或吞吐通过。
- 配置修改提供备份与恢复，系统软件包、实时数据库和网站数据不属于完整事务备份。恢复或卸载前先核对 [备份与失败恢复](docs/usage-guide.md#备份与失败恢复)。

源码回归与隔离实验不代表公网吞吐或生产放行。实际覆盖、待验收项目和历史失败见 [验证记录](docs/verification.md)、[验收索引](docs/audit/README.md)与 [修复进度](docs/audit/2026-10-12-vps-repair-progress.md)。

## 文档导航

| 主题 | 文档 |
| --- | --- |
| 安装与基本使用 | [使用指南](docs/usage-guide.md) · [命令行参考](docs/cli-reference.md) · [更名与升级](docs/project-rename.md) |
| 网站防护与来源识别 | [AppSec 接入](docs/appsec-guide.md) · [日志与真实 IP](docs/detection-guide.md) |
| 中转与检测中心 | [中转部署](docs/relay-mode.md) · [中心运维](docs/remote-bouncer-operations.md) · [性能测量](docs/relay-benchmark.md) |
| V2bX 落地与代理协议 | [落地指南](docs/v2bx-guide.md) · [部署验收](docs/v2bx-deployment-acceptance.md) · [协议能力](docs/protocol-capabilities.md) |
| 防火墙与可选配置 | [防火墙维护](docs/firewall-maintenance.md) · [TCP 配置](docs/network-configuration.md) · [端口策略](docs/port-policy.md) |
| 维护、通知与恢复 | [管理维护](docs/management-guide.md) · [Telegram 机器人](docs/2026-10-13-custom-telegram-bot.md) · [通知降噪](docs/telegram-noise-control.md) · [备份恢复](docs/usage-guide.md#备份与失败恢复) |
| 兼容性与验收 | [兼容性矩阵](docs/audit/2026-10-12-vps-compatibility.md) · [验证记录](docs/verification.md) · [验收索引](docs/audit/README.md) |
| 开发与本地测试 | [测试入口、依赖与验证范围](tests/README.md) |

<p align="center">
  <a href="docs/README.md">完整文档索引</a> ·
  <a href="https://github.com/8bitNull/CrowdBastion">GitHub 仓库</a> ·
  <a href="https://www.crowdsec.net/">CrowdSec</a>
</p>

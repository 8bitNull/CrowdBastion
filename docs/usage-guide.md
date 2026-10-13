# CrowdSec 防护管理中心使用说明

[返回 README](../readme.md)

本说明对应仓库 `refactor/menu-consolidation` 分支，覆盖网站防护、本地中转精简模式和远端 Bouncer-only。安装前先选节点职责，再使用对应入口；完整验证范围见 [VPS 兼容性矩阵](audit/2026-10-12-vps-compatibility.md)。

## 目录

- [选择部署方式](#选择部署方式)
- [准备环境与下载](#准备环境与下载)
- [网站服务器](#网站服务器)
- [本地中转精简节点](#本地中转精简节点)
- [远端 Bouncer-only 节点](#远端-bouncer-only-节点)
- [安装后的验证](#安装后的验证)
- [日常维护与更新](#日常维护与更新)
- [备份与失败恢复](#备份与失败恢复)
- [移除与卸载](#移除与卸载)
- [常见问题](#常见问题)

## 选择部署方式

| 场景 | 入口 | 本机运行组件 | 需要另行准备 |
| --- | --- | --- | --- |
| 网站日志检测与 IP 阻断 | `--install-core` | CrowdSec、Firewall Bouncer | 实际访问日志与合适的规则集合 |
| 网站在线请求检查 | 网站核心安装后进入菜单 `1 → 2` | CrowdSec AppSec、兼容的 Web Bouncer | Nginx/OpenResty 或受支持容器布局、逐网站验证 |
| 中转 VPS 自己检测 SSH 攻击 | `--install-relay` | CrowdSec、Firewall Bouncer、系统/SSH 采集 | 本机认证日志或标准 SSH journal |
| 中转 VPS 只执行中心决策 | `--install-relay-bouncer` | Firewall Bouncer | 已就绪的中心 LAPI、独立账号和可信通信路径 |

对于性能一般、线路优化的 gost/realm 节点，可优先评估独立中心加 Bouncer 的部署方式，将日志处理放到中心；需要本地独立 SSH 检测时选择本地精简模式。更多 CPU/RAM 可以承载更多日志和规则，但不能补足被转发/NAT 隐藏的源 IP，也不能解决上游带宽耗尽。

512 MiB 本地核心已有短时客机通过证据，256 MiB Bouncer-only 也有早期短时模拟；两者都不是长期容量保证。本轮连续 1 小时/24 小时验收、独立恢复和原生 ARM64 默认启动仍未完成，目前没有本轮新增试用放行组合。生产节点按自身业务量、内存余量、真实流量路径和最新[修复进度](audit/2026-10-12-vps-repair-progress.md)评估。

## 准备环境与下载

需要 systemd Linux、root 权限、Bash、可访问的官方软件源。核心安装覆盖 Debian/Ubuntu 和 CentOS/RHEL/AlmaLinux/Rocky/Fedora 分支；实际支持范围以矩阵中的系统版本和测试模式为准。受限容器、LXC/OpenVZ 的防火墙权限需另行检查。

安装前保存现有 CrowdSec/防火墙配置，确认管理员公网来源 IP，准备 VPS 控制台或其他可用恢复入口。已有 gost、realm、NAT 规则继续由其原工具管理。

```bash
git clone --branch refactor/menu-consolidation https://github.com/8bitNull/crowdsec-1key.git
cd crowdsec-1key
bash install-crowdsec-1panel.sh --help
sudo bash install-crowdsec-1panel.sh
```

始终保留完整 `lib/`，不要只下载一个 `.sh` 文件。命令行每次只指定一个操作；安装和配置参数仍有交互输入。菜单输入 `0` 返回，`Ctrl+D` 或输入结束退出；取消确认不会执行删除、注销或卸载。

配置编辑需要 Python 3/PyYAML，安装入口会准备对应包。已有核心若缺少依赖，可按系统选择：

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y python3-yaml

# RHEL 系列：另选这一组，不需执行上面的 apt 命令
sudo dnf install -y python3-pyyaml

# 检查 root 实际使用的 Python
sudo python3 -c 'import yaml; print(yaml.__version__)'
```

WebUI 另需 Docker/Compose；定时更新另需运行中的 cron/crond。容器镜像、规则和核心软件包仍需下载。

## 网站服务器

### 安装核心并检查日志

```bash
sudo bash install-crowdsec-1panel.sh --install-core
sudo bash install-crowdsec-1panel.sh --status
sudo bash install-crowdsec-1panel.sh --check-logs
```

对应菜单 `1 → 1`、`4 → 1`、`4 → 2`。安装时按提示核对管理员来源 IP。菜单 `2` 按网站类型选择规则；需要 Web 日志检测集合时使用 `--install-waf`。检查实际访问日志是否读取，日志中客户端 IP 是否正确；新增站点后可使用 `--repair-logs` 按实际配置和挂载补齐采集。

### 接入 AppSec 与 Web Bouncer

菜单 `1 → 2` 分别提供 AppSec 配置、首次 Web Bouncer 安装、状态、主动验证、故障策略和停用。命令行步骤为：

```bash
sudo bash install-crowdsec-1panel.sh --install-appsec
# 尚无 Web Bouncer 时，在 AppSec 监听就绪后安装
sudo bash install-crowdsec-1panel.sh --install-web-bouncer
sudo bash install-crowdsec-1panel.sh --appsec-status
sudo bash install-crowdsec-1panel.sh --verify-appsec
```

AppSec 集合、监听、Web Bouncer 接入和实际请求验证是不同步骤。按提示选择实际部署方式、容器和站点；不要只凭监听 7422 或服务 active 判断网站已有 WAF。

1Panel、科技lion LDNMP、NPM 和宿主机 Nginx/OpenResty 的适配前提见 [AppSec 接入与环境适配](appsec-guide.md#web-bouncer-与环境适配)。原生容器首次安装使用实际持久化挂载；Docker bridge 需要先准备私有 LAPI/AppSec 网关，再用 `--configure-docker-endpoints` 登记，登记入口不会自动创建网络或暴露公网端口。

### 核对真实客户端 IP

存在 CDN、反向代理或多层容器时，进入菜单 `1 → 3` 或 `4 → 4`，先选择 Docker/宿主机，再做只读诊断、修复、正常请求核验或撤销。用受控的正常页面请求关联访问日志 IP 与 Web Bouncer 使用的 IP。只信任明确的代理来源，不把所有来源的 X-Forwarded-For 都视为可信。

`--admin-allowlist` 管理中央管理员 AllowList，**会使该来源跳过 AppSec**；不要把 CDN 或共享代理网段当作管理员 IP 加入。

## 本地中转精简节点

适用于本机需要独立系统/SSH 检测的 gost、realm、socat、Nginx Stream 或 NAT 节点。

```bash
sudo bash install-crowdsec-1panel.sh --install-relay
sudo bash install-crowdsec-1panel.sh --relay-status
sudo bash install-crowdsec-1panel.sh --relay-path
sudo cscli metrics
```

安装入口是菜单 `1 → 5`；诊断入口是 `4 → 10` 和 `4 → 11`。安装补齐 linux、sshd、whitelist-good-actors，优先复用 `/var/log/auth.log`、`/var/log/secure` 或标准 SSH journal。自定义 SSH unit/日志需人工核对，使用 metrics 确认日志真的被读取与解析。

此入口保留已有 Web/AppSec 组件，重复安装不会自动把完整版“瘦身”。纯中转缺少系统采集时重新执行 `--install-relay`；`--reset-baseline` 是网站基础集合入口，不适合作为中转精简重置。

在 `--relay-path` 中声明节点角色、用户态/NAT/bridge 路径和 TCP/UDP 入口端口。宿主机 gost/realm 通常检查 INPUT，内核 DNAT/路由转发检查 FORWARD，Docker bridge 需核对实际钩子和跳转顺序。多跳入口看到的来源可能只有上游节点；封禁该来源会影响其所有用户。详见 [中转模式](relay-mode.md)。

## 远端 Bouncer-only 节点

### 中心先创建节点账号

在已就绪的中心 CrowdSec 上，为每个中转节点创建不同账号：

```bash
# 仅在中心执行；返回的密钥保存到安全位置
sudo cscli bouncers add relay-a
```

中心 LAPI 应可经可信私网/WireGuard 到达，或通过证书有效的 HTTPS 提供访问。限制中心入口来源，确认中转到中心的连通性；不直接把明文 HTTP LAPI 开放到公网。中心监听、TLS 和日志转发须自行准备，具体边界见 [中心运维说明](remote-bouncer-operations.md)。

### 中转节点接入

```bash
# 仅在中转执行：URL 和密钥按提示交互输入
sudo bash install-crowdsec-1panel.sh --install-relay-bouncer
sudo bash install-crowdsec-1panel.sh --relay-bouncer-status
```

对应菜单 `1 → 6 → 1` 和 `1 → 6 → 3`。输入中心实际 LAPI URL（例如私网 `http://10.20.0.1:8080/`）和刚创建的 Bouncer 密钥。密钥隐藏输入，不放进命令行参数。首次无 Bouncer 的安装使用校验后的官方 0.0.36 发布包；已有基础配置时复用原安装和防火墙后端，非托管 `.local` 覆盖或归属冲突会拒绝自动修改。

接入不会安装本地 CrowdSec，也不会自动停用已有核心。本地核心产生的决策不会自动转发给中心。若要中心识别中转 SSH 攻击，另行配置可信日志集中采集，并确认中心解析到原始攻击来源 IP。

### 更换中心或密钥

先在中心创建新账号，然后在对应中转执行：

```bash
sudo bash install-crowdsec-1panel.sh --configure-relay-bouncer
sudo bash install-crowdsec-1panel.sh --relay-bouncer-status
```

确认真实同步和业务验证正常后，再在中心撤销旧账号。`--relay-bouncer-status` 不发起认证请求，状态正常不等于 URL/密钥已完成实际认证和业务阻断验证。中心账号也可用 `sudo cscli bouncers list` 检查拉取记录。

## 安装后的验证

对于本地核心，检查配置、服务和解析结果：

```bash
sudo crowdsec -t
sudo systemctl is-active crowdsec crowdsec-firewall-bouncer
sudo cscli metrics
sudo cscli alerts list
sudo cscli decisions list
```

远端 Bouncer-only 节点只检查自身 Bouncer；核心、metrics、alerts、decisions 在中心查询。日志解析计数、服务状态、决策存在和业务阻断分别核验。

在自己控制的测试环境，用独立测试来源和正常来源对照：正常 TCP/UDP 可达，封禁测试来源后其新连接失败，正常来源仍可达，解封后恢复。选择目标入口，分别核查实际启用的 IPv4/IPv6、INPUT/FORWARD 路径；避免用管理员 SSH 来源、共享出口或上游中转做封禁试验。实验结束删除测试决策。实验示例中的 TEST-NET 地址不能替代真实可控客户端。

本地节点在 LAPI 上操作决策；远端节点在其中心操作。仅创建一个测试 IP 决策并查看集合，不等于已验证真实流量阻断。已有长连接和 conntrack 可能继续通行，应使用新会话测试。

| 命令/情况 | 如何解读 |
| --- | --- |
| `--status` 返回 `1` | 发现异常，按输出检查具体链路 |
| `--status` 返回 `2` | 存在尚未验证项目，不能当作全链路通过 |
| `--relay-status` / `--relay-path` 返回 `2` | 只取得静态/路径证据，还需真实业务验证；是这些入口的预期边界 |
| `--relay-bouncer-status` 返回 `0` | 托管配置与服务检查通过，未验证远端认证/业务阻断 |
| 修改操作返回 `75` | 另一管理操作持锁，等其正常结束后重试 |
| 安装/配置命令其他非零退出 | 本次操作未成功，保留诊断并检查恢复状态 |

日志路径、低解析率和代理信任的详细排查见[日志、防火墙与真实 IP 参考](detection-guide.md)。

## 日常维护与更新

```bash
# 按节点模式选择状态入口
sudo bash install-crowdsec-1panel.sh --status

# 本地核心或中心：手动更新 Hub
sudo bash install-crowdsec-1panel.sh --update-hub

# 本地核心或中心：配置每天 03:30 的 Hub 更新
sudo bash install-crowdsec-1panel.sh --enable-cron
```

仅 Bouncer 的节点不运行本地 Hub 更新。定时任务使用服务器时区，需 cron/crond 正常运行；日志在 `/var/log/crowdsec-1key-update.log`，保留 8 份轮转。更新 Hub 不等于更新 CrowdSec 软件包；CAPI 社区决策由引擎同步。

更新本工具源码前先结束修改操作，再在未自行修改源码的检出目录执行：

```bash
git pull --ff-only origin refactor/menu-consolidation
bash install-crowdsec-1panel.sh --help
```

有本地源码改动时先保存并审阅冲突，不覆盖自己的修改。`--enable-cron` 会把脚本及依赖复制到 `/usr/local/lib/crowdsec-1key/current`；只更新仓库不会自动更新已有 cron 使用的副本，更新后重新运行 `--enable-cron` 同步管理副本和计划。

其他可选操作：菜单 `5 → 1` 部署 WebUI；`5 → 3` 管理 Telegram，首次默认即时通知，也可选择官方批量通知。`--telegram-test` 会发送真实测试消息，API 接受只说明服务接收成功。菜单 `4 → 8` / `--optimize` 先诊断，默认不选择任何修复，再汇总确认；不要把它当作无条件“一键提速”。WAL 通过 `--enable-wal` 在明确数据库为本地磁盘后启用。

WebUI 接入条件、Telegram 即时/批量通知、API 回执和维护事务细节见[管理与维护参考](management-guide.md)。完整参数见[命令行参考](cli-reference.md)。

## 备份与失败恢复

普通配置修改备份位于 `/var/backups/crowdsec-1key/change.*`；Hub 事务快照位于 `hub.*`。目录权限 700，含凭据文件权限 600。不要将完整配置、密钥或备份上传到公开仓库。

新快照 format 3 把文件内容分块保存在 `files/`，`transaction.json` 记录元数据和校验值。**保留或迁移快照时复制整个目录**。旧 format 2 可以恢复，但其内嵌内容读取仍需更多内存。快照不包含运行中的 SQLite 数据库及 WAL，不能代替数据库专门备份。

配置校验失败不会重启核心；启动/加载失败会尝试恢复原配置和服务。快照损坏、权限异常或外部写入冲突会拒绝恢复，需保留现场核对。安装的系统软件包和依赖不属于文件事务完整回滚范围。

确需手动恢复 Hub 时，先结束其他管理操作，确认目标快照及冲突提示，再按实际目录替换下面路径：

```bash
sudo python3 lib/crowdsec_maintenance.py restore /var/backups/crowdsec-1key/hub.实际目录 && \
sudo crowdsec -t && \
sudo systemctl reload crowdsec && \
sudo bash install-crowdsec-1panel.sh --status
```

本步骤只适用于本地核心或中心。恢复失败时不要删除保护文件或数据库来绕过检查；先检查工具输出和日志。

## 移除与卸载

远端中转撤销接入：

```bash
sudo bash install-crowdsec-1panel.sh --remove-relay-bouncer
```

这会停用 Bouncer 并移除托管远端覆盖，保留基础配置、软件包、二进制和 standalone unit，不会自动启动原本地配置。中心旧账号需管理员另行撤销。随后直接执行本地核心安装可能被迁移保护拒绝，须先人工核对保留的 unit、二进制、配置和包归属，具体见 [迁移边界](relay-mode.md#远端与本地核心之间的迁移边界)。

本地核心卸载前，先按提示撤销仍接入的 Web Bouncer 并验证网站，然后执行：

```bash
sudo bash install-crowdsec-1panel.sh --uninstall
sudo bash install-crowdsec-1panel.sh --check-clean
```

卸载必须明确确认，会停止服务、移除检测到的软件包及 CrowdSec 数据；防火墙无法检查或仍有受管理资源时会中止/保留现场。备份、系统日志、软件源和其他容器不自动删除。只需停用 AppSec 时使用 `--disable-appsec`；撤销本工具的原生容器 Web Bouncer 使用 `--remove-web-bouncer`。

## 常见问题

| 现象 | 排查步骤 |
| --- | --- |
| 找不到 `lib/` 或辅助模块 | 下载并保留同一分支的完整仓库；不要混用旧单文件脚本 |
| 已安装 PyYAML 仍报缺少依赖 | 用 `sudo python3 -c 'import yaml'` 检查实际解释器，核对自定义 Python/虚拟环境 |
| Firewall Bouncer active，但不能确认阻断 | 检查实际 LAPI、账号拉取、链/集合引用、入口路径，并做独立客户端对照 |
| 远端 URL/密钥无效 | 检查私网/HTTPS 连通与证书、中心账号；用 configure 入口重新输入，保留其他节点账号 |
| 移除远端后本地安装被拒绝 | 核对保留 standalone unit 和配置，按迁移边界人工处理；不要直接删除归属保护 |
| metrics 没有 SSH 解析 | 确认真实认证日志/SSH unit、标签和新事件；远端 Bouncer-only 需另配中心采集 |
| 更新失败或回滚提示冲突 | 检查更新日志与完整快照，暂停外部并行写入，保留现场 |
| ARM64 核心启动超时 | 先查看 unit 和启动日志；TCG 曾出现默认超时，原生验证尚缺，不直接套用诊断延时 |
| 线路良好但 VPS 被大流量打满 | 需要上游限流或清洗；本工具的 IP 决策阻断不能恢复已耗尽的上游带宽 |

只读查看服务日志：本地核心用 `journalctl -u crowdsec -n 50 --no-pager`；Bouncer 用 `journalctl -u crowdsec-firewall-bouncer -n 50 --no-pager`，按权限加 `sudo`。反馈时说明系统/架构、内存、节点模式、命令、退出码、来源路径和脱敏日志。

更多参考：[中转模式](relay-mode.md)、[中心运维](remote-bouncer-operations.md)、[性能测量](relay-benchmark.md)、[验证记录](verification.md)、[修复进度](audit/2026-10-12-vps-repair-progress.md)。

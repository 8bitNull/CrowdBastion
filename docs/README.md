# CrowdBastion 文档索引

项目总览和启动入口见 [仓库 README](../readme.md)。日常使用看指南，验收状态看报告，设计与计划不代表功能已交付。

## 使用与运维

| 文档 | 用途 |
| --- | --- |
| [使用说明](usage-guide.md) | 场景选择、安装、验证、备份恢复、卸载与常见问题 |
| [更名与升级](project-rename.md) | 仓库地址、主入口及旧版运行标识兼容性 |
| [命令行参考](cli-reference.md) | 参数、菜单、互斥与退出码 |
| [AppSec 指南](appsec-guide.md) | Web Bouncer、网站和 Docker 接入条件 |
| [日志与真实 IP 排查](detection-guide.md) | 来源信任、采集与解析、AllowList、防火墙核查 |
| [管理与维护](management-guide.md) | WebUI、Telegram、Hub 更新和恢复 |
| [自定义 Telegram 机器人](2026-10-13-custom-telegram-bot.md) | 可选交互查询与迁移回滚 |
| [维护边界](optimization-boundary.md) | 配置所有权、支持前提与验收要求 |

## 中转与 V2bX 落地

| 文档 | 用途 |
| --- | --- |
| [中转模式](relay-mode.md) | 本地系统／SSH 检测与远端 Bouncer 选择 |
| [中心与远端运维](remote-bouncer-operations.md) | LAPI、凭据、决策范围、故障恢复 |
| [性能测量](relay-benchmark.md) | 目标节点的测量方法，不以仿真吞吐设阈值 |
| [V2bX 指南](v2bx-guide.md) | 三内核诊断、日志核查、持久观察采样与支持格式 |
| [V2bX 部署验收](v2bx-deployment-acceptance.md) | 生产版本、实际入口、来源与仅观察试点条件 |
| [结构化事件契约](v2bx-structured-events.md) | 明确拒绝、固定字段、隐私与日志限额 |
| [实验补丁索引](../experimental/README.md) | 固定版本源码实验，不是自动升级入口 |
| [仅观察规则样板](../rules/v2bx/README.md) | 规范化投影的解析器／场景，未安装 |

## 验收、历史与计划

[验证记录](verification.md)保存各轮检查方法和结果；[验收索引](audit/README.md)指向报告及证据。系统试用放行以 [VPS 修复进度](audit/2026-10-12-vps-repair-progress.md)和 [兼容性矩阵](audit/2026-10-12-vps-compatibility.md)为准，不能用源码测试数量替代目标系统验收。

最近的 V2bX [混合入口实验](audit/2026-10-13-v2bx-mixed-ingress.md)已取得基础组合的双账号、IPv4/IPv6 和 TCP/UDP 应用载荷证据；生产观察仍未部署。历史报告记录当时的版本、配置与检测缺口，后续变化以对应新报告为准。

实施计划位于 `superpowers/plans/`，设计位于 `superpowers/specs/`；V2bX 的后续顺序见 [防护路线](superpowers/plans/2026-10-13-v2bx-protection-roadmap.md)。旧的安装设计、功能审计和实施计划保留作历史背景，不替代当前使用指南。

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| `crowdbastion.sh` | 菜单与命令行主入口 |
| `install-crowdsec-1panel.sh` | 指向主入口的兼容链接，供旧命令和验证工具使用 |
| `lib/` | Bash 功能模块与 Python 配置、诊断、观察工具；运行时必须保留 |
| `docs/` | 使用与部署指南；`audit/` 保存验收报告及证据，`superpowers/` 保存计划与设计 |
| `tests/` | 自动回归及需要外部官方程序的隔离验证工具 |
| `tools/` | 可选辅助工具 |
| `rules/v2bx/` | 未安装的 V2bX 仅观察规则样板 |
| `experimental/` | 固定版本实验源码补丁，不自动替换生产程序 |

验收归档脚本可能依赖各轮临时环境；复现前先阅读对应报告，不将其当作安装入口。

历史验收记录、设计与计划保留当时的 `crowdsec-1key` 名称及脚本路径；当前入口与兼容说明见 [更名与升级](project-rename.md)。

落地常驻采集服务的配置、状态与停用见 [V2bX 指南](v2bx-guide.md#落地常驻仅观察服务)，仍需真实 VPS 试点验收。

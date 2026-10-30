# 验收与证据索引

报告与同轮证据保持原路径。历史通过只说明指定程序、配置和环境；失败轮次与后续对照一起保留。归档脚本可能引用临时实验环境，复现条件以报告为准。

## 2026-10-30 VPS 修复与复审

四台节点的最新检查均为运行检查通过、实际拦截待验证；本地命名空间流量、正常页面可用性和真实 IP 核验的具体范围以各报告为准。

| 节点 | 报告与顺序 | 最新结果与边界 |
| --- | --- | --- |
| VPS 1 | [首次更新](2026-10-30-vps1-script-remediation.md) → [循环修复](2026-10-30-vps1-cycle-repair.md) | 迁移 iptables/ipset，验证续封及真实 IP；首次报告的未解决故障已有后续修复 |
| VPS 2 | [循环修复](2026-10-30-vps2-cycle-repair.md) → [追加复审](2026-10-30-vps2-followup.md) | 修复续封、NPM 主作用域 include 日志识别和混合用途检查指引 |
| VPS 3 | [更新与实测](2026-10-30-vps3-cycle-repair.md) → [追加复审](2026-10-30-vps3-rereview.md) | 原 iptables/ipset 流量验收通过；复现并停用覆盖动态规则的旧开机任务，未做冷启动演练 |
| VPS 4 | [部署修复与流量验收](2026-10-30-vps4-cycle-repair.md) | 修复续封、旧开机任务和 sysctl 配置；冲突 HTTP 代理已停用，尚未恢复该代理服务 |

## 仓库与通知验收

2026-10-30 [仓库整理与回归验收](2026-10-30-repository-consolidation.md)：统一整理重载、真实 IP、健康摘要和防火墙维护改动，串联四台 VPS 及后续脚本复审报告，记录最终提交前验证。

2026-10-30 [防火墙流程循环复审与修复](2026-10-30-firewall-cycle-review.md)：修复集合引用／链覆盖误判、中断清理、并发修改、回退权限及旧版启动顺序文件兼容；新增复审回归，未部署 VPS。

2026-10-30 [四台 VPS 验收回流加固](2026-10-30-four-vps-script-hardening.md)：新增开机规则覆盖、Docker 顺序和双栈入口检查，以及带定时回退、流量验收和独立 SSH 提交的默认后端迁移；本轮仅本地验证，未部署 VPS。

2026-10-29 [Telegram 分级降噪 VPS 更新](2026-10-29-telegram-noise-vps-update.md)：已在目标 VPS 启用分级通知并更新交互机器人；四项服务运行正常，真实普通告警已入库等待汇总，API 只读检查通过。保留备份及恢复脚本；未额外发送测试消息。

2026-10-29 [Telegram 降噪循环复审](2026-10-29-telegram-noise-review.md)：四轮复现并修复 12 个问题，新增 17 项回归；全仓 1135 项（1069 通过、66 可选跳过、0 失败），含真实通知进程经本地 TLS API 验证重启限流、确认与恢复。保留逐轮失败及通过证据。未部署 VPS。

2026-10-29 [Telegram 分级降噪](2026-10-29-telegram-noise-control.md)：持久化通知队列、普通汇总、紧急优先、确认与恢复、迁移回滚；全仓 1118 项（1052 通过、66 可选跳过、0 失败），包含官方 CrowdSec 1.8.1 插件至本地模拟 API 的集成验证。未部署 VPS。

2026-10-20 [仓库整合验收](2026-10-20-repository-consolidation.md)：统一脚本复审、Web 执行证据和 Telegram 九宫格及可靠性修复；全量 1047 项零失败，18 项真实 Nginx/Lua 通过，16 项官方通知检查另行补验通过。包含本地分支归档与同步说明；本轮未部署 VPS。

2026-10-19 [多台 VPS 问题回流加固](2026-10-19-vps-script-hardening.md)：新装默认 iptables/ipset、已知 nftables 续封缺陷检查、托管 Web Bouncer 两项故障策略及旧模块升级；本轮未部署 VPS。

最新中转验证见[入口引导验收与安装反馈](2026-10-14-relay-guided-verification.md)：827 项回归、31 项验收专项，说明人工外部对照、本机只读证据和结论范围。

此前[普通用户检查总结](2026-10-14-health-summary.md)与[节点用途与检查引导](2026-10-14-node-guidance.md)记录保留。

## V2bX 三内核

按实施顺序阅读；最新生产状态仍为未部署、仅观察规则未安装。

| 阶段 | 报告 | 证据与解释 |
| --- | --- | --- |
| 离线日志投影 | [离线观察](2026-10-13-v2bx-observation.md) | [结果](2026-10-13-v2bx-observation-results.json)、[源码来源](2026-10-13-v2bx-observation-sources.json)；早期 synthetic 样本 |
| 网络执行层模拟 | [VPS 模拟](2026-10-13-v2bx-vps-simulation.md) | [归档](v2bx-vps-sim-2026-10-13/)；网络回显、LAPI/Bouncer，不是三内核协议验收 |
| 官方程序基础协议 | [真实协议模拟](2026-10-13-v2bx-real-protocol-simulation.md) | [归档](v2bx-real-protocol-2026-10-13/)；官方 v0.4.0、IPv4、TCP 应用载荷 |
| 持久观察与日志覆盖 | [稳定性验收](2026-10-13-v2bx-observation-stability.md) | [归档](v2bx-observation-stability-2026-10-13/)；恢复、轮转风险、AnyTLS、Shadowsocks 中性分类 |
| hysteria2 core 实验事件 | [认证拒绝实验](2026-10-13-v2bx-hy2-structured-events.md) | [归档](v2bx-hy2-structured-2026-10-13/)；固定版本实验补丁 |
| sing QUIC 实验事件 | [TUIC/Hysteria1/2 实验](2026-10-13-v2bx-sing-quic-events.md) | [归档](v2bx-sing-quic-2026-10-13/)；配套安全 logger、明确拒绝、真实边界对照 |
| 双账号、IPv6、UDP 应用 | [混合入口验收](2026-10-13-v2bx-mixed-ingress.md) | [归档清单](v2bx-mixed-ingress-2026-10-13/manifest.json)；原 25/26 主矩阵及独立 IPv4 监听对照，合并覆盖 26 组、20 告警／0 决策 |

最新[常驻仅观察告警闭环](2026-10-13-v2bx-observation-alerts.md)全仓 730 项（710 通过、20 跳过、0 失败），新增专项 23 项；官方私有引擎形成 10 组观察告警／0 观察决策，独立对照 1 决策。此前[落地采集服务](2026-10-13-v2bx-landing-observer.md)和[本地整合](2026-10-13-local-integration.md)记录分别保留，各轮数量与覆盖范围不能相加后当作一轮验收。

## 系统、中转与资源验证

| 报告 | 范围 |
| --- | --- |
| [VPS 兼容性矩阵](2026-10-12-vps-compatibility.md) | 操作系统、架构、防火墙和资源组合的分层证据 |
| [试用前修复进度](2026-10-12-vps-repair-progress.md) | 当前阻断项、重启与长测状态 |
| [核心安装定位](2026-10-12-core-install-diagnosis.md) | 包配置失败与后续实测 |
| [低配模拟](2026-10-12-low-spec-simulation.md) | 历史资源模拟与限制 |
| [Hub blob 内存修复](2026-10-12-hub-blob-memory-repair.md) | 内存问题、修复和各轮对照 |
| [RPM／ARM systemd 历史验收](2026-10-12-rpm-arm-systemd-acceptance.md) | 原 Task 2 报告；当时的客机结果、失败与复现条件 |
| [ARM64 后续核查](2026-10-12-arm64-followup.md) | 原生架构与模拟证据边界 |
| [远端 Bouncer 验证](2026-10-12-remote-bouncer-validation.md) | 中心同步、执行层与恢复 |

更多历史记录与测试方法见 [验证记录](../verification.md)，运维入口见 [文档索引](../README.md)。证据目录的哈希清单用于核对归档内容；不随文档整理移动或改写原始数据。

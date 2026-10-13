# 验收与证据索引

报告与同轮证据保持原路径。历史通过只说明指定程序、配置和环境；失败轮次与后续对照一起保留。归档脚本可能引用临时实验环境，复现条件以报告为准。

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

最新一轮未重新运行整仓测试；最近完整回归为 sing QUIC 阶段的 689 项（669 通过、20 跳过、0 失败）。各轮告警数、测试数和覆盖范围不能相加后当作一轮验收。

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

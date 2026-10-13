# V2bX 常驻仅观察告警闭环（2026-10-13）

在已有落地观察服务上增加增量发布、专用 profiles guard，以及接入／状态／停用入口。原始日志保持本地，SQLite 固定投影按持久游标发布；不重复导入完整快照。用空 decisions、`on_success: break` 的首个专用 profile 隔离观察场景；其他场景沿用原 profiles。

入口为菜单 `4 → 14 → 4/5/6`，或 `--enable-v2bx-alerts`／`--v2bx-alerts-status`／`--disable-v2bx-alerts`。操作条件、核心重启和恢复边界见[使用指南](../v2bx-guide.md#常驻仅观察告警接入)，设计与实施记录见[设计](../superpowers/specs/2026-10-13-v2bx-observation-alerts-design.md)和[计划](../superpowers/plans/2026-10-13-v2bx-observation-alerts.md)。

## 模拟闭环

[结果](v2bx-observation-alerts-2026-10-13/pipeline-result.json)、[完整输出](v2bx-observation-alerts-2026-10-13/pipeline-final.txt)、[源码与二进制哈希](v2bx-observation-alerts-2026-10-13/source-hashes.json)、[归档哈希](v2bx-observation-alerts-2026-10-13/artifact-hashes.json)。

真实 Python 采集进程读取三内核格式的 synthetic 原始日志，实际 SQLite 与增量发布器接入官方 CrowdSec 1.8.1 私有引擎、LAPI 和数据库。没有协议客户端，也没有生产流量；hysteria2 认证事件样本沿用固定实验契约，不能视为官方未打补丁程序新增日志能力。

- 25 条投影：10 条合格失败、9 条共享中转、6 条健康连接；形成 10 组观察告警，逐告警决策为空，观察决策为 0。
- profiles 后置的无条件封禁兜底故意忽略 Remediation。观察 guard 成功阻断它；独立 `qa-control` 场景仍对 `198.51.100.250` 产生 1 条预期决策，说明没有通过清空所有 profiles／决策来伪造隔离成功。
- 初始积压、采集进程与发布对象正常重启、三个源日志重命名轮转后继续读取；最终事件 ID 唯一，已发布记录不再次导出。模拟消费者代际改变被阻止，输出字节保持一致。
- 这不是逐行告警率、真实公网协议验收或消费端恰好一次交付。场景有 1 秒 blackhole；本轮合格失败分别落在不同来源／内核／协议组，未测试同组高频告警阈值。

运行命令：

```bash
PYTHONPATH=/tmp/v2bx-test-python-deps python3 tests/verify_v2bx_alert_pipeline.py /tmp/crowdsec-qa-engine/crowdsec-v1.8.1 RESULT_JSON
```

## 源码与生命周期验收

新增发布器 11 项、管理器 12 项，共 23 项通过。包含完整待提交写入恢复后 fsync、零字节意图等待同一消费者、部分写入停止、输出替换、源库替换、容量上限、单进程发布、copytruncate 风险报告、规则／guard 变更拒绝、同名资产／重复采集拒绝、配置失败恢复、恢复重启失败保留证据、并发创建目录保留、重复进程不覆盖心跳、遗留指标恢复及陈旧 acquisition 计数不释放积压。

最终[全仓输出](v2bx-observation-alerts-2026-10-13/final-unittest.txt)：730 项，710 通过、20 按环境条件跳过、0 失败，175.261 秒。Bash/Python 语法、ShellCheck（既有排除项）、新 unit 的 `systemd-analyze verify`、本地 Markdown 目标与 diff 检查通过；README 保持 70 行。管理启停为 systemctl fixture，不能计作真实 systemd 客机验收。

```bash
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=/tmp/v2bx-test-python-deps python3 -m unittest discover -s tests -q
```

## 失败与复审

首轮闭环的对照断言失败，见[初次输出](v2bx-observation-alerts-2026-10-13/pipeline-initial-failed.txt)和[定位输出](v2bx-observation-alerts-2026-10-13/pipeline-diagnosis-failed.txt)。实际官方 cscli 将决策嵌套在告警组中，测试误按扁平列表读取；定位输出证实对照决策存在。修正断言后重跑完整闭环，观察决策仍为零。

独立审查发现：完整批次恢复需先 fsync、恢复重启失败不能先删除备份、非锁持有者不能覆盖状态、崩溃指标临时文件需锁内恢复、不能清理其他操作创建的目录。每项均用失败回归复现后修正；后续复审无重要遗留问题。部分失败输出保留在[恢复回归记录](v2bx-observation-alerts-2026-10-13/recovery-tests-failed.txt)。此外补充 acquisition 新读数和源采集器健康要求，防止陈旧指标误报正常。

## 真实试点待办

当前宿主机没有安装本轮服务、修改核心配置或防火墙。实际 VPS 的 systemd 沙箱、服务权限、Prometheus、真实直连／中转来源、日志轮转与磁盘增长仍待验证。需要已有 SSH 主机别名、目标职责、V2bX／CrowdSec 版本、实际日志路径、中转 IPv4／IPv6 出口和受控客户端；不在聊天中提供密钥。

Publisher 有持久意图与游标，不代表 CrowdSec tail 的持久接收确认。消费端崩溃可能丢失已读取但未保存的告警；核心代际改变会停止发布，等待对照，不自动补发或丢弃证据。部分写入／容量耗尽／停用后重新接入也需人工确认新观察窗口。业务自动封禁、TCP／UDP 连接限制及带宽清洗均未完成。

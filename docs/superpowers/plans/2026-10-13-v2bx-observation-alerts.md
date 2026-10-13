# V2bX 仅观察告警实施计划

> 当前会话顺序执行；使用 test-driven-development、verification-before-completion，完成后按 requesting-code-review 做独立复审。

**Goal:** 连接采集数据库与 CrowdSec 观察告警，提供可恢复接入入口。
**Architecture:** 有持久账本的增量发布器、私有 systemd 服务、profiles 最前隔离 guard、独占规则与 acquisition。
**Tech Stack:** Python 3、SQLite、PyYAML、Bash、CrowdSec 1.8.1。
**Spec:** ../specs/2026-10-13-v2bx-observation-alerts-design.md

## 约束

单批最多 256 行；输出上限 128 MiB；不产生观察场景决策；不自动重放消费端重启的记录；不改写原始日志或既有采集库；不部署宿主机。

## Task 1: 增量发布

Files: `lib/crowdsec_v2bx_stream.py`、`tests/test_v2bx_stream.py`。
接口：`Publisher(state, databases, output=None)`；`bind_consumer(generation)`；`publish()`；`probe()`；`close()`。

- [x] 写游标／积压／崩溃／容量／消费者代际测试，执行专项，确认 helper 缺失的失败。
- [x] 实现源库只读连接、单实例账本锁、持久意图及完整写入恢复。
- [x] 测试正常重启不重发、部分写入／换库／代际变化停止，固定脱敏失败码。

## Task 2: 接入管理与决策隔离

Files: `lib/crowdsec_v2bx_alerts.py`、`tests/test_v2bx_alerts.py`、`tests/verify_v2bx_observation.py`。
接口：profiles guard 原始前缀；`AlertManager.enable/status/disable`；发布服务 run 循环。

- [x] 先写恢复／重复采集／guard 保留测试再实现管理器。
- [x] 官方引擎先验证 guard 与全封禁兜底，再连接真实采集器和发布器。
- [x] 检查所有观察告警零决策，对照场景保留正常决策。

## Task 3: CLI／文档与验收

Files: `lib/v2bx.sh`、主脚本、V2bX 指南、验收索引与新实验报告。

- [x] 接入启用、只读状态和停用入口；明确持久记录与恢复边界。
- [x] 跑专项、官方隔离闭环、全仓、ShellCheck、语法、unit 静态校验及索引链接／哈希检查。
- [x] 独立审查并修复重要问题；只在本地整合，远端推送沿用用户授权但不部署实际 VPS。

# Telegram Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 对齐 TG 与主脚本的维护互斥、状态检查和程序副本更新。

**Architecture:** JSON 状态接口复用主脚本原始检查和共享结论规则；机器人通过受限入口读取，并在确认修改时获得共享维护锁。安装随附托管主脚本副本，独立比较和更新机器人代码，保留配置和服务状态。

**Tech Stack:** Bash、Python 3 标准库、现有 PyYAML、flock/systemd；无新依赖。

**Spec:** `docs/superpowers/specs/2026-11-01-telegram-alignment-design.md`

## Global Constraints

保留所有既有工作区改动，不提交、不推送、不连接 Telegram、不部署 VPS。旧菜单编号保留。产品修改保留确认。20 秒完整检查预算、30 秒缓存。失败不误报健康；命令成功不代表业务拦截。无子代理工具，实施与最终顺序自查均在本会话进行。

## Review Focus

- 锁争用或迁移未完成时，确认已领取也不得产生系统修改。
- JSON 采集失败、配置不一致、超时，不能静默回落为完整检查通过。
- 安装副本离开源码仍可检查；更新失败恢复原代码及服务状态。
- 代码变化不受私有配置和状态变化干扰；未知类型和归属拒绝覆盖。
- 取消更新与停用服务更新不得隐式启用机器人。

### Task 1: 共享维护锁

**Files:** 新增 `lib/crowdsec_bot_runtime.py`、`tests/test_telegram_alignment.py`；修改 `lib/crowdsec_bot.py`。

**Interfaces:** `maintenance_guard(lock_path, migration_path)` context manager；bot 配置 `maintenance_lock` / `migration_state` 默认使用主脚本路径。

- [x] 添加真实 flock 争用、未结束迁移、安全路径、锁释放及确认流程失败不执行测试，运行确认失败。
- [x] 实现安全非阻塞锁和迁移检查，接入 `execute_confirmed`，保留审计与未知结果语义；成功使缓存失效。
- [x] 运行 `python3 -m unittest test_telegram_alignment test_custom_bot_flow test_custom_bot_actions`，预期全部通过。

### Task 2: 同源结构化健康检查

**Files:** 修改 `lib/crowdbastion_health.py`、`lib/health_summary.sh`、`crowdbastion.sh`、`lib/crowdsec_bot_health.py`、`lib/crowdsec_bot.py`；扩充 `tests/test_telegram_alignment.py`。

**Interfaces:** `--status-json` 输出 `{version, checked_at, config_path, roles, checks, required, summary, scope}`；`HealthCollector(config_path, roles_path=..., manager_path=None)`，`collect()` 仍返回现有 report 结构。

- [x] 添加 JSON 与原始采集一致、无原始秘密、故障退出码、manager 超时/损坏不误报、旧配置范围标识测试并确认失败。
- [x] JSON 模式复用原始检查和 summarize；bot 使用固定 argv、20 秒进程组超时、验证 schema/退出码并缓存；详情显示完整范围。
- [x] 运行 `python3 -m unittest test_telegram_alignment test_custom_bot_health test_custom_bot_views test_health_summary`，预期全部通过。

### Task 3: 自包含部署、版本检查与更新

**Files:** 修改 `lib/custom_bot.sh`、`lib/crowdsec_bot_settings.py`、`lib/crowdsec_bot_runtime.py`，扩充安装与对齐测试，更新 Telegram / CLI / 使用指南。

**Interfaces:** bot runtime 位于 bot 程序目录 `runtime/current/manager.sh`；新增菜单 4 代码检查、5 保留配置更新。代码比较接口使用主程序与 helper 的内容哈希及 runtime 指纹，返回 0 一致、2 缺失/不同、1 检查失败。

- [x] 添加自包含安装、代码漂移、取消、配置字节保留、原服务状态、更新失败回滚、安全归属测试并确认失败。
- [x] 在 setup 安装 runtime，配置记录固定路径；更新复用备份/回滚及 runtime 发布，保留原启用和运行状态；检查不写配置、不调用 TG。
- [x] 运行机器人全部测试与相关维护测试，预期通过；更新文档。

### Task 4: 最终复核与证据

- [x] 单独复核最终 diff 的失败/取消路径、JSON 信任边界、锁与副本归属；发现问题先 red 后 green。
- [x] 运行 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests:lib python3 -m unittest discover -s tests`，预期零失败；记录条件跳过。
- [x] Bash/Python 语法、相关 ShellCheck、帮助、文档链接及 `git diff --check`；归档 `.txt` 证据，写审计报告。

## Execution ledger

用户已确认上述优先范围；继续当前 feature 分支，避免拆离相互依赖的未提交修改。计划不包含提交步骤。授权覆盖本地实现和验证，不包含部署。最终不要求再次批准这些已授权动作。

Task 1–3 完成；最终代码专项为 71 / 97 / 268 项通过。九轮顺序自查及修复已记录于 [审计报告](../../audit/2026-11-01-telegram-alignment.md)。第六轮补齐 required 必检项，使用 renderer/CLI 到 bot reader 的真实往返取代仅手工构造摘要的覆盖假设；第七轮隔离 fixture 进程扫描；第八轮拒绝由 is-enabled 的返回码推断非常规启用意图；第九轮支持可信 sticky 锁目录，保持私有配置/报告目录规则严格。

Ruling: 保留现有未提交 feature 工作区，不创建提交或推送 — 保护用户混合改动与授权边界 — 代价是提交范围工具无法代表本次交付。

Ruling: 没有独立 reviewer 工具，最终使用本会话实际工作区 diff 与新文件顺序自查 — 复审、RED/GREEN 和全仓结果作为本地证据 — 代价是仍缺独立审阅和 VPS/TG 联机验收。

工具记账在初始实施及前五轮复审后补齐。`task-start`/`task-done` 已实际运行，base/head 相同表示未提交工作区，不表示无改动；`review-package` 拒绝空提交范围，未绕过保护，改为记录实际工作树快照。一次中间安装断言失败单项未复现，之后全仓的明确输出和稳定 RED 证明进程扫描缺少隔离；第七轮修复 fixture 并保留生产冲突检查。另一次运行在第八轮修复后主动终止，第八轮后全仓曾以 1391 项、89 跳过、零失败结束；该记录早于第九轮代码和新增用例，最终全仓在第九轮最后代码/测试修改后重跑：1392 项、1303 通过、89 条件跳过、零失败，461.115 秒，退出码 0。Task 4 完成；最终静态及本地链接检查通过，167 文件源码快照归档并核对一致。

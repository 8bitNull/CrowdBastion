# Telegram 通知降频 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** VPS 关注首次及时、后续一小时聚合，普通六小时汇总，修复并发入站时绕过窗口及退避。
**Architecture:** 保留现有持久事件和槽队列，投递时校验汇总窗口；仅更新现有配置的两个间隔。远端基于已上线源码构建本轮管理副本，单独重启通知进程。
**Tech Stack:** Python unittest、SQLite、Bash、systemd、SSH。
**Spec:** `docs/superpowers/specs/2026-11-01-telegram-noise-design.md`

## Global Constraints

- 已批准一小时/六小时间隔；关注窗口按节点共用，窗口内新规则也合并。
- 不改防护、规则分级、路由、凭据及消费状态，不提交、不推送。
- 保留混合工作树，先快照；VPS 基于已部署版本叠加本轮通知文件。
- 证据目录0700、文件0600；不用真实发送测试冒充聊天验收。

## Review Focus

- 发送成功前新增事件和调度替换快照：只标记已发送计数，窗口内不再发。
- 失败时快照被替换：退避仍应用于当前槽并跨重启保留。
- 窗口关闭期间持久旧队列：投递选择直接阻止，不能饿死紧急消息。
- 六小时摘要及关注窗口重启：新增数据不丢，无新增不发。
- 部署失败：恢复代码和配置，活队列不倒退，其他服务 PID 不变。

### Task 1: 通知调度和回归

**Files:** `lib/crowdsec_notify.py`, `tests/test_notify_noise.py`, `docs/telegram-noise-control.md`。
**Interfaces:** 继续使用 `Store.schedule(now)` / `deliver_one(send, now)`；配置字段不增加。

- [x] 写测试：3600/21600配置，首次关注与跨规则合并、重启、无事件静默、紧急绕过。
- [x] 写失败回归：send 中 ingest+schedule 后立即再次 deliver_one 被阻止，关注及普通均覆盖。
- [x] 写失败回归：send 中替换快照后网络失败，5秒/429退避仍保留，重启不提前重试。
- [x] 运行 `PYTHONPATH=tests:lib python3 -m unittest discover -s tests -p test_notify_noise.py`，保存 RED。
- [x] 最小修复投递窗口、成功槽清理及失败槽退避，跑通知相关测试与完整 unittest discover，保存 GREEN。
- [x] 文档注明推荐配置、节点共用窗口和重试限制，作者顺序自查差异。

### Task 2: VPS 发布及证据

**Files:** 本轮独立审计报告、证据目录和私有临时部署脚本。
**Interfaces:** 保留现有安装路径与服务，只改通知运行文件及管理副本中的同名源码。

- [x] 读取当前指纹、路径、服务和实际配置，校验与先前上线基准；暂存候选代码、校验哈希。
- [x] 建立0700备份目录，配置/代码备份及SQLite一致性备份，保存服务与消费状态摘要。
- [x] 在共享维护锁内停止通知、原子更新通知程序/配置及管理副本，启动通知；异常/INT/TERM尝试恢复。
- [x] 检查本地配置与实际安装导入、就绪/健康、新策略、旧事件键保留、其他服务PID、管理副本一致性和offset。
- [x] 写报告、完成检查项、封存文件哈希和权限；说明未实等六小时、未主动发送聊天测试。

## Ledger

- 已按用户批准继续执行，无子代理，复审采用作者顺序自查。
- 新旧默认兼容：只把本 VPS 显式策略改为3600/21600，通用默认不迁移。
- Task 1 complete：新增9项、初次7失败；通知64项（62通过/2跳过），全仓1415项（1326通过/89跳过），exit 0。150 Python AST、18 Bash及169源码哈希核对通过。
- Task 2 complete：通知服务单独重启，配置仅2字段变化，15保护文件不变、1 offset不倒退、291 incidents/477 events原键保留。远端11个稳定备份文件完成哈希封存，SQLite quick_check ok，0700/0600通过。
- Ruling：直接在已核验的通知安装副本原子更新唯一变更的程序文件及配置，避免完整安装流程重启core；其余7 helper与测试源码hash相同，独立安装检查及线上就绪/健康复核通过。

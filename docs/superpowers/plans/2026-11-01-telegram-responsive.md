# Telegram 健康查询响应 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复健康结论、缓存提示及约十秒采集阻塞主循环的问题，并更新 VPS。

**Architecture:** 在现有 bot 内加入单线程有界健康页面调度器，复用已有 collector、API 状态锁和所有修改保护。仅两种健康视图异步处理，显式刷新与普通导航分开。

**Tech Stack:** Python 标准库、unittest、现有 Bash 部署入口。

**Spec:** [设计](../specs/2026-11-01-telegram-responsive-design.md)

## Global Constraints

不提交推送；原混合工作树原位继续；维护锁、确认、offset 防重放和审计保持；不得降低完整检查失败的结论；旧历史证据不改。

## Review Focus

- 持续刷新：最多 8 卡片，同卡片合并，无界增长必须拒绝。
- 页面返回及操作确认：在途旧结果不得覆盖新内容。
- 查询异常：安全失败文案且工作线程继续处理下一项。
- 修改完成时检查还在进行：旧健康结果失效，下次重新采样。
- 缓存失效／完整接口失败：强制采样不复用旧结论，不退回轻量全绿。

### Task 1: 展示与刷新语义

**Files:** 修改 `lib/crowdsec_bot.py`，新增 `tests/test_telegram_responsive.py`。
**Interfaces:** `render_view(..., force_refresh=False, requested_at=None)`；原 renderer 签名保持。

- [x] 写简版／详情 verdict、pending 中性名称、缓存命中、强制刷新及失败边界测试，运行确认 RED。
- [x] 实现中性名称、全部页面结论及采样提示；健康刷新使用 fresh: 前缀。
- [x] 运行新增测试及健康／菜单／同源回归确认 GREEN。

### Task 2: 有界后台健康页面

**Files:** 同上。
**Interfaces:** `HealthViewWorker.submit(key, render, deliver)`、`invalidate(key=None)`、`close()`；main 创建 worker，handle_update 身份通过后使旧卡片任务失效。

- [x] 写慢采集期间主菜单可响应、队列有界、同卡片替换、旧结果抑制、异常恢复及修改失效测试并确认 RED。
- [x] 实现单个 daemon worker，条件变量保护任务和发送；仅采集在后台，修改留主循环。
- [x] 运行交互、确认、锁、API 及安装回归确认 GREEN；作者顺序自查并记录。

### Task 3: 验收与 VPS 更新

**Files:** 更新用户说明，新增 `docs/audit/2026-11-01-telegram-responsive.md` 及私有证据目录。

- [x] 执行全仓 unittest、语法及 diff 检查，记录源码 hash。
- [x] 只读核对 VPS 当前来源与服务，备份现有 bot 程序／helpers／unit 和状态元数据。
- [x] 完整 manager/lib 发布至新版本目录，通过菜单 5 更新 bot；保留配置字节、offset、审计和服务意图。
- [x] 验证已安装真实 renderer、同源结论、版本一致、轮询、单实例；记录真实 TG 验收边界及回滚路径。
- [x] 封存证据，交付报告。

## Execution ledger

- 用户确认授权已覆盖此范围，按开发者要求不为技能额外重复索取批准。
- 继续现有 feat/user-experience-20261101；新 worktree 会遗漏大量既有未提交实现，因此保留当前工作树并保存本轮开始快照。
- 本环境无独立 reviewer，所有审阅明确为作者顺序自查。
- 三轮本地复审：新增行为、确认存储并发初始化及旧启动测试精确性。185 项与 45 项相关回归通过；最终全仓 1406 项，1317 通过、89 跳过，源码 168 项无漂移。
- 首次远端调用因重复取共享锁而拒绝，入口已恢复；按已有嵌套锁约定修正部署脚本后，菜单 5 更新成功。保留失败／恢复证据。
- VPS 新指纹 73c519efafda0ac9…，7 项配置不变，offset 不倒退，原审计 0 文件。仅重启 bot；实际采集约 10 秒，本地传输替身下导航不等待采集。真实 TG 只读 API 与轮询通过，用户按钮／投递仍待验收。
- 报告：[本轮验收](../../audit/2026-11-01-telegram-responsive.md)。

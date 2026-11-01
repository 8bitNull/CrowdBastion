# Guided Interaction Implementation Plan

> **For agentic workers:** Implement the approved interaction in the current session, task by task, then obtain an independent review.

**Goal:** 让用户从用途选择、安装、检查走到问题处理和复查。

**Architecture:** 复用原菜单与底层部署函数，在 node_guidance.sh 增加用途引导，首页缩减并将原菜单移到高级管理。health_summary.sh 管理检查循环和服务排查，Python 保持证据判断并改善展示。

**Tech Stack:** Bash、Python 3 标准库、现有 unittest 和伪终端测试。

**Spec:** docs/superpowers/specs/2026-10-31-guided-interaction-design.md

## Global Constraints

- 不新增依赖，不改现有 CLI 名称与退出码。
- 修改配置沿用锁与确认；检查和取消操作不改变部署。
- 远端与纯落地用途不强制安装本地核心。

## Tasks

- [x] 1. 修改 crowdbastion.sh 首页为检查、引导安装、IP 管理、高级管理；原菜单置于 manage_advanced。在 lib/node_guidance.sh 增加 guided_setup，按用途提供步骤与检查入口。更新 tests/test_workflows.py 和 tests/test_node_guidance.py 导航测试，增加用途分派及取消测试。
- [x] 2. 修改 lib/crowdbastion_health.py，保持 summarize 的判定兼容，增加用户摘要并修正混合问题计数。修改 lib/health_summary.sh，支持复查循环、结构化服务排查与经确认的启动操作；启动在锁内复验条件。补充 tests/test_health_summary.py 对应测试。
- [x] 3. 同步 readme.md、docs/usage-guide.md、docs/cli-reference.md 与其他活跃文档路径。运行 bash -n、上述测试与相关 CLI 回归；审查完整 diff 并取得独立代码审查。

## Review Focus

- EOF 和取消不能触发安装或反复检查。
- 组合用途按用途展示，不为纯落地推荐中转核心安装。
- systemd 未知状态与配置校验失败不能提供盲目启动。
- 排查后的返回不丢失检查流程，详情仍使用同一份采集结果。
- CLI 默认仍不提示输入、不执行启动、不保存用途。

## Execution record

- 新增引导测试先失败，再实现首页、用途步骤、排查和复查；最终新增 12 项测试通过。
- 独立审查发现首次保存用途发生于管理锁子 shell，需要父 shell 重新读取；新增两条真实锁复现测试先失败，修复后通过。
- 纯落地不再建议安装本地 CrowdSec，同步相关回归断言。
- 检查结果相关 41 项测试通过；中转及脚本修复相关 78 项完成，76 通过、2 跳过。
- 最终主要回归 190 项全部通过，覆盖引导、检查摘要、用途与原工作流。
- Bash/Python 语法、帮助入口和 git diff --check 通过。未修改真实 VPS 服务，未提交或推送。
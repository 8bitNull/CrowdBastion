# Node Guidance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan. Steps use checkbox syntax for tracking.

**Goal:** 让 CrowdBastion 按用户声明的节点用途引导安装、检查与下一步，减少菜单中的无意义输入。

**Architecture:** 在现有 Bash 功能模块之上增加用途与引导模块，复用原有安装、诊断和修复函数。用标准库 Python helper 保存用途；扩展现有指标与防火墙检查以服务中转/远端场景，保留保护证据边界。

**Tech Stack:** Bash、Python 3 标准库、项目现有 PyYAML、unittest 和 PTY。

**Spec:** `docs/superpowers/specs/2026-10-14-node-guidance-design.md`。对应用户确认的第一轮四项优化。

## Global Constraints

- 主菜单 1–6 及现有命令行参数保持兼容。
- `remote` 不能与 `web` / `relay` 同选，`remote node` 可以同选。
- 用途保存到 `/var/lib/crowdbastion/node-roles.json`，不保存凭据。
- 首次引导仅在交互终端运行；状态命令不增加输入或写操作。
- 修改仍使用现有锁、确认、备份和回滚；不自动安装、修复、封禁或发送验证请求。
- 状态 `1` 表示异常、`2` 表示尚未验证，实际业务未验证不得宣称全部通过。

## Task 1: 用途、检查与导航作为一个可验收交互流程

这些改动共用主菜单、状态分派与推荐动作，作为同一任务执行，避免半成品入口。

**Files:**

- Create: `lib/crowdbastion_node.py`（用途配置的标准库读写与校验）。
- Create: `lib/node_guidance.sh`（用途选择、推荐入口、角色检查和交互下一步）。
- Modify: `crowdbastion.sh`（加载引导模块、主菜单、状态分派和暂停位置）。
- Modify: `lib/maintenance.sh`、`lib/crowdsec_maintenance.py`（系统/SSH 指标路径）。
- Modify: `lib/crowdsec_relay.py`、`lib/relay.sh`（远端规则检查不要求本地核心）。
- Modify: `lib/v2bx.sh`（返回菜单的暂停行为）。
- Create: `tests/test_node_guidance.py`。
- Modify: `tests/test_maintenance.py`、`tests/test_relay_mode.py`、必要的现有菜单测试。
- Modify: `readme.md`、`docs/usage-guide.md`、`docs/cli-reference.md`。

**Interfaces:**

- Consumes: 现有 `install_crowdsec_core [web|relay]`、`remote_bouncer_change`、`check_relay_status`、`diagnose_v2bx`、`manage_*` 与 `locked_operation`。
- Produces: 用途配置 helper `load PATH` / `save PATH ROLE...`，验证角色后返回规范化的角色列表。
- Produces: Bash 用途加载、选择、标签、推荐入口；`check_health_status` 按用途分派，未选择用途保持旧行为；交互 wrapper 提供下一步，CLI 返回状态。

- [x] **Step 1: 建立失败回归。** 在 `tests/test_node_guidance.py` 中复用临时目录的 Workflows 夹具，测试选择 `relay node` 后重载保持用途、`remote web` 被拒绝、`0`/EOF 不写文件、只读状态不修改文件；用 PTY 重放首次选择与返回菜单。添加系统指标与远端审计用例。

```python
# 生产行为目标示例：remote 模式不能访问本地核心。
result = self.run_shell('NODE_ROLES="remote"; check_health_status', overrides=remote_fixture)
self.assertNotIn('cscli ', self.commands())
self.assertNotIn('systemctl is-active --quiet crowdsec\n', self.commands())
self.assertEqual(result.returncode, 2)
```

- [x] **Step 2: 验证失败来自缺失行为。**

```bash
python3 -m unittest discover -s tests -p test_node_guidance.py
```

- [x] **Step 3: 实现用途持久化与引导。** 严格限定四种用途；拒绝不安全文件、无效版本及角色冲突；使用同目录临时文件与原子替换。设置入口只保存用户选择，首屏展示匹配推荐。
- [x] **Step 4: 实现用途匹配的只读检查。** 复用网站检查；系统检查读取 acquisition JSON 并按系统/SSH 来源汇总；远端审计仅检查 Bouncer；组合用途覆盖本机已有防护。聚合 `1 > 2 > 0`，缺失证据与未部署不混淆。
- [x] **Step 5: 接入下一步与减少暂停。** 推荐动作从检查结果或缺失组件得出。交互选择下一步才分派修改动作；CLI 只打印建议。把 `pause` 留在叶子操作上，返回与无效输入直接重绘菜单。
- [x] **Step 6: 验证行为与兼容性。**

```bash
python3 -m unittest discover -s tests -p test_node_guidance.py
python3 -m unittest discover -s tests -p test_workflows.py
python3 -m unittest discover -s tests -p test_maintenance.py
python3 -m unittest discover -s tests -p test_relay_mode.py
bash -n crowdbastion.sh lib/*.sh
shellcheck -x -e SC2317,SC2329,SC2120,SC2119 crowdbastion.sh lib/*.sh
git diff --check
```

- [x] **Step 7: 同步使用文档并完整回归。** 文档说明组合用途、首次终端引导、保存路径、新入口、CLI 行为与验收边界。运行 `python3 -m unittest discover -s tests`；可选外部实验仍按其依赖条件跳过。
- [x] **Step 8: 独立审查、修正并集成。** 审查安全边界、角色遗漏、推荐动作、返回/EOF 与兼容性。检查通过后提交并合入已授权同步的 `main`，验证远端与本地提交一致。

## 验证记录

最终回归 769 项：748 通过、21 跳过、0 失败。独立审查完成，问题已修正；详见 `docs/audit/2026-10-14-node-guidance.md`。整合采用已授权的 main 快进与远端同步。

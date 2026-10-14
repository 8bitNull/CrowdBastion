# 中转引导验收 Implementation Plan

> **For agentic workers:** Execute inline using executing-plans. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 普通用户能够按引导完成一次中转入口验收，并分清通过、失败与证据不足。

**Architecture:** 独立 Python 模块负责输入、只读 nftables 证据与验收状态机；Shell 接入现有菜单、命令行和安装后的检查。外部业务连接由操作者在自己的设备执行，验证不创建或删除决策。

**Tech Stack:** Bash、Python 3 标准库；读取现有配置复用 PyYAML。

**Spec:** ../specs/2026-10-14-relay-guided-verification-design.md

## Global Constraints

- 维持现有菜单编号和 CLI 参数；新增中转菜单第 3 项及 `--verify-relay`。
- nftables 先支持直接 INPUT/FORWARD 来源集合 DROP/REJECT。
- 测试原因唯一，建议决策有效期为 2 分钟；不执行修改命令。
- 通过依赖全部外部对照与本机证据，明确人工确认与本次入口范围。
- 远端模式不调用本地 cscli、不访问中心或输出密钥。

## Task 1: 引导验收状态机和防火墙证据

Files: `lib/crowdbastion_relay_verify.py`, `tests/test_relay_verification.py`.

- [x] 先编写验收行为测试：初始可达、封禁后测试失败／对照成功、适用集合与计数增加、集合退出和恢复；任何缺失结果保持未完成。
- [x] 用 `python3 -m unittest discover -s tests -p test_relay_verification.py` 观察新增入口缺失的失败。
- [x] 实现 `nft_evidence(ruleset, family, table, names, hook, source)` 和 `verify(root, remote=False)`；字段输入只接受单个 IP、1–65535 端口、固定协议／链和明确人工结果。
- [x] 补齐 IPv6、CAPI/cscli 后缀、错误命名空间、计数缺失／重置、已封禁来源、管理来源、共享来源、EOF/取消和远端只读测试；执行同一专项。

## Task 2: 菜单、推荐操作和安装反馈

Files: `lib/relay.sh`, `lib/health_summary.sh`, `lib/remote_bouncer.sh`, `crowdbastion.sh`, `tests/test_relay_verification.py`.

- [x] 先测试 CLI 只读边界、中转菜单第 3 项、成功安装后检查、不把检查异常改成安装失败、取消不自动启动验证。
- [x] 新增 `verify_relay` 与 `relay_after_install`；前者传入配置根及检测中心模式，后者运行只读检查并在 TTY 上由用户选择进入向导。
- [x] 接入 `--verify-relay`、中转子菜单与健康总结验证方法；本地 relay 安装及远端 install 成功分支调用检查。
- [x] 执行新专项、relay、health_summary、node_guidance、remote_bouncer、workflows 相关测试。

## Task 3: 文档与交付

Files: `readme.md`, `docs/relay-mode.md`, `docs/cli-reference.md`, `docs/usage-guide.md`, `docs/audit/2026-10-14-relay-guided-verification.md`, `docs/audit/README.md`.

- [x] 文档说明进入方式、测试设备、人工证据、支持范围和单一验收结论；记录测试命令与真实 VPS 验收边界。
- [x] 检查 Bash/Python 语法、ShellCheck、文档链接和 `git diff --check`。
- [x] 运行完整 unittest，一次独立代码审查后处理必要反馈。
- [x] 按已有授权合并 main、推送并核对远程 SHA。

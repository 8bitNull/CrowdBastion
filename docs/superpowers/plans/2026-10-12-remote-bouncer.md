# Remote Bouncer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 验证真实中心 LAPI 到中转 Bouncer，并加入可维护的 Bouncer-only 入口。
**Architecture:** 复用现有事务和隔离网络验收；远端认证配置采用独立小模块。
**Tech Stack:** Bash, Python/PyYAML, CrowdSec 1.8.1, Firewall Bouncer 0.0.36, QEMU.
**Spec:** docs/superpowers/specs/2026-10-12-remote-bouncer-design.md

## Global Constraints
- 不提交、不改宿主防火墙、不安装宿主包；保留全部已有工作。
- 真实与模拟验证明确分开；密钥不可泄露；操作失败须恢复原配置。

### Task 1: 真实远端验证
**Files:** Create `tests/verify_remote_bouncer.py`, `tests/test_remote_bouncer_lab.py`; reuse `tests/relay_network_lab.py`; archive `docs/audit/2026-10-12-remote-bouncer-results.json` and report.
**Interfaces:** JSON includes tested condition, observations, pass/fail, actual versions and scope; no credentials.
- [x] 先写隔离 guard、结果验收逻辑及失败清理测试，运行观察缺少实现导致失败。
- [x] 实现独立中心网络节点 LAPI、官方 cscli 和 Bouncer 的真实认证与决策流。
- [x] 测试 fresh session 封禁、正常客户端、实际 DROP 计数、解除、过期、中心断连恢复、错误凭据及重启；采集实际结果。
- [x] 在无 NIC QEMU 客机执行并归档，注明无法验证的条件，不编造成功。

### Task 2: 安装与维护入口
**Files:** Create `lib/crowdsec_remote_bouncer.py`, `lib/remote_bouncer.sh`, `tests/test_remote_bouncer.py`; modify `install-crowdsec-1panel.sh`, `docs/relay-mode.md`, `readme.md`.
**Interfaces:** CLI --install-relay-bouncer, --configure-relay-bouncer, --relay-bouncer-status, --remove-relay-bouncer; interactive inputs URL and secret, no secret CLI args.
- [x] 先写 URL/secret 校验、认证失败、事务回滚、.local 覆盖、托管卸载边界以及入口测试，观察预期失败。
- [x] 实现独立配置 helper 和复用包安装的安全事务；遵守 spec 中已有核心与服务保留边界。
- [x] 运行定向测试及 ShellCheck，补正文档中的输入、维护、故障语义、日志集中方式和限制。

### Task 3: 集成验收
- [x] 独立 reviewer 检查以上实现与实际验证报告，修复重要问题并复审。
- [x] 运行完整单元测试、ShellCheck、git diff --check；逐条报告实测与未验证范围。

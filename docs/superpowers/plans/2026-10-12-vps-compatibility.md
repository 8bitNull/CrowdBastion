# VPS Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 建立并执行有证据等级的VPS环境矩阵，发现并修复可复现兼容问题。
**Architecture:** OS真实systemd客机验收与隔离分支fixture并行，已有数据归档复用而非冒充新运行。
**Tech Stack:** Python/unittest, Bash, QEMU, official distro cloud images, CrowdSec/Bouncer.
**Spec:** docs/superpowers/specs/2026-10-12-vps-compatibility-design.md

## Global Constraints
- 不提交，不安装宿主包，不改宿主服务/防火墙，不发布宿主端口，不共享宿主目录。
- 只测试消息通道配置，禁止真实发送Telegram/邮件等消息。
- 镜像/包下载仅使用官方来源；测试密钥不输出。
- 实际环境与fixture分别报告；未运行不能通过。

### Task 1: amd64 Debian/Ubuntu真实systemd
**Files:** Create `tests/verify_vps_systemd.py`, relevant unit tests and `docs/audit/2026-10-12-vps-deb-results.json`.
**Interfaces:** Each result contains actual distro/arch/kernel/RAM, case, evidence, validation_level, status and failure cause; credential-free.
- [x] 用官方cloud image或可启动systemd rootfs创建独立快照客机，准备有界串口驱动，不改宿主。
- [x] 在Debian12/13、Ubuntu22.04/24.04执行远端Bouncer真实首次安装/自启/重复/修改/坏密钥/.local保护/移除/核心保留；实际核心relay安装单独记录。
- [x] 保存真实命令退出码与断言结果，失败进行定位和必要修复。新runner逻辑测试先失败再实现。

### Task 2: RPM及ARM实际环境
**Files:** Create independent lab runner(s), `docs/audit/2026-10-12-vps-rpm-arm-results.json`.
**Interfaces:** Same result fields as Task1; no conflicting edits to Task1 runner/production without coordination.
- [x] 检查官方镜像及可移植QEMU可用性，优先Alma9/Rocky9/CentOSStream/Fedora与Debian/Ubuntuarm64。
- [x] 真实systemd测试可启动环境的安装/重复/配置/移除，先执行remote模式，记录core软件源支持情况。
- [x] 未启动或不可获取系统明确未测试/RHEL需授权；不以mock代替OS实测。

### Task 3: 环境分支及配置状态回归矩阵
**Files:** Create `tests/verify_vps_matrix.py`, `tests/test_vps_matrix.py`, extend relevant tests only when gaps established; `docs/audit/2026-10-12-vps-fixture-results.json`.
**Interfaces:** deterministic matrix manifest + runner, explicit fixture level and separate actual archive imports.
- [x] 检查现有tests/test_workflows等，列出七发行版分支、nft/iptables、existing/fresh、overrides和readonly功能覆盖缺口。
- [x] 新增实质断言，先失败再实现；执行全部代表性fixture组合，核验已有配置/核心保留、失败回滚、密钥不泄漏。
- [x] JSON完整性及case验收逻辑回归，不把静态/模拟当作真实systemd。

### Task 4: 汇总与独立审查
- [x] 合并实际/模拟/既有实测证据，中文矩阵清楚列出未验证功能。
- [x] 真实iptables代表性封禁测试（隔离客机内），补全已有证据边界。
- [x] 独立review，相关及完整测试、ShellCheck和diff检查后交付；不宣称所有厂商与全功能已验收。

## Execution outcome

授权的有界真实客机尝试已执行并完成归档，不表示全部通过。9 个 OS/架构组合：远端模式 8 个通过、ARM64 失败；本地完整安装 4 个通过、3 个 DEB 系统失败，CentOS 原安装 OOM 未完成（后续安装案例通过但测试程序失败），ARM64 已有核心集成失败。RHEL 未授权镜像未测试。详细证据与未覆盖功能见 docs/audit/2026-10-12-vps-compatibility.md。最终回归结果写入同目录 ledger，不提交或部署。

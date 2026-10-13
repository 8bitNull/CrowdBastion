# VPS 下一阶段验证计划

此阶段建议已细化为 [试用前修复计划](2026-10-12-vps-repair-before-trial.md)，后续执行以新计划和配套设计为准。本文件保留作为先前规划记录。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. 本计划顺序执行，不主动分派子代理。

**Goal:** 补齐未完成的生命周期验收，并形成可重复的低配中转节点验证流程。

**Architecture:** 复用已有隔离客机和官方软件，先改进观察与结果判定，再补测缺失案例。默认条件与诊断对照分别归档；长期资源实验另列，避免用跨架构模拟速度推断真实 VPS 性能。

**Tech Stack:** Python unittest、QEMU、cloud-init、systemd、CrowdSec、nftables、gost/realm。

**Spec:** `docs/audit/2026-10-12-arm64-followup.md`、`docs/audit/2026-10-12-vps-compatibility.md`、`docs/audit/2026-10-12-low-spec-simulation.md`。

## Global Constraints

- 保留当前工作区变更及所有历史失败证据，不自动提交、部署或覆盖旧实验。
- 软件包、服务和防火墙操作仅在独立客机执行；不修改宿主服务或防火墙。
- 使用官方校验镜像、独立磁盘和不可变 seed；仅出站 NAT，不共享宿主目录。
- 不发送真实 Telegram 或邮件，不操作未授权的真实 VPS。
- 每个案例单列执行、断言、健康状态；主动停止、缺失标记及未知退出不能通过。
- 不因 TCG 仿真启动超时直接修改生产默认超时。
- 真实 ARM64 节点及真实性能实验需要可用、明确授权的测试环境；缺少时保留未验证，继续其他独立工作。

---

### Task 1：固化可靠的验收程序（优先）

**Files:**
- Review/Modify: `tests/verify_vps_rpm_arm.py`
- Review/Modify: `tests/vps_rpm_arm_phase2.py`
- Test: `tests/test_vps_rpm_arm.py`
- Reference: `docs/audit/arm64-followup-evidence/`

**Interfaces:** 保持现有 guest 环境、案例与结果字段兼容；新增健康证据必须与原始案例断言分开。结果读取器需拒绝重复案例/健康事件、冲突字段、非整数退出码、人工停止及缺少完成标记。

- [ ] 从归档的故障注入和判定程序提取已验证的边界，先在现有 unittest 中复现旧判定缺陷。
- [ ] 将 nft 读取退出码检查、有界就绪采样、明确的进程终止判定及健康事件判定整合到对应现有程序；不顺带改变生产安装行为。
- [ ] 将密钥脱敏改为每阶段一次采集、复用；控制串口输出大小，停止周期性大栈输出，详细日志在客机落盘，串口只输出有限摘要和明确进度。
- [ ] 增加每阶段独立时间预算与结束记录，区分服务失败、诊断失败和整机超时。
- [ ] 执行相关单元测试；用缺少完成标记、重复健康事件及 nft 读取失败的客机/fixture 输入确认不能误判。

```bash
python3 -m unittest discover -s tests -p test_vps_rpm_arm.py -v
```

**验收:** 同一失败证据不会因瞬时 active 或 QEMU 退出 0 被接受；健康及阶段结果有独立证据，诊断过程不会无限等待。

### Task 2：补齐 ARM64 与 CentOS 的缺失生命周期

**Files:**
- Review/Modify: `tests/vps_rpm_arm_guest_arm.py`
- Review/Modify: `tests/vps_rpm_arm_phase2.py`
- Review/Modify: `tests/prepare_vps_rpm_arm.py`
- Create: 新时间戳的 `docs/audit/` 结果与证据目录
- Update: `docs/audit/2026-10-12-vps-compatibility.md`

**Interfaces:** 使用 Task 1 的验收程序；每次 seed 与客机必须记录准确 source/hash、实际架构、PID 1、内存、案例及 QEMU 终止状态。

- [ ] 在 ARM64 独立客机补测移除、已有核心配置保留、两种迁移保护、本地中转核心集成、重启与重启后决策同步。
- [ ] 单独验证 ARM64 从空白客机执行本地核心安装，避免将已有 LAPI 集成标为首次安装。
- [ ] 默认配置与客机诊断超时对照分别记录；默认启动失败仍为失败，不用对照补算通过。
- [ ] 为 CentOS Stream 9 使用新磁盘完成安装、重复安装、重启、决策添加/删除及最终清理，补齐旧轮次的清理异常与完成标记缺失。
- [ ] 若已有明确授权的原生 ARM64 测试环境，在该环境复测默认启动和实际决策同步，确认是否仅仿真环境超时；没有环境时明确标记原生硬件未验证。
- [ ] 更新兼容性矩阵，逐案例列出通过、失败、未执行及环境限制。

**验收:** 所有已执行轮次均有终止状态；缺失项已实际补测或明确未验证。只在真实证据满足全部谓词时将某个范围改为通过。

### Task 3：低配纯中转节点的稳定性与恢复能力

**Files:**
- Review/Reuse: `tests/benchmark_relay.py`
- Review/Reuse: `tests/relay_network_lab.py`
- Review/Reuse: `tests/verify_remote_bouncer.py`
- Update: `docs/relay-benchmark.md`
- Create: 新时间戳的长期实验结果与报告

**Interfaces:** 使用已验证的中转与决策同步流程；资源容量数据仅来自原生执行或可明确解释的同架构虚拟化环境。TCG 数据仅列功能观察。

- [ ] 先对远程 Bouncer 模式做 1 小时试运行，通过后再扩展至 24 小时；按资源可用情况顺序测试 256 MiB 与 512 MiB。
- [ ] 保持 gost/realm 转发负载一致，分别记录未启用防御及启用防御时的 CPU、RSS、连接成功率、吞吐、延迟和决策同步时间。
- [ ] 使用固定负载安排正常流量与短时突发，不向公网第三方发送攻击流量。
- [ ] 在隔离环境测试中心 LAPI 暂时不可达、网络恢复、服务重启与规则重复加载；记录现有封禁规则是否保留、恢复后是否继续同步。
- [ ] 将核心共存的 512 MiB/1 GiB 实验另列，避免把纯 Bouncer 的资源结论套用于本地核心。
- [ ] 根据实测结果给出最低可运行条件及保留余量建议；没有实际性能环境时，不给出吞吐承诺。

**验收:** 有明确负载、时长、基线及失败统计；恢复测试有决策和防火墙证据；短测、长期稳定性及仿真结果分别说明。

### Task 4：最终回归与交付

- [ ] 所有客机结束后执行全仓回归，避免仿真负载干扰时间敏感测试。
- [ ] 校验 seed/source/evidence 的映射，确认归档无凭据或完整私密配置。
- [ ] 更新 README 与验证文档，报告尚未覆盖的真实线路、厂商及运行环境。

```bash
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH="$PWD/.venv/lib/python3.11/site-packages" python3 -m unittest discover -s tests -q
/tmp/crowdsec-qa-python/bin/shellcheck -x -e SC2317,SC2329,SC2120,SC2119 install-crowdsec-1panel.sh lib/*.sh
bash -n install-crowdsec-1panel.sh lib/*.sh
git diff --check
```

**执行顺序:** Task 1 → Task 2 → Task 3 → Task 4。先完成可靠验收和已有缺口，再投入长时间测试。

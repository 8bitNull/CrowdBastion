# 一键脚本试用前修复计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking。按任务顺序执行；不要自动提交、部署或主动分派子代理。

**Goal:** 关闭已知启动问题与验收缺口，并用完整生命周期、24 小时运行和断线恢复证据决定哪些 VPS 组合可以试用。

**Architecture:** 先把临时验证中已证明必要的判定与诊断修正整合到现有客机测试，再定位真实产品问题并做最小修复。测试按范围分开，历史失败不覆盖，默认设置与诊断对照不混计。

**Tech Stack:** Python unittest、Bash、cloud-init、QEMU/systemd、CrowdSec、官方 Firewall Bouncer、nftables、gost/realm。

**Spec:** `docs/superpowers/specs/2026-10-12-vps-repair-acceptance-design.md`。

## 全局约束

- 本计划已获用户确认并开始执行；进度与未完成项见 `docs/audit/2026-10-12-vps-repair-progress.md`。保留未勾选项，不能因观察器已实现便算客机或长测通过。
- 保留当前工作区变更与所有历史失败，不自动提交或部署。
- 软件包、服务与防火墙操作仅在独立客机；不改变宿主服务/防火墙，不开放入站映射或共享宿主目录。
- 使用官方校验镜像、独立磁盘、不可变 seed；归档记录安装脚本、辅助文件、seed 与证据校验值。
- 不因 TCG 仿真结果直接改生产默认超时；没有明确授权的原生测试环境时不操作真实 VPS。
- 判定按系统/架构/内存/模式；未测、人工停止、超时与产品失败分别记录，不计通过。
- 生产修复先有失败复现或回归测试，再做最小修改；不增加无关功能或重构。

---

## 任务 1：修复验收误判与诊断停滞风险（P0）

**Files:**
- Modify: `tests/verify_vps_rpm_arm.py`
- Modify: `tests/test_vps_rpm_arm.py`
- Modify: `tests/vps_rpm_arm_guest_arm.py`、`tests/vps_rpm_arm_guest.py`、`tests/vps_rpm_arm_phase2.py`
- Modify: `tests/prepare_vps_rpm_arm.py`
- Create: `tests/vps_guest_runtime.py`、`tests/test_vps_guest_runtime.py`
- Reference: `docs/audit/arm64-followup-evidence/` 中归档的检查程序与正反例

**Interfaces:**
- 保持 `parse_serial(serial, distro)` 的读取入口；增加可选关键字 `scope`，默认完整生命周期，合法范围为 `full_lifecycle`、`remote_only`、`fresh_native_core_only`、`existing_core_integration`，由 seed 清单选择。
- 扩展 `final_status(status, timed_out, returncode, *, stopped_by_agent=False)`；只接受整数 0、明确未超时且未主动停止。
- 客机公共模块提供 `run_bounded(argv, *, timeout, input_text=None)`，返回退出码、捕获输出及耗时；超时为 124，同时终止并回收该命令及其子进程。
- 健康事件与原始案例断言分离；共享 `service_healthy(properties)`，只接受唯一属性中的 active/running/success。

- [x] **先写并运行失败测试。** 以下测试加入现有 `GuestEvidenceTests`，验证布尔退出码及 note 内嵌环境不能通过：

```python
def test_boolean_qemu_exit_is_not_success(self):
    self.assertEqual(self.load().final_status('passed', False, False), 'failed')

def test_environment_embedded_in_note_is_not_identity(self):
    serial = 'VPS_NOTE expected VPS_ENV {"pid1":"systemd","architecture":"aarch64"}\n'
    result = self.load().parse_serial(serial, 'debian13-arm64')
    self.assertNotIn('pid1', result)
```

```bash
python3 -m unittest discover -s tests -p test_vps_rpm_arm.py -v
```

- [x] **加入行为边界测试。** 将归档 `check_harness.py` 的 nft 无权限故障输入和 `recovery-check_archive.py` 的六个输入整合到 unittest；覆盖 nft 读取非 0、重复/冲突健康属性、主动停止、重复案例、缺失完成标记、假阳性瞬时 active，以及不同 scope 的必需案例。
- [x] **修正解析与整机判定。** 只接受已知完整串口/journal 前缀；精确校验字段、类型、来源 hash 和案例唯一性。保留旧 JSON；旧证据缺少新健康数据时只读取原始观察，不赋予新健康保证。
- [x] **修正客机判断。** nft 读取必须退出 0；就绪轮询使用 monotonic 截止时间与单次 5 秒查询，保存截止内结果；重启后添加并删除实际决策，验证 API 可用和规则同步，避免用 active 代替健康。
- [x] **实现有界公共运行与脱敏。** 用临时子进程测试超时后没有遗留子进程；每阶段一次提取敏感值后复用，串口单事件不超过 4 KiB，诊断阶段不超过 60 秒，详细日志客机落盘。移除周期性大栈输出；未知诊断停滞不标为已确认死锁。
- [x] **将公共模块加入 seed。** 首阶段通过 systemd journal+console 输出有限事件；打包公共模块及阶段文件并记录校验值。
- [x] **跑相关测试与一次短客机试验。** 正常路径完整结束；主动停止或诊断超时仍产生明确失败状态，不能报完整成功。

```bash
python3 -m unittest discover -s tests -p test_vps_guest_runtime.py -v
python3 -m unittest discover -s tests -p test_vps_rpm_arm.py -v
```

**验收:** 误判反例全部拒绝；健康失败不能被瞬时 active 覆盖；诊断和命令均有真正可执行的上限。该任务只修改测试设施，不修改生产防御策略。

## 任务 2：关闭 ARM64 默认启动问题（P1）

**Files:**
- Reuse/Modify: `tests/vps_rpm_arm_guest_arm.py`、`tests/vps_rpm_arm_phase2.py`、`tests/prepare_vps_rpm_arm.py`
- Conditional Modify: `install-crowdsec-1panel.sh` 中经证据确认有问题的启动路径及对应 `lib/` 文件
- Conditional Test: `tests/test_workflows.py` 或对应生产辅助模块的现有测试文件
- Create: 新时间戳 ARM64 默认启动/对照报告与结果

**Interfaces:** 使用任务 1 的运行器与 scope；每个诊断修改显式列入清单，不能静默进入生产源码或默认验收。

- [ ] **基线复现。** 新 ARM64 客机不带诊断超时 drop-in；记录核心 unit、ExecStartPre、TimeoutStartUSec、带时间启动日志、实际资源及原始命令退出。首次启动和重启分别计数。
- [ ] **拆分原因。** 对比默认冷启动、同一检查单独执行与诊断超时对照；不因延长等待后成功就宣布根因是 CPU 竞争。
- [ ] **在明确授权的原生 ARM64 环境复核。** 默认冷启动、三次重启，每次检查核心、Bouncer、实际添加/删除同步。没有此环境时明确保留阻断，先继续任务 3 的其他系统工作。
- [ ] **根据证据选择处理。** 仅 TCG 失败、原生默认通过：记录模拟限制，不改生产超时。原生亦失败：依据实际原因写失败回归，再最小修复配置、启动顺序、资源问题或超时策略；不得删除有效检查或吞掉 systemd 错误。
- [ ] **验证修复及已有配置保护。** 在原失败环境重跑，验证重复安装不破坏已有 unit/drop-in/凭据；实际配置错误仍应明确失败。对照和默认验收结果分别归档。

**验收:** 拟支持的 ARM64 默认配置通过冷启动、三次重启及同步。原生环境缺失或仍失败时，ARM64 资格未关闭、不进入试用清单；不把它写成已修复。

## 任务 3：补齐生命周期验收（P1）

**Files:**
- Modify: `tests/prepare_vps_rpm_arm.py`、`tests/vps_rpm_arm_guest_arm.py`、`tests/vps_rpm_arm_guest_core.py`、`tests/vps_rpm_arm_phase2.py`
- Modify/Test: `tests/verify_vps_rpm_arm.py`、`tests/test_vps_rpm_arm.py`
- Update: `docs/audit/2026-10-12-vps-compatibility.md`

**Interfaces:** 三种实验独立 scope：纯远程生命周期、空白系统本地核心首次安装、已有核心集成；不得把已有 LAPI 的安装实验标为首次核心安装。

- [ ] **建立实验清单。** ARM64 各 scope 使用独立磁盘；核心首次安装不先手动安装 CrowdSec。修正 `--core-only` 当前仅限 RPM 的准备路径，使原生 ARM64 首次安装可独立执行。
- [ ] **远程生命周期。** 首次/重复安装、URL/密钥变更、错误密钥/归属保护、三次重启后的同步、移除及核心配置保留。
- [ ] **迁移保护。** 移除远程模式后保留独立 unit；直接请求本地中转核心或网站核心安装必须在变更前拒绝，配置 hash 不变。只在实验内明确清理本轮残留后才继续本地集成。
- [ ] **本地核心生命周期。** 官方包首次安装、重复安装及配置保留、三次重启、自启、决策添加/删除。ARM64 的默认与诊断配置分别计数。
- [ ] **CentOS Stream 9 复测。** 保留原 1 GiB 尝试的实际可用内存条件和 OOM 历史，新轮次完成安装、重复安装、重启、决策同步及清理。若资源不足，单列新增较大内存组合，不能把它算作原组合通过。
- [ ] **受影响系统复测。** 修改共享安装路径时复测已有 Debian/Ubuntu/RPM 成功组合；仅测试设施变化时，用代表性 amd64 客机验证新观察器，并复算新轮次，旧 JSON 不覆盖。
- [ ] **归档。** 每轮均有明确终止与完成标记；案例级别的成功与整轮未完成分开，公布更新后的支持矩阵。

**验收:** 拟试用组合无缺失必需案例；无安装成功但重启/卸载未测的“完整通过”。

## 任务 4：建立长期稳定性与恢复测试（P2）

**Files:**
- Create: `tests/relay_soak_guest.py`、`tests/test_relay_soak.py`
- Reuse: `tests/benchmark_relay.py`、`tests/verify_remote_bouncer.py`、`tests/relay_network_lab.py`
- Update: `docs/relay-benchmark.md`、`docs/remote-bouncer-operations.md`
- Create: 新时间戳的稳定性与恢复结果

**Interfaces:** 新 soak 入口仅在独立客机执行，由外部运行器/manifest 提供不可变的模式、资源、总时长及案例清单；输出分钟采样、单独恢复案例、最终完成事件与进程退出。它组织已有转发和真实 LAPI 逻辑，不在宿主运行有权限变更的网络实验。

- [ ] **先固定实验和失败条件。** 采用设计文件的资源组合、固定负载、每分钟采样、每小时添加/删除及每六小时短突发。分别保存未启用防御和启用防御基线。
- [x] **测试时长与判定。** 使用可控时钟及确定输入写 unittest：遗漏采样/完成标记、隐藏服务重启、OOM、连接成功率低于 99.9%、同步超过 60 秒、恢复超过 120 秒均不能通过；提前退出不得标为 24 小时成功。
- [ ] **实现 soak 编排。** 正常与故障注入窗口分别计数；命令有上限，子进程会回收；采样实际 MemTotal/MemAvailable、RSS、CPU、服务 NRestarts、连接结果和规则数量。轻负载与突发参数写入结果，串口输出大小受控。
- [ ] **复用短基线。** 当前 benchmark 将单次 duration 限制为最多 60 秒；长期运行使用新编排器，不把 `--duration 86400` 传给现有程序，也不为长测任意放宽其输入限制。
- [ ] **执行 1 小时试跑。** 纯远程模式分别测试 256/512 MiB，本地核心分别测试 512 MiB/1 GiB；失败组合先定位，不直接开始长测。
- [ ] **执行连续 24 小时。** 对每个拟发布支持且短测通过的组合分别运行完整 24 小时，记录峰值与最后六小时内存走势。全部环境不必同时运行，避免 CPU 竞争污染结果。
- [ ] **独立恢复测试。** 中心中断 60 秒；核对未过期规则保留、到期行为、合法流量、重连后的添加/删除同步；分别重启 Bouncer 和中心，验证规则没有非预期重复。
- [ ] **遇到生产失败先复现再修复。** 仅修改实际出错的模块，增加回归测试，然后重复失败恢复案例和该组合的 1 小时/24 小时验收；失败计时不能拼接成连续通过。

```bash
python3 -m unittest discover -s tests -p test_relay_soak.py -v
python3 -m unittest discover -s tests -p 'test_remote_bouncer*.py' -v
```

**验收:** 无 OOM、非计划服务退出/重启、持续故障；正常连接成功率至少 99.9%，同步各不超过 60 秒，恢复不超过 120 秒；内存走势符合设计门槛。仿真只能证明功能，不提供真实 VPS 吞吐保证。

## 任务 5：试用资格审查与交付（P3）

**Files:**
- Update: `readme.md`、`docs/verification.md`、`docs/relay-mode.md`、`docs/remote-bouncer-operations.md`
- Create: 时间戳化的试用资格清单与未关闭问题表

**Interfaces:** 每行包含系统、架构、实际内存、模式、源码版本、生命周期、稳定性、恢复、未关闭问题与对应证据。

- [ ] **核对资格。** 只有任务 2—4 对该组合所需的默认条件全部通过，才标可试用。原生 ARM64 缺少、稳定性未满时长或任何阻断未关闭，均不放行该组合。
- [ ] **完成源码回归。** 待所有客机结束后执行下方检查；新失败先定位，不能为通过而放宽断言。
- [ ] **检查证据和脱敏。** 验证 source/seed/log hash 映射，拒绝未知退出、重复结果、凭据或完整私密配置归档。
- [ ] **交付支持范围。** 发布准确的试用组合、失败/未验证组合和操作边界；不声明所有 VPS、所有功能、所有中国线路均通过。实际试用部署是后续动作，不在本次计划制定中执行。

```bash
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH="$PWD/.venv/lib/python3.11/site-packages" python3 -m unittest discover -s tests -q
/tmp/crowdsec-qa-python/bin/shellcheck -x -e SC2317,SC2329,SC2120,SC2119 install-crowdsec-1panel.sh lib/*.sh
bash -n install-crowdsec-1panel.sh lib/*.sh
git diff --check
```

## 执行顺序与停止条件

顺序：任务 1 → 任务 2/3 → 任务 4 → 任务 5。先启动任务 1；原生 ARM64 环境不可用时保留任务 2 阻断，继续不依赖它的 amd64/CentOS 验证和低配实验。

不能承诺在固定几天内全部结束：每个支持组合的连续长测至少需要 24 小时，修复后的失败组合必须重新计时。每完成一项报告改动、证据、剩余问题；试用资格未满足之前不安排实际节点部署。

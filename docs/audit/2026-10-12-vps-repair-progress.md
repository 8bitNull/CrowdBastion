# 试用前修复执行记录（2026-10-12）

状态：进行中，尚未满足试用资格。用户已确认执行 [修复计划](../superpowers/plans/2026-10-12-vps-repair-before-trial.md)，无需再次确认同一范围。

本轮生产安装脚本 SHA256 仍为 `222b807f5b5012476f6eec7919f5d8fd06ad6b138befd21e6dfb5cf263d9eaf5`。目前修复测试设施，没有因 TCG 失败改生产默认超时。原工作区脏变更和历史失败保留；实现先在隔离 worktree `/tmp/crowdsec-vps-repair-worktree`，交付时按基线 hash 检查冲突后回写。

> 当前状态以文末“最新验证与负载观察器修复”为准；中间各时刻的“正在执行”是历史进度，不表示当前仍在运行。

## 已实施

- 退出严格区分：整数 0、正常预期拒绝 1—123、超时 124、信号、布尔/缺失值不能混计。断言集合、案例唯一性、系统/版本/架构、完成标记和来源校验严格匹配。
- 四种 scope 分开；完整生命周期必须包括只读检查和两种迁移保护。远程与本地核心分别记录三次独立重启、截止内就绪和实际决策添加/删除；最终独立健康查询只能增加失败，不能补救截止失败。
- nft 无权限不能算已删除；服务查询超时不能算已停用。公共运行器采用真实命令上限，处理进程组和另建会话的子进程；记录 /proc starttime，避免误杀复用 PID。
- 每阶段刷新短凭据集合；缺 YAML 依赖时隐藏原始摘要。递归 YAML 有访问去重；摘要先折叠换行再按字节截断，单事件低于 4 KiB。
- 新 seed 拒绝覆盖；启动前核对 seed/payload/辅助源码 hash、架构与 scope。新清单还记录库源码映射；人工停止、格式错误及 QEMU 原始退出有失败报告。
- 支持真正空白系统的 ARM64/core-only；首次核心安装不会预装 LAPI。长期观察器与宿主重算已实现，本地核心 seed 可带 120/3600/86400 秒实验，详见 [方法](../relay-benchmark.md)。

## 客机轮次

各轮使用官方镜像、独立 qcow2 overlay、只读不可变 seed，无主机目录共享/入站转发。每台 1 vCPU；TCG 数字只证明该实验功能。CentOS 官方镜像本身为 10 GiB，不做破坏性缩小；Debian 独立 overlay 扩到 8 GiB。

| 轮次目录 | 系统 / 请求内存 | 范围 | 状态 |
| --- | --- | --- | --- |
| `/tmp/crowdsec-vps-repair-pilot-20261012` | Debian 12 / 1 GiB | 空白核心 | seed 光驱未识别，无测试案例；主动停止，失败记录保留 |
| 同上 | CentOS Stream 9 / 1 GiB、实际 781252 KiB | 空白核心 | 已结束：首次/重复安装、配置保留、三次重启及各次同步均通过，6 案例、QEMU 0、2124.709 秒；此 v1 seed 最终健康使用较早缓存，不能补授最新最终采样保证 |
| `/tmp/crowdsec-vps-repair-pilot-v2-20261012` | Debian 12 / 1 GiB、实际 995588 KiB | 空白核心 | 已完整结束：首次/重复安装、配置保留、三次重启及每次决策增删同步通过；7 案例，QEMU 退出 0，1003.853 秒。仅空白核心 scope，不含远程/恢复/长测 |
| `/tmp/crowdsec-vps-repair-soak-smoke-20261012` | Debian 12 / 1 GiB | 空白核心 + 120 秒烟雾 | 已结束，QEMU 0 / 1118.887 秒；核心三重启通过，120 秒负载失败。此旧 seed 缺 gost UDP keepAlive 与最新最终采样；另有宿主/客机观察器版本差异，不能归为生产失稳 |

每一轮的源码/seed hash 独立记录，后续代码修改不能追溯成为先前客机实测。进程结束后归档结果和串口校验值。已归档 [Debian 12 空白核心结果](vps-repair-evidence/debian12-cold-core-v2.json) 与 [seed 光驱主动停止记录](vps-repair-evidence/debian12-seed-cdrom-stopped.json)。旧版 [烟雾失败结果](vps-repair-evidence/debian12-soak-observer-v1-failed.json) 单独保留；其中最终 OOM/健康测量缺失不表示真实发生 OOM/重启。CentOS [v1 原始结果](vps-repair-evidence/centos9-cold-core-v1.json) 已归档，严格新健康观察器另起独立 v2 轮次。新增 `/tmp/crowdsec-vps-repair-soak-512-v2-20261012` 为最终调度器的 Debian 12 / 512 MiB / 120 秒烟雾，已因实际安装 OOM 主动停止，详见下文。

## 尚未关闭

| 事项 | 当前限制 / 下一项必要证据 |
| --- | --- |
| ARM64 默认启动 | 已有默认 90 秒超时失败及 300 秒诊断对照；缺明确授权的原生 ARM64 环境，保持阻断 |
| 完整生命周期 | 新本地核心轮次尚在运行；新的远程三重启、移除及已有核心集成未实测 |
| 低资源长期稳定性 | 未完成远程 256/512 MiB、本地 512 MiB/1 GiB 的 1 小时及独立连续 24 小时 |
| 独立恢复 | 中心中断 60 秒、过期/保留、正常流量、恢复同步及双方重启仍需真实独立中心实验；观察器不自动把空恢复列表判通过 |
| 无防御对照 | 当前 seed 只集成本地核心实验；未完成同负载的独立长基线 |
| 最终回归/资格审查 | 待本轮客机结束，再做完整回归、ShellCheck、语法、证据脱敏检查；当前没有新放行组合 |

不能据本轮测试设施修复宣称“一键脚本只剩细节”或“全部 VPS 已通过”。


## 当前检查与持续执行

最近相关检查：69 项 `test_vps*.py`、11 项 `test_relay_soak.py` 通过；官方 gost 的短基准回归 10 项通过，ShellCheck（既有排除项）、Bash 语法通过。完整源码回归尚未执行，待客机结束再进行；这些数量不是各 VPS 的生命周期数量。独立只读审查已确认命令退出、系统身份、移除查询、秘密收集、最终健康、迁移保护必需项、慢内存下降、分钟负载停顿、setsid 子进程及最终采样误判已修正。

512 MiB 本地模式已设置有界顺序控制器 `/tmp/crowdsec-vps-repair-soak-queue.py`，状态在 `/tmp/crowdsec-vps-repair-soak-queue.json`。先等待烟雾和当前其他客机结束，再将烟雾串口用最新严格观察器重算，保留原 JSON 和单列 `debian12-revalidated.json`；这是验收设施迭代时的明确重算，不修改客机观察。仅当完整生命周期、烟雾、真实 QEMU 退出全部通过时启动独立 1 小时轮次；其通过后才能启动独立 24 小时轮次。任何失败都会停止自动推进。每个长测重新安装、三次重启，失败计时不能拼接成连续成功。

后续目录：`/tmp/crowdsec-vps-repair-soak-512-hour-20261012`、`/tmp/crowdsec-vps-repair-soak-512-day-20261012`。二者目前只有已准备的独立磁盘/不可变 seed，排队不算运行，更不算通过。控制器即使长测成功也明确 `trial_qualified=false`，因为独立恢复、无防御长基线与其他组合仍未完成。停止控制器会同时停止它拥有的活动客机；不操作其他历史实验。

CentOS 最新独立复测目录为 `/tmp/crowdsec-vps-repair-centos-v2-20261012`，1 GiB 请求内存、最新原始核心 scope；尚在执行。


## 512 MiB 安装 OOM：实际阻断

Debian 12 / 512 MiB 请求内存（实际 MemTotal 480260 KiB）在首次核心安装阶段触发两次实际 OOM：客机 uptime 536.868 秒与 554.327 秒，python3 PID 2036 / 2037 被内核杀死，anon RSS 分别 311412 / 322296 KiB。生产安装未返回 `core_relay_install` 案例，不能计为成功；尚未唯一确认受害进程命令，不能先归因到 Hub 快照。

该轮已主动停止并保留 [结果](vps-repair-evidence/debian12-512m-install-oom.json) 与 [原始串口](vps-repair-evidence/debian12-512m-install-oom.serial.log)。长测控制器进入 blocked，未启动 1 小时/24 小时。旧烟雾轮次只是采样缺失，此轮有内核 OOM 证据，两者不可混淆。

独立诊断客机 `/tmp/crowdsec-vps-oom-diagnostic-20261012` 使用同一生产源码、1 vCPU / 512 MiB，额外记录 Python 脚本白名单身份及 RSS；不记录完整参数、配置或秘密。它属于诊断 scope，不自动授予默认验收资格。

范围入口已补齐 remote-only 与 integration-only，后者必须具有原生仓库、原生包安装和配置保留证据；两项缺失被误判通过的反例已红→绿复现，72 项 VPS 单元测试通过。新增范围尚待实际客机验证。


## 最终快照修复与继续验证（15:59 UTC）

诊断轮次确认 PID 1987 为 `crowdsec_maintenance.py`，RSS 升至 246652 KiB，随后在 uptime 485.954 秒被内核 OOM 杀死。完整快照 fixture 在旧 `before` 的 Base64 编码处复现 MemoryError。新建快照改为 format 3 私有分块内容文件；旧格式恢复兼容。恢复前校验所有内容，FIFO/符号链接/损坏/缺失/宽权限目录均明确拒绝，读取坏快照不创建目录。

独立审查已关闭 FIFO 打开阻塞和读取 mkdir 副作用；10 项内存/完整性、30 项维护、23 项 Hub 维护通过。最终源码回归 **577 项通过、无跳过**；语法、ShellCheck、编译、diff 检查通过。完整 61+11 MiB fixture 峰值 RSS 19424 KiB，资源限制 160 MiB；元数据内存随文件数增长，不宣称总内存恒定。

CentOS v2 严格观察器原源码复测已通过：6 案例、三次重启、QEMU 0 / 1906.215 秒 / 实际 781240 KiB，归档 `centos9-cold-core-v2.*`。此证据不是新内容存储版本的复测。新 CentOS 目录 `/tmp/crowdsec-vps-repair-centos-blob-v3-20261012` 正在执行。

最终相同源码 512 MiB 目录 `/tmp/crowdsec-vps-repair-512-blob-v4-20261012` 正在执行。先前 blob v3 因后续 FIFO/读取修复需保持源码一致而主动停止，归档为失败/停止，不赋予通过资格。失败注入客机已观察到退出码 42 触发 `VPS_HARNESS_FAILED` 后正常关机、QEMU 0 / 无超时，失败报告保留。

新顺序控制器 `/tmp/crowdsec-vps-blob-v4-queue.py`，状态 `/tmp/crowdsec-vps-blob-v4-queue.json`；固定源码副本 `/tmp/crowdsec-vps-blob-v4-pinned-repo`。短测结果、源码/hash、观察器、最终回归全部匹配才继续独立 hour/day 客机；任何失败停止，终止时回收所属进程。旧控制器已 blocked，不再使用旧长测 seed。新长测目录 `crowdsec-vps-repair-512-blob-v4-hour-20261012` / `...-day-20261012` 目前只有准备好的种子，未运行也未通过。

恢复、无防御对照、独立远程 256/512 MiB、本地 1 GiB 和原生 ARM64仍未关闭；当前无新增试用资格。详细修复、源码校验值及历史区分见 [专门记录](2026-10-12-hub-blob-memory-repair.md)。


## 最终宿主观察器补充（16:10 UTC）

安装/前一重启发生的裸内核 OOM 即使后续服务恢复，也强制整轮失败；只检查原始内核发送者行，`VPS_NOTE` 和 Python 日志引用示例不会误报。反例红→绿、独立只读复核通过。最终源码 **578 项通过、无跳过**，173.180 秒；[新版回归记录](vps-repair-evidence/blob-final-regression-v2.json) 保留旧 577 项报告，未覆盖历史。

当前控制器改为 `/tmp/crowdsec-vps-blob-v6-queue.py`、状态 `/tmp/crowdsec-vps-blob-v6-queue.json`、冻结观察器 `/tmp/crowdsec-vps-blob-v6-pinned-repo`。v4/v5 在尚未启动长测时停止，避免引用旧宿主观察器；生产 lib 和客机 seed/hash 没有因此变化。客机原 JSON 保留，使用独立 pinned-v6-revalidated JSON 重算；最终短测、hour、day 及 CentOS seed 的生产源码 hashes 全部一致。

默认 512 MiB 已观察到首次安装、重复安装/配置保留及前两次重启的实际增删同步通过。第三次重启和 120 秒负载仍在执行；尚未授予整轮通过。


## 最新验证与负载观察器修复（16:30 UTC）

源码回归 **581 项全部通过、无跳过**，166.925 秒；ShellCheck、Bash 语法、Python 编译及 diff-check 通过。[新回归记录](vps-repair-evidence/blob-final-regression-v3.json) 保留先前 577/578 项报告。

新快照生产版本的 CentOS Stream 9 / 请求 1 GiB（实际 781240 KiB）已完成首次安装、重复安装/配置保留、三次独立重启及每次实际决策增删。6 案例、QEMU 0、1853.309 秒；原始结果和最新宿主观察器独立重算均通过，没有观察到内核 OOM。[原始结果](vps-repair-evidence/centos9-blob-v3.json)、[重算结果](vps-repair-evidence/centos9-blob-v3-observer-v5-revalidated.json)。仅证明空白本地核心 scope，不含远程、恢复、卸载和长测。

Debian 12 / 512 MiB 的 blob-v4 轮次已结束，**整体失败**：首次/重复安装、配置保留、三次重启和实际增删同步通过；没有观察到 OOM，但 120 秒负载四条路径各有 7 次错误，成功率不足 99.9%，另有分钟负载间隔失败。QEMU 0、1129.712 秒。[原始失败结果](vps-repair-evidence/debian12-512m-blob-v4-soak-failed.json)、[独立 pinned-v6 重算](vps-repair-evidence/debian12-512m-blob-v4-pinned-v6-revalidated.json) 均保留，不能将安装部分成功扩展为整轮通过。

负载设施定位到固定等候 2 秒没有确认转发器就绪，以及外部查询前的时间戳与查询后的计数不一致。现增加四路径实际 TCP/UDP 回显就绪检查（总上限 30 秒，独立 setup 事件），在开始负载前采集零计数基线；运行中时间戳和计数在同一个锁内获取。setup 缺失、重复、未就绪或超时均失败。实测错误不清零，成功率/分钟连续性门槛不放宽。14 项 soak 与 74 项 VPS 测试通过，并完成只读复核。

新独立客机 `/tmp/crowdsec-vps-repair-512-soak-v5-20261012` 使用新观察器与同一生产修复，目前执行 120 秒短测。控制器 `/tmp/crowdsec-vps-blob-v7-queue.py` 使用冻结 `/tmp/crowdsec-vps-blob-v7-pinned-repo`，状态 `/tmp/crowdsec-vps-blob-v7-queue.json`；只有同源码/观察器回归、seed 校验、整轮短测和真实 QEMU 退出全部通过才启动独立 1 小时，然后启动独立 24 小时。旧 v6 已因负载失败 blocked，未启动长测。新 hour/day 目录目前准备完毕，排队不算运行或通过。

仍缺独立远程 256/512 MiB、本地 1 GiB 长测、无防御对照、中心中断与双方重启恢复、转发器 RSS 监测及原生 ARM64证据。长测成功也不能自动关闭这些项目；当前 `trial_qualified=false`。


已有核心集成已启动独立 Debian 12 / 1 GiB 客机 `/tmp/crowdsec-vps-repair-debian-existing-v1-20261012`，使用冻结 v7 的生产源码及验收器。先由官方原生仓库安装 CrowdSec，保存原始配置与 sentinel，再执行脚本集成、重复安装及三次重启同步。此范围 `existing_core_integration` 与空白首次安装分开，尚未结束，不计通过。


## 最新短测通过，独立 1 小时已启动（16:44 UTC）

`/tmp/crowdsec-vps-repair-512-soak-v5-20261012` 已正常结束并整轮通过：Debian 12 / 1 vCPU / 请求 512 MiB，实际 MemTotal 480260 KiB；首次/重复安装、配置保留、三次重启及每次实际增删同步、最终健康、120 秒负载全部通过。QEMU 0、无超时/主动停止、1095.064 秒，整轮未观察到内核 OOM。

实际四路径就绪耗时 4.713 秒（上限 30 秒）；零计数初始样本、60.484 秒每路径 61 成功/0 错误、120.511 秒每路径 121 成功/0 错误；最终 121.009 秒仍为每路径 121/0。最低 MemAvailable 261188 KiB，核心采样峰值 RSS 133828608 bytes、Bouncer 19648512 bytes。CPU/吞吐仅为 TCG 实验数据，不代表真实 VPS 容量。

[原始短测结果](vps-repair-evidence/debian12-512m-soak-v5-smoke.json) 与 [冻结观察器独立重算](vps-repair-evidence/debian12-512m-soak-v5-pinned-v7-revalidated.json) 均通过；原 blob-v4 负载失败记录仍保留，不改写。串口 SHA256 `5638edbdccbe75fad1054def79daa843169e7c3929f49f9ca920e0b03f6198dc`。

v7 控制器在 16:43:37 UTC 实际启动 `/tmp/crowdsec-vps-repair-512-soak-v5-hour-20261012` 独立客机，重新安装/重复安装/三次重启后执行 3600 秒负载。当前 hour 正在运行，day 尚未启动；只有 hour 完整通过才推进独立 86400 秒轮次。`qualified_24h=false`、`recovery_qualified=false`、`trial_qualified=false`；本短测不关闭长测、恢复、其他组合和原生 ARM64缺口。


## 已有核心集成整轮通过（16:46 UTC）

Debian 12 / 请求 1 GiB（实际 MemTotal 995588 KiB）独立 `existing_core_integration` 轮次已完整结束。[结果](vps-repair-evidence/debian12-existing-core-v1.json) 包含官方原生仓库配置及包安装、预先存在配置 sentinel 保留、脚本集成、重复安装和三次重启实际决策增删同步、最终独立健康检查；QEMU 0，无超时/主动停止，未观察到内核 OOM。此证据单独计已有核心集成，不当作空白首次安装、远程生命周期或长期恢复验证。

当前唯一活动 QEMU 为 512 MiB 独立 hour 轮次；控制器继续保持仅 hour 完整通过才启动 day。整体计划仍未完成，不授予试用资格。

## 文档发布前状态复核（2026-10-13）

独立 hour 目录有安装/三次重启同步的串口事件，但没有最终 `debian12.json`、负载完成标记或 QEMU 退出证据。当前控制器 PID 1033848、运行器 PID 1034106 均不存在，也未发现活动 QEMU；控制器状态文件仍停留在 2026-10-12 的 running，属于过期状态，不能据此称测试仍在运行。中断原因和退出码未获证据，不推断为 OOM、超时或产品失败。

day 目录没有串口或最终报告，因此没有实际执行证据。hour 与 day 均保持未完成/未通过验收；此前短测、CentOS 及已有核心集成通过证据不受影响。重新执行长测需独立新轮次，不能将中断时长拼接计为连续通过。独立恢复、其他资源/模式和原生 ARM64仍未关闭，本轮没有新增试用资格。

README 与[具体使用说明](../usage-guide.md)按此状态发布，保留原始历史失败和阶段报告。

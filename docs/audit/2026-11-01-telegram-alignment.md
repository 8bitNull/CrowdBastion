# Telegram 机器人与主脚本对齐验收（2026-11-01）

本轮完成已确认的共用维护锁、同源健康检查、机器人代码版本检查与保留配置更新，并进行了九轮顺序复审与修复。实施保留已有未提交改动；未提交、推送或部署 VPS，未连接 Telegram、发送消息或发出攻击请求。

设计见 对齐设计（本地归档：`../superpowers/specs/2026-11-01-telegram-alignment-design.md`），执行记录见 实施计划（本地归档：`../superpowers/plans/2026-11-01-telegram-alignment.md`），实际使用见 [机器人说明](../2026-10-13-custom-telegram-bot.md)。本报告接续 [使用体验复审](2026-11-01-user-experience-review.md)，旧报告的通过数量不能代替本轮结果。

## 最终验证

最终全仓在第九轮最后代码/测试修改之后执行：**1392 项，1303 通过，89 条件跳过，零失败，461.115 秒，退出码 0**。完整输出见 full.txt（本地归档：`2026-11-01-telegram-alignment/full.txt`），退出码见 full-exit.txt（本地归档：`2026-11-01-telegram-alignment/full-exit.txt`）。条件跳过没有执行，不计入通过数量。

最终代码专项检查：

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 维护锁、确认流程、动作 | 71 项通过，27.341 秒 | task-1.txt（本地归档：`2026-11-01-telegram-alignment/task-1.txt`） |
| 同源健康、卡片、CLI | 97 项通过，34.542 秒 | task-2.txt（本地归档：`2026-11-01-telegram-alignment/task-2.txt`） |
| 机器人全部模块与维护/健康组合 | 268 项通过，62.508 秒 | task-3.txt（本地归档：`2026-11-01-telegram-alignment/task-3.txt`） |

最终静态检查通过：18 个 Bash 文件语法、148 个 Python 文件无缓存编译、9 个相关 Bash 文件 warning 级 ShellCheck、实际 `--help`、文档本地链接和 `git diff --check`，详见 checks.txt（本地归档：`2026-11-01-telegram-alignment/checks.txt`）、shellcheck.txt（本地归档：`2026-11-01-telegram-alignment/shellcheck.txt`） 和 help.txt（本地归档：`2026-11-01-telegram-alignment/help.txt`）。代码与测试的 167 个文件哈希另存 source-sha256.json（本地归档：`2026-11-01-telegram-alignment/source-sha256.json`），最终归档再次核对源码未漂移。

组合间存在重复用例，不能把数量相加作为独立覆盖量。测试中的 429/5xx、健康异常和恢复提示来自隔离故障场景，以 unittest 汇总为准。

中间一次 Task 1 组合运行中，空维护路径测试的首次安装返回 1；单项、20 次隔离安装和完整的 68 项组合均未复现，原失败摘录及复跑见 installation-intermittent.txt（本地归档：`2026-11-01-telegram-alignment/installation-intermittent.txt`）、installation-repeat.txt（本地归档：`2026-11-01-telegram-alignment/installation-repeat.txt`）。随后 中间全仓（本地归档：`2026-11-01-telegram-alignment/round7-full-red.txt`） 1389 项出现 4 项安装失败，详细输出证明冲突扫描读到了另一组隔离测试的真实进程。第七轮用明确的同名参数进程复现，修复 fixture 的 `/proc` 隔离，并验证模拟目录中的外部机器人仍阻止安装；没有削弱生产检查。最早一次断言没有命令输出，不能倒推其具体报错已被直接证实。

另一次全仓运行期间又发现并修复第八轮服务状态问题，已主动终止该中间运行并保存 部分输出（本地归档：`2026-11-01-telegram-alignment/intermediate-full-interrupted.txt`）。第八轮后的 1391 项全仓（本地归档：`2026-11-01-telegram-alignment/before-sticky-lock-full.txt`） 为零失败、89 条件跳过，468.346 秒；第九轮又更改锁目录兼容性并新增用例，因此该结果也只保留为历史。最终全仓从第九轮最后代码/测试修改之后完整重跑；旧通过、旧失败和中止运行均不能代替最终结果。

## 交付行为

- TG 确认后的封禁、解封、日志加白、重载和释放缓存共用主维护锁；锁被占用、迁移未完成或路径不安全时明确拒绝，保留一次性确认和审计语义。成功动作清除旧健康缓存。共享维护锁支持 root 所有且带 sticky 位的标准 `/run/lock`，仍检查文件归属、权限和类型，使用 `O_NOFOLLOW` 且不截断已有锁文件。配置与报告的直接父目录规则保持严格。
- `--status-json` 复用终端实际采集及统一结论，输出版本、时间、配置路径、角色、范围、检查项、必检项和摘要，不传出原始诊断。机器人固定参数调用，20 秒预算、超时杀进程组、30 秒缓存；验证配置、schema、检查项、摘要和退出码，失败显示检查未完成。
- 安装携带所有机器人依赖及独立的主脚本/lib 运行副本。源码目录移走、cron 未安装时仍可从随附入口检查。旧配置可自动发现随附入口，无需重写配置原文；没有随附入口的旧安装保留明确标识的轻量检查。
- 机器人菜单保留 `1–3`，增加 `4` 代码检查、`5` 保留配置更新。代码指纹覆盖机器人、辅助模块及随附主脚本，配置和状态不参与比较。源码、cron 和机器人副本分别更新。
- 更新预览默认取消；确认后保留配置字节、offset、审计和原 enabled/active 意图。备份覆盖配置、程序、helpers、unit 及 `current` 链接；复制、配置、启动失败或捕获 INT/TERM 时尝试恢复，恢复不完整明确提示。服务状态不能安全读取时先拒绝写入；只接受退出码及文本均匹配的 `enabled`/`disabled`，`enabled-runtime`、`static`、`linked` 等状态拒绝推断。
- 未知 unit、helper 链接、非托管 runtime 和越界 `current` 指针拒绝覆盖或误报一致。核心卸载清理托管运行副本，未知归属目录在停用服务前拒绝清理。

## 循环复审与修复

本会话没有独立 reviewer/子代理工具。下列轮次均为作者在本会话中的顺序自查和隔离回归，不代表独立评审或不存在其他缺陷。

| 轮次 | 可复现问题及修复 | 回归 |
| --- | --- | --- |
| 1：安装及回滚 | 自包含依赖、路径、代码检查和更新入口初始缺失；实现中回滚测试又暴露 `cp` 将目录链接当作目录的问题，恢复链接改为 `cp -a -T --remove-destination` | 初始部署 RED（本地归档：`2026-11-01-telegram-alignment/deployment-red.txt`） 为 7 项失败/错误；部署及恢复组合 GREEN（本地归档：`2026-11-01-telegram-alignment/deployment-green.txt`） 60 项通过。该初始 RED 是功能未实现的基线，未单独归档目录链接问题的中间输出 |
| 2：清理与配置 | 卸载遗留随附 runtime；未知 runtime 仍开始清理；维护路径为 null 仍通过配置校验 | RED（本地归档：`2026-11-01-telegram-alignment/round2-red.txt`） 3 项/4 失败 → GREEN（本地归档：`2026-11-01-telegram-alignment/round2-green.txt`） 33 项通过 |
| 3：更新中断 | TERM 中断后留下新 `current` 且未恢复运行服务；停止服务失败时未尝试恢复 | RED（本地归档：`2026-11-01-telegram-alignment/round3-red.txt`） 2 失败 → GREEN（本地归档：`2026-11-01-telegram-alignment/round3-green.txt`） 65 项通过 |
| 4：副本归属 | 越界 `current` 指针在内容相同时误报一致；补充验证旧配置原文升级及缺 helper 副本修复 | RED（本地归档：`2026-11-01-telegram-alignment/round4-red.txt`） 1 失败 → GREEN（本地归档：`2026-11-01-telegram-alignment/round4-green.txt`） 38 项通过 |
| 5：服务意图 | 状态查询失败被当作 inactive/disabled，可能在更新后错误改变运行意图 | RED（本地归档：`2026-11-01-telegram-alignment/round5-red.txt`） 2 个子场景失败 → GREEN（本地归档：`2026-11-01-telegram-alignment/round5-green.txt`） 175 项通过 |
| 6：协议往返 | JSON 丢失 `required` 必检项，机器人重算摘要与终端不一致；新增真实 renderer/CLI 输出往返，覆盖 7 组用途 × 4 种状态，传递并验证必检项 | RED（本地归档：`2026-11-01-telegram-alignment/round6-red.txt`） 28 个组合及 CLI 共 29 个错误 → GREEN（本地归档：`2026-11-01-telegram-alignment/round6-green.txt`） 94 项通过 |
| 7：测试进程隔离 | 并行运行时安装冲突扫描读取真实 `/proc`，把其他测试的 `--check-config` 子进程当作独立机器人；将复制到 fixture 的扫描路径指向模拟进程目录，同时验证模拟外部机器人仍阻止安装 | 中间全仓 4 失败；RED（本地归档：`2026-11-01-telegram-alignment/round7-red.txt`） 同名参数子进程稳定复现 1 失败 → GREEN（本地归档：`2026-11-01-telegram-alignment/round7-green.txt`） 66 项通过 |
| 8：启用状态语义 | `is-enabled` 返回 0 不等于持久 enabled，原实现可能把临时启用/静态等意图变成永久启用；改为同时校验状态文本及退出码，非常规状态在写入/停服务前拒绝 | RED（本地归档：`2026-11-01-telegram-alignment/round8-red.txt`） 8 种状态失败 → GREEN（本地归档：`2026-11-01-telegram-alignment/round8-green.txt`） 267 项通过；启动失败测试同时确认实际到达 restart |
| 9：标准锁目录 | 本机 `/run/lock` 为 root 所有的 `1777` 目录（只读观测（本地归档：`2026-11-01-telegram-alignment/environment-lock-mode.txt`）），私有文件规则错误拒绝默认锁路径；仅锁校验显式支持可信 sticky 直接父目录，配置/报告仍使用严格规则 | RED（本地归档：`2026-11-01-telegram-alignment/round9-red.txt`） 新建/已有锁两个子场景错误 → GREEN（本地归档：`2026-11-01-telegram-alignment/round9-green.txt`） 101 项通过；覆盖真实争用/释放、普通可写目录和可写锁文件拒绝、私有报告拒绝 |

共享锁和健康接口的初始失败及修复结果另存 lock-red.txt（本地归档：`2026-11-01-telegram-alignment/lock-red.txt`）、lock-green.txt（本地归档：`2026-11-01-telegram-alignment/lock-green.txt`）、health-red.txt（本地归档：`2026-11-01-telegram-alignment/health-red.txt`）、health-green.txt（本地归档：`2026-11-01-telegram-alignment/health-green.txt`）。

## 复核范围与流程记录

最终复核覆盖确认领取后的锁拒绝、迁移与路径安全、检查失败和配置错配、源码移走、取消与停用更新、旧配置字节、受损 helper、越界指针、启动失败及 TERM 恢复。测试使用临时树、命令替身和合成状态，不调用真实 TG API。

原技能的 `task-start`/`task-done` 工具已补齐执行，结果以实际工作区为准；记账晚于初始实施及前五轮复审，不能表述为任务开始前已建立 ledger。用户要求保留未提交工作，故没有新提交，工具记录中的 base/head 相同。`review-package` 的提交范围保护拒绝空范围，最终审查使用实际未提交 diff 和新源文件，另存 working-tree-review.txt（本地归档：`2026-11-01-telegram-alignment/working-tree-review.txt`），计划记账副本见 plan-progress.txt（本地归档：`2026-11-01-telegram-alignment/plan-progress.txt`），未绕过保护伪造提交审查；实际拒绝输出见 review-package-rejection.txt（本地归档：`2026-11-01-telegram-alignment/review-package-rejection.txt`）。

## 边界及后续部署验收

本地证据没有验证真实 VPS 的 systemd/包升级、Telegram 轮询和发送、实际网站/中转/V2bX 流量阻断。进程内回滚不能覆盖 SIGKILL、断电或主机故障；系统软件包和依赖安装也不属于文件事务整体回滚。

部署时仍需先核对备份，验证旧版本升级、取消、停用服务更新、启动失败恢复及检查超时；再在实际聊天核对只读卡片与确认操作。真实阻断按入口、协议、IPv4/IPv6、路径、新连接和时间分别验收，保留正常来源对照。服务 active、代码一致、命令返回 0、决策存在、内核集合命中和历史验收均不能代替当前业务阻断证据。

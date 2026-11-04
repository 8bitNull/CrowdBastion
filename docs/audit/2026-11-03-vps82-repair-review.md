# 192.0.2.27：三轮复审与 sysctl 最小修复

用户在[部署适配性检查](2026-11-03-vps82-readonly.md)后要求“循环复审加修复”。本轮修复了已确认的 sysctl 持久配置错误：**`net.core.netdev_budget_usecs` 从无效的 6000 改为该机当前已运行的 8000**。定向应用退出 0、无 stderr；81 项采样运行参数全部保持一致。完整执行范围见计划（本地归档：`../superpowers/plans/2026-11-03-vps82-repair-review.md`）。

仅修改 `/etc/sysctl.d/99-network-optimize.conf` 中这一项，未部署 CrowdSec、升级系统、改变防火墙、调整其他网络参数、重启生产服务或重启 VPS。root 公钥认证的启用是用户在本轮之前操作的，不计作本轮修复。

## 第一轮：重新确认故障与边界

新基线采样为 **2026-11-03 12:03:51 UTC**，补充有效配置检查后再次采样。现场仍为 Debian 11／XanMod 6.18.6、约 455 MiB 内存、13 个 realm 2.9.4 转发。journal 保存了本次开机拒绝写入 6000 的错误，`systemd-sysctl.service` 为 failed；当前运行值则是 8000。

实际 `/lib/systemd/systemd-sysctl --cat-config --no-pager` 展开的七个配置来源中，只有 `/etc/sysctl.d/99-network-optimize.conf` 的一条目标赋值，没有其他匹配该键的通配、排除或覆盖项。unit 使用原始 `/lib/systemd/systemd-sysctl`，没有 drop-in。文件 root 所有、0644、无符号链接或硬链接复用。

该机内核配置为 `CONFIG_HZ=250`。Linux 上游 v6.18 定义此参数下限为 `2 * USEC_PER_SEC / HZ`，计算为 **8000 微秒**，并使用带最小值约束的处理器。这与现场拒绝 6000、运行值 8000 一致。上游源代码仅作解释依据，没有声称与定制 XanMod 源码逐字节一致，也没有在生产机重复写入已知无效值。来源记录（本地归档：`2026-11-03-vps82-repair-review/kernel-reference.json`）。

独立复审提出三项核验补充，均已落实：使用真正有效的配置栈；保护 Agent／SSH／Fail2Ban 配置而不只核对 realm；分清定向应用成功、清除历史失败与完整 unit 验收。

## 第二轮：带前置条件的修复

执行前独立审阅了实际脚本与注入基线，未发现重要阻塞项。修复持共用维护锁，检查原文件哈希、权限／归属、唯一精确赋值、完整配置栈哈希、81 项运行值和 **177 个唯一受保护文件**。14 个 realm 文件与另采集的 176 项有 13 项重叠，因此不能将二者简单相加为 190 个独立文件。

先在 root 私有备份目录保存原件、元数据和基线，再同目录原子替换，保留原 uid／gid／权限。只运行：

```text
/lib/systemd/systemd-sysctl --prefix=/net/core/netdev_budget_usecs
```

该命令于 **12:08:28 UTC** 的执行记录中返回 0、stdout／stderr 均为空。随后确认文件只改这一赋值、有效配置栈除该赋值外一致、81 项运行值全部不变、177 项保护哈希一致。脚本包含受候选哈希约束的失败／信号回滚，但本次没有触发该路径，也没有进行故障注入测试。

配置修复成功后，另一次 SSH 查询确认本轮基线以来该 unit 没有新增 journal 事件，再执行 `systemctl reset-failed systemd-sysctl.service`，仅确认并清除历史失败。最终实际状态为：

```text
Result=success
ExecMainStatus=1
ActiveState=inactive
```

**`Result=success` 来自 reset-failed，不是完整单元重跑成功；`ExecMainStatus=1` 保留了原执行失败的历史状态。** 本轮未执行完整 sysctl reload／restart，未冷启动，不能据 failed units=0 宣称所有开机 sysctl 已验收。

证据：修复前基线（本地归档：`2026-11-03-vps82-repair-review/preflight.json`）、修复结果（本地归档：`2026-11-03-vps82-repair-review/repair-result.json`）、历史状态确认（本地归档：`2026-11-03-vps82-repair-review/history-ack.json`）、实际执行脚本（本地归档：`2026-11-03-vps82-repair-review/scripts/executed_repair.py`）。脚本是一次性、固定旧哈希的操作记录，修复后不能直接重复执行。

## 第三轮：业务连续性与结论复审

最终现场采样始于 **12:09:30 UTC**，之后另做外部 TCP 建连复验。所有判定均使用本轮新基线及实际结果，没有沿用上一台 VPS 的封禁验收。

| 核验 | 结果 |
| --- | --- |
| 生产服务 | 18 个服务 active，PID、启动时间、NRestarts 及采样状态前后一致，包含 13 个 realm、Agent、SSH、Fail2Ban、journald、rsyslog |
| 文件连续性 | 177 个唯一保护文件哈希一致，覆盖 realm 二进制／TOML、Agent 二进制／配置、SSH 和 Fail2Ban 配置 |
| 监听 | 13 个 realm TCP／UDP 与 SSH 监听地址、端口、PID 保持一致 |
| 外部 TCP | 修复前、修复后均 **14／14** 建连成功：SSH 与全部 13 个 realm 入口 |
| 网络运行值 | 81 项全部不变；目标始终为 8000，BBR/fq 等既有设置保持 |
| 错误计数 | UDP RcvbufErrors／SndbufErrors／MemErrors、TCP ListenOverflows／ListenDrops，修复前后均为 0 |
| 防火墙 | iptables／ip6tables 输出不变；去除计数变化后的 nft 规则图一致，ForwardX 统计表保留 |
| 开机任务 | root crontab 及旧 mangle 快照哈希不变；没有加载、停用或迁移 |
| failed units | 当前为 0；sysctl 的历史标记清除与定向应用分开记录 |

最终独立复审从原始前后采样重新计算上述比较，未发现重要问题或缺失的必要检查。

外部建连仅证明 TCP 连接能建立，没有携带真实代理认证；UDP 监听与错误计数正常不能代替公网 UDP 后端回包验收。未测试已有长连接、峰值吞吐、真实攻击封禁、模块加载或完整冷启动。CrowdSec 尚未安装，因此不存在“CrowdSec 防护已验收”的结论。

## 保留事项与复审修正

root 的 `@reboot iptables-restore < /etc/iptables/rules.v4` 目前只恢复 **mangle 表的三条 MSS 规则**。旧快照与当前空 iptables 运行状态不同，但无法据此确认是 cron 失败、后续清表还是有意现状。没有证据支持本轮立即恢复、停用或新增一套持久化工具。

该快照不包含 filter 表，因此“它必然清空 CrowdSec filter 封禁链”的推断不成立；同时也不能将整表恢复描述为完全无风险。它仍会被脚本启动审计报告，未来真正接入 CrowdSec 时，需要确认 MSS 意图、任务归属和启动顺序。上一报告中的“部署前应处理”应理解为集成前协调项，不是已证明的当前业务故障。

Debian 11 超出官方 LTS 的生命周期问题仍存在。当前内存更适合 Bouncer-only 的建议不变；扩大本地检测部署或升级 OS 都需要独立部署／维护工作，本轮没有自动实施。

## 备份和恢复

私有备份：`/var/backups/crowdbastion/vps82-sysctl-review-iqdvz68q`，目录 0700、文件 0600，六个文件已封存；原配置、候选配置、基线、定向结果及历史状态确认均保留。原件 SHA256 为 `cf9b36e6f436349ebd061640e7feef9ed500e8d5354ff72727471cd2f6301062`；修复后为 `8077d4e3c25a45e613ff52a81003adb01f870c0526a89109a1c5a8de1e212447`。

恢复仅应在维护锁内、核对后续编辑及候选哈希后针对该文件进行；不要恢复其他网络配置或整表防火墙。恢复原件会重新引入下次应用时对 6000 的拒绝，不能将其当作推荐配置。本次备份不是 OS 快照，也不提供断电、SIGKILL 或不遵守维护锁的其他特权编辑器并发下的事务保证。

原只读报告及其 13 项封存文件哈希保持一致。本轮新增文件仅位于此报告、其同名证据目录及计划文件；未修改产品源码，未运行产品全套测试，未提交或推送。

其余证据：连续性核验（本地归档：`2026-11-03-vps82-repair-review/verification.json`）、外部 TCP 前（本地归档：`2026-11-03-vps82-repair-review/tcp-before.json`）／后（本地归档：`2026-11-03-vps82-repair-review/tcp-after.json`）、最终现场（本地归档：`2026-11-03-vps82-repair-review/final-result.json`）、独立复审（本地归档：`2026-11-03-vps82-repair-review/independent-review.json`）、私有备份封存（本地归档：`2026-11-03-vps82-repair-review/seal-result.json`）。

# 192.0.2.10：循环复审与修复

本轮针对用户要求的 ForwardX realm／CrowdSec 防护进行三轮复审、修复和现场复验。开始采样为 **2026-11-03 11:20:57 UTC**，最终现场采样始于 **11:36:10 UTC**，备份核验于 **11:37:39 UTC** 完成。连接目标仅为 `root@192.0.2.10:53322`。

发现并修复一项静态规则恢复脚本的失败路径缺陷，以及修复复审中发现的重复信号清理竞态。最终未发现本轮检查范围内的重要阻塞项。**现场开始时规则完整，没有证据表明已发生部分应用故障。**

## 第一轮：基线与故障复现

基线中 Bouncer 决策覆盖为 12346／12346，遗漏 0；健康检查除真实业务流量验收 `pending` 外均为 `ok`。旧备份哈希无漂移，SQLite 一致性副本 `quick_check=ok`。

原 `/usr/local/lib/crowdbastion-static-policy/apply.py` 逐条查询、立即追加。若后面的查询或追加失败，之前新增的规则会留在现场；原 unit 也未配置失败重试。离线使用原脚本内容与文件／命令边界替身复现：第六条查询失败时，留下前五条新增规则，没有回滚。未在生产防火墙注入故障。

针对旧实现的首次回归记录有四项失败、五项因新契约或信号安全而跳过；这不是旧实现通过记录。证据：原脚本复现（本地归档：`2026-11-03-vps144-forwardx-review/scripts/reproduce_legacy.py`）、失败记录（本地归档：`2026-11-03-vps144-forwardx-review/tests-legacy-red.txt`）。

## 第二轮：修复与交叉复审

新脚本先完整校验固定九条清单、查询全部规则，再追加缺失规则，并在结束后复查。失败时逆序撤销本次计划追加且仍存在的规则；既有规则不列入撤销清单。追加意图先于命令记录，因此覆盖“内核已追加，但调用随后超时”的情况。回滚遇错继续清理，并明确报告不完整回滚。

同时增加共用维护锁、root 所有权与路径／链接检查、命令超时及 TERM／HUP／INT 清理。复审发现最初修正版在安装忽略信号处理器的过渡期间仍可能被第二个信号打断；独立复现后，使用取消与恢复状态标记修正。该回归失败记录（本地归档：`2026-11-03-vps144-forwardx-review/tests-signal-red.txt`）保留。

最终针对清单校验、晚期查询／追加／复验失败、超时后副作用、真实信号及重复信号、回滚失败继续清理、幂等性和锁安全的 **12 项检查通过**。主执行者独立运行也为 12 项通过；另一次交叉复审没有发现重要阻塞项。原有封禁／转发实验的取消清理也经离线复核。

证据：修正版（本地归档：`2026-11-03-vps144-forwardx-review/scripts/static_policy.py`）、测试（本地归档：`2026-11-03-vps144-forwardx-review/scripts/test_static_policy.py`）、完整通过记录（本地归档：`2026-11-03-vps144-forwardx-review/tests-green.txt`）、独立通过记录（本地归档：`2026-11-03-vps144-forwardx-review/tests-parent.txt`）、实验取消检查（本地归档：`2026-11-03-vps144-forwardx-review/cancellation-check.json`）。项目广泛测试发现流程曾启动后主动终止，未完成产品测试套件，不作全套测试通过声明。

## 第三轮：部署与现场复验

仅替换静态规则脚本及其 systemd unit；unit 增加 `Restart=on-failure`、10 秒重试、取消启动频率限制，以及有界启动／停止超时。保留 oneshot、RemainAfterExit 和 Bouncer 前置顺序。静态服务连续两次重跑成功，最终 enabled、active/exited、ExecMainStatus=0；另一次受锁保护的现场观测为 **18 次查询、0 次追加／删除**，规范化后的防火墙规则图与顺序不变。

本轮未重启 VPS、三个生产 realm、ForwardX Agent、CrowdSec、Bouncer 或 journald。七个服务 PID 全部与本轮基线一致；realm 二进制和三份 TOML，以及 CrowdSec 本地／在线身份和 Bouncer 基础配置哈希保持一致。前一部署中 Agent 的历史正常重启不属于本轮，也没有被隐去；最终证据中的旧基线 Agent 连续性为 false，本轮 `review_pid_continuity` 全为 true。

| 核验 | 结果与覆盖范围 |
| --- | --- |
| 实际 Bouncer 生命周期 | 三个生产 TCP 监听及生产 INPUT 后的私有 UDP 回显：封禁、续期跨原期限、精确删除恢复、自然到期恢复均通过；正常对照始终可用，实际 DROP 计数增加 |
| TCP／UDP 转发实验 | 已安装 realm 2.9.4，独立 loopback namespace；IPv4／IPv6、三个端口、两种协议、每组三个客户端、64／512／1200 字节，共 36 用例、108 次逐字节一致往返，无响应串线 |
| 实验清理 | 测试决策、集合成员、UDP 进程、veth、namespace 及影子 realm 全部清理；最终无测试 namespace／接口残留 |
| 决策覆盖 | 最终适用网络 **12312**、实际集合 **12312**、遗漏 **0**；与基线数量变化来自动态决策，不是遗漏 |
| 配置／运行 | `crowdsec -t`、防火墙和维护副本检查退出 0；健康检查其余项均 ok，真实业务验收仍 pending、退出 2 |
| TCP／UDP 参数 | 七项 TCP 默认值保持已提交值；BBR/fq、32 MiB 缓冲上限、UDP 最小缓冲 8192 保持；三个 UDP 缓冲／内存错误计数均 0，ListenOverflows=0、ListenDrops=7，与原采样一致 |
| 业务与观察边界 | 后端 2087／2096 TCP 可建连；ForwardX nft 统计表存在；realm 观察样本归类成功且不提取封禁用 `source_ip` |

最终源代码及维护副本一致，原防火墙迁移和网络事务仍为 committed，未重复执行迁移。未新增按连接量、超时或 EOF 自动封禁规则，未加入宽泛白名单或改 PROXY 配置。

证据：部署结果（本地归档：`2026-11-03-vps144-forwardx-review/deployment.json`）、封禁生命周期（本地归档：`2026-11-03-vps144-forwardx-review/enforcement.json`）、隔离转发实验（本地归档：`2026-11-03-vps144-forwardx-review/relay-lab.json`）、最终现场核验（本地归档：`2026-11-03-vps144-forwardx-review/final-result.json`）。

## 备份、恢复与限制

新私有备份为 `/var/backups/crowdbastion/vps144-static-review-20261103T113133Z`，保存脚本／unit 原件、规则和服务基线、候选文件及本轮验收结果；21 个文件已封存。原 `/var/backups/crowdbastion/vps144-20261103T103358Z` 全部已封存文件哈希一致、没有新增文件，SQLite quick_check=ok。原本地报告及证据的 42 项清单也全部一致。本轮证据单独保存，没有覆盖旧验收结果。

恢复只应针对这两份文件，在维护锁内核对当前哈希及后续变更后，用新备份中的 `apply.py.before` 和 `crowdbastion-static-policy.service.before` 恢复，再 daemon-reload 并检查静态服务。不得整表恢复旧防火墙或覆盖当前动态数据库。原件恢复会重新引入本文修复的失败路径缺陷。

新的固定清单有意只允许本次审核的九条规则；未来修改 `rules.json` 需同步复审脚本。回滚与重试不能保证 SIGKILL、断电或不遵守维护锁的特权进程并发修改时的原子性。未进行冷启动、已有长连接被封后行为、公网 UDP 后端响应或真实业务认证验收；隔离 IPv6 通过不代表公网 IPv6 可用，也不作 WAN 吞吐或大流量攻击承载能力声明。

审计工具的服务查询补齐 journald，并将观察样本输出改到新目录后才运行，避免比较基线缺项及覆盖旧证据。封存工具首次因数据库后缀假设错误停止于写入前，改为实际 `.sqlite3` 文件后核验成功；这些是工具问题，不是生产故障。

现场封存：核验结果（本地归档：`2026-11-03-vps144-forwardx-review/seal-result.json`）。本轮未修改产品源码、提交或推送仓库；所有新增本地文件位于此报告及其同名证据目录。

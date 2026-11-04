# 2026-11-01 通知降频循环复审与修复

用户要求“循环复审加修复”。本轮在既有混合工作树内顺序自查，修复三类已复现问题，保持关注3600秒、普通21600秒及紧急／恢复阈值不变。没有独立reviewer，不提交、不推送；原[降频验收](2026-11-01-telegram-noise.md)和证据不改写。

执行步骤见复审计划（本地归档：`../superpowers/plans/2026-11-01-telegram-noise-review.md`），操作语义见[通知说明](../telegram-noise-control.md)。

## 第一轮：恢复消息误报未送达

故障通知网络请求释放数据库锁后，健康线程可能确认恢复或停止监测，排队消息按当时的notified=0生成“异常期间的通知尚未确认送达”。故障通知随后成功，旧代码未校正该说明。

恢复／停止监测各一项RED复现；成功提交时刷新仍存在的后续消息，保留退避和due，不重建已被新故障取消的恢复消息。与原策略合跑33项GREEN。

## 第二轮：升级导致已发送计数未入账

发送期间普通→关注或关注→紧急升级会增加generation。原成功处理整体跳过不同generation，导致已真实发送的事件计数未写入reported；后续关注把这部分再次算作“新增”。

两项RED复现reported=0而非1。修复仅合并已发送计数的MAX值，不修改新等级的首次提醒、催办计数及截止时刻；新等级首次通知继续生效。合跑35项GREEN。

## 第三轮：同一规则被拆成多类

冷却时间后再次告警会生成新的事件实体。六小时摘要把同规则的多段事件逐行展示，错误声称是多类；来源数也无法在分段间去重。

普通／关注各一项RED复现。按原始规则／服务／模拟类型／健康组件fingerprint合并展示和分类计数，来源在相同分组留存记录内去重，普通按分组新增总量排序。发送快照仍保留每个实体的id/count/generation，逐个更新，未展示的组仍由总计覆盖。额外回归验证服务和模拟边界、六行上限与遗漏类别数、发送失败后真实未送达说明、新故障撤销旧恢复。

新增10项回归，通知相关74项：**72通过、2条件跳过、0失败，44.044秒**。三轮共6项初始失败，分别保存为round1/2/3-red.txt；对应GREEN及作者自查（本地归档：`2026-11-01-telegram-noise-review/review-notes.txt`）一起保留。

## 全仓与静态验收

全仓命令`PYTHONPATH=tests:lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests`：**1425项，1336通过、89条件跳过、0失败，492.798秒，exit0**；控制器耗时493.134秒，169源码运行前后hash一致。日志内故障／回退文字为隔离测试预期输出，不是本轮生产操作。

另用临时本地SQLite放入50,000条模拟接收记录、同规则50段事件，摘要正确合并一类、254个去重来源，快照仍保留50段。该次汇总构建0.026秒，仅说明本地样本行为，不作为生产时延承诺。见聚合量核验（本地归档：`2026-11-01-telegram-noise-review/aggregate-volume-probe.json`）。

150个Python AST、18个Bash语法、diff检查通过；相对上轮受检169源码，仅通知程序及新增测试发生变化。新发布另7个通知helper与本地测试依赖hash一致。初始混合diff与两份本轮起始源码保存，未覆盖其他工作。

## VPS 发布与运行核验

全仓通过且169源码再次核对后切换成功；客户端exit0、3.088秒。**仅通知服务重启，PID252086→279489**，core116932、Bouncer2109、交互bot195577、Docker642均未变；五服务active/enabled、NRestarts0。

独立核验安装程序、root管理源码及发布通知源码相同，日常入口／root／bot随附管理完整指纹一致，候选相对基础版本只有`lib/crowdsec_notify.py`一处差异。私有通知配置在内的16份受保护文件逐字节保持；1份offset不倒退，原审计文件数0，未声称既有审计内容经过验证。SQLite inode保留，292事件实体／479接收记录原键保持，一致性备份quick_check=ok。队列ready、pending/retrying/open_critical均0，bot轮询healthy且有部署后成功心跳。完整健康11.291秒、exit2，仍为“运行检查通过，实际拦截待验证”，traffic=pending。

证据见部署（本地归档：`2026-11-01-telegram-noise-review/vps-deployment.json`）、独立核验（本地归档：`2026-11-01-telegram-noise-review/vps-verification.json`）和远端封存（本地归档：`2026-11-01-telegram-noise-review/remote-seal.json`）。

- 基础发布：`/opt/crowdbastion/releases/tg-noise-20261101-1e6161406092-r2`。
- 候选发布：`/opt/crowdbastion/releases/tg-noise-review-20261101-760bc26e003d`。
- 候选完整管理指纹：`8762b626ab1f7f1d3944876da8e7a15b114c1926e34a4b53173fede9a5b77ec0`。
- 通知源码SHA256：`760bc26e003d5621f9ddccaeccc256cd610ff868e73c30a580ee1c21ccee2842`。
- 私有备份：`/var/backups/crowdbastion/tg-noise-review-20261101T150243Z`。

生产前置核对ready、pending/retrying/open_critical均0，五服务active/enabled、NRestarts0。候选以已部署完整版本为基础，只叠加受检通知文件，同步root管理源码、日常入口与bot随附管理指针；bot自身程序和其他helper不改。配置保持逐字节一致。

发布在共享维护锁内执行：记录服务意图和受保护文件hash，备份原程序／入口／配置、bot offset／审计摘要及SQLite一致性副本，停止通知后原子替换程序与入口，再切换管理指针并启动通知。不执行会重新加载core的完整安装流程，依赖均已单独核对。异常／INT／TERM尝试恢复原程序、指针、服务；活队列始终保留。

## 回退与验收边界

人工回退先取得同一维护锁并留存当前消费状态。仅当前程序／入口／指针仍匹配本轮时停止通知，按备份before.json的原权限恢复`0-crowdsec_notify.py.before`到通知程序、`1-crowdsec_notify.py.before`到root管理源码、`2-crowdbastion.before`到日常入口，并恢复stage.json中的old_pointer，再按原服务意图启动。配置本轮不改，`notify-config.before.json`只留审计，不覆盖管理员后续更改。

**不恢复活SQLite、已发送标记、offset或审计**；consistent数据库只供审计和另行评估灾难恢复。不动防火墙与其他服务。生产回退和断电／SIGKILL未演练，不承诺完整事务恢复。

生产不额外发送Telegram测试，不冒充真实聊天收件或六小时实等验收。网络超时或API接受后未及提交便崩溃，仍可能重复投递。完整健康结论与实际业务阻断范围维持既有口径。

远端11份稳定备份文件封存，目录0700／文件0600、root归属及一致性SQLite只读quick_check通过；最终manifest SHA256为`8be9f1fbaf8d0cf7b169856558c78225e939d7bc467b3526fecf69ed15e142bd`。私有配置本身保留0600原文供审计。

本轮修改了持续维护的审计索引和通知说明，旧版本字节保存在`prior-supporting-documents/`，并核对匹配上一轮原manifest，未改写旧清单。本轮原始证据、脚本和哈希清单见证据目录（本地归档：`2026-11-01-telegram-noise-review/`）。

# V2bX 日志覆盖与观察采集稳定性验收

本阶段完成已授权的前两项：扩展有可靠来源的失败投影，提供持久观察采样，并核验正常／故障、轮转和重启。官方 V2bX v0.4.0 三内核、真实 sing-box 1.12.0 客户端在本机 loopback 控制环境完成 **66/66** 对照；实际日志投影在官方 CrowdSec 1.8.1 临时引擎产生 **6 个观察告警、0 个决策**。这些是指定版本的本机证据，未接入生产。

## 新增能力

sing AnyTLS 仅在 ERROR 的 `unknown user password: fallback disabled`、明确连接来源和可靠时间同时存在时映射 auth_failure。规则只新增 AnyTLS auth_failure，未知protocol_rejection、fallback候选和普通TLS/网络错误均不能借此进入告警。

sing Shadowsocks 的明确 `serve TCP from ... chacha20poly1305: message authentication failed` 核验外层和内层来源端点一致后记为 integrity_failure。它可能来自错误密码或损坏密文，**不作为认证失败或观察告警**。本阶段只覆盖该一个已观察到的cipher／错误格式。

新增 `--v2bx-observe` 与 Python Observer：只读输入日志，SQLite同一事务保存固定投影及偏移；单数据库与活动源inode的advisory lock抑制本采样器并发重复采集。状态包含配置摘要、数值游标、锚点摘要和计数，不含原始行、账号、密码、面板地址或目标。私有数据库和快照为0600；拒绝FIFO／源链接、路径冲突、数据库配置改变与容量超限。一次性快照包含全部已保存事件，不能反复当作生产tail输入。

命令与恢复／停用方式见 [指南](../v2bx-guide.md)。进程停止或Ctrl-C即停止采样，已提交SQLite进度保留；恢复用相同配置和数据库。未创建systemd、生产acquisition、防火墙规则或任何封禁决策。

## 真实程序测试

同前轮官方发行包和源提交 `3deccaae00d168fd049f8a8659656664f25ee301`，包／二进制依赖证据见 [program-sources.json](v2bx-observation-stability-2026-10-13/program-sources.json)。本阶段使用native loopback，服务仅监听127.0.0.1；受控UniProxy、临时凭据和本地证书，无宿主路由／防火墙变化。不能把本轮表述为新的QEMU、IPv6或真实VPS路径验收。

13个基础内核／协议组合均运行正常、错误凭据、恢复、目标端口不可达；7个TLS／QUIC组合另验证错误server_name，1个VLESS组合验证本地目标不返回响应导致超时，共60个对照。轮转／写入进程重启、采样器重启和copytruncate另有6个正常／错误凭据对照，共66个。每个业务成功须校验随机HTTP令牌；失败控制要求有效SOCKS negotiation且探针无基础设施错误。正常、恢复、TLS错误、不可达和超时阶段不得产生eligible失败投影；不从阶段名字构造事件。

结果见 [results.json](v2bx-observation-stability-2026-10-13/results.json)。循环内日志窗口在客户端终止后等待0.15秒，并由采样器保存实际投影；异步晚写不能排除，不声称逐请求精确归因。某次错误凭据对照可产生多条失败投影；游标去重针对已提交日志位置，不将相同时间/IP的投影擅自删为“同一次尝试”。

## 采集生命周期

19项Observer回归验证append、partial、重启续读、rename/create、有限旧inode找回、copytruncate、长于offset的改写、缺失源、事务失败回滚、过长行、无效UTF-8、relay排除、源／数据库／导出alias、FIFO／链接、同库及跨库双采集、容量停止和输出权限。实际程序对照另验证：

- 轮转后程序仍写旧inode时先收集旧记录，停止／排空旧写入者，再创建新日志并重启V2bX；健康和错误凭据对照均成功。
- 重启采样器后先检查已保存事件数不变，再执行新请求；不重复提交已保存位置。
- 截断输入后新错误事件继续可见，truncations明确增加；不把这解释为截断前未读内容已恢复。

实际各源指标：

| core | 物理行 | 固定投影 | eligible失败投影 | integrity_failure | rotations | truncations | continuity_risks |
| --- | --- | --- | --- | --- | --- | --- | --- |
| xray | 16 | 15 | 2 | 0 | 0 | 0 | 0 |
| sing | 139 | 11 | 8 | 1 | 1 | 1 | 2 |
| hysteria2 | 108 | 6 | 0 | 0 | 0 | 0 | 0 |

continuity_risks是保守风险提示，不是实际丢失条数。每次旧fd到新inode交接均增加风险，因为观察到EOF不能证明所有写入者已重开；后续旧fd晚写仍可能漏采。回归测试验证这种风险被标记，**没有验证任意轮转无损**。copytruncate可丢未读字节；相同前缀快速重写／inode复用、超出有限查找的旧文件、快速多轮轮转和外部写入竞态不保证可发现／恢复。日志中相邻重复文本不作为未经证实的重复事件删除；其他忽略advisory lock的采集器仍需单独核查。

## 官方引擎观察

主采样器导出实际事件，加上独立采样器将127.0.0.0/8声明为relay CIDR后的真实日志排除样本，合计33条投影、10条eligible失败。该CIDR对照验证声明排除逻辑，**不是本轮新的物理中转测试**。按source/core/protocol每组保留一条真实失败，连同所有非eligible事件送入引擎，共29条读取、6告警、0决策；严格核对alert.events元数据组，不只数告警。

已覆盖观察组：Xray VMess/VLESS，sing VMess/VLESS/Trojan/AnyTLS。正常／网络错误、SS integrity、fallback候选与声明relay排除样本无额外告警。批量去重避免trigger场景1秒blackhole，不代表生产逐行告警率，也没有删除原始采样证据。结果见 [real-replay.json](v2bx-observation-stability-2026-10-13/real-replay.json)，输入快照独立归档。

另有synthetic/source-backed反例验收：16条、6告警、0决策，包含无效source、不观察记录以及不支持的AnyTLS protocol_rejection；它与上述实际日志回放分开。首轮规则过宽触发额外告警，随后收紧，失败说明见 [failed-attempts.json](v2bx-observation-stability-2026-10-13/failed-attempts.json)。

## 审查与回归

独立审查发现导出在源缺失时可能创建源文件，以及数据库父目录alias绕过早期冲突检查；均加入先失败后通过的回归并修复。旧fd晚写风险也已加入测试和指标。新协议格式、源锁与官方规则均经过失败／修正／通过对照。

最终全仓687项，667通过、20跳过、0失败，169.466秒；Bash/Python语法、ShellCheck、diff与归档脱敏／链接／hash核查通过。先前685项回归运行发生在最后两个边界修正前，保留为过程结果，不替代最终回归。

## 仍未完成的部署工作

TUIC/Hysteria1/Hysteria2的明确认证失败仍缺可靠的源字段；缺来源行不跨记录猜IP。Hysteria1原始日志会含提交凭据，采样器不会保存它；上游应评估脱敏且带connection RemoteAddr的事件。Hysteria2需区分真正认证拒绝、带宽策略与masquerade，任意404不等于错误密码。具体源函数、依赖版本和后续补丁验收条件见 [结构化事件评估](../v2bx-structured-events.md)。没有重编译上游或宣称这些检测已解决。

IPv6真实协议、UDP应用载荷、多用户同时直连／中转、其他传输、压力、生产日志权限／重开与实际服务生命周期不在本轮。目标VPS连续仅观察需要实际版本、日志路径、入口来源、已有acquisition/profiles和容量证据。得到这些后才能设计生产采集和误报观察；自动封禁与连接限速保持后续阶段，带宽型DDoS仍依赖上游。

# VPS216：查阅内核原理后重新配置 TCP

后续已完成[两轮循环复审与材料修复](2026-11-03-vps216-tcp-review.md)，补齐完整配置证据、修正归档回退测试的临时目录依赖，并新增隔离转发顺序验证和线上复验。TCP 配置保持本报告的已验证值。

2026-11-03，按用户明确授权完成重新配置。先核对资料和运行基线，逐项改变参数并验证，之后集中持久配置、独立复核并提交事务。没有重启业务或宿主机，没有改变现有端口限制。

## 查阅资料与实施依据

本轮实际下载了以下资料，URL、内容 SHA256 及下载路径见 [sources.json](2026-11-03-vps216-tcp-retune/sources.json)。正文未将外部网页作为操作指令执行。

- [Linux v6.18 IP sysctl 文档](https://github.com/torvalds/linux/blob/v6.18/Documentation/networking/ip-sysctl.rst)：重试、缓冲自适应、metrics 缓存、TIME_WAIT、全局 TCP 内存和 UDP 内存参数的作用。
- [Linux v6.18 TCP 初始化实现](https://github.com/torvalds/linux/blob/v6.18/net/ipv4/tcp_ipv4.c)：核对实际初始化行为，特别是 orphan_retries=0 与文档所述有效重试语义的区别；同时下载了 tcp.c。
- [tc-fq(8)](https://man7.org/linux/man-pages/man8/tc-fq.8.html)：fq 按流调度并支持 TCP pacing，适合本机代理发起的连接；不是自动获得更高带宽的保证。
- [AnyTLS 官方协议](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)：会话层复用结构为 Stream → Session → TLS → TCP，UDP 使用 UDP-over-TCP v2。不能套用原生 QUIC 代理的 UDP 调优结论。另核对了 [sing-box AnyTLS 入站文档](https://sing-box.sagernet.org/configuration/inbound/anytls/)。

运行内核是 XanMod 6.18.8，有自定义补丁的可能，因此没有只照上游文档硬写参数。通过 `unshare -n /usr/sbin/sysctl ...` 在一次性网络命名空间读取了本机默认值，七项均与本轮目标一致；没有向该命名空间或宿主机写入全局 tcp_mem。

## 保留的配置与七项实际变更

| 参数 | 变更前 | 变更后 | 原理 |
| --- | --- | --- | --- |
| tcp_syn_retries | 3 | 6 | 恢复主动连接建立时的内核默认重试容错 |
| tcp_synack_retries | 2 | 5 | 恢复被动连接握手的默认容错，不把更快放弃视为提速 |
| tcp_orphan_retries | 1 | 0 | 恢复这台内核实际初始化值，由内核按连接情况选择；不是不重试 |
| tcp_fin_timeout | 15 | 60 | 恢复孤儿连接 FIN_WAIT_2 的默认保持期；不影响所有正常 TCP 连接的寿命 |
| tcp_autocorking | 0 | 1 | 恢复有发送队列积压时合并连续小写入的默认行为 |
| tcp_no_metrics_save | 1 | 0 | 允许保存连接指标；不能笼统认定复用 RTT 等指标必然降低性能 |
| tcp_tw_reuse | 1 | 2 | 恢复仅回环 TIME_WAIT 复用的默认范围；当前无端口耗尽证据 |

保持 BBR、实际 eth0 fq、16MiB TCP 收发缓冲上限、自动接收缓冲调节、UDP 参数、队列参数及所有其他网络运行值。系统开启 TFO 不代表应用启用，本轮没有修改 V2bX 的 TCPFastOpen=false，也没有声称获得 TFO 收益。

没有再次缩小全局 tcp_mem：仍为 122112/244224/488448 页，与变更前相同。该值是阈值，不是立即预分配；本轮没有负载证据支持按固定比例调整它。保留不等于已证明满载时最优，1GB 主机的长期容量仍需实际中转负载评估。

把原三份实际文件中的 active net.* 设置集中到 `/etc/sysctl.d/99-zz-crowdbastion-anytls.conf`，共 64 项。原文件中对应行改为明确的 consolidated 注释，非网络设置及 `/etc/sysctl.d/99-sysctl.conf` 别名保留。未全量运行 sysctl --system，也未重载无关设置。

## 本轮验证结果

变更前连续三次全量 LAPI 查询读取 15,350 条记录，耗时 0.522、0.455、0.486 秒；无新增 UDP 缓冲错误、TCP 内存压力或监听溢出。

应用阶段每次只改一个参数，读回并查询 LAPI、检查回环 8443 TCP 连接后才继续。七次 API 耗时为 0.476、0.435、0.475、0.416、0.437、0.455、0.476 秒，全部通过；之后才原子替换持久配置。独立验证见 [verification.json](2026-11-03-vps216-tcp-retune/verification.json)：

- 64 项运行值、文件摘要、唯一 active 赋值及 systemd 开机配置解析全部匹配。
- 独立三次 API 查询为 0.511、0.501、0.427 秒；决策适用网络 15,350、内核网络 15,350、遗漏 0。
- 短观察窗口 TCP OutSegs 增加 416，重传增加 0；双栈 UDP 缓冲错误、TCP 内存压力、监听溢出和丢弃均无新增。该窗口负载低，不能代表全天或满载表现。
- V2bX/CrowdSec/Bouncer/Docker PID 保持 661/6185/1306/700，NRestarts=0。eth0 仍为 fq；本轮即时 vmstat 采样 I/O wait 为 0，首行历史平均数不作为即时数据。
- 5244/51080 双栈回环可访问，已有公网限制及 CrowdSec 第一条跳转保持。独立外部 IPv4 TCP 测试中 SSH/8443 可连接、5244/51080 超时，公网 HTTPS 首页返回 200，见 [external.json](2026-11-03-vps216-tcp-retune/external.json)。未冒称外部 IPv6 实测。

## 回退、审查及交付状态

远端 root 私有目录 `/var/backups/crowdbastion/tcp-retune-20261103/` 保存原配置、候选配置、immutable manifest、逐项应用证据、独立验证和回退脚本。本轮使用独立事务锁和 15 分钟回退定时器；最终持同锁再次核对文件/运行值，写入 committed 后停止定时器并确认 inactive。已经提交本轮维护配置；不是 git 提交。

独立审查指出失败路径无条件停回退定时器的风险，以及单项读取失败会中止其他参数恢复的问题，均在实际应用前修正。当前失败路径只有在回退确实成功、errors=[] 时才停止定时器；回退逐项捕获错误，恢复其他项，汇总失败并保留漂移值。

[隔离回退检查](2026-11-03-vps216-tcp-retune/scripts/check-rollback.py)验证：一个运行值读取缺失时其余参数仍恢复、配置恢复且新增文件移除、之后重试可完成、外部修改值不被覆盖，四项通过；只操作本地临时夹具，没有执行生产回退演练。归档 Python AST 与 JSON 语法检查通过。相关 [维护脚本](2026-11-03-vps216-tcp-retune/scripts/)供审阅；未改产品代码、未跑无关全仓测试、未提交或推送仓库。

## 结论及边界

本轮重新配置已通过配置一致性与短时运行检查并保留生效，没有重现前轮 API 超时。不能据此认定此前存储/API 间歇异常的根因已经查清或修复。

本轮恢复的是有文档和本机默认值依据的稳健 TCP 行为，保留已有有效基础。没有中转端可控测试环境、真实客户端流量对照、完整 AnyTLS 鉴权/协议测试或长时间高峰观察，不能承诺吞吐提升百分比或称为最优参数。8443 来源白名单仍待中转出口 IP，属于独立未完成事项。

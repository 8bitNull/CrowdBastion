# VPS216 TCP 配置循环复审与修复

2026-11-03，用户要求“循环复审加修复”。本轮围绕已交付 TCP 配置、持久化、回退、端口限制和验证材料进行了两轮复审。未修改 VPS 业务配置或参数，未重启业务；隔离网络测试只在一次性子网络命名空间写入 per-net 设置，退出即销毁。

## 第一轮：独立审查与现场核对

两名独立审查者分别检查配置/资料依据和事务/回退路径。未发现 Critical/Important 问题：七项本机默认值适用、全局 tcp_mem 未被更改、配置集中顺序可解析，apply/rollback/commit 共用锁并有漂移和提交门禁。来源文件的大小及 SHA256 重新核对一致。

发现并修复两项轻微问题：

1. 完整 64 项 manifest、最终配置、现场 unshare 默认值输出只保存在远端，离线独立重算依据不足。现已补齐 [manifest.json](2026-11-03-vps216-tcp-review/manifest.json)、[final-sysctl.conf](2026-11-03-vps216-tcp-review/final-sysctl.conf)、[local-kernel-defaults.txt](2026-11-03-vps216-tcp-review/local-kernel-defaults.txt) 和 [状态摘要](2026-11-03-vps216-tcp-review/inventory-summary.json)。manifest 中 staged 是不可变的制备状态，状态摘要另证实事务已有 committed 标记。
2. 归档回退测试硬编码读取 `/tmp/crowdbastion216-retune/rollback.py`，临时目录清空后不能复现，也可能读取与归档不同的版本。已改为读取同目录 rollback.py，加入生产 base/proc 路径唯一匹配及完整重定向检查。修复位置：[check-rollback.py](2026-11-03-vps216-tcp-retune/scripts/check-rollback.py)。

修复后在原目录运行四项故障检查通过；仅复制 check-rollback.py 和 rollback.py 到一个全新目录、从 `/` 工作目录执行，也全部通过。覆盖单项缺失时继续恢复其他参数、原配置恢复/新增文件移除、重试完成部分回退、保留外部漂移值。测试只操作本地临时夹具。

## 第二轮：修复后复审与实际行为验证

两名审查者重新核对相应修复，均未发现新的待修问题。本地独立重算最终配置 SHA256 与 manifest.after 匹配，64 项唯一赋值与 settings 完全相等，七项现场默认值与 changes 相等。

还核实了仅解析配置文本不能覆盖的 forwarding 副作用：Linux v6.18 [devinet.c](https://github.com/torvalds/linux/blob/v6.18/net/ipv4/devinet.c#L2423) 开启转发会改变 all.accept_redirects、default.forwarding 和已有接口 forwarding，但这些变化与当前目标相容；ip_forward 和 conf.all.forwarding 指向同一字段。

在新子 netns 中显式先设 IPv4 ip_forward=0，再按实际字典顺序重放 16 项 per-net IPv4/IPv6 接口与转发设置，结果全部匹配目标，mismatches 为空。没有写 tcp_mem 或其他全局参数。此为隔离的顺序/副作用测试，不冒称宿主机冷启动或完整网络初始化演练。[结果](2026-11-03-vps216-tcp-review/isolated-forwarding-replay.json)、[检查脚本](2026-11-03-vps216-tcp-review/inspect-review.py)。

## 新的现场复验

[verification.json](2026-11-03-vps216-tcp-review/verification.json) 和 [external.json](2026-11-03-vps216-tcp-review/external.json) 为本轮实际新查询：

- 64 项运行值、持久文件摘要、开机配置解析、唯一赋值均通过。三个维护回退定时器均 inactive。
- API 连续三次为 0.536、0.462、0.462 秒；适用封禁网络 15,350，内核网络 15,350，遗漏 0。
- 短观察窗口 OutSegs 增加 425、重传增加 0；UDP 双栈缓冲错误、TCP 内存压力、监听溢出/丢弃均无新增。这不代表满载或全天统计。
- V2bX/CrowdSec/Bouncer/Docker 的 PID 与原基线一致，NRestarts=0；eth0 仍运行 fq。当前即时 I/O wait 为 0，不以 vmstat 首行的历史平均数替代即时数据。
- 外部 IPv4 TCP：SSH 和 8443 可连接，5244/51080 超时；公网 HTTPS 首页 200。两个私有端口的双栈回环连接正常，CrowdSec 首条跳转保持。没有进行外部 IPv6 业务实测。
- 原有 `session-86.scope` 历史失败记录仍在，没有为使状态变绿而清除；它不是本轮新增的核心服务失败。

## 结论及范围

两轮复审后没有需要继续修复的已知配置或回退问题；两项复核材料问题已修复。当前已验证的 TCP 参数保持生效，不追加无依据的调参。没有修改其他未提交的产品代码，没有提交或推送仓库。

本轮未证明历史磁盘/API 间歇异常的根因已解决，未完成真实中转链路的吞吐/延迟对照、AnyTLS 鉴权/协议全流程或宿主机冷启动。8443 中转来源白名单仍缺用户提供的出口 IP。已有端口 oneshot 只保证开机加载，不承诺管理员整套重建防火墙后自动自愈。这些是已明确的范围边界，不能写成全部防护和性能已验收。

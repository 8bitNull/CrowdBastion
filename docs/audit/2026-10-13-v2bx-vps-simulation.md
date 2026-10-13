# V2bX 混合入口：隔离 VPS 网络模拟

本轮验证防护执行位置与决策同步的网络层行为。探针为数值来源回显 TCP/UDP 服务，不运行 V2bX，不将本轮结果标为 xray/sing/hysteria2 协议握手或认证检测验收。现有日志观察规则的官方引擎验证仍见 [离线日志记录](2026-10-13-v2bx-observation.md)。

## 环境与隔离

复用已有 QEMU 客机磁盘的独立副本，TCG、1 vCPU、1024 MiB、Linux 6.1.0-47-amd64，无外网 NIC、无共享宿主目录，磁盘 snapshot=on。客机以实验 init 启动，不是 systemd 服务生命周期测试。宿主 `unshare --net --mount` 返回 Operation not permitted，故未在宿主运行任何防火墙/路由修改；操作只在 QEMU 客机的私有网络和 mount namespaces 执行。

客机内分离受控测试客户端、健康客户端、落地和中心网络命名空间。探针每次建立新 TCP/UDP socket，校验随机回显 token 和服务收到的 peer IP。DROP 必须由真实 nftables 计数增加佐证；进程超时不能代替阻断证据。

使用真实官方 CrowdSec LAPI/Bouncer，gost/realm，以及 Linux DNAT/MASQUERADE。源脚本/二进制 SHA-256 见 [sources.json](v2bx-vps-sim-2026-10-13/sources.json)，实际磁盘二进制与源树逐一核对，见 [disk-binaries.json](v2bx-vps-sim-2026-10-13/disk-binaries.json)。`landing.py` 等是仅用于本轮验收的临时探针，不是生产安装器。

## 两组矩阵

第一组复用 `tests/verify_remote_bouncer.py`：中心运行真实 LAPI，通过 cscli 创建/解除测试决策，中转使用官方 Bouncer。覆盖 gost/realm/SNAT × IPv4/IPv6 × TCP/UDP，共 12 个案例，分别断言正常连接、封禁后阻断、DROP 计数增加、健康客户端通行和解封恢复；另检查决策过期、中心断连/恢复、Bouncer/LAPI 重启及错误密钥拒绝。

第二组把真实 Bouncer 放在落地命名空间，只挂 INPUT，使用隔离的合成决策 API；覆盖直连、保源 DNAT、gost 代理 × IPv4/IPv6 × TCP/UDP，共 12 个案例。直连与保源须核实落地 peer 为测试客户端出口，封禁后 DROP 增加且健康客户端正常，解封恢复。代理须核实 peer 为中转地址，落地封禁客户端 IP 不能阻断代理会话，且 DROP 不增加；这是执行位置限制的预期证据，不是“防护通过”。正确的中转入口阻断由第一组另行验证。

两组均有独立健康客户端；代理与直连使用相同落地回显服务端口，可对照共享中转流量在用户 IP 决策下保持可用。未测试透明代理 TPROXY、PROXY header、防伪造元数据、容器网络、已有会话或所有中转软件。

## 失败与时限对照

首轮使用仓库原有 5 秒探针进程等待预算，两个矩阵均因探针进程超时失败，未算作成功或封禁。LAPI 认证预检和配置生成已通过。原始失败结果见 [attempt-1-results.json](v2bx-vps-sim-2026-10-13/attempt-1-results.json)，QEMU 状态见 [attempt-1-runner.json](v2bx-vps-sim-2026-10-13/attempt-1-runner.json)。QEMU 正常退出不代表客机验收通过。

隔离对照中，访问本机关闭端口的最小 Python socket 启动耗时约 0.25 秒，完整探针约 2.23 秒；五个完整探针并发时完成耗时约 12.22 秒，证实 TCG 单核导入/进程启动竞争超过原 5 秒预算。空闲对照见 [startup-idle.json](v2bx-vps-sim-2026-10-13/startup-idle.json)，并发对照见 [startup-loaded.json](v2bx-vps-sim-2026-10-13/startup-loaded.json)。

后续轮次只在客机副本中将探针进程等待预算从 5 秒改为 20 秒，套接字超时仍为 1.5 秒；仓库现有测试和生产默认不变。该调整不能补算首轮通过，亦不能用于推算真实 VPS 性能。保留副本见 [verify_relay_network-simulation.py](v2bx-vps-sim-2026-10-13/verify_relay_network-simulation.py)。

## 调整后轮次的实测结果

实际版本：CrowdSec/cscli 1.8.1-909b5157，Firewall Bouncer 0.0.36，gost 3.3.0，realm 2.9.6。运行耗时 326.67 秒，任务退出 0，QEMU 退出 0，无超时；完整结构化结果见 [results.json](v2bx-vps-sim-2026-10-13/results.json)，启动参数/退出状态见 [runner.json](v2bx-vps-sim-2026-10-13/runner.json)。没有将首轮失败改为通过。

| 实际检查 | 调整后轮次结果 |
| --- | --- |
| 中转入口：gost/realm/SNAT × IPv4/IPv6 × TCP/UDP | 12/12 通过；测试来源阻断、DROP 增加、健康来源正常、解封恢复 |
| 落地：直连 × IPv4/IPv6 × TCP/UDP | 4/4 通过；peer 是客户端，落地按客户端 IP 阻断，健康来源正常，解封恢复 |
| 落地：保源 DNAT × IPv4/IPv6 × TCP/UDP | 4/4 通过；peer 保留客户端地址，落地封禁/恢复有效 |
| 落地：gost 代理 × IPv4/IPv6 × TCP/UDP | 4/4 符合预期；peer 是中转，落地客户端 IP 决策不能阻断代理；健康来源与共享中转正常 |
| 真实 LAPI 同步与故障恢复 | 配置生成、矩阵、在线/断连到期、断连保留有效 ban、健康来源、恢复解封、Bouncer 重启、LAPI 重启、错误密钥拒绝，共 10 条条件全部通过 |

原有 `test_relay_network.py` 10 项、`test_remote_bouncer_lab.py` 7 项定向回归均通过。仅新增验收报告和临时探针归档，未更改生产实现；本轮未重复完整测试仓库，之前的 662 项全仓结果仍属于离线实现阶段。

## 验收边界

只有全部矩阵断言、任务成功标记与 QEMU 正常终止齐备，才报告调整后轮次通过。未完成或失败轮次单列，不用旧报告替代本轮结果。

这些实验不验证 V2bX 当前部署版本、真实三内核协议失败日志、面板动态配置、来源信任、公网线路、容量阈值、带宽型 DDoS 清洗或长期运行。下一轮真实 core 模拟需固定 V2bX 构建与受控面板配置，再逐协议生成健康/失败日志，对照已经实现的日志投影；无失败事件的协议仍需明确保留检测缺口。

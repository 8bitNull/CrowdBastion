# V2bX 三内核：真实协议与日志隔离验收

本轮使用官方 V2bX v0.4.0 和真实 sing-box 1.12.0 客户端，受控 UniProxy API 提供临时节点与账号。最终客机结果为 **26/26** 基础组合／路径案例通过，完成 **78** 个正常、错误凭据、恢复阶段；日志来自实际运行程序，没有用构造日志代替。UDP 中转显式使用 gost `keepalive=true&ttl=30s` 保持 QUIC 会话，不能将此结果泛化到默认单次响应 UDP 转发。失败轮次也单独保留。

## 程序、拓扑与证据

官方发布包 SHA-256 经 release digest 核对。V2bX 对应提交 `3deccaae00d168fd049f8a8659656664f25ee301`，嵌入 xray 25.9.11 对应 fork、sing-box_mod 1.13.0-alpha.5、Hysteria core/v2 2.6.3。客户端 1.12.0 用于保留 Hysteria1 支持。此版依赖与前轮分析的 HEAD `71277de` 不同，不能把两版结果混为兼容性保证。完整版本和校验值见 [sources.json](v2bx-real-protocol-2026-10-13/sources.json)。

独立 QEMU TCG 客机，2 vCPU／1536 MiB、Linux 6.1.0-47，无外网 NIC、无宿主共享目录、snapshot 磁盘；客机内部网络命名空间分离客户端、中转和落地。宿主不修改防火墙、路由或生产配置。客机使用实验 init，不验证 systemd 服务生命周期。

同一个 V2bX 进程同时启动三内核、13 节点；直连和代理中转访问相同落地端口。真实 SOCKS 客户端通过每种隧道请求落地本机 TCP HTTP 服务，每次校验随机响应令牌。正确凭据和恢复必须得到精确响应，错误凭据必须在有效本地 SOCKS negotiation 后不能取得响应；监听或进程存活不能替代业务成功。错误阶段的“不能取得响应”与“日志明确记录认证失败”分别统计。

直连成功日志须出现 `10.231.1.2`，gost 中转成功日志须出现 `10.231.3.1`；来源只取程序明确连接字段。gost 为 TCP 或 UDP 代理，QUIC 协议仍发生实际握手。源码、客机载荷 hashes（31 个打包文件逐一从磁盘读回核对）、结构化原始断言见 [归档目录](v2bx-real-protocol-2026-10-13/results.json)。不归档私钥、原始配置和原始账号日志；实验脚本中的固定账号仅为无生产用途的合成凭据。

## 实际结果

| 内核 | 协议 | 直连 | gost 中转 | 直连错误凭据的适配日志 |
| --- | --- | --- | --- | --- |
| xray | vmess | 通过 | 通过 | auth_failure |
| xray | vless | 通过 | 通过 | auth_failure |
| xray | shadowsocks | 通过 | 通过 | 无适配事件；不可据此推断无错误日志 |
| xray | trojan | 通过 | 通过 | fallback_candidate |
| sing | vmess | 通过 | 通过 | protocol_rejection |
| sing | vless | 通过 | 通过 | auth_failure |
| sing | shadowsocks | 通过 | 通过 | 无适配事件；不可据此推断无错误日志 |
| sing | trojan | 通过 | 通过 | protocol_rejection |
| sing | tuic | 通过 | 通过 | 无适配事件；不可据此推断无错误日志 |
| sing | anytls | 通过 | 通过 | 无适配事件；不可据此推断无错误日志 |
| sing | hysteria | 通过 | 通过 | 无适配事件；不可据此推断无错误日志 |
| sing | hysteria2 | 通过 | 通过 | 无适配事件；不可据此推断无错误日志 |
| hysteria2 | hysteria2 | 通过 | 通过 | 无适配事件；不可据此推断无错误日志 |

客机任务退出 0、QEMU 退出 0、无超时，耗时 226.13 秒；验收还检查全 26 案例和每例阶段断言，QEMU 退出码本身不构成通过证据。完整 [results.json](v2bx-real-protocol-2026-10-13/results.json) 与 [runner.json](v2bx-real-protocol-2026-10-13/runner.json) 可复核。

## CrowdSec 观察和检测缺口

真实程序日志投影共 36 条，其中 eligible 失败投影 5 条。按来源／内核／协议去重后，将每组一个实际失败事件与全部非 eligible 正常／fallback／中转事件送入官方 CrowdSec 1.8.1 的临时引擎：读取 36 条，产生 5 个观察告警、**0 个决策**。去重用于避开场景 1 秒 blackhole 对批量回放的影响，不声称逐条告警率；没有修改事件来源或编造缺失的认证日志。见 [replay-results.json](v2bx-real-protocol-2026-10-13/replay-results.json)。

真实日志暴露两处格式漏检：sing 节点标签包含嵌套方括号的面板地址；Xray VMess 明确认证失败前有 drain/read-timeout 包装。本轮只适配有数值端点及明确认证理由的固定格式，标签、UUID、目标与原始错误不会输出。两个先失败后通过的回归测试保护此行为；普通 timeout 不转换为认证失败。

当前日志适配范围仍集中于 Xray VMess/VLESS、sing VMess/VLESS/Trojan，以及 Hysteria2 连接事件。Xray Trojan 的 `not a valid user` 属于 `fallback_candidate`，即便本轮错误凭据最终失败也不能普遍转换为封禁依据。Shadowsocks、TUIC、AnyTLS、Hysteria1/2 的认证失败没有在本轮统一变成可采信告警；无适配事件也不等于无服务端日志。不能把全部协议业务验收通过表述为全部协议行为检测已覆盖。

日志窗口在客户端终止后最多等待 5 秒，连续 1 秒无变化后结束；仍明确标记不能排除异步延迟 teardown，不能声称逐请求的精确日志归因。来源验收使用成功连接字段，观察回放使用实际固定投影，不依赖阶段名字判定认证失败。

## 失败轮次与修正

本机预检首轮 11/13，修正 TUIC 缺少 ALPN h3、sing Hysteria2 的 BBR／带宽 fixture 组合后 13/13。受控面板最初缺 `network_settings` 时触发发布版 Xray nil StreamSetting；提供显式空设置，没有修改上游程序。首个客机载荷遗漏 Python 传递依赖，在任何协议案例开始前退出；随后将项目 lib/*.py 打包。

首个完整客机轮次保留原始断言：Xray 默认 HTTP 嗅探将 Host localhost 变为出站域名，无外网客机向 ::1:53 查询失败；临时探针改用数值 Host。部分中转首阶段在 gost 监听就绪前发起，增加实际 ss 监听就绪等待。诊断证据为真实 Xray `failed to open connection ... lookup localhost ... connection refused`，没有将基础设施失败算作攻击阻断。第二轮完整矩阵为 22/26，四种 QUIC 中转仍失败；单独诊断发现 gost 默认 UDP keepalive=false，在首次 WriteTo 返回后关闭虚拟连接。同一客户端 socket 在 debug 日志中反复出现不同上游端口，与 gost 二进制的 go-gost/x v0.16.0 对应源码的条件 Close 一致。源码 URL、SHA-256 与节选一并归档，见 [gost-source-check.json](v2bx-real-protocol-2026-10-13/gost-source-check.json)。实验 UDP 中转改为明确 keepalive=true、ttl=30s 后再重跑完整矩阵；这些参数不是生产容量或安全阈值。失败统计及各轮结果见 [failed-attempts.json](v2bx-real-protocol-2026-10-13/failed-attempts.json)。

## 验证与范围限制

仓库回归：664 项，644 通过、20 跳过、0 失败；Bash/Python 语法、ShellCheck、diff 空白检查通过。官方引擎的原有 synthetic 13 条／5 告警／0 决策测试也重跑通过；上述真实日志回放另有独立结果，不混用。

本轮覆盖 IPv4 下 13 个基础内核／协议组合，TCP、TLS、QUIC 传输，Shadowsocks 一个 `chacha20-ietf-poly1305` cipher，以及 TCP HTTP 应用载荷。没有验证所有 WS/gRPC/REALITY/XHTTP/mux/加密套件、IPv6 下真实协议、UDP 应用代理载荷、实际 fallback 后端、典型网络故障、生产用户并发和攻击负载。前轮网络回显的 IPv6 或 Bouncer 结果不能替代这些项目。

本轮不新增封禁决策，不把中转地址当攻击用户。代理中转时落地看到中转来源，不能通过封中转来代替用户封禁；执行位置的隔离网络实验证据另见 [前轮记录](2026-10-13-v2bx-vps-simulation.md)。本机规则不能解决上游链路带宽已经被打满的问题。下一步应在指定生产版本先观察真实脱敏日志和误报，再按协议扩展可采信事件及执行位置。

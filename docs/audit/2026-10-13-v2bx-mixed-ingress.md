# V2bX 多账号混合入口、IPv6 与 UDP 应用载荷验收

2026-10-13，在无外网 NIC、无宿主共享目录的 QEMU 客机内，使用此前完成验收的实验构建，扩展两个有效账号的直连／共享中转及错误凭据对照。**26 个基础内核／协议／地址族组合取得有效配置下的通过证据；不是同一套双栈监听配置全部通过。** 原始主矩阵为 25/26；hysteria2 独立内核的 IPv4 使用另一客机的显式 IPv4 监听对照通过，原失败完整保留。

## 程序与隔离范围

服务端基于 V2bX v0.4.0 commit `3deccaae00d168fd049f8a8659656664f25ee301`，包含此前的 hysteria2 与 sing QUIC 实验补丁。最终二进制 SHA256 为 `4b475ac949676bfb0da05f840e14ce5ab1fcc506b946e2fcc0252b59a69d4c2f`，与上一阶段一致；客户端是官方 sing-box 1.12.0。源码／依赖／补丁来源见 [sing QUIC 验收](2026-10-13-v2bx-sing-quic-events.md)。

QEMU 使用 TCG、1536 MiB RAM、2 vCPU；客机内另建私有网络与挂载命名空间。有效账号 A 直接到落地，有效账号 B 经 gost 代理；错误凭据分别走直连与中转。健康用户、异常用户和中转在落地可见的 peer 不同：

| 路径 | IPv4 peer | IPv6 peer |
|---|---|---|
| 健康直连 | 10.231.2.2 | fd42:231:2::2 |
| 异常直连 | 10.231.1.2 | fd42:231:1::2 |
| 共享中转 | 10.231.3.1 | fd42:231:3::1 |

只依据实际 peer 排除共享中转，没有恢复中转后用户 IP，也没有封禁共享中转。

## 实际协议与载荷结果

| 内核 | 基础协议 | 两个地址族的覆盖数 |
|---|---|---:|
| xray | VMess、VLESS、Shadowsocks、Trojan | 8 |
| sing | VMess、VLESS、Shadowsocks、Trojan、TUIC、AnyTLS、Hysteria1、Hysteria2 | 16 |
| hysteria2 | Hysteria2 | 2 |

每组合执行基线、混合错误凭据、恢复三个阶段。两个不同有效账号在所有阶段分别走直连和中转；混合阶段加入两个错误客户端。TCP 使用 SOCKS CONNECT，UDP 使用 SOCKS UDP ASSOCIATE，均校验 48 字节随机回显载荷。IPv6 用例同时使用 IPv6 外层入口和后端 `::1` 应用目标；IPv4 后端为 `127.0.0.1`。不是仅以 QUIC 使用 UDP 来代替应用数据报验收。

配置对照合并后共 78 阶段、416 次探针：156 次健康 TCP、156 次健康 UDP 均取得正确载荷，104 次错误账号探针均未取得载荷；SOCKS 协商、探针格式和进程存活断言通过。26 组健康基线均有实际直连／中转 peer 日志证据。全部阶段的 TCP／UDP **探针请求区间**存在重叠：子进程先在同一个客机 monotonic 时刻开始请求，再独立测量区间；这不等于服务端抓包证明每一毫秒都在同时处理认证，也不是压力／容量测试。

Shadowsocks 使用 chacha20-ietf-poly1305；它的原生 UDP 需要单独的 gost UDP 监听，不能沿用其他 TCP 隧道协议的 TCP 中转配置。TUIC/Hysteria1/2 和 Shadowsocks 的 UDP 中转显式启用 `keepalive=true&ttl=30s`。AnyTLS 的实际 UDP 应用回显也通过。

## 监听地址族发现与对照

原主矩阵统一使用 `ListenIP=::`，其余 25 用例通过，hysteria2 独立内核 IPv4 的健康基线失败且未产生认证拒绝事件。固定依赖 `hysteria/extras/v2@v2.6.3/correctnet` 会根据解析后的地址选网络：`::` 选择 `udp6`，不是双栈通配监听。该路径由 `core/hy2/config.go` 的 `getConn` 调用。

另一个隔离客机仅将监听改为 `10.231.3.2`，对 hysteria2 独立内核 IPv4 重做全部三阶段，TCP／UDP、两账号、来源与并发检查全部通过。原矩阵使用 `::` 的 IPv6 用例通过。因此，**不能从设置 `::` 推断 hysteria2 core 已开放 IPv4**；生产应按实际入口分别核验监听与连接。没有修改该内核的网络行为。

原始失败在 `full-matrix-results.json`；独立对照在 `hy2-ipv4-results.json`；`results.json` 逐行注明使用哪套配置。主矩阵客机任务结果是 failed，QEMU 正常关机退出 0 不能替代业务结果；主矩阵运行 868.19 秒，独立对照 53.21 秒。

## 实际事件与官方引擎

配置对照得到 157 条固定投影，其中 40 条合格直连失败。按来源／内核／协议去重后，137 条记录进入官方 CrowdSec 1.8.1：严格核对 **20 组观察告警、0 决策**，恰为两个地址族各 10 组。共享中转的相应失败组完整存在但均被排除，健康 peer 未成为告警来源。

每族的检测组为 xray VMess/VLESS，sing VMess/VLESS/Trojan/AnyTLS/TUIC/Hysteria1/Hysteria2，以及 hysteria2 core Hysteria2。sing VMess/Trojan 的明确协议拒绝仍按既有规则解释；不把所有未回显都称为认证拒绝。两个内核的 Shadowsocks 及 xray Trojan 仍不具备本次自动归因场景覆盖；完整连接验收通过不代表每个协议都有认证失败检测。去重用于隔离引擎批量告警／blackhole 核查，不是逐行告警率测试。

规则仍未安装，场景保持 `remediation: false`。这轮未部署生产采集、Bouncer、自动封禁或限速。

## 失败轮次、检查与复现

前四轮均主动中止、不计最终通过：第一轮未强制并发断言；第二轮探针字段校验与同步失败边界不足；第三轮严格断言发现 TCG 启动错开；第四轮源码核对发现 Shadowsocks 缺少 UDP 中转。修改后完整重跑，摘要见 `failed-attempts.json`。一次宿主分析命令未设置 PyYAML 依赖路径，随后使用同一测试依赖路径重跑全部断言通过，未修改产品代码。

新增探针合同测试 5/5、现有日志适配测试 24/24 通过；严格验收断言 8/8、实际官方引擎回放通过，独立审查核对探针、同步、监听地址族归因与证据。这轮只新增实验脚本与文档，未重复整仓测试，上一阶段整仓结果不冒充本轮重新运行。

证据在 [归档目录](v2bx-mixed-ingress-2026-10-13/manifest.json)。保留脚本、实际固定投影、原始与组合结果、构建来源、测试输出、失败摘要及哈希；不含原始业务日志、运行配置、SQLite、私钥、二进制或磁盘镜像。fixture 中只有公开的合成实验账号。

复现需要前几轮准备的 QEMU 内核／镜像与工具、相同实验构建和官方客户端。先执行归档 `package.py` 与 `runner.py`，另执行 `hy2-ipv4-package.py` 生成独立对照，运行该目录生成的 runner；随后 `combine.py`、`analyze.py` 和仓库 `tests/verify_v2bx_real_observation.py`。宿主分析与回放需设置包含 PyYAML 的 `PYTHONPATH`；这些脚本引用实验目录，不是生产安装器。

范围不含所有传输／TLS 模式／密码套件、所有协议同时施压、持续高并发、链路性能或生产公网路径。两个有效账号都来自同一个健康网络命名空间，并非两条公网线路。实际 VPS 版本、入口来源、采集与 profiles 仍需部署验收，不能把 QEMU 吞吐用于限速阈值或称为带宽 DDoS 清洗。

# V2bX sing QUIC认证拒绝实验验收

在固定V2bX v0.4.0与sing依赖的临时副本补齐TUIC、Hysteria1/2明确认证拒绝日志，使用固定安全logger前缀、脱敏事件和每Service日志总量限制。最终版本真实客户端专项36/36、QUIC边界5/5、三内核回归66/66通过；实际三内核投影回放官方CrowdSec1.8.1形成10组观察告警、0决策。没有替换生产程序、安装采集或启用自动封禁。

## 固定来源及实现

V2bX v0.4.0源码提交 `3deccaae00d168fd049f8a8659656664f25ee301`；sing-quic v0.5.0、wyx2685/sing-box_mod v1.13.0-alpha.5。临时源码位于 `/tmp/v2bx-sing-quic-20261013/source`，仅本地模块副本修改，未改全局Go缓存。V2bX go.mod添加两个相对本地替换，各依赖模块的go.mod/go.sum及V2bX go.sum不改。累积此前hysteria2 core补丁，用Go1.25.0、jsonv2及官方完整三内核build tags编译，版本明确标记 `v0.4.0-quic-observation-experimental`。

[配套补丁及重建说明](../../experimental/v2bx-sing-quic/README.md)、[版本／源文件／二进制哈希](v2bx-sing-quic-2026-10-13/provenance.json)、[实际buildinfo](v2bx-sing-quic-2026-10-13/buildinfo.txt)。最终实验二进制为 `/tmp/v2bx-sing-quic-20261013/V2bX-final`，不归档为生产发行包。

TUIC在未知UUID与token不匹配分支取当前QUIC connection的RemoteAddr；单session的sync.Once最多记录一次明确拒绝，脱敏sentinel避免服务关闭和等待流重复打印。Hysteria1保留Wrong password响应与原关闭code，移除 `auth_str=提交值`。Hysteria2只在密码查询失败分支记录；未将普通404、带宽政策拒绝、TLS错误和未提交认证的超时改为失败。

## 隐私修正与日志限额

初版JSON payload字段安全，但独立审查发现完整记录仍带继承的inbound面板URL前缀。最终版新增sing-box的ObservationLogger：从原standard factory派生 `v2bx-auth/协议` 固定标签，保持配置输出及级别，普通logger不改。未知logger实现或未知协议返回NOP，不能回退到可能敏感的原标签。三个Service显式注入该logger，nil不生成新增事件。实际能力仅验证标准factory；其他实现需单独接入并验收。

最终事件整行格式为带时间的ERROR固定前缀及 `v2bx-observation {JSON}`。JSON仅版本、core、protocol、auth_rejected和数值addr；新增记录没有面板URL、提交密码、UUID或访问目标。专项／边界脚本实际检查完整新增记录无HTTP(S)面板前缀和两份测试账号UUID，并检查payload字段白名单、Hysteria1 auth_str日志消失。原有其他日志仍可能含账户／面板信息，整份原始日志不能公开。适配器只接受固定安全前缀，拒绝初版带inbound节点标签的格式。

每个QUIC Service实例独立固定一秒窗口最多20拒绝记录；不是core总限额，节点数量增加会增加总上限。超额计数在下一窗口的新尝试输出无源地址的observations_dropped摘要，停止前可能未报告。相邻窗口可在滑动一秒内超过20条；同步日志仍受writer性能影响。不保留按IP增长的map，也不是连接限速或带宽清洗。

## 最终真实测试

[客户端专项36项](v2bx-sing-quic-2026-10-13/sing-results.json)：3协议分别直连／实际UDP socket中转的健康、错误凭据、恢复、目标不可达、TLS名称错误，共30项；TUIC两入口各增加正确UUID/错误密码；实际Hysteria2带宽政策拒绝1项；采样器重启后各协议错误凭据3项。常规单次错误认证仅一条事件。中转绑定127.0.0.2，实际记录该peer并通过CIDR标记relay_address、排除eligible；不恢复原用户地址。

[QUIC边界5项](v2bx-sing-quic-2026-10-13/controls-results.json)：普通HTTP/3 masquerade404无事件；同HTTP/3 transport两次错误认证产生2条；有效账号的真实BBR政策拒绝404无认证事件；TUIC真实TLS/QUIC已连接但不提交认证，服务因认证超时关闭，无认证事件；同连接45次错误认证加下一窗口1次，46次均404，输出21拒绝事件及25丢弃计数，摘要不进入认证投影。重复认证的对端endpoint相同；不以时间/IP相同判断为重复尝试。

[三内核回归66项](v2bx-sing-quic-2026-10-13/three-core-results.json)：13个core/protocol组合各4项健康/错误凭据/恢复/目标不可达，7项TLS/QUIC名称错误、1项响应超时以及6项轮转/程序或消费者重启/截断控制。累积补丁回归正常业务响应均校验随机TCP HTTP token。Shadowsocks完整性错误及Xray Trojan fallback候选维持中性，不强行增加认证场景。

以上是原生IPv4 loopback真实程序与UDP转发实验，不是新的QEMU跨主机、公网VPS、gost或全部transport/cipher验证。IPv6仅Go地址测试，UDP在此为QUIC传输，尚未验证UDP应用载荷或多用户同时混合入口。阶段事件归属基于客户端停止后短暂排空，异步日志仍是实验时序边界。

## 代码、采集及官方引擎

[Go集成-race输出](v2bx-sing-quic-2026-10-13/go-race.log)：6个新增测试覆盖固定字段、数值/无效/IPv6地址、100并发失败20输出/80丢弃、TUIC单session拒绝与去重、Hysteria1响应兼容/去凭据、Hysteria2三分支及logger前缀隐私。使用V2bX实际模块依赖图；不是仅独立sing-quic自己的旧依赖图。恢复上游三个认证分支的对照测试均失败，证明能捕捉缺失事件、UUID/凭据泄漏；安全logger和Python前缀也有先失败再通过证据。

Python日志24项通过；[独立synthetic引擎](v2bx-sing-quic-2026-10-13/synthetic-engine.log)读取24条投影、10告警、0决策，含三个QUIC protocol_rejection负例。规则仅放行匹配协议的auth_failure，仍remediation:false，且未生产安装。

[sing实际专项＋边界回放](v2bx-sing-quic-2026-10-13/sing-replay.json)：34投影、30 eligible，按source/core/protocol分组去重后7条进入引擎，3组告警、0决策；4条中转事件排除。

[三内核实际回放](v2bx-sing-quic-2026-10-13/three-core-replay.json)：35投影、13 eligible，分组去重后32条进入引擎，严格核对10组告警、0决策：xray VMess/VLESS；sing VMess/VLESS/Trojan/AnyTLS/TUIC/Hysteria1/Hysteria2；hysteria2 core Hysteria2。分组去重用于bulk blackhole检查，不代表逐行告警率或所有错误请求都可检测。

持久采样的重启及既有生命周期控制通过；旧fd晚写、copytruncate未读字节毁失及快速轮转等边界仍存在，不能声称日志无损。容量耗尽和风险计数仍按原观察采样器行为处理。

## 归档与后续

归档保留最后实际执行脚本、固定事件、边界payload、测试输出与哈希；不保留原始日志、数据库、私钥、配置凭据或二进制。脚本保留实际临时路径，依赖前阶段受控面板fixture、临时证书和sing-box1.12.0客户端；固定源码应用配套补丁并构建QUIC probe后，按客户端、边界、三内核脚本顺序运行，避免共享端口冲突。

初版前缀隐私失败、测试工具初始化问题和原分支对照记录见 [失败尝试](v2bx-sing-quic-2026-10-13/failed-attempts.json)。最终全仓689项，669通过、20跳过、0失败，165.433秒，见 [完整输出](v2bx-sing-quic-2026-10-13/full-unittest.log)。Bash/Python语法、ShellCheck、git diff --check及3份实验补丁的git apply --check通过。生产VPS仅观察、多用户同时混合入口、IPv6真实协议与UDP应用矩阵仍需后续验收；自动封禁、连接限速、带宽清洗未在此阶段实施。

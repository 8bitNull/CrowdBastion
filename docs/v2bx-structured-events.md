# V2bX 缺失失败来源：上游事件评估

最初评估未修改上游程序；后续已按授权完成 hysteria2 core 与 sing TUIC/Hysteria1/2 的临时fork补丁及真实客户端验收，见 [hysteria2补丁](../experimental/v2bx-hy2/README.md)、[sing配套补丁](../experimental/v2bx-sing-quic/README.md)和[最新报告](audit/2026-10-13-v2bx-sing-quic-events.md)。没有部署生产，也没有给缺失来源的错误行拼接用户IP。官方未打补丁包仍有原始日志覆盖缺口。

## 当前缺口和可选落点

| 内核／协议 | 实际证据 | 可评估的事件落点 |
| --- | --- | --- |
| sing TUIC | `authentication: unknown user` 失败行没有源地址；可能输出同一原因两次 | sing-quic v0.5.0 TUIC 服务的认证状态转移／连接上下文，直接取该 QUIC connection 的 RemoteAddr，避免后续stream重复记录 |
| sing Hysteria1 | `authentication failed, auth_str=...` 失败行没有源地址，且原始日志包含提交的凭据 | sing-quic v0.5.0 的服务认证分支直接记录固定拒绝原因与connection RemoteAddr，移除 auth_str 原文 |
| sing Hysteria2 | 错误凭据得不到业务响应，但现有INFO日志没有可靠认证失败事件 | sing-quic v0.5.0 Hysteria2 HTTP/QUIC auth处理处，区分认证false、带宽策略拒绝和masquerade；不把任意404解释为认证失败 |
| hysteria2 core | Authenticate(addr,auth,tx)接收net.Addr，未匹配时直接返回false；现有logger主要记录成功连接／断开 | V2bX core/hy2/user.go 的真实认证false分支，保留addr，额外接入脱敏结构化logger；认证尝试仅记录一次 |
| xray Trojan | 无效用户记录在fallback处理前，当前只记fallback_candidate | 若扩展，需要“认证失败且最终无fallback接管”的明确终态，不能从既有候选行直接启用封禁 |
| Shadowsocks | AEAD message authentication failed有来源，但损坏密文也可触发 | 保持integrity_failure；需要独立误报和负载证据才讨论检测场景，不改名为确定认证失败 |

源码版本、URL和SHA-256见 [本阶段源码证据](audit/v2bx-observation-stability-2026-10-13/log-source-check.json)。生产版本可能不同，应先核实实际buildinfo再选择落点。

## 建议的最小事件契约

事件由拥有当前连接的代码产生，包含带UTC偏移的时间、core、protocol、固定event_type、数值peer IP/port及非敏感node标识（若可可靠取得）。可新增单连接的opaque event_id用于抑制服务与stream层重复日志，但不得以UUID／密码作为ID。日志不得包含提交凭据、用户UUID、完整面板地址、访问目标或未经清洗的错误字符串。

`remote_addr`只代表可见网络对端。代理中转后它仍是中转IP，不能宣称恢复了用户出口。真实用户来源若另有可信元数据，需要单独验证信任路径、防伪造和执行位置，不能由本接口自行推导。

候选事件先区分：明确auth_rejected、integrity_failure、fallback_candidate、network_error、bandwidth_policy_rejected、正常连接。只有实际明确auth_rejected可进入认证观察；不得把握手超时、设备限制、政策拒绝、masquerade或404统一视为攻击。

## 后续补丁的验收条件

固定该发布版本与依赖；先在临时fork实现，保持客户端行为和面板兼容，不能用自行构造日志代替实际事件。正例为错误凭据确实被拒绝且同一次尝试仅产生一次脱敏事件。反例包含正常连接、重连、TLS错误、超时、目标不可达、带宽策略拒绝及fallback成功。测试直连与共享中转实际peer，限制异常负载下日志增长并保留丢弃计数。

随后核验日志采集偏移、轮转重开、程序／采样器重启、重复采集和官方引擎0决策，再进入指定VPS仅观察。hysteria2 core及sing三个QUIC协议补丁已完成隔离验收；自动封禁、限速与上游DDoS清洗不在此接口验收内。

当前hysteria2实现以认证回调为尝试单位，同一QUIC连接重复提交认证会生成多条事件；实际普通客户端单次错误认证产生一条。每core固定一秒窗口最多20条拒绝事件，超额丢弃计数在下一窗口的新尝试时输出，停止前可能未报告。未知或无效地址不输出；数值peer不等于可信用户出口。无node标识或event_id，避免将面板URL／UUID带入日志。

sing实现以每个QUIC Service为限额单位，固定窗口20拒绝事件、延迟丢弃摘要；TUIC单session最多一次，Hysteria2每次明确错误认证提交可记录。专用logger固定标签保留输出位置／级别，去掉新事件原inbound前缀中的面板URL；未知logger实现返回NOP。初版隐私缺口和最终重跑证据均有记录。实际三内核回放10组观察告警、0决策，不代表全部协议/transport均有可靠攻击归因。

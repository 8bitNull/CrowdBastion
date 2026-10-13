# V2bX hysteria2 结构化认证拒绝实验验收

已在临时源码副本实现并编译 hysteria2 core 认证拒绝补丁，真实客户端专项13/13、补丁版完整三内核回归66/66通过。没有替换生产程序、安装观察规则或启用自动封禁。sing的QUIC日志补齐仍属于后续阶段。

## 实现及来源

基于官方v0.4.0提交 `3deccaae00d168fd049f8a8659656664f25ee301`，Go1.25.0、jsonv2实验和官方三内核build tags。只修改原有 `core/hy2/hy2.go` logger初始化与 `core/hy2/user.go` 认证false分支，增加一个日志文件和两份测试；go.mod/go.sum保持原始哈希。实验版本明确标记 `v0.4.0-hy2-observation-experimental`。

[可应用补丁及重建说明](../../experimental/v2bx-hy2/README.md)、[源码／二进制SHA256](v2bx-hy2-structured-2026-10-13/provenance.json)、[完整buildinfo](v2bx-hy2-structured-2026-10-13/buildinfo.txt)。临时二进制位于 `/tmp/v2bx-hy2-structured-20261013/V2bX-experimental`，不作为生产发行包。

拒绝事件新增字段仅版本、core、protocol、固定auth_rejected分类和实际数值UDP对端。认证成功返回原有auth id，失败返回false/空id，未改变面板接口。日志调用在用户map读锁释放后执行。每个认证回调最多一条，重复HTTP/3认证提交是新尝试。每core固定一秒窗口最多20拒绝记录，常量内存，下一窗口的新尝试触发超额丢弃摘要；关闭前可能未输出，窗口边界不满足滑动一秒20条限制。同步logger仍依赖stderr性能；不是连接限速措施。

现有console事件实际验证；JSON编码契约仅synthetic测试。适配器只接受精确消息、ERROR、版本1和匹配的core/protocol/event_type，投影为auth_failure；丢弃摘要、普通404及政策错误均不投影为失败。既有成功日志仍可能包含UUID，不能公开原始日志。

## 实际测试

[hysteria2专项结果](v2bx-hy2-structured-2026-10-13/hy2-results.json)包括直连／UDP转发各5项：正常、错误凭据、恢复、目标不可达、TLS名称不匹配；另有普通HTTP/3 masquerade、同QUIC连接重复错误认证两次和消费者重启。正常响应均校验随机HTTP token，错误凭据拒绝；常规单次客户端错误认证产生一条事件。普通请求404不产生事件；两次实际错误认证均404且产生两条事件，证明不能把所有404归类为认证失败。实际依赖hysteria core/v2 v2.6.3认证通过后处理带宽/BBR，没有sing实现中的带宽政策404分支；此轮没有伪造该生产分支测试。

UDP转发器绑定127.0.0.2真实socket并重建对端，服务实际记录127.0.0.2；采样器配置中转CIDR后标记relay_address并排除。它是宿主loopback真实UDP转发实验，不是新QEMU跨主机、gost或公网链路测试，也不恢复用户出口。

[三内核回归结果](v2bx-hy2-structured-2026-10-13/three-core-results.json)：13个内核/协议组合的正常／错误凭据／恢复／目标不可达，7个TLS/QUIC错误名称、1个响应超时和6个轮转／程序及采样器重启／截断控制，共66项全部通过。测试范围沿用此前原生IPv4/TCP token目标；未覆盖所有transport、cipher、IPv6真实协议或UDP应用载荷。sing TUIC/Hysteria1/2错误凭据可验证业务拒绝，但日志检测仍无可靠来源；不能宣称三内核所有协议均能产生认证观察。

Go两个认证测试（行为兼容、字段隐私、IPv4/IPv6地址和无效地址、100并发失败的限额及80丢弃）通过 `-race`。IPv6这里是地址单元测试。Python日志适配23项通过；实际UDP peer类型和console编码由上述客户端测试补足。独立只读审查未发现重要缺陷，强调固定窗口与延迟丢弃摘要边界。

## CrowdSec及采集结果

[hysteria2实际投影回放](v2bx-hy2-structured-2026-10-13/hy2-replay.json)：17投影、4条eligible，按来源/core/protocol去重后14条进入官方CrowdSec1.8.1，1组观察告警、0决策；中转事件排除。

[三内核实际投影回放](v2bx-hy2-structured-2026-10-13/three-core-replay.json)：32投影、10条eligible，分组去重后29条进入官方引擎，严格核对7组告警、0决策（xray VMess/VLESS，sing VMess/VLESS/Trojan/AnyTLS，hysteria2 core Hysteria2）。分组去重用于bulk blackhole验收，不能计算逐行告警率。

[独立synthetic反例](v2bx-hy2-structured-2026-10-13/synthetic-engine.log)：18投影、7告警、0决策，含不支持的hy2 protocol_rejection负例。所有场景保持remediation:false。采样器既有轮转晚写/copytruncate漏采边界不因新补丁消失。

## 复现与边界

实验脚本、fixture、HTTP/3控制源码和固定投影保存在本归档目录；脚本保留实际执行的 `/tmp/v2bx-real-lab` 与 `/tmp/v2bx-hy2-structured-20261013` 路径，依赖此前隔离实验的客户端、临时证书及面板fixture。按实验补丁README在固定源码构建后，按hy2-lab.py及three-core-lab.py分别运行，不应同时启动共享端口。HTTP/3 probe源需在同模块内构建。未归档原始日志、数据库、私钥、配置凭据或二进制。

首次全仓测试有一项原有5秒期限超时，独立复测无改动通过；详情保留于 [失败尝试记录](v2bx-hy2-structured-2026-10-13/failed-attempts.json)。结束编译后的最终全仓复测688项，668通过、20跳过、0失败，155.228秒，见 [完整输出](v2bx-hy2-structured-2026-10-13/full-unittest.log)。Bash/Python语法、ShellCheck及git diff --check通过，补丁对原始提交的git apply --check通过。生产VPS来源信任、真实误报率、长时资源表现和执行位置尚未验收。下一阶段补齐sing QUIC明确拒绝分支，再做多用户混合入口与真实VPS仅观察。

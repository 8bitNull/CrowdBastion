# V2bX v0.4.0 hysteria2 认证观察实验补丁

仅适用于 `wyx2685/V2bX` v0.4.0 源码提交 `3deccaae00d168fd049f8a8659656664f25ee301`，不能直接应用到任意版本或替换生产发行包。补丁给 hysteria2 core 的 `Authenticate` 明确拒绝分支加入固定结构化字段；sing 内核的 Hysteria2、TUIC 和 Hysteria1 后续补丁独立保存在 [sing配套实验](../v2bx-sing-quic/README.md)。

补丁：[v0.4.0-auth-observation.patch](v0.4.0-auth-observation.patch)。在该提交的干净临时源码目录，先运行 `git apply --check /absolute/path/to/v0.4.0-auth-observation.patch`，再 `git apply`。使用 Go 1.25.0、`GOEXPERIMENT=jsonv2`：

```bash
GOEXPERIMENT=jsonv2 go test -race ./core/hy2 -run TestAuthObservation -count=1
GOEXPERIMENT=jsonv2 go build -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' -trimpath -ldflags '-X github.com/InazumaV/V2bX/cmd.version=v0.4.0-hy2-observation-experimental -s -w -buildid=' -o V2bX-experimental .
```

新事件消息为 `v2bx authentication rejected`，ERROR 级别，字段仅 `schema_version=1`、`core=hysteria2`、`protocol=hysteria2`、`event_type=auth_rejected` 和数值 UDP 对端 `addr`。现有 logger 添加时间与级别；当前 core 使用 console 编码。支持该固定契约的 JSON 编码适配器由 synthetic 测试验证。新增日志不输出密码、UUID、面板地址或目标；原程序的其他日志仍可能包含这些内容，不能公开原始日志。

每个明确拒绝的认证回调最多一条记录。同一 QUIC connection 可以重复提交认证请求，每次是真实的新尝试，不承诺每连接仅一条。客户端常规单次认证的确切事件数量由真实实验另行验证。成功、TLS失败、目标错误与普通masquerade不生成该事件。

每个 core 共用固定一秒窗口，最多20条拒绝记录，常量内存，不保存每IP映射。超额递增 `dropped`，在下一窗口有新拒绝尝试时输出一条 `v2bx authentication observations dropped` 摘要；停止前可能仍有未输出丢弃计数。相邻窗口边界可以在任意滑动一秒内超过20条。摘要不作为认证失败进入CrowdSec。此限制仅控制新增日志增长，不能代替连接限速或带宽清洗；同步日志输出仍受stderr写入性能影响。

数值peer始终是服务器可见对端。共享中转地址必须通过 `V2BX_RELAY_CIDRS` 排除；此补丁不恢复用户出口、不建立源地址信任。未知Addr类型、无效/组播/未指定地址、带zone的IPv6和无效端口不产生事件。

投影后为 `auth_failure`，始终 `observation_only=true`、`source_status=unverified`（配置中转后改为 `relay_address`）。仓库规则没有生产安装入口，`remediation: false`。部署、自动封禁与上游发布均需后续独立验收。

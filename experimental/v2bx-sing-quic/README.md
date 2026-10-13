# V2bX sing QUIC认证观察实验补丁

只适用于V2bX v0.4.0源码提交 `3deccaae00d168fd049f8a8659656664f25ee301` 的固定依赖：sing-quic v0.5.0、wyx2685/sing-box_mod v1.13.0-alpha.5。此目录是实验源码补丁，不是生产升级器。

补丁必须配套应用：

- [sing-quic认证分支与日志总量限制](sing-quic-v0.5.0-auth-observation.patch)。
- [sing-box专用安全logger与三个inbound注入](sing-box-mod-v1.13.0-alpha.5-safe-logger.patch)。
- [V2bX本地依赖替换](v2bx-local-quic.patch)。

在固定V2bX临时源码内，复制上述两个固定版本的完整模块源码到 `sing-quic/` 和 `sing-box_mod/`，使副本可写。分别在模块副本目录对对应补丁运行 `git apply --check` 再 `git apply`；在V2bX根目录应用本地替换补丁。禁止修改全局Go模块缓存。模块go.mod/go.sum保持原有内容；V2bX go.mod只将这两个模块替换为本地副本。此前的 [hysteria2 core补丁](../v2bx-hy2/README.md)独立应用；本次实际测试使用累积两阶段补丁的完整三内核二进制。

使用Go1.25.0，沿用官方完整build tags：

```bash
GOEXPERIMENT=jsonv2 go test -race github.com/sagernet/sing-box/log github.com/sagernet/sing-quic/internal/observation github.com/sagernet/sing-quic/tuic github.com/sagernet/sing-quic/hysteria github.com/sagernet/sing-quic/hysteria2 -run 'TestObservationLogger|TestFixedPrivateFields|TestConcurrentBounded|TestUnknownUser|TestWrongPassword|TestRejectionIsDistinct' -count=1
GOEXPERIMENT=jsonv2 go build -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' -trimpath -ldflags '-X github.com/InazumaV/V2bX/cmd.version=v0.4.0-quic-observation-experimental -s -w -buildid=' -o V2bX-experimental .
```

新记录格式为带时间的 `ERROR v2bx-auth/PROTOCOL: v2bx-observation {...}`。JSON字段仅 `schema_version=1`、`core=sing`、protocol、`event_type=auth_rejected` 和实际数值UDP对端addr。专用logger从原日志factory派生固定标签，保持配置输出位置与级别，不继承可能含面板URL的节点tag，也不输出密码、用户UUID或目标。未知logger实现返回NOP；只在验证过的标准factory生成事件，没有回退到敏感标签。其他原有程序日志仍可能包含账户或面板信息，不能公开整份日志。

TUIC只在未知UUID／token不匹配分支记录每session最多一次拒绝；脱敏sentinel抑制服务关闭和等待流的重复认证错误。Hysteria1保持原协议Wrong password响应及关闭code，去掉原 `auth_str=提交凭据` 错误。Hysteria2只在密码查询失败分支记录；普通masquerade、任意404、带宽政策拒绝、TLS错误和认证超时不作为明确认证失败。

每个QUIC Service实例独立固定一秒窗口最多20拒绝日志，不是sing core全局限额；增加节点会增加总上限。超额丢弃统计在下一窗口的新尝试输出 `event_type=observations_dropped` 摘要，无源地址，不进入认证场景。关闭前可能未报告；相邻窗口可在任意滑动一秒内超过20条。同步日志性能仍依赖配置的writer。这仅限制新增认证日志增长，不是连接限速或带宽清洗。

TUIC按session抑制重复；Hysteria2同连接重复提交错误认证是多次尝试，每次可产生事件。对端取自当前QUIC连接的RemoteAddr，未知类型、无效地址／port或IPv6 zone不记录。中转后仍为中转peer，必须通过V2BX_RELAY_CIDRS排除，不恢复用户出口。

适配器只接受固定安全logger前缀与精确事件契约，拒绝初版带inbound节点标签的记录。投影是auth_failure，始终仅观察。规则没有生产安装入口，remediation:false；生产部署及自动封禁不属于此实验。

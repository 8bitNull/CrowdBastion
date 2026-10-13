# V2bX 实验源码补丁

这里保存固定版本的认证拒绝观察实验，不是生产升级器；项目主脚本不会应用补丁、编译或替换 V2bX。

| 目录 | 作用 | 条件 |
| --- | --- | --- |
| [v2bx-hy2](v2bx-hy2/README.md) | hysteria2 独立内核的明确认证拒绝事件 | V2bX v0.4.0 固定提交；按该目录说明应用、编译与验证 |
| [v2bx-sing-quic](v2bx-sing-quic/README.md) | sing TUIC/Hysteria1/2 的明确拒绝和安全 logger | sing-quic、sing-box_mod 和 V2bX 本地依赖替换补丁必须配套 |

两类实现不同，不能把独立 hysteria2 core 的覆盖当作 sing Hysteria2 覆盖。实验使用可写模块副本，不修改全局 Go 模块缓存；完整 tags、依赖版本、事件格式和测试命令均在各目录说明中。

事件仅记录数值 UDP peer 和固定字段，不恢复中转后用户来源。日志限制用于控制新增事件增长，不是连接限速或带宽清洗。未知 logger、缺失事件、丢弃摘要和普通网络错误都不能解释为明确认证失败。

对应 [规则样板](../rules/v2bx/README.md)保持仅观察、未安装。构建身份、输出位置、来源范围和生产接入需按 [部署验收](../docs/v2bx-deployment-acceptance.md)核实。既有程序其他日志仍可能含敏感字段，不提交原始运行日志或配置。

源码与真实客户端对照见 [hysteria2 实验](../docs/audit/2026-10-13-v2bx-hy2-structured-events.md)、[sing QUIC 实验](../docs/audit/2026-10-13-v2bx-sing-quic-events.md)和 [混合入口验收](../docs/audit/2026-10-13-v2bx-mixed-ingress.md)。

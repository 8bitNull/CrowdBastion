# V2bX 仅观察规则样板

本目录未安装，也没有业务规则安装入口。它用于隔离验证已脱敏的固定字段投影，原始 V2bX 日志不能直接作为输入。

| 文件 | 作用 |
| --- | --- |
| [解析器](parsers/s01-parse/10-v2bx-observation.yaml) | 只接受 `v2bx-observation` 标签、固定契约、合法 IP 和已列出的失败类型／内核／协议 |
| [场景](scenarios/v2bx-failure-observation.yaml) | 单事件观察触发，`remediation: false`；没有攻击速率阈值 |

合格失败覆盖 xray VMess/VLESS，sing VMess/VLESS/Trojan/AnyTLS，以及固定实验构建的 sing TUIC/Hysteria1/2 和 hysteria2 core Hysteria2。匹配格式及语义见 [V2bX 指南](../../docs/v2bx-guide.md)。

xray Trojan 的拒绝可能进入 fallback，保持中性；Shadowsocks 的完整性错误不进入失败场景。健康连接、普通网络错误、未知格式及声明为 `relay_address` 的共享中转事件排除。`unverified` 不是可信用户标记，部署前仍须核对实际来源和中转范围。

固定投影可以由 `--v2bx-log-check` 或 `--v2bx-observe` 取得。后者导出数据库全部事件的一次性快照，不要把重复或重叠快照接入多个数据源。规则不会安装这些工具或创建常驻采集服务。

即使场景声明 `remediation: false`，忽略该字段的自定义 profiles 仍可能产生决策。真实 VPS 接入前必须隔离核查 profiles、采集去重、来源排除与停用方式，见 [部署验收](../../docs/v2bx-deployment-acceptance.md)。

最近的 [实际事件回放](../../docs/audit/2026-10-13-v2bx-mixed-ingress.md)按来源／内核／协议去重后形成 20 组观察告警、0 决策；这不是逐行告警率，也不是生产封禁验收。

# V2bX 离线日志观察：源码依据与隔离验收

日期：2026-10-13。范围为按源码构造的 synthetic 样本及隔离官方引擎，未取得目标 VPS 日志，没有生产验收或全协议支持结论。

## 版本与来源

基准：[wyx2685/V2bX](https://github.com/wyx2685/V2bX/tree/71277de69efbbc86c23ad8ae02b68efd174e5756)，提交 `71277de69efbbc86c23ad8ae02b68efd174e5756`。使用 go.mod 中的替换依赖，不能用 vanilla core 的格式代替：

| 模块 | 版本/提交 |
| --- | --- |
| wyx2685/xray-core | `v0.0.0-20251202200223-63db1dc9e9e2` |
| wyx2685/sing-box_mod | `v1.13.0-alpha.5.0.20251202212447-8d054dcd8bfe` |
| wyx2685/sing-vmess（VLESS 替换） | `v0.0.0-20250723121437-95d5ab59ff92` |
| sagernet/sing-vmess（VMess） | `v0.2.8-0.20250909125414-3aed155119a1` |
| apernet/hysteria/core/v2 | `v2.6.4` |
| 官方 CrowdSec Linux amd64 引擎 | `v1.8.1-909b5157` |

所读取源码与官方发行压缩包 SHA-256 见 [sources.json](2026-10-13-v2bx-observation-sources.json)。本地临时下载目录不是部署路径。

Xray `common/log/access.go` 和 `logger.go` 确定 access 消息与日期/微秒格式；VLESS 编码/入站与 VMess 编码/入站确定失败原因及 AccessRejected 的记录条件。Trojan `server.go` 185–215 行在 fallback 判断前记录两类拒绝消息，故这两类只归为 `fallback_candidate`，不作为失败导出。

Sing `log/format.go`、`log/log.go` 确定带偏移/相对时间与连接标签格式；替换 VLESS `vless/service.go` 确定 unknown UUID，VMess `service.go` 确定 bad request，Trojan `transport/trojan/service.go` 确定 fallback disabled 的返回条件。设备/账号限制、未知 flow 和其他错误未纳入失败场景。

V2bX `core/hy2/hy2.go` 使用 console 日志，`logger.go` 定义兼容 JSON epoch-ms 编码；`user.go` 的 Authenticate 与 Hysteria `server/server.go` 的认证失败路径没有可用失败日志回调。只支持连接/断开观察，不构造认证失败规则。

## 官方引擎验收

运行 `tests/verify_v2bx_observation.py OFFICIAL_RELEASE RESULT_JSON`，需要 Python 3/PyYAML 与解压的官方 CrowdSec 发行包。脚本在临时目录复制发行配置，使用仅 loopback LAPI/metrics、临时 SQLite、空 Hub index 和本项目本地规则，关闭 Central API；不安装 Bouncer、不访问生产配置或面板。使用发行包默认 profiles（仅对 `Alert.Remediation == true` 生成修复决策）。

启动就绪条件是 tailer 已启动且指标可查询。空文件在第一条记录前没有 acquisition metric series，不能以文件计数出现作为写入前提。

真实 `crowdsec -t` 通过；13 条规范化事件全部被读取，5 条产生观察告警：Xray VLESS/VMess，sing VLESS/VMess/Trojan。两类 Xray Trojan fallback 候选、成功连接、普通 TLS 错误、Hysteria2 连接、已声明中转地址、observation_only=false、非法来源均未产生失败告警。

实际加载的场景明确设置 `remediation: false`。`cscli alerts list -o json` 不提供瞬时的 Remediation 字段，因此验收检查 YAML 标签、每条告警 decisions 为空、全局 decisions 为空，不把缺失字段当成 false。结果见 [results.json](2026-10-13-v2bx-observation-results.json)：5 条告警、0 个决策。

这里只证明默认 profiles 下的离线行为；忽略 Remediation 的自定义 profiles 可能产生决策。`rules/v2bx/` 仍为未安装的离线样板，无生产采集/规则安装入口，也没有攻击频率阈值。

## 审查与生产缺口

独立只读审查发现并修复 Trojan fallback 误分类及 `str.splitlines()` 控制字符分行绕过。回归先复现失败，再验证中性分类、LF 分行、CRLF 和 C0/C1/DEL/Unicode separators 拒绝。

部署仍需真实 V2bX/core 版本、各协议本机日志、日志与数据包来源对照、中转地址清单、误报基线、重复采集与轮转策略。来源字段即使可解析也保持 `unverified`；未列出的中转地址不能自动识别。PROXY 元数据不证明落地防火墙看到用户地址。没有以上证据时不启用生产业务封禁。

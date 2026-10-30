# V2bX 落地诊断与观察指南

适用于 xray、sing、hysteria2 多内核，以及中转与用户直连并存的落地。当前交付包括只读诊断、离线日志核查、持久观察采样、未安装的规则样板及固定版本实验源码补丁；隔离真实协议与混合入口验收已有证据。没有安装 V2bX 专用检测规则，也没有启用业务自动封禁或连接限速。

## 使用

菜单 `4 → 4 → 1`，或运行：

```bash
sudo bash crowdbastion.sh --diagnose-v2bx
```

需要项目既有 Python 3/PyYAML 依赖。工具不自动安装依赖。默认检查 `V2bX.service`；如果主进程可识别且启动参数含绝对配置路径，使用该路径，否则仅检查候选 `/etc/V2bX/config.json`。候选路径不证明服务实际加载了它。

非默认路径和 unit 可明确指定：

```bash
sudo env V2BX_CONFIG=/etc/V2bX/config.json \
  V2BX_UNIT=V2bX.service \
  V2BX_ENTRIES='1:mixed,2:mixed,3:mixed' \
  bash crowdbastion.sh --diagnose-v2bx
```

`V2BX_ENTRIES` 的编号按主配置 `Nodes` 数组从 1 开始，而非面板 NodeID。上例仅适用于至少有三个节点，且前三个节点均有混合入口的情况。省略的节点报告 `unknown`。可声明：

| 声明 | 含义与条件性建议 |
| --- | --- |
| `direct` | 用户直连；核验数据包来源后由落地封禁 |
| `relay-preserve` | 中转宣称保留源地址；实际核验后才能由落地封禁 |
| `relay-proxy` | 代理/SNAT 中转；若可信获取用户来源，应在能看到该 IP 的中转入口执行 |
| `mixed` | 同一节点兼有直连和中转；每条路径分别核验 |
| `unknown` | 来源路径未确认，不确定自动封禁执行位置 |

这些是操作者声明，不会写入配置，也不会提升来源可信度。PROXY protocol 字段为配置声明；不同版本、内核和传输的支持情况需要核实，它不改变防火墙数据包的源 IP。

相对 Include 或日志路径根据 systemd 实际工作目录解析。无法取得工作目录时保持未验证；可通过 `V2BX_WORKING_DIR` 指定已核实的绝对工作目录。容器内路径、自定义启动包装器、多进程部署、动态配置与额外内核原始配置需要进一步人工核查。

结构化报告可直接调用 Python helper：

```bash
sudo python3 lib/crowdsec_v2bx.py \
  --config /etc/V2bX/config.json \
  --cs-dir /etc/crowdsec \
  --unit V2bX.service \
  --entries '1:mixed,2:mixed,3:mixed' \
  --json
```

## 报告含义

- 配置：支持 JSON，以及上游支持的注释、尾逗号。支持扁平节点与 `ApiConfig`/`Options` 格式。读取本机 Include，不下载远程 Include，不递归解析嵌套 Include。不可读取的节点显示未知。
- 内核：按 `Core` 或 `CoreName` 关联；多实例无法唯一关联、自动选核、未知内核不强行猜测。诊断不列举所有可能协议，只报告当前配置声明。
- 端口和传输：V2bX 常从面板取得这些设置，工具不调用面板 API。配置与 socket 不足以确定某个节点对应哪个端口/协议。
- 监听：读取数字地址的本地 TCP/UDP socket；只有 PID 与服务 MainPID 一致才展示为服务 PID 匹配。共享端口、通配监听、IPv6 与其他进程不用于推断节点归属。带 `%scope` 的地址不输出，避免携带任意字符串。
- 版本：仅展示最近 200 条 journal 中符合固定 V2bX 版本行格式的候选值；历史启动日志不能证明当前安装或运行版本。
- 日志：按配置引用标识（数组编号从 1 开始）定位，原始路径不输出。xray 空 AccessPath 视为关闭；ErrorPath 为空时仅列出 journal 候选；sing 识别 `Disable` 声明；该 Hysteria2 配置结构仅支持 `Log.Level`，不把未知 `Output` 字段当成实际日志目的地。
- 采集：复用 CrowdSec 有效采集路径逻辑，包括 `config.yaml.local`。文件通配符、重复匹配、整 unit journal 与额外过滤条件分别报告。采集配置存在不证明事件进入引擎或被正确解析；采集标签不输出，也不承诺标签兼容专用解析器。
- 样本：文件最多读取尾部 64 KiB、200 行；journal 最近 200 条。仅输出固定事件分类计数和结构化连接事件是否含合法来源，不输出原文、用户 UUID、密码、API Key、目标地址或异常原文。失败关键词只表示候选，不是可自动封禁的攻击证据。整个 unit 的 journal 样本可能包含多个内核，相同样本不能重复算作各内核独立证据。
- Bouncer：复用现有本地只读审查，报告本地引用状态，不展示原始输出，也不证明认证、同步或业务阻断。

退出码：`1` 表示配置/输入无效或关键本机查询失败；`2` 表示已生成诊断但端到端保护尚未验证。缺少工具、日志、采集或 Bouncer 的局部状态仍逐项显示，不能将 `2` 当成保护通过。帮助返回 `0`。

诊断不重启服务、不写入采集或白名单、不创建决策、不修改防火墙、不访问面板，也不自动信任中转。

## 日志样本离线核查（第二阶段离线部分）

菜单 `4 → 4 → 2` 或 `--v2bx-log-check`。每次选择一个内核，混合 unit 的其他格式会计入忽略项，不猜测协议。下面的时区、路径和中转网段是示例，必须替换为实际值：

```bash
sudo env V2BX_LOG_FILE=/root/v2bx-xray-sample.log \
  V2BX_LOG_CORE=xray V2BX_LOG_TIMEZONE=+08:00 \
  V2BX_RELAY_CIDRS='198.51.100.10/32,2001:db8::10/128' \
  bash crowdbastion.sh --v2bx-log-check
```

`V2BX_LOG_CORE` 支持 `xray`、`sing`、`hysteria2`。`V2BX_RELAY_CIDRS` 是逗号分隔的严格网络地址，已声明中转来源会标为 `relay_address`，排除失败事件导出。未声明的地址始终为 `unverified`，并非可信直连用户；共享中转网段需在核查前完整列出。不要将此设置理解为全局 CrowdSec 白名单。

文件最多 1 MiB、2000 行，每行最多 8192 个字符；超限不继续解析。只按 LF 分行，支持 CRLF；控制字符和 Unicode 行分隔注入会被拒绝。输出仅含固定分类、时间、内核、协议和数值来源 IP，不包含原始错误、账户标签、UUID 或访问目标。来源 IP 本身仍需妥善保管。

| 内核/协议 | 当前匹配格式与分类 | 失败观察 |
| --- | --- | --- |
| xray VLESS | access `rejected` + `invalid request user id` | 认证失败 |
| xray VMess | access `rejected` + `invalid user` 错误链 | 认证失败 |
| xray Trojan | `not a valid user` / `not trojan protocol` | 仅 `fallback_candidate`，日志在 fallback 分支之前产生，不能证明失败 |
| xray 成功连接 | access `accepted` | 仅连接事件，协议未知 |
| sing VLESS | `process connection from` + 完整 `unknown UUID` | 认证失败，UUID 不输出 |
| sing VMess/Trojan | `bad request` / `bad request: fallback disabled` | 无效请求候选，不证明攻击 |
| sing 普通错误 | 明确 TLS 握手、EOF、超时、连接重置 | 仅网络错误 |
| sing AnyTLS | 完整 `unknown user password: fallback disabled` | 认证失败 |
| sing Shadowsocks | 完整 chacha20poly1305 校验错误链 | 仅 `integrity_failure`，不触发失败观察 |
| sing TUIC/Hysteria1/2（实验补丁） | 固定 `v2bx-auth/PROTOCOL` 前缀及 `auth_rejected` 事件契约 | 明确认证失败，官方未打补丁包无此覆盖 |
| hysteria2 官方日志 | console 连接/断开日志；兼容 JSON epoch-ms 编码 | 仅连接事件 |
| hysteria2 core（实验补丁） | 固定认证拒绝消息与数值 UDP peer | 明确认证失败，须核实实验构建 |
| 其他协议/传输/版本 | 未确认格式或无来源/时间 | 忽略并计数，不宣称全协议支持 |

早期离线样本按替换依赖源码构造，见 [源码与隔离验证记录](audit/2026-10-13-v2bx-observation.md)。后续已有真实程序日志对照及 [IPv4/IPv6 混合入口验收](audit/2026-10-13-v2bx-mixed-ingress.md)，但没有采集目标生产 VPS 的真实业务日志。固定依赖、实验补丁与官方包的覆盖不能混用。

xray 文件时间没有时区，需 `V2BX_LOG_TIMEZONE` 明确指定事件发生时的实际 UTC 偏移。sing 完整日志需带偏移；相对计时日志不能直接使用当前时间补齐。可在目标 VPS 本机导出 journal JSON，保留时间和 unit：

```bash
sudo sh -c 'umask 077; journalctl -u V2bX.service -n 200 --no-pager -o json > /root/v2bx-journal-sample.jsonl'
sudo env V2BX_LOG_FILE=/root/v2bx-journal-sample.jsonl \
  V2BX_LOG_CORE=sing V2BX_UNIT=V2bX.service \
  bash crowdbastion.sh --v2bx-log-check
```

原始导出可能包含凭据，仅在受控本机保存，不提交仓库或公开分享。不要用 `-o cat` 替代 JSON，否则丢失 journal 接收时间和 unit。工具使用 `__REALTIME_TIMESTAMP` 作接收时间依据并检查 `_SYSTEMD_UNIT`，不据此提升来源可信度。以上命令还需按实际路径补充 `V2BX_RELAY_CIDRS`。

可直接调用 helper 加 `--events-only` 导出 eligible 失败观察 NDJSON：

```bash
python3 lib/crowdsec_v2bx_logs.py --file /root/v2bx-xray-sample.log \
  --core xray --timezone +08:00 --relay-cidrs '198.51.100.10/32' --events-only
```

报告与导出成功仍返回 `2`，表示生产验证未完成；无效输入返回 `1`，帮助返回 `0`。导出为空可能表示没有匹配事件，不能证明没有攻击。

`rules/v2bx/` 是**未安装的离线规则样板**：专用 `v2bx-observation` 标签只接受规范化失败事件；单事件 trigger 设置 `remediation: false`，不设攻击阈值。早期 synthetic 验证为 5 条告警、0 个决策；后续固定实验构建的 IPv4/IPv6 实际投影回放核对 20 组告警、0 决策，见 [最新验收](audit/2026-10-13-v2bx-mixed-ingress.md)。自定义 profiles 若忽略 `Alert.Remediation`，可能仍产生决策，因此不要直接接入生产采集；如需接入，应使用下述“仅观察告警接入”入口，由专用 profiles guard 隔离决策。日志核查命令不会安装这些规则或改变服务、防火墙与决策。

## 下一阶段的证据

先为实际部署中的每条路径完成来源核验。直连用户、代理中转和保源中转分别对照：日志来源地址、落地网络对端、能执行封禁的入口节点。共享中转地址不能替代用户地址作为业务封禁对象；固定中转的信任配置也不等于所有协议均可安全传递真实 IP。

再收集各内核和协议的脱敏成功事件、明确失败事件与普通网络错误。提供版本、节点配置允许字段，以及日志实际产生条件。不要提交完整配置、凭据或用户访问目的地。没有失败日志的协议明确保持专用检测未验证；需要改进 V2bX 事件日志时另行适配。

有可靠来源和失败事件后才进入解析器/场景开发、仅观察验收、隔离来源封禁/恢复验证。限速需要各入口正常峰值与资源基线；带宽型 DDoS 需要上游防护。完整顺序见 [阶段计划](superpowers/plans/2026-10-13-v2bx-protection-roadmap.md)。

具体部署诊断命令、逐路径来源对照和观察接入条件见 [部署验收流程](v2bx-deployment-acceptance.md)。

## 真实三内核的隔离协议验收

现已使用官方 V2bX v0.4.0、受控 UniProxy API、真实 sing-box 1.12.0 客户端验证基础内核／协议组合与实际日志。程序发布版的依赖和此前分析的 HEAD 不同；各路径结果、日志漏检修正、认证失败检测缺口和失败轮次见 [真实协议验收记录](audit/2026-10-13-v2bx-real-protocol-simulation.md)。基础握手和业务响应成功不能表示所有传输或每个协议的行为检测已覆盖；生产接入仍按前述流程核验。

## 持久观察采样（不安装生产采集）

`--v2bx-observe` 按固定投影保存本机样本，SQLite 将事件与源日志偏移一起提交。数据库绑定日志路径摘要、core、时区、unit 和中转 CIDR；同一配置重启续读，改变配置需另建数据库。当前用户拥有的状态目录不得对组／其他用户可写，数据库与新导出快照权限为 0600。

```bash
install -d -m 700 /var/lib/crowdsec/v2bx-observe
V2BX_LOG_FILE=/var/log/V2bX/sing.log \
V2BX_LOG_CORE=sing \
V2BX_OBSERVE_DB=/var/lib/crowdsec/v2bx-observe/sing.sqlite \
V2BX_OBSERVE_DURATION=60 \
V2BX_RELAY_CIDRS=198.51.100.10/32 \
V2BX_OBSERVE_EXPORT=/var/lib/crowdsec/v2bx-observe/sing-snapshot-001.ndjson \
bash crowdbastion.sh --v2bx-observe
```

替换为实际日志和中转范围；样例地址不是可直接部署的白名单。Xray 文件日志另设 `V2BX_LOG_TIMEZONE=+08:00` 等明确偏移，不猜测本地时区。各源使用独立数据库；同一数据库拒绝双实例，活动源 inode 也使用 advisory lock，防止本采样器用不同数据库并发重复读取。该锁不能约束忽略锁的其他采集程序，仍需核查现有 acquisition。

直接 Python 等价入口支持 `--poll-interval`（默认0.5秒）、`--max-events`（默认100000，上限1000000）、`--duration`（默认60秒，上限86400秒），超出事件容量停止并保留已提交进度，不静默删样本。再次运行可提高容量后续读。命令完成返回2表示生产未验收；错误返回1，Ctrl-C返回130，已提交内容保留。

这是**观察样本存储**，没有创建 systemd 服务、日志轮转策略或长期 CrowdSec 输入。导出包含数据库内全部投影事件，是一次性快照，拒绝覆盖和源路径冲突；不能把多次重叠快照同时送入 acquisition，否则会重复采集。快照仅在命令成功导出后用于离线核查或隔离引擎验收。

采集指标包含 `lines/events/failure_observations/ignored/rotations/truncations/continuity_risks/oversized_lines/missing_polls`。未换行片段暂缓；过长行整行丢弃并计数；无效UTF-8、控制字符和未知格式不猜测。任意普通网络错误不会因“请求失败”自动改写为认证失败。

轮转时先读旧fd到观察到的EOF，再读新inode；重启会有限查找同名未压缩轮转文件。**EOF不能证明旧进程已重新打开日志**，每次交接保守增加连续性风险，交接后旧fd晚写可能漏采。copytruncate和锚点变化会计数并重新读取，但截断前未读字节、未发现旧inode、快速多轮轮转、相同前缀截断后快速再增长／inode复用及外部写入竞态均不能保证无损。出现风险需核查日志重开方式和保留时间；本工具不能把风险计数解释成具体丢失条数或“恰好一次”交付。

官方日志适配支持 sing AnyTLS 的明确 `fallback disabled` 认证失败；sing Shadowsocks 的 chacha20poly1305 校验错误记为 `integrity_failure`，可能来自错误密码或损坏数据，**不触发失败观察告警**。官方未打补丁包中 TUIC/Hysteria1/2 缺来源的失败行继续忽略；实验新增契约见后文，来源改进方案见 [结构化事件评估](v2bx-structured-events.md)。真实对照、采集连续性限制和官方引擎结果见 [本阶段验收](audit/2026-10-13-v2bx-observation-stability.md)。

按后续授权已实现 [hysteria2 core实验补丁](../experimental/v2bx-hy2/README.md)，在真实认证拒绝分支新增脱敏事件并接入现有观察投影。官方未打补丁发行包仍不具备该事件；sing Hysteria2是不同内核实现，不能借用此覆盖结论。真实客户端直连／UDP转发和三内核回归结果见 [实验验收](audit/2026-10-13-v2bx-hy2-structured-events.md)。没有生产替换或规则安装。

后续已补齐 [sing TUIC/Hysteria1/2实验补丁](../experimental/v2bx-sing-quic/README.md)，在固定版本明确认证拒绝分支输出安全前缀和固定事件。初版继承的面板URL日志标签已修正；需配套应用sing-box安全logger和sing-quic补丁。官方未打补丁包的缺口仍存在；未知logger实现不回退到敏感标签，需独立验收。专项36项、QUIC边界5项和三内核66项及10组观察告警／0决策见 [最新报告](audit/2026-10-13-v2bx-sing-quic-events.md)。仍未部署生产。

最新 [混合入口验收](audit/2026-10-13-v2bx-mixed-ingress.md) 补充双账号同时直连／中转、真实 IPv6 与 UDP 应用载荷。需注意 hysteria2 core 的 `::` 在固定依赖下是 IPv6 UDP 专用监听，以及 Shadowsocks 的原生 UDP 中转配置；模拟通过不替代实际 VPS 的监听、来源及观察采集验收。

## 落地常驻仅观察服务

菜单 `4 → 4 → 3`，或使用以下三个命令。它将每个内核的独立文件日志接入持久 Observer；不安装 CrowdSec acquisition、场景或 profiles，也不创建告警、封禁或限速规则。真实 VPS 部署仍须按[部署验收](v2bx-deployment-acceptance.md)核实。

先在本机建立 root 所有、权限 `0600` 的 JSON 配置，路径按真实日志修改。中转 CIDR 示例必须换成实际出口；三个内核需要三个不同文件，xray 文件日志必须指定实际时区偏移：

```json
{
  "poll_interval": 1,
  "sources": [
    {"name": "xray", "core": "xray", "file": "/var/log/V2bX/xray-error.log", "timezone": "+08:00", "relay_cidrs": "198.51.100.10/32,2001:db8::10/128", "max_events": 100000},
    {"name": "sing", "core": "sing", "file": "/var/log/V2bX/sing.log", "relay_cidrs": "198.51.100.10/32,2001:db8::10/128", "max_events": 100000},
    {"name": "hy2", "core": "hysteria2", "file": "/var/log/V2bX/hysteria2.log", "relay_cidrs": "198.51.100.10/32,2001:db8::10/128", "max_events": 100000}
  ]
}
```

日志文件必须已存在且为非符号链接普通文件。不修改 V2bX 日志设置；只有 journal 或混合 core 共用同一日志文件时，先保留现有离线采样流程，不能复制配置条目重复采集。服务启用 PrivateTmp，不支持 `/tmp`、`/var/tmp` 内日志。源名称只允许小写字母开头的字母、数字、下划线或短横线，最长 32 字符；最多 16 个独立源。

```bash
sudo chmod 600 /root/v2bx-observer.json
sudo env V2BX_OBSERVER_CONFIG=/root/v2bx-observer.json bash crowdbastion.sh --install-v2bx-observer
sudo bash crowdbastion.sh --v2bx-observer-status
sudo bash crowdbastion.sh --disable-v2bx-observer
```

安装检查 `/usr/bin/python3` 的 PyYAML，不借用当前 shell 的临时 PYTHONPATH。首次安装复制 helper 和配置到 `/usr/local/lib/crowdsec-v2bx-observer/`，创建 `crowdsec-v2bx-observer.service`，数据位于 `/var/lib/crowdsec-v2bx-observer/`。拒绝覆盖现有目录或同名 unit；安装失败且服务能停下时撤销新文件，若无法停下则保留文件用于排查。停用保留全部数据，不影响 V2bX 和其他防护服务。确认配置无变化且源可用后，可用 `systemctl enable --now crowdsec-v2bx-observer.service` 恢复观察。

状态返回 `2` 表示业务防护仍未验证，`1` 表示关键查询或输入失败。检查 `service_active`、`heartbeat_age_seconds` 和每源 `source_present`；active 不等于观察健康。指标含事件数、中转排除后的合格失败数、忽略原因、轮转和连续性风险，不含原始日志／UUID／密码。

每源默认最多 100000 个事件，最大 1000000；达到容量后本轮不提交，服务停止并记录 `observation_capacity_reached`，不丢弃旧数据。此时勿仅重启：先停用、备份数据库与配置，再制定新观察窗口或调整容量。修改已安装配置会被完整性检查标记，当前入口不支持自动迁移或滚动删除；需要保留备份后人工维护，并重新核对安装与采集契约。数据库及备份保持本机私有，不提交到 Git。

轮询间隔 0.5–60 秒；systemd 限制内存 256 MiB、CPU 20%，这是服务资源上限而非吞吐保证。首次从文件开头读取，历史积压可能很快耗尽容量；试点应使用经核对的有界当前日志，避免全量 debug。数据库游标随事件提交，正常停用／重启不会重复已提交事件；旧文件迟写、copytruncate、轮转后旧 inode 无法找回仍可能丢失或重采，风险指标不表示恰好一次交付。

## 常驻仅观察告警接入

菜单 `4 → 4 → 4` 的 `1/2/3` 分别为接入、只读状态和停用。先完成健康的常驻采集器和实际来源核对，再在隔离副本验证本机 CrowdSec 配置；当前自动接入仅支持 `/etc/crowdsec` 标准 config_dir／acquis.d 布局，要求 CrowdSec 可用且运行、Prometheus acquisition 指标可查询。官方模拟验收固定 CrowdSec 1.8.1，不等于其他版本或真实 VPS 已放行。

```bash
sudo bash crowdbastion.sh --enable-v2bx-alerts
sudo bash crowdbastion.sh --v2bx-alerts-status
sudo bash crowdbastion.sh --disable-v2bx-alerts
```

接入会安装独占 parser、仅观察场景及 acquisition；在 profiles 最前增加该场景专用的空 decisions／`on_success: break` guard，再校验并重启 CrowdSec，启动 `crowdsec-v2bx-alerts.service`。**该操作会重启核心**，须选择维护窗口。原 SSH／Web 等场景仍走后续原 profiles；本工具不创建观察场景决策。存在同名资产、重复文件采集或配置漂移时拒绝自动修改。

接入按 `config.yaml` 与 `config.yaml.local` 合并后的 `profiles_path` 定位规则；若存在 `profiles_path.local`，guard 写在这个优先执行的文件最前。停用恢复对应文件，保留其他 profiles；配置覆盖变化、优先 profiles 文件新增／移除或 guard 损坏会阻止继续发布。配置和 profiles 的符号链接不接受自动接管。

增量发布只读已有 SQLite，每源每批最多 256 条；私有目录 `/var/lib/crowdsec-v2bx-alerts/` 保存 `events.ndjson`、发布账本与状态，helper／原 profiles 备份位于 `/usr/local/lib/crowdsec-v2bx-alerts/`。输出默认上限 128 MiB，不自动轮转。每条投影携带稳定 `observation_id`，用于本机证据核对，不是 CrowdSec 端去重保证；不要另建重叠 acquisition。

首次发布先用不匹配业务 parser 的 `{}` 探针确认 acquisition 读取量增加，再排空采集积压。正常发布进程重启复用游标；完整待提交批次经内容核对、fsync 后推进游标而不重发。部分写入、输出替换／截断、源库／契约变更、容量耗尽或 CrowdSec InvocationID 改变时停止，状态为 `needs_attention`／`publication_requires_review`，保留证据。观察原始日志的 copytruncate、迟写和找回旧 inode 的限制仍然存在，不以稳定发布 ID 消除原始采集丢失／重采风险。

CrowdSec 文件 tail 没有逐条持久确认，本方案**不保证消费端恰好一次**。核心重启后，已发布但未持久保存的告警可能缺失；发布服务会拒绝自动续发和重放。不能仅重启发布器或删除账本解除阻塞：先停用接入、私有备份配置／账本／NDJSON，按来源、事件 ID、时间和实际告警对照，制定新观察窗口。本阶段不提供自动迁移、自动补发或停用后一键重新接入，保留目录会阻止盲目覆盖。

Telegram 启用／停用通知造成的 YAML 排版变化和守卫通知列表变化，不会被当作守卫规则被篡改；守卫仍必须位于第一份 profiles 文档，保持固定过滤条件、空 decisions 和 `on_success: break`。修改通知引发的核心重启仍适用上述消费边界，不能据此自动恢复发布。

深度卸载核心前，先执行 `--disable-v2bx-alerts`，再执行 `--disable-v2bx-observer`。任一服务仍运行、仍启用或状态无法读取时，卸载会中止。观察数据库、发布账本、NDJSON 及程序目录保留，残留检查会列出这些路径，需按证据保留要求另行处理。

停用先停止发布端，再移除仅本工具 acquisition／规则和 profiles guard，校验并重启核心；保留原 profiles 后续外部更新、原场景与发布证据。受管资产被外部修改时停止操作，不覆盖这些改动。接入失败会恢复旧配置；若发布已尝试启动或核心恢复重启失败，保留私有备份与状态，需人工核对。中断／恢复不完整时也须据备份与实际服务状态处理，不能据单个退出码宣称全部已恢复。

状态返回 `2` 表示观察接入报告成功但真实业务防护仍未验证；关键错误返回 `1`。健康要求发布服务和核心活跃、心跳新鲜、源采集器健康及受管规则／guard 完整。观察告警数量受 trigger 的 1 秒 blackhole 及分组影响，不等于逐行事件数；核查本场景增量决策为零，不能要求生产已有其他场景的全局决策清空。

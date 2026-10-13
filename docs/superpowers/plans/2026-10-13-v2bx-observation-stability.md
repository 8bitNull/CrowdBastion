# V2bX 日志覆盖与观察采集稳定性实施计划

> 按用户“按照你的建议执行”授权在已有 feat/v2bx-diagnosis 工作区顺序实施，保留先前未提交修改与 task-2-report.md，不提交、不部署生产。使用 executing-plans 和 TDD。

**Goal:** 扩展有真实来源证据的 sing 失败格式，并提供可恢复的本地观察采样，验证误报、重启和日志轮转。

**Architecture:** 复用固定投影 parse_line。新增独立 Python 采样器，以 SQLite 单事务提交数值文件标识、偏移和脱敏事件；不在数据库存原始行、面板地址、凭据和目的地。采样器只写显式指定的数据库，可导出一次性固定事件快照用于隔离引擎验收，不建立自动生产采集服务。

**Tech Stack:** Python stdlib sqlite3/fcntl/os、现有 parser/scenario、官方 V2bX v0.4.0、CrowdSec 1.8.1。

**Spec:** 用户已确认的下一阶段前两项：补齐明确失败事件；正常重连、网络超时、目标不可达、TLS 错误、日志轮转、重启与重复采集核查。基础协议范围沿用前轮记录，不扩大为生产封禁或压力验收。

## 约束与设计取舍

- AnyTLS `unknown user password: fallback disabled` 可作为明确 auth_failure；fallback 未禁用不能推断认证拒绝。
- Shadowsocks `chacha20poly1305: message authentication failed` 是 AEAD integrity_failure（损坏数据和错误密码均可触发），不宣称一定错误凭据；暂不纳入失败告警场景。
- TUIC/Hysteria1/2 缺少可靠失败来源时保持未适配，不从相邻连接行或日志 UUID 拼接猜测；评估上游结构化日志所需字段，未实际修改上游不能宣称解决。
- 本地采样器以 private SQLite 数据库持久化，不维护额外实时 NDJSON tail 文件，避免跨文件事务导致假“恰好一次”。导出为显式独立快照，不可把反复快照接入生产以免重复采集。
- 输入 regular file、nofollow、nonblock 打开；单实例锁；配置绑定至数据库；输出拒绝覆盖、链接、FIFO。原始行限定8192字节，UTF-8严格解码，partial line不提前提交；游标锚点检测截断/改写。源文件本身不修改。
- 轮转时排空旧fd，然后接入新inode；重启后旧inode不可找到、快速多轮轮转和copytruncate不可恢复部分明确计数为采集连续性风险，不承诺无损。
- 只保存固定投影与数值计数；源路径配置仅存摘要；relay CIDR依旧排除失败观察。不创建生产决策、服务或防火墙配置。

## Task 1: 真实日志适配与负面对照

Files: lib/crowdsec_v2bx_logs.py、tests/test_v2bx_logs.py、rules/v2bx/parsers/s01-parse/10-v2bx-observation.yaml。

- [x] 先加入真实 AnyTLS、SS 格式，IPv4/IPv6、来源一致性、fallback、无源 QUIC、普通错误负面测试；命令 `PATH="$PWD/.venv/bin:$PATH" python3 -m unittest discover -s tests -p test_v2bx_logs.py -q` 应因新事件缺失失败。
- [x] 实现固定规则：sing协议允许anytls/shadowsocks；AnyTLS exact reason映射auth_failure；SS精确包装并核对两个endpoint相同，映射integrity_failure。未知wrapper不接受。观察parser仅增加anytls auth_failure，不增加SS integrity_failure。
- [x] 重跑测试并用实际程序对照正常／错误凭据／TLS／目标故障；不依据测试阶段名字生成事件。

## Task 2: 原子持久观察采样

Files: lib/crowdsec_v2bx_observe.py、tests/test_v2bx_observe.py、docs/v2bx-guide.md。

- [x] 先加入append、partial、重启无重复、rename/create、copytruncate、改写长于offset、缺失文件、链接/FIFO、数据库配置冲突、双实例、脱敏与导出只读输入测试。接口 `Observer(source, database, core, timezone_offset, relay_cidrs)`，`poll()`返回固定计数，`export(path)`创建独立快照。
- [x] 实现SQLite事务、nofollows、inode/offset anchor、8192字节行上限、锁及固定字段状态。命令 `python3 lib/crowdsec_v2bx_observe.py --file FILE --database DB --core CORE --duration SECONDS [--timezone OFFSET] [--relay-cidrs CIDRS] [--export NEWFILE]`，运行完成返回2表示生产未验收，错误返回1。
- [x] 重跑测试；使用真实程序日志验证端到端采样、正常控制、程序重启与文件轮转。模拟不能代替真实VPS日志权限/服务管理验收。

## Task 3: 官方引擎验收与交付

Files: tests/verify_v2bx_observation.py、新的隔离验收脚本及 docs/audit 归档。

- [x] 官方引擎核验AnyTLS实际失败告警、SS integrity不告警、正常/网络错误/relay排除；严格检查来源/core/protocol及0决策。
- [x] 独立审查修改；运行全仓 unittest、Bash/Python语法、ShellCheck、diff和输出脱敏检查。
- [x] 归档真实版本、失败轮次、结构化结果和源码hash；更新指南与路线。IPv6/UDP应用/多用户/真实VPS观察作为后续条件，不标完成。

**交付：** 原始功能与边界回归19项，真实程序66/66，官方实际回放6观察告警／0决策，最终687项全仓测试0失败。轮转交接的旧fd晚写、copytruncate和部分重写不可保证无损，风险指标和指南明确保留；不是生产实时采集服务。详见 [验收记录](../../audit/2026-10-13-v2bx-observation-stability.md)。

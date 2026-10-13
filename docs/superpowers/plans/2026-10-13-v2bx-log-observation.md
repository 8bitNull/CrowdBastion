# V2bX 日志离线观察实现计划

> 执行方式：executing-plans，在当前 feat/v2bx-diagnosis 分支执行；保留第一阶段和已有未跟踪文件。用户已授权阶段计划并明确继续。

**Goal:** 在没有目标 VPS 日志和连接信息时，完成有源码依据的事件解析、脱敏样本核查和仅观察 CrowdSec 规则的隔离验收。

**Architecture:** 新增独立日志 helper，从单行事件提取固定字段，不关联不同连接或从访问目标猜测来源。主 CLI 提供只读样本检查。规范化事件携带 observation_only=true 和来源未验证标记；离线规则只形成非修复告警，不安装生产采集或规则。

**Tech Stack:** Python 3/PyYAML、既有 Bash CLI、官方 CrowdSec 1.8.1 临时引擎。

**Spec:** 既有阶段计划第二阶段的离线部分。生产版本、来源可信度、误报基线和实际采集仍需目标部署证据。本轮不宣称第二阶段生产验收完成。

## 约束

- 使用 wyx2685/V2bX 71277de 的依赖替换版本：xray-core 63db1dc9e9e2；sing-box_mod 8d054dcd8bfe；sing-vmess_mod 95d5ab59ff92；Hysteria core/v2 v2.6.4。
- 日志样本由源码格式构造，明确标为 synthetic/source-backed；不称为生产抓取日志。
- 只解析有依据的日志格式，未知格式计数且不输出原文；不输出 UUID、密码、账户标签、目的地址或文件路径。
- 来源只取当前事件的固定来源字段，数值 IP/端口必须有效；拒绝 hostname、scoped IPv6、无时间依据和多行注入。
- xray 文件的无时区时间须明确提供实际时区偏移；journal JSON 可用可信导出中的接收时间作时间依据。不自动把本地时间当 UTC。
- PROXY protocol、入口路径或日志源本身不提升可信度。指定中转地址的事件不能进入用户失败观察规则。
- Hysteria2 无认证失败事件，连接/断开日志仅观察；不从错误字符串虚构认证失败。
- 普通超时、TLS 握手错误、设备限制、域名审计与成功连接不进入失败场景。
- CrowdSec 样板场景为单事件观察触发器，remediation=false；不设未经流量验证的统一封禁阈值。
- 所有生成物和真实引擎检查仅用于临时目录，不操作生产服务、防火墙或决策。

## Task 1：严格解析与只读样本 CLI

**Files:** 新建 lib/crowdsec_v2bx_logs.py、tests/test_v2bx_logs.py；修改 lib/v2bx.sh、install-crowdsec-1panel.sh。

**Interfaces:** parse_line(line, core, timezone_offset=None, journal_unit='V2bX.service') 返回 (固定字段事件或 None, 固定状态码)。inspect_file(path, core, timezone_offset, relay_networks, journal_unit) 返回分类计数与脱敏事件。入口 --v2bx-log-check 使用 V2BX_LOG_FILE、V2BX_LOG_CORE、V2BX_LOG_TIMEZONE、V2BX_RELAY_CIDRS、V2BX_UNIT；缺少文件/内核时在菜单询问，不持久化。

- [x] 用 table-driven 正反样本先写失败测试：xray VLESS/VMess 拒绝与 Trojan fallback 候选日志、sing VLESS unknown UUID、sing VMess/Trojan bad request、Hysteria2 JSON/console 连接事件、journal 时间、IPv4/IPv6、敏感字段剔除、中转来源排除、未知格式与时区、FIFO/大文件、CLI/菜单不加锁。
- [x] 执行 `PATH="$PWD/.venv/bin:$PATH" python3 -m unittest discover -s tests -p test_v2bx_logs.py -q`，确认缺少功能导致失败。
- [x] 实现固定格式和固定分类，事件恒有 `observation_only: true`、`source_status: unverified`；只输出白名单字段。
- [x] 接入菜单 `4 → 13` 和只读分发；不修改其他安装流程。
- [x] 重跑定向回归，检查读取前后配置、日志文件与系统调用记录。

## Task 2：仅观察规则与官方引擎验证

**Files:** 新建 rules/v2bx/ 下规范化事件 parser 和非修复 trigger 场景；新建 tests/verify_v2bx_observation.py；扩充 tests/test_v2bx_logs.py。

**Interfaces:** 规范化 NDJSON 固定字段 schema_version=1、timestamp、core、protocol、event_type、source_ip、source_status、observation_only。官方 parser 只接受专用标签 v2bx-observation 的规范化事件；场景只接受未验证的独立来源失败事件，并设置 remediation=false。

- [x] 在临时配置中使用真实 CrowdSec -t 检验 YAML；让官方引擎处理源码格式构造事件，核对解析字段、事件分类及 UTC 时间。
- [x] 核对失败事件形成非修复告警，成功、普通错误和中转来源不形成失败告警；LAPI 决策始终为空。
- [x] 记录源码依据、构造样本范围和实际引擎结果；明确这不是目标 VPS 流量测试。

## Task 3：文档、审查与回归

**Files:** 修改 docs/v2bx-guide.md、docs/cli-reference.md、docs/verification.md 和阶段路线；新建源码依据/隔离验证记录。

- [x] 写出各已适配格式、未支持协议、时区和 journal 导出方法、日志容量边界及中转来源配置说明。
- [x] 按 requesting-code-review 进行独立只读审查，修复重要发现。
- [x] 完整 unittest、Bash/Python 语法、ShellCheck 和 diff 检查。
- [x] 将离线交付与生产待验证项分别记录；没有真实部署证据时不启用生产采集、日志轮转或封禁。

## 实施记录

离线任务已实现；专项 16 项测试包含独立审查发现的 Trojan fallback 中性分类与控制字符分行注入回归。官方 CrowdSec 1.8.1 的配置检查与临时引擎验收通过：13 条构造事件全部读取，5 条观察告警，0 个决策；加载场景 remediation=false，默认 profiles 对观察告警不修复。cscli 告警 JSON 不包含 Remediation 字段，验证逐告警和全局决策为空，不假定缺失字段等于 false。源码、校验值与结果见 docs/audit/2026-10-13-v2bx-observation.md。

这只完成第二阶段的离线部分。目标 VPS 样本、版本兼容、来源信任、误报观察、生产采集和日志轮转仍未验收，不启用生产业务封禁。完整回归结果见 docs/verification.md。

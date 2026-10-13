# Telegram 通知迁移与 HTTP 取证修复（2026-10-12）

## 原因与范围

同一来源命中不同规则会产生不同 Alert，分别推送是正常行为。旧 `http_default` 与本工具 `crowdsec_1key_telegram` 同时路由时，则会收到两种通知。重复安装无需先卸载 CrowdSec 或整个机器人：应原位更新受管理配置，并替换能明确识别为同一 Bot Token / Chat ID 的旧 HTTP 路由。

旧模板错误地使用 `index .Meta "http_path"`：官方 CrowdSec 1.8.1 的告警和事件 Meta 都是 `key/value` 列表，而不是字典。当前仓库此前的简短模板也没有展示 HTTP 取证字段。

官方引擎实测进一步证实 AppSec 的字段位置不同：事件 Meta 保存 `uri`；告警 Meta 的 `target_uri`、`user_agent`、`method` 是 JSON 数组字符串。只读取事件 UA 或只匹配包含 `http` 的场景名，都会漏掉虚拟补丁告警。

截图中含解封/白名单按钮的卡片不在当前仓库中；其独立程序的源码、服务名和运行环境仍需确认，本次不能声称已经修复或停止该程序。当前工作区没有 `/etc/crowdsec`，本次只修改仓库并进行隔离验证，未修改用户 VPS。

## 修复行为

- 重复配置原位更新，检测同一机器人/聊天的旧 HTTP 通知路由并替换；支持代理 API 路径前缀、YAML 多文档和 `.local` profiles。其他目标和动态/多目标 Chat ID 模板保留；旧插件文件保留，避免影响共享文件内的其他配置。
- 更新前备份，校验或加载失败恢复；本工具 profile 路由去重，其他通知通道保留。
- 遍历事件 Meta，最多显示 3 组不同的路径/UA/方法样本；无事件样本时使用告警上下文。
- 解析 AppSec 告警上下文的 JSON 数组；只有 WAF 告警、单一上下文且路径明确匹配时，才补齐事件中缺失的 UA 和方法。事件自己的 UA 始终优先。
- 区分缺少元数据与请求没有 UA；采用纯文本、整体 JSON 编码及长度限制，防止引号、换行、HTML、超长输入导致投递失败。

## 验证

完整 unittest 回归 **399 项全部通过**（包含官方插件测试，无跳过）。测试环境用虚拟环境的 PyYAML 路径补齐了强制调用系统 Python 的诊断子进程。

新增 11 项 Telegram 测试：迁移、重复配置、回滚、代理前缀、动态目标保留、实际 Go 模板渲染、HTTP 样本对应、AppSec 上下文匹配、空 UA、缺少字段和长字段。使用官方 CrowdSec 1.8.1 HTTP 插件，目标仅为本地接收器。

```bash
PATH="$PWD/.venv/bin:$PATH" \
CROWDSEC_TEST_RELEASE=/path/to/crowdsec-v1.8.1 \
python3 -m unittest discover -s tests -p test_telegram.py -v

PATH="$PWD/.venv/bin:$PATH" \
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1
```

官方引擎隔离验证通过：配置校验、真实 `/.env` 请求阻断、通知显示请求路径与实际 UA、普通请求放行、独立 LAPI 凭据及决策增删。复审未发现剩余严重问题。Bash 语法、Python 编译、ShellCheck（既有动态函数/变量排除项）和 diff 空白检查通过。

## 加载到 VPS

更新脚本及 `lib` 后，在 VPS 上执行：

```bash
sudo bash install-crowdsec-1panel.sh --telegram
```

选择 `1. 配置/更新`，输入机器人参数并加载新模板。仓库文件更新不会自动改写 VPS 已安装的通知配置。菜单中的官方测试会向真实 Telegram 聊天发消息，但不含真实攻击事件；HTTP 取证显示仍需观察实际新告警。

## 后续职责收敛（2026-10-12）

用户批准后，TG 菜单保留配置/更新、官方插件/API 回执测试、只读状态与重复来源检查、停用本工具通道四项。检测与决策属于 CrowdSec，实际拦截属于 Bouncer；TG 不扩展为远程解封、白名单或执行命令的控制机器人。

- 配置原位更新，可选即时通知或原生批量通知（`group_wait: 30s`、`group_threshold: 10`）；留空保留已有时序，首次配置默认即时。批量消息统计全部告警和规则，最多展示 10 个规则摘要、3 条详细告警，每条 1 组取证；剩余记录用 `cscli alerts list / inspect` 查询。消息整体限制在 3900 字节。
- 零/负 ID 显示实时告警，正 ID 保留告警编号；无决策与模拟告警分别说明。Go 模板对 `*bool` 先读取实际布尔值，避免 false 指针被误报为模拟。消息明确未核验 Bouncer 执行。
- 只读检查分别报告配置、有效 profile 路由、API 测试证据和真实攻击取证，列出同目标旧通道、重复路由、可能连续匹配的 profile，以及名称/cron 内容匹配的独立推送候选。候选不证明正在推送，也不能排除其他名称的进程；不停止或删除未知服务。检查不发消息。
- 官方 `cscli notifications test` 的退出码不足以证明送达：使用私有临时有效配置和 loopback 接收器转发一次实际插件消息，同时校验 API HTTP 状态和 JSON `ok: true`，不改变生产配置。拒绝重定向，错误输出脱敏。失败覆盖旧测试证据；证据文件权限 600，只含时间、配置指纹与接受结果，24 小时或配置变化后失效。API 接受不等于使用者已读或真实攻击验证。
- 停用时删除通知配置失败会恢复已修改的 profile 路由；独立复审复现后补充了旧实现失败、新实现通过的回滚回归。

TG 专项 **29/29 通过**，包含官方 CrowdSec 1.8.1 插件的真实模板和 API 成功/失败回执测试。真实引擎单条及批量隔离验证通过：实际 `/.env` 请求与 UA 入卡；10 条告警合并、两个规则各 5 条、模拟数量及 3 组有限取证正确。目标仅为本地接收器，未向真实 Telegram 发消息或部署 VPS。Bash 语法、Python 编译、ShellCheck 与 diff 空白检查通过。

后续完整回归 **451 项：450 通过、1 项可选跳过，无失败**（包含同一工作区其他任务的测试）。此结果为职责收敛及复审回滚修复后的最新验收；前面的 399 项记录保留为首轮修复历史。

```bash
PATH="$PWD/.venv/bin:$PATH" \
python3 tests/verify_telegram_batch.py /path/to/crowdsec-v1.8.1
```

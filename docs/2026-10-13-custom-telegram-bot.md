# 自定义 TG 机器人修复与接入

修复基于用户上传的 `crowdsec_bot.py`，原上传文件与 VPS 的 `/usr/local/bin/crowdsec_bot.py` 未覆盖。新版位于 `lib/crowdsec_bot.py`，保留九宫格、资源采样、告警查询、取证、NPM 日志抽样和原有操作入口。

## 原因与修复

原脚本执行 `cscli alerts inspect ID --no-metrics`。官方 CrowdSec 1.8.1 实测返回 `unknown flag: --no-metrics`，而原 `run_cmd` 忽略退出码和 stderr；取证正则继续解析空输出，导致“未知路径 / 未知 UA”。即使命令成功，人类可读输出也不是稳定的数据接口。

新版使用 `cscli -c CONFIG alerts inspect ID --details -o json`，支持官方返回的单个对象及数组；遍历事件 `key/value` Meta，识别 HTTP 与 AppSec 的路径、UA 和方法字段，解析告警上下文的 JSON 数组。样本来自同一事件，最多展示 3 组；只有 AppSec 单一上下文且路径一致时才补齐事件缺失值。多请求上下文不能证明路径与 UA 的对应关系时不强行组合。空 UA 与未记录 UA 分别显示，非 HTTP 告警说明不适用。

同时修复：

- 自动告警线程默认关闭，由官方 HTTP 通道唯一推送。查询和按钮产生的是用户请求响应；启动仍发送一条上线提示。
- 告警卡片展示实际附带决策和模拟状态，不再写死“内核 DROP 4 小时”；告警时间不称为已验证拦截时间。
- 命令使用参数数组、检查退出码和超时；封禁/解封校验 IP 与时长，不再通过 shell 插入用户输入，不再把失败显示为成功。
- 按钮与普通消息同时核对管理员个人 ID 和聊天 ID，支持群组负数 Chat ID。TG API 校验 JSON `ok`、拒绝重定向，长轮询 HTTP 超时大于等待时间，不打印含 Token 的异常。
- 同 Token 的本工具实例共享文件锁；轮询 offset 私有保存并按 Token 隔离，避免服务重启重放已领取更新，Token 更换不沿用旧 offset。更新在执行前记录，进程崩溃时可能丢失该次请求，应重新查询状态再重试。
- 白名单首次生成有效 YAML，原文件未知格式保留不改；修改前校验、失败恢复并报告恢复不完整。加白仅代表日志解析白名单，不保证 AppSec、CAPI 或其他防护放行。
- NPM 取证为最多 8 个 access 文件、每个尾部 512KB 的抽样；不是全量统计或容量承诺。资源菜单也不再声称没有 OOM 风险。

## 在 VPS 使用

1. 更新完整项目，包含脚本和 `lib`。
2. 核对并停用旧自定义机器人的轮询服务/cron，保留原脚本备份。官方 HTTP 通知保留。不要同时运行旧机器人与新版轮询同一 Token。
3. 在项目目录执行：

   ```bash
   sudo bash install-crowdsec-1panel.sh --custom-bot
   ```

   也可进入 `--telegram` 菜单第 5 项“可选交互机器人”。
4. 选择“配置/更新并启用”，填写 Token、Chat ID、管理员个人用户 ID、NPM 日志目录与 API 端点。Token 隐藏输入；留空沿用已保存值，首次可读取旧脚本中的静态参数。旧脚本参数只做 AST 字面量读取，不执行其代码。群组 Chat ID 与管理员个人 ID 不同，必须分别填写。
5. 在配置的聊天中发送 `/start`，然后用 `/inspect 告警ID` 核对路径/UA；核对按钮操作结果与实际 CrowdSec 决策。只读状态仅证明配置和服务状态，不证明 Telegram 轮询或生产拦截。

部署文件：

| 项目 | 路径 |
|---|---|
| 服务 | `crowdsec-1key-bot.service` |
| 程序 | `/usr/local/lib/crowdsec-1key-bot/crowdsec_bot.py` |
| 私有配置（600） | `/etc/crowdsec/crowdsec-1key-bot.json` |
| 状态目录（700） | `/var/lib/crowdsec-1key-bot` |
| 新机器人日志解析白名单 | `/etc/crowdsec/parsers/s02-enrich/crowdsec-1key-tg-whitelist.yaml` |

使用实际 `config.yaml` 的 DB 路径及 `-c` 参数，不假定 CrowdSec 数据库路径；原脚本 DB 路径仅作为缺省回退。旧白名单文件保留，管理员应核对现有规则是否仍需要。

更新前备份配置、脚本和 unit；启动失败恢复文件及原服务启用/运行状态。识别其他 CrowdSec 机器人服务、已知脚本进程或 cron 候选时拒绝启动，要求人工核对，不删除未知服务。即使同名服务位于 vendor/transient 路径，也检查 systemd 实际加载来源，只有本工具标记的服务才允许接管。名称/脚本扫描不能排除其他实现的同 Token 消费者，Telegram 409 冲突仍需排查其他节点。

交互机器人“停用”保留配置与程序，官方通知继续运行。确认卸载核心时会停用并移除受管理的机器人 unit、程序和状态，备份及旧独立脚本保留。此组件默认以 root 运行，以支持现有决策、白名单和重载操作；Token 与配置需保持私有，管理员权限等同于这些操作的主机权限。

## 隔离验收

`tests/test_custom_bot.py` 验证取证、身份校验、输入拒绝、操作失败反馈、单实例、offset、白名单创建/回滚、服务更新回滚、未知服务保留、核心卸载和独立停用。原实现复现了错误取证与错误成功反馈，新实现回归通过。

```bash
PATH="$PWD/.venv/bin:$PATH" python3 -m unittest discover -s tests -p test_custom_bot.py -v
PATH="$PWD/.venv/bin:$PATH" python3 tests/verify_custom_bot.py /path/to/crowdsec-v1.8.1
```

官方 1.8.1 引擎集成使用临时配置、真实 LAPI/SQLite 与 CLI：注入带事件 Meta 的合成告警，取证卡片正确显示路径、UA、来源及按钮；最新告警、保留的数据库菜单、生成的白名单均通过。`crowdsec -t` 和决策删除真实执行，systemd 重载模拟；从不调用真实 TG API，不代表 VPS 已部署或生产按钮操作已验收。

机器人专项 **26/26 通过，无跳过**；独立复审发现的卸载清理、白名单错误反馈、只读命令错误反馈、同名 vendor/transient 服务接管问题均已补齐回归并关闭。Bash/Python 语法、ShellCheck 和 diff-check 通过。

最终完整回归 **607 项：603 通过、4 项可选跳过，无失败**。含官方插件的既有 TG 测试及全仓其他测试；不把跳过项当作已经验证。运行输出及原脚本失败复现见 [验收记录](audit/2026-10-13-custom-telegram-bot-results.json)。

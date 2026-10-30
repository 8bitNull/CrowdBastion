# 2026-10-30 脚本全面复审

审查基线：`d31e3a2d96c8fcbe20dedad5f98f79d1ebb92417`。本轮检查主脚本及安装、配置事务、Hub、防火墙、Web Bouncer、真实 IP、Telegram 和 V2bX 的关键辅助模块，执行本地回归及隔离故障注入。仅新增审查证据，未修复产品代码、部署服务器、修改真实防火墙或发送 Telegram 消息。

发现 7 项需要处理的问题：1 项 P1、6 项 P2。其中 6 项有本地隔离复现；远端决策流游标副作用通过当前调用链和官方 CrowdSec 1.8.1 源码确认，未作真实中心实验。P1 表示应优先修复，P2 表示应纳入后续修复。

1. **[P1] Web Bouncer 撤销未确认重载生效，就删除运行依赖。**

   位置：`lib/native_web_bouncer.sh:217–227`；首次安装同类问题位于 `:167–169`，失败恢复也有直接发送 reload 的分支。

   `nginx -s reload` 返回 0 只能说明信号发送成功；master 可能因 Lua 初始化失败等原因继续运行旧 workers。撤销流程立即设置 `committed=true`，删除 Bouncer 账号和资源；仍运行旧配置的 workers 会失去依赖，正常网站流量可能被拒绝或报错。首次安装则可能将尚未生效的防护登记为成功。仓库已有 `nginx_reload_verified`，但只有部分升级/策略流程使用。

   隔离复现：模拟配置检查和 reload 命令返回 0、master 未接受重载。撤销仍返回 0 并显示成功，账号被删除、资源目录消失，未查询 workers。首次安装的同类模拟也返回成功。

   建议：安装、撤销和失败恢复统一核验新配置被 master 接受；账号/资源清理必须在旧配置恢复已被证实后进行，否则保留恢复记录与依赖。

2. **[P2] 首次分级通知安装遇到核心校验失败，会遗留活跃服务和启用链接。**

   位置：`lib/notify.sh:141`、`:65–74`；关联 `crowdbastion.sh:218–225`。

   `apply_core_config` 在 `crowdsec -t` 失败时先调用 `restore_config_change`，已删除新建 unit。随后 `notify_rollback` 的 `notify_owned` 为假，且首次安装的 `NOTIFY_WAS_PRESENT=false`，因此跳过 stop/disable。磁盘文件恢复了，但此前启动的通知进程和 systemd enable 链接未恢复。

   隔离复现：注入核心校验失败，返回 1；unit 已不存在，服务活跃标记与 enable 链接仍在；命令记录没有通知服务 stop/disable。已有测试只检查文件恢复，未验证这一服务状态。

   建议：由外层通知事务统一负责恢复顺序，或显式记录本次启动/启用动作；先停用新服务，再恢复或删除 unit。

3. **[P2] 分级通知启停没有中断回滚，可能留下指向不存在服务的路由。**

   位置：`lib/notify.sh:97–104`、`:147–153`；关联 `lib/crowdsec_notify_setup.py:108–119`。

   `prepare` 先将官方通知改为本地 webhook，之后才安装并启动 worker。流程仅在普通命令失败时显式回滚，没有自己的 EXIT/INT/TERM 事务处理，也未开启通用核心配置 pending 跟踪。收到 SIGTERM/SIGINT 时，外层锁的退出处理不会恢复这些文件。停用过程中也存在服务已停、路由未恢复的窗口。

   隔离复现：在真实 `prepare` 返回后向操作子 shell 发送 SIGTERM，退出码 143；路由仍是 `/alerts`，原路由未恢复，unit 尚未创建。核心下次加载该配置后自动通知无法投递。

   建议：在独立子 shell 中维护通知事务、提交标志和信号回滚，覆盖启用、更新和停用全过程。

4. **[P2] 配置 Telegram 会破坏 V2bX 告警的守卫检查，并阻止正常停用。**

   位置：`lib/crowdsec_config.py:660–678`、`lib/crowdsec_v2bx_alerts.py:131–133`、`:238–239`。

   Telegram 配置对所有 profiles 增加通知并重新序列化 YAML，包括 V2bX 的无决策守卫。V2bX 却要求文件以 `GUARD` 的原始字节串开头；字段新增或排版变化即被判定为守卫损坏。发布循环停止，后续 `disable` 也先执行同一检查，无法通过正常入口停用。即使 `decisions: []` 的安全语义仍保留，也会触发。

   隔离复现：在现有 V2bX 管理器 fixture 中成功 enable，再调用真实 `profiles … enable`。守卫仍为空 decisions，但 `check_managed`、`disable` 均抛出 `observation_guard_changed`。

   建议：明确两模块的配置所有权与协作方式；保留受管守卫或以结构化方式严格核验安全字段，并为通知字段变更提供受控迁移。仅放宽字节检查仍不能解决文档已说明的核心重启/消费游标维护问题。

5. **[P2] 远端认证预检会消费现用 Bouncer 的决策流游标。**

   位置：`lib/crowdsec_remote_bouncer.py:46–47`、`:107–115`；关联 `lib/remote_bouncer.sh:147–166`。

   预检使用真实密钥 GET `/v1/decisions/stream?startup=true`，但成功响应会更新中心记录的 Bouncer 拉取状态。更新现有节点、沿用当前密钥时，如果预检后配置写入失败或操作中断，旧进程没有重启全量同步，下一次增量拉取可能跳过被预检读取的新增/撤销决策。该调用不能视为无副作用认证检查。

   官方源码证据：[CrowdSec v1.8.1 decisions.go](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/apiserver/controllers/v1/decisions.go#L277)。`StreamDecision` 成功发送 GET 后调用 `UpdateBouncerStreamPull`；HEAD 分支明确不更新拉取时间，以免影响下次 delta。读取时该文件的 Git blob 为 `3c7396d5b793fd18f2cb17ee9758dfdc92abb6bc`。此项属于源码确认，未对实际中心执行请求。

   建议：使用上游提供的不消费游标的 HEAD 认证检查；若仍需验证响应内容，使用独立测试凭据，并避免复用运行中 Bouncer 的流。

6. **[P2] 远端预检拒绝超过 1 MiB 的合法决策流，阻止正常接入。**

   位置：`lib/crowdsec_remote_bouncer.py:53–60`。

   `startup=true` 返回全量决策，正常中心在启用较大封禁列表后就可能超过 1 MiB。当前代码将合法的大响应当作预检失败，而且统一改写为认证/TLS/连接错误；安装及修改连接都无法继续，诊断方向也不正确。

   隔离复现：loopback HTTP 服务返回 10000 条决策、1468914 字节、HTTP 200、合法 `new/deleted` JSON；预检仍拒绝并报认证/TLS/连接错误。

   建议：优先改用 HEAD，从根本上避免认证预检拉取全量名单；如需读决策，采用有明确容量策略的流式处理，并保留真实失败分类。

7. **[P2] 全局卸载遗漏 V2bX 采集/发布服务，删除核心后仍留下启用的辅助服务。**

   位置：`crowdbastion.sh:1882–1887`、`:1911–1918`；残留检查 `:1799–1817` 同样未覆盖这些服务。

   全局卸载处理通知机器人、核心和 Firewall Bouncer，却既不检查也不停用 `crowdsec-v2bx-observer.service`、`crowdsec-v2bx-alerts.service`。随后删除 `/etc/crowdsec`，发布器失去受管规则与核心配置；采集器可以继续写观察数据库，两个 unit 仍可能开机启动。保留历史证据不应等同于继续运行服务。

   隔离复现：临时树中存在两个 V2bX unit 时，全局卸载返回 0、删除核心配置、保留两个 unit，命令记录没有对应 stop/disable。该复现只验证卸载遗漏，不声称真实 systemd 行为已实测。

   建议：删除核心前检查相关受管服务，要求先停用或在核验所有权后有序停用；保留证据目录，并让残留检查展示这些组件。

最终全量回归 **1135 项：1091 通过、44 跳过、0 失败/错误**，耗时 433.979 秒。跳过包括 18 项真实 Lua Nginx、21 项官方 CrowdSec 插件/回执、1 项 gost 和 4 项 pycdlib 检查，不能计入通过证据。另完成 Web 安装 21 项、Web 工作流 14 项，以及真实通知 worker 对接本地 TLS 模拟 API 的 1 项专项，均通过，数量与全量重叠。

前一轮已配置依赖的全量回归有 1 项错误：接收端 16 个槽位占满时，测试预期 HTTP 503，却收到 `URLError(BrokenPipeError)`；单独重跑也失败，最终全量运行则通过。期间未修改相关代码或测试，因此保留为时序相关的回归不稳定性，不把最后一次通过当作问题消失。首轮另外发生的系统 Python 缺少 PyYAML、独立 Web 测试缺少模块搜索路径，已通过设置 `PYTHONPATH` 排除，不计为产品缺陷。

17 个 Bash 文件语法、36 个生产 Python 文件语法与 diff 空白检查通过。ShellCheck 0.11.0 在既有排除项下没有 error/warning 级诊断，但有 3 条 info（SC2030 × 1、SC2031 × 2，涉及子 shell 中 `assets` 的作用域），命令退出 1；不将此描述为全量 ShellCheck 零诊断通过。

详细结果见同目录 `2026-10-30-script-review-results.json`；隔离复现脚本与结果位于 `2026-10-30-script-review/`。命令及前置条件以结果文件为准。真实 systemd、内核防火墙、目标 Nginx/Lua、远端中心及公网 Telegram 送达不在本轮运行验证范围内。

复现前准备 `tests/requirements.txt` 中的 PyYAML，并确保子进程使用的系统 Python 也能导入。仓库已有虚拟环境时可从仓库根目录执行（按实际 Python 版本调整路径）：

```bash
PYTHONPATH="$PWD/lib:$PWD/.venv/lib/python3.11/site-packages" \
  .venv/bin/python docs/audit/2026-10-30-script-review/reproduce.py
```

Web 复现沿用现有测试的官方固定资源：`/tmp/crowdsec-official-openresty.tgz` 来自 `https://github.com/crowdsecurity/cs-openresty-bouncer/releases/download/v1.2.3/crowdsec-openresty-bouncer.tgz`，SHA256 为 `2a3dceeb166b3fabb450c1c9a5ccd960d1493f5aa52677a9be2be36d6014a0bf`；`/tmp/crowdsec-http` 来自 `https://codeload.github.com/ledgetech/lua-resty-http/tar.gz/refs/tags/v0.17.1`，SHA256 为 `f52a0538b20a2d45025f318c18a138b78f6f88f07713dd0ed502183cb3d16f17`。本轮下载后均已核对哈希。

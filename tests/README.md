# 测试入口与范围

仓库沿用 unittest。默认完整测试，不根据旧耗时自动排除用例；现有 `python3 -m unittest discover -s tests` 仍可用。先准备现有依赖：

```bash
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements.txt
```

从仓库根目录执行：

```bash
# 日常核心回归：防误封、凭据、事务、锁、双栈、转发证据与生命周期
.venv/bin/python tests/run_tests.py --tier quick

# 修改功能后的相关模块；可重复 --module，名称不含 .py
.venv/bin/python tests/run_tests.py --module test_workflows --module test_maintenance

# 发布或跨模块变更前：完整发现，包括专项与历史节点回归
.venv/bin/python tests/run_tests.py --timings /tmp/crowdbastion-full-timings.json

# 环境依赖专项；缺少条件时显示每种跳过原因
.venv/bin/python tests/run_tests.py --tier integration

# 已备齐该专项全部依赖时，禁止用跳过项冒充验收通过
.venv/bin/python tests/run_tests.py --tier integration --require-no-skips

# 特定节点历史脚本的回归；所需的两份脚本仍随仓库分发
.venv/bin/python tests/run_tests.py --tier archive

# 只看清单，不运行 setUp/用例
.venv/bin/python tests/run_tests.py --tier quick --list
```

`test_tiers.json` 显式列出 quick、integration、archive 的模块，三者不重叠。full 包含全部发现的测试，包括未列入清单的新模块。quick 是精选子集，不能代替完整验证；普通功能模块在 full 中，通过 `--module` 单独运行。模块筛选与 `--tier` 取交集；未知模块、重复清单、空选择或导入失败返回 2，避免静默漏测。只列清单仍会导入测试模块。

专项入口复用已有测试：integration 包含 Lua Nginx、官方通知插件和本地 TLS worker 等环境依赖模块；其中部分测试在普通主机上也能运行。常见依赖由现有用例检查，包括 `CROWDBASTION_TEST_NGINX`、`CROWDBASTION_TEST_LUA_PREFIX`、`CROWDSEC_TEST_RELEASE`、openssl 和预备好的固定版本资源。严格检查某一专项可加 `--module`，不必为无关模块备齐依赖。

真实内核网络、容器/虚拟机、官方 Bouncer 与 realm/gost 的数据面验收，仍使用已有 `verify_relay_network.py`、`verify_relay_iptables.py`、`verify_remote_bouncer.py`、`verify_vps_matrix.py` 等隔离实验入口，按各脚本 `--help` 和相关文档准备条件。普通 unittest 通过不代表这些实验已执行，也不代表公网 UDP、重启或攻击流量验收通过。本轮没有运行它们。

`--timings PATH` 输出 JSON，记录选择范围、总墙钟时间、每项状态和耗时、跳过原因、失败/错误/预期失败/意外成功计数，以及最终是否被接受。逐项耗时包含用例 setUp、测试本体、tearDown 与 cleanup；模块/类夹具与导入耗时只计入总时间，夹具失败单独记录且耗时为 null。跳过的子测试会让父用例标记 skipped；跳过计数按 unittest 事件计，可能与 skipped 状态的父用例数不同。`--top N` 控制控制台慢项摘要，默认 10；`--top 0` 关闭摘要。失败返回 1，严格模式遇到 skip 也返回 1，报告写入失败返回 2；`--list` 不能与 `--timings` 合用。

`workflow_fixture.py` 只保存公共夹具，不继承 TestCase，也没有测试方法。每项仍创建独立临时目录；不要让功能测试继承包含测试方法的类。`Workflows` 保留为原回归类，并继承该 mixin；少量现有测试内直接调用它继承来的辅助方法保持兼容，以保留原测试方法源码。新测试应直接使用 `WorkflowFixtureMixin`。

耗时用于定位维护成本，不能直接证明用例冗余。优先优化反复启动进程、真实等待和重复准备；仅在输入、风险路径、断言和失败可定位性都等价时才合并用例。共享可变目录、缓存被测配置或按历史耗时跳过测试会削弱隔离性，不作为本轮提速手段。

最新 quick 为 311 项全部通过、无跳过、约 33 秒；最新 full 为 1669 项、1580 通过、89 项因环境条件跳过、约 487 秒。原有覆盖保留，入口和夹具行为自测合计新增 14 项。三项显式虚拟时钟回归从 40.49 秒降至 3.19 秒，十项显式事务夹具回归从 29.79 秒降至 7.50 秒；这些局部收益不代表整仓按相同比例提速。不能以 quick 替代相关功能回归或发布验证。

`reload_clock.virtual_reload_clock()` 仅供三项使用同步假命令的重载业务回归显式启用。它让假 sleep 推进每个临时树自己的逻辑时间，仍执行真实的 PID、日志证据与回滚代码。真实命令、线程、截止时间和子进程清理测试继续使用实钟；不要把该辅助函数设为默认夹具。支持的 sleep 参数为 0–60 秒的单个十进制数，转义、负值、单位后缀及科学计数法会被拒绝。

`WorkflowFixtureMixin.run_optimizer()` 供只验证优化事务的测试显式使用：前置健康诊断固定为待验证（返回 2），事务仍运行原来的锁、依赖、YAML、确认、写入、校验、服务加载与回滚。调用者的 overrides 在该替换后执行。健康报告本身、诊断依赖、交互摘要或完整集成行为测试应继续使用 `run_shell()`。原有取消测试、两项缺少 YAML 的诊断测试、完整优化测试和独立健康报告测试保留真实诊断。

官方 Web 归档已在本机准备并校验：`/tmp/crowdsec-official-openresty.tgz`（OpenResty Bouncer v1.2.3）和 `/tmp/crowdsec-http`（lua-resty-http v0.17.1）。此前因这两份资源缺失而跳过的 45 项已全部补跑通过，剩余 44 项仍需其它环境依赖。本次是定向补跑，未产生新的整仓运行结果；测试总数仍为 1669。资源未随仓库分发，/tmp 清理后需从上游重新下载，并按 `lib/crowdsec_web.py` 固定 SHA256 校验。

剩余 44 项专项已补齐依赖并全部实际通过（Lua Nginx18、官方通知21、种子/gost5）。原工作区可先 `source docs/audit/2026-11-04-specialist-dependency-validation/environment.sh`，再运行 `tests/run_tests.py --tier integration --require-no-skips`；该环境脚本仅保留在本地，引用已校验的 /tmp 资源。新克隆需按上文准备依赖并设置对应变量，不能直接使用该路径。可选 Python 依赖在 `tests/requirements-integration.txt`。设置该环境后的发现阶段没有依赖跳过；本轮是分组验证，未重新运行完整套件。详细版本、SHA256 和边界见对应审计记录。

原始验收输出、临时脚本与计划仅在本地归档。现有回归直接引用的两份节点脚本和一份脱敏 JSON 仍随仓库分发，见 [发布范围](../docs/repository-layout.md)，普通测试不依赖未跟踪的本地证据。

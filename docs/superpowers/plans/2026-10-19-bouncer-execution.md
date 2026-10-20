# Bouncer 执行核验 implementation plan

**Goal:** 在 TG 查询 Web Bouncer 的真实拒绝记录。
**Architecture:** vendor ban 标记 -> log 阶段确认 -> Nginx error log -> 有界 Python reader -> 已鉴权 TG 查询。
**Tech stack:** Python stdlib, Lua/OpenResty, Bash, unittest。
**Spec:** ../specs/2026-10-19-bouncer-execution-design.md
**Constraints:** 用户已确认；在既有隔离工作区执行；保留全部用户改动与故障策略；不提交整个脏基线；不发送真实 TG 测试消息。

- [x] Task 1 — 在 tests/test_web_bouncer_runtime.py 写拒绝证据失败测试。
  `status, body, count, records = self.request_case("deny", "rule_block", evidence=True)`；断言 status403、count0、cause=appsec_rule、request_id32位。增加 LAPI ban、故障拒绝、业务403、正常/故障放行和伪造头。
  Run: `CROWDBASTION_TEST_NGINX=/tmp/crowdbastion-lua-runtime-20261019/root/usr/sbin/nginx CROWDBASTION_TEST_LUA_PREFIX=/tmp/crowdbastion-lua-runtime-20261019/root PYTHONPATH=/tmp/crowdbastion-test-python-20261019:tests python3 -m unittest test_web_bouncer_runtime -v`。
- [x] Task 2 — lib/crowdsec_web.py 生成 log.lua、execution.lua，严格匹配固定 vendor 补丁；PHASES 含 log，1Panel 用 loadfile 保留原 hook。记录接口 mark(ip,cause,expected_status)、emit()。真实 HTTP 测试转绿。
- [x] Task 3 — tests/test_execution_evidence.py 验证尾读、来源/状态/时间/IP校验、缺失与零命中，随后实现 lib/crowdsec_execution.py 的 query(log_dirs,ip,since,now=None) -> dict。最多128日志、每文件64KiB、总8MiB；无 symlink；只认执行 Lua 模块产生的 Nginx error log 行。
- [x] Task 4 — tests/test_custom_bot_execution.py 先验证 exp:ID 回调鉴权、先确认再查询、刷新原卡、无证据与异常区分；再修改 lib/crowdsec_bot.py 和 lib/crowdsec_config.py。forensics 加按钮；module_execution 查当前来源IP决策，调用 reader，显示同源关联边界。
- [x] Task 5 — lib/custom_bot.sh 纳入新 Python companion 的备份/安装/归属/清理；lib/crowdsec_web.py 与 lib/native_web_bouncer.sh 提供既有安装受保护升级；tests/test_web_install.py 验证策略保留、哈希冲突拒绝、原WAF日志顺序与恢复。
- [x] Task 6 — 运行相关 Python、Bash 和真实 Lua tests；请求独立 code review，修复重要问题；仅将 feature 增量同步主目录。
- [x] Task 7 — VPS 先备份并核验哈希，独立 NPM loopback 验证；部署受管理 Web 文件和 bot 增量；语法检查、重载/单服务重启；离线渲染查询结果；记录 docs/audit/2026-10-19-execution-evidence.md 的结果与未验证范围。

完成记录：最终项目目录专项 76 项通过；VPS 独立 OpenResty 11 项通过；成功发布备份 execution-proof-20261019T133705Z；有效 hooks、单实例、离线查询及策略保留经独立复核。首次发布查询失败已恢复，补充有界就绪检查后重试成功。详见 ../../audit/2026-10-19-execution-evidence.md。

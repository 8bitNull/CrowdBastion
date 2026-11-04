# 优化事务测试的诊断边界收敛

用户要求继续定位整仓耗时。本轮先按命令边界剖析：四项取消/EOF 输入累计健康事件序列化 92 次（2.926 秒）、PyYAML 可用性探测 40 次（1.435 秒），以及多次真实诊断 helper。事务断言反复承担独立健康报告的成本。

方案：增加显式测试夹具入口 `run_optimizer(user_input='', overrides='', timeout=15)`，只替换 smart_audit_and_optimize 的前置 check_health_status 为记录一次调用并返回 2（检查尚未验证）的固定结果。真实事务、日志发现、配置写入、锁、参数交互、配置/服务校验和回滚保持不变。调用者 overrides 在固定诊断后追加，仍可显式覆盖。

仅把 tests/test_workflows.py 中 10 个以 test_optimize_ 开头的事务测试改用该入口。四个原有测试继续走完整 run_shell：test_optimize_cancel_does_not_change_configuration、两个缺少 YAML 的诊断测试、test_optimize_all_items_loads_changes_once。独立健康报告、节点引导、CLI 集成和其它夹具消费者完全不变。相比默认抹去诊断、缓存 import 结果、持续 Python 服务或并行执行，显式边界更便于确定各测试在验证什么。

保留原 1667 个测试 ID、原断言 AST；只允许这 10 项测试方法改变调用入口。增加 2 项夹具行为约束：真实 metrics 事务执行但不运行健康 helper；调用者覆盖诊断失败状态后事务仍按实际代码执行。新入口只在测试中存在，不修改生产代码、默认 run_shell 行为、分层清单或 VPS。

验收：10 项改前/改后单独计时，四项完整集成及健康报告重点验证，真实事务定向变异应被原断言检测；所有旧 ID/断言保留检查；独立复审；一次最终完整验证；基线哈希保护交付。全量耗时按实测报告，不从局部收益推断整仓提速。不提交或部署。

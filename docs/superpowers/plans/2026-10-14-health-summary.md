# Health Summary Implementation Plan

**Goal:** 让普通用户看到一个明确、准确的检查结论和一个相关的下一步。

**Architecture:** 检查器记录固定的状态标识，标准库报告器统一生成结论。技术输出临时保存在私有目录，展开详情不重新运行检查。

**Tech Stack:** Bash、Python 3 标准库，沿用现有 YAML 检查器。

**Spec:** 用户已确认的设计：默认简短总结、详情按需展开，区分运行通过但拦截待验证、问题、部署未完成、检查未完成；缺少证据不能判为正常。

## Global Constraints

- 保留主菜单 1–8 和现有参数；新增详情参数。
- 检查只读，不自动安装、修复、封禁或发送业务验证请求。
- 退出码沿用 1 异常、2 待验证；组合故障优先。
- 不改品牌和启动画面；远端节点不恢复本地检测中心探测。
- 可选组件未部署不影响结论；已部署组件仍须检查。

## Task 1: Typed results and verdicts

Files: `lib/crowdbastion_health.py`, `lib/health_summary.sh`, `tests/test_health_summary.py`。

- [x] 先增加故障、缺失、无法读取、空闲日志、完整证据和缺少结果的判定测试，运行确认失败。
- [x] 实现 `emit(key, state)` 与 `summarize(records, status, scope, roles)`；必需检查缺失时判为无法完成，固定文案不包含原始配置。
- [x] 验证 fault > missing > unknown/pending > runtime pass；无实际验证记录不得宣称全部通过。

## Task 2: Integrate checks and navigation

Files: `crowdbastion.sh`, `lib/node_guidance.sh`, `lib/relay.sh`, `lib/v2bx.sh`, `lib/remote_bouncer.sh`, `lib/maintenance.sh`, 对应 Python 检查器。

- [x] 增加 CLI 默认简短、详情仅采集一次、PTY 返回/EOF 清理、故障推荐日志和缺失推荐安装的测试，先观察失败。
- [x] 在原有检查分支记录结果；包装整体、中转和 V2bX 检查为统一报告，提供详情参数。
- [x] 交互仅显示推荐操作、详情、返回；保留原操作锁与确认。
- [x] 原有详细输出测试改用明确的详情入口，保留只读和角色分派断言。

## Task 3: Documentation and delivery

Files: `readme.md`, `docs/usage-guide.md`, `docs/cli-reference.md`, `docs/verification.md`。

- [x] 记录结论含义、详情参数和验证示例。
- [x] 运行针对性测试、全套回归、Bash/Python 语法、ShellCheck、文档链接和差异检查。
- [x] 独立代码审查并修复重要问题。
交付步骤：提交、合并到 main 并推送，使用会话中的既有授权。

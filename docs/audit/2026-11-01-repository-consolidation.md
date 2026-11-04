# 2026-11-01 仓库整理与合并验收

以 `43e592536d88a2074136a03c1521003c5392c89f` 为基线，整理 `feat/user-experience-20261101` 工作树，目标为快进合并至 `main` 并推送 `origin/main`。本轮仅进行本地仓库整理及回归验证，既有 VPS 操作记录按各报告原文保留。

## 整理范围

- 纳入安装前变更预览、按用途引导、修改后的自动只读复查、快捷菜单、诊断导出、中转历史验收、V2bX 配置生成及维护副本同步。
- 纳入已有部署修复、逐项确认旧开机任务、双栈防火墙入口及实际引用集合的决策核对。
- 纳入 Telegram 维护互斥、同源健康检查、自包含副本更新、后台健康查询，以及一小时关注／六小时普通汇总与后续复审修复。
- 纳入相应测试、用户说明、设计与计划，以及 2026-11-01 的使用体验、Telegram 和两台 VPS 的原始审计证据。
- 明确纳入 `2026-11-01-user-experience/` 中被全局 `*.log` 忽略规则排除的 11 份验收日志，保持报告引用及原始路径完整。缓存、虚拟环境和运行时数据库仍使用现有忽略规则。
- 清理 `tests/test_existing_deployment.py` 末尾一个多余空行，未修改测试逻辑；与最近一次 169 文件验收源码快照相比，仅此处格式变化。

## 验证

本轮从当前代码完整重跑 **1425 项：1336 通过、89 按条件跳过、0 失败／错误**，unittest 耗时 472.202 秒，控制器耗时 472.529 秒，退出码 0。完整输出见回归日志（本地归档：`2026-11-01-repository-consolidation/full-regression.txt`）及退出结果（本地归档：`2026-11-01-repository-consolidation/full-regression-result.json`）。命令为：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests:lib python3 -m unittest discover -s tests
```

测试期间唯一源码变化为上述测试文件末尾空行清理；全量结束后针对该文件另跑 24 项，全部通过，见专项结果（本地归档：`2026-11-01-repository-consolidation/existing-deployment-regression.txt`）。最终产品与测试源码摘要见 source-sha256.json（本地归档：`2026-11-01-repository-consolidation/source-sha256.json`）。日志中的故障／回退输出来自隔离测试，不是本轮生产操作；条件跳过不计作通过。

静态检查包括 150 个产品／测试 Python 文件 AST、19 个 Bash 文件语法，以及 ShellCheck warning/error 级检查，沿用 `SC2317`、`SC2329`、`SC2120`、`SC2119` 排除项。主入口 `--help` 已实际执行。

本轮核对原归档的 208 条哈希，全部匹配；初始待提交文档中的 315 个本地链接目标均存在，且对应文件已纳入提交。7 份原始差异／补丁证据包含上下文空格及末尾空行，保留原始字节，不宣称全归档 `git diff --check` 无提示；产品、测试和持续维护文档的差异检查通过。具体文件见静态记录（本地归档：`2026-11-01-repository-consolidation/static-checks.json`）。

新增内容及补纳入日志的私钥、Telegram Token 和 GitHub Token 常见格式扫描未发现匹配；该扫描不替代原始审计的脱敏边界说明。

为保留前轮归档中支持文档的历史摘要，本轮新增索引条目前的审计索引另存为 prior-audit-index.md（本地归档：`2026-11-01-repository-consolidation/prior-audit-index.md`）。各轮历史源码摘要记录当时状态，不能作为当前完整源码一致的证明。

## 分支与验证边界

`main`、当前功能分支与 `origin/main` 的起点相同，本轮目标采用快进合并。已有 `archive/20261020/*` 分支和备份 worktree 保留；它们的历史整合见 [2026-10-20 仓库整合验收](2026-10-20-repository-consolidation.md)，不重新合并归档分支。已清理指向不存在目录的临时验证 worktree 登记。

本轮未连接 VPS 或 Telegram，也没有执行真实防火墙迁移或公网阻断验收。各报告中的历史失败、条件跳过、真实投递及业务拦截验收边界继续有效。

# 2026-11-04 全量严格零跳过验收

本次在当前主工作区实际执行完整套件，**1669 项全部通过，失败 0、错误 0、跳过 0**。严格模式 `--require-no-skips` 已启用，测试进程退出码为 0，报告 `accepted=true`。没有通过缩小选择范围、修改断言或改变跳过条件完成验收。

## 实际结果

| 指标 | 结果 |
| --- | --- |
| 测试范围 | full；未指定模块过滤 |
| 发现、选中与实际执行 | 1669 个唯一 ID，完全一致 |
| 通过 | 1669 |
| 失败 / 错误 / 跳过 | 0 / 0 / 0 |
| 预期失败 / 意外成功 | 0 / 0 |
| unittest 执行耗时 | 618.279 秒 |
| 测试入口总耗时（含发现） | 618.555 秒，约 10 分 19 秒 |
| 开始 / 结束（UTC） | 2026-11-04 01:08:23 / 01:18:42 |

上一次完整套件为 1669 项、1580 通过、89 项依赖跳过。本轮测试 ID 集合与其完全相同，原 89 项跳过用例均在本次完整运行中实际通过；这是一次新的完整运行记录，不是将此前分组结果相加。

## 执行与依赖

在仓库根目录执行：

```bash
source docs/audit/2026-11-04-specialist-dependency-validation/environment.sh
.venv/bin/python tests/run_tests.py --tier full --require-no-skips \
  --timings docs/audit/2026-11-04-full-strict-validation/full-timings.json
```

运行前再次核验官方 Web 归档，以及 CrowdSec cscli、notification-http、gost、Nginx 和动态模块的既有 SHA256；记录 Python 版本、PyYAML/pycdlib 版本和相关环境变量。专项资源仍位于本机 `/tmp`，清理或换机器后需要重新准备，环境脚本仅设置变量。

日志中的 Telegram 429/5xx、拒绝重载、防火墙状态异常及回滚提示来自相关测试夹具和故障路径，不能作为本机或远端 VPS 的现场状态报告；最终用例状态全部为 passed。

## 文件与执行边界

运行前记录的 1769 个现有仓库文件在测试结束及最终核对时哈希全部一致。本轮仅新增本报告及对应证据目录，未修改生产代码、测试实现、断言或既有审计记录。运行结束后未发现从专项依赖目录执行的残留进程。

本轮没有登录或变更 VPS，没有提交、推送或部署。真实 Lua Nginx 与官方通知程序、gost 等在本地测试夹具中执行；该结果不替代公网 TCP/UDP、实际内核封禁、VPS 重启或攻击负载验收。

## 证据

- 逐项状态与耗时（本地归档：`2026-11-04-full-strict-validation/full-timings.json`）
- 完整控制台日志（本地归档：`2026-11-04-full-strict-validation/full.txt`）
- 结果摘要（本地归档：`2026-11-04-full-strict-validation/summary.json`）
- 命令、时间与退出码（本地归档：`2026-11-04-full-strict-validation/run.json`）
- 测试 ID 清单（本地归档：`2026-11-04-full-strict-validation/selected-tests.json`）
- 依赖校验（本地归档：`2026-11-04-full-strict-validation/dependency-verification.json`）
- 运行前文件哈希（本地归档：`2026-11-04-full-strict-validation/baseline-hashes.json`）
- 运行后文件核验（本地归档：`2026-11-04-full-strict-validation/source-verification.json`）
- 最终交叉核验（本地归档：`2026-11-04-full-strict-validation/verification.json`）
- 交付哈希清单（本地归档：`2026-11-04-full-strict-validation/delivery-manifest.json`）

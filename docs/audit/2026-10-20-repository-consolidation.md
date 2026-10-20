# 本地与远程仓库整合验收

2026-10-20，以 `origin/main` 的 `e960b08` 为基线整合原目录的 38 个内容修改、63 个新文件及两个开发分支的修复。正式提交统一整理变更，原始中间状态保留在本地归档分支和备份中，避免把早期快照中的批量执行权限变更带入主线。

## 整合结果

- 保留防火墙续封缺陷与有效启动程序检查、新装后端选择、AppSec/LAPI 故障策略、Web 拒绝记录，以及 Nginx 接受配置和 worker 更替的重载证据与失败回滚。详见[脚本复审](2026-10-20-script-rereview-fixes.md)、[worker 重生修复](2026-10-20-nginx-respawn-fix.md)和[执行证据](2026-10-19-execution-evidence.md)。
- 合入 Telegram 统一九宫格、卡片导航、同管理员确认与审计、运行诊断、信号中断结果待核对、重启后继续等待已保存的 API 退避时间。
- 合并时保留源目录较新的本机/管理员地址封禁保护、执行证据模块和安装 helper；取证页同时提供执行核验与当前决策查询。新增回归验证取证、执行核验及返回时保持同一告警 ID，查询只编辑原卡片。
- 原目录 101 个变更文件全部纳入。协调后的 5 个文件是机器人主程序、流程测试及 3 份相关说明；其余源变更内容不变。兼容入口软链接保留，既有文件无执行模式变更。

## 验证

| 检查 | 结果 |
| --- | --- |
| 原目录基线 | 1026 项，1005 通过、21 可选跳过、0 失败；377.980 秒 |
| 整合版全量 unittest | 1047 项，1026 通过、21 可选跳过、0 失败；377.339 秒 |
| 机器人专项 | 160 项全部通过 |
| 官方 Telegram 插件与回执补验 | 全量中跳过的 16 项另行全部通过；本地 loopback 接收器 |
| 真实 Nginx/Lua | 全量内 18 项全部通过，含初始化拒绝、旧 worker 重生及回滚 |
| 包管理/配置保留模拟矩阵 | 109/109 通过 |
| 独立只读审查 | 未发现实质问题，另有 65 项定向测试通过 |
| 语法 | 26 个 Bash、194 个 Python 文件通过 |
| ShellCheck 0.11.0 | 无警告或错误；3 条跨独立子 shell 局部变量的既有提示，经审查确认误报 |

其余未运行的可选检查为 1 项官方 gost 二进制及 4 项 ISO 媒体验证。文档相对链接、差异空白及凭据模式检查通过。测试日志摘要、代码与测试 SHA256 见[结构化结果](2026-10-20-repository-consolidation-results.json)。

复现主回归：

```bash
PYTHONPATH=/tmp/crowdbastion-review-deps:tests:lib \
PYTHONDONTWRITEBYTECODE=1 \
CROWDBASTION_TEST_NGINX=/tmp/crowdbastion-lua-runtime-20261019/root/usr/sbin/nginx \
CROWDBASTION_TEST_LUA_PREFIX=/tmp/crowdbastion-lua-runtime-20261019/root \
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

真实运行时需固定版本 Nginx/Lua、OpenSSL、`/tmp/crowdsec-official-openresty.tgz`、`/tmp/crowdsec-http`；官方通知补验另设置 `CROWDSEC_TEST_RELEASE=/tmp/crowdbastion-official-render-release-20261019`。完整准备条件见上述历史验收报告。

## 本地归档与同步

原目录整理前状态已保存为 `archive/20261020/source`（`05c27df`）。其余 5 个临时工作区已移入 `/projects/script/CrowdBastion-backups/20261020T015901Z/archived-worktrees/`，保留未提交内容、原文件权限、软链接及被忽略文件，逐项哈希与 Git 差异核对一致。已命名分支整理至 `archive/20261020/`；原来的七个开发提交仍可访问。备份目录保存引用 bundle、元数据、逐文件清单及完整日志。

整合结果经验证后以快进方式更新本地 `main`，使用普通推送更新远程 `main`，再次核对两端提交一致。归档分支保留在本地，不作为远程开发分支发布。

本轮没有部署 VPS 或向 Telegram 发送消息。Docker/systemd 边界使用 fixture，Nginx/Lua 使用真实进程；源码回归不替代目标 VPS 的真实业务请求与内核阻断验收。

# Telegram 重启限流等待复核（2026-10-21 UTC）

用户要求修复轮询收到 `429 retry_after=120`、10 秒后重启跳过剩余 110 秒的问题。本轮检查的本地和远程 `main` 均为 `c5c194e829973ba06c7999809c689ffdfac911a8`，已经包含原修复 `2059356677f8b233952359d9d9ee8e8f028f3b8e` 的内容（经 `fc395ad` 整合）。因此没有重复修改生产代码或已有回归测试；本提交记录重新验证结果。

## 修复与回归位置

- `lib/crowdsec_bot.py:1265` 的 `main()` 首先调用 `wait_for_retry(get_api_client().retry_delay())`，再注册命令、启动通知线程和进入轮询；这些位置对应本轮检查的已提交版本。
- `tests/test_custom_bot_flow.py:173` 的 `PollingRestart` 使用实际客户端状态持久化，销毁客户端后重新加载；网络与时钟隔离，不调用真实 Telegram。
- `test_restart_waits_for_remaining_rate_limit_before_any_request` 覆盖 120 秒限流、第 10 秒重启，断言等待 60+50 秒后才发送 `setMyCommands` 和 `getUpdates`。另有 5xx 退避恢复、已过期等待、首次启动三项回归，四项均通过。

在临时副本中仅移除上述启动等待，再运行 429 重启回归：测试按预期断言失败，实际请求时间为 1010，期望为 1120。原源码保持不变，验证测试能够识别原缺陷。

## 新鲜测试结果

| 检查 | 结果 |
| --- | --- |
| 当前全部 TG 专项（包含原 128 项及后续新增项） | 162 项全部通过 |
| 全量 unittest discover | 1063 项：1024 通过、39 可选跳过、0 失败；325.075 秒 |
| Nginx/Lua 与官方 Telegram 通知补验 | 35 项全部通过，补齐全量中的 29 个跳过项 |
| Nginx 实际重载补验 | 5 项全部通过，补齐全量中的另外 5 个跳过项 |
| 去重后完整套件结果 | 1058 通过、5 可选跳过、0 失败，共 1063 项 |

剩余可选跳过为 1 项官方 gost 二进制测试与 4 项依赖 pycdlib 的 ISO 媒体验证。另检查了相关 Python 语法与差异空白。结构化计数、源码与日志摘要见[验证结果](2026-10-21-telegram-restart-backoff-verification.json)。

复现主要命令：

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/tmp/crowdbastion-tg-deps:tests:lib python3 -m unittest test_custom_bot_flow.PollingRestart -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/tmp/crowdbastion-tg-deps:tests:lib python3 -m unittest discover -s tests -p 'test_custom_bot*.py' -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/tmp/crowdbastion-tg-deps:tests:lib python3 -m unittest discover -s tests -p 'test_*.py' -v
```

补验使用已有的 `CROWDBASTION_TEST_NGINX=/tmp/crowdbastion-lua-runtime-20261019/root/usr/sbin/nginx`、`CROWDBASTION_TEST_LUA_PREFIX=/tmp/crowdbastion-lua-runtime-20261019/root`、`CROWDSEC_TEST_RELEASE=/tmp/crowdbastion-official-render-release-20261019`，运行 `test_web_bouncer_runtime test_telegram` 及 `test_nginx_reload.LiveReload`。

验证在隔离工作区完成，未包含原目录尚未提交的 TG 卡片文案修改，未修改生产服务或发送真实 Telegram 消息。本提交只新增验证记录及结构化结果。

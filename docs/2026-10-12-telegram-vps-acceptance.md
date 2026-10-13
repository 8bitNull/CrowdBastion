# TG 模拟 VPS 验收（2026-10-12）

本轮隔离模拟验收通过。使用临时 VPS 配置目录、loopback 端口和真实进程，不是完整虚拟机安装。未安装系统服务、修改宿主机防火墙或发送真实 Telegram 消息，生产代码未修改。

官方组件：CrowdSec 1.8.1、OpenResty 1.25.3.2、OpenResty Bouncer 1.2.3、lua-resty-http 0.17.1。OpenResty Debian 包按 SHA256 核验后解包运行；Firewall Bouncer 0.0.36 仅执行配置校验，不作为实际防火墙拦截证据。

## 验收结果

| 检查 | 证据与结果 |
|---|---|
| 配置/迁移/停用 | TG 专项 29 项、停用工作流 2 项全部通过，无跳过；重复配置路由去重，同目标旧通道迁移，其他目标保留，校验及删除失败回滚 |
| 重复来源诊断 | base/local 路由顺序、重复路由、可能连续匹配的 profile、独立服务/cron 候选及脱敏通过；服务和 cron 输入是模拟数据 |
| 官方测试回执 | 真实 HTTP 插件发送至本地模拟 TG API；成功、401/429、HTTP 200 且 ok=false、CLI 成功却无消息、证据过期及配置变化均有覆盖 |
| 即时通知 | 真实 AppSec `/.env` 告警经官方插件显示请求路径和 UA，普通请求放行 |
| 批量通知 | 10 次实际 AppSec 请求生成合并通知；另经真实 LAPI 注入 10 条合成告警，两个规则各 5 条、模拟 2 条、详细样本 3 条，长度限制通过 |
| 实际 Web 拦截 | 真实 OpenResty/Bouncer 收到 `/.env` 请求，HTTP 403 且后端未收到；正常 `/` HTTP 200 且后端收到；原 WAF 拦截及钩子保留 |
| 同一次请求关联 TG | 客户端 → OpenResty/Bouncer → AppSec → 官方 HTTP 插件 → 模拟 TG API；仅收到 1 条匹配 `/.env` 的攻击卡片，路径、UA、来源 IP 一致。另有 1 条官方测试消息，不计入攻击卡片 |
| 故障策略 | AppSec 不可用时 passthrough 到达后端，deny 未到达后端；官方 Bouncer 的 deny 页面可能 HTTP 200，判断依据为后端是否收到请求 |
| 状态边界 | 测试回执正常后，只读状态仍将生产攻击取证标为尚未验证，返回 2；隔离验收结果不冒充生产配置的验证证据 |

实际捕获卡片包含：

```text
场景: crowdsecurity/vpatch-env-access
决策: 本告警未附带处置决策
来源: 203.0.113.20
刺探目标: GET /.env
客户端指纹: CrowdSec OpenResty integration
```

卡片明确通知未核验 Bouncer 实际拦截；本轮拦截证据来自真实 HTTP 响应、AppSec 计数/规则命中和后端请求记录。未出现“未知路径”“未知 UA”或误报模拟状态。

关联验收复用了 `tests/verify_web.py` 的真实 Web 实验室，在临时驱动中于引擎启动前加入 TG 配置、官方插件和本地 API 接收器。初次驱动断言遗漏路径前的 `GET`，导致正确卡片未被匹配；修正匹配、在引擎存活期间等待通知后，重新运行全部关联流程通过。不是业务模板修复。

## 重跑与边界

```bash
PATH="$PWD/.venv/bin:$PATH" \
CROWDSEC_TEST_RELEASE=/path/to/crowdsec-v1.8.1 \
python3 -m unittest discover -s tests -p 'test_telegram*.py' -v

PATH="$PWD/.venv/bin:$PATH" \
python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1

PATH="$PWD/.venv/bin:$PATH" \
python3 tests/verify_telegram_batch.py /path/to/crowdsec-v1.8.1

PATH="$PWD/.venv/bin:$PATH" \
python3 tests/verify_web.py /path/to/crowdsec-v1.8.1 \
  /path/to/crowdsec-openresty-bouncer-v1.2.3.tgz /path/to/lua-resty-http-v0.17.1.tgz
```

以上独立命令覆盖通知与 Web 拦截；同请求关联还需本轮临时驱动的 TG 接收器配置。完整运行输出、卡片及验收摘要见 [原始记录](audit/2026-10-12-telegram-vps-results.json)。

本轮不证明真实 Telegram 公网/代理连通、目标 VPS 包管理与 systemd 安装、未知按钮机器人运行情况、生产 Firewall/Docker/IPv6 链路或 24–48 小时运行稳定性。后续到目标 VPS 加载模板，再用真实回执和另一台设备的请求完成生产验收。

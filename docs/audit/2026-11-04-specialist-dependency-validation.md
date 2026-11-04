# 2026-11-04 剩余 44 项专项依赖与验证

按用户要求补齐并实际执行上一轮剩余的 44 项测试，全部通过：零失败、零错误、零跳过。未修改生产代码、测试实现或断言，未登录或变更 VPS。新增可选测试依赖清单和复跑文档。

## 已执行

| 分组 | 项数 | unittest 耗时 | 验证范围 |
| --- | --- | --- | --- |
| Lua Nginx | 18 | 90.152 秒 | 真实 master/worker 重载、旧进程拒绝、失败回滚、请求放行、AppSec/LAPI 故障拒绝、业务 403 与拦截回执区别 |
| CrowdSec 官方插件与回执 | 21 | 21.252 秒 | 官方 notification-http 模板执行、消息截断/字段语义、持久队列、去重及 HTTP/API 拒绝与回执失效 |
| 种子和 gost | 5 | 2.327 秒 | 4 项 ISO/payload 完整性检查与官方 gost 的持续 UDP 并发转发 |

三组独立并行运行，耗时不能相加当作总墙钟。选中 ID 与上一轮 remaining-skips.json 的 44 个 ID 完全一致，状态均为 passed。未改变 skip 条件，也没有通过替换依赖、缩短实际等待或减弱断言使其通过。

上一轮已额外补跑 45 项，本轮完成剩余 44 项；原来 89 个依赖跳过项现均有实际通过证据。设置本轮环境后，完整发现仍为 1669 项，发现阶段依赖跳过为 0。本轮没有重复执行完整套件，不将分组结果写成一次新的全量通过记录。

## 资源和隔离

- CrowdSec v1.8.1：从官方 crowdsec-release.tgz 提取配置、cscli 与 notification-http；归档 SHA256 为 ae64cdab8ee49534d6c36eab4ce40b5478842a4b4abfe83f7796aace569821eb。
- gost v3.3.3 linux amd64：官方归档 SHA256 为 f4c1255dc892a7014c0ad6e5f1c3573108f7bea4403f04f21873406ab58aa666。
- Debian 12 amd64 Nginx 1.22.1-9+deb12u10、Lua 模块 0.10.23、ndk、LuaJIT2、resty-core/lrucache、cjson 与 pcre：9 个包按本机 APT 索引的 SHA256 校验，仅 dpkg-deb -x 解包到 /tmp/crowdbastion-specialist-deps/nginx-root；未安装系统 Nginx 服务。
- pycdlib 1.14.0：下载 wheel，按 PyPI 元数据 SHA256 校验后，仅安装到项目 .venv。既有 .venv 不含 pip，因此使用系统 pip 的 --python 指向虚拟环境安装，未写入系统 Python 包。

版本、URL、归档/包 SHA256 和大小详见 resources.json。资源校验后才执行，未运行厂商安装脚本；Lua Nginx 的监听、日志、配置与进程均由原临时测试夹具管理。

## 复跑

在本机仓库根目录启用已准备好的环境：

```bash
source docs/audit/2026-11-04-specialist-dependency-validation/environment.sh
PYTHONPATH=tests:lib .venv/bin/python -m unittest -v \
  test_nginx_reload.LiveReload \
  test_web_bouncer_runtime.WebBouncerRuntime \
  test_notify_integration.OfficialNotificationPipeline \
  test_telegram.TelegramRendering test_telegram.TelegramReceipts \
  test_vps_seed.SeedTests \
  test_relay_benchmark.Benchmark.test_persistent_gost_udp_concurrency
```

也可使用现有入口运行环境专项：

```bash
.venv/bin/python tests/run_tests.py --tier integration --require-no-skips
```

可选 Python 依赖清单为 tests/requirements-integration.txt。临时二进制目录未随仓库分发，清理 /tmp 或换机器时，需按 resources.json 的固定版本和摘要重新准备；仅设置环境变量不会下载或安装资源。

## 实际边界

本轮以 root 使用 Debian 12 amd64、本机真实 Nginx/Lua 与官方程序。Telegram HTTP/API 回包由本地测试服务模拟，没有向真实用户发送通知；gost 为本机 UDP 转发，并非公网或内核封禁验收。ISO 测试读取生成介质和内容，未启动虚拟机。结果不替代真实 VPS 冷启动、公网 TCP/UDP 或攻击负载测试。

证据：本轮目录（本地归档：`2026-11-04-specialist-dependency-validation/`）。原 45 项补跑见 [上一轮](2026-11-03-official-web-archive-validation.md)。交付核验完成：17 个文档/证据/依赖清单文件（另计 manifest 本身），1751 个其余原文件保持基线哈希，205 个既有源码/测试/规则文件保持原样，新清单使核对文件总数为 206。未提交、推送或部署。

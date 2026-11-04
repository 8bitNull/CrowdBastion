# 2026-11-03 官方 Web 归档依赖补齐与定向验证

本轮补跑上一轮因缺少官方归档而跳过的 45 项集成回归。生产、测试和规则源码均未修改，未登录 VPS、安装系统软件或部署服务。只准备本地测试归档并新增文档和审计证据。

## 结果

此前跳过的 45 项全部实际执行通过：零失败、零错误、零跳过，unittest 耗时 131.533 秒，总墙钟 131.625 秒。覆盖官方归档分发与隔离、原 WAF 保护、重复安装、桥接网络、容器重建、旧版升级、卸载、异常加载和恢复失败时依赖保留。相关 Docker、systemd 与包操作按原测试夹具模拟。

| 模块 | 此次从跳过变为实际通过 |
| --- | --- |
| test_native_workflows | 14 |
| test_deployment_adapters | 13 |
| test_web_install | 10 |
| test_vps_hardening | 5 |
| test_script_review_fixes | 2 |
| test_audit_appsec | 1 |

本轮没有新发现需要修改源码的问题。所有选中测试 ID 与结果逐一相等，状态均为 passed。

## 官方资源

下载后先调用生产代码已有的 `crowdsec_web.verify_archive()` 校验固定 SHA256，再以不覆盖已有文件的方式放置到原测试要求的路径；未执行厂商安装脚本。

| 资源 | 测试路径 | SHA256 |
| --- | --- | --- |
| CrowdSec OpenResty Bouncer v1.2.3 | /tmp/crowdsec-official-openresty.tgz | 2a3dceeb166b3fabb450c1c9a5ccd960d1493f5aa52677a9be2be36d6014a0bf |
| lua-resty-http v0.17.1 | /tmp/crowdsec-http | f52a0538b20a2d45025f318c18a138b78f6f88f07713dd0ed502183cb3d16f17 |

上游 URL、大小和 tar 成员数见 resources.json。两份资源共约 84KB，当前留在本机 /tmp，未加入仓库；清理临时目录或重启后可能需要重新准备。

## 剩余边界

上一轮完整套件为 1669 项：1580 通过、89 项环境跳过。本轮只执行其中此前跳过的 45 项；因为源码未变，没有重复运行完整套件，也不把两次结果写成一次新的全量通过记录。

剩余 44 项在当前发现阶段仍明确因环境依赖跳过：Lua Nginx 18、官方 CrowdSec 通知插件 16、官方接收回执 5、可选 gost 1、pycdlib 4。测试 ID 和原因见 remaining-skips.json。45 个补跑 ID 与这些 44 个 ID 无重叠，恰好覆盖上轮 89 个跳过项。

本轮验证是带官方归档的配置/事务测试，不代表真实 Nginx/Lua 请求处理、官方通知插件执行、内核数据面、公开网络攻击或 VPS 冷启动验收。后续优先补齐可复现的 Lua Nginx 与官方插件运行环境。

证据：[本轮目录](2026-11-03-official-web-archive-validation/)。此前完整验证见 [上一轮记录](2026-11-03-optimizer-test-isolation.md)。

交付核验完成：8 个文档/证据文件（另计清单本身）哈希一致，1743 个其余原文件保持基线哈希，205 个源码/测试/规则文件与执行版本一致。未提交、推送或部署。

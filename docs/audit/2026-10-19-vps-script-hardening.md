# 多台 VPS 问题回流：一键脚本优先加固

本轮落实已确认的前两项优化：规避已知 nftables 续封缺陷，统一托管 Web Bouncer 的 AppSec/LAPI 故障策略入口。依据是[第二台 VPS 续封修复](2026-10-19-second-vps-remediation.md)、[第二台故障策略调整](2026-10-19-second-vps-appsec-failure-policy.md)和[第三台修复验收](2026-10-19-third-vps-remediation-acceptance.md)。本轮仅修改与验证源码，未连接、部署或重载任何 VPS。

## 防火墙后端

- 首次本地、远端 Bouncer 安装默认使用 iptables/ipset；iptables 的 nf_tables 兼容层与 Bouncer 的 nftables 后端分开判断。
- 合并基础 YAML 与 `.local` 检查实际后端。nftables 版本优先取运行中服务的 `/proc/<MainPID>/exe -version`，避免磁盘上替换过的程序掩盖实际运行版本。
- 已确认 0.0.36、0.0.38 的 nftables 后端有续封缺陷。核心安装、Bouncer 包安装／远端配置及连接修复会在相关修改前拒绝；诊断向健康总结报告异常。其他 nftables 版本标为尚未验证，保留既有配置，不推断已修复。
- 配置损坏时仅输出通用诊断，避免 YAML 错误回显 API 密钥。iptables/ipset 检查通过仅表示未使用这一已知缺陷实现，仍需真实续封流量验收。

本轮没有自动迁移已有 nftables 部署。迁移需单独保存有效决策和规则、保护管理员来源，再按[使用说明](../usage-guide.md#安装后的验证)完成短封、续封、跨原截止时间、删除及自然到期的独立来源对照。

## 网站故障策略

- 新装本工具托管的原生容器 Web Bouncer 明确设置 AppSec/LAPI 故障均 `deny`，返回 HTTP 403；正文不可读策略保持 `false`。故障期间正常访客也可能被拒绝，已有允许缓存仍按剩余有效期使用。
- 旧托管安装可重新运行 `--install-web-bouncer`，升级 Lua 模块、配置解析器和执行记录钩子，保留账号、密钥、URL 及原策略。旧配置未指定 LAPI 策略时仍按兼容默认 `passthrough`，不随升级改为拒绝。
- `--appsec-policy` 在核验资源归属、实际模块能力及有效请求钩子后，分别提供两项策略选择。未确认能力的宿主机／第三方／旧模块明确提示，并拒绝写入显式 LAPI 策略。
- 修改后核对有效配置、重载及钩子；失败恢复策略和安装记录。模块升级的回滚备份包含配置解析器，重复执行无变化时不重复改写。

LAPI 策略仅控制 `MODE=live` 的决策查询错误；`stream` 后台同步不受该选项控制。详细操作和缓存边界见 [AppSec 说明](../appsec-guide.md)。

## 本轮验证

- 完整 unittest **902 项：881 通过、21 跳过、0 失败**，耗时 306.375 秒；其中真实 Nginx/Lua 运行时 **13 项全部通过**。
- 包管理／配置保留 fixture 矩阵 **109/109 通过**，覆盖 Debian/Ubuntu 与 RPM 系发行版分支，未执行真实系统安装。
- Bash 语法检查 **25 个文件**、Python AST 解析 **181 个文件**及 `git diff --check` 通过。
- 21 项可选检查跳过：1 项 gost、16 项官方 CrowdSec 通知插件／回执、4 项 ISO 媒体校验。独立只读复审无未解决的实质问题。

本轮统计、跳过原因和源码摘要见[结构化验证结果](2026-10-19-vps-script-hardening-results.json)。

真实 Nginx/Lua 请求对照覆盖 AppSec、LAPI 的连接拒绝、超时和 HTTP 错误，新装默认拒绝均检查 HTTP 403 与业务后端零请求，并保留健康请求 HTTP 200 对照。另将原始旧模块、已有执行记录的旧模块分别升级后发出真实故障请求，验证两项策略生效。

源码回归覆盖有效 `.local` 后端、运行中二进制优先、未知版本、凭据不泄露、提前拒绝账号创建、部分写入回滚、重复策略键、策略保留、非托管能力拒绝和重载前后钩子漂移。包管理分支使用临时目录与模拟命令，不是各发行版真实安装验收。

完整回归在隔离目录执行，使用临时 PyYAML 依赖与已准备的 Lua-enabled Nginx：

```bash
PYTHONPATH=/tmp/crowdbastion-review-deps:tests:lib \
PYTHONDONTWRITEBYTECODE=1 \
CROWDBASTION_TEST_NGINX=/tmp/crowdbastion-lua-runtime-20261019/root/usr/sbin/nginx \
CROWDBASTION_TEST_LUA_PREFIX=/tmp/crowdbastion-lua-runtime-20261019/root \
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

运行时用例还需要已固定校验的 `/tmp/crowdsec-official-openresty.tgz` 与 `/tmp/crowdsec-http`。未提供 Nginx 或归档时相应集成测试会跳过，不能将普通源码回归替代为运行时验证。本轮未运行 ShellCheck，当前环境未安装该工具。

## 范围与后续

此次改动在现有工作区快照的隔离目录完成，回填时仅同步本轮差异，保留此前未提交改动。没有提交、推送或生产部署。本轮未执行真实内核封禁／续封或外部 VPS 业务验收；相关历史实测单独保留，不算作本轮部署结果。

定时任务去重、定期日志盘点和通用版本漂移管理保留为后续事项。本轮也不提供 nftables 自动迁移或对未知版本的修复保证。

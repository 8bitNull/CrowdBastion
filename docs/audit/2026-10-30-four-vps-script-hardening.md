# 四台 VPS 验收结果回流到脚本

本轮将四台现场记录中的共性问题纳入管理脚本，保留工作区已有的 Nginx 重载、真实 IP、健康摘要修复及原始证据。没有连接 VPS、修改生产配置、发送 Telegram 消息或创建提交。

## 调整

- `--firewall-check`：只读定位 cron／rc.local 的规则恢复命令和常见启用的恢复服务，检查 Docker 启动顺序及双栈链入口；读取失败报尚未验证，不等同没有风险。整体网站／系统健康检查纳入对应观察。
- `--firewall-maintenance`：提供 iptables 启动配置修复和分阶段后端迁移。启动配置保留两地址族的自定义链，补齐 INPUT／FORWARD 及适用的 DOCKER-USER；专用 `After=docker.service` drop-in 不覆盖其他内容。配置未变且运行检查通过时跳过重启，规则丢失时仍尝试恢复。失败通过原有事务恢复。
- 本地安装、Bouncer 连接修复和远端 iptables 接入复用启动配置逻辑；远端接入的回滚同时恢复新增 drop-in。
- nftables 迁移仅处理通过预检的默认官方 root 服务及本机 LAPI。保留基础配置和凭据，提前建立独立回退定时器、有效封禁快照和 SSH 来源／实际端口保护，核验内核覆盖与既有业务规则／策略。配置漂移时不覆盖管理员修改。
- 提交前必须运行本事务的双栈 TCP／UDP 输入／转发封禁、续封、删除、自然到期和正常对照验收，并从同一管理员来源的新独立 SSH 连接提交。测试地址、接口、命名空间、路由或监听冲突时停止；使用独立 systemd 服务和清理定时器管理临时监听。
- 回退恢复原配置并确认原生集合重新覆盖有效封禁后，才移除临时封禁快照；未确认恢复时保留保护及备份。LAPI、YAML 和 HTTP 库错误不打印凭据。

使用步骤与支持条件见[防火墙维护](../firewall-maintenance.md)。现场依据见[四台 VPS 验收索引](README.md#2026-10-30-vps-修复与复审)，本轮不会把现场的 sysctl 或 gost 端口选择套到其他服务器。

## 验证

完整回归命令：

```bash
PYTHONPATH="$PWD/lib:$PWD/.venv/lib/python3.11/site-packages" \
.venv/bin/python -m unittest discover -s tests -v
```

完整回归发现 **1202 项，1113 通过、89 跳过、0 失败／错误**，耗时 421.176 秒。在其运行期间继续完善回退覆盖、凭据脱敏、路由冲突和重复修复等边界，因此最终代码另外执行针对性回归，而没有将较早启动的完整回归冒充最终代码全量重跑。

最终针对性回归命令：

```bash
PYTHONPATH="$PWD/lib:$PWD/tests:$PWD/.venv/lib/python3.11/site-packages" \
.venv/bin/python -m unittest \
  test_firewall_runtime test_vps_hardening test_firewall_startup test_remote_bouncer -v
```

结果为 **96 项，91 通过、5 跳过、0 失败／错误**。其中新增的 43 项检查和事务测试全部通过；覆盖成功迁移流程、定时器先于切换、原配置及凭据保持、部分写入失败、配置漂移拒绝、旧 SSH／缺少流量证据拒绝提交、内核集合覆盖、双栈入口／负匹配拒绝、测试资源冲突和启动修复回滚。最终针对性跳过的 5 项均需固定官方归档；全仓跳过另包括 Lua Nginx、通知插件／回执、gost 和 pycdlib，详见原始日志。

136 个产品及测试 Python 文件 AST、主入口和 16 个 Bash 模块语法、ShellCheck warning/error（沿用 SC2317、SC2329、SC2120、SC2119 排除项）和 `git diff --check` 通过。证据目录保存两次正式回归的日志、结果 JSON 和本轮源码 SHA256。

## 范围

本轮防火墙、systemd、SSH 连接和 LAPI 的变更测试使用临时文件及模拟命令，没有对新的通用迁移工具执行真实宿主机切换或冷启动演练。四台既有现场证据说明原问题及其定点修复有效，不能代替新工具在其他配置上的部署验收。

独立定时器会在 8 分钟触发回退，并与交互操作共用事务锁；正在执行的检查或系统调用超时可能延迟实际恢复。配置漂移或无法确认内核覆盖时需要人工处理保留的私有备份。回退到原生 nftables 不会修复旧后端的已知续封缺陷。

本机流量验收不会自动写入公网攻击阻断通过记录；公网 CDN、Docker 实际业务端口和 V2bX 协议仍需按真实路径验收。旧开机任务只做定位，具体停用与规则归属仍需人工核对。

证据：[结果](2026-10-30-four-vps-script-hardening/results.json)、[完整回归](2026-10-30-four-vps-script-hardening/full-regression.txt)、[最终针对性回归](2026-10-30-four-vps-script-hardening/focused-regression.txt)、[摘要清单](2026-10-30-four-vps-script-hardening/SHA256SUMS)。

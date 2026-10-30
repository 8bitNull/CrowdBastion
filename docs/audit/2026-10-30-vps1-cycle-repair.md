# 第一台 VPS：循环复审与修复

目标 `45.82.122.6:53322`，沿用 root 公钥及已固定的主机密钥。此记录接续同日的 [首次部署记录](2026-10-30-vps1-script-remediation.md)，后者的“防火墙续封问题尚未解决”是历史状态，现已修复。

## 结果

- Firewall Bouncer 0.0.36 的原生 nftables 续封缺陷已在本机复现，并迁移到 iptables/ipset 后验证修复。
- 修复真实 IP 工作流未确认重载生效的问题，以及重载进程采样的过渡状态误报；日常脚本与维护 release 均已更新。
- 最终 59 项针对性回归全部通过；真实 OpenResty 隔离测试通过；一个公网正常请求的真实 IP 核验完整通过。
- 健康检查由退出码 **1（故障）** 变为 **2（运行检查通过，外部实际拦截待验证）**。未宣称已完成公网攻击阻断验收。

## 防火墙复现与修复

在本机临时网络命名空间使用 `198.18.233.2`、`fd42:cb:1::2` 作为测试封禁来源，另设不封禁的对照来源。覆盖 IPv4/IPv6 × TCP/UDP × 主机输入/转发，共 8 条封禁流及相应对照流。

原后端先设置 40 秒封禁，再延长到 120 秒。原到期时间之后，LAPI 决策仍有效约 85 秒，但 8 条封禁流全部恢复可达，确认续封缺陷。`flow-before.json` 的 `passed: true` 表示**成功复现故障**，不是原配置健康。

安装 `ipset` 及其依赖，保留原 Bouncer YAML 和凭据，以 `.yaml.local` 覆盖启用 `mode: iptables` 与 `INPUT, FORWARD, DOCKER-USER`。增加 systemd `After=docker.service`。系统 iptables 使用 nf_tables 兼容层，与有缺陷的原生 nftables Bouncer 后端不同。

迁移期间使用独立恢复定时器、当前有效封禁的临时快照规则和 SSH 来源保护。前两次迁移校验分别误判了官方分片 ipset 名称和 `CROWDSEC_CHAIN` 间接跳转，触发回退；第一次回退被操作进程中断后显式完成，第二次自动完成。根据上游实现修正校验器后，第三次迁移成功。失败日志保留在远端，没有作为成功证据。

迁移后同样的续封测试全部正确阻断，正常对照始终可达；删除决策和自然到期均恢复通信。迁移时 17,400 条应覆盖网络全部在内核中；最终动态快照为 17,379 条，缺失为 0（统计剩余有效期超过 15 秒的决策）。既有 1Panel/Docker 规则内容与顺序保持，两种地址族的三个入口均先进入 CrowdSec 链。新的独立 SSH 连接成功。

## 脚本循环修复

1. `lib/real_ip.sh` 的应用、撤销、临时诊断恢复现在统一使用 `nginx_reload_verified`。恢复未确认时不写“已验证”记录。新增回归覆盖真实重载拒绝时的配置/注册记录恢复及错误传播。
2. 生产核验暴露出进程采样竞态：先处理有效 master 下的短暂无 worker 空窗；再次核验时抓到新 fork 子进程尚未改名，仍显示 master 标题。最终按父子关系识别此过渡状态，在原有共享 10 秒观察期限内等待稳定采样。独立多 master、master 更换和查询失败继续拒绝；仍要求 master 接受配置的日志证据。
3. 最终针对性回归 **59/59 通过**，覆盖重载进程证据、真实 IP、部署适配与请求审计。Bash 语法、ShellCheck warning/error 级别及 `git diff --check` 通过；ShellCheck 默认级别另有原有 EXIT trap 函数 SC2329 提示。本轮没有重跑整个仓库测试集。
4. 使用生产相同镜像的临时 OpenResty 容器实测，禁用网络且无业务挂载：正常重载成功；`nginx -t` 成功但 Lua 初始化主动失败时，确认函数返回失败且保留原 worker；恢复后重载成功。第一份隔离夹具错误使用了非默认配置路径，失败后修正；最终证据来自 `reload-isolated-r3`。

最终公网正常请求访问 `https://codeg-x.688600.xyz/`，连接对端为 Cloudflare 地址，访问日志 IP、Bouncer IP、预期出口 IP 均为 `45.82.122.6`。临时 Lua 诊断恢复及重载确认成功，完整命令退出 0。先前两次核验的失败及恢复日志均保留；最终托管资源检查和 Bouncer 配置原始摘要检查通过。

## 最终运行状态与边界

- CrowdSec、Firewall Bouncer、Docker 均 active；核心与 Nginx 配置检查通过。CrowdSec 和 Docker 的启动时间保持不变，既有健康容器仍 healthy。
- `codeg-x.688600.xyz`、`test.688600.xyz`、`waf.860525.xyz` 三站源站首页均返回 200。这组检查使用 loopback `--resolve` 和 `-k`，不代表公网 TLS 验收。
- 测试决策、命名空间、网卡、18080 监听、临时规则/封禁快照、隔离容器、恢复定时器均已清理；迁移已提交，自动回退已解除。
- 未发送 Telegram 消息。正常页面真实 IP 核验不等于公网恶意请求拦截验证，也不代表其他域名已逐一完成真实 IP 验收。
- OpenResty 日志中既有 1Panel 可选模板缺失及未配置 recaptcha key 提示不属于本轮已修复项；未擅自更改验证码策略或下载模板。

## 部署与恢复资料

最终维护 release：`/usr/local/lib/crowdsec-1key/release-review-20261030-cycle4-d75639c0`。`current` 已原子切换；日常目录 `/root/crowdsec-1key` 的两个修复模块与维护 release 摘要一致。旧 release 均保留。未创建 git 提交。

远端备份及过程证据：`/var/backups/crowdbastion/vps1-cycle-20261030/`，目录仅 root 可访问，文件 0600。包含原配置、规则、迁移/回退日志、故障复现和修复后流量结果、原脚本与最终脚本。含凭据备份未下载到仓库。

防火墙人工回退入口为 `python3 /var/backups/crowdbastion/vps1-cycle-20261030/migrate.py manual-rollback`，带配置漂移检查及切换保护。该入口经过语法检查，但提交后人工回退未执行；回退会返回已知存在续封缺陷的旧后端，不能作为常规维护步骤。原完整备份仍位于 `/var/backups/crowdsec-1key/remediation-20261030-ab0af70/`。

可审阅证据： [最终验证](2026-10-30-vps1-cycle-repair/verification-final.json)、[故障复现](2026-10-30-vps1-cycle-repair/flow-before.json)、[修复后流量测试](2026-10-30-vps1-cycle-repair/flow-after.json)、[隔离重载测试](2026-10-30-vps1-cycle-repair/isolated-reload.json)、[真实 IP 核验](2026-10-30-vps1-cycle-repair/real-ip-live-verification-final.txt)、[回归测试](2026-10-30-vps1-cycle-repair/reload-regressions-final.txt)。目录 `SHA256SUMS` 包含证据、报告和本轮源码摘要。

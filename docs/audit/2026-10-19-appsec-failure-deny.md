# AppSec 故障策略切换为 deny

用户明确确认后，已于 **2026-10-19 13:53 UTC** 将 `179.255.121.95:53322` 上托管 Web Bouncer 的 `APPSEC_FAILURE_ACTION` 从 `passthrough` 切换为 **`deny`**，保留 `FALLBACK_REMEDIATION=ban`。**13:53:39 UTC** 独立复核通过。脱敏数据见[验收证据](2026-10-19-appsec-failure-deny-results.json)。

AppSec 检查发生连接失败、读取超时或服务错误时，将拒绝请求；不再按原有 AppSec 故障放行策略继续回源。正常访问也可能在 AppSec 故障期间收到 403，这是本次用户已确认的安全与可用性取舍。

## 变更与生效验证

本次只修改两个文件：

- `/home/docker/npm/data/crowdsec-1key/bouncer.conf`：仅将 `APPSEC_FAILURE_ACTION=passthrough` 改为 `APPSEC_FAILURE_ACTION=deny`，其他字节保留。
- `/etc/crowdsec/crowdsec-1key-web-installs.json`：仅更新该配置对应的资源指纹。指纹按既有规则将 `APPSEC_URL` 归一化，其他记录语义不变。

操作前核对配置、安装状态、请求钩子和 Lua 文件摘要，持有工具管理锁后备份并原子替换。发布前后 `nginx -t`、托管资源完整性及有效 access/log hooks 均通过。完成平滑重载，master PID 保持 `317941`，worker 从 `2051094` 更新为 `2052528`；独立复读确认新 worker 仍运行、目标配置为 `deny`。

CrowdSec、Firewall Bouncer、自定义 TG 机器人均为 active，PID 未变、重启计数均为 0。没有修改账号、密钥、机器人配置、Lua 源码、超时或 LAPI 故障策略，没有重启这些服务或更改防火墙规则。本轮不改变仓库的新安装默认值。

## 真实 OpenResty 对照

先在 VPS 当前 NPM 容器中启动独立、仅监听 loopback 的临时 Nginx，使用**实际生产安装的 Lua 库**，配置独立模拟 LAPI/AppSec 端点和计数的业务上游。测试使用独立凭据和端口，没有让生产 AppSec 停机，也没有对生产站点发送故障探针。

| 场景 | HTTP 状态 | 业务上游请求数 | 执行回执 |
| --- | ---: | ---: | --- |
| AppSec 健康，策略 deny | 200 | 1 | 无拒绝回执 |
| AppSec 连接拒绝 | 403 | 0 | appsec_failure |
| AppSec 读取超时 | 403 | 0 | appsec_failure |
| AppSec 返回 503 | 403 | 0 | appsec_failure |

四个场景全部通过；拒绝回执由 log 阶段生成，并被 TG 使用的读取器接受。隔离测试结束时生产进程列表未变，临时 Nginx 进程和目录已清理。隔离验证目录为 `/var/backups/crowdbastion/appsec-deny-validation-20261019T134856Z`。

独立发布脚本复审无剩余重要问题；模拟验证了新 worker 确认、无新 worker 时超时拒绝、master 变化时拒绝、服务恢复失败后的回滚重试及未知并发编辑拒绝。

本次没有发送 TG 测试消息，没有公网/CDN 全链路探测；四个运行时场景属于独立 loopback 对照，生产生效证据为配置、完整性、有效 hooks 和新工作进程。本次切换不代表此前 AppSec 突发超时原因已解决，也不证明每条历史告警的原始请求被拦截。

## 备份与回滚

备份：`/var/backups/crowdbastion/appsec-deny-20261019T135302Z`。原配置、安装记录、完整输出仅保留在 root 可访问的目录，仓库中不包含凭据。

若要恢复为变更前的 `passthrough`，在 VPS 执行：

```sh
python3 /var/backups/crowdbastion/appsec-deny-20261019T135302Z/rollback.py
```

回滚持有同一管理锁，核对两个文件的前后摘要允许列表和备份摘要，拒绝未知并发修改；恢复原字节、权限和所有者后检查 Nginx 配置，并要求 master 不变、出现新 worker 才报告恢复成功。服务恢复失败后允许再次执行。

先前的[执行核验部署记录](2026-10-19-execution-evidence.md)中“保留 passthrough”描述的是当时状态；本次确认后已切换为 deny。

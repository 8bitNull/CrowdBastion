# 192.0.2.19 排查方向复核

2026-11-03，通过新建专用 SSH 密钥连接 root@192.0.2.19:53322。本轮仅查询配置、服务、决策及内核集合，并请求网站首页；未修改远端配置或重启服务。

## 当前实测

- CrowdSec、Firewall Bouncer、Docker、V2bX 均 active。最近两小时相关服务 journal 的 err 查询无记录，不代表所有文件日志无错误。
- 适用 ban IP/range 网络 15,343，内核集合网络 15,343，遗漏 0。调用远端现有 `crowdsec_firewall_evidence.inspect`；按该模块排除即将过期的决策。这是快照核对，不是实际业务流量阻断测试。
- IPv4、IPv6 的 INPUT、FORWARD、DOCKER-USER 首条均跳转 CROWDSEC_CHAIN；该链引用对应地址族来源集合执行 DROP。
- Nginx 配置查询成功，无 access_by_lua hook，也未发现 crowdsec 配置文本。不能据此认定没有其他类型的请求防护，但不能声称已安装 CrowdSec 请求级拦截。
- site-05.example.com 源站和公网 HTTPS 首页均为 200。源站通过 loopback resolve 并跳过证书校验；公网请求正常校验证书。
- 当前采集指标：Nginx access.log 369 行读取、369 行解析；auth.log 228 行读取、51 行解析、177 行未解析。不能仅以未解析数判定有效 SSH 检测失效。
- netfilter-persistent 为 active、disabled；本轮未验证重启行为及其他启动依赖。
- `/etc/cron.d/crowdsec-autoupdate` 存在，活跃任务为每日本地时间 03:30 执行 `/usr/local/lib/crowdsec-1key/current/manager.sh --update-hub`，目标文件存在。旧 `/opt/crowdbastion/maintenance/current` 不存在不足以证明维护缺失。本轮未执行更新或验证历史任务成功情况。
- 根分区使用率 83%，剩余约 1.8 GiB。gost-http-proxy 仍退出，其他三个既有容器运行；HTTP 代理先前因端口冲突停用，不能视为已恢复业务。

## 对排查方向的判断

当前证据不支持重复重装或切换 Firewall Bouncer 后端。既有报告中的配置和路径结论必须重新核实，不能直接当成仍存在的故障。

目前已证明运行状态、决策入核及正常首页访问。尚未证明真实网站访客来源识别、请求级攻击阻断、V2bX 协议业务阻断、封禁续期和重启后的恢复。没有实际异常复现时，不能把这些待验收项全部称为修复失败，也不能把当前快照称为全面修复完成。

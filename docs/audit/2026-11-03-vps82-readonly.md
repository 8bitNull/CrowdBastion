# 192.0.2.27：CrowdBastion 部署适配性只读检查

**结论：具备运行脚本及轻量防火墙 Bouncer 的基础条件，优先推荐远端 Bouncer-only；不建议在当前小内存及旧系统上直接照搬上一台 VPS 的本地 CrowdSec 部署。** 本地精简检测模式并非确定不能运行，但需要额外容量试验；本轮未安装，不能宣称已验证其稳定性。

目标为 `root@192.0.2.27:53322`。用户开启公钥认证后登录成功；现场采样时间为 **2026-11-03 11:54:59–11:57:29 UTC**。只读查询经 SSH stdin 在内存执行，没有在服务器部署脚本或写入配置，没有安装软件、重启／重载服务、调整 sysctl 或修改防火墙。查询、认证和 HTTPS 请求可能产生正常日志及计数。

## 配置与兼容性

| 项目 | 现场结果 | 判断 |
| --- | --- | --- |
| 系统 | Debian 11 bullseye，x86_64，systemd，root | 脚本有 Debian 安装路径；系统维护期限是独立问题 |
| 虚拟化／CPU | KVM，1 vCPU，AMD EPYC-Rome | 满足轻量执行基础条件，未做吞吐压测 |
| 内存 | 可见总量 455.4 MiB；初采 MemAvailable 261.3 MiB；1 GiB swap 几乎未用 | 更适合 Bouncer-only；swap 不代表等量业务内存 |
| 磁盘 | ext4 9.7 GiB，余量约 6.6 GiB | 当前安装空间充足；后续仍需控制日志与数据库 |
| 现有转发 | realm 2.9.4，13 个 ForwardX unit，每个均有 TCP／UDP 监听 | 合计 RSS 约 83.8 MiB，RSS 含共享页，不能当作精确独占量 |
| 管理与检测 | ForwardX Agent active；Fail2Ban active；未安装 CrowdSec／Bouncer | 应协调已有 SSH 防护，不能把检测重叠当作安装失败 |
| 基础依赖 | Bash、Python 3.9.2、PyYAML、curl、systemctl 可用；Git、ipset 缺失 | 部署前补依赖；不必把缺包判为内核不兼容 |
| 内核 | XanMod `6.18.6-x64v3-xanmod1` | ip_set、hash_ip、hash_net、xt_set 编译为模块且文件存在；root 有 NET_ADMIN／SYS_MODULE |
| 防火墙 | iptables 1.8.7；当前 iptables-save／ip6tables-save 无规则；nft 有 ForwardX 统计表 | 保留 `inet forwardx_traffic`；没有 Docker／UFW／firewalld 并行管理迹象 |
| 日志 | auth.log 存在且有内容；rsyslog、journald active；SSH journal 有样本 | 有系统／SSH 检测来源，尚未安装 CrowdSec，未验证其实际解析 |
| 网络设置 | BBR/fq、16 MiB 收发上限、UDP 最小缓冲 8192、SYN cookies=1 | 当前无需为安装继续放大缓冲；不把 BBR 视为 UDP 拥塞控制 |

仓库当前 **48 个 lib Python 源文件**在该机 Python 3.9.2 中内存编译成功；这只证明语法兼容，不等于全模块导入、业务功能或安装验收。脚本原样的环境采样函数连续观察约 4 秒，返回 stable，I/O wait=0、blocked tasks=0；PSI 接口缺失，因此没有对应压力指标，短采样不能代替高峰／长期容量判断。

从该机访问安装器、packagecloud、GitHub 的 HTTPS HEAD 返回 200。Hub 与 CAPI 根路径返回 403，证明 TLS／HTTP 可达，不能将根路径 403 当作网络不通，也不能据此宣称规则下载、注册及认证已通过。默认 APT 缓存仅提供 CrowdSec 1.0.9，未列出 Bouncer；正式部署须配置官方源，不能直接沿用该旧候选版本。仅核对了官方安装器当前生成的 packagecloud `any` 仓库行，没有执行安装器或 apt update。

## 正式部署前应处理的事项

1. **系统已超出 Debian 官方 LTS。** Debian 官方发布页确认 bullseye LTS 于 **2026-08-31** 结束；本次日期为 2026-11-03。除非另有已验证的付费延长支持，建议另行安排备份与升级到 Debian 12／13，业务迁移及重启应独立规划。新内核不能替代旧用户空间安全维护。
2. **开机恢复任务需要协调。** root 存在活动 `@reboot iptables-restore < /etc/iptables/rules.v4`。当前快照仅包含 mangle 表及三条 MSS 规则，不能说它必然清空未来的 CrowdSec filter 链；但它会整体替换所含表，并会被脚本的启动任务审计识别。部署时应核对规则归属、所需 MSS 策略和启动顺序，避免并行恢复旧快照。未停用任务，也未加载快照。
3. **sysctl 启动服务失败。** journal 明确记录内核拒绝写入 `net.core.netdev_budget_usecs=6000`，配置来自 `/etc/sysctl.d/99-network-optimize.conf:27`；当前运行值为 8000。应修正这一不兼容持久值并逐项核验，而非盲目重跑整份 sysctl 或猜测其他键也全部失败。本轮只确认原因，没有修复或 reset-failed。
4. **部署方式优先轻量执行。** 推荐脚本 `--install-relay-bouncer`，由独立中心负责检测，使用独立 Bouncer 凭据及受保护的 LAPI 通信路径。此时本机不新增 CrowdSec 日志处理／数据库负担；现有 Fail2Ban 可保留负责本机 SSH。仅接中心信誉决策不会自动把本机 SSH 攻击日志送到中心。若要求本机独立 CrowdSec 检测，可评估扩容至至少 1 GiB 后使用 `--install-relay`；1 GiB 是容量建议，不是脚本的硬门槛。

Fail2Ban 当前只有 sshd jail，实际动作是 `iptables-multiport`，端口已正确配置为 **53322**，journalmatch 为 `_SYSTEMD_UNIT=sshd.service + _COMM=sshd`；“No file is currently monitored”结合 journalmatch 不能直接判定失去日志来源。本轮未做真实失败登录检测或封禁验收。若未来切换本机 SSH 检测组件，先完成新组件采集、解析和阻断验收，再决定是否停用旧组件。

无论采用哪种方式，Bouncer 新装建议按脚本现有默认使用 **iptables/ipset**；iptables 的 nf_tables 兼容层与 Bouncer 原生 nftables 后端不是同一实现。未加载或实际创建 ipset、未验证封禁集合，所以模块可用性结论止于编译配置、模块文件及权限检查。

realm 日志中的超时、EOF、连接量不应直接生成来源 ban；共享上游／NAT 拓扑未确认。本机已有 batched-udp，不需要为了安装改 PROXY、转发目标或 UDP 会话参数。IP 防护无法代替上游带宽清洗，真实应用认证仍需后端可用日志。

## 连续性与证据

13 个 realm PID 从初始监听采样到最后服务查询均一致，二进制与 13 份 TOML 的 14 个哈希全部一致；后续比较的 16 个服务均 active 且 PID 一致。ForwardX Agent、SSH、Fail2Ban 均未由本轮启停。没有进入任何安装流程，也没有变更其他 VPS。

本次未做公网转发认证、UDP 后端回包、实际封禁／续封、模块加载、冷启动、长期资源或峰值吞吐测试；这些属于后续部署验收。一次诊断封装因 stdin 编码失败，改用 ASCII 压缩封装后执行成功，没有据失败结果判断服务器兼容性。未运行产品测试套件，未修改产品源码、提交或推送。

证据：[初始清单](2026-11-03-vps82-readonly/inventory.json)、[开机与容量复查](2026-11-03-vps82-readonly/followup.json)、[短时环境／Python 检查](2026-11-03-vps82-readonly/environment.json)、[最终检查](2026-11-03-vps82-readonly/final-check.json)、[连续性核验](2026-11-03-vps82-readonly/continuity.json)、[官方资料摘要](2026-11-03-vps82-readonly/upstream-reference.json)。

官方生命周期：[Debian bullseye 发布信息](https://www.debian.org/releases/bullseye/)。

# 防火墙启动检查与后端迁移

本流程来自四台 VPS 的验收：[第一台](audit/2026-10-30-vps1-cycle-repair.md)、[第二台](audit/2026-10-30-vps2-cycle-repair.md)、[第三台](audit/2026-10-30-vps3-rereview.md)、[第四台](audit/2026-10-30-vps4-cycle-repair.md)。其中三台复现原生 nftables 后端续封失效；第三台原有 iptables/ipset 续封正常。iptables 的 nf_tables 兼容层与原生 nftables Bouncer 后端不同。

## 只读检查

```bash
sudo bash crowdbastion.sh --firewall-check
```

检查系统和用户 cron、`rc.local` 中直接调用的规则恢复命令，以及常见已启用的 netfilter-persistent、iptables、ip6tables、nftables 恢复服务；显示位置，不执行任务或显示任务正文。它不会展开自定义脚本、shell 别名或任意 systemd unit，因此没有发现冲突不代表已穷尽所有开机修改来源。

同时检查 Bouncer 的 `After=docker.service`，以及 iptables 双栈 INPUT、FORWARD、适用的 DOCKER-USER 首条无条件跳转和来源集合 DROP。CrowdSec 链内出现 ACCEPT、RETURN 或其他条件路径时不报告覆盖通过；内核成员只按这些路径实际引用的集合核对。保留自定义链配置，地址族被禁用或无法读取时不报双栈通过。退出码：0 为上述运行检查通过，1 为已确认异常，2 为尚未验证。整体网站／系统健康检查也包含这些观察，但始终保留公网实际拦截待验证。

旧快照恢复任务需要先备份并核对归属，再人工停用或调整顺序。脚本不会自动注释任务、加载快照或替换其他工具管理的规则。

## 修复启动顺序和链

```bash
sudo bash crowdbastion.sh --firewall-maintenance
```

选择 `2` 修复现有 iptables 后端。脚本在 `.yaml.local` 中分别补齐 IPv4/IPv6 的 INPUT、FORWARD，并在发现 Docker unit 时补齐 DOCKER-USER 和专用 systemd drop-in；保留原有自定义链及凭据。四台现场使用的无注释旧版顺序文件会原样复用；新增文件采用原子写入。配置变化后重启 Bouncer，核验链入口；失败恢复配置并重启原服务。重复执行且配置与运行检查均通过时不额外重启；配置未变但入口规则丢失时仍尝试重启恢复。不存在或未启用 IPv6 Docker 链的环境可能无法满足双栈条件，修复会失败并回滚，需按实际部署人工安排。

新装本地核心、现有 Bouncer 连接修复和远端 iptables 接入也使用同一启动配置逻辑。非 iptables 后端保留原行为；迁移通过下面的独立流程进行。

## 迁移原生 nftables 后端

当前自动迁移范围为：本机 loopback HTTP LAPI、正在以 root 运行的官方 Bouncer、显式 `-c /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml` 启动参数、默认 DROP 策略、可识别的双栈原生 input／forward 集合引用、默认集合及链布局、双栈 Docker DOCKER-USER 链均存在。自定义链／集合、远端 LAPI、非 SSH 会话或规则恢复任务冲突时停止。`iptables`、`ip6tables`、`ipset`、`nft`、`ip`、`cscli` 和 systemd 工具需要已安装；脚本不自动换包、升级 Bouncer 或修改 API 账号。

1. 在当前 SSH 会话运行维护入口，选择 `3`。使用 sudo 时通过 `sudo --preserve-env=SSH_CONNECTION bash crowdbastion.sh --firewall-maintenance` 保留连接信息；无法读取连接信息时拒绝迁移。脚本创建私有事务目录，备份原配置和业务规则，保存独立回退代码，先启用 **8 分钟回退定时器**，再建立当前有效封禁快照和当前 SSH 来源／实际端口保护，切换后端。
2. 切换后立即在同一入口选择 `4`。必须在事务准备时间起约 2 分 15 秒内开始，为最坏情况下的验收和清理预留窗口；剩余时间不足时会拒绝启动验收。验收使用保留的专用测试地址、临时命名空间和监听，覆盖 IPv4/IPv6 × TCP/UDP × 输入/转发共 8 条封禁流及正常对照，验证新封禁、续封越过原期限、删除和自然到期。通常约 1–2 分钟；验收本身运行在有最长运行时限的独立 systemd 服务中；独立清理定时器处理连接中断后的残留。测试放行只插入已核验的 CrowdSec 跳转之后，不越过封禁；续封等待从初次决策创建完成后计时。已占用的测试资源会导致停止，不修改宿主机转发 sysctl。
3. 从相同管理员来源新建独立 SSH 连接，再运行维护入口选择 `5`。必须已完成本事务的流量验收，且凭据／配置无漂移、有效封禁已进入内核、业务规则及链策略保持，才能提交并解除回退。
4. 流程失败或不准备提交时选择 `6`；未提交的事务也会由定时器回退。8 分钟是定时器触发时间；回退需取得事务锁，正在执行的检查或系统调用超时可能延迟实际恢复。回退先停止验收服务并清理测试资源，再恢复原配置及文件权限／归属、启动原 Bouncer，并按双栈 input／forward 实际引用的集合分别核验覆盖，最后移除临时封禁快照。某一清理步骤失败后仍会尝试清理其他资源，未确认清理时保留事务和保护。恢复或清理失败时保留现场，需按私有备份核对，不能将其当作成功回退。

事务目录为 `/var/lib/crowdbastion/firewall-migration/`，包含原配置及凭据，权限仅限 root。迁移未结束时，其他管理修改和 cron Hub 维护会返回 75，检查及迁移恢复入口仍可使用。准备阶段备份失败且尚未切换时会记录终止状态，避免留下无法通过正常入口处理的半成品事务。终态目录保留作恢复证据；再次迁移前须人工确认上一事务已提交或已回退、定时器与临时资源均清理，再归档目录。未提交状态和配置漂移不能通过删除事务目录绕过。

失去原管理入口时，回退定时器使用的独立入口为：

```bash
sudo python3 /var/lib/crowdbastion/firewall-migration/crowdsec_firewall_migrate.py rollback
```

已提交事务的 `rollback` 不会覆盖现有配置。回退到旧后端并不修复其已知续封缺陷。迁移期间封禁快照暂时保留切换时有效的封禁，直到提交或确认回退后移除；这段时间撤销的决策可能仍被快照阻断。遇到配置漂移、内核／文件系统错误时会保留保护并报告未完成，需人工处理，不能保证在所有系统故障下自动恢复。

本机命名空间验收不等于公网 CDN、实际 Docker 业务端口或 V2bX 协议已经完成外部攻击验收；也不提供 Lua Web Bouncer 或 AppSec 安装。

本轮循环复审及回归记录见[防火墙流程复审修复](audit/2026-10-30-firewall-cycle-review.md)。

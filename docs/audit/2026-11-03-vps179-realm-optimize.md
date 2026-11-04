# VPS179：ForwardX realm 防护优化交付

用户确认使用 ForwardX，并授权按[前次检查建议](2026-11-03-vps179-realm.md)优化 VPS。2026-11-03 已完成现场应用、独立脚本复核、隔离封禁验收及清理。最终现场采样为服务器 UTC **09:32:34** 起。

本轮保留 ForwardX、realm 2.9.4、现有两条转发和 iptables Firewall Bouncer。增加 realm 错误日志的观察采集，限制 journal 存储容量，并证明当前 Bouncer 能阻断受控来源的新连接。本轮没有启用按连接数、EOF、后端超时等事件自动封禁的规则。

## 实际变更

| 新增文件 | 作用 |
| --- | --- |
| `/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml` | 只跟随两条 ForwardX realm unit 的 journal；同名 `_SYSTEMD_UNIT` 条件为 OR，不重复采集 SSH |
| `/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml` | 将结构化 realm 日志标记为 `realm_forwardx_observation`，记录级别、模块和协议；不提取 `source_ip`，不添加 scenario，不产出封禁决策 |
| `/etc/systemd/journald.conf.d/60-crowdbastion-storage-cap.conf` | 持久 journal 目标上限 128M、保留磁盘空闲 512M；运行时 journal 目标上限 32M、保留内存文件系统空闲 16M |

journald 实际启动日志确认：当前 system journal 为 **16M，max 128M**。没有运行 vacuum、清空历史日志或设置按天强制删除。journald 的容量策略受活动日志文件等因素影响，不是任意时刻绝不超过的硬配额。

本机 SYN cookies、SYN 队列、socket backlog、realm 文件描述符上限及 unit 日志限速已有配置，没有证据支持继续增大。两条后端 `192.0.2.13:2053` 和 `192.0.2.19:8443` 的 TCP 建连在操作前后均成功。未修改网络 sysctl、业务端口、PROXY protocol、全机白名单、核心／Bouncer API 凭据或现有检测规则。

## 解析与运行核验

先在官方引擎确认原配置不能识别新增 observation，再在私有副本中验证配置：realm ERROR、WARN 两个样本成功归类；不匹配格式未被误识别；SSH 对照仍由原 sshd parser 处理，没有 realm 标记。`crowdsec -t` 对暂存及最终现场配置均返回 0。

现场确认 CrowdSec 下存在实际 journalctl 子进程，参数同时包含两条 realm unit，并采用 `--follow -n 0`。最终采样尚无新的 realm 错误事件，因此 realm acquisition 计数尚未出现：**已证明 follower 就绪及离线解析正确，没有宣称已经观察到真实新事件被实时解析。** 正常连接不产生日志不表示失效，不需要为显示计数人为制造业务故障。

首次现场应用的验收错误地要求无新事件时也必须有 acquisition 计数，因此自动移除了三份新增配置并恢复服务。核心日志证明当时 follower 已启动。定位后，将就绪检查改为核对实际子进程，再重新应用成功。相关失败及回退记录均保留。

CrowdSec 核心与 journald 因首次应用、自动回退、最终应用，各重启 **3 次**。ForwardX Agent、两条 realm 和 Firewall Bouncer 全程 PID 与原基线一致，均为 active、自动重启计数 0。PID 一致证明没有重启这些进程，不等同于证明所有用户的应用请求从未受到影响；核心重启期间 HTTP/AppSec 存在短暂检测服务切换。

所有原受保护文件的 SHA256 保持一致，包括 realm 二进制、两条 TOML、两个 realm unit、原 acquisition、CrowdSec 主配置和两份 Bouncer 配置。最终新增文件均 root 所有、0644。

## 实际 Bouncer 隔离验收

使用临时 network namespace 和 veth，将文档保留地址 `203.0.113.242`、`203.0.113.243` 作为受控测试与正常对照来源送入**生产宿主机 INPUT**。测试决策通过实际 LAPI 创建，由实际 Firewall Bouncer 同步；没有手工绕过 Bouncer 去插入封禁规则。

| 路径 | 封禁前 | 封禁测试来源后 | 解封后 |
| --- | --- | --- | --- |
| 实际 realm TCP `56017` | 双方可建连 | 测试来源超时，对照可建连 | 双方恢复 |
| 实际 realm TCP `58372` | 双方可建连 | 测试来源超时，对照可建连 | 双方恢复 |
| 临时私有地址 UDP 回显 `17773` | 双方成功 | 测试来源超时，对照成功 | 双方恢复 |

完成两轮：第一轮测试集合的 DROP 包计数从 0 增至 3；独立复核修正清理逻辑后，第二轮从 3 增至 6。两轮都验证对照不受影响、解封恢复。决策仅针对测试地址、具有唯一 reason、最长 2 分钟；清理采用地址与 reason 双重限定。

最终确认：测试决策不存在、地址已从封禁集合移除、UDP 监听进程已结束、临时 veth 和 namespace 已删除。没有使用管理员 SSH 来源或实际用户来源做封禁实验。

**覆盖边界：** TCP 验证了实际 realm 监听的新连接，未携带实际用户认证去验证完整代理业务；UDP 验证了同一生产 INPUT 封禁链的执行与回显恢复，没有验证两条 realm UDP 路径的后端应用响应。本轮也未验证公网 WAN、多跳真实用户 IP、已有长连接中断、冷启动或公网 IPv6。没有把该结果写成 `--verify-relay` 的公网业务验收记录。

最终 `crowdbastion --firewall-check` 返回 0：启动顺序与适用双栈入口检查通过；**适用网络 16850、实际集合网络 16850、遗漏 0**。数量相较前次采样变化来自实时决策更新，不要求与历史数量完全相同。

## 独立复核与失败保护

独立 reviewer 发现两项运维脚本失败路径：服务重启失败时必须仍纳入回退恢复；删除测试决策超时后仍应继续停止回显进程、删除隔离网络。两个故障注入检查在修正前失败、修正后均通过；修正后的网络验收脚本又在现场完整通过一次。

最终核验同时按 unit 名比较 ForwardX／realm／Bouncer PID，避免依赖输出顺序。测试与脚本复核都针对本轮运维材料，没有运行或冒称通过整个产品代码测试套件，也没有修改项目已有产品代码。

## 保守决策及后续边界

- 上游拓扑仍未获得确认，因此按可能共享公网来源处理；没有加入按 IP 连接量封禁、共享来源全机放行或限速。代价是新增的观察采集不提供新的自动攻击识别。
- 不启用 PROXY protocol。后端是否支持、可信上一跳及 UDP 传递方式未核实；后续如接入后端认证检测，应先确认真实来源，并把封禁放在实际可匹配该用户网络源 IP 的入口。
- 保留现有全机 IP ban 行为：网站产生的 ban 仍可能同时影响 realm。需要按业务隔离时应作为单独策略设计，不在拓扑未知时改写当前生产规则。
- 日志容量只设存储上限，不设置强制 14 天删除；用于保留现有历史记录。没有安装另一套管理器或额外常驻监控进程。

## 备份与回退

服务器私有备份：

```text
/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z
```

该目录为 root 私有，包含原配置副本、受保护文件哈希、暂存配置、首次回退证据、解析结果、实际封禁结果及清单。敏感配置仅保存在服务器，不复制进仓库。

已准备但**未执行**手动回退脚本：

```bash
python3 /var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z/rollback.py \
  /var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z
```

它持维护锁，核对三份新增文件仍匹配本轮哈希后才移除，运行 `crowdsec -t` 并重启 journald／CrowdSec；遇到失败会尝试恢复移除的文件。不还原整张防火墙、不覆盖动态决策、不修改 ForwardX，不停止 Bouncer。文件被后续管理员修改时拒绝回退。手动脚本做了语法检查，未在生产上额外演练；本轮首次应用的自动回退已经实际发生并有记录。

## 本地证据

- 最终现场核验（本地归档：`2026-11-03-vps179-realm-optimize/final-result.json`）
- 第二轮实际封禁验收（本地归档：`2026-11-03-vps179-realm-optimize/enforcement-final.json`）
- 解析验证（本地归档：`2026-11-03-vps179-realm-optimize/parser-verification.json`）
- 失败路径检查（本地归档：`2026-11-03-vps179-realm-optimize/failure-path-tests.txt`）
- 执行清单（本地归档：`../superpowers/plans/2026-11-03-vps179-realm-optimize.md`）

现场新日志出现后，可用 `cscli metrics show` 查看 `realm-forwardx` journal 源及 `local/realm-forwardx-observation` parser 的读取／解析计数；这类观察事件不会自动生成封禁。基础封禁同步继续使用 `crowdbastion --firewall-check` 检查。

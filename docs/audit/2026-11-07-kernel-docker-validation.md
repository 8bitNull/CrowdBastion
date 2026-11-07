# 2026-11-07 真实内核与 Docker 链路验证

本轮按用户要求继续小步收敛，先补齐[功能回归报告](2026-11-07-functional-regression.md)中 A-01 的隔离环境链路证据。基于提交 `5d7d3fa07abe7947e06dfe5ff3eb30153f58529f`，76 个产品文件与原工作区逐一核对一致；变更集中在测试工具和文档。

**真实 nftables、iptables-legacy/ipset 各 12 项通过；真实 Docker 相关 8 项通过，另完成 daemon 重启后续封及内核自然到期复验。完整回归 1,846 项全部通过，失败、错误、跳过均为 0。**

## 实验环境与隔离

| 项目 | 本次实际配置 |
| --- | --- |
| 客机 | Debian 12 官方 genericcloud amd64 镜像，Linux `6.1.0-54-cloud-amd64`，真实 systemd |
| 虚拟机 | QEMU 7.2.22 TCG，2 vCPU、2048 MiB；无外网 NIC、无共享目录，基于原镜像的快照磁盘 |
| 内核能力 | 私有 net/mount namespace 可用；br_netfilter、ip6_tables、ip_set_hash_net、ip_tables、nf_nat、nf_tables、overlay、xt_set 均加载成功 |
| 执行程序 | 官方 Firewall Bouncer v0.0.36、gost 3.3.3、realm 2.9.6、Docker 27.5.1；iptables/ip6tables 1.8.9、ipset 7.17 |
| Docker | 独立 daemon、数据目录和 socket，真实 bridge、容器和发布端口；vfs 存储，userland-proxy 关闭 |
| 回显镜像 | 使用客机 Python 与实际链接库离线导入，不连接镜像仓库 |
| 决策来源 | 客机内本地模拟 LAPI 决策流；官方 Bouncer 与内核规则真实执行，不是命令替身 |

宿主容器仍然不具备 namespace 权限，本轮通过独立客机完成实验。QEMU 及依赖仅在宿主机下载、校验和解包，没有安装宿主机 Docker 服务或修改其防火墙。客机内部的实验再次进入私有网络／挂载命名空间。

48 份下载资源保留来源、版本、大小与摘要：Debian 软件包按 APT 元数据 SHA-256 校验，cloud image 按官方 SHA-512 校验，Bouncer／realm 按 GitHub release 摘要校验；Docker 静态包从官方 HTTPS 地址下载并记录 SHA-256。另核对 11 个执行文件与本次 payload 中的字节一致。后续直接启动使用从同一已校验镜像提取的匹配内核和 initrd，摘要另行记录。

## 真实包流量结果

| 实验 | 实际结果 | 范围及证据 |
| --- | --- | --- |
| nftables | 12/12，通过，137.88 秒 | gost／realm／NAT × IPv4／IPv6 × TCP／UDP；正常、封禁、DROP 计数、正常对照与解除恢复 |
| iptables-legacy/ipset | 12/12，通过，140.01 秒 | 同一 12 项流量矩阵，实际 legacy filter 与 nft NAT |
| Docker 及本机 INPUT | 8/8，通过 | 本机 INPUT／Docker 发布端口 × IPv4／IPv6 × TCP／UDP；发布端口 34000 与容器端口 29000 不同 |
| Docker 生命周期复验 | 双栈 TCP／UDP 均通过 | daemon 重启并显式恢复原容器后，续封跨越原到期窗口；内核集合自然到期后恢复，正常对照始终可用 |

两轮内核矩阵在第二台快照客机中完成；Docker 最终版本在第四台快照客机中完成。它们是分阶段实验，不合并描述为一次全量测试或生产验收。Docker 实验进程耗时 250.73 秒，对应整次客机运行 405.00 秒；最终 QEMU 退出 0、结果记录恰为一份、外层 `accepted=true`。

Docker 四项发布端口测试均从外部测试 namespace 进入实际 DNAT，容器看到原始测试来源。每个场景均有独立正常对照、被封来源失败、来源 DROP 计数增长、解除后恢复。本次 IPv4、IPv6 计数均观察到 `0→2`、`2→3`、`3→5`、`5→6`，产品的真实 `chain_coverage` 检查为 `ok`；不以 daemon 运行或规则存在代替包流量结果。

续封初始时长为 15 秒，随后更新为 45 秒；两族实际集合 timeout 均观察到 44 秒。确认初始集合安装后等待 17 秒，再验证四种发布端口组合仍阻断被封来源且正常对照可达。随后观察集合自然移除，四种组合的两个来源均恢复。采样及后续恢复探测合计约 54.64 秒，不据此声称精确的内核到期时间。

Docker 清理成功；实验正常结束后 QEMU 退出。所有实验进程和数据均属于本次专属环境。

## 本轮收敛内容与复审

- 新增 `tests/verify_docker_network.py`，复用已有隔离、回显、决策流、计数与路径检查；统一要求完整 8 项、来源、DNAT、计数、控制和恢复证据，缺项或失败不能返回通过。
- 新入口以继承的真实 namespace 文件描述符核验隔离，移除可伪造的 inode 数字参数。拒绝留在原 net/mount namespace 执行修改。
- `Processes` 增加可选 subreaper 监督，只在新入口的专属外层进程启用，回收脱离进程组并被收养的测试后代；原调用默认行为保留。增加真实孤儿进程清理回归。
- 超时先给予内层最多 90 秒清理，再清理剩余后代；JSONL 检查点保留已完成场景，超时或中断始终失败，不能因 worker 随后退出 0 而升级为通过。
- Docker 就绪同时核对服务端版本和错误字段；探测进程单独采用 15 秒外层预算，socket 超时保持 1.5 秒。共享 client 的默认进程预算仍为 5 秒。

独立代码审查确认三项 Important 问题：原内部参数可绕过隔离、外层清理窗口不足且不能收养后代、超时丢失部分证据，均补失败复现后修正。续封计时起点也经延迟安装复现后改为“确认初始集合已安装”；这项证据准确性问题按 Important 处理。没有确认 Critical；未保留待办 Minor。

新增结果判定、拒绝、就绪、计时、超时和真实后代清理共 18 项测试；初始入口与生命周期断言分别经历 RED→GREEN，审查修正及空检查点分类也分别复现失败后通过。相关网络／防火墙回归此前共 94 项通过；最终完整套件包含新增用例与全部既有用例。

最终运行使用 `tests/run_tests.py --tier full --require-no-skips`，UTC 2026-11-07 08:32:34—08:44:18，耗时 704.37 秒，约 11 分 44 秒；退出码 0，`accepted=true`。发现清单与实际执行的 1,846 个唯一 ID 一致，逐项均为 `passed`，原有 1,828 个 ID 全部保留，新增恰为 18 项。运行期间代码和测试输入指纹无变化，最终 Docker payload 中的非 Markdown 源文件与当前工作区一致；结束后未发现本轮 QEMU 或专项资源目录下仍在运行的程序。

## 失败记录

| 轮次 | 实际失败与处理 | 结果边界 |
| --- | --- | --- |
| 第一轮 | 离线依赖缺少 libjansson4，补齐校验包 | 停在客机包准备，未执行包流量矩阵 |
| 第二轮 | `docker info --format` 在 daemon 未连接时仍可返回 0，提前继续创建网络；改为核对实际服务端版本及错误 | 两轮内核矩阵真实通过；该轮 Docker 不能计为通过 |
| 第三轮 | 首个冷启动探测进程超过 5 秒外层期限，无 OOM 记录；采用现有 legacy 实验同类的 15 秒进程预算，并延迟加载仅监督器需要的 ctypes | 停在首个未完成场景，不能计为 Docker 通过 |
| 第四轮 | 使用修正后的工具与原镜像重新启动独立快照客机 | Docker 8 项与生命周期均通过，退出及清理核对通过 |

错误轮次、串口、分项 JSON 和外层失败状态均留在本地。未删断言、跳过 IPv6／UDP、放宽包流量超时或将空结果视为成功。

## 复跑

在具备 namespace 权限、所需程序和内核模块的隔离 Linux 测试机或虚拟机中执行：

```bash
sudo .venv/bin/python tests/verify_relay_network.py \
  --gost /path/to/gost --realm /path/to/realm \
  --bouncer /path/to/crowdsec-firewall-bouncer --output /tmp/cb-nft.json

# 本入口要求实际使用 iptables-legacy/ip6tables-legacy。
sudo .venv/bin/python tests/verify_relay_iptables.py \
  --gost /path/to/gost --realm /path/to/realm \
  --bouncer /path/to/crowdsec-firewall-bouncer --output /tmp/cb-iptables.json

sudo .venv/bin/python tests/verify_docker_network.py \
  --docker /path/to/docker --dockerd /path/to/dockerd \
  --bouncer /path/to/crowdsec-firewall-bouncer --output /tmp/cb-docker.json
```

Docker 实验还需要匹配的 containerd、runc 等 runtime 程序位于 PATH。具体依赖和常规回归入口见[测试说明](../../tests/README.md)。QEMU 资源和 bootstrap 保存在本机忽略目录，新克隆不包含镜像和原始证据；Docker 验收入口本身随 `tests/` 分发。

## 验收状态与取舍

A-01 中真实内核与 Docker 包流量证据现已取得，适用于上表版本和隔离拓扑。A-02 的指定 VPS／公网业务闭环仍待验收。以下范围本轮未新增放行：真实 LAPI 中心同步、生产软件包安装与冷启动恢复、生产 Docker 自动恢复、Docker overlay 驱动、已有连接、网络／端口策略完整事务及定时回滚、真实访客 IP／CDN、日志攻击检测、公网吞吐与实际攻击负载。nftables 的本轮 12 项结果不扩展为该后端续封／到期验收。

本轮采用本机 TCG，代价是准备和运行时间，不能推算硬件或公网性能；使用 vfs 和离线镜像，另需验证生产存储驱动与镜像；模拟决策只验证执行，不验证真实中心和检测。原有工作区报告保留，验收改动经逐文件摘要核对后纳入主工作区，恢复可依据 Git 版本、隔离工作区和文件摘要。审查中暂不评价的生产启动、远端 LAPI、公网及外部不可信镜像均按上述边界保留，不升级为已验收。

原始材料位于主工作区本地 `private-audit/kernel-docker-2026-11-07/`：`resources.json`、`bin-identities.json`、`direct-boot-resources.json`、`kernel-summary.json`、`docker-summary.json`、`review.md`、`final-verification.json`，以及 `evidence/` 下四轮客机的命令、串口和结果。后续轮次另保存源码清单、guest 脚本和 seed；首轮仅保留原命令、摘要及依赖失败记录。最终本地回归清单、逐项耗时与文件指纹位于 `evidence/full-regression/`。计划和 RED／GREEN 日志保留在隔离工作区 `.superpowers/sdd/2026-11-07-kernel-docker/`。

上述实验未部署生产；后续仓库提交和推送不代表生产现场验收完成。

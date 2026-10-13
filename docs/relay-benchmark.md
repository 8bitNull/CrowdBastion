# 中转节点性能测量

目标是在同一 VPS、同一负载下对比转发器与 Firewall Bouncer 的开销，为是否使用精简模式提供数据。首版覆盖 **IPv4、gost/realm、TCP/UDP**；不测 NAT、IPv6、WAN 线路、攻击流量或 CrowdSec 核心日志检测容量。

## 完整隔离基准

需要 Linux root、可创建网络/挂载命名空间、Python/PyYAML、iproute2、nftables、mount 和对应程序。程序沿用隔离验收器的双命名空间保护；两个客户端网络和后端在私有网络中，规则及 `/run/netns` 位于私有环境。生产 LAPI 不参与，Bouncer 消费合成 loopback 决策 API。不调整宿主机限额或生产服务。

```bash
sudo python3 tests/benchmark_relay.py \
  --gost /path/to/gost --realm /path/to/realm \
  --bouncer /path/to/crowdsec-firewall-bouncer \
  --duration 5 --warmup 0.5 --concurrency 4 --payload 1024 \
  --repeats 3 --ban-sizes 0,1000 --seed 17 \
  --output /tmp/relay-benchmark.json
```

每个重复 block 包含所有工具、协议和条件，使用固定 seed 随机排列。`ban_count: null` 是未运行 Bouncer 的基线；`0` 是 Bouncer 已启动但没有决策；`1000` 是加载 1000 个合成封禁来源。封禁范围 `198.18.0.0/16` 不包含负载来源 `10.231.1.2`，因此测量的是正常流量查表成本。每次条件重启自己启动的进程，并在私有环境释放 Bouncer 表，避免前次条件残留。首版只有一个测量节点，多次 block 是同机重复，不能当作多台 VPS 的独立证据。

UDP 使用最大 1200 字节 payload，避免本实验因 MTU 造成分片；gost 明确采用 `keepAlive=true`，realm 配置启用 UDP。gost 默认一次响应后关闭虚拟 UDP 会话，不能直接用于本次持续回显负载。该参数记录于 JSON 的 `forwarder_settings`。本实验不是加密转发、PROXY protocol 或生产配置复刻。

## 指标含义

| 指标 | 定义与边界 |
| --- | --- |
| `goodput_mbps` | 成功回显的请求 payload 字节 × 8 / 客户端实际耗时 / 10⁶；不重复计算返回 payload，不含协议头 |
| `transactions_per_second` | 完成的回显事务数 / 实际耗时；不等同新建连接数 |
| `p50_ms` / `p95_ms` | 请求发送到完整响应的 RTT；每个客户端最多保留 4096 个 reservoir 样本，按其完成事务数加权，属于估计值 |
| `error_rate` | 错误事件 /（成功事务 + 错误事件）；每客户端遇错停止，故不能解释为持续压测下的 UDP 丢包率 |
| `cpu_percent_one_core` | 被监控进程 CPU 时间增量 / 记录的墙钟间隔；100% 表示一个核，可超过 100% |
| `peak_sampled_rss_bytes` | 50ms 采样所得最大 RSS，可能漏掉短时峰值；不是严格峰值，也不是总系统内存 |
| `comparisons` | 同工具、协议、block 内 Bouncer 条件相对基线的 goodput 变化；仅包含双方无错误的配对，保存每对变化及其中位数 |

工作负载是持续 TCP 连接/UDP socket 的闭环回显，各客户端等待响应后才发下一条请求。它用于受控比较，不等同单向 iperf 吞吐或最大转发能力。生成负载、后端回显、API fixture 都与被测转发器同机，可能成为瓶颈。进程 CPU 不含内核 softirq、nftables、客户端、后端或 CrowdSec 核心消耗。CPU 计量区间包含负载进程启动和采样收尾，单独记录 `measured_wall_seconds`；goodput 使用客户端实际负载区间。

JSON 保存参数、版本、内核、可见 CPU/内存、可读取的 cgroup v2 限额、测试顺序、每次原始样本、错误原因和进程资源。可见 CPU/内存不一定等于容器或 VPS 可分配额度。没有足够配对、任何负载出错或资源读取失败时，不把它解释为“零开销”。失败报告保留 `active_condition` 和 `phase`；返回 `0` 表示请求的测量完成且负载无错误、`1` 表示失败、`2` 表示依赖/隔离未支持。返回 0 不证明 VPS 容量达标。

## 在目标低配 VPS 上使用

选择业务较空闲的时段，先用 `--duration 1 --repeats 2 --concurrency 1` 验证流程，再逐步对比并发 1、4、16 或与你业务相近的负载。保留所有失败及原始结果，并在不同时间窗口重复，记录 CPU steal、宿主机波动、既有服务和 VPS 额度。较长测试会竞争同机 CPU，测试期间不要把业务延迟变化归因于 Bouncer 本身。

要评估精简模式**总开销**，还应在真实日志速率下观察 CrowdSec 核心与系统资源。若已有 `sysstat`，可在独立终端只读观察：

```bash
CROWDSEC_BENCH_PID="$(systemctl show -p MainPID --value crowdsec)"
pidstat -u -r -p "$CROWDSEC_BENCH_PID" 1 60
mpstat -P ALL 1 60
```

先确认 MainPID 非零且对应预期核心。`pidstat` 观察核心 CPU/RSS，`mpstat` 观察系统 CPU、softirq 与 steal；用 `cscli metrics` 核验同时段的实际采集量。分别记录空闲期和真实业务期。转发基准中的 Bouncer 进程指标不能代替这些测量。

受限容器可用 `--forward-only` 运行 loopback 基线，无 Bouncer/防火墙比较；缺少隔离能力不会自动退化为该模式。QEMU TCG 下得到的数字只验证工具流程，不可用于选择 VPS、宣称开销比例或推荐最低 CPU/内存规格。

## 工具验证记录

2026-10-12：真实 loopback 8 次测量无错误；隔离 QEMU 客体 24 次测量无错误，覆盖全部工具/协议/三种条件及两个 block。[烟雾测试原始报告](audit/2026-10-12-relay-benchmark-smoke.json)带有明确 QEMU 标记。未在真实低配 VPS 上采集容量数据，不据此推荐最低配置或宣称固定开销百分比。

后续实际进行了 **1 vCPU / 512 MiB、1 vCPU / 256 MiB** 的磁盘根文件系统模拟，并加入真实 CrowdSec 核心与合成 SSH 日志。512 MiB 共存短矩阵及 256 MiB 无核心对照通过；256 MiB 核心共存未完成，最低可用内存仅 10.6 MiB。完整方法、失败结果和解释见 [低配资源模拟记录](audit/2026-10-12-low-spec-simulation.md)。这些数据不是实机最低配置或吞吐保证。


## 稳定性观察器（修复进行中）

`tests/relay_soak_guest.py` 独立于单次最多 60 秒的基准负载。它只接受带实验标记的独立 QEMU 客机，清单固定模式、时长、四条 loopback 转发路径及决策命令；120 秒烟雾、1 小时与 24 小时分别记录，短测不授予长测资格。`prepare_vps_rpm_arm.py --core-only --soak-duration ... --gost ... --realm ...` 当前只准备 amd64 本地核心共存实验，不把同客机核心当成远程低内存中心。

每条 gost/realm × TCP/UDP 路径使用持续 socket，每秒一个 1 KiB 请求。gost UDP 复用既有基准的 `keepAlive=true`。正常尝试数逐分钟检查（目标 1 Hz，调度容差 2%），实际请求成功率至少 99.9%；正常与额外突发计数分开。24 小时运行在第 6/12/18 小时各做满 60 秒、每路径合计并发 4 的突发。分钟采样与每小时同步使用独立线程，同步不能占用采样时钟；命令超时仍有限。

分钟 JSONL 含实际 MemTotal/MemAvailable、OOM 计数、核心/Bouncer PID、NRestarts、采样 RSS/CPU、规则数及流量计数。日志事件逐条归档到串口，主机端按 seed 的清单与观察器 hash 重算结果；未知退出、漏样本、重复小时、意外重启、同步超时均失败。RSS 峰值是分钟采样峰值，会漏掉短时峰值。

24 小时内存门槛明确采用保守观察规则：比较最后六小时两半的可用内存与服务 RSS 中位数，漂移不得超过 max(16 MiB, MemTotal 的 5%)；同时将该六小时按 20 分钟取中位数。若相关系数绝对值至少 0.8、至少 75% 的相邻窗口持续朝可用内存下降/RSS 增长方向变化，则不算平台，即使总变化低于前述限额。报告保留斜率、相关性、方向比例、最小可用内存和采样 RSS 峰值。这是试验门槛，不是容量保证。

当前还没有四个目标资源组合的 1 小时/24 小时、独立无防御长基线及恢复证据。观察器或烟雾测试通过不能替代这些未完成项，所有组合仍不具备本计划的试用资格。进度见 [修复执行记录](audit/2026-10-12-vps-repair-progress.md)。

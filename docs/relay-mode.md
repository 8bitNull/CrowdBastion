# 纯中转节点精简模式

适用于需要基础 SSH 行为检测和 IP 决策阻断的 Linux/systemd 中转节点。菜单 `1 → 5` 安装，`4 → 3 → 1` 只读检查；CLI 对应 `--install-relay`、`--relay-status`。沿用项目发行版、软件源、Python/PyYAML 和管理员 IP 前提。

## 安装与已有配置

安装 CrowdSec 与官方 Firewall Bouncer，只补齐 Linux、SSH 和良性行为白名单集合，不扫描 HTTP/Docker 日志或接入 AppSec。软件包本身可能自动检测并安装其他集合，本工具不会删除它们。已装核心保留版本、软件源、身份、Web/AppSec 集合和配置。

系统采集使用有效 `config.yaml` / `.local` 中的 `acquisition_dir` 与 `acquisition_path`，按已有文件路径和通配符去重。只在现存 `/var/log/auth.log`、`/var/log/secure` 尚未被采集时补齐；没有认证文件且没有已识别标准 SSH journalctl 源时，生成：

```yaml
source: journalctl
journalctl_filter:
  - _SYSTEMD_UNIT=ssh.service
  - _SYSTEMD_UNIT=sshd.service
labels:
  type: syslog
```

写入独立的 `crowdsec-1key-relay.yaml`，保留该文件中的已有数据源；不迁移或删除 Web 采集。存在标准 SSH journalctl 源时优先复用它，避免再添加认证文件重复处理相同事件。同一 `_SYSTEMD_UNIT` 字段的多个 journal 匹配是 OR：包含 SSH 和其他 unit 的来源也会参与去重。已有 SSH 源含额外字段约束时保留并提示完整覆盖未验证，不新增可能重叠的源。自定义 unit、容器内 SSH、syslog 转存及其他采集格式需要自行适配；配置存在不证明 SSH 事件已经被读取。已有采集以错误标签处理 SSH 时提示核对，不用重复采集掩盖错误。

复用管理锁、Hub 事务、配置备份、`crowdsec -t`、核心加载与失败恢复。无新增规则/配置时跳过核心重启；重复执行不重写相同采集。软件包安装和服务启动不属于完整原子事务；已安装软件包可能保留，Bouncer 启动失败会返回非零。既有网站模式入口及规则修复保持其原有用途，`--reset-baseline` 会补齐 Web 集合。

## 只读证据与限制

检查有效 Firewall Bouncer 配置与运行服务。iptables 模式检查配置集合是否存在，以及 INPUT/FORWARD/DOCKER-USER 中直接或经自定义链引用来源 IP 集合的 DROP/REJECT 规则；nftables 模式检查对应 IPv4/IPv6 表、集合及直接挂在 input/forward 上的来源 IP 阻断规则。集合名称读取官方 `blacklists_ipv4` / `blacklists_ipv6` 配置；nftables 同时识别配置名称与官方按决策来源生成的集合，例如 `crowdsec-blacklists-CAPI`、`crowdsec-blacklists-cscli` 和 `crowdsec6-blacklists-CAPI`。仍要求集合实际存在于同一 family/table，并被来源 IP 匹配的 DROP/REJECT 规则引用；不以任意名为 crowdsec 的表作为生效证据。V2bX 诊断复用这项检查。

IPv6 全局禁用或 nftables 分组未启用时明确显示。ipset 和 nftables set-only 的过滤规则由部署者接入。nftables 自定义跳转图、复杂表达式及非标准规则可能无法识别，报告“尚未发现”并不等于不存在防护。规则引用也不证明其匹配范围和执行顺序；iptables 提前 ACCEPT、已建立连接旁路、Docker 跳转顺序和其他规则管理器的更新都需在目标节点核验。

诊断不发送网络请求、不写文件、不操作决策或防火墙、不获取修改锁，也不显示 API 密钥。发现配置错误、服务未运行或规则命令读取失败时返回 `1`；缺少配置/工具或仅取得静态证据时返回 `2`。该入口没有业务阻断验证功能，不能返回代表全链路通过的 `0`。

| 转发类型 | 通常需核查的路径 | 关注点 |
| --- | --- | --- |
| 宿主机 gost / realm / socat / Nginx Stream | INPUT | 是否监听本机、来源地址及 IPv4/IPv6 |
| 内核 DNAT + 路由转发 | FORWARD | Bouncer 规则与业务放行顺序 |
| Docker bridge 端口发布 | FORWARD / DOCKER-USER 或 nftables 对应钩子 | 实际 Docker 后端、跳转和地址转换 |
| 多跳 / 加密隧道 / userspace WireGuard | 外层监听与具体内部转发路径 | 外层来源可能只有上游节点，封禁会影响全部用户 |

选择独立、可控的外部测试来源，分别核验 TCP、UDP、IPv4、IPv6 和实际业务路径。不要用管理员 SSH 来源或共享上游节点做封禁测试。应用通过 PROXY protocol 获取真实 IP，不代表本机防火墙也能按该 IP 封禁。

该模式提供系统/SSH 日志检测与 IP 决策阻断，不提供中转专用行为检测、通用 SYN/UDP flood 防御、自动连接限速或带宽清洗。资源需求随规则、日志量、集合大小和原有业务变化，没有固定性能保证。

## 中转入口引导验收

菜单 `4 → 3 → 3`，或在中转 VPS 上运行：

```bash
sudo bash crowdbastion.sh --verify-relay
```

本地中转安装、远端 Bouncer 接入成功后，脚本自动只读检查中转服务与防火墙；在终端中可选择进入验收。检查异常会单独显示原因，成功安装本身仍返回 `0`。健康检查推荐的验证方法也提供此入口。

**需要准备：** 你管理的测试设备、另一公网来源的正常对照设备，以及目标入口 IP／端口。两个来源必须不同，测试来源不能是当前管理来源或共享上游节点。先用 `--relay-path` 核对本机实际看到的来源 IP 与流量路径。每次选择一个入口、TCP 或 UDP，以及 IPv4 或 IPv6。

向导按四步收集结果：

1. **封禁前正常可达。** 两个来源使用现有业务客户端访问同一入口。TCP 使用新连接并确认业务响应；UDP 必须取得应用响应，单纯发送成功或无响应不能代表正常。
2. **短时封禁测试来源。** 向导生成唯一测试原因和有效期为 `2m` 的决策命令，由你明确执行。本地模式在本地核心执行；托管远端模式只在检测中心执行。向导等待你确认同步后，读取所选链中测试来源的集合与规则计数。
3. **封禁期间对照。** 确认测试来源的新连接失败，正常来源仍能访问。向导核对测试来源仍在集合内、同一封禁规则计数增加；计数缺失、重置或规则替换时保留证据不足。
4. **到期后恢复。** 等待本次短时决策到期，核对来源退出集合且防护规则仍存在，再确认两个来源都恢复。如果提前撤销，仅处理本次唯一原因对应的决策 ID，不按 IP 批量删除其他决策。

外部测试需要逐项明确选择“成功／失败／不确定”。输入 `q`、EOF 或 Ctrl+C 会结束，若已显示封禁命令且尚未确认来源退出集合，则提示等待本次决策到期并核查恢复。来源原本已经在适用封禁集合中时，向导要求更换测试来源。

| 验收结论 | 含义 | 退出码 |
| --- | --- | --- |
| 本次入口验证通过（人工确认） | 全部人工连接对照和本机集合／计数／恢复证据齐全 | `0` |
| 本次入口验证未通过 | 测试前不可达、封禁后仍可达、正常来源受影响或恢复失败 | `1` |
| 验证未完成 | 缺少结果、读取失败、决策未同步、计数无证据、取消或路径不支持 | `2`；Ctrl+C 为 `130` |

**范围：** 当前支持 nftables 中直接挂在 INPUT/FORWARD 的单个来源集合匹配、计数和最终 DROP/REJECT 规则，可读取命名计数器和匿名规则计数器。额外端口／接口／连接状态条件、Docker bridge、iptables/ipset、自定义跳转图及未核对的来源／路径保持未完成，不靠人工填写替代缺失的本机证据。

通过结论注明目标、端口、协议、地址族、声明路径和来源对照。外部连接结果由操作者确认，来源集合计数也可能包含其他流量；二者共同形成一次人工验收记录，不代表自动取得逐包归因证据。它不保存用途或修改服务、配置、决策、防火墙，不会使用或输出连接密钥，也不会访问检测中心或把静态健康检查升级成全节点防护通过。其他入口、既有长连接、日志攻击检测、AppSec 和带宽清洗需要各自验证。

## 参考资料与验证

参考 Forwardx 提交 `fa15e35fe3a0ec556ea8ebcdcd84e691c85bc110` 的[转发规则](https://github.com/poouo/Forwardx/blob/fa15e35fe3a0ec556ea8ebcdcd84e691c85bc110/docs/guide/rules.md)、[Agent 文档](https://github.com/poouo/Forwardx/blob/fa15e35fe3a0ec556ea8ebcdcd84e691c85bc110/docs/guide/agent.md)、[日志路径](https://github.com/poouo/Forwardx/blob/fa15e35fe3a0ec556ea8ebcdcd84e691c85bc110/docs/guide/paths-logs.md)和[连接限制实现](https://github.com/poouo/Forwardx/blob/fa15e35fe3a0ec556ea8ebcdcd84e691c85bc110/agent/port_access_limits.go)，以及官方 [Firewall Bouncer 文档](https://docs.crowdsec.net/u/bouncers/firewall/)和 v0.0.36 示例配置。仅参考设计与兼容边界，不运行 Forwardx 安装器或复制其实现。

回归命令：

```bash
python3 -m unittest discover -s tests -p test_relay_mode.py
python3 tests/verify_relay.py /path/to/crowdsec-v1.8.1
```

隔离的官方引擎验证只处理临时配置和合成 SSH 日志，不操作生产服务或主机防火墙。它验证采集配置与实际文件解析，不能替代目标 VPS 的真实 journal、转发器共存及端到端封禁测试。

## 节点角色与流量路径诊断

菜单 `4 → 3 → 2` 或 `sudo bash crowdbastion.sh --relay-path` 依次选择入口/中间/出口/不确定、用户态/NAT/bridge/不确定，以及可选 TCP/UDP 本地入口端口。选择只用于本次输出，不保存。EOF、`q` 或角色/路径菜单的 `0` 取消。

诊断读取数字 socket 地址与必要的本地 NAT 规则，不读取转发器配置或进程完整命令行。角色是操作者声明，socket 对端是本机可见网络对端；两者不能证明完整远程拓扑。取反、集合端口及其他无法忠实表示的 NAT 条件跳过并标为未验证。随后复用 Bouncer 静态检查；完整诊断仍返回 `2`，读取/输入异常返回 `1`。

## 隔离转发与封禁验收

验收器独立于安装脚本，使用你提供的 gost、realm 和官方 Firewall Bouncer 可执行文件：

```bash
sudo python3 tests/verify_relay_network.py \
  --gost /path/to/gost --realm /path/to/realm \
  --bouncer /path/to/crowdsec-firewall-bouncer --output /tmp/relay-results.json
```

完整模式要求 Linux root、`unshare`、`mount`、`ip`、`nft`、Python/PyYAML 和可用内核功能。先建立私有网络及挂载命名空间，再创建两个客户端和后端；`/run` 使用私有 tmpfs。只修改隔离环境的转发参数、防火墙和子命名空间，不向生产 LAPI 提交决策。官方 Bouncer 消费合成的 loopback 决策流 API；这是防火墙执行验收，不是日志检测或 CAPI 同步验收。

矩阵包含 gost、realm 和内核 DNAT+MASQUERADE，各自 TCP/UDP、IPv4/IPv6。每项要求：正常可达、封禁来源不可达、另一来源仍可达、官方规则计数增加、解封后双方恢复；记录后端观察到的来源 IP。使用新连接/新 UDP socket，不验证已有长连接中断，不作为吞吐量或低配 VPS 性能基准。Docker bridge、iptables Bouncer 后端、真实多跳和加密隧道未纳入矩阵。

返回 `0` 表示请求的检查通过、`1` 表示验收失败、`2` 表示依赖/隔离不支持。受限环境可明确使用 `--forward-only`：仅在 loopback 运行 gost/realm 转发，不初始化防火墙，结果不代表封禁通过。验收进程回收自己启动的进程；完整模式退出后私有命名空间与规则随之释放。

2026-10-12 的隔离客体验收中，以上完整矩阵 **12/12 通过**；[原始报告](audit/2026-10-12-relay-network-results.json)和[验证环境与边界](verification.md#中转路径与隔离网络验收)已保存。它验证 nftables Bouncer 的 INPUT/FORWARD 执行，不替代目标节点部署验收或低配硬件性能测量。

## 性能测量

新增独立 [中转性能基准与指标说明](relay-benchmark.md)，对比同机 gost/realm TCP/UDP 在无 Bouncer、空决策和指定封禁集合下的 goodput、RTT 及进程 CPU/RSS。使用私有命名空间及合成 API，不操作生产决策。测量不覆盖 CrowdSec 核心日志检测和 WAN 线路，目标 VPS 的总开销需按文档另行观察。

## 远端 LAPI / Bouncer-only

在中心运行 CrowdSec、在中转仅执行中心封禁时，使用 `--install-relay-bouncer`，而非安装本地日志检测核心。安装菜单第 6 项也提供接入与维护。中心管理员先为每个中转创建独立 Bouncer 密钥；详见 [中心账号、日志与运维](remote-bouncer-operations.md)。

```bash
sudo bash crowdbastion.sh --install-relay-bouncer
sudo bash crowdbastion.sh --configure-relay-bouncer
sudo bash crowdbastion.sh --relay-bouncer-status
sudo bash crowdbastion.sh --remove-relay-bouncer
```

URL 和密钥交互输入，密钥隐藏，不支持密钥命令行参数。URL 不允许用户信息、查询、片段或重定向。HTTPS 使用系统 CA 校验；HTTP 只接受字面环回、RFC1918 和 IPv6 ULA 地址，不接受公网地址或域名（含 `.local` 域名）。建议使用 WireGuard 私网或 TLS。认证预检访问真实 `/v1/decisions/stream?startup=true`，检查 HTTP 200 和 JSON 决策流结构；整个 helper 操作限制 15 秒。超时、错误密钥、TLS 或连接失败均不替换原配置。

已有官方基础 YAML 保留；本工具仅写入 root-only `crowdsec-firewall-bouncer.yaml.local` 与无密钥 SHA256 托管标记。已有非托管 `.local`，或托管文件被外部修改，均拒绝接管/移除。覆盖配置指定 INPUT/FORWARD 和 nftables input/forward hooks，明确启用 TLS 校验和 API-key 认证；不会自动停止、卸载或配置已安装的 CrowdSec 核心，不注册中心账号、不修改其他 Bouncer。

全新 amd64/arm64 节点安装固定官方 Firewall Bouncer v0.0.36 release：通过官方 GitHub HTTPS release 元数据中的 asset SHA256 digest 验证归档；无 digest 或校验失败时拒绝安装。直接部署官方二进制、完整配置与独立 systemd unit，默认使用 iptables/ipset 后端；只复用系统包管理安装 iptables、ipset、curl/CA/PyYAML 等运行依赖，避免 upstream install.sh/软件包 postinst 自动访问本地 cscli。已有 Bouncer 基础配置时使用原安装与防火墙后端；命中已确认的 0.0.36／0.0.38 nftables 续封缺陷时先拒绝安装／配置，按[后端与续封检查](usage-guide.md#防火墙后端与续封检查)规划迁移。检测到残留 binary/unit 但缺少基础配置时拒绝覆盖，需人工核对。

配置或启动失败恢复原 `.local`、托管标记以及原服务启用/运行状态；首次安装失败移除新 binary/unit/base 配置，已安装的通用依赖保留。移除入口先验证托管标记与内容，再停用 Firewall Bouncer 并移除本工具远端覆盖；原基础配置、包和二进制保留，不自动重新启动原本地配置。遇非托管或修改过的覆盖先拒绝，不改变服务。状态命令不做认证请求、服务重启或防火墙写入，也不显示密钥；服务运行不等于真实业务阻断通过。

Bouncer-only 不采集 SSH 日志、不会识别新的 SSH 攻击；集中日志需自行配置独立可信传递通道。转发/SNAT 丢失源 IP 会影响后端检测，不能由中心凭空恢复。它不承诺阻止流量型 DDoS，短期隔离验收也不代表 WAN 带宽或长期稳定性。

### 远端与本地核心之间的迁移边界

`--remove-relay-bouncer` 只撤销托管远端覆盖并停用服务，**保留 standalone systemd unit、二进制与基础配置**。保留在 `/etc/systemd/system` 的 unit 会优先于软件包提供的 unit；因此移除远端接入不等于已经准备好切换为本地核心。

`--install-core`（网站模式）与 `--install-relay`（本地日志检测中转模式）发现托管远端标记或本工具创建的 standalone unit 时，均在安装包、创建账号、修改配置或启停服务前拒绝执行，明确提示不支持自动迁移。不会自动删除或转换远端状态。检查不跟随 unit 符号链接；符号链接（含 masked unit）、悬空链接及非普通文件均拒绝并要求人工核对，避免读取无关目标或绕过检查。普通发行版的常规 Firewall Bouncer unit 文件不因此被拒绝。

如需切换，先由管理员备份并人工核对远端凭据/中心账号、基础配置、`.local` 与托管标记、unit 的真实目标、二进制来源及发行版包归属，再决定如何撤销 standalone 安装并恢复正确的软件包 unit。涉及已有核心或其他防护接入时需先制定恢复方案；完成核对与清理后再运行本地安装入口。这一步不是移除入口自动完成的操作。

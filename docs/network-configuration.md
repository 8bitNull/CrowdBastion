# 可选 TCP 默认值恢复与配置归属审计

网络调整是独立可选操作。默认安装、`--optimize` 不调用它；不改变 BBR/fq、收发缓冲、UDP、队列、全局 `tcp_mem` 或业务配置，不重启服务，不执行 `sysctl --system`。恢复内核默认值不代表吞吐提升，也不能替代真实中转客户端测试。

先运行 `sudo bash crowdbastion.sh --network-status`。只读 JSON 列出 sysctl 配置的真实路径与链接别名、普通 `net.*` 赋值及行号、运行值、systemd/procps 两种加载顺序和最终值，以及当前源码、托管 current 和实际 cron 维护副本的摘要与原执行时间。只展示网络赋值，不输出其他配置内容或执行任何配置文本。无法读取、动态/通配/复杂语法和不能解释的维护命令保持 `unknown`。

systemd 对 `/etc`、`/run`、`/usr/local/lib`、`/usr/lib`、`/lib` 的 sysctl.d 同名文件先按目录优先级选择，再按文件名排序；`/lib` 的真实路径别名会去重。systemd 只有通过发行版链接等配置才读取 `/etc/sysctl.conf`；procps `--system` 还可能最后读取该旧文件。报告分别计算这两种结果，不能用最终文本赋值推断转发等非选定键的运行副作用。请明确选择主机实际使用的 loader；本工具不执行或更换 loader。

创建 root 私有的 `/var/lib/crowdbastion/network.json`（0600，父目录不可由其他用户写入）：

```json
{
  "version": 1,
  "loader": "systemd",
  "keys": ["net.ipv4.tcp_syn_retries", "net.ipv4.tcp_fin_timeout"],
  "sources": ["/etc/sysctl.conf"]
}
```

`keys` 必须显式选定。支持的七项是 `net.ipv4.tcp_syn_retries`、`tcp_synack_retries`、`tcp_orphan_retries`、`tcp_fin_timeout`、`tcp_autocorking`、`tcp_no_metrics_save`、`tcp_tw_reuse`（后六项同样使用 `net.ipv4.` 前缀）。拒绝其他键、全局内存键、任意命令和值。目标值由固定内部只读脚本在临时网络命名空间中读取本机内核初始化值；命名空间权限或键不可用时计划仍可读，但拒绝应用，绝不猜测默认值。该脚本不向命名空间或宿主机写入任何键。

`sources` 是审计报告中确实含有竞争赋值的真实路径，表示用户已核对并接受后续覆盖；没有竞争赋值时使用 `[]`。工具保留这些文件及其全部内容、元数据和链接，只在单一托管文件 `/etc/sysctl.d/99-zz-crowdbastion-network.conf` 写入选定键。因此计划明确标为 `selected-overrides`，不宣称去除重复或完成配置集中。未确认的竞争来源、动态/通配/复杂活动声明、后续文件的覆盖，以及 procps 最后读取旧 sysctl.conf 覆盖目标值，均会阻止应用。不会替换已存在的用户文件；托管文件由事务根中的私有 ownership 状态核对，发生外部修改后停止。

每次主入口只接受一个操作：

- `--network-plan`：只读显示归属、两种 loader 的最终值、选定旧值/新值及理由、竞争来源和阻止原因。
- `--network-apply`：重新规划、交互确认，取得共同维护锁，检查环境稳定、配置与维护副本摘要；逐键写入并立即读回，比较本机服务的 PID/重启计数及已配置 Bouncer 的 LAPI 查询结果，最后原子持久化选定键。任何无法验证的情况安全恢复未提交更改。API 超时保留阶段/错误码，不据此归因于某个 TCP 键。
- `--network-verify`：独立核对运行值、配置文件/链接和 loader 顺序、维护副本、服务/API 基线；不测中转吞吐。
- `--network-commit`：再次核验并在期限内提交，之后取消自动回退。
- `--network-rollback`：逆序恢复未提交事务，保留外部漂移；单项失败继续其他项，并保留定时重试，全部恢复后才取消定时器。

事务共用 `/var/lib/crowdbastion/changes`：私有完整 Python 运行副本、不可变 manifest、逐项 journal、共同锁及 15 分钟 systemd 回退定时器。网络和端口策略共用“最多一个未完成变更”的约束，但各自的 verify/commit/rollback 只接受本类型事务。重复应用同一托管配置不增加文件/注释；仍检查环境和当前基线。回退只依赖标准库，不依赖 API 健康、环境门禁或调用者的 venv/PyYAML。

Python 自动化入口：`python3 lib/crowdbastion_network.py status|plan|apply|verify|commit|rollback [--config PATH] [--root PATH] [--id ID] [--manager PATH] [--runtime PATH] [--cron PATH]`。`--id` 可明确选择同类型事务；主脚本选择唯一未完成同类型事务。恢复副本入口与端口策略共用 `crowdbastion_change.py rollback --root ROOT --id ID`，其固定分派依据 manifest 的 kind 选择网络适配器。不要修改 manifest 或把运行副本依赖留在临时目录。

退出码：正常只读/准备/暂存/核验/提交/完整回退为 0；阻止、未知、核验失败、部分回退及已安全回退的应用失败为 1；环境不稳定/未知或锁忙为 75。`--network-status` 不执行 API、服务命令或命名空间默认值检查。常规测试全部使用临时文件夹和注入命令；本地容器若拒绝 unshare，只能报告默认值未知，不能声称真实内核设置或流量已验证。

审计同时报告配置文件的 uid/gid/mode、链接原目标、可信父目录和托管状态（`absent/foreign/managed/drift/unknown`）。不安全归属或权限阻止应用。以后缩小 `keys` 选择时，已有托管文件中的未选项保留；如需撤销原来选过的配置，请使用相应未提交事务的回退，或另行审查持久配置，不能把缩小选择理解成隐式删除。

修改前必须预先安装 Python 3：安全管理锁使用其标准库，缺少时首次安装也在写入前停止，不自动绕过锁自举。菜单 `4 → 4 → 7` 提供相同操作。主脚本显式 status/plan 保留完整 JSON；修改入口和菜单显示简短结论，直接 Python 保留机器 JSON。无变化不创建新事务，已有未提交事务保留原期限；应用失败即使成功恢复仍返回 1。

共享事务被另一类型占用时，结构化 `pending_change/pending_kind` 指明先处理的类型，查看对应 status 再提交或回退。过期 commit 报 `verification_failed` 和 `refusal_code=transaction_expired`，不会取消回退机会；一般核验失败也不提交。需锁的修改缺少 Python、路径不安全或无法证实前提时安全拒绝。

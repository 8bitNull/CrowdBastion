# 2026-11-07 功能回归与阻断项

本轮按“功能回归 → 整理阻断项 → 再做收敛”的顺序执行前两步。被测提交为 `5d7d3fa07abe7947e06dfe5ff3eb30153f58529f`，开始时工作区干净。未修改产品代码、测试实现或断言。

**本次完整回归 1,828 项全部通过，失败、错误、跳过均为 0；本轮覆盖内未确认功能阻断，可以进入保持现有行为的小步收敛。真实内核链路和 VPS／公网现场验收仍未完成，见下方验收阻断清单。**

## 本次执行结果

| 检查 | 结果 |
| --- | --- |
| 完整回归 | `full --require-no-skips`，1,828 项通过，失败 0、错误 0、跳过 0；退出码 0，`accepted=true` |
| 完整运行时间 | UTC 2026-11-07 07:33:22—07:45:31；入口耗时 728.69 秒，外层记录 728.84 秒，约 12 分 9 秒 |
| 执行完整性 | 实际执行 1,828 个唯一 ID，与仅导出 Git 发布文件后的发现清单完全一致；全部逐项记录为 `passed` |
| 兼容分支补充矩阵 | `verify_vps_matrix.py` 的 109 个独立夹具场景全部通过，约 16.43 秒；覆盖七种发行版标识、apt/dnf/yum、后端选择和已有部署保护 |
| 发布文件冒烟 | `git archive HEAD` 导出后，主入口和旧兼容链接的 `--help` 均返回 0，输出完全一致；完整测试发现成功 |
| 静态检查 | 190 个 Python 文件编译检查、24 个 Shell 文件语法检查通过；`lib/user_flow.sh`、`lib/remote_bouncer.sh` 的 warning 级 ShellCheck 通过 |
| 基线完整性 | 运行中及结束后核对 370 个原有 Git 跟踪文件，内容 SHA-256、权限、链接目标均未变化，提交未变化 |
| 专项资源 | 6 份既有运行二进制／模块和 2 份官方 Web 归档 SHA-256 与原验收记录一致；结束后未发现仍从专项资源目录运行的进程 |

109 个补充场景不计入 1,828 项 unittest 数量。夹具中的发行版标识和系统命令替身不构成真实发行版安装、systemd 开机或内核封禁验收。

## 重点行为覆盖

以下为本次完整回归中的子集，均实际执行并通过，不额外累计为测试总数。

| 范围 | 通过项数 | 主要核验内容 |
| --- | --- | --- |
| 六个智能流程模块 | 159 | 目标及任务依赖、只读探测、网站实例隔离、取消／失败、暂缓及重启续办、过时计划在锁内拒绝、远端计划保护 |
| 新旧导航与 CLI 七个相关模块 | 143 | 高级菜单与旧入口、退出码、确认和取消、已有部署修复、维护副本和交互结果 |
| 网站重载与 Web Bouncer 两个模块 | 32 | 配置与重载证据、失败恢复、请求阻断和故障策略；其中真实 Lua Nginx／worker 用例 18 项 |
| 官方通知与 Telegram 两个模块 | 27 | 模板、官方插件、回执、队列与本地模拟 API；其中官方插件及回执三类用例 21 项 |
| 锁与共同事务两个模块 | 26 | 互斥、期限、漂移、部分失败恢复、中断重试和稳定运行副本 |

旧记录中的 40 项环境跳过，本次均已实际通过：Lua Nginx 18 项、官方通知插件及回执 21 项、gost UDP 1 项。本次为同一固定代码基线上的一次完整严格运行，未将历史分组结果拼接为全量通过。

## 阻断项与关闭条件

**功能阻断：0 项确认。** 完整套件没有失败、错误或跳过，不需要为本轮回归修改业务逻辑。此结论仅适用于上述测试覆盖及环境。

以下两项阻断相应的现场验收结论；保持行为的代码收敛可以继续，生产完整验收仍需补齐这些证据。

| 编号 | 当前证据与影响 | 关闭条件 |
| --- | --- | --- |
| A-01：真实内核／容器链路验收条件不足 | `unshare --net --mount -- true` 返回 1，错误为 `Operation not permitted`；Docker、ip、nft、iptables、ip6tables、ipset 缺失，未发现可用 QEMU 程序或既有客机资源。当前不能执行真实 INPUT/FORWARD、Docker DNAT、双栈封禁及恢复验收 | 在具备网络／挂载命名空间权限和相应工具的隔离 Linux 主机或虚拟机，按目标后端运行现有 `verify_relay_network.py`、`verify_relay_iptables.py`、`verify_remote_bouncer.py` 等适用实验；记录正常对照、封禁、续封、删除、到期和恢复结果 |
| A-02：当前版本的现场业务闭环未验收 | 本轮未进行真实 VPS 软件包安装、生产网站重载、冷启动、公网 IPv4/IPv6 TCP/UDP 或真实访客 IP 与拦截关联验证。Telegram 使用本地模拟 API，未向真实用户发送消息。单测结果不能关闭这些现场验收项 | 在明确的测试节点与业务入口，验证适用的安装／接入／失败恢复／重启及外部允许和阻断对照，关联真实 IP、规则和请求证据；需要真实通知交付结论时另行验证实际送达 |

日志中的 Telegram 429／5xx、服务或防火墙异常、回滚和“尚未验证”等文字来自故障注入及夹具场景。最终逐项状态全部为通过，不能将这些模拟输出作为本机或远端的现场故障报告。

## 复跑与本地证据

本机使用既有专项环境，Python 3.11.2、PyYAML 6.0.3、pycdlib 1.14.0；资源为 CrowdSec v1.8.1、gost v3.3.3、Nginx 1.22.1 及匹配 Lua 模块。本轮未安装或升级系统服务。

```bash
source docs/audit/2026-11-04-specialist-dependency-validation/environment.sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tests/run_tests.py \
  --tier full --require-no-skips \
  --timings /tmp/crowdbastion-functional-regression-full.json

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tests/verify_vps_matrix.py \
  --output /tmp/crowdbastion-functional-regression-matrix.json
```

环境脚本和 `/tmp` 专项资源仅在保有本地归档的工作区可用。新克隆需依据[测试说明](../../tests/README.md)及[专项依赖记录](2026-11-04-specialist-dependency-validation.md)准备资源，设置 `CROWDSEC_TEST_RELEASE`、`CROWDBASTION_TEST_NGINX`、`CROWDBASTION_TEST_LUA_PREFIX`、`GOST_TEST_BINARY`；不能仅复制变量便视为依赖已就绪。

原始证据仅保存在本地忽略目录 `private-audit/functional-regression-2026-11-07/run-7g028wp1/`：`baseline.json`、`run.json`、`summary.json`、`full.txt`、`full-timings.json`、`verification.json`、`compatibility-matrix.json`、`compatibility-matrix-run.json`、`release-selected-tests.txt`、`release-smoke.json`、`static-checks.json`、`environment-preflight.json`、`coverage-inventory.json`。报告和证据索引在回归结束后添加，不属于上述 370 个原文件的变更。

本轮未执行代码收敛、Git 提交／推送或生产部署。后续收敛应保持 CLI／JSON、状态判断、确认、实例范围、锁、事务和恢复行为，并以本次固定提交及测试清单复验。

## 后续真实链路补验

用户继续授权后，已在独立 QEMU 客机完成真实 nftables／iptables 各 12 项、Docker 相关 8 项，以及 daemon 重启后的双栈 TCP／UDP 续封和内核自然到期复验。A-01 的隔离环境链路证据已取得；A-02 的指定 VPS／公网现场验收继续保留。新增验证工具后的完整回归为 1,846 项严格零跳过通过，原有 1,828 项全部保留，产品代码保持原基线。版本、失败轮次、工具收敛与未覆盖边界见[后续验收报告](2026-11-07-kernel-docker-validation.md)。

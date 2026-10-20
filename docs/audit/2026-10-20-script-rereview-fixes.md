# 脚本复审：重载证据、事务中断与启动程序检查

本轮修复复审确认的三项问题，保持命令行入口、新装默认策略及未选择的已有策略兼容。代码修复在当前源码快照的隔离目录完成；仅回填本轮差异，保留原工作区已有改动和 `install-crowdsec-1panel.sh` 软链接。未连接或部署 VPS。

后续复审发现 worker 自动重生也会满足 PID 更替条件；补充修复为同时要求本次 master 接受配置的完整日志证据。该修复新增日志可观察性前提，详见[worker 重生修复与复审](2026-10-20-nginx-respawn-fix.md)。下文测试数字保留为上一轮交付的历史记录。

## 运行中的 Nginx 配置

策略修改及托管模块升级共用运行进程检查：记录实际 master 和 worker PID，发送重载，在单个 10 秒观察期限内每隔 200 毫秒采样，要求 master 不变、完整的新 worker 集合连续两次存活，再检查托管请求钩子。宿主机核对 systemd MainPID 与实际 Nginx 进程，容器读取 Docker top 的主机 PID 表。正在退出及僵尸 worker 不计入成功证据。

观察命令共享剩余时间预算；初始进程采样、配置测试及发送重载有各自的超时边界。使用单调时钟，避免系统时间调整和 Bash 版本差异影响期限。到达命令期限后强制终止本次命令进程组，覆盖命令及其子进程忽略 TERM 的情况。

真实 Lua 初始化失败可能使 `nginx -t`、`nginx -s reload` 和 `nginx -T` 全部返回零，而旧 worker 继续使用原策略。回归用真实官方 Lua、两 worker 的 Nginx master 及外部 mTLS 证书重现这一情况，并检查脚本返回失败、恢复磁盘策略及报告恢复状态。

## 事务与恢复

策略修改在独立子 shell 中执行，设置 EXIT/INT/TERM 清理及提交标记。提交前的失败或中断会恢复配置和托管安装记录，避免两者摘要不一致导致后续归属检查失败。模块升级备份和恢复原有模块、解析器、钩子及安装记录。

恢复同样需要运行中 worker 的重载证据和托管钩子检查；文件恢复成功但运行状态未确认时，明确报告恢复未完成，并保留备份。如果缺失的外部证书仍未恢复，旧 worker 可能仍在服务，工具不会把这一状态报告为恢复成功。

## Bouncer 重启目标

诊断继续优先读取运行中 `/proc/<MainPID>/exe`。修改前的 guard 另查 systemd 有效 `ExecStart` 指向的磁盘可执行文件，包含 drop-in 覆盖；运行程序或启动程序任一个确认是 nftables 缺陷版本 0.0.36／0.0.38，即在配置、账号及重启操作前拒绝。

ExecStart 仅作为数据解析；版本探测使用独立参数数组，不解释 shell 字符。保留 systemctl 输出路径中的字面空格、引号和反斜杠。元数据不可读及其他版本仍明确标为尚未验证，保持原有允许语义，不自动切换后端。iptables/ipset 的检查语义保持不变。

## 验证与边界

隔离工作区完整 unittest **927 项：906 通过、21 跳过、0 失败**，耗时 350.941 秒；其中真实 Nginx/Lua **16 项全部通过**。包管理／配置保留模拟矩阵 **109/109 通过**。项目 Bash 语法 26 个文件、Python AST 183 个文件、改动模块 ShellCheck 0.11.0 及差异空白检查通过；统计不包含虚拟环境依赖。

21 项可选检查跳过：1 项 gost、16 项官方 CrowdSec 通知插件／回执、4 项 ISO 媒体校验；真实 Nginx/Lua 测试未跳过。独立复审提出的路径转义、超时终止和模拟故障注入问题均已修正并验证。

回填后在保留并行改动的原工作区再次运行完整回归：**1014 项，993 通过、21 跳过、0 失败**，耗时 361.987 秒；包含同样的 16 项真实 Nginx/Lua 验证。原工作区项目语法检查覆盖 26 个 Bash、191 个 Python 文件。代码与测试摘要和各项日志见[结构化结果](2026-10-20-script-rereview-fixes-results.json)。

复现完整回归使用当前仓库测试目录、临时 PyYAML 依赖及准备好的固定版本运行时：

```bash
PYTHONPATH=/tmp/crowdbastion-review-deps:tests:lib \
PYTHONDONTWRITEBYTECODE=1 \
CROWDBASTION_TEST_NGINX=/tmp/crowdbastion-lua-runtime-20261019/root/usr/sbin/nginx \
CROWDBASTION_TEST_LUA_PREFIX=/tmp/crowdbastion-lua-runtime-20261019/root \
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

真实运行时用例还需要 OpenSSL、已固定校验的 `/tmp/crowdsec-official-openresty.tgz` 和 `/tmp/crowdsec-http`。缺少这些依赖会跳过相应用例，不能算作完成运行时验证。

本轮真实 Nginx/Lua 测试覆盖正常重载与 vendor 初始化拒绝；进程检查回归另覆盖 master 替换、新 worker 短暂存活、查询挂起、共享期限与忽略 TERM。策略／模块回归覆盖信号中断、静默重载拒绝、钩子漂移及恢复未完成。Bouncer 回归覆盖运行与启动版本不一致、有效路径解析、未知版本、凭据保护及实际脚本调用边界。

Docker 命令和 systemd 元数据由本地 fixture 提供；Nginx 运行时使用真实进程和请求，未使用真实 Docker 守护进程或修改宿主机服务。结束 Docker 客户端不保证取消已经提交给守护进程的操作，恢复结果仍须通过运行进程及钩子检查确认。进程检查证明采样窗口内的 worker 更替，不能保证其长期健康，仍需外部业务请求验收。本轮没有内核封禁／续封流量或 VPS 部署验收。

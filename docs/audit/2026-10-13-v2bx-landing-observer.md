# 落地常驻仅观察服务（2026-10-13）

新增 `--install-v2bx-observer`、`--v2bx-observer-status`、`--disable-v2bx-observer`，菜单 `4 → 14`。安装私有 helper、配置和 systemd unit，支持三内核独立文件源；每源私有 SQLite，正常退出／重启恢复游标。提供心跳、源存在状态、容量、忽略与连续性风险指标；容量耗尽硬停止，不自动删除证据。

本阶段未安装 CrowdSec acquisition、场景、profiles，不生成告警或封禁，不设置连接／带宽限制；共享中转继续按明确 CIDR 声明排除。运行参数及边界见 [V2bX 指南](../v2bx-guide.md#落地常驻仅观察服务)。

## 验证结果

- 专项 18 项全部通过：真实文件追加、SIGTERM／重启不重复、三内核独立源、中转排除、容量停止、日志缺失、重复进程互斥、崩溃指标恢复、安装／停用保留状态、配置／inode／符号链接限制、依赖缺失、外部 unit、失败撤销与只读状态。
- 隔离安装目录实际运行已复制的 Python daemon，通过首个完整心跳后才认定安装成功；停用后数据库事件保留。systemctl 行为为 fixture，不代表真实 systemd 启停或沙箱验收。
- 最终全仓 707 项：687 通过、20 按环境条件跳过、0 失败，172.795 秒；见[原始输出](v2bx-landing-observer-2026-10-13/final-unittest.txt)。
- Bash/Python 语法、ShellCheck（既有排除项）、systemd-analyze verify、Markdown 本地目标与 diff 检查通过。README 保持 70 行。
- 独立代码审查发现并关闭启动就绪过早、unit 中途失败残留两项问题；修复前测试复现失败、修复后通过。

全仓使用已存在的临时依赖环境，没有安装系统包：

```bash
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=/tmp/v2bx-test-python-deps python3 -m unittest discover -s tests -q
PYTHONPATH=/tmp/v2bx-test-python-deps python3 -m unittest discover -s tests -p test_v2bx_service.py -q
```

## 初始失败与修正

初次专项运行的默认解释器缺少 PyYAML；切换到既有临时依赖环境后完成测试，不把临时环境当生产依赖。新增边界测试先复现重复进程覆盖心跳和遗留临时文件阻塞恢复，加入互斥锁及锁内恢复后通过。

独立审查的两个问题均以回归测试复现：active 不能证明采集初始化完成；unit 写入／chmod 失败必须清理独占创建的文件。真实安装目录启动测试进一步发现漏复制 `crowdsec_config.py`、`crowdsec_relay_paths.py` 两个间接依赖，补齐 helper 与完整性清单后通过。

[首次全仓输出](v2bx-landing-observer-2026-10-13/initial-unittest-failed.txt)记录 702 项、2 个错误、20 跳过；该轮与后续修正存在重叠，不作为最终稳定源码验收。最终修正稳定后重新跑完整 707 项，以最终轮结果为准。

## 未验证范围

当前宿主机未安装该服务；实际 VPS 的 systemd 沙箱、SELinux、日志写入权限、轮转、并发负载和磁盘增长仍待核实。CPUQuota 20%／MemoryMax 256M 为限制设置，不是吞吐测试。首次读取历史积压可能提前达到容量；混合 core 共用一文件、实时 journal、自动保留期／滚动清理及配置迁移尚不支持。

观察事件未流入 CrowdSec，下一阶段需来源证据和 profiles 核查后再做仅观察告警接入；自动封禁、连接限制、带宽清洗均不能据此宣称完成。

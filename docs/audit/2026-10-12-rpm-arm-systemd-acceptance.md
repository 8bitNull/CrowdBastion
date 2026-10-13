# Task 2：RPM / ARM 真实 systemd 验收

计划中的授权客机尝试已完成；这不代表每个环境均通过。逐案例退出码、断言、官方镜像校验和、实际内核/RAM、不可变 seed/source 哈希见 [验收 JSON](2026-10-12-vps-rpm-arm-results.json)。脱敏串口日志及原始测试源码版本已归档到 [证据目录](vps-rpm-arm-evidence)，每条记录含日志 SHA256 和归档 UTC；实验目录原件保留。

| 实际环境 | 请求 / 实际 RAM | 远端 10 案例 | 原生核心/relay | 整次运行 |
|---|---|---|---|---|
| AlmaLinux 9.8 x86_64 | 2048 MiB / 2008608 KiB | 通过 | fresh 安装通过 | 通过，QEMU rc0 |
| Rocky Linux 9.8 x86_64 | 2048 MiB / 1812012 KiB | 通过 | fresh 安装通过 | 通过，QEMU rc0 |
| Fedora 44 x86_64 | 2048 MiB / 2000336 KiB | 通过 | fresh 安装通过 | 通过，QEMU rc0 |
| CentOS Stream 9 x86_64 | 1024 MiB / 781252 KiB | 通过 | 首次尝试 OOM，未观察 CLI 最终退出 | 失败/未完整 |
| Debian 13 ARM64 | 1024 MiB / 980512 KiB | 9/10 通过；重启后 active=false | 原生包 bootstrap 通过；已有核心 relay 集成失败 | 失败，QEMU 退出码 unknown |
| RHEL | 无授权许可镜像 | 未测试 | 未测试 | 未测试 |

通过的 RPM 客机使用原生 CrowdSec v1.8.1 与原生 Bouncer；远端阶段的 LAPI 则使用已取得的官方 v1.8.1 构建产物及私有数据副本，在真实客机 systemd 中运行，不能冒充原生包验收。ARM 首先通过官方软件源安装原生 CrowdSec 包作为 LAPI，因此后续 relay 测试是已有核心集成，不能称为 fresh 核心安装。

远端案例包括 fresh/repeat、真实端点 `127.0.0.1 → 127.0.0.2` 与 key 轮换、坏 key 回滚、外来 `.local` 保护、真实 CrowdSec decision 添加/删除与 nft 集合出现/消失、重启自启、移除托管配置、已有核心文件 SHA256 保留。Alma/Rocky/Fedora 还通过真实 `--help` 与只读状态不改配置，以及保留独立 unit 时两种本地安装入口拒绝、配置不变。历史 Alma/Rocky 初次尝试保留单独失败记录，旧 URL 尾斜线规范化明确仅算 key 轮换。

CentOS 首次核心 CLI 期间内核 OOM 杀死 python3 PID4115；实际杀死进程对应的具体生产命令未证实。更新 hub helper 后，同一官方镜像、同样实际 781252 KiB 的 fresh-core-only 后续尝试实际 CLI rc0、核心与 Bouncer active、版本 v1.8.1，未见 OOM。后续测试脚本在版本检查后的清理处缺少 faulthandler 导入，出现 NameError、未输出完整标记；核心案例通过与测试脚本失败分别保留，不标整次通过。脚本导入已修正，未进行额外客机轮次。

ARM 原生包安装 rc0、初次 systemd 核心启动通过，初始远端 7 案例通过；重启后 Bouncer enabled=true、active=false，随后移除/核心保留与两种迁移 guard 通过。已有核心 relay 集成在 Bouncer 包 postinst 启动服务时失败，最终两服务 inactive；缺少对应 unit journal，原因未定，不等于 ARM 不支持。原 1500 秒 runner 为保留已进行的 ARM TCG 重启而终止，同一客机由有界 2400 秒监视器接管，完成标记后关机；实际 QEMU 退出码无法回收，明确 unknown。

全部客机使用 QEMU TCG、1 vCPU、独立快照；不用于性能比较。2 GiB 功能通过不能替代 1 GiB 容量结论，RPM kdump 预留也已体现在实际 RAM。nft 集合命中不等于各 VPS 厂商 INPUT/FORWARD、IPv4/IPv6 业务流量阻断已验证；TLS/公网远端端点与 Ubuntu ARM64 未在本任务实测。未安装宿主包、修改宿主服务/防火墙、转发宿主端口、共享宿主目录或发送 Telegram。

可复现入口（调用者需先备妥便携 QEMU、官方校验镜像、pycdlib 与官方核心快照）：

```sh
python3 tests/prepare_vps_rpm_arm.py --lab LAB --core-root OFFICIAL_CORE_SNAPSHOT --output LAB/seed-rpm.iso
python3 tests/prepare_vps_rpm_arm.py --lab LAB --arm --output LAB/seed-arm.iso
python3 tests/verify_vps_rpm_arm.py --lab LAB --distro alma9 --ram 2048 --timeout 1800 --seed LAB/seed-rpm.iso
python3 -m unittest discover -s tests -p test_vps_rpm_arm.py
```

验证：12 个 harness 单元测试通过，所有新增 Python 文件编译检查通过。完成判断要求真实 systemd 身份、精确案例断言、独立完成标记、完整核心尝试、无超时和已知正常 QEMU 退出；任意 true 占位断言、重复案例、凭据字段或截断不能产生通过。

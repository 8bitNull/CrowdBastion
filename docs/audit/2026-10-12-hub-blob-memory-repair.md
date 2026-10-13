# 试用前快照内存修复

生产辅助模块的内存修复及源码回归已完成；最终默认 VPS 复测和长期/恢复验收仍在执行，没有新增试用放行组合。没有修改宿主机防火墙、服务、软件包或部署真实节点。

## 根因证据

[原始 512 MiB 安装失败](vps-repair-evidence/debian12-512m-install-oom.json)：实际 MemTotal 480260 KiB，两次内核 OOM；原轮次未记录完整命令，不能单独指定根因。

[独立诊断](vps-repair-evidence/debian12-512m-oom-diagnostic.json) 与 [串口](vps-repair-evidence/debian12-512m-oom-diagnostic.serial.log)：同一默认生产源码、1 vCPU / 512 MiB，有限白名单进程身份/RSS 采样。PID 1987 为 `crowdsec_maintenance.py`，RSS 从 94820 升至 246652 KiB，随后内核在 uptime 485.954 秒将该 PID 杀死，anon RSS 262132 KiB。不记录完整参数或凭据；这不是默认资格验收。

完整快照生命周期回归使用 61 MiB City + 11 MiB ASN 文件和 160 MiB 地址空间限制，旧代码在 `before` 的 `base64.b64encode(path.read_bytes())` 处触发 MemoryError。文件原文、编码内容及 JSON 同时驻留；之前只分块计算 JSON 校验值仍不能解决完整内容驻留。

## 修改与边界

`crowdsec_maintenance.snapshot` 新建 format 3：以 1 MiB 分块读取/复制文件，私有 `files/` 目录按 SHA256 保存去重内容，JSON 保留元数据、内容哈希及大小。文件权限 600、目录 700；备份必须整体保存。元数据仍随文件数增长。新格式减少文件内容的内存副本，同时增加磁盘读写，因此仍需要真实低配客机复测。

读取和恢复检查全部内容、普通文件类型、符号链接、大小/哈希及私有目录；FIFO 使用无阻塞打开并立即拒绝。缺目录的读取不创建目录。恢复之前的冲突检查、数据库/WAL 排除及受管理链接保护保持有效。旧 format 2 内嵌快照和历史 manifest 可恢复；旧内嵌内容读取仍可能需要较大内存，未自动迁移或删除历史快照。

已有核心集成 scope 现强制原生仓库、包安装和初始配置保留证据，缺任一项即失败。测试各阶段异常退出通过 OnFailure 输出固定失败标记并关机；完整案例不能覆盖这个标记。[真实失败注入](vps-repair-evidence/debian12-harness-failure-injection.json) 中测试脚本故意退出 42，观察到失败标记与 QEMU 正常退出；缺系统身份是此故障注入的预期现象，不代表正常安装验收。

## 验证

[最终资源 fixture](vps-repair-evidence/blob-memory-fixture.json)：完整创建、修改记录、恢复成功，峰值 RSS 19424 KiB（约 19 MiB），地址空间限制 160 MiB。腐坏、符号链接、FIFO、非法路径、缺/宽权限内容目录、空快照以及旧格式恢复均有回归。独立审查未发现剩余 Critical/Important。

[最终源码回归](vps-repair-evidence/blob-final-regression-v2.json)：578 项全部通过、无跳过；启用官方 gost 与 CrowdSec 插件可选测试。ShellCheck（既有排除项）、Bash 语法、Python 编译及 diff 检查通过。每个生产辅助模块和测试源文件 SHA256 都记录在报告中。

[CentOS v2](vps-repair-evidence/centos9-cold-core-v2.json) 是新健康观察器、旧内存代码的完整成功：实际 781240 KiB、6 案例、三次重启与实际增删同步、QEMU 0、1906.215 秒。新内存版本使用独立 `/tmp/crowdsec-vps-repair-centos-blob-v3-20261012` 复测，不能把这份旧成功追溯成新版本验收。

## 正在执行与未关闭

最终同源码 Debian 12 / 512 MiB：`/tmp/crowdsec-vps-repair-512-blob-v4-20261012`。新 CentOS / 同原资源：`/tmp/crowdsec-vps-repair-centos-blob-v3-20261012`。均为官方独立基础镜像、默认安装、无生产超时诊断 drop-in。

有界顺序控制器状态 `/tmp/crowdsec-vps-blob-v6-queue.json`：只有同源码完整短测及回归通过才执行独立 1 小时，只有其通过才执行独立 24 小时；各轮重新计时，失败停止。冻结源码副本和 seed/provenance 防止将后续修改拼到旧结果。长测即使通过也不自动授予试用资格。

仍缺独立中心的远程 256/512 MiB 验证、1 GiB 长测、无防御对照、中心中断及双方重启恢复、原生 ARM64 默认启动证据。连续 24 小时尚未完成，不宣称所有 VPS 已通过。


## 后续客机证据与判定边界

新生产版本 CentOS Stream 9 空白本地核心生命周期已通过（实际内存 781240 KiB，三次重启/实际增删同步，QEMU 0），见 [结果](vps-repair-evidence/centos9-blob-v3-observer-v5-revalidated.json)。Debian 12 / 512 MiB 首次/重复安装与三次重启均通过且未观察 OOM，但旧 120 秒负载失败，**整轮仍失败**，见 [保留的失败报告](vps-repair-evidence/debian12-512m-blob-v4-soak-failed.json)。新就绪与同时间采样观察器另起独立轮次，不重写旧证据。最新 581 项源码回归全部通过、无跳过。上述结果不授予恢复、24 小时稳定性或原生 ARM64资格。

# 自定义 Telegram 机器人融合实施计划

**Goal:** 修复用户上传的 crowdsec_bot.py，保留交互功能，默认由官方通道独占自动告警；提供独立、可回滚的可选服务接入。

**Architecture:** `lib/crowdsec_bot.py` 保存修复后的标准库机器人；只通过结构化 cscli JSON 获取指定告警取证，事件样本保持路径与 UA 对应。私有 JSON 配置保存 Token、用户与聊天 ID、有效 CrowdSec 配置路径；单实例 flock 防止重复轮询。`lib/custom_bot.sh` 管理独立 systemd 服务，与官方通知启停分开。

**Spec:** 本会话已确认的“官方通知自动推送、自定义机器人查询及按钮操作”方案；原文件 `/data/uploads/conv-14-codex-60/crowdsec_bot.py` 保留不改。

**Constraints:** 不向真实 TG 发消息，不修改生产服务；不删除或接管未知机器人服务；不提交其他任务内容；独立程序只使用 Python 标准库。

## 1. 机器人行为修复

- [x] 新增 tests/test_custom_bot.py，先验证原脚本的 inspect 调用、固定 DROP 描述和操作失败误报问题。
- [x] 用参数数组运行 cscli，不使用 shell 拼接；检查退出码、超时与 JSON 格式，调用 alerts inspect ID --details -o json。
- [x] 解析 key/value Meta、事件 uri 和 AppSec JSON 数组上下文，最多显示 3 个相互对应的样本；空 UA、缺失字段、非 HTTP 明确区分。HTML 转义并限制字段长度。
- [x] 读取私有 JSON 配置，校验独立用户/聊天身份，默认不启动自动告警线程；API long-poll 超时大于 Telegram 等待时长，禁止重定向与重复实例。
- [x] 保留九宫格功能；封禁/解封校验 IP 与时长，按执行状态显示结果。白名单首次创建有效 YAML，校验失败恢复，重载失败恢复，不伪报永久加白成功。

## 2. 可选服务接入

- [x] 测试服务安装/更新、失败回滚、已有未知服务保留、只读检查和独立停用。
- [x] lib/custom_bot.sh 配置、更新、状态、停用；安装到本工具独立目录，Token 写入 600 配置；配置与服务修改先备份，启动失败回滚。已知其他脚本/服务/cron 候选或更新轮询冲突时拒绝并说明，不自动删除未知服务。
- [x] TG 菜单增加可选交互机器人子菜单；原四项官方通知功能保持独立。帮助和 README 说明旧 /usr/local/bin/crowdsec_bot.py 不自动覆盖，旧服务由用户核对后停用。

## 3. 验收

- [x] 机器人专项、官方 TG 回归、管理工作流通过；用官方 CrowdSec 1.8.1 JSON 告警验证 inspect 解析。
- [x] 完整 unittest、Bash/Python 语法、ShellCheck 和 diff-check；独立代码复审并处理有依据的问题。
- [x] 保存修复使用说明及隔离验收证据，明确未部署 VPS、未发送真实 TG 消息。

最终验收：机器人 26/26；全仓 607 项（603 通过、4 可选跳过），官方 1.8.1 JSON/SQLite/白名单集成通过；独立复审四项发现闭环。未部署 VPS 或调用真实 TG API。

# V2bX 落地常驻观察实施计划

> 执行方式：当前会话顺序实施，按 test-driven-development 和 verification-before-completion 验证，不创建子代理。

**Goal:** 提供三内核独立日志源的可安装、可检查、可停用观察服务。
**Architecture:** 复用 Observer，新增 daemon／service helper；shell 只分发入口。数据保持私有，无 CrowdSec 接入。
**Tech Stack:** Python 3、SQLite、Bash、systemd。
**Spec:** ../specs/2026-10-13-v2bx-landing-observer-design.md

## 约束

最多 16 个独立源；每源 1–1000000 事件；轮询 0.5–60 秒；无原始错误输出；不覆盖已有安装；停用保留数据库；不部署当前宿主机。

## Task 1: 常驻采集与生命周期

Files: `lib/crowdsec_v2bx_service.py`、`tests/test_v2bx_service.py`。
接口：`load_config(path)` 返回验证后的配置；`run(config, state)` 复用 Observer；`Manager(root, systemctl).install(config)`、`.status()`、`.disable()` 支持隔离 fixture。

- [x] 写真实文件生命周期和安装撤销测试，`python3 -m unittest discover -s tests -p test_v2bx_service.py -v` 确认缺少 helper 的失败。
- [x] 实现严格 JSON 校验、多源循环、SIGTERM、私有指标文件和固定失败码。
- [x] 实现固定文件安装、systemctl 验证、启动失败清理、只读状态、停用保留。
- [x] 跑专项；失败先定位；加入安全和生命周期边界测试。

## Task 2: CLI 与文档整合

Files: `lib/v2bx.sh`、`install-crowdsec-1panel.sh`、`docs/v2bx-guide.md`、`docs/cli-reference.md`、`docs/v2bx-deployment-acceptance.md`、`readme.md`。

- [x] 接入 `--install-v2bx-observer`、`--v2bx-observer-status`、`--disable-v2bx-observer`；安装使用 `V2BX_OBSERVER_CONFIG`。
- [x] 文档给出三内核配置、停用、容量满处理与混合日志限制；真实部署保持未验证。
- [x] 跑全仓 unittest、ShellCheck、Bash/Python 语法、Markdown 链接与 diff 检查，记录实际结果。

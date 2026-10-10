# AppSec Web Bouncer 安装实施计划

设计依据：[appsec-installation-design.md](appsec-installation-design.md)。按已有用户授权在本会话实施，保留网站和 WAF 配置，完成后提交源码。

- [x] 增加独立 `lib/crowdsec_web.py`：计划、受支持钩子合并、固定版本资源校验、状态和撤销操作；先复现缺失安装能力，再实现。
- [x] 增加 Bash 首次安装/撤销入口：容器选择、官方软件包分支、备份事务、独立账号和错误回滚；模拟用户流程测试。
- [x] 根据实际 Lua 能力与持久化 HTTP 入口判断科技lion Nginx、NPM、1Panel 和宿主机；已有接入流程保持兼容。
- [x] 使用真实 OpenResty/CrowdSec 在临时目录验证请求进入 AppSec，同时保留模拟原 WAF 的正常与阻断行为。
- [x] 独立代码审查并修复关键问题，更新 README 与验证记录；148 项回归、Bash 语法、ShellCheck 和真实运行验证通过。变更随本计划一起提交到远程。

实施中确认：原 Lua 脚本需使用 loadfile 后直接调用，避免 dofile 的协程边界；内部 Lua 模块单独命名以防依赖冲突；恢复运行失败保留账号/资源及恢复记录；重载成功后的删除通过 cleanup-pending 可重试。宿主机自动首次安装限定标准 Debian/Ubuntu 软件包且依赖已准备，保留原服务。

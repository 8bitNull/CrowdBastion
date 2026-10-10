# 使用流程与官方配置核查计划

目标：保留现有安装、WebUI、规则、定时更新、黑名单、Console、Telegram、诊断和卸载入口，让失败退出、取消操作和重复执行可预测，并补全 AppSec 的配置与验证流程。

实现范围：

1. `tests/test_workflows.py`：在临时目录中模拟系统命令和用户输入，先复现错误，再覆盖主菜单、各功能成功/失败、取消和重复操作。测试不得修改宿主机服务、防火墙、软件包或真实凭据。
2. `install-crowdsec-1panel.sh`：统一输入、依赖检查、状态码和服务校验；保留原有功能，禁止用成功提示掩盖失败；健康和残留检查保持只读。
3. `lib/crowdsec_config.py`：使用结构化 YAML 编辑，保留无关设置，创建备份并原子写入；配置失败时恢复。修改配置需要 Python 3 与 PyYAML，由核心安装流程安装。
4. AppSec：遵循官方 Nginx/OpenResty quickstart，安装两个官方集合、创建 loopback 数据源、配置已存在且支持 AppSec 的 Web Bouncer；容器环境显示接入要求，不自动改写容器 Nginx。
5. WebUI：复用本工具的有效凭据，拉取镜像成功后再更新；仅管理明确归属本工具的容器和凭据。
6. 卸载：显式确认、按实际安装的软件包处理，停止服务后清理明确归属的文件与防火墙资源；避免广泛进程匹配导致脚本杀死自身。
7. `readme.md` 与 `docs/verification.md`：记录官方参考、完整入口、验证命令、模拟覆盖与真实部署限制。

验证：Bash 语法、ShellCheck、Python 单元测试；下载官方发布的 CrowdSec 到临时目录，对生成的 YAML、Hub 集合、AppSec 和通知模板做真实引擎验证。真实主机安装及 Telegram 外部发送不在模拟验证中冒充通过。

官方依据：

- https://docs.crowdsec.net/docs/next/appsec/intro/
- https://docs.crowdsec.net/docs/next/appsec/quickstart/nginxopenresty/
- https://docs.crowdsec.net/docs/next/log_processor/data_sources/appsec/
- https://docs.crowdsec.net/docs/next/local_api/notification_plugins/http/
- https://docs.crowdsec.net/docs/next/local_api/profiles/intro/
- https://docs.crowdsec.net/u/bouncers/firewall/

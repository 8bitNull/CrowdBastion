# 2026-10-19 脚本复审与修复

按“修复、继续复审、发现问题再修复”的要求完成多轮检查。最后一轮独立复审未发现新的可复现实质问题；结论限于本次审查和测试覆盖的范围。改动保留在工作区，未提交或部署。

修复内容：

- V2bX 仅观察接入读取 `config.yaml` 与 `config.yaml.local` 的合并配置，在优先执行的 `profiles_path.local`（存在时）最前安装 guard。检测配置覆盖变化、优先 profiles 文件新增／移除及 guard 损坏；拒绝配置／profiles 符号链接，停用和安装失败时恢复对应文件。
- Telegram 手动封禁复用本机／管理员地址保护，覆盖接口地址、管理员解析白名单、显式 own/admin 记录及 IPv4-mapped 地址。接口或安全记录格式错误、非字符串 IP、断开的记录链接或检查依赖不可用时拒绝提交决策，错误响应不包含私有配置。
- 机器人安装同时部署安全模块，将其纳入归属检查、备份、回滚和卸载。独立复审通过 helper 复制失败和服务启动失败注入，核对配置、程序、unit、安全模块的内容及权限恢复。
- iptables/ipset 中转审计识别官方 `<blacklist>-<数字索引>` 集合，并使用实际存在的集合名追踪规则；保留旧版精确集合名支持，拒绝相似前缀和非数字后缀。审计结果仍只是规则引用证据，实际拦截需要独立验收。
- Machine 清理、WebUI 部署／卸载和防火墙 Bouncer 修复读取有效 `api.client.credentials_path`，保护实际宿主机身份并使用正确 LAPI 地址；路径无效、所需凭据不可读或配置覆盖链接断开时停止操作。
- 四处 Machine 删除调用增加 `--`，将名称按字面参数传递。官方 CrowdSec 1.8.1 的 Machine 删除命令没有 `--all` 选项，本次仅确认并修复名称与 CLI 选项的边界问题。
- 本地 TCP/UDP 回显测试改为实际回显就绪后再测量，消除固定等待 100 毫秒的启动竞态；最终工作负载的成功数、错误数和字节数断言保留。

验证：

- 新增问题均先观察失败复现再修复；Bouncer URL 回归同时核对 `.local` 新地址和 base 配置保留。
- 最后一轮独立复审的 15 项定向测试全部通过，覆盖凭据边界、原 WebUI 生命周期和实际 TCP/UDP 回显。
- 完整回归：**856 项，805 通过、51 跳过、0 失败**，耗时 199.287 秒。原始输出见 [unittest 日志](2026-10-19-script-review-unittest.txt)。
- Bash 语法检查覆盖 15 个文件；Python AST 解析覆盖 103 个文件；`git diff --check` 通过。

完整回归命令：

```bash
PATH="/tmp/crowdbastion-test-discovery:$PATH" \
PYTHONPATH=/tmp/crowdbastion-review-deps:tests:lib \
PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s tests -p 'test_*.py'
```

容器缺少 PyYAML，测试依赖仅安装在 `/tmp/crowdbastion-review-deps`。容器也缺少 `journalctl`，因此 PATH 前置一个仅返回 127 的临时可执行文件，满足三项既有 SSH 日志回退测试的程序发现条件；相关系统调用由测试 fixture 接管，没有执行真实日志采集。51 项可选集成测试仍被跳过。

本次没有操作真实 VPS、systemd 服务、CrowdSec 决策、防火墙或 Telegram API；真实部署和生产拦截仍须实机验收。工作区原有权限变更保留。

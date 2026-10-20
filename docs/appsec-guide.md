# AppSec 与 Web Bouncer 接入参考

[返回 README](../readme.md) · [使用说明](usage-guide.md) · [命令参考](cli-reference.md)

首次操作按使用说明完成安装；本页说明环境适配、Docker 网络、验证和撤销条件。日志检测、Firewall Bouncer 与 AppSec 在线请求检查需要分别接入和验证。

## 目录

- [配置 AppSec](#配置-appsec)
- [Web Bouncer 与环境适配](#web-bouncer-与环境适配)
- [Docker 网络与端点登记](#docker-网络与端点登记)
- [验证网站阻断](#验证网站阻断)
- [正文与故障策略](#正文与故障策略)
- [停用与撤销](#停用与撤销)

日志检测读取访问日志、识别行为并形成决策，由 Bouncer 执行相应阻断。安装 `http-cve`、`base-http-scenarios` 等日志集合不会自动建立在线请求检查链路。

根据 [官方 AppSec 介绍](https://docs.crowdsec.net/docs/next/appsec/intro/) 和 [Nginx/OpenResty quickstart](https://docs.crowdsec.net/docs/next/appsec/quickstart/nginxopenresty/)，AppSec 需要三个部分：

1. 官方集合 `crowdsecurity/appsec-virtual-patching` 和 `crowdsecurity/appsec-generic-rules`。
2. 启用 `source: appsec` 数据源，并重启 CrowdSec。
3. 已安装、注册并在网站中启用的 AppSec 兼容 Web Bouncer，将 HTTP 请求转发给 AppSec。

## 配置 AppSec

菜单 `1 → 2 → 1` 或 `--install-appsec` 安装集合，并创建：

```yaml
source: appsec
listen_addr: 127.0.0.1:7422
appsec_configs:
  - crowdsecurity/appsec-default
labels:
  type: appsec
```

配置写入实际启用的 `crowdsec_service.acquisition_dir`（读取 `config.yaml` 与 `.local`），校验并重启后检查 `127.0.0.1:7422` 是否存在监听。监听未出现时返回失败并提示查看日志；存在监听也只代表引擎连接入口可用，网站接入还需单独验证。已有外部 AppSec 数据源时不会创建重复监听。

## Web Bouncer 与环境适配

接入菜单显示已安装且命令可用的宿主机 Bouncer，并提供 `3：接入已有 Docker Web Bouncer`、`4：首次安装 Web Bouncer`。首次安装也可单独执行 `sudo bash crowdbastion.sh --install-web-bouncer`，前提是 AppSec 已监听。Docker 已有接入会核对 host 或已登记的私有 bridge 网络、有效 CrowdSec 请求调用和真实 bind/volume 配置挂载，备份后修改 `APPSEC_URL`、执行 `nginx -t` 并重载；重复接入不变时跳过重载。

首次安装生成的持久化配置也支持该入口。

| 环境 | 首次安装适配与前提 |
| --- | --- |
| 1Panel OpenResty | 支持已确认的 `1pwaf/data/conf/waf.conf` 布局及 host 或已登记私有 bridge 网络；从实际 Mounts 定位配置，不依赖固定宿主机目录 |
| 科技lion LDNMP | 默认无 Lua 的 Nginx 保留日志/Firewall 路径；兼容 Lua、持久化 HTTP conf.d、host 或已登记私有 bridge 端点时可安装 Web Bouncer |
| Nginx Proxy Manager | 检测实际 Lua 能力，使用持久化 `/data/nginx/custom/http_top.conf`；支持 host 或已登记的私有 bridge；生成站点配置不作为修改入口，覆盖钩子或 satisfy any 时停止 |
| 宿主机 Nginx/OpenResty | Debian/Ubuntu 标准软件包环境使用官方 Bouncer 包；要求 CrowdSec apt 候选版本和已准备好的依赖，安装计划涉及其他软件包时停止，保留现有服务 |

容器安装使用 SHA256 校验的官方 OpenResty Bouncer `v1.2.3` 和 lua-resty-http `v0.17.1`。库、模板、私有配置及钩子保存在同一持久化挂载中，并注册独立 Bouncer 账号。1Panel 原初始化、请求、worker 脚本先执行，再调用 CrowdSec，保留日志钩子、共享字典和原 Lua 搜索路径。使用 `loadfile` 后直接调用 Lua 函数以兼容 WAF 的 `ngx.exit`/协程行为；CrowdSec 及 HTTP 依赖单独命名，避免替换原 WAF 的 `resty.http`。

## Docker 网络与端点登记

Firewall Bouncer 支持 IP 封禁，但[不支持 AppSec HTTP 转发](https://docs.crowdsec.net/u/bouncers/firewall/)。Docker host 网络可以连接宿主机 loopback；bridge 的 loopback 指向容器自身。bridge 接入先用 `--configure-docker-endpoints`（菜单 `1 → 4`）登记已经准备好的私有 IPv4 网关 LAPI/AppSec，要求匹配实际 NetworkID/IPAM、精确私有监听、容器可达及 LAPI 密钥认证。

端点监听、转发和防火墙放行由部署者准备，脚本保持核心 loopback，不安装转发器、更换网络或发布端口。配置连通性与真实网站阻断分别核验。

AppSec 容器诊断读取对应容器的私有端点登记，并重新核对当前 bridge NetworkID/IPAM 和两个端点的宿主机精确监听。未登记时给出配置入口；已登记但网络变化、监听缺失或登记损坏时报告核验失败，AppSec 状态检查返回非零。匹配成功只证明网络及监听条件，容器连通性、LAPI 认证与实际网站防护仍需分别验证；诊断不发送请求或修改部署配置。

Docker internal bridge 没有默认网关时，容器检查结果中的 `Gateway` 可以为空；此时仅在实际网络为 internal bridge、NetworkID 匹配、端点等于 IPAM 网关且容器 IP 属于同一 IPAM 子网时接受登记。宿主机精确监听、容器连通性和认证要求保持一致。

未知 Lua 钩子、子级请求钩子覆盖、只读/非持久化挂载以及网络不满足前提时会停止安装。安装失败恢复原配置；确认原运行配置重载成功后才移除资源并注销新账号。恢复重载失败则保留资源和账号，记录 `recovery-required` 供后续恢复，避免删除仍被运行中 worker 使用的依赖。`--appsec-status` 同时检查数据源、监听、容器网络及请求处理组件。

## 验证网站阻断

验证方式：菜单 `1 → 2 → 4` 或 `--verify-appsec` 输入自己管理的网站根地址。明确确认后发送带唯一标识的 GET `/.env` 请求，读取 HTTP 状态及 AppSec 指标，输出通过（返回 0）、失败（1）或无法判断（2）。通过条件包括 403、Processed/Blocked 增量和 `crowdsecurity/vpatch-env-access` 命中；累计增量可能来自其他请求，仍需按唯一标识关联日志。优先从另一台设备验证，单独一个 403 不能证明 AppSec 生效。

`--verify-appsec` 会在发送请求前提示 Self-Report 风险并要求确认；取消或 EOF 不发送验证请求。该命令从当前主机访问 `/.env`，即使使用公网域名，也可能绕回本机并产生针对本机地址的告警。推荐从另一台设备验证；定时健康检查使用正常页面或专用 `/healthz`。验证入口不删除历史告警、封禁决策或修改白名单。

## 正文与故障策略

AppSec 正文/故障策略可用 `--appsec-policy` 或菜单 `1 → 2 → 5` 检查并明确设置。支持标准宿主机 Bouncer，或输入 `docker` 选择持久化容器配置；不修改原 `APPSEC_URL`。`APPSEC_DROP_UNREADABLE_BODY=true` 会拒绝无法分析的正文，`APPSEC_FAILURE_ACTION=deny` 会按上游故障策略拒绝请求，需先评估业务。

官方 OpenResty Bouncer 1.2.3 的 AppSec 故障拒绝分支原先可能返回 HTTP 200。本项目生成的原生容器 Bouncer 已修正为 403。已有本工具托管容器可重新运行 `--install-web-bouncer`，选择原容器，升级受管 Lua、策略解析器及执行记录钩子；保留原账号、凭据和策略，更新资源摘要并校验重载，失败回滚。非托管安装需单独核对。故障测试还应检查业务后端是否收到请求。

本项目新装的原生容器 Bouncer 明确设置 `APPSEC_FAILURE_ACTION=deny`、`LAPI_FAILURE_ACTION=deny`，正文不可读策略仍为 `false`。已有安装升级时保留原配置；旧配置未指定 LAPI 策略时，模块仍以 `passthrough` 保持兼容。`LAPI_FAILURE_ACTION` 只控制 `MODE=live` 下的决策查询错误；设为 `deny` 时立即返回 403，后续 AppSec 或验证码逻辑不能覆盖该拒绝。

`--appsec-policy` 对已验证能力的托管容器分别提供 AppSec、LAPI 故障策略选择；LAPI 留空保留原值。策略修改和受管模块升级会核对运行中的 master 与 worker：重载后最多等待 10 秒，以连续两次采样确认新 worker 存活，并要求本次 master 重载日志中的完整 worker 启动记录与其对应，再检查托管请求钩子。仅配置测试通过、重载命令成功或 worker PID 更替仍不足以证明新策略生效：Lua 初始化失败后，master 可能使用旧配置重生崩溃的 worker。验证失败或提交前收到 INT/TERM 时恢复本次配置及安装记录，并检查恢复重载；恢复未确认时保留备份并明确提示人工核对。宿主机官方包、其他来源或尚未升级的模块不会被假定支持 LAPI 策略，工具会明确提示；应先完成受管模块升级，再选择需要的策略。

该重载验证要求主配置文件直接声明普通文件类型的 `error_log /绝对路径/error.log notice;`（`info`、`debug` 级别也可），且该日志已由运行中的 master 打开并可由管理脚本读取。容器通过实际 master 的文件描述符及 PID 命名空间核对。请先按现有部署方式加载日志设置，再运行策略修改或托管模块升级；工具不会自动改动网站日志配置。仅写入 stderr 管道、syslog、隐式默认日志、相对路径、仅在 include 文件声明或无法读取日志时，自动重载验证会停止并提示人工核对；stderr 已重定向至普通文件时可验证。日志轮转、截断、覆盖或本次新增记录超过 1 MiB 导致证据不完整时，也返回未确认，不会用旧日志判定成功。

容器应分别使用自己的错误日志文件。若另一个进程持有同一日志文件，且在其命名空间中显示的 PID 与目标 master 相同（例如两个容器的 master 都是 PID 1），记录归属无法区分，工具会拒绝自动验证；无法检查相关 `/proc` 元数据时同样停止。

需要安全优先时，应明确选择 `APPSEC_FAILURE_ACTION=deny` 和 `LAPI_FAILURE_ACTION=deny`：相应检查失败会拒绝正常访客，直至服务恢复。有效的决策缓存仍按 `CACHE_EXPIRATION` 到期，例如配置为 1 秒时，已有允许缓存可在其剩余有效期内继续使用；这不是瞬时探测服务故障的开关。`stream` 模式的后台同步故障不受新增 LAPI 策略控制。部署前应核对 `.local` 覆盖、有效请求钩子和两端点实际密钥认证，部署后验证受保护的 HTTPS 页面；HTTP 跳转成功不足以证明请求检查正常。

已有 Web Bouncer 接入、停用和状态检查会检查 `.local` 覆盖、重复 AppSec 键以及非规范 `APPSEC_URL` 赋值，遇到未明确解释的覆盖会停止；容器内无法检查的 `.local` 也不会当成不存在。请先核对配置并规范为 `APPSEC_URL=...`，不要为了通过检查直接删掉已有覆盖。

## 停用与撤销

停用入口只处理本工具数据源和记录过的 Web Bouncer 接入，并恢复接入前的 `APPSEC_URL`；外部配置和 AppSec 集合保留。管理的 Docker 接入按容器名称与实际持久化挂载核对，支持容器重建后安全恢复；手工改过地址、挂载或网络时先停止并要求核对。失败时恢复配置并重载已变更的服务/容器。未由本工具接入的容器和外部代理需要自行同步停用转发。

菜单 `1 → 2 → 7` 或 `--remove-web-bouncer` 撤销本工具首次安装的原生容器 Bouncer：核对挂载和文件内容，先恢复原网站/WAF 配置并重载，再注销账号、清理资源。清理失败保留 `cleanup-pending` 记录，可重复执行；已经删除的账号/资源不会阻止重试。手工修改过的配置或资源会保留并要求核对。宿主机官方软件包的撤销请按[官方 Nginx](https://docs.crowdsec.net/u/bouncers/nginx/)或 [OpenResty](https://docs.crowdsec.net/u/bouncers/openresty/)文档进行，先确认网站正常再卸载核心。

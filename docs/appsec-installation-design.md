# AppSec Web Bouncer 首次安装适配

用户目标：修复 1Panel OpenResty 的首次接入，并将科技lion LDNMP、NPM 与宿主机 Nginx 纳入同一部署判断流程。

## 部署与能力

- 1Panel：已确认的 `1pwaf/data/conf/waf.conf` 通过 Docker Mounts 映射到宿主机。使用固定版本官方 CrowdSec Lua 库和 lua-resty-http。只合并已知的三条 file 钩子，保留 shared dictionaries、日志钩子和原 Lua 路径。资源放在同一持久化目录中，容器重建无需重新复制软件。
- Lua 可用的 NPM/其他 Nginx 容器：从有效 `nginx -T` 中选择 HTTP 层持久化配置入口。NPM 使用 `/data/nginx/custom/http_top.conf`；普通 Nginx 使用已启用的 `/etc/nginx/conf.d/*.conf`。存在未知 Lua 钩子时停止，保留现有逻辑。
- LDNMP：上游默认 `nginx:alpine`。检测运行时 Lua 模块，缺失时提供兼容组件前提，不修改镜像或安装 ABI 不匹配的模块。
- 宿主机 Nginx/OpenResty：提供官方软件包首次安装，安装前检查配置与现有 Lua 钩子；有旧 Bouncer 时沿用接入，不重装。
- Docker 自动安装要求 host 网络。bridge 部署需要先建立私有网络可达的 LAPI/AppSec 地址；保留 loopback 监听，不自动将端口绑定公网。

## 修改与生命周期

安装前形成计划，验证有效配置、挂载可写性、已有文件和脚本支持范围。下载固定发布并核验 SHA256，注册独立 Bouncer；密钥写入权限受限的配置文件，不输出或放入命令参数。修改前备份原配置和状态，新生成资源由独立记录管理。完成写入后执行 `nginx -t` 和重载，失败回滚；确认原运行配置恢复后撤销本次新账号。

安装资源和原钩子单独记录；已有的 AppSec Docker 地址恢复机制继续负责停用 AppSec。首次安装入口重复执行时复用资源/账号。撤销时核对配置和资源未被手工改动、容器名称/挂载相符，再恢复原配置、校验并重载，最后注销本工具账号和资源。恢复配置/重载失败回滚；重载成功后的清理失败进入可重试的 `cleanup-pending`，不会重新启用已注销密钥。安装失败后原运行配置重载失败则保留资源与密钥，记录 `recovery-required`，以后通过撤销入口重载原配置后清理。

原 WAF 先调用，使用 `assert(loadfile(path))()` 保留 Lua 协程/ngx.exit 行为；CrowdSec 代码和 resty-http 放入独立模块命名空间，改写其内部 require 引用，保留原 WAF 的依赖解析。NPM 的 `satisfy any` 和未知子级 Lua 钩子在修改前拒绝。

## 验证

先建立失败回归，再实现：原 1Panel WAF 的四阶段保留、通用/NPM HTTP 入口、无 Lua/未知钩子/bridge/非持久化挂载拒绝、取消、账号失败、下载校验失败、重载回滚、重复安装及撤销。用隔离的真实 OpenResty 和官方 CrowdSec 验证正常请求、AppSec 阻断以及原 WAF 阻断同时有效。生产 1Panel 私有 WAF 的行为仍需目标服务器核验。

#!/usr/bin/env bash
# Sourced by the manager. Package installation is deliberately limited to
# standard host runtimes whose dependencies are already installed.

host_web_config() {
    python3 - "$@" <<'PY'
import fnmatch
import re
import sys
from pathlib import Path

action, effective, main, snippet = sys.argv[1:]
text = Path(effective).read_text()

def tokens(source):
    # Preserve quoted values; ignore comments and retain brace positions.
    return [(m.group(), m.end()) for m in re.finditer(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\n]*|[{};]|[^\s{};#]+', source)
        if not m.group().startswith('#')]

def http_includes(source):
    parts = tokens(source)
    stack, includes, http_positions = [], [], []
    for i, (token, end) in enumerate(parts):
        if token == '{':
            previous = parts[i-1][0] if i else ''
            if previous == 'http' and not stack:
                http_positions.append(end)
            stack.append(previous)
        elif token == '}':
            if not stack:
                raise ValueError('HTTP 配置括号不匹配')
            stack.pop()
        elif token == 'include' and stack == ['http'] and i+2 < len(parts) and parts[i+2][0] == ';':
            includes.append(parts[i+1][0].strip('\"\''))
    if stack:
        raise ValueError('HTTP 配置括号不匹配')
    return includes, http_positions

try:
    source = Path(main).read_text()
    includes, positions = http_includes(source)
    if len(positions) != 1:
        raise ValueError('仅支持主配置含单一 HTTP 块的标准安装')
    if action == 'preflight':
        if '# configuration file '+main+':' not in text:
            raise ValueError('有效配置未使用标准主配置路径，请手动安装')
        directives = [token for token, _ in tokens(text)]
        if any(re.fullmatch(r'\w+_by_lua(?:_file|_block)?', t) for t in directives):
            raise ValueError('发现已有 Lua 钩子；请手动评估现有 WAF，未覆盖配置')
        if 'lua_package_path' in directives or 'crowdsec_cache' in directives:
            raise ValueError('发现已有 Lua 路径或 CrowdSec 缓存，未覆盖配置')
        if re.search(r'\bsatisfy\s+any\s*;', text):
            raise ValueError('satisfy any 可能绕过请求检查，请先评估现有配置')
        if main.endswith('/etc/nginx/nginx.conf') and not any(fnmatch.fnmatchcase(snippet, p) for p in includes):
            raise ValueError('Nginx 主配置必须在 HTTP 块 include 标准 conf.d/*.conf')
    elif action == 'include':
        if not any(fnmatch.fnmatchcase(snippet, p) for p in includes):
            pos = positions[0]
            # Keep all original content; only add the official include.
            Path(main).write_text(source[:pos]+'\n    include '+snippet+';'+source[pos:])
    elif action == 'loaded':
        if '# configuration file '+snippet+':' not in text:
            raise ValueError('官方 Bouncer 配置未进入有效配置，网站尚未接入')
        if not re.search(r'\baccess_by_lua(?:_block|_file)?\b', text):
            raise ValueError('有效配置缺少 Web Bouncer 请求钩子')
    else:
        raise ValueError('未知宿主机配置检查')
except (OSError, ValueError) as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
PY
}

host_web_rollback_package() {
    local service="$1" snapshot="$2" package="$3" after name result=0
    if ! restore_config_change || ! "$service" -t || ! systemctl reload "$service"; then
        log_err '无法确认旧 Web 配置已恢复并重新加载；保留本次新增 Bouncer 账号和软件包资源，避免仍在运行的新配置失去凭据。'
        log_warn "请检查修改前备份及仅 root 可读的安装日志，手动修复配置，再执行 ${service} -t 和 systemctl reload ${service}；确认旧配置已运行后再清理本次新增账号。"
        return 1
    fi
    after=$(mktemp) || return 1
    if cscli bouncers list -o json > "$after"; then
        local added
        added=$(python3 - "$snapshot" "$after" "$package" <<'PY'
import json
import re
import sys
from pathlib import Path
before, after, package = sys.argv[1:]
def names(path):
    data = json.loads(Path(path).read_text())
    if not isinstance(data, list) or any(not isinstance(x, dict) or not isinstance(x.get('name'), str) for x in data):
        raise ValueError('Bouncer 列表结构无效')
    return {x['name'] for x in data}
try:
    for name in sorted(names(after)-names(before)):
        if re.fullmatch(re.escape(package)+r'-\d+', name):
            print(name)
except (OSError, ValueError) as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
PY
        ) || result=1
        while IFS= read -r name; do
            [[ -z "$name" ]] || cscli bouncers delete "$name" || result=1
        done <<< "$added"
    else
        log_warn '无法获取新增 Bouncer 列表；请手动检查本次包安装生成的账号。'
        result=1
    fi
    rm -f -- "$after"
    log_warn '已尝试恢复覆盖的配置。已安装的软件包及 Lua 依赖保留；请检查安装日志后再手动修复，不会卸载现有 Web 服务。'
    return "$result"
}

install_host_web_bouncer() {
    local service="${1:-}" package file main snippet effective version candidate plan snapshot install_log status start_command
    case "$service" in
        nginx)
            main=/etc/nginx/nginx.conf
            snippet=/etc/nginx/conf.d/crowdsec_nginx.conf ;;
        openresty)
            main=/usr/local/openresty/nginx/conf/nginx.conf
            snippet=/usr/local/openresty/nginx/conf/conf.d/crowdsec_openresty.conf ;;
        *) log_err '请选择宿主机 nginx 或 openresty。'; return 1 ;;
    esac
    package="crowdsec-${service}-bouncer"
    file="${CS_DIR}/bouncers/${package}.conf"
    require_core && require_yaml && require_commands "$service" python3 ss || return 1
    if ! declare -F appsec_default_listener_ready >/dev/null || ! appsec_default_listener_ready; then
        log_err '无法确认 AppSec 在 127.0.0.1:7422 监听；请先安装并验证 AppSec，再接入宿主机 Web Bouncer。'
        return 1
    fi
    # A .local override wins over the main file, so blindly changing APPSEC_URL
    # in the latter would report an ineffective integration.
    if [[ -f "${file}.local" ]] && grep -Eq '^[[:space:]]*APPSEC_URL[[:space:]]*=' "${file}.local"; then
        log_err "${file}.local 覆盖 APPSEC_URL，请先手动评估；未覆盖配置。"
        return 1
    fi
    if [[ -f "$file" ]]; then
        if [[ -n "${APPSEC_DOCKER_LINKS:-}" && -f "$APPSEC_DOCKER_LINKS" ]] && yaml_tool docker-link-owned "$file" "$APPSEC_DOCKER_LINKS" >/dev/null 2>&1; then
            log_err '该配置已有容器接入记录，请先停用原接入。'
            return 1
        fi
        confirm "接入已有宿主机 ${service} Web Bouncer？" || return 0
        begin_config_change "$file" "$APPSEC_LINKS" || return 1
        if ! yaml_tool link-web-bouncer "$file" "$APPSEC_LINKS" || ! "$service" -t || ! systemctl reload "$service"; then
            restore_config_change || return 1
            if "$service" -t; then systemctl reload "$service" || true; fi
            log_err 'Web Bouncer 接入失败，已恢复修改前配置。'
            return 1
        fi
        log_succ '已有 Web Bouncer 已配置 APPSEC_URL；请运行 AppSec 验证确认真实请求。'
        return 0
    fi
    case "${OS_ID:-linux}" in
        debian|ubuntu) ;;
        *) log_err '首次宿主机安装仅支持 Debian/Ubuntu 官方软件包；其他系统请按官方文档手动安装。'; return 1 ;;
    esac
    require_commands apt-cache apt-get dpkg-query cscli systemctl || return 1
    [[ -f "$main" && ! -L "$main" ]] || { log_err '仅支持具有常规主配置文件的宿主机安装。'; return 1; }
    [[ ! -e "$snippet" && ! -L "$snippet" ]] || { log_err "已有 ${snippet}，请手动核对；未覆盖文件。"; return 1; }
    status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) || status=''
    if [[ "$status" == *'installed'* ]]; then
        log_err 'Web Bouncer 软件包已安装但配置缺失，请先手动修复；不会重装或覆盖账号。'
        return 1
    fi
    status=$(dpkg-query -W -f='${Status}' "$service" 2>/dev/null) || status=''
    [[ "$status" == 'install ok installed' ]] || { log_err '只支持已安装官方发行版 Web 服务的软件包环境。'; return 1; }
    version=$("$service" -V 2>&1) || return 1
    if [[ "$version" != *"--conf-path=${main}"* ]]; then
        if [[ "$service" != openresty || "$version" == *'--conf-path='* || "$version" != *'--prefix=/usr/local/openresty/nginx'* ]]; then
            log_err 'Web 服务使用自定义配置路径，请手动安装 Bouncer。'
            return 1
        fi
    fi
    systemctl is-active --quiet "$service" || { log_err '请先确认对应宿主机 Web 服务正在运行。'; return 1; }
    start_command=$(systemctl show --property=ExecStart --value "$service") || return 1
    if [[ -z "$start_command" || "$start_command" =~ (^|[[:space:]])-[cp]([^[:space:]]*|[[:space:]]) ]]; then
        log_err 'Web 服务启动参数含自定义配置/前缀，或无法确认启动命令；请手动安装。'
        return 1
    fi
    effective=$(mktemp) || return 1
    if ! "$service" -T > "$effective" 2>/dev/null || ! host_web_config preflight "$effective" "$main" "$snippet"; then
        rm -f -- "$effective"
        log_err '首次安装预检失败，现有 Web 配置未修改。'
        return 1
    fi
    candidate=$(LC_ALL=C apt-cache policy "$package" | awk '$1 == "Candidate:" { print $2; exit }')
    if [[ -z "$candidate" || "$candidate" == '(none)' ]]; then
        rm -f -- "$effective"
        log_err "没有 ${package} 的 apt 候选版本；请先按官方文档配置 CrowdSec 软件源。"
        return 1
    fi
    plan=$(LC_ALL=C apt-get --simulate --no-upgrade --no-remove --no-install-recommends install "${package}=${candidate}" 2>&1) || {
        rm -f -- "$effective"; log_err '软件包安装计划失败；未修改配置。'; return 1;
    }
    if ! printf '%s\n' "$plan" | awk -v package="$package" '
        /^Remv / { bad=1 }
        /^Inst / { if ($2 != package) bad=1; else found=1 }
        /^Conf / { if ($2 != package) bad=1 }
        END { exit (bad || !found) }
    '; then
        rm -f -- "$effective"
        log_err '安装计划会修改其他软件包；请先按官方文档手动准备依赖，避免升级或替换现有 Web 服务。'
        return 1
    fi
    snapshot=$(mktemp) || { rm -f -- "$effective"; return 1; }
    if ! cscli bouncers list -o json > "$snapshot" || ! python3 - "$snapshot" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
assert isinstance(data, list) and all(isinstance(x, dict) and isinstance(x.get('name'), str) for x in data)
PY
    then
        rm -f -- "$effective" "$snapshot"
        log_err '无法安全读取现有 Bouncer 账号，未开始安装。'
        return 1
    fi
    if ! confirm "首次安装官方 ${package} ${candidate} 并接入 AppSec？现有 Lua/WAF 配置必须通过预检。"; then
        rm -f -- "$effective" "$snapshot"
        return 0
    fi
    if ! begin_config_change "$main" "$snippet" "$file" "${file}.local" "$APPSEC_LINKS"; then
        rm -f -- "$effective" "$snapshot"
        return 1
    fi
    install_log=$(mktemp /var/backups/crowdsec-1key/host-install.XXXXXXXX.log) || { rm -f -- "$effective" "$snapshot"; return 1; }
    chmod 600 "$install_log" || { rm -f -- "$effective" "$snapshot" "$install_log"; return 1; }
    log_info "软件包安装日志（可能含密钥，仅 root 可读）: ${install_log}"
    if ! DEBIAN_FRONTEND=noninteractive apt-get -y --no-upgrade --no-remove --no-install-recommends install "${package}=${candidate}" > "$install_log" 2>&1 ||
       [[ ! -f "$file" || ! -f "$snippet" ]] ||
       ! grep -Eq '^API_KEY=[^<[:space:]][^[:space:]]*$' "$file" ||
       ! host_web_config include "$effective" "$main" "$snippet" ||
       ! yaml_tool link-web-bouncer "$file" "$APPSEC_LINKS" ||
       ! "$service" -T > "$effective" 2>/dev/null ||
       ! host_web_config loaded "$effective" "$main" "$snippet" ||
       ! "$service" -t || ! systemctl reload "$service"; then
        host_web_rollback_package "$service" "$snapshot" "$package" || log_err '部分回滚操作失败，请立即检查 Web 服务与安装日志。'
        rm -f -- "$effective" "$snapshot"
        log_err '宿主机 Web Bouncer 安装或接入失败；网站尚未验证。'
        return 1
    fi
    rm -f -- "$effective" "$snapshot"
    log_succ "${package} 已安装并配置 APPSEC_URL；请运行 AppSec 验证确认真实网站请求被处理。"
}

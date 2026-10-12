#!/usr/bin/env bash

transport_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_transport.py" "$@"; }

transport_inspect() {
    local container="$1" work="$2" networks
    docker inspect "$container" > "$work/inspection" || return 1
    networks=$(python3 - "$work/inspection" <<'PY'
import json
from pathlib import Path
import sys
data = json.loads(Path(sys.argv[1]).read_text())[0]
for network in data['NetworkSettings']['Networks'].values():
    identity = network['NetworkID']
    if len(identity) != 64 or any(value not in '0123456789abcdef' for value in identity):
        raise ValueError('Docker network ID 无效')
    print(identity)
PY
    ) || return 1
    local identities=()
    mapfile -t identities <<< "$networks"
    [[ -n "$networks" ]] || return 1
    docker network inspect "${identities[@]}" > "$work/networks" || return 1
}

transport_current() {
    local container="$1" name="$2" work="$3"
    if ! web_tool get "$DOCKER_ENDPOINTS" "$name" >/dev/null 2>&1; then
        log_err 'bridge 接入需先运行 --configure-docker-endpoints 登记可达的私有端点。'
        return 1
    fi
    transport_inspect "$container" "$work" &&
        transport_tool check "$DOCKER_ENDPOINTS" "$name" "$work/inspection" "$work/networks" "$work/transport" || return 1
    ss -H -lnt > "$work/listeners" || return 1
    transport_tool listeners "$work/transport" "$work/listeners"
}

diagnose_docker_transport() (
    local container="$1" name="$2" network="$3" work details status registered_api_url registered_appsec_url
    if details=$(transport_tool registered "$DOCKER_ENDPOINTS" "$name" 2>&1); then
        :
    else
        status=$?
        if [[ "$status" == 2 ]]; then
            log_warn "${network} 网络：未登记私有端点；容器内 loopback 不指向宿主机，请先准备私有网关端点并运行 --configure-docker-endpoints。"
            return 0
        fi
        log_warn "${network} 网络：私有端点登记无法读取，未完成核验。${details}"
        return 1
    fi
    require_commands ss || return 1
    work=$(mktemp -d) || return 1
    trap 'rm -rf -- "$work"' EXIT
    if ! details=$(transport_current "$container" "$name" "$work" 2>&1); then
        log_warn "${network} 网络：已登记私有端点核验失败。${details}"
        return 1
    fi
    registered_api_url=$(web_tool get "$work/transport" api_url) || return 1
    registered_appsec_url=$(web_tool get "$work/transport" appsec_url) || return 1
    log_info "${network} 网络：已登记私有端点，当前 bridge 网络与宿主机精确监听匹配；LAPI=${registered_api_url}，AppSec=${registered_appsec_url}。"
    log_info '容器连通性和实际防护仍需请求验证。'
)

configure_docker_endpoints() (
    require_core && require_commands docker ss || return 1
    local NATIVE_ID NATIVE_NAME selected api_url appsec_url work code
    select_native_container
    selected=$?
    [[ "$selected" == 2 ]] && return 0
    [[ "$selected" == 0 ]] || return 1
    work=$(mktemp -d) || return 1
    trap 'rm -rf -- "$work"' EXIT
    transport_inspect "$NATIVE_ID" "$work" || return 1
    log_info '仅登记已经准备好的私有 LAPI/AppSec；保持核心 loopback、容器镜像和网络配置。'
    log_info '端点需精确绑定当前容器连接的私有 bridge 网关；可使用自行管理的网关 TCP 转发。'
    prompt api_url '私有 LAPI 地址（例如 http://172.18.0.1:18080；留空取消）: ' || return 0
    [[ -n "$api_url" ]] || return 0
    prompt appsec_url '同一私有网关的 AppSec 地址（例如 http://172.18.0.1:17422）: ' || return 0
    [[ -n "$appsec_url" ]] || return 0
    transport_tool plan "$work/inspection" "$work/networks" "$api_url" "$appsec_url" "$work/transport" || return 1
    api_url=$(web_tool get "$work/transport" api_url) || return 1
    appsec_url=$(web_tool get "$work/transport" appsec_url) || return 1
    ss -H -lnt > "$work/listeners" || return 1
    transport_tool listeners "$work/transport" "$work/listeners" || return 1
    code=$(docker exec "$NATIVE_ID" curl -sS --noproxy '*' --connect-timeout 3 --max-time 8 -o /dev/null -w '%{http_code}' "${api_url%/}/v1/decisions") || return 1
    [[ "$code" == 401 || "$code" == 403 ]] || { log_err '私有 LAPI 未返回预期的未认证响应。'; return 1; }
    code=$(docker exec "$NATIVE_ID" curl -sS --noproxy '*' --connect-timeout 3 --max-time 8 -o /dev/null -w '%{http_code}' "${appsec_url%/}/") || return 1
    [[ "$code" =~ ^[234][0-9][0-9]$ ]] || { log_err '容器无法取得私有 AppSec HTTP 响应。'; return 1; }
    confirm '登记上述私有端点？此检查只证明连通性，实际 AppSec 防护仍需网站请求验证。' || return 0
    transport_tool record "$DOCKER_ENDPOINTS" "$NATIVE_NAME" "$work/transport" || return 1
    log_succ '私有端点已登记；Lua 能力合适的容器可继续安装 Web Bouncer。'
)

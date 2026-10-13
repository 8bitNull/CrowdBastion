#!/usr/bin/env bash

maintenance_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_maintenance.py" "$@"; }

locked_operation() (
    if [[ "${MAINTENANCE_LOCK_HELD:-}" != true ]]; then
        require_commands flock || return 1
        mkdir -p "$(dirname "$MAINTENANCE_LOCK")" || return 1
        exec 9> "$MAINTENANCE_LOCK" || return 1
        if ! flock -n 9; then log_warn '另一个 CrowdSec 管理操作正在执行，请稍后重试。'; return 75; fi
    fi
    trap hub_workflow_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    MAINTENANCE_LOCK_HELD=true "$@"
)

config_change_needed() {
    [[ "${CORE_RULES_CHANGED:-false}" == true ]] && return 0
    local index path copy
    for index in "${!BACKUP_PATHS[@]}"; do
        path="${BACKUP_PATHS[$index]}" copy="${BACKUP_COPIES[$index]}"
        [[ "$path" == "$WEBUI_DIR/"* ]] && continue
        if [[ -f "${copy}.absent" ]]; then
            [[ -e "$path" || -L "$path" ]] && return 0
        elif [[ -L "$copy" || -L "$path" ]]; then
            [[ -L "$copy" && -L "$path" && "$(readlink "$copy")" == "$(readlink "$path")" ]] || return 0
        elif ! cmp -s -- "$copy" "$path"; then
            return 0
        fi
    done
    return 1
}

reload_core_rules() {
    crowdsec -t || { hub_abort no-load; return 1; }
    if [[ "${CORE_RULES_CHANGED:-false}" == true ]]; then
        CORE_CONFIG_LOADING=reload
        if ! systemctl reload crowdsec || ! systemctl is-active --quiet crowdsec; then hub_abort; return 1; fi
    else
        systemctl is-active --quiet crowdsec || { hub_abort no-load; log_err '核心未运行，请先恢复服务。'; return 1; }
        log_info '规则未变化，跳过重载。'
    fi
    hub_finalize || { hub_abort; return 1; }
    # Read by the shared Hub workflow exit handler.
    # shellcheck disable=SC2034
    CORE_CONFIG_LOADING=''
    CORE_RULES_CHANGED=false
}

run_hub_update() {
    hub_maintenance update
}

check_log_inventory() (
    require_core && require_yaml || return 1
    prepare_log_repair || return 1
    trap cleanup_log_repair EXIT
    maintenance_tool audit-acquisition "$CS_DIR" || return 1
    if [[ "$LOG_REPAIR_COUNT" != 0 ]]; then
        log_warn "发现 ${LOG_REPAIR_COUNT} 项待调整采集；运行 --repair-logs 可统一修复。"
        return 2
    fi
    log_info '当前发现的日志均已有采集入口；此检查未修改配置。'
)

webui_ready() (
    require_commands docker curl || return 1
    local port="$1" attempt status response attempts="${2:-30}"
    response=$(mktemp) || return 1
    trap 'rm -f -- "$response"' EXIT
    for ((attempt=0; attempt<attempts; attempt++)); do
        status=$(docker inspect --format '{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' crowdsec-web-ui 2>/dev/null) || status='false none'
        if [[ "$status" == 'true healthy' ]]; then
            if curl -fsS --connect-timeout 2 --max-time 4 "http://127.0.0.1:${port}/api/health" > "$response" && maintenance_tool webui-health "$response" && webui_lapi_status; then
                return 0
            fi
        fi
        [[ "$status" == 'false '* || "$status" == *' unhealthy' ]] && break
        sleep 1
    done
    log_err 'WebUI HTTP、容器健康或独立 LAPI 登录未就绪。'
    return 1
)

check_webui_status() {
    if ! webui_owned && [[ ! -f "${WEBUI_DIR}/docker-compose.yml" ]]; then
        log_info 'WebUI: 未部署（可选）。'
        return 0
    fi
    local port
    port=$(maintenance_tool webui-port "${WEBUI_DIR}/docker-compose.yml") || return 1
    valid_port "$port" || { log_err 'WebUI 端口无效，未执行健康请求。'; return 1; }
    webui_ready "$port" 1 || return 1
    log_info '[正常] WebUI HTTP、容器与独立 LAPI 登录。'
}

webui_owns_port() {
    local port="$1" processes sockets
    processes=$(docker top crowdsec-web-ui -eo pid 2>/dev/null) || return 1
    sockets=$(ss -H -lntp "sport = :${port}") || return 1
    python3 - "$processes" "$sockets" <<'PY'
import re
import sys
pids = set(re.findall(r'^\s*(\d+)\s*$', sys.argv[1], re.M))
owners = set(re.findall(r'pid=(\d+)', sys.argv[2]))
sys.exit(0 if owners and owners <= pids else 1)
PY
}

install_maintenance_runtime() {
    local stage
    maintenance_tool runtime-preflight "$MAINTENANCE_RUNTIME" || return 1
    mkdir -p "$MAINTENANCE_RUNTIME" || return 1
    chmod 700 "$MAINTENANCE_RUNTIME" || return 1
    stage=$(mktemp -d "${MAINTENANCE_RUNTIME}/.stage.XXXXXXXX") || return 1
    if ! cp -- "$MANAGER_FILE" "$stage/manager.sh" || ! cp -a -- "${SCRIPT_DIR}/lib" "$stage/lib"; then rm -rf -- "$stage"; return 1; fi
    chmod -R go-rwx "$stage" || { rm -rf -- "$stage"; return 1; }
    local release
    release="${MAINTENANCE_RUNTIME}/release-$(date +%s)-${RANDOM}" || return 1
    mv -- "$stage" "$release" || return 1
    local link="${MAINTENANCE_RUNTIME}/.current-${RANDOM}"
    ln -s "$release" "$link" || return 1
    mv -Tf -- "$link" "${MAINTENANCE_RUNTIME}/current" || return 1
    (umask 077; touch "${MAINTENANCE_RUNTIME}/.crowdsec-1key-managed") || return 1
}

update_hub_logged() {
    mkdir -p "$(dirname "$UPDATE_LOG")" || return 1
    (umask 077; touch "$UPDATE_LOG") || return 1
    chmod 600 "$UPDATE_LOG" || return 1
    printf '\n[%s] Hub 更新\n' "$(date -Is)" | tee -a "$UPDATE_LOG"
    run_hub_update 2>&1 | tee -a "$UPDATE_LOG"
}

check_protection_evidence() (
    local work result=0 id name status service
    work=$(mktemp -d) || return 1
    trap 'rm -rf -- "$work"' EXIT
    if cscli metrics show acquisition -o json > "$work/acquisition" && cscli metrics show appsec -o json > "$work/appsec"; then
        maintenance_tool health-metrics "$work/acquisition" "$work/appsec" || result=1
    else
        log_err '[异常] 无法读取保护指标。'
        result=1
    fi
    check_log_inventory || { status=$?; [[ "$status" == 2 ]] || result=1; }
    for service in nginx openresty; do
        command -v "$service" >/dev/null 2>&1 || continue
        if "$service" -T > "$work/effective" 2>/dev/null; then
            python3 "${SCRIPT_DIR}/lib/crowdsec_host.py" "$work/effective" "$work/mounts" || { result=1; continue; }
            request_audit_tool status-host "$IP_VERIFICATIONS" "host:${service}" "$work/effective" "$APPSEC_LINKS" "$work/mounts" "${CS_DIR}/bouncers/crowdsec-${service}-bouncer.conf" || { status=$?; [[ "$status" == 2 ]] || result=1; }
        else
            log_err "[异常] 宿主机 ${service} 有效配置不可读。"
            result=1
        fi
    done
    if command -v docker >/dev/null 2>&1; then
        while read -r id name; do
            [[ -n "$id" && -n "$name" ]] || continue
            if docker exec "$id" nginx -T > "$work/effective" 2>/dev/null && docker inspect --format '{{json .Mounts}}' "$id" > "$work/mounts"; then
                request_audit_tool status "$IP_VERIFICATIONS" "$name" "$work/effective" "$WEB_INSTALLS" "$work/mounts" || { status=$?; [[ "$status" == 2 ]] || result=1; }
            fi
        done < <(docker ps --format '{{.ID}} {{.Names}}')
    fi
    [[ "$result" == 0 ]] && return 2
    return 1
)

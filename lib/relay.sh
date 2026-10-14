#!/usr/bin/env bash
# Relay mode shares the core transaction; runtime firewall inspection is read-only.
prepare_relay_logs() {
    # Consumed by the shared core backup and apply_staged_log_repair workflow.
    # shellcheck disable=SC2034
    LOG_REPAIR_FILE=$(yaml_tool relay-acquis-file "$CS_DIR") || return 1
    # shellcheck disable=SC2034
    LOG_PRESET_FILE=''
    LOG_REPAIR_STAGE=$(mktemp -d) || return 1
    LOG_REPAIR_COUNT=0
    if ! LOG_REPAIR_COUNT=$(python3 "${SCRIPT_DIR}/lib/crowdsec_relay.py" stage "$CS_DIR" "${LOG_REPAIR_STAGE}/repaired.yaml" "$@"); then
        cleanup_log_repair
        return 1
    fi
    log_info "系统/SSH 日志检查完成，待新增 ${LOG_REPAIR_COUNT} 项采集。"
}

check_relay_status() {
    if [[ -n "${CROWDBASTION_HEALTH_EVENTS:-}" ]]; then check_relay_status_raw "${2:-}"
    else health_report relay "${1:-summary}" "${2:-}"; fi
}

check_relay_status_raw() {
    health_expect bouncer
    health_expect rules
    require_yaml || return 1
    local action=audit
    load_node_roles || return 1
    if [[ "${1:-}" == remote ]] || node_has_role remote; then
        action=audit-remote
        # Shared role is consumed by health_report after this raw check.
        # shellcheck disable=SC2034
        NODE_ROLES=remote
    fi
    python3 "${SCRIPT_DIR}/lib/crowdsec_relay.py" "$action" "$CS_DIR"
}

verify_relay() {
    require_commands python3 || return 1
    load_node_roles || return 1
    local args=(--root "$CS_DIR")
    if [[ "${1:-}" == remote ]] || node_has_role remote || [[ -e "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.remote.json" ]]; then
        args+=(--remote)
    fi
    python3 "${SCRIPT_DIR}/lib/crowdbastion_relay_verify.py" "${args[@]}"
}

relay_after_install() {
    local mode="${1:-local}" status=0
    log_info '安装已完成，开始只读检查中转服务与防火墙。'
    if [[ "$mode" == remote ]]; then check_relay_status summary remote || status=$?
    else check_relay_status || status=$?; fi
    if [[ "$status" == 1 ]]; then
        log_info '安装已完成；运行检查发现问题，请先按结论处理，再进行入口验证。'
    elif [[ -t 0 ]]; then
        if confirm '现在进入中转入口验证向导（需独立测试设备）？'; then
            verify_relay "$mode" || true
        fi
    else
        log_info '实际入口验证：--verify-relay，或菜单 [4] → [3] → [3]。'
    fi
    # Report installation separately from runtime checks or optional acceptance.
    return 0
}

check_remote_firewall_status() {
    require_yaml || return 1
    python3 "${SCRIPT_DIR}/lib/crowdsec_relay.py" audit-remote "$CS_DIR"
}

check_relay_path() {
    local path_result=0 bouncer_result=0
    python3 "${SCRIPT_DIR}/lib/crowdsec_relay_paths.py" || path_result=$?
    # EOF/cancel returns before any local checks, including the Bouncer audit.
    [[ "$path_result" -eq 0 ]] && return 0
    [[ "$path_result" -eq 2 ]] || return 1
    check_relay_status || bouncer_result=$?
    [[ "$bouncer_result" -eq 0 || "$bouncer_result" -eq 2 ]] || return 1
    return 2
}

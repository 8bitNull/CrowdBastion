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
    require_yaml || return 1
    python3 "${SCRIPT_DIR}/lib/crowdsec_relay.py" audit "$CS_DIR"
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

#!/usr/bin/env bash
# No service/config/decision changes. Optional selectors are operator declarations.
diagnose_v2bx() {
    require_yaml || return 1
    local args=(--cs-dir "$CS_DIR" --unit "${V2BX_UNIT:-V2bX.service}" --entries "${V2BX_ENTRIES:-}")
    [[ -z "${V2BX_CONFIG:-}" ]] || args+=(--config "$V2BX_CONFIG")
    [[ -z "${V2BX_WORKING_DIR:-}" ]] || args+=(--working-dir "$V2BX_WORKING_DIR")
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx.py" "${args[@]}"
}

check_v2bx_logs() {
    local sample_file="${V2BX_LOG_FILE:-}" sample_core="${V2BX_LOG_CORE:-}"
    if [[ -z "$sample_file" ]]; then
        prompt sample_file '本机日志样本路径（q 取消）: ' || return 0
        [[ "$sample_file" != q && -n "$sample_file" ]] || return 0
    fi
    if [[ -z "$sample_core" ]]; then
        prompt sample_core '样本内核 xray/sing/hysteria2（q 取消）: ' || return 0
        [[ "$sample_core" != q && -n "$sample_core" ]] || return 0
    fi
    require_yaml || return 1
    local args=(--file "$sample_file" --core "$sample_core" --unit "${V2BX_UNIT:-V2bX.service}" --relay-cidrs "${V2BX_RELAY_CIDRS:-}")
    [[ -z "${V2BX_LOG_TIMEZONE:-}" ]] || args+=(--timezone "$V2BX_LOG_TIMEZONE")
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_logs.py" "${args[@]}"
}

# Opt-in sample storage only; production acquisition and services are untouched.
observe_v2bx_logs() {
    if [[ -z "${V2BX_LOG_FILE:-}" || -z "${V2BX_LOG_CORE:-}" || -z "${V2BX_OBSERVE_DB:-}" ]]; then
        echo '请设置 V2BX_LOG_FILE、V2BX_LOG_CORE、V2BX_OBSERVE_DB；数据库需放在当前用户的私有目录。'
        return 1
    fi
    require_yaml || return 1
    local args=(--file "$V2BX_LOG_FILE" --core "$V2BX_LOG_CORE" --database "$V2BX_OBSERVE_DB"
        --unit "${V2BX_UNIT:-V2bX.service}" --relay-cidrs "${V2BX_RELAY_CIDRS:-}"
        --duration "${V2BX_OBSERVE_DURATION:-60}" --max-events "${V2BX_OBSERVE_MAX_EVENTS:-100000}")
    [[ -z "${V2BX_LOG_TIMEZONE:-}" ]] || args+=(--timezone "$V2BX_LOG_TIMEZONE")
    [[ -z "${V2BX_OBSERVE_EXPORT:-}" ]] || args+=(--export "$V2BX_OBSERVE_EXPORT")
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_observe.py" "${args[@]}"
}

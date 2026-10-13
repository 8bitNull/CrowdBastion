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

# Dedicated local service; no CrowdSec rules, acquisition or firewall changes.
v2bx_observer_service() {
    local action="$1" args=()
    require_yaml || return 1
    if [[ "$action" == install ]]; then
        if [[ -z "${V2BX_OBSERVER_CONFIG:-}" ]]; then
            echo '请设置 V2BX_OBSERVER_CONFIG 为私有 JSON 配置文件路径；格式见 V2bX 指南。'
            return 1
        fi
        args+=(--config "$V2BX_OBSERVER_CONFIG")
    fi
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_service.py" "$action" "${args[@]}"
}

manage_v2bx_observer() {
    local choice
    while true; do
        printf '\nV2bX 落地仅观察服务\n1. 安装（需 V2BX_OBSERVER_CONFIG）\n2. 只读状态\n3. 停用并保留数据\n4. 接入 CrowdSec 仅观察告警\n5. 只读告警接入状态\n6. 停用告警接入并保留证据\n0. 返回\n'
        prompt choice '请选择 [0-6]: ' || return 0
        case "$choice" in
            1) locked_operation v2bx_observer_service install ;;
            2) v2bx_observer_service status ;;
            3) locked_operation v2bx_observer_service disable ;;
            4) locked_operation v2bx_alert_service enable ;;
            5) v2bx_alert_service status ;;
            6) locked_operation v2bx_alert_service disable ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
        pause
    done
}

# Managed observation guard and incremental output; no remediation decisions.
v2bx_alert_service() {
    require_yaml || return 1
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_alerts.py" "$1"
}

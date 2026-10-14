#!/usr/bin/env bash
# Typed observations are optional outside a captured report.
health_event() {
    [[ -n "${CROWDBASTION_HEALTH_EVENTS:-}" ]] || return 0
    python3 "${SCRIPT_DIR}/lib/crowdbastion_health.py" event "$1" "$2"
}
health_expect() { health_event "$1" required; }

health_service() {
    local key="$1" unit="$2" output status=0
    health_expect "$key"
    output=$(systemctl is-active "$unit") || status=$?
    printf '%s\n' "$output"
    if [[ "$status" == 0 ]]; then health_event "$key" ok
    elif [[ "$output" == inactive || "$output" == failed ]]; then health_event "$key" fault
    elif [[ "$output" == unknown ]]; then health_event "$key" missing
    else health_event "$key" unknown; fi
    return "$status"
}

health_probe() {
    local key="$1" failure="$2" status=0
    shift 2
    health_expect "$key"
    "$@" || status=$?
    if [[ "$status" == 0 ]]; then health_event "$key" ok
    else health_event "$key" "$failure"; fi
    return "$status"
}

health_verification_help() {
    printf '\n如何验证实际拦截\n'
    if node_has_role web || [[ -z "$NODE_ROLES" ]]; then
        printf '从另一台设备访问你管理的网站；结合访问日志、真实来源 IP 和处理指标核对网站接入。\nAppSec 验证入口：--verify-appsec；执行前会说明请求并要求确认。\n'
    fi
    if node_has_role relay || node_has_role remote || node_has_role node; then
        printf '1. 用 --relay-path 核对测试连接经过 INPUT 还是 FORWARD，以及本机看到的来源 IP。\n2. 准备独立的外部测试来源，先确认正常连接可用。\n3. 为测试来源设置短时封禁，对比新的连接与该规则计数变化，再撤销封禁并确认恢复。\n使用你管理的测试设备；保留当前管理连接，不封禁管理 IP 或共享中转 IP。\n'
    fi
    node_has_role node && printf 'V2bX 此检查只核对配置和运行证据；专用攻击检测需另外接入并验证。\n'
    printf '以上为操作说明，本次未发送测试请求或创建封禁。\n'
}

health_recommended_action() {
    case "$1" in
        verify) health_verification_help ;;
        core_logs) journalctl -u crowdsec -n 50 --no-pager ;;
        bouncer_logs) journalctl -u crowdsec-firewall-bouncer -n 50 --no-pager ;;
        v2bx_logs) journalctl -u "${V2BX_UNIT:-V2bX.service}" -n 50 --no-pager ;;
        install_web) locked_operation install_crowdsec_core web ;;
        install_relay) locked_operation install_crowdsec_core relay ;;
        install_remote) locked_operation manage_remote_bouncer ;;
        log_help) printf '先核对日志格式、labels.type 与已安装解析器。可只读查看：cscli metrics show acquisition；cscli parsers list。\n'; cat -- "$2" ;;
        path_help) health_verification_help ;;
        *) cat -- "$2" ;;
    esac
}

health_report() (
    local scope="$1" mode="${2:-summary}" work result=0 choice action label
    umask 077
    work=$(mktemp -d "${TMPDIR:-/tmp}/crowdbastion-health.XXXXXXXX") || { log_err '无法准备检查报告。'; return 1; }
    trap 'rm -rf -- "$work"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export CROWDBASTION_HEALTH_EVENTS="$work/events" PYTHONDONTWRITEBYTECODE=1
    : > "$work/events"
    case "$scope" in
        overall) check_health_status_raw > "$work/details" 2>&1 || result=$? ;;
        relay) check_relay_status_raw > "$work/details" 2>&1 || result=$? ;;
        node) diagnose_v2bx_raw > "$work/details" 2>&1 || result=$? ;;
    esac
    if [[ -z "$NODE_ROLES" && "$scope" != overall ]]; then
        [[ "$scope" == relay ]] && NODE_ROLES=relay || NODE_ROLES=node
    fi
    # Unknown exit statuses still mean a failed check, never a successful result.
    [[ "$result" == 0 || "$result" == 2 ]] || result=1
    local rendered=0
    python3 "${SCRIPT_DIR}/lib/crowdbastion_health.py" "$work/events" "$result" "$scope" "$NODE_ROLES" "$work/action" > "$work/summary" 2> "$work/report-errors" || rendered=$?
    if [[ ( "$rendered" == 0 || "$rendered" == 1 || "$rendered" == 2 ) && -s "$work/action" ]]; then
        cat -- "$work/summary"
        result=$rendered
    else
        printf '检查结论：检查未完成，暂时无法判断\n需要关注：检查报告未能生成。\n下一步：查看详情，核对 Python 与报告工具是否完整。\n'
        printf 'details\n查看检查详情和未完成原因\n' > "$work/action"
        cat -- "$work/report-errors" >> "$work/details"
        result=1
    fi
    if [[ "$mode" == details ]]; then cat -- "$work/details"; return "$result"; fi
    if [[ "$mode" != interactive || ! -t 0 ]]; then
        printf '查看详情：%s\n' "$(case "$scope" in overall) printf '%s' --status-details;; relay) printf '%s' --relay-status-details;; node) printf '%s' --diagnose-v2bx-details;; esac)"
        return "$result"
    fi
    { read -r action; read -r label; } < "$work/action" || { cat -- "$work/details"; return 1; }
    # No check output or event context is allowed to leak into a later action.
    unset CROWDBASTION_HEALTH_EVENTS
    while true; do
        printf '\n1. %s（推荐）\n2. 查看检查详情\n0. 返回\n' "$label"
        prompt choice '请选择 [0-2]: ' || return 0
        case "$choice" in
            0) return 0 ;;
            1) health_recommended_action "$action" "$work/details"; result=$?; pause; return "$result" ;;
            2) cat -- "$work/details" ;;
            *) log_warn '无效选项。' ;;
        esac
    done
)

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
    if node_has_role web || [[ -z "$NODE_ROLES" ]] || node_web_deployed; then
        printf '从另一台设备访问你管理的网站；结合访问日志、真实来源 IP 和处理指标核对网站接入。\nAppSec 验证入口：--verify-appsec；执行前会说明请求并要求确认。\n'
    fi
    if node_has_role relay || node_has_role remote || node_has_role node; then
        printf '中转入口验证向导：--verify-relay，或菜单 [4] → [4] → [3] → [3]。\n先用 --relay-path 核对来源与 INPUT/FORWARD 路径；准备独立测试设备和正常对照来源。\n向导核对外部新连接对照、封禁集合与规则计数，给出本次入口的验收结论。\n'
    fi
    node_has_role node && printf 'V2bX 此检查只核对配置和运行证据；专用攻击检测需另外接入并验证。\n'
    printf '以上为操作说明，本次未发送测试请求或创建封禁。\n'
    if { node_has_role relay || node_has_role remote; } && [[ -t 0 ]]; then
        if confirm '现在进入中转入口验证向导？'; then verify_relay; return $?; fi
    fi
    return 0
}

# is-active can print "inactive" for a unit that does not exist. Require both
# a loaded unit and the documented status code before offering a start.
health_service_state() {
    local unit="$1" loaded state status=0
    loaded=$(systemctl show --property=LoadState --value "$unit") || { printf 'unknown\n'; return; }
    if [[ "$loaded" == not-found ]]; then printf 'missing\n'; return; fi
    if [[ "$loaded" != loaded ]]; then printf 'unknown\n'; return; fi
    state=$(systemctl is-active "$unit") || status=$?
    case "$status:$state" in
        0:active|3:inactive|3:failed) printf '%s\n' "$state" ;;
        *) printf 'unknown\n' ;;
    esac
}

health_start_service() {
    local unit state
    case "$1" in
        core) unit=crowdsec; crowdsec -t || return 1 ;;
        bouncer)
            unit=crowdsec-firewall-bouncer
            require_yaml || return 1
            python3 "${SCRIPT_DIR}/lib/crowdsec_firewall.py" guard "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" || return 1 ;;
        *) return 1 ;;
    esac
    state=$(health_service_state "$unit")
    if [[ "$state" != inactive && "$state" != failed ]]; then
        log_warn '服务状态已变化，本次不启动；请重新检查。'; return 1
    fi
    if ! systemctl start "$unit"; then
        log_err '服务启动失败，下面是最新日志，请按错误原因处理后重新检查。'
        journalctl -u "$unit" -n 30 --no-pager
        return 1
    fi
    if ! systemctl is-active --quiet "$unit"; then
        log_err '启动后服务仍未运行，下面是最新日志，请继续排查。'
        journalctl -u "$unit" -n 30 --no-pager
        return 1
    fi
    printf '服务已启动；返回检查页后将自动复查防护情况。\n'
    health_note_change
}

health_service_diagnose() {
    local key="$1" unit label state valid=true
    case "$key" in
        core) unit=crowdsec; label='检测服务' ;;
        bouncer) unit=crowdsec-firewall-bouncer; label='防火墙封禁服务' ;;
        v2bx) unit="${V2BX_UNIT:-V2bX.service}"; label='V2bX 服务' ;;
        *) return 1 ;;
    esac
    printf '\n排查%s\n' "$label"
    state=$(health_service_state "$unit")
    case "$state" in
        inactive|failed) printf '已确认：服务目前没有运行。\n' ;;
        active) printf '服务现在已经运行，请重新检查，确认原问题是否仍存在。\n' ;;
        missing) printf '服务未安装或无法读取，请先从首页 2 核对安装。\n' ;;
        *) printf '暂时无法确定服务状态，先核对是否已安装及 systemd 是否可用。\n' ;;
    esac
    if [[ "$key" == core ]]; then
        if crowdsec -t; then printf '配置校验通过。\n'
        else printf '配置校验未通过：请先处理上方配置错误，再尝试启动。\n'; valid=false; fi
    fi
    printf '\n最近启动日志（供进一步排查）：\n'
    journalctl -u "$unit" -n 30 --no-pager
    if [[ "$key" != v2bx && "$valid" == true && ( "$state" == inactive || "$state" == failed ) ]]; then
        printf '\n可以尝试启动%s；启动成功后仍需重新检查。\n' "$label"
        if confirm '现在尝试启动服务？'; then
            locked_operation health_start_service "$key"
            return $?
        fi
    fi
    printf '下一步：按上方明确的错误处理；原因仍不明确时，可把相关错误提供给维护者。\n'
    return 0
}

health_recommended_action() {
    case "$1" in
        repair_existing) locked_operation repair_existing_deployment ;;
        verify) health_verification_help ;;
        core_logs) health_service_diagnose core ;;
        bouncer_logs) health_service_diagnose bouncer ;;
        v2bx_logs) health_service_diagnose v2bx ;;
        install_web) locked_operation install_crowdsec_core web ;;
        install_relay) locked_operation install_crowdsec_core relay ;;
        install_remote) locked_operation manage_remote_bouncer ;;
        log_help)
            printf '\n本次检查的原始证据：\n'
            cat -- "$2"
            printf '\n如果日志已读取但没有成功解析：先核对失败来源的日志格式、labels.type 与解析器。\n可只读核对：cscli metrics show acquisition；cscli parsers list。\n接下来检查采集路径；路径已覆盖不代表日志解析正常。\n'
            check_log_inventory ;;
        path_help) check_relay_path ;;
        *) cat -- "$2" ;;
    esac
}

health_report() (
    local scope="$1" mode="${2:-summary}" context="${3:-}" work result=0 choice action label before after action_status
    if [[ "$mode" == interactive && -t 0 ]]; then
        # Consumed by health_stage while detailed output is captured.
        # shellcheck disable=SC2034
        exec {CROWDBASTION_PROGRESS_FD}>&1
    fi
    umask 077
    work=$(mktemp -d "${TMPDIR:-/tmp}/crowdbastion-health.XXXXXXXX") || { log_err '无法准备检查报告。'; return 1; }
    trap 'rm -rf -- "$work"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    while true; do
        result=0
        rm -f -- "$work/action"
        export CROWDBASTION_HEALTH_EVENTS="$work/events" PYTHONDONTWRITEBYTECODE=1
        : > "$work/events"
        health_stage '准备只读检查'
        case "$scope" in
            overall) check_health_status_raw > "$work/details" 2>&1 || result=$? ;;
            relay) check_relay_status_raw "$context" > "$work/details" 2>&1 || result=$? ;;
            node) diagnose_v2bx_raw > "$work/details" 2>&1 || result=$? ;;
        esac
        if [[ -z "$NODE_ROLES" && "$scope" != overall ]]; then
            [[ "$scope" == relay ]] && NODE_ROLES=relay || NODE_ROLES=node
        fi
        # Unknown exit statuses still mean a failed check, never a successful result.
        [[ "$result" == 0 || "$result" == 2 ]] || result=1
        if [[ "$mode" == json ]]; then
            python3 "${SCRIPT_DIR}/lib/crowdbastion_health.py" json "$work/events" "$result" "$scope" "$NODE_ROLES" "${CS_DIR}/config.yaml"
            return $?
        fi
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
        if [[ "$scope" != node ]] && { node_has_role relay || node_has_role remote; }; then show_relay_acceptance; fi
        if [[ "$mode" == details ]]; then cat -- "$work/details"; return "$result"; fi
        if [[ "$mode" != interactive || ! -t 0 ]]; then
            printf '查看详情：%s\n' "$(case "$scope" in overall) printf '%s' --status-details;; relay) printf '%s' --relay-status-details;; node) printf '%s' --diagnose-v2bx-details;; esac)"
            return "$result"
        fi
        { read -r action; read -r label; } < "$work/action" || { cat -- "$work/details"; return 1; }
        # No check output or event context is allowed to leak into a later action.
        unset CROWDBASTION_HEALTH_EVENTS
        while true; do
            printf '\n1. %s（推荐）\n2. 查看技术详情\n3. 重新检查\n4. 导出脱敏诊断报告\n0. 返回\n' "$label"
            prompt choice '请选择 [0-4]: ' || return 0
            case "$choice" in
                0) return 0 ;;
                1)
                    before=$(ux_config_fingerprint) || before=''
                    export CROWDBASTION_HEALTH_CHANGED="$work/changed"
                    rm -f -- "$work/changed"
                    action_status=0
                    health_recommended_action "$action" "$work/details" || action_status=$?
                    after=$(ux_config_fingerprint) || after=''
                    unset CROWDBASTION_HEALTH_CHANGED
                    if [[ "$action_status" == 0 ]] && { [[ -f "$work/changed" ]] || [[ -n "$before" && -n "$after" && "$before" != "$after" ]]; }; then
                        printf '\n检测到已执行的修改，正在自动复查（只读）…\n'
                        break
                    fi
                    if [[ "$action_status" != 0 ]]; then printf '\n操作未完成，请按上方错误处理；选择 3 可复查当前情况。\n'
                    else printf '\n未检测到配置或服务修改；返回或取消不会改变检查结论。选择 3 可重新检查。\n'; fi ;;
                2) show_health_details "$work/details" ;;
                3) break ;;
                4) export_health_details "$work/details" ;;
                *) log_warn '无效选项。' ;;
            esac
        done
    done
)

#!/usr/bin/env bash
# Shared interaction helpers. Status labels never assert traffic protection.
ux_tool() { python3 "${SCRIPT_DIR}/lib/crowdbastion_ux.py" "$@"; }

ux_config_fingerprint() { ux_tool fingerprint "$CS_DIR" 2>/dev/null; }

ux_service_label() {
    local state status=0
    state=$(systemctl is-active "$1" 2>/dev/null) || status=$?
    case "$status:$state" in
        0:active) printf '已配置，服务运行；实际防护待验证' ;;
        3:inactive|3:failed) printf '已配置，服务未运行；实际防护待验证' ;;
        *) printf '已配置，服务状态待检查' ;;
    esac
}

guided_step_state() {
    case "$1" in
        web|relay)
            if [[ -f "${CS_DIR}/config.yaml" ]]; then ux_service_label crowdsec
            else printf '待安装'; fi ;;
        remote)
            if [[ -f "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.remote.json" ]]; then ux_service_label crowdsec-firewall-bouncer
            else printf '待连接'; fi ;;
        website)
            if [[ -f "$APPSEC_FILE" ]]; then printf '发现引擎配置，网站接入及请求待验证'
            else printf '待配置'; fi ;;
        realip)
            if [[ -f "$REALIP_STATE" ]]; then printf '发现托管配置，真实请求待验证'
            else printf '待核对代理信任和真实请求'; fi ;;
        relaypath) printf '待核对路径；各入口、协议、地址族需单独验收' ;;
        node)
            if [[ -f "$V2BX_OBSERVER_INSTALLED_CONFIG" ]]; then ux_service_label crowdsec-v2bx-observer
            else printf '配置与日志待检查；持续记录可选'; fi ;;
    esac
}

ux_operation_feedback() {
    local before="$1" status="$2" after
    after=$(ux_config_fingerprint) || after=''
    if [[ "$status" != 0 ]]; then
        printf '\n本步骤未完成，请处理上方原因后重试；当前配置和服务以重新检查为准。\n'
    elif [[ -n "$before" && -n "$after" && "$before" != "$after" ]]; then
        printf '\n检测到配置变化；请继续验证配置、服务和实际请求，选择 9 可检查当前防护。\n'
    elif [[ -n "$before" && -n "$after" ]]; then
        printf '\n未检测到配置变化；返回或取消不会标记完成。请按上方检查结果继续，实际防护仍需验证。\n'
    else
        printf '\n操作已返回，未能比较配置变化；请按上方结果继续检查。\n'
    fi
}

show_maintenance_runtime_status() {
    ux_tool runtime "$MANAGER_FILE" "${MAINTENANCE_RUNTIME}/current/manager.sh"
}

sync_maintenance_runtime() {
    local status=0
    show_maintenance_runtime_status || status=$?
    [[ "$status" != 1 ]] || return 1
    [[ -f "$CRON_FILE" && ! -L "$CRON_FILE" ]] || { log_warn '尚未启用定时更新，请先使用 --enable-cron。'; return 1; }
    ux_tool runtime-cron "$CRON_FILE" "${MAINTENANCE_RUNTIME}/current/manager.sh" || {
        log_warn '定时任务未指向托管维护副本或已被注释，未同步；请先核对 cron 配置。'
        return 1
    }
    log_info '将当前脚本及 lib 同步到定时任务使用的副本；cron 文件和原执行时间保留。'
    confirm '现在同步维护副本？' || { log_info '已取消同步。'; return 0; }
    install_maintenance_runtime || return 1
    show_maintenance_runtime_status || return 1
    log_succ '维护副本已同步；定时任务配置未改动。'
}

show_relay_acceptance() {
    ux_tool acceptance "$RELAY_ACCEPTANCE_FILE" "$CS_DIR" || log_warn '历史验收记录无法读取；请重新验收。'
}

show_health_details() {
    if [[ -t 0 && -t 1 && "${TERM:-dumb}" != dumb ]] && command -v less >/dev/null 2>&1; then
        # Do not execute arbitrary PAGER/LESSOPEN commands as root.
        LESSSECURE=1 LESSOPEN='' LESSCLOSE='' less -F -X -- "$1"
    else
        cat -- "$1"
    fi
}

export_health_details() {
    local destination
    prompt destination '脱敏报告绝对路径（目录须已存在；不覆盖文件；留空取消）: ' || return 0
    [[ -n "$destination" ]] || return 0
    [[ "$destination" == /* ]] || { log_warn '请输入绝对路径。'; return 1; }
    ux_tool export "$1" "$destination" || return 1
    log_succ "脱敏报告已保存：${destination}（0600）。分享前请人工核对域名、路径和业务信息。"
}

health_note_change() {
    if [[ -n "${CROWDBASTION_HEALTH_CHANGED:-}" ]]; then
        : > "$CROWDBASTION_HEALTH_CHANGED" || log_warn '无法记录服务变化，请手动重新检查。'
    fi
    return 0
}

health_stage() {
    [[ -n "${CROWDBASTION_PROGRESS_FD:-}" ]] || return 0
    printf '正在检查：%s…\n' "$1" >&"$CROWDBASTION_PROGRESS_FD"
}

generate_v2bx_observer_config() {
    local core filename zone='' networks='' destination
    printf '\n生成持续日志记录配置 — 输入 q 或 Ctrl+D 取消\n不会修改内核日志设置；请先准备独立的本机日志文件。\n'
    prompt core '内核 xray/sing/hysteria2: ' || return 0
    [[ "$core" != q && -n "$core" ]] || return 0
    prompt filename '独立日志文件绝对路径: ' || return 0
    [[ "$filename" != q && -n "$filename" ]] || return 0
    if [[ "$core" == xray ]]; then
        prompt zone '日志实际时区（例如 +08:00，不确定请取消）: ' || return 0
        [[ "$zone" != q && -n "$zone" ]] || return 0
    fi
    prompt networks '实际中转出口 CIDR，逗号分隔（无中转留空）: ' || return 0
    [[ "$networks" != q ]] || return 0
    prompt destination '保存配置的绝对路径（已有目录，不覆盖文件）: ' || return 0
    [[ "$destination" != q && -n "$destination" ]] || return 0
    [[ "$destination" == /* ]] || { log_warn '配置路径必须为绝对路径。'; return 1; }
    local args=("$destination" "$core" "$filename" "$zone" "$networks" "${V2BX_UNIT:-V2bX.service}")
    require_yaml || return 1
    printf '\n校验及预览：\n'
    ux_tool observer-preview "${args[@]}" || return 1
    confirm '仅保存上述配置（0600），服务启动需另选开始记录？' || { log_info '已取消保存配置。'; return 0; }
    # The parent shell remembers the generated path; only the write takes the lock.
    locked_operation ux_tool observer-write "${args[@]}" >/dev/null || return 1
    # Read by the caller's observer menu after returning from this function.
    # shellcheck disable=SC2034
    V2BX_OBSERVER_CONFIG="$destination"
    log_succ "配置已保存并校验：${destination}。持续记录菜单选 1 即可使用。"
}

manage_quick_actions() {
    local choice
    while true; do
        printf '\n当前位置：首页 → 常用操作 — %s\n1. 防火墙检查与修复\n2. 中转入口验证\n3. V2bX 落地管理\n4. 网站与真实 IP 检查\n5. 通知管理\n6. 查看维护副本版本\n7. 同步维护副本（保留执行时间）\n8. 查看上次中转验收\n9. 代理协议使用导航（AnyTLS/QUIC 等）\n0. 返回首页\n' "$(node_role_label)"
        prompt choice '请选择 [0-9]: ' || return 0
        case "$choice" in
            1) locked_operation manage_firewall_maintenance ;;
            2) verify_relay ;;
            3) manage_v2bx_node ;;
            4) locked_operation manage_real_ip ;;
            5) locked_operation manage_telegram ;;
            6) show_maintenance_runtime_status ;;
            7) locked_operation sync_maintenance_runtime ;;
            8) show_relay_acceptance ;;
            9) manage_proxy_guidance ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
    done
}

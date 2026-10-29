#!/usr/bin/env bash
# Managed, independent notification worker; it never polls Telegram updates.
NOTIFY_HELPERS=(crowdsec_notify.py crowdsec_notify_client.py crowdsec_bot_api.py
    crowdsec_bot_health.py crowdbastion_health.py crowdbastion_node.py)

notify_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_notify_setup.py" "$@"; }

notify_owned() {
    [[ -f "$NOTIFY_UNIT" && ! -L "$NOTIFY_UNIT" ]] &&
        grep -Fxq '# crowdbastion-managed-notify' "$NOTIFY_UNIT"
}

notify_preflight() {
    local info line loaded='' fragment='' path
    if [[ -e "$NOTIFY_UNIT" || -L "$NOTIFY_UNIT" ]] && ! notify_owned; then
        log_err '同名通知服务归属未知，未修改。'; return 1
    fi
    info=$(systemctl show --property=LoadState --property=FragmentPath crowdbastion-notify.service) || return 1
    while IFS= read -r line; do
        case "$line" in LoadState=*) loaded=${line#LoadState=} ;; FragmentPath=*) fragment=${line#FragmentPath=} ;; esac
    done <<< "$info"
    if [[ "$loaded" != not-found ]] && { [[ "$fragment" != "$NOTIFY_UNIT" ]] || ! notify_owned; }; then
        log_err '无法确认已加载的通知服务归属。'; return 1
    fi
    notify_tool preflight "$CS_DIR" --state-dir "$NOTIFY_STATE" --code-dir "$NOTIFY_CODE" --unit "$NOTIFY_UNIT" || return 1
    for path in "$NOTIFY_CONFIG" "$NOTIFY_CODE" "$NOTIFY_STATE"; do
        if [[ -L "$path" ]]; then log_err '通知配置和目录不能为符号链接。'; return 1; fi
    done
    for path in "${NOTIFY_HELPERS[@]}"; do
        if [[ -L "$NOTIFY_CODE/$path" ]] || { [[ -e "$NOTIFY_CODE/$path" ]] && { [[ ! -f "$NOTIFY_CODE/$path" ]] || ! notify_owned; }; }; then
            log_err '通知程序文件归属未知，未覆盖。'; return 1
        fi
    done
}

notify_snapshot() {
    NOTIFY_WAS_ACTIVE=false NOTIFY_WAS_ENABLED=false NOTIFY_WAS_PRESENT=false NOTIFY_WAS_RUNTIME=false
    if notify_owned; then
        NOTIFY_WAS_PRESENT=true
        local info line active='' enabled=''
        info=$(systemctl show --property=ActiveState --property=UnitFileState crowdbastion-notify.service) || {
            log_err '无法读取原通知服务状态，未修改。'; return 1;
        }
        while IFS= read -r line; do
            case "$line" in ActiveState=*) active=${line#ActiveState=} ;; UnitFileState=*) enabled=${line#UnitFileState=} ;; esac
        done <<< "$info"
        case "$active" in
            active|reloading) NOTIFY_WAS_ACTIVE=true ;;
            inactive|failed) ;;
            *) log_err '原通知服务状态未稳定或无法确认，未修改。'; return 1 ;;
        esac
        case "$enabled" in
            enabled) NOTIFY_WAS_ENABLED=true ;;
            enabled-runtime) NOTIFY_WAS_ENABLED=true NOTIFY_WAS_RUNTIME=true ;;
            disabled) ;;
            *) log_err '无法确认原通知服务的启用方式，未修改。'; return 1 ;;
        esac
    fi
    local helper paths=("$NOTIFY_CONFIG" "$TG_NOTIF_FILE" "$NOTIFY_UNIT" "${TG_PROFILE_PATHS[@]}")
    for helper in "${NOTIFY_HELPERS[@]}"; do paths+=("$NOTIFY_CODE/$helper"); done
    begin_config_change "${paths[@]}"
}

notify_rollback() {
    local failed=false
    if notify_owned || [[ "$NOTIFY_WAS_PRESENT" == true ]]; then
        systemctl stop crowdbastion-notify.service || failed=true
        if [[ "$NOTIFY_WAS_ENABLED" != true || "$NOTIFY_WAS_RUNTIME" == true ]]; then
            # Disable while the unit still exists, before rollback removes a new unit.
            systemctl disable crowdbastion-notify.service || failed=true
        fi
    fi
    restore_config_change || failed=true
    systemctl daemon-reload || failed=true
    if [[ "$NOTIFY_WAS_ENABLED" == true ]]; then
        local flags=()
        if [[ "$NOTIFY_WAS_RUNTIME" == true ]]; then flags+=(--runtime); fi
        systemctl enable "${flags[@]}" crowdbastion-notify.service || failed=true
    fi
    if [[ "$NOTIFY_WAS_ACTIVE" == true ]]; then
        systemctl restart crowdbastion-notify.service || failed=true
        systemctl is-active --quiet crowdbastion-notify.service || failed=true
    fi
    if [[ "$failed" == true ]]; then log_err '通知服务回滚不完整，请检查原服务和路由。'; return 1; fi
}

notify_ready() {
    local attempt
    for ((attempt=0; attempt<10; attempt++)); do
        notify_tool ready "$CS_DIR" >/dev/null 2>&1 && return 0
        sleep 1
    done
    log_err '通知服务未就绪，正在恢复原配置。'
    return 1
}

enable_smart_notifications() {
    require_core && require_yaml && resolve_telegram_paths && notify_preflight || return 1
    [[ -f "$TG_NOTIF_FILE" ]] || { log_err '请先通过 Telegram 菜单第 1 项设置通知目标。'; return 1; }
    notify_tool plan "$CS_DIR" --state-dir "$NOTIFY_STATE" --bot-config "$CUSTOM_BOT_CONFIG" || return 1
    notify_snapshot || return 1
    local helper python_bin
    python_bin=$(command -v python3) || return 1
    if ! notify_tool prepare "$CS_DIR" --state-dir "$NOTIFY_STATE" --bot-config "$CUSTOM_BOT_CONFIG" ||
        ! mkdir -p "$NOTIFY_CODE" "$NOTIFY_STATE" "$(dirname "$NOTIFY_UNIT")" ||
        ! chmod 700 "$NOTIFY_CODE" "$NOTIFY_STATE"; then
        notify_rollback; return 1
    fi
    for helper in "${NOTIFY_HELPERS[@]}"; do
        if ! cp -- "$SCRIPT_DIR/lib/$helper" "$NOTIFY_CODE/$helper" || ! chmod 600 "$NOTIFY_CODE/$helper"; then
            notify_rollback; return 1
        fi
    done
    if ! cat > "$NOTIFY_UNIT" <<EOF
# crowdbastion-managed-notify
[Unit]
Description=CrowdBastion grouped and urgent Telegram notifications
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="$python_bin" "$NOTIFY_CODE/crowdsec_notify.py" run "$NOTIFY_CONFIG"
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths="$NOTIFY_STATE"

[Install]
WantedBy=multi-user.target
EOF
    then notify_rollback; return 1; fi
    if ! python3 "$NOTIFY_CODE/crowdsec_notify.py" check "$NOTIFY_CONFIG" ||
        ! systemctl daemon-reload || ! systemctl enable crowdbastion-notify.service ||
        ! systemctl restart crowdbastion-notify.service || ! notify_ready; then
        notify_rollback; return 1
    fi
    if ! apply_core_config; then notify_rollback; return 1; fi
    log_succ '已启用分级通知：普通告警每小时汇总，未知规则首次提醒，持续组件故障紧急通知。'
    log_info '原通知模式已保存；交互机器人更新后支持“已知晓”和“查看详情”。'
    log_info '本次未发送测试消息；可用 TG 菜单第 2 项验证官方插件、队列和 API 回执。'
}

disable_smart_notifications() {
    local mode="${1:-restore}"
    require_core && require_yaml && resolve_telegram_paths && notify_preflight || return 1
    notify_tool enabled "$CS_DIR" || return 1
    notify_snapshot || return 1
    if ! systemctl disable --now crowdbastion-notify.service || ! notify_tool restore "$CS_DIR"; then
        notify_rollback; return 1
    fi
    if [[ "$mode" == off ]]; then
        if ! update_telegram_profiles disable || ! rm -f -- "$TG_NOTIF_FILE"; then
            notify_rollback; return 1
        fi
    fi
    if ! apply_core_config; then notify_rollback; return 1; fi
    log_succ '分级通知已停用，待发队列保留。'
    if [[ "$mode" == restore ]]; then log_info '已恢复启用分级前的官方通知模式。'; fi
}

purge_smart_notifications() {
    [[ -e "$NOTIFY_UNIT" || -L "$NOTIFY_UNIT" ]] || return 0
    notify_preflight || return 1
    systemctl disable --now crowdbastion-notify.service || return 1
    local helper
    for helper in "${NOTIFY_HELPERS[@]}"; do rm -f -- "$NOTIFY_CODE/$helper" || return 1; done
    rm -f -- "$NOTIFY_UNIT" "$NOTIFY_CONFIG" || return 1
    rm -rf -- "$NOTIFY_STATE" || return 1
    systemctl daemon-reload
}

manage_smart_notifications() {
    local choice
    while true; do
        printf '\n分级降噪通知\n1. 启用/更新分级通知\n2. 查看队列与健康检查状态\n3. 停用分级，恢复原通知模式\n0. 返回\n'
        prompt choice '请选择 [0-3]: ' || return 0
        case "$choice" in
            1) enable_smart_notifications ;;
            2) notify_tool status "$CS_DIR" ;;
            3) disable_smart_notifications ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
        pause
    done
}

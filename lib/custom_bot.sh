#!/usr/bin/env bash
# Optional interactive bot; official HTTP notifications retain their own lifecycle.
CUSTOM_BOT_HELPERS=(crowdsec_safety.py crowdsec_execution.py crowdsec_bot_actions.py
    crowdsec_bot_api.py crowdsec_bot_health.py crowdbastion_health.py crowdbastion_node.py crowdsec_notify_client.py
    crowdsec_bot_runtime.py crowdbastion_ux.py)

custom_bot_owned() {
    [[ -f "$CUSTOM_BOT_UNIT" && ! -L "$CUSTOM_BOT_UNIT" ]] &&
        grep -Fxq '# crowdsec-1key-managed-interactive-bot' "$CUSTOM_BOT_UNIT"
}

check_custom_bot_ownership() {
    if [[ -e "$CUSTOM_BOT_UNIT" || -L "$CUSTOM_BOT_UNIT" ]] && ! custom_bot_owned; then
        log_err '同名机器人服务归属未知，未修改或停用。'; return 1
    fi
    local info line loaded='' fragment=''
    info=$(systemctl show --property=LoadState --property=FragmentPath crowdsec-1key-bot.service) || {
        log_err '无法确认同名服务归属，未修改。'; return 1;
    }
    while IFS= read -r line; do
        case "$line" in
            LoadState=*) loaded=${line#LoadState=} ;;
            FragmentPath=*) fragment=${line#FragmentPath=} ;;
        esac
    done <<< "$info"
    if [[ "$loaded" != not-found ]] && { [[ -z "$loaded" || "$fragment" != "$CUSTOM_BOT_UNIT" ]] || ! custom_bot_owned; }; then
        log_err 'systemd 中同名服务归属未知，未覆盖或停用。'; return 1
    fi
}

custom_bot_conflicts() {
    local units unit rest candidates line
    units=$(systemctl list-unit-files --type=service --no-legend --no-pager) || {
        log_err '无法检查已有机器人服务，未启动新实例。'; return 1;
    }
    while read -r unit rest; do
        [[ -n "$unit" && "$unit" != crowdsec-1key-bot.service ]] || continue
        if [[ "$unit" =~ crowdsec.*(bot|telegram|tg) ]] && systemctl is-active --quiet "$unit"; then
            log_err "发现其他正在运行的 CrowdSec 机器人服务 ${unit}，请先核对并手工停用旧轮询服务。"
            return 1
        fi
    done <<< "$units"
    if ! candidates=$(python3 "${SCRIPT_DIR}/lib/crowdsec_bot_settings.py" conflicts "$CUSTOM_BOT_SCRIPT" "$CUSTOM_BOT_CRON_DIR"); then
        log_err "发现独立机器人候选或无法完成检查：${candidates}；未自动停用。"
        return 1
    fi
    if candidates=$(crontab -l 2>/dev/null); then
        while IFS= read -r line; do
            [[ ! "$line" =~ ^[[:space:]]*# ]] || continue
            if [[ "$line" =~ crowdsec_bot\.py ]]; then
                log_err 'root crontab 存在 crowdsec_bot.py 候选，请先核对旧启动任务。'; return 1
            fi
        done <<< "$candidates"
    fi
}

restore_custom_bot() {
    CUSTOM_BOT_UPDATE_PENDING=false
    local failed=false
    systemctl stop crowdsec-1key-bot.service || failed=true
    restore_config_change || failed=true
    systemctl daemon-reload || failed=true
    if [[ "$CUSTOM_BOT_WAS_ENABLED" == true ]]; then
        systemctl enable crowdsec-1key-bot.service || failed=true
    else
        systemctl disable crowdsec-1key-bot.service || failed=true
    fi
    if [[ "$CUSTOM_BOT_WAS_ACTIVE" == true ]]; then
        systemctl restart crowdsec-1key-bot.service || failed=true
    fi
    if [[ "$failed" == true ]]; then log_err '机器人回滚或原服务恢复不完整，请手工检查。'; return 1; fi
}

custom_bot_update_exit() {
    local result=$?
    if [[ "${CUSTOM_BOT_UPDATE_PENDING:-false}" == true ]]; then
        log_err '机器人更新未完成，正在恢复原文件和服务状态。'
        restore_custom_bot || true
    fi
    return "$result"
}

setup_custom_bot() (
    require_core && require_yaml || return 1
    check_custom_bot_ownership || return 1
    custom_bot_conflicts || return 1
    local mode="${1:-configure}" runtime
    runtime="$(dirname "$CUSTOM_BOT_SCRIPT")/runtime" || return 1
    [[ "$mode" == configure || "$mode" == keep-config ]] || return 1
    local token='' chat='' admin='' npm='' endpoint='' python_bin helper target
    local -a helper_paths=()
    for helper in "${CUSTOM_BOT_HELPERS[@]}"; do
        helper_paths+=("$(dirname "$CUSTOM_BOT_SCRIPT")/$helper")
    done
    if [[ "$mode" == configure ]]; then
        log_info '官方通知继续自动推送；本组件只处理查询/按钮，不覆盖旧 /usr/local/bin/crowdsec_bot.py。'
        log_info '留空沿用已保存配置；首次可导入旧脚本中的静态参数。群组 Chat ID 与管理员个人 ID 分别填写。'
        read -r -s -p 'Bot Token（隐藏输入）: ' token || return 1
        printf '\n'
        prompt chat 'Chat ID: ' && prompt admin '管理员用户 ID（正数）: ' &&
            prompt npm 'NPM 日志目录 [保留/默认]: ' && prompt endpoint 'HTTPS API 端点 [保留/默认]: ' || return 1
    else
        custom_bot_owned && [[ -f "$CUSTOM_BOT_CONFIG" ]] || { log_err '请先配置本工具机器人。'; return 1; }
        python3 "${SCRIPT_DIR}/lib/crowdsec_bot.py" --config "$CUSTOM_BOT_CONFIG" --check-config || return 1
    fi
    CUSTOM_BOT_WAS_ACTIVE=false CUSTOM_BOT_WAS_ENABLED=false
    if [[ -f "$CUSTOM_BOT_UNIT" ]]; then
        local service_status=0 enabled_state=''
        systemctl is-active --quiet crowdsec-1key-bot.service || service_status=$?
        case "$service_status" in
            0) CUSTOM_BOT_WAS_ACTIVE=true ;;
            3) ;;
            *) log_err '无法确认原机器人运行状态，未更新文件。'; return 1 ;;
        esac
        service_status=0
        enabled_state="$(systemctl is-enabled crowdsec-1key-bot.service 2>/dev/null)" || service_status=$?
        case "$service_status:$enabled_state" in
            0:enabled) CUSTOM_BOT_WAS_ENABLED=true ;;
            1:disabled) ;;
            *) log_err '无法确认原机器人启用状态（仅支持 enabled/disabled），未更新文件；请在终端核对。'; return 1 ;;
        esac
    fi
    [[ ! -L "$CUSTOM_BOT_CONFIG" && ! -L "$CUSTOM_BOT_SCRIPT" && ! -L "$CUSTOM_BOT_UNIT" ]] || {
        log_err '受管理文件不能为符号链接。'; return 1;
    }
    for target in "${helper_paths[@]}"; do
        if [[ -L "$target" ]] || { [[ -e "$target" ]] && { [[ ! -f "$target" ]] || ! custom_bot_owned; }; }; then
            log_err '机器人模块归属或文件类型未知，未覆盖。'; return 1
        fi
    done
    python3 "${SCRIPT_DIR}/lib/crowdsec_bot_runtime.py" preflight "$CUSTOM_BOT_CONFIG" "$CUSTOM_BOT_SCRIPT" "$CUSTOM_BOT_UNIT" "$CUSTOM_BOT_STATE" "$runtime" "${helper_paths[@]}" &&
        maintenance_tool runtime-preflight "$runtime" || return 1
    if [[ -e "$CUSTOM_BOT_SCRIPT" ]] && ! custom_bot_owned; then
        log_err '机器人程序归属未知，未覆盖。'; return 1
    fi
    begin_config_change "$CUSTOM_BOT_CONFIG" "$CUSTOM_BOT_SCRIPT" "$CUSTOM_BOT_UNIT" "${helper_paths[@]}" "$runtime/current" || return 1
    CUSTOM_BOT_UPDATE_PENDING=true
    trap custom_bot_update_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ "$CUSTOM_BOT_WAS_ACTIVE" == true ]] && ! systemctl stop crowdsec-1key-bot.service; then
        log_err '原机器人停止结果不确定，正在尝试恢复原状态。'
        restore_custom_bot; return 1
    fi
    if [[ "$mode" == configure ]] && ! printf '%s\n' "$token" "$chat" "$admin" "$npm" "$endpoint" |
        python3 "${SCRIPT_DIR}/lib/crowdsec_bot_settings.py" configure "$CUSTOM_BOT_CONFIG" "$CS_DIR" "$CUSTOM_BOT_STATE" "$CUSTOM_BOT_LEGACY" "$runtime/current/manager.sh" "$MAINTENANCE_LOCK" "$(dirname "$NODE_ROLES_FILE")/firewall-migration"; then
        restore_custom_bot; return 1
    fi
    python_bin=$(command -v python3) || { restore_custom_bot; return 1; }
    if ! MAINTENANCE_RUNTIME="$runtime" install_maintenance_runtime ||
        ! mkdir -p "$(dirname "$CUSTOM_BOT_SCRIPT")" "$(dirname "$CUSTOM_BOT_UNIT")" "$CUSTOM_BOT_STATE" ||
        ! chmod 700 "$CUSTOM_BOT_STATE" || ! cp "${SCRIPT_DIR}/lib/crowdsec_bot.py" "$CUSTOM_BOT_SCRIPT" || ! chmod 755 "$CUSTOM_BOT_SCRIPT"; then
        restore_custom_bot; return 1
    fi
    for helper in "${CUSTOM_BOT_HELPERS[@]}"; do
        target="$(dirname "$CUSTOM_BOT_SCRIPT")/$helper"
        if ! cp "${SCRIPT_DIR}/lib/$helper" "$target" || ! chmod 600 "$target"; then
            restore_custom_bot; return 1
        fi
    done
    if ! cat > "$CUSTOM_BOT_UNIT" <<EOF
# crowdsec-1key-managed-interactive-bot
[Unit]
Description=CrowdBastion optional interactive Telegram bot
After=network-online.target crowdsec.service
Wants=network-online.target

[Service]
Type=simple
ExecStart="$python_bin" "$CUSTOM_BOT_SCRIPT" --config "$CUSTOM_BOT_CONFIG"
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    then restore_custom_bot; return 1; fi
    if ! python3 "$CUSTOM_BOT_SCRIPT" --config "$CUSTOM_BOT_CONFIG" --check-config ||
        ! systemctl daemon-reload; then
        restore_custom_bot; return 1
    fi
    if [[ "$mode" == configure ]] && ! systemctl enable crowdsec-1key-bot.service; then
        restore_custom_bot; return 1
    fi
    if [[ "$mode" == configure || "$CUSTOM_BOT_WAS_ACTIVE" == true ]]; then
        if ! systemctl restart crowdsec-1key-bot.service || ! systemctl is-active --quiet crowdsec-1key-bot.service; then
            restore_custom_bot; return 1
        fi
        if [[ "$mode" == configure ]]; then
            log_succ '交互机器人配置和程序已保存、服务已启动；请在配置的聊天中使用 /start。服务活跃不代表 Telegram 轮询成功。'
        else
            log_succ '交互机器人代码已更新、服务已启动；保留配置和状态。服务活跃不代表 Telegram 轮询成功。'
        fi
    else
        log_succ '交互机器人代码已更新；保留配置、状态及原停用状态，未启动或启用服务。'
    fi
    CUSTOM_BOT_UPDATE_PENDING=false
)

custom_bot_code_status() {
    python3 "${SCRIPT_DIR}/lib/crowdsec_bot_runtime.py" status "$MANAGER_FILE" "$CUSTOM_BOT_SCRIPT" "$(dirname "$CUSTOM_BOT_SCRIPT")/runtime" "${CUSTOM_BOT_HELPERS[@]}"
}

update_custom_bot() {
    check_custom_bot_ownership || return 1
    custom_bot_owned && [[ -f "$CUSTOM_BOT_CONFIG" ]] || { log_err '请先配置本工具机器人。'; return 1; }
    local status=0
    custom_bot_code_status || status=$?
    [[ "$status" == 0 || "$status" == 2 ]] || return 1
    log_info '更新预览：替换机器人程序、辅助模块及随附主脚本；保留配置、轮询进度和审计；原运行服务会短暂停止并重启，原停用服务保持停用。'
    log_info '不会更新定时任务副本；失败恢复原文件、主脚本指针和服务状态。'
    confirm '确认更新本工具机器人代码？' || return 0
    setup_custom_bot keep-config
}

check_custom_bot() {
    if [[ ! -f "$CUSTOM_BOT_CONFIG" ]]; then log_info '交互机器人：未配置（可选）。'; return 2; fi
    local service_status=0 runtime_status=0
    python3 "$CUSTOM_BOT_SCRIPT" --config "$CUSTOM_BOT_CONFIG" --check-config || return 1
    systemctl is-active crowdsec-1key-bot.service || service_status=1
    python3 "$CUSTOM_BOT_SCRIPT" --config "$CUSTOM_BOT_CONFIG" --runtime-status || runtime_status=$?
    log_info '自动告警：关闭，由官方通道推送；轮询及按钮操作请在 TG 实测。'
    custom_bot_conflicts || return 1
    [[ "$service_status" == 0 && "$runtime_status" != 1 ]] || return 1
    [[ "$runtime_status" == 0 ]] && return 0
    return 2
}

disable_custom_bot() {
    check_custom_bot_ownership || return 1
    [[ -f "$CUSTOM_BOT_UNIT" ]] || { log_info '本工具交互机器人未部署。'; return 0; }
    confirm '停用本工具交互机器人？官方通知与旧脚本保留。' || return 0
    systemctl disable --now crowdsec-1key-bot.service || return 1
    log_succ '交互机器人已停用；配置保留供再次启用。'
}

purge_custom_bot() {
    [[ -e "$CUSTOM_BOT_UNIT" || -L "$CUSTOM_BOT_UNIT" ]] || return 0
    check_custom_bot_ownership || return 1
    if custom_bot_owned; then
        local helper runtime
        runtime="$(dirname "$CUSTOM_BOT_SCRIPT")/runtime" || return 1
        if [[ -e "$runtime" || -L "$runtime" ]]; then
            maintenance_tool runtime-preflight "$runtime" || return 1
        fi
        local -a paths=("$CUSTOM_BOT_UNIT" "$CUSTOM_BOT_SCRIPT")
        for helper in "${CUSTOM_BOT_HELPERS[@]}"; do paths+=("$(dirname "$CUSTOM_BOT_SCRIPT")/$helper"); done
        systemctl disable --now crowdsec-1key-bot.service || return 1
        rm -f -- "${paths[@]}" || return 1
        rm -rf -- "$CUSTOM_BOT_STATE" || return 1
        if [[ -d "$runtime" ]]; then rm -rf -- "$runtime" || return 1; fi
    fi
}

manage_custom_bot() {
    local choice
    while true; do
        printf '\n可选交互机器人\n1. 配置/更新并启用\n2. 只读检查\n3. 停用交互机器人\n4. 只读代码版本检查\n5. 保留配置更新代码\n0. 返回\n'
        prompt choice '请选择 [0-5]: ' || return 0
        case "$choice" in
            1) setup_custom_bot ;;
            2) check_custom_bot ;;
            3) disable_custom_bot ;;
            4) custom_bot_code_status ;;
            5) update_custom_bot ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
        pause
    done
}

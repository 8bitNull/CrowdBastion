#!/usr/bin/env bash
# Independent opt-in network configuration. Default setup/optimize never calls it.
network_tool() {
    PYTHONDONTWRITEBYTECODE=1 python3 "${SCRIPT_DIR}/lib/crowdbastion_network.py" "$@" \
        --config /var/lib/crowdbastion/network.json --manager "${SCRIPT_DIR}/crowdbastion.sh" \
        --runtime "$MAINTENANCE_RUNTIME" --cron "$CRON_FILE"
}

manage_network_configuration() { manage_change_configuration network '可选 TCP 默认值恢复'; }

# Menus keep read-only inspection outside the lock and acquire it only for the
# selected mutation, using the same confirmation and guard as the main CLI.
manage_change_configuration() {
    local kind="$1" title="$2" choice action
    [[ "$kind" == network || "$kind" == port-policy ]] || return 1
    while true; do
        printf '\n%s\n默认安装不调整此策略；需先准备私有 JSON。\n1. 查看当前状态\n2. 查看只读计划\n3. 应用并暂存（需确认）\n4. 独立核验\n5. 重新核验并提交\n6. 回退未提交事务\n0. 返回\n' "$title"
        prompt choice '请选择 [0-6]: ' || return 0
        case "$choice" in
            1) change_human_action "$kind" status ;;
            2) change_human_action "$kind" plan ;;
            3) action=apply ;;
            4) action=verify ;;
            5) action=commit ;;
            6) action=rollback ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        if [[ "$choice" == [3-6] ]]; then
            case "$kind" in
                network) locked_operation network_action "$action" ;;
                port-policy) locked_operation port_policy_action "$action" ;;
            esac
        fi
        pause
    done
}
network_action() {
    change_configuration_action network "$1" \
        '恢复已选 TCP 项的本机内核默认值？未提交变更将在 15 分钟后自动回退。'
}

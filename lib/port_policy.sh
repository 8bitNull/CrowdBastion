#!/usr/bin/env bash
# Fixed private profile keeps the main CLI's single-operation convention.
port_policy_tool() {
    PYTHONDONTWRITEBYTECODE=1 python3 "${SCRIPT_DIR}/lib/crowdbastion_port_policy.py" "$@" --config /var/lib/crowdbastion/port-policy.json
}

manage_port_policy() { manage_change_configuration port-policy '选定入口端口策略'; }
port_policy_action() {
    change_configuration_action port-policy "$1" \
        '应用已选端口策略？未提交的变更将在 15 分钟后自动回退。'
}

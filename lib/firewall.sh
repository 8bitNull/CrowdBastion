#!/usr/bin/env bash
# Startup changes use the existing manager transaction and private backups.
FIREWALL_DROPIN="${FIREWALL_DROPIN:-/etc/systemd/system/crowdsec-firewall-bouncer.service.d/20-crowdbastion-docker-order.conf}"

firewall_migration_pending() {
    [[ -d "$FIREWALL_MIGRATION_STATE" && ! -f "$FIREWALL_MIGRATION_STATE/committed" && ! -f "$FIREWALL_MIGRATION_STATE/rolled-back" ]]
}

check_firewall_runtime() {
    require_yaml || return 1
    python3 "${SCRIPT_DIR}/lib/crowdsec_firewall_runtime.py" audit "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml"
}

firewall_write_startup() {
    python3 "${SCRIPT_DIR}/lib/crowdsec_firewall_runtime.py" write-startup "$1" --dropin "$FIREWALL_DROPIN"
}

repair_firewall_startup() (
    require_yaml && require_commands systemctl || return 1
    local cfg="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" committed=false changed=false
    # shellcheck disable=SC2329
    firewall_startup_exit() {
        local result=$?
        trap - EXIT INT TERM
        if [[ "$changed" == true && "$committed" != true ]]; then
            if ! restore_config_change || ! systemctl daemon-reload || ! systemctl restart crowdsec-firewall-bouncer; then
                log_err '防火墙启动配置回滚未完成，请核对修改前备份。'
            fi
        fi
        exit "$result"
    }
    python3 "${SCRIPT_DIR}/lib/crowdsec_firewall.py" guard "$cfg" || return 1
    systemctl is-active --quiet crowdsec-firewall-bouncer || return 1
    begin_config_change "${cfg}.local" "$FIREWALL_DROPIN" || return 1
    trap firewall_startup_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    changed=true
    firewall_write_startup "$cfg" || return 1
    if cmp -s "${BACKUP_COPIES[0]}" "${cfg}.local" && { cmp -s "${BACKUP_COPIES[1]}" "$FIREWALL_DROPIN" || { [[ -f "${BACKUP_COPIES[1]}.absent" && ! -e "$FIREWALL_DROPIN" ]]; }; } && check_firewall_runtime; then
        committed=true
        log_info '启动配置未变化，跳过重启。'
        return 0
    fi
    systemctl daemon-reload && systemctl restart crowdsec-firewall-bouncer &&
        systemctl is-active --quiet crowdsec-firewall-bouncer || return 1
    # The check reports cron conflicts but never edits administrator jobs.
    local status=0
    check_firewall_runtime || status=$?
    [[ "$status" == 0 ]] || return "$status"
    committed=true
    log_succ '双栈防火墙链与 Docker 启动顺序已配置；未修改开机任务。'
)

manage_firewall_maintenance() {
    local choice
    printf '\n防火墙维护\n1. 只读检查开机任务、启动顺序与双栈链\n2. 修复 iptables 双栈链和 Docker 启动顺序\n3. 迁移 nftables 至 iptables/ipset（8 分钟自动回退）\n4. 验收本次迁移的本机封禁、续封、删除与到期\n5. 从新 SSH 连接提交本次迁移\n6. 回退未提交的迁移\n0. 返回\n'
    prompt choice '请选择 [0-6]: ' || return 1
    case "$choice" in
        0) return 0 ;;
        1) check_firewall_runtime ;;
        2)
            if firewall_migration_pending; then log_err '防火墙迁移尚未结束，请先验收提交或回退。'; return 75; fi
            repair_firewall_startup ;;
        3|4|5|6)
            require_yaml || return 1
            local action
            case "$choice" in 3) action=start ;; 4) action=verify ;; 5) action=commit ;; 6) action=rollback ;; esac
            python3 "${SCRIPT_DIR}/lib/crowdsec_firewall_migrate.py" "$action"
            ;;
        *) log_err '无效选项。'; return 1 ;;
    esac
}

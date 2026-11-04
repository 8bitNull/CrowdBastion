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

existing_deployment_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_existing_deployment.py" "$@"; }
wait_firewall_decisions() { python3 "${SCRIPT_DIR}/lib/crowdsec_firewall_evidence.py" "$1" --wait 30; }

repair_existing_deployment() (
    if [[ "${MAINTENANCE_LOCK_HELD:-}" != true ]]; then locked_operation repair_existing_deployment "$@"; return $?; fi
    local cfg="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" plan rows index family backup result=0
    local cron_backups=() completed=false
    check_firewall_runtime || true
    plan=$(existing_deployment_tool plan "$cfg") || return 1
    printf '%s\n' "$plan" | python3 -c 'import json,sys; p=json.load(sys.stdin); print("修复范围：保留自定义链，补齐双栈入口与 Docker 启动顺序；备份后仅重启 Bouncer，限时等待决策同步。"); print("已发现开机规则风险：", len(p["cron_risks"])); print("需要人工处理的恢复服务：", ", ".join(p["restore_services"]) or "无")' || return 1
    confirm '现在备份并修复已有防火墙部署？' || return 0
    environment_change_guard || return $?
    # Each selected crontab transition has its own private backup, restored in
    # reverse order only if the current content still matches our after state.
    existing_repair_exit() {
        local code=$? i
        trap - EXIT INT TERM
        if [[ "$completed" != true ]]; then
            for ((i=${#cron_backups[@]}-1; i>=0; i--)); do
                existing_deployment_tool cron-restore "${cron_backups[i]}" || { log_err '定时任务恢复未完成，请核对备份及外部修改。'; code=1; }
            done
        fi
        exit "$code"
    }
    trap existing_repair_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    rows=$(existing_deployment_tool cron-list) || return 1
    rows=$(printf '%s\n' "$rows" | python3 -c 'import json,sys; [print(str(r["index"])+"\t"+r["family"]) for r in json.load(sys.stdin)]') || return 1
    while IFS=$'\t' read -r index family <&8; do
        [[ -n "$index" ]] || continue
        printf 'root 开机任务第 %s 行：恢复旧 %s 规则快照，可能覆盖动态封禁和 Docker 规则。\n' "$index" "$family"
        if confirm '停用这一项并保留原文备份？'; then
            local cron_root="${UPDATE_BACKUPS}/existing-deployment"
            maintenance_tool runtime-preflight "$cron_root" || return 1
            mkdir -p "$cron_root" && chmod 700 "$cron_root" || return 1
            (umask 077; touch "$cron_root/.crowdsec-1key-managed") || return 1
            backup=$(mktemp -d "${cron_root}/cron.XXXXXXXX") || return 1
            cron_backups+=("$backup")
            existing_deployment_tool cron-disable "$backup" "$index" || return 1
            log_info "开机任务备份：$backup"
        fi
    done 8<<< "$rows"
    # Remaining unknown jobs/services block automatic repair rather than
    # leaving a configuration which will fail the startup check afterwards.
    existing_deployment_tool plan "$cfg" | python3 -c 'import json,sys; p=json.load(sys.stdin); sys.exit(1 if p["cron_risks"] or p["restore_services"] else 0)' || { log_err '仍有开机恢复冲突，请人工处理后重试。'; return 1; }
    repair_firewall_startup || result=$?
    [[ "$result" == 0 ]] || return "$result"
    completed=true
    if ((${#cron_backups[@]})); then health_note_change; fi
    log_succ '已有部署修复及运行复查完成；公网真实拦截仍需独立验收。'
)

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
    wait_firewall_decisions "$cfg" || return 1
    # The check reports cron conflicts but never edits administrator jobs.
    local status=0
    check_firewall_runtime || status=$?
    [[ "$status" == 0 ]] || return "$status"
    committed=true
    health_note_change
    log_succ '双栈防火墙链与 Docker 启动顺序已配置；未修改开机任务。'
)

manage_firewall_maintenance() {
    local choice
    printf '\n防火墙维护\n1. 只读检查开机任务、启动顺序与双栈链\n2. 修复 iptables 双栈链和 Docker 启动顺序\n3. 迁移 nftables 至 iptables/ipset（8 分钟自动回退）\n4. 验收本次迁移的本机封禁、续封、删除与到期\n5. 从新 SSH 连接提交本次迁移\n6. 回退未提交的迁移\n7. 检查并修复已有部署（逐项确认旧开机任务）\n0. 返回\n'
    prompt choice '请选择 [0-7]: ' || return 1
    case "$choice" in
        0) return 0 ;;
        1) check_firewall_runtime ;;
        7)
            if firewall_migration_pending; then log_err '请先完成或回退现有迁移。'; return 75; fi
            repair_existing_deployment ;;
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

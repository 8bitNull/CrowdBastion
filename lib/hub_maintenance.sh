#!/usr/bin/env bash
# One Hub transaction lifecycle for updates, removals and deferred installs.
HUB_TX_BACKUP=''
HUB_TX_FD=''
HUB_TX_ACTION=''
HUB_TX_AFTER=false
HUB_TX_CONFIG=false
CORE_CONFIG_LOADING=''
CORE_CONFIG_TRACKING=false
CORE_CONFIG_PENDING=false

hub_release() {
    if [[ -n "$HUB_TX_FD" ]]; then exec {HUB_TX_FD}>&-; fi
    HUB_TX_FD=''
    HUB_TX_BACKUP=''
    HUB_TX_ACTION=''
    HUB_TX_AFTER=false
    HUB_TX_CONFIG=false
    CORE_CONFIG_LOADING=''
    # Shared with the installation/configuration workflows.
    # shellcheck disable=SC2034
    CORE_RULES_CHANGED=false
}

hub_event() {
    local log="${UPDATE_LOG:-${HUB_LOG_FILE:-/var/log/crowdsec-1key-update.log}}"
    mkdir -p -- "$(dirname "$log")" || return 1
    (umask 077; touch "$log") && chmod 600 "$log" || return 1
    printf '%s action=%s %s\n' "$(date -u +%FT%TZ)" "$HUB_TX_ACTION" "$*" >> "$log"
}

hub_begin() {
    require_core && require_yaml && require_commands flock || return 1
    if [[ -n "$HUB_TX_BACKUP" ]]; then
        [[ "$HUB_TX_ACTION" == install && "$1" == install ]] && return 0
        log_err '已有尚未提交的 Hub 事务，未开始其他维护。'
        return 75
    fi
    HUB_TX_ACTION="$1"
    CORE_CONFIG_LOADING=''
    mkdir -p -- "$(dirname "$HUB_LOCK_FILE")" || return 1
    exec {HUB_TX_FD}>"$HUB_LOCK_FILE" || return 1
    if ! flock -n "$HUB_TX_FD"; then
        hub_event 'outcome=busy' || true
        hub_release
        log_warn '已有 Hub 维护任务，跳过本次操作。'
        return 75
    fi
    if [[ "$1" != install ]] && ! systemctl is-active --quiet crowdsec; then
        hub_release
        log_err '核心未运行，未执行 Hub 维护。'
        return 1
    fi
    if ! crowdsec -t; then hub_release; return 1; fi
    mkdir -p "$UPDATE_BACKUPS" || { hub_release; return 1; }
    HUB_TX_BACKUP=$(mktemp -d "${UPDATE_BACKUPS}/hub.XXXXXXXX") || { hub_release; return 1; }
    if ! chmod 700 "$HUB_TX_BACKUP" || ! maintenance_tool snapshot "${CS_DIR}/config.yaml" "$HUB_TX_BACKUP"; then
        hub_event 'outcome=snapshot-failed' || true
        log_err "Hub 快照失败，未修改规则；保留诊断目录：${HUB_TX_BACKUP}"
        hub_release
        return 1
    fi
    HUB_TX_AFTER=false
    if ! hub_event "outcome=started snapshot=${HUB_TX_BACKUP}"; then hub_release; return 1; fi
    log_info "Hub ${HUB_TX_ACTION} 开始；规则备份：${HUB_TX_BACKUP}"
}

hub_record_after() {
    [[ -n "$HUB_TX_BACKUP" ]] || return 0
    maintenance_tool after "$HUB_TX_BACKUP" || return 1
    HUB_TX_AFTER=true
}

hub_workflow_exit() {
    local result=$? operation="${CORE_CONFIG_LOADING:-}" config_restored=true hub_restored=true
    trap - EXIT INT TERM
    if [[ -n "$HUB_TX_BACKUP" || "$CORE_CONFIG_PENDING" == true ]]; then
        if [[ "$HUB_TX_CONFIG" == true || "$CORE_CONFIG_PENDING" == true ]]; then
            restore_config_change || { config_restored=false; log_err '配置恢复失败，请核对修改前备份。'; }
        fi
        # Restore disk before loading it, including interruptions during service loading.
        hub_abort no-load || hub_restored=false
        if [[ "$hub_restored" == true && "$config_restored" == true && -n "$operation" ]]; then
            if ! crowdsec -t || ! systemctl "$operation" crowdsec || ! systemctl is-active --quiet crowdsec; then
                log_err 'Hub 与配置已尝试恢复，但核心加载失败，请手工核验。'
            fi
        fi
    fi
    if [[ "$CORE_CONFIG_TRACKING" == true ]]; then cleanup_log_repair; fi
    exit "$result"
}

hub_abort() {
    [[ -n "$HUB_TX_BACKUP" ]] || return 0
    local backup="$HUB_TX_BACKUP" result=0
    # Preserve the captured post-mutation state; do not absorb later external changes.
    if [[ "$HUB_TX_AFTER" != true ]] && ! hub_record_after; then
        result=1
    elif ! maintenance_tool restore "$backup"; then
        result=1
    elif ! crowdsec -t; then
        result=1
    elif [[ "${1:-reload}" != no-load ]]; then
        if ! systemctl reload crowdsec || ! systemctl is-active --quiet crowdsec; then result=1; fi
    fi
    if [[ "$result" == 0 ]]; then
        hub_event "outcome=failure rollback=restored snapshot=${backup}" || true
        log_warn "Hub 操作失败，原规则和下载数据已恢复：${backup}"
    else
        hub_event "outcome=failure rollback=failed snapshot=${backup}" || true
        log_err "Hub 回滚未完成或检测到外部修改，请使用 ${backup} 手动核对恢复。"
    fi
    hub_release
    return "$result"
}

hub_finalize() {
    [[ -n "$HUB_TX_BACKUP" ]] || return 0
    local backup="$HUB_TX_BACKUP"
    touch "$backup/.successful" || return 1
    hub_event "outcome=success snapshot=${backup}" || { rm -f "$backup/.successful"; return 1; }
    # Loading has succeeded: mark configuration committed before releasing Hub
    # state and running interruptible snapshot cleanup. Inventory-only installs
    # can finalize earlier, while configuration still awaits its final load.
    if [[ -n "$CORE_CONFIG_LOADING" ]]; then CORE_CONFIG_PENDING=false; fi
    hub_release
    maintenance_tool prune-snapshots "$UPDATE_BACKUPS" || log_warn '旧成功快照清理失败，请检查备份目录。'
}

hub_commit() {
    local comparison=0
    crowdsec -t || { hub_abort no-load; return 1; }
    maintenance_tool changed "$HUB_TX_BACKUP" || comparison=$?
    if [[ "$comparison" == 0 ]]; then
        if ! systemctl reload crowdsec || ! systemctl is-active --quiet crowdsec; then hub_abort; return 1; fi
    elif [[ "$comparison" == 1 ]]; then
        log_info 'Hub 内容未变化，跳过重载。'
    else
        hub_abort
        return 1
    fi
    hub_finalize || { hub_abort; return 1; }
}

hub_maintenance() (
    local action="${1:-}" result=0
    case "$action" in update) ;; remove) [[ $# -gt 1 ]] || return 1 ;; *) log_err '不支持的 Hub 操作。'; return 1 ;; esac
    shift
    if [[ "${MAINTENANCE_LOCK_HELD:-}" != true ]]; then
        require_commands flock || return 1
        mkdir -p "$(dirname "$MAINTENANCE_LOCK")" || return 1
        exec 9> "$MAINTENANCE_LOCK" || return 1
        flock -n 9 || { log_warn '已有管理操作，跳过本次 Hub 维护。'; return 75; }
    fi
    if declare -F firewall_migration_pending >/dev/null && firewall_migration_pending; then
        log_warn '防火墙迁移尚未结束，跳过 Hub 维护。'; return 75
    fi
    trap 'hub_abort || true' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    hub_begin "$action" || return $?
    case "$action" in
        update) cscli hub update && cscli hub upgrade || result=$? ;;
        remove) cscli collections remove "$@" || result=$? ;;
    esac
    hub_record_after || return 1
    [[ "$result" == 0 ]] || return "$result"
    hub_commit
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    HUB_ENTRY_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
    if [[ -f "$HUB_ENTRY_ROOT/manager.sh" ]]; then
        # shellcheck source=/dev/null
        source "$HUB_ENTRY_ROOT/manager.sh"
    else
        # shellcheck source=/dev/null
        source "$HUB_ENTRY_ROOT/crowdbastion.sh"
    fi
    case "${1:-update}" in
        update) main --update-hub ;;
        remove) check_root && hub_maintenance "$@" ;;
        *) log_err '用法：hub_maintenance.sh [update | remove 集合...]'; exit 1 ;;
    esac
fi

#!/usr/bin/env bash
# Independent, installed cron runner and shared interactive Hub transaction.
hub_maintenance() (
    umask 077
    local helper_dir="${HUB_HELPER_DIR:-${SCRIPT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}/lib}"
    local config="${CS_DIR:-/etc/crowdsec}/config.yaml"
    local lock="${HUB_LOCK_FILE:-/run/lock/crowdsec-1key-hub.lock}" log="${HUB_LOG_FILE:-/var/log/crowdsec-1key-hub.log}"
    local snapshot action="${1:-}" outcome='failure' rollback='not-needed'
    hub_command() { "$@" >> "$log" 2>&1; }
    mkdir -p -- "$(dirname "$lock")" "$(dirname "$log")" || return 1
    if ! command -v flock >/dev/null 2>&1; then
        printf 'Hub: missing flock; no mutation performed.\n' >&2
        printf '%s action=%s outcome=preflight-failed dependency=flock\n' "$(date -u +%FT%TZ)" "$action" >> "$log"
        return 1
    fi
    if ! python3 -c 'import yaml' >> "$log" 2>&1; then
        printf 'Hub: Python3/PyYAML preflight failed; no mutation performed.\n' >&2
        printf '%s action=%s outcome=preflight-failed dependency=python3-pyyaml\n' "$(date -u +%FT%TZ)" "$action" >> "$log"
        return 1
    fi
    exec 9>"$lock" || return 1
    if ! flock -n 9; then printf '%s action=%s outcome=busy\n' "$(date -u +%FT%TZ)" "$1" >> "$log"; return 1; fi
    snapshot=$(mktemp "${TMPDIR:-/tmp}/crowdsec-hub-snapshot.XXXXXXXX") || return 1
    trap 'if [[ "$outcome" == success || "$rollback" == restored ]]; then rm -f -- "$snapshot"; else printf "Hub snapshot retained: %s\n" "$snapshot" >&2; printf "snapshot=%s\n" "$snapshot" >> "$log"; fi' EXIT
    if ! hub_command python3 "$helper_dir/crowdsec_hub_snapshot.py" before "$config" "$snapshot"; then
        printf '%s action=%s outcome=snapshot-failed\n' "$(date -u +%FT%TZ)" "$action" >> "$log"
        return 1
    fi
    local rc=0
    case "${1:-}" in
        update) hub_command cscli hub update && hub_command cscli hub upgrade || rc=$? ;;
        remove) shift; [[ $# -gt 0 ]] || return 1; hub_command cscli collections remove "$@" || rc=$? ;;
        *) printf 'Hub: unsupported action\n' >&2; return 1 ;;
    esac
    if [[ "$rc" == 0 ]]; then hub_command crowdsec -t && hub_command systemctl reload crowdsec || rc=$?; fi
    if [[ "$rc" == 0 ]]; then
        outcome=success
    else
        rollback=failed
        if hub_command python3 "$helper_dir/crowdsec_hub_snapshot.py" after "$config" "$snapshot" && hub_command python3 "$helper_dir/crowdsec_hub_snapshot.py" restore "$config" "$snapshot"; then
            rollback=restored
            if ! hub_command crowdsec -t; then rollback=restored-validation-failed
            elif ! hub_command systemctl reload crowdsec; then rollback=restored-reload-failed; fi
        fi
    fi
    printf '%s action=%s outcome=%s rollback=%s\n' "$(date -u +%FT%TZ)" "$action" "$outcome" "$rollback" >> "$log" || return 1
    printf 'Hub action=%s outcome=%s rollback=%s log=%s\n' "$action" "$outcome" "$rollback" "$log"
    [[ "$rc" == 0 ]]
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    HUB_HELPER_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    hub_maintenance "${1:-update}"
fi

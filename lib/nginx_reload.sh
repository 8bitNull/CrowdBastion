#!/usr/bin/env bash
# A successful signal/config test does not prove init_by_lua accepted a reload.
# Docker top returns host PIDs, including masters below container supervisors.
# KILL at the deadline bounds TERM-ignoring commands and their owned process group;
# do not use --foreground (it leaves command children outside timeout control).
nginx_monotonic_us() { python3 -c 'import time; print(time.monotonic_ns() // 1000)'; }
nginx_reload_tool() { timeout --signal=KILL "$1" python3 "${SCRIPT_DIR}/lib/crowdsec_nginx_reload.py" "${@:2}"; }

nginx_reload_log_source() {
    local service=$1 container=$2 master=$3 effective=$4
    if [[ "$service" == docker ]]; then
        timeout --signal=KILL 10 docker exec "$container" nginx -T > "$effective" 2>/dev/null || return 1
    else
        timeout --signal=KILL 10 "$service" -T > "$effective" 2>/dev/null || return 1
    fi
    nginx_reload_tool 2 locate "$master" "$effective"
}

nginx_process_snapshot() {
    local service=$1 container=$2 master='' table deadline now remaining limit
    now=$(nginx_monotonic_us) || return 1
    deadline=${3:-$((now + 2000000))}
    remaining=$((deadline - now))
    (( remaining > 0 )) || return 1
    printf -v limit '%d.%06d' "$((remaining / 1000000))" "$((remaining % 1000000))"
    if [[ "$service" == docker ]]; then
        table=$(timeout --signal=KILL "$limit" docker top "$container" -eo pid,ppid,stat,args) || return 1
    else
        master=$(timeout --signal=KILL "$limit" systemctl show "$service" --property MainPID --value) || return 1
        [[ "$master" =~ ^[1-9][0-9]*$ ]] || return 1
        now=$(nginx_monotonic_us) || return 1; remaining=$((deadline - now))
        (( remaining > 0 )) || return 1
        printf -v limit '%d.%06d' "$((remaining / 1000000))" "$((remaining % 1000000))"
        table=$(timeout --signal=KILL "$limit" ps -eo pid,ppid,stat,args) || return 1
    fi
    printf '%s\n' "$table" | awk -v wanted="$master" '
        $1 ~ /^[0-9]+$/ && $3 !~ /[ZX]/ {
            if ($4 == "nginx:" && $5 == "master" && $6 == "process" && (wanted == "" || $1 == wanted)) {
                master=$1; masters++
            }
            if ($4 == "nginx:" && $5 == "worker" && $6 == "process" && $7 != "is") parent[$1]=$2
        }
        END {
            if (masters != 1) exit 1
            print "master", master
            count=0
            for (pid in parent) if (parent[pid] == master) { print "worker", pid; count++ }
            if (!count) exit 1
        }' | sort -k1,1 -k2,2n
    return "${PIPESTATUS[1]}"
}

nginx_reload_verified() (
    local service=$1 container=${2:-} before after master old_workers workers previous='' deadline now remaining
    local work source log_fd log_ref witness_status limit worker_pids=()
    work=$(mktemp -d) || return 1
    chmod 700 "$work" || { rm -rf -- "$work"; return 1; }
    trap 'rm -rf -- "$work"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    before=$(nginx_process_snapshot "$service" "$container") || {
        log_err '无法确认 Nginx master/worker 进程，未发送重载。'; return 1;
    }
    master=${before%%$'\n'*}
    old_workers=$'\n'${before#*$'\n'}$'\n'
    source=$(nginx_reload_log_source "$service" "$container" "${master#master }" "$work/effective") || return 1
    # Keep the original inode open across reload/rename; never follow a new
    # pathname containing old or unrelated success records.
    exec {log_fd}< "$source" || return 1
    log_ref="/proc/${BASHPID}/fd/${log_fd}"
    if [[ "$service" == docker ]]; then
        timeout --signal=KILL 10 docker exec "$container" nginx -t || return 1
    else
        timeout --signal=KILL 10 "$service" -t || return 1
    fi
    nginx_reload_tool 2 capture "${master#master }" "$log_ref" > "$work/cursor" || return 1
    if [[ "$service" == docker ]]; then
        timeout --signal=KILL 10 docker exec "$container" nginx -s reload || return 1
    else timeout --signal=KILL 10 systemctl reload "$service" || return 1
    fi
    now=$(nginx_monotonic_us) || return 1; deadline=$((now + 10000000))
    while :; do
        now=$(nginx_monotonic_us) || return 1; remaining=$((deadline - now))
        (( remaining > 0 )) || break
        after=$(nginx_process_snapshot "$service" "$container" "$deadline") || {
            log_err '重载后无法确认 Nginx master/worker 进程。'; return 1;
        }
        now=$(nginx_monotonic_us) || return 1
        (( now < deadline )) || break
        [[ "${after%%$'\n'*}" == "$master" ]] || {
            log_err '重载期间 Nginx master 已变化，未确认本次配置。'; return 1;
        }
        workers=${after#*$'\n'}
        local worker fresh=true
        while IFS= read -r worker; do
            if [[ "$old_workers" == *$'\n'"$worker"$'\n'* ]]; then fresh=false; fi
        done <<< "$workers"
        if [[ "$fresh" == true && "$workers" == "$previous" ]]; then
            worker_pids=()
            while IFS= read -r worker; do worker_pids+=("${worker#worker }"); done <<< "$workers"
            now=$(nginx_monotonic_us) || return 1; remaining=$((deadline - now))
            (( remaining > 0 )) || break
            printf -v limit '%d.%06d' "$((remaining / 1000000))" "$((remaining % 1000000))"
            nginx_reload_tool "$limit" check "$work/cursor" "$log_ref" "${worker_pids[@]}"
            witness_status=$?
            now=$(nginx_monotonic_us) || return 1
            (( now < deadline )) || break
            [[ "$witness_status" != 0 ]] || return 0
            [[ "$witness_status" == 2 ]] || return 1
        fi
        previous=''
        [[ "$fresh" != true ]] || previous=$workers
        now=$(nginx_monotonic_us) || return 1
        (( deadline - now >= 200000 )) || break
        sleep 0.2
    done
    log_err '10 秒内未同时确认稳定的新 Nginx workers 及 master 接受重载的记录，重载未被证实。'
    return 1
)

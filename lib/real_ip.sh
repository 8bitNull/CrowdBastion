#!/usr/bin/env bash
# Dedicated real-IP configuration; existing custom trust rules remain untouched.
real_ip_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_realip.py" "$@"; }

repair_cloudflare_real_ip() (
    local operation="${1:-apply}"
    require_core && require_commands docker python3 curl || return 1
    local NATIVE_ID NATIVE_NAME selected work target changed=false committed=false
    select_native_container
    selected=$?
    [[ "$selected" == 2 ]] && return 0
    [[ "$selected" == 0 ]] || return 1
    work=$(mktemp -d) || return 1
    # shellcheck disable=SC2329 # invoked by EXIT trap
    real_ip_exit() {
        local result=$?
        trap - EXIT INT TERM
        if [[ "$changed" == true && "$committed" != true ]]; then
            if restore_config_change; then
                if ! docker exec "$NATIVE_ID" nginx -t || ! docker exec "$NATIVE_ID" nginx -s reload; then
                    log_err '原配置已恢复但重载失败，请使用修改前备份核对运行配置。'
                fi
            else
                log_err '恢复配置失败，请使用修改前备份人工恢复。'
            fi
        fi
        rm -rf -- "$work"
        exit "$result"
    }
    trap real_ip_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    docker inspect --format '{{json .Mounts}}' "$NATIVE_ID" > "$work/mounts" || return 1
    if [[ "$operation" == remove ]]; then
        real_ip_tool restore-plan "$REALIP_STATE" "$NATIVE_NAME" "$work/mounts" "$work/plan" || return 1
    else
        docker exec "$NATIVE_ID" nginx -T > "$work/effective" 2>&1 || return 1
        docker exec "$NATIVE_ID" nginx -V > "$work/version" 2>&1 || return 1
        if ! grep -q -- '--with-http_realip_module' "$work/version" && ! grep -Eq 'load_module[^;]*ngx_http_realip_module' "$work/effective"; then
            log_err '运行时未发现 HTTP real-IP 模块，未修改配置。'
            return 1
        fi
        curl -fL --connect-timeout 10 --max-time 30 https://www.cloudflare.com/ips-v4 -o "$work/ipv4" || return 1
        curl -fL --connect-timeout 10 --max-time 30 https://www.cloudflare.com/ips-v6 -o "$work/ipv6" || return 1
        real_ip_tool plan "$work/effective" "$work/mounts" "$work/ipv4" "$work/ipv6" "$REALIP_STATE" "$NATIVE_NAME" "$work/plan" || return 1
    fi
    target=$(web_tool get "$work/plan" host_target) || return 1
    log_info "真实 IP 持久化配置：${target}"
    if [[ "$operation" == remove ]]; then
        confirm "移除 ${NATIVE_NAME} 的本工具 Cloudflare 真实 IP 配置并重载？" || return 0
    else
        log_info '只信任 Cloudflare 官方网段，用 CF-Connecting-IP 改写 remote_addr；不修改白名单、日志采集或 WAF 钩子。'
        log_warn 'Cloudflare Tunnel 的 loopback/内网连接需另行核对；该入口不会自动信任本机或内网来源。'
        confirm "为 ${NATIVE_NAME} 应用/更新 Cloudflare 真实 IP 配置并重载？" || return 0
    fi
    begin_config_change "$target" "$REALIP_STATE" || return 1
    changed=true
    if [[ "$operation" == remove ]]; then
        real_ip_tool remove "$REALIP_STATE" "$NATIVE_NAME" || return 1
    else
        real_ip_tool apply "$work/plan" "$REALIP_STATE" "$NATIVE_NAME" || return 1
    fi
    docker exec "$NATIVE_ID" nginx -t && docker exec "$NATIVE_ID" nginx -s reload || return 1
    committed=true
    log_succ '真实 IP 配置已校验并重载；请从外部访问实际站点，并核对日志首字段及 Bouncer 使用的访客 IP。'
)

#!/usr/bin/env bash
# Dedicated real-IP configuration; existing custom trust rules remain untouched.
real_ip_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_realip.py" "$@"; }

repair_cloudflare_real_ip() (
    local operation="${1:-apply}"
    require_core && require_commands docker python3 curl || return 1
    local NATIVE_ID NATIVE_NAME selected work target provider header ranges scope changed=false committed=false
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
        real_ip_tool discover "$work/effective" || return 1
        printf '1. Cloudflare 公网节点直接接入（官方网段 + CF-Connecting-IP）\n2. 已核对的其他 CDN/反向代理（明确 Header 和可信网段）\n0. 取消\n'
        prompt provider '请选择实际接入类型 [0-2]: ' || return 0
        case "$provider" in
            1)
                curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 30 https://www.cloudflare.com/ips-v4 -o "$work/ipv4" || return 1
                curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 30 https://www.cloudflare.com/ips-v6 -o "$work/ipv6" || return 1
                real_ip_tool plan "$work/effective" "$work/mounts" "$work/ipv4" "$work/ipv6" "$REALIP_STATE" "$NATIVE_NAME" "$work/plan" || return 1 ;;
            2)
                prompt header '输入上游约定的 IP Header（如 X-Forwarded-For；不支持 RFC Forwarded）: ' || return 0
                [[ -n "$header" ]] || return 0
                log_warn '只填写你控制或已核对的代理来源网段；内网仅接受 IPv4 /24 或更窄、IPv6 /64 或更窄，回环需单个地址。'
                prompt ranges '可信代理 IP/CIDR（空格分隔，留空取消）: ' || return 0
                [[ -n "$ranges" ]] || return 0
                real_ip_tool plan-custom "$work/effective" "$work/mounts" "$header" "$ranges" "$REALIP_STATE" "$NATIVE_NAME" "$work/plan" || return 1 ;;
            0|'') return 0 ;;
            *) log_err '接入类型无效，未修改配置。'; return 1 ;;
        esac
    fi
    target=$(web_tool get "$work/plan" host_target) || return 1
    log_info "真实 IP 持久化配置：${target}"
    if [[ "$operation" == remove ]]; then
        confirm "撤销 ${NATIVE_NAME} 的本工具真实 IP 配置并重载？" || return 0
    else
        header=$(web_tool get "$work/plan" header) || return 1
        ranges=$(web_tool get "$work/plan" ranges) || return 1
        scope=$(web_tool get "$work/plan" scope) || return 1
        log_info "选定 Header：${header}；可信来源：${ranges}"
        log_info '仅使用选定 Header，不尝试其他候选；缺失或无法提取有效 IP 时保留连接来源 IP。X-Forwarded-For 按可信代理从右向左处理。'
        if [[ "$scope" == npm-proxy-hosts ]]; then
            log_warn '作用于加载 server_proxy.conf 的全部 NPM Proxy Host；在站点层使用上述网段，保留原自定义内容及 HTTP 层配置。'
        else
            log_info '作用于该容器 HTTP 层；保留现有 WAF、日志采集与白名单。'
        fi
        log_warn 'Cloudflare Tunnel 的 loopback/内网连接需另行核对；该入口不会自动信任本机或内网来源。'
        confirm "确认上述代理来源、Header 和作用范围，为 ${NATIVE_NAME} 应用/更新并重载？" || return 0
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
    log_info '从另一台设备访问正常页面，附加唯一查询参数（如 ?crowdsec_ip_check=你选定的标识），在对应 access.log 关联该行并核对设备公网 IP；不要用 localhost 攻击路径验证。'
)

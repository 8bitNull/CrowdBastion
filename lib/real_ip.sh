#!/usr/bin/env bash
# Dedicated real-IP configuration; existing custom trust rules remain untouched.
real_ip_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_realip.py" "$@"; }
request_audit_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_request_audit.py" "$@"; }

real_ip_select_runtime() {
    if [[ "${1:-}" == host ]]; then
        prompt REALIP_HOST_SERVICE '选择宿主机服务 [nginx/openresty]（留空取消）: ' || return 2
        [[ -n "$REALIP_HOST_SERVICE" ]] || return 2
        case "$REALIP_HOST_SERVICE" in nginx|openresty) ;; *) log_err '服务选择无效。'; return 1 ;; esac
        require_commands "$REALIP_HOST_SERVICE" || return 1
        NATIVE_NAME="host:${REALIP_HOST_SERVICE}"
        return 0
    fi
    require_commands docker || return 1
    select_native_container
}

real_ip_web_command() {
    if [[ -n "${REALIP_HOST_SERVICE:-}" ]]; then
        if [[ "$1 $2" == '-s reload' ]]; then systemctl reload "$REALIP_HOST_SERVICE"; else "$REALIP_HOST_SERVICE" "$@"; fi
    else
        docker exec "$NATIVE_ID" nginx "$@"
    fi
}

real_ip_runtime_mounts() {
    if [[ -n "${REALIP_HOST_SERVICE:-}" ]]; then
        python3 "${SCRIPT_DIR}/lib/crowdsec_host.py" "$1" "$2"
    else
        docker inspect --format '{{json .Mounts}}' "$NATIVE_ID" > "$2"
    fi
}

verify_real_ip_request() (
    require_core && require_yaml && require_commands curl || return 1
    local NATIVE_ID NATIVE_NAME REALIP_HOST_SERVICE='' selected target expected request_token work lua changed=false verified=false mode attempt
    real_ip_select_runtime "${1:-}"
    selected=$?
    [[ "$selected" == 2 ]] && return 0
    [[ "$selected" == 0 ]] || return 1
    prompt target '输入所选 Web 服务的站点根地址（如 https://example.com）: ' || return 0
    [[ -n "$target" ]] || return 0
    prompt expected '此次请求的已知公网 IP（外部设备或当前主机出口 IP）: ' || return 0
    yaml_tool ip "$expected" || return 1
    printf '1. 从当前主机发送一次正常页面请求\n2. 从外部设备访问生成的标记 URL，随后按回车核验\n'
    prompt mode '选择请求来源 [1-2]: ' || return 0
    [[ "$mode" == 1 || "$mode" == 2 ]] || { log_err '请求来源无效。'; return 1; }
    work=$(mktemp -d) || return 1
    real_ip_verify_exit() {
        local result=$?
        trap - EXIT INT TERM
        if [[ "$changed" == true ]]; then
            if ! restore_config_change || ! real_ip_web_command -t || ! real_ip_web_command -s reload; then
                log_err '临时诊断钩子恢复/重载失败，请根据修改前备份恢复。'
                result=1
                verified=false
            fi
        fi
        if [[ "$verified" == true ]]; then
            request_audit_tool record "$IP_VERIFICATIONS" "$NATIVE_NAME" "$work/result" || result=1
        fi
        rm -rf -- "$work"
        exit "$result"
    }
    trap real_ip_verify_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    real_ip_web_command -T > "$work/effective" 2>/dev/null || return 1
    real_ip_runtime_mounts "$work/effective" "$work/mounts" || return 1
    request_token=$(python3 -c 'import secrets; print(secrets.token_hex(12))') || return 1
    if [[ -n "$REALIP_HOST_SERVICE" ]]; then
        request_audit_tool plan-host "$work/effective" "$work/mounts" "$APPSEC_LINKS" "$REALIP_HOST_SERVICE" "$target" "$expected" "$request_token" "$work/plan" "${CS_DIR}/bouncers/crowdsec-${REALIP_HOST_SERVICE}-bouncer.conf" || return 1
    else
        request_audit_tool plan "$work/effective" "$work/mounts" "$WEB_INSTALLS" "$NATIVE_NAME" "$target" "$expected" "$request_token" "$work/plan" || return 1
    fi
    lua=$(web_tool get "$work/plan" target) || return 1
    target=$(web_tool get "$work/plan" url) || return 1
    begin_config_change "$lua" || return 1
    changed=true
    request_audit_tool stage "$work/plan" && real_ip_web_command -t && real_ip_web_command -s reload || return 1
    sleep 1
    log_info "正常请求核验 URL：${target}"
    if [[ "$mode" == 1 ]]; then
        local family=-4
        [[ "$expected" == *:* ]] && family=-6
        curl "$family" -sS --connect-timeout 5 --max-time 20 -o /dev/null "$target" || return 1
    else
        prompt selected '外部设备访问完成后按回车核验（Ctrl+D 取消）: ' || return 0
    fi
    local wait_seconds
    wait_seconds=$(web_tool get "$work/plan" wait_seconds) || return 1
    for ((attempt=0; attempt<wait_seconds; attempt++)); do
        if request_audit_tool verify "$work/plan" "$work/result" > "$work/report" 2> "$work/error"; then verified=true; break; fi
        sleep 1
    done
    cat "$work/report"
    if [[ "$verified" != true ]]; then cat "$work/error" >&2; return 1; fi
    log_succ '同一正常请求的访问日志和 Bouncer IP 与预期来源一致，临时诊断代码即将恢复。'
)

repair_cloudflare_real_ip() (
    local operation="${1:-apply}"
    if [[ "$operation" == remove ]]; then require_core || return 1; fi
    require_commands python3 || return 1
    local NATIVE_ID NATIVE_NAME REALIP_HOST_SERVICE='' selected work target provider header ranges scope changed=false committed=false
    real_ip_select_runtime "${2:-}"
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
                if ! real_ip_web_command -t || ! real_ip_web_command -s reload; then
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
    real_ip_web_command -T > "$work/effective" 2>&1 || return 1
    real_ip_runtime_mounts "$work/effective" "$work/mounts" || return 1
    if [[ "$operation" == remove ]]; then
        real_ip_tool restore-plan "$REALIP_STATE" "$NATIVE_NAME" "$work/mounts" "$work/plan" || return 1
    else
        real_ip_tool discover "$work/effective" || return 1
        if [[ "$operation" == diagnose ]]; then
            real_ip_tool evidence "$work/effective" "$work/mounts" "$REALIP_STATE" "$NATIVE_NAME"
            return $?
        fi
        printf '1. Cloudflare 公网节点直接接入（官方网段 + CF-Connecting-IP）\n2. 已核对的其他 CDN/反向代理（明确 Header 和可信网段）\n3. 上游不确定：只读诊断与外部请求核对指引\n4. 已确认客户端直连：无需新增配置\n0. 取消\n'
        printf '5. 已核验 Cloudflare 公网直连：CF 访客头缺失，但 XFF 链可靠（官方网段 + X-Forwarded-For）\n'
        prompt provider '请选择实际接入类型 [0-5]: ' || return 0
        case "$provider" in
            3)
                real_ip_tool evidence "$work/effective" "$work/mounts" "$REALIP_STATE" "$NATIVE_NAME" || return 1
                return 0 ;;
            4)
                log_info '已确认客户端直连，无需新增真实 IP 配置；已有信任规则保留，需撤销本工具配置时使用 --restore-real-ip。'
                log_info '仍应从另一台设备正常访问并核对新日志 IP；本次未修改配置、管理记录或运行服务。'
                return 0 ;;
            0|'') return 0 ;;
            1|2|5) ;;
            *) log_err '接入类型无效，未修改配置。'; return 1 ;;
        esac
        require_core || return 1
        real_ip_web_command -V > "$work/version" 2>&1 || return 1
        if ! grep -q -- '--with-http_realip_module' "$work/version" && ! grep -Eq 'load_module[^;]*ngx_http_realip_module' "$work/effective"; then
            log_err '运行时未发现 HTTP real-IP 模块，未修改配置。'
            return 1
        fi
        case "$provider" in
            1|5)
                require_commands curl || return 1
                curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 30 https://www.cloudflare.com/ips-v4 -o "$work/ipv4" || return 1
                curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 30 https://www.cloudflare.com/ips-v6 -o "$work/ipv6" || return 1
                local planner=plan
                [[ "$provider" == 5 ]] && planner=plan-cloudflare-xff
                real_ip_tool "$planner" "$work/effective" "$work/mounts" "$work/ipv4" "$work/ipv6" "$REALIP_STATE" "$NATIVE_NAME" "$work/plan" || return 1 ;;
            2)
                prompt header '输入上游约定的 IP Header（如 X-Forwarded-For；不支持 RFC Forwarded）: ' || return 0
                [[ -n "$header" ]] || return 0
                log_warn '只填写你控制或已核对的代理来源网段；内网仅接受 IPv4 /24 或更窄、IPv6 /64 或更窄，回环需单个地址。'
                prompt ranges '可信代理 IP/CIDR（空格分隔，留空取消）: ' || return 0
                [[ -n "$ranges" ]] || return 0
                real_ip_tool plan-custom "$work/effective" "$work/mounts" "$header" "$ranges" "$REALIP_STATE" "$NATIVE_NAME" "$work/plan" || return 1 ;;
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
        python3 "${SCRIPT_DIR}/lib/crowdsec_detection_diagnose.py" range-diff "$work/plan" "$REALIP_STATE" "$NATIVE_NAME" || return 1
        log_info "来源核对时间（UTC）：$(date -u '+%Y-%m-%d %H:%M:%S')；Cloudflare 模式本次从官方 HTTPS 获取，后续网段变更可重新运行更新。"
        log_info '仅使用选定 Header，不尝试其他候选；缺失或无法提取有效 IP 时保留连接来源 IP。X-Forwarded-For 按可信代理从右向左处理。'
        if [[ "$scope" == npm-proxy-hosts ]]; then
            log_warn '作用于加载 server_proxy.conf 的全部 NPM Proxy Host；在站点层使用上述网段，保留原自定义内容及 HTTP 层配置。'
        else
            log_info '作用于所选 Web 服务的 HTTP 层；保留现有 WAF、日志采集与白名单。'
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
    if ! config_change_needed; then committed=true; log_info '真实 IP 配置未变化，跳过重载。'; return 0; fi
    real_ip_web_command -t && real_ip_web_command -s reload || return 1
    committed=true
    log_succ '真实 IP 配置已校验并重载；请从外部访问实际站点，并核对日志首字段及 Bouncer 使用的访客 IP。'
    log_info '从另一台设备访问正常页面，附加唯一查询参数（如 ?crowdsec_ip_check=你选定的标识），在对应 access.log 关联该行并核对设备公网 IP；不要用 localhost 攻击路径验证。'
)

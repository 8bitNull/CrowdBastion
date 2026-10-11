#!/usr/bin/env bash
# Effective AppSec policy inspection never displays API credentials.
appsec_audit_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_appsec.py" "$@"; }

appsec_guard_config() {
    appsec_audit_tool guard "$1" || return 1
    if [[ -n "${2:-}" ]]; then
        # Inspect the container too: single-file mounts do not expose sibling .local files.
        if ! docker exec "$2" test ! -e "${3}.local"; then
            log_err "容器 ${2} 的 ${3}.local 存在或无法检查，请先手动评估；未修改配置。"
            return 1
        fi
    fi
}

configure_appsec_policy() {
    require_core && require_yaml || return 1
    local file="${1:-}" body="${2:-}" failure="${3:-}" container="${4:-}" service target='' mounts containers id _image name selected native_targets stage entry managed=false
    local targets=()
    [[ -n "$file" ]] || prompt file '宿主机官方 Bouncer 配置绝对路径，或输入 docker（留空取消）: ' || return 0
    [[ -n "$file" ]] || return 0
    case "$file" in
        docker)
            require_commands docker || return 1
            containers=$(appsec_containers) || return 1
            [[ -n "$containers" ]] || { log_err '没有运行中的 Web 容器。'; return 1; }
            printf '%s\n' "$containers"
            [[ -n "$container" ]] || prompt container '容器 ID 或名称（留空取消）: ' || return 0
            [[ -n "$container" ]] || return 0
            selected=''
            while read -r id _image name; do
                if [[ "$container" == "$id" || "$container" == "$name" ]]; then selected="$id"; break; fi
            done <<< "$containers"
            [[ -n "$selected" ]] || { log_err '请选择列表中的容器。'; return 1; }
            container="$selected"
            mounts=$(docker inspect --format '{{json .Mounts}}' "$container") || return 1
            native_targets=$(web_tool targets "$WEB_INSTALLS" "$name") || return 1
            while IFS= read -r target; do [[ -z "$target" ]] || targets+=("$target"); done <<< "$native_targets"
            targets+=("${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf")
            file=''
            for target in "${targets[@]}"; do
                file=$(printf '%s' "$mounts" | yaml_tool docker-bouncer-path "$target" 2>/dev/null) && break
                file=''
            done
            [[ -n "$file" ]] || { log_err '未找到持久化官方 Web Bouncer 配置；未修改容器。'; return 1; }
            appsec_guard_config "$file" "$container" "$target" || return 1
            if [[ -n "$native_targets" ]]; then
                entry=$(mktemp) || return 1
                if ! web_tool check "$WEB_INSTALLS" "$name" <(printf '%s' "$mounts") "$entry"; then rm -f -- "$entry"; return 1; fi
                rm -f -- "$entry"
                managed=true
            fi
            service=docker ;;
        "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf") service=openresty ;;
        "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf") service=nginx ;;
        *) log_err '请选择标准宿主机官方 Bouncer 配置，或输入 docker。'; return 1 ;;
    esac
    appsec_audit_tool show "$file" || return 1
    log_info '官方默认：无法读取正文 false；AppSec 返回 500 时 passthrough。HTTP2/HTTP3 无 Content-Length 正文可能无法分析。'
    log_warn 'true 会拒绝不可分析正文，deny 会拒绝 AppSec 故障请求；请评估正常业务与可用性。留空保留配置。'
    log_warn '官方 OpenResty Bouncer 1.2.3 连接故障时 deny 页面可能返回 HTTP 200；请结合响应内容与后端是否收到请求验证。'
    [[ -n "$body" ]] || prompt body 'APPSEC_DROP_UNREADABLE_BODY [true/false，留空取消]: ' || return 0
    [[ -n "$body" ]] || return 0
    [[ -n "$failure" ]] || prompt failure 'APPSEC_FAILURE_ACTION [deny/passthrough，留空取消]: ' || return 0
    [[ -n "$failure" ]] || return 0
    appsec_guard_config "$file" && require_commands "$service" || return 1
    confirm '应用明确选择的正文/故障策略并校验重载？' || return 0
    stage=$(mktemp) || return 1
    cp -- "$file" "$stage" || { rm -f -- "$stage"; return 1; }
    if ! appsec_audit_tool policy "$stage" "$body" "$failure"; then rm -f -- "$stage"; return 1; fi
    if [[ "$managed" == true ]]; then
        begin_config_change "$file" "$WEB_INSTALLS" || { rm -f -- "$stage"; return 1; }
    else begin_config_change "$file" || { rm -f -- "$stage"; return 1; }
    fi
    cp -- "$stage" "$file" || { rm -f -- "$stage"; restore_config_change; return 1; }
    rm -f -- "$stage"
    if [[ "$managed" == true ]] && ! appsec_audit_tool record-policy "$WEB_INSTALLS" "$name" "$file"; then restore_config_change; return 1; fi
    local valid=false
    if [[ "$service" == docker ]]; then
        if docker exec "$container" nginx -t && docker exec "$container" nginx -s reload; then valid=true; fi
    elif "$service" -t && systemctl reload "$service"; then valid=true
    fi
    if [[ "$valid" != true ]]; then
        restore_config_change || return 1
        if [[ "$service" == docker ]]; then
            if ! docker exec "$container" nginx -t || ! docker exec "$container" nginx -s reload; then log_warn '恢复策略后容器重载失败，请检查容器状态。'; fi
        else systemctl reload "$service" || true
        fi
        return 1
    fi
    log_succ 'AppSec 正文/故障策略已按选择配置。请从外部设备补测正常业务、HTTP2 正文和引擎故障行为。'
}

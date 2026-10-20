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

appsec_managed_hooks() {
    local name="$1" container="$2" mounts="$3" effective status=0
    effective=$(mktemp) || return 1
    if ! docker exec "$container" nginx -T > "$effective" 2>&1 ||
        ! web_tool active-hooks "$WEB_INSTALLS" "$name" <(printf '%s' "$mounts") "$effective" >/dev/null; then
        log_err '受管 Web Bouncer 未进入有效请求钩子，或存在覆盖；请先核对有效配置。'
        status=1
    fi
    rm -f -- "$effective"
    return "$status"
}

configure_appsec_policy() (
    require_core && require_yaml || return 1
    local file="${1:-}" body="${2:-}" failure="${3:-}" container="${4:-}" lapi="${5:-}" service target='' mounts containers id _image name selected native_targets stage entry managed=false lapi_supported=false
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
                appsec_managed_hooks "$name" "$container" "$mounts" || return 1
                if web_tool lapi-policy-supported "$WEB_INSTALLS" "$name" <(printf '%s' "$mounts") >/dev/null 2>&1; then lapi_supported=true; fi
            fi
            service=docker ;;
        "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf") service=openresty ;;
        "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf") service=nginx ;;
        *) log_err '请选择标准宿主机官方 Bouncer 配置，或输入 docker。'; return 1 ;;
    esac
    appsec_audit_tool show "$file" || return 1
    if [[ "$lapi_supported" != true ]]; then
        log_warn '当前安装未确认支持 LAPI 故障策略；上方 LAPI 值仅为配置/兼容默认，不能证明模块会执行。'
        if [[ -n "$lapi" ]]; then log_err '未确认 LAPI 故障拒绝能力，未修改策略。'; return 1; fi
    fi
    log_info '新装托管容器默认 AppSec/LAPI 均 deny；此操作保留未选择的已有策略。HTTP2/HTTP3 无 Content-Length 正文可能无法分析。'
    log_warn 'true 会拒绝不可分析正文，deny 会拒绝 AppSec 故障请求；请评估正常业务与可用性。留空保留配置。'
    log_warn '未升级的 OpenResty Bouncer 1.2.3 故障拒绝页可能返回 HTTP 200；本工具受管模块升级已修正，仍需核对后端是否收到请求。'
    [[ -n "$body" ]] || prompt body 'APPSEC_DROP_UNREADABLE_BODY [true/false，留空取消]: ' || return 0
    [[ -n "$body" ]] || return 0
    [[ -n "$failure" ]] || prompt failure 'APPSEC_FAILURE_ACTION [deny/passthrough，留空取消]: ' || return 0
    [[ -n "$failure" ]] || return 0
    if [[ "$lapi_supported" == true && -z "$lapi" ]]; then
        prompt lapi 'LAPI_FAILURE_ACTION [deny/passthrough，留空保留]: ' || return 0
    fi
    local policy_args=("$body" "$failure")
    [[ -z "$lapi" ]] || policy_args+=("$lapi")
    appsec_guard_config "$file" && require_commands "$service" || return 1
    confirm '应用明确选择的正文/故障策略并校验重载？' || return 0
    local committed=false changed=false
    stage=$(mktemp) || return 1
    # shellcheck disable=SC2329 # invoked by EXIT trap
    policy_change_exit() {
        local status=$?
        trap - EXIT INT TERM
        if [[ "$changed" == true && "$committed" != true ]]; then
            if ! restore_config_change || ! nginx_reload_verified "$service" "$container" ||
                { [[ "$managed" == true ]] && ! appsec_managed_hooks "$name" "$container" "$mounts"; }; then
                log_err '策略恢复不完整；修改前备份已保留，请人工核对配置、安装记录及 Nginx 运行状态。'
            fi
            [[ "$status" != 0 ]] || status=1
        fi
        rm -f -- "$stage"
        exit "$status"
    }
    trap policy_change_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cp -- "$file" "$stage" || return 1
    appsec_audit_tool policy "$stage" "${policy_args[@]}" || return 1
    if [[ "$managed" == true ]]; then
        begin_config_change "$file" "$WEB_INSTALLS" || return 1
    else begin_config_change "$file" || return 1
    fi
    changed=true
    cp -- "$stage" "$file" || return 1
    if [[ "$managed" == true ]]; then
        appsec_audit_tool record-policy "$WEB_INSTALLS" "$name" "$file" || return 1
    fi
    nginx_reload_verified "$service" "$container" || return 1
    if [[ "$managed" == true ]]; then
        appsec_managed_hooks "$name" "$container" "$mounts" || return 1
    fi
    appsec_audit_tool show "$file" || return 1
    committed=true
    log_succ '正文及 AppSec/LAPI 故障策略已按选择配置。请从外部设备补测正常业务、HTTP2 正文和两端故障行为。'
)

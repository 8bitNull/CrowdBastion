#!/usr/bin/env bash
# Sourced by the manager; mutations run in a subshell with transaction cleanup.
web_tool() { python3 "${SCRIPT_DIR}/lib/crowdsec_web.py" "$@"; }

select_native_container() {
    local containers id image name requested
    containers=$(appsec_containers) || return 1
    [[ -n "$containers" ]] || { log_err '未发现运行中的 Web 容器。'; return 1; }
    printf '%s\n' "$containers"
    prompt requested '输入容器 ID 或名称（留空取消）: ' || return 2
    [[ -n "$requested" ]] || return 2
    while read -r id image name; do
        if [[ "$requested" == "$id" || "$requested" == "$name" ]]; then
            NATIVE_ID=$id NATIVE_IMAGE=$image NATIVE_NAME=$name
            return 0
        fi
    done <<< "$containers"
    log_err '请选择列表中的容器。'
    return 1
}

install_docker_web_bouncer() (
    require_core && require_yaml && require_commands docker curl ss || return 1
    appsec_default_listener_ready || { log_err '请先配置 AppSec 引擎，确认 127.0.0.1:7422 监听。'; return 1; }
    local NATIVE_ID NATIVE_IMAGE NATIVE_NAME selection
    select_native_container
    selection=$?
    [[ $selection == 2 ]] && return 0
    [[ $selection == 0 ]] || return 1
    local work network target assets account='' registered=false changed=false committed=false entry_status remote_assets config
    work=$(mktemp -d) || return 1
    chmod 700 "$work" || { rm -rf -- "$work"; return 1; }
    # shellcheck disable=SC2329 # invoked through EXIT trap
    native_install_exit() {
        local status=$?
        trap - EXIT INT TERM
        if [[ "$committed" != true ]]; then
            if [[ "$changed" == true ]]; then
                if restore_config_change; then
                    if ! docker exec "$NATIVE_ID" nginx -t || ! docker exec "$NATIVE_ID" nginx -s reload; then
                        log_warn '恢复后重载失败，保留资源和账号；请恢复容器运行后执行 --remove-web-bouncer。'
                        web_tool recovery "$work/plan" "$WEB_INSTALLS" "$NATIVE_NAME" "$account" || log_err "恢复记录失败，需人工保留并核对资源 ${assets}、账号 ${account}。"
                        registered=false
                    else
                        rm -rf -- "$assets"
                    fi
                else
                    log_err '回滚配置失败，保留资源与账号以免中断现有网站。'
                    web_tool recovery "$work/plan" "$WEB_INSTALLS" "$NATIVE_NAME" "$account" || log_err '恢复记录失败，请人工检查。'
                    registered=false
                fi
            fi
            if [[ "$registered" == true ]]; then
                cscli bouncers delete "$account" >/dev/null 2>&1 || log_warn "未能撤销新账号 ${account}，请执行 cscli bouncers delete 清理。"
            fi
        fi
        rm -rf -- "$work"
        exit "$status"
    }
    trap native_install_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$NATIVE_ID") || return 1
    local appsec_url='http://127.0.0.1:7422' transport_args=()
    if [[ "$network" != host ]]; then
        transport_current "$NATIVE_ID" "$NATIVE_NAME" "$work" || return 1
        appsec_url=$(web_tool get "$work/transport" appsec_url) || return 1
        transport_args=("$work/transport")
    fi
    docker inspect --format '{{json .Mounts}}' "$NATIVE_ID" > "$work/mounts" || return 1
    if [[ -f "$WEB_INSTALLS" ]] && web_tool check "$WEB_INSTALLS" "$NATIVE_NAME" "$work/mounts" "$work/existing" 2>/dev/null; then
        entry_status=$(web_tool get "$work/existing" status) || return 1
        [[ "$entry_status" == installed ]] || { log_err '旧安装清理未完成，请先运行撤销 Web Bouncer。'; return 1; }
        if [[ "$network" != host ]]; then
            transport_tool installed-current "$work/existing" "$work/transport" || return 1
        elif web_tool get "$work/existing" transport >/dev/null 2>&1; then
            log_err '原 bridge 安装网络已变化，请先人工核对。'; return 1
        fi
        docker exec "$NATIVE_ID" nginx -T > "$work/effective" 2>&1 &&
            web_tool active-hooks "$WEB_INSTALLS" "$NATIVE_NAME" "$work/mounts" "$work/effective" || return 1
        assets=$(web_tool get "$work/existing" host_assets) || return 1
        remote_assets=$(web_tool get "$work/existing" container_assets) || return 1
        appsec_guard_config "${assets}/bouncer.conf" "$NATIVE_ID" "${remote_assets}/bouncer.conf" || return 1
        log_info '已有本工具 Web Bouncer，复用原账号；可用接入已有 Docker Web Bouncer 恢复 AppSec 地址。'
        return 0
    fi
    docker exec "$NATIVE_ID" nginx -T > "$work/effective" 2>&1 || { log_err 'nginx -T 失败，未修改。'; return 1; }
    docker exec "$NATIVE_ID" nginx -V > "$work/version" 2>&1 || return 1
    web_tool plan "$work/effective" "$work/mounts" "$NATIVE_IMAGE" "$network" "$work/version" "$work/plan" "${transport_args[@]}" || return 1
    target=$(web_tool get "$work/plan" host_target) || return 1
    assets=$(web_tool get "$work/plan" host_assets) || return 1
    remote_assets=$(web_tool get "$work/plan" container_assets) || return 1
    appsec_guard_config "${assets}/bouncer.conf" "$NATIVE_ID" "${remote_assets}/bouncer.conf" || return 1
    log_info "持久化配置：${target}；资源：${assets}"
    log_info '安装官方固定版本 Bouncer；原 WAF 先执行，保留原日志钩子。'
    confirm "为 ${NATIVE_NAME} 首次安装 Web Bouncer、接入 AppSec 并重载？" || return 0
    curl -fL --retry 2 --connect-timeout 15 --max-time 120 \
        https://github.com/crowdsecurity/cs-openresty-bouncer/releases/download/v1.2.3/crowdsec-openresty-bouncer.tgz -o "$work/bouncer.tgz" || return 1
    curl -fL --retry 2 --connect-timeout 15 --max-time 120 \
        https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v0.17.1.tar.gz -o "$work/http.tgz" || return 1
    web_tool verify "$work/bouncer.tgz" "$work/http.tgz" || return 1
    local credentials api_url
    credentials=$(web_tool credentials "${CS_DIR}/config.yaml") || return 1
    api_url=$(yaml_tool get "$credentials" url) || return 1
    [[ "$api_url" =~ ^http://(127\.0\.0\.1|localhost):[0-9]+/?$ ]] || { log_err '自动安装需要 loopback LAPI 地址，未注册账号。'; return 1; }
    if [[ "$network" != host ]]; then api_url=$(web_tool get "$work/transport" api_url) || return 1; fi
    account="cs-web-1key-$(python3 -c 'import secrets; print(secrets.token_hex(8))')" || return 1
    if ! cscli bouncers add "$account" -o raw > "$work/key" 2> "$work/key-error"; then
        log_err 'Bouncer 注册失败，未修改网站配置。'
        return 1
    fi
    registered=true
    if [[ "$network" != host ]]; then
        transport_tool probe-config "$work/key" "$work/transport" "$work/probe" || return 1
        if ! docker exec -i "$NATIVE_ID" curl -fsS --noproxy '*' --connect-timeout 3 --max-time 8 --config - < "$work/probe" > "$work/response" 2>/dev/null ||
            ! transport_tool probe-response "$work/response"; then log_err '私有 LAPI 无法用本次账号认证，已中止接入。'; return 1; fi
    fi
    web_tool stage "$work/plan" "$work/bouncer.tgz" "$work/http.tgz" "$work/assets" "$work/key" "$api_url" || return 1
    [[ ! -e "$assets" ]] || { log_err '资源目录已变化，未覆盖。'; return 1; }
    begin_config_change "$target" "$WEB_INSTALLS" "$APPSEC_DOCKER_LINKS" || return 1
    changed=true
    web_tool apply "$work/plan" "$work/assets" "$WEB_INSTALLS" "$NATIVE_NAME" "$account" || return 1
    remote_assets=$(web_tool get "$work/plan" container_assets) || return 1
    config="${assets}/bouncer.conf"
    yaml_tool link-docker-bouncer "$config" "$APPSEC_DOCKER_LINKS" "$NATIVE_ID" "${remote_assets}/bouncer.conf" "$NATIVE_NAME" "$appsec_url" "${transport_args[@]}" || return 1
    yaml_tool web-bouncer "$config" "$appsec_url" || return 1
    chmod 600 "$config" || return 1
    docker exec "$NATIVE_ID" nginx -t && docker exec "$NATIVE_ID" nginx -s reload || return 1
    committed=true
    log_succ 'Web Bouncer 已首次安装并重载；请通过网站验证实际请求、原 WAF 与 AppSec 指标。'
)

remove_docker_web_bouncer() (
    require_core && require_yaml && require_commands docker || return 1
    local entries selected work target assets account status network changed=false committed=false
    entries=$(web_tool list "$WEB_INSTALLS") || return 1
    [[ -n "$entries" ]] || { log_info '没有本工具的原生容器 Web Bouncer 安装记录。'; return 0; }
    printf '%s\n' "$entries"
    prompt selected '输入要撤销的容器名称（留空取消）: ' || return 0
    [[ -n "$selected" ]] || return 0
    if ! awk -F '\t' -v name="$selected" '$1==name {found=1} END {exit !found}' <<< "$entries"; then log_err '请选择安装记录中的名称。'; return 1; fi
    work=$(mktemp -d) || return 1
    # shellcheck disable=SC2329 # invoked through EXIT trap
    native_remove_exit() {
        local result=$?
        trap - EXIT INT TERM
        if [[ "$changed" == true && "$committed" != true ]]; then
            restore_config_change || log_err '回滚失败，请人工恢复网站配置。'
            if ! docker exec "$selected" nginx -t || ! docker exec "$selected" nginx -s reload; then log_warn '回滚后重载失败。'; fi
        fi
        rm -rf -- "$work"
        exit "$result"
    }
    trap native_remove_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    docker inspect --format '{{json .Mounts}}' "$selected" > "$work/mounts" || return 1
    web_tool check "$WEB_INSTALLS" "$selected" "$work/mounts" "$work/entry" || return 1
    account=$(web_tool get "$work/entry" account) || return 1
    target=$(web_tool get "$work/entry" host_target) || return 1
    assets=$(web_tool get "$work/entry" host_assets) || return 1
    status=$(web_tool get "$work/entry" status) || return 1
    confirm "撤销 ${selected} 的本工具 Web Bouncer 安装（保留原 WAF）？" || return 0
    if [[ "$status" != cleanup-pending ]]; then
        network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$selected") || return 1
        if [[ "$network" != host ]]; then
            transport_inspect "$selected" "$work" &&
                transport_tool check-install "$work/entry" "$work/inspection" "$work/networks" || return 1
        elif web_tool get "$work/entry" transport >/dev/null 2>&1; then
            log_err '原 bridge 容器网络已变化，未撤销配置。'; return 1
        fi
        begin_config_change "$target" "$WEB_INSTALLS" "$APPSEC_DOCKER_LINKS" || return 1
        changed=true
        web_tool restore "$work/entry" || return 1
        web_tool unlink-record "$APPSEC_DOCKER_LINKS" "${assets}/bouncer.conf" || return 1
        # Record pending cleanup before reload; rollback restores this state on failure.
        web_tool pending "$WEB_INSTALLS" "$selected" || return 1
        docker exec "$selected" nginx -t && docker exec "$selected" nginx -s reload || return 1
    fi
    committed=true
    if ! cscli bouncers delete "$account" >/dev/null 2>&1; then
        # A previous cleanup may already have revoked the account before failing.
        if ! cscli bouncers list -o json > "$work/bouncers" || ! web_tool account-absent "$account" "$work/bouncers"; then
            log_err "原网站配置已恢复；账号 ${account} 清理失败，安装记录保留，可再次执行撤销。"
            return 1
        fi
    fi
    web_tool forget "$WEB_INSTALLS" "$selected" || { log_err '账号已撤销；资源清理失败，可再次执行撤销。'; return 1; }
    log_succ '原网站/WAF 配置已恢复，本工具的 Web Bouncer 账号和资源已移除。'
)

install_web_bouncer() {
    local choice
    printf '1. 首次安装 Docker Web Bouncer（1Panel/NPM/Lua Nginx）\n2. 首次安装宿主机 Nginx Bouncer\n3. 首次安装宿主机 OpenResty Bouncer\n0. 返回\n'
    prompt choice '请选择 [0-3]: ' || return 0
    case "$choice" in
        1) install_docker_web_bouncer ;;
        2) install_host_web_bouncer nginx ;;
        3) install_host_web_bouncer openresty ;;
        0|'') return 0 ;;
        *) log_err '无效选项。'; return 1 ;;
    esac
}

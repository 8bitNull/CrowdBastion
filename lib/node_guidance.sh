#!/usr/bin/env bash
# Purpose selection changes preferences only; checks never save preferences.

load_node_roles() {
    local status=0
    NODE_ROLES=$(python3 "${SCRIPT_DIR}/lib/crowdbastion_node.py" load "$NODE_ROLES_FILE") || status=$?
    [[ "$status" == 3 ]] && return 0
    return "$status"
}

node_has_role() { [[ " $NODE_ROLES " == *" $1 "* ]]; }

node_role_label() {
    local role
    if [[ -z "$NODE_ROLES" ]]; then printf '未选择'; return; fi
    for role in $NODE_ROLES; do
        case "$role" in
            web) printf '网站 ' ;;
            relay) printf '本地中转 ' ;;
            remote) printf '远端执行 ' ;;
            node) printf 'V2bX 落地 ' ;;
        esac
    done
}

select_node_roles() {
    local answer token roles=() valid
    printf '\n选择这台服务器的用途（可组合，例如 2 4）\n1. 网站：本机检测网站请求和系统日志\n2. 本地中转：本机检测系统/SSH，防火墙封禁\n3. 远端执行：仅连接检测中心，执行中心决策\n4. V2bX 落地：检查配置、连接来源与运行日志\n0. 暂不选择／返回\n'
    [[ -f "${CS_DIR}/config.yaml" ]] && log_info '发现本地检测配置；请根据实际用途选择。'
    [[ -f "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.remote.json" ]] && log_info '发现托管远端连接；请选择远端执行或远端执行 + 落地。'
    log_info '远端执行不能与网站／本地中转同选。选择用途只保存偏好。'
    while true; do
        prompt answer '用途编号 [0-4，可用空格组合]: ' || return 0
        [[ "$answer" == 0 ]] && return 0
        roles=(); valid=true
        for token in $answer; do
            case "$token" in
                1) roles+=(web) ;;
                2) roles+=(relay) ;;
                3) roles+=(remote) ;;
                4) roles+=(node) ;;
                *) valid=false ;;
            esac
        done
        if [[ "$valid" == true ]] && python3 "${SCRIPT_DIR}/lib/crowdbastion_node.py" save "$NODE_ROLES_FILE" "${roles[@]}" >/dev/null; then
            load_node_roles || return 1
            log_succ "节点用途已保存：$(node_role_label)。尚未安装或修改防护组件。"
            return 0
        fi
        log_warn '用途无效、重复、组合冲突或保存失败，请重新选择；0 返回。'
    done
}

node_web_deployed() {
    local path
    for path in "$APPSEC_FILE" "$APPSEC_LINKS" "$APPSEC_DOCKER_LINKS" "$WEB_INSTALLS" "$REALIP_STATE" "$DOCKER_ENDPOINTS" "${CS_DIR}/acquis.d/web-sites.yaml" "${CS_DIR}/acquis.d/crowdsec-1key-log-repair.yaml"; do
        [[ -e "$path" || -L "$path" ]] && return 0
    done
    require_yaml >/dev/null 2>&1 || return 1
    maintenance_tool managed-web-deployed "$CS_DIR" >/dev/null 2>&1
}

node_core_present() {
    [[ -f "${CS_DIR}/config.yaml" ]] && command -v crowdsec >/dev/null 2>&1 && command -v cscli >/dev/null 2>&1
}

node_recommendation() {
    if node_has_role remote; then
        log_info '建议：远端连接状态 --relay-bouncer-status；连接来源和转发路径 --relay-path。首页 [2] 可引导连接。'
    elif [[ "$NODE_ROLES" == node ]] && ! node_core_present; then
        log_info '建议：先检查 V2bX 配置与日志；此用途不要求安装本地 CrowdSec。'
    elif ! node_core_present; then
        if node_has_role web || [[ -z "$NODE_ROLES" ]]; then
            log_info '建议：从首页 [2] 安装网站基础防护，或 --install-core。'
        else
            log_info '建议：从首页 [2] 安装本机系统/SSH 基础防护，或 --install-relay。'
        fi
    elif node_has_role web || node_web_deployed || [[ -z "$NODE_ROLES" ]]; then
        log_info '建议：排查网站 [4] → [4] → [2]；真实 IP 检查 --diagnose-real-ip。实际网站接入验证需明确选择 --verify-appsec。'
    else
        log_info '建议：先检查连接来源和转发路径 [4] → [4] → [3] → [2]，或 --relay-path；规则引用不等于流量阻断验收。'
    fi
    node_has_role node && log_info '落地建议：检查 V2bX 配置与连接来源 --diagnose-v2bx；运行日志 --v2bx-log-check。'
    return 0
}

# Keep role-specific steps together; only an explicit step changes deployment.
guided_setup() {
    local choice role number result
    local steps=() labels=()
    load_node_roles || { log_warn '用途配置无法读取，请重新选择。'; NODE_ROLES=''; }
    if [[ -z "$NODE_ROLES" ]]; then
        locked_operation select_node_roles || return $?
        load_node_roles || return 1
        [[ -n "$NODE_ROLES" ]] || return 0
    fi
    for role in $NODE_ROLES; do
        case "$role" in
            web)
                steps+=(web website realip)
                labels+=('安装网站基础防护：检测日志并执行 IP 封禁' '按网站运行方式接入请求防护' '核对访客真实 IP：确保识别的是访问者') ;;
            relay)
                steps+=(relay relaypath)
                labels+=('安装中转基础防护：检测本机系统和 SSH 日志' '核对中转路径：确认封禁作用在哪个入口') ;;
            remote)
                steps+=(remote relaypath)
                labels+=('连接检测中心：由中心检测，本机执行封禁' '核对中转路径：确认封禁作用在哪个入口') ;;
            node)
                steps+=(node)
                labels+=('管理 V2bX：检查配置、分析样本、持续记录与告警') ;;
        esac
    done
    while true; do
        printf '\n安装或调整防护 — %s\n按顺序完成适用步骤；已有配置可以直接检查。\n' "$(node_role_label)"
        for ((number=0; number<${#steps[@]}; number++)); do
            printf '%s. %s\n' "$((number+1))" "${labels[number]}"
        done
        node_has_role node && printf 'V2bX 日志观察本身不提供业务攻击自动封禁。\n'
        node_has_role web && printf '第 2 项先选择网站运行方式；Docker bridge 按引擎、私有地址、拦截组件的顺序接入。\n'
        printf '9. 检查当前防护情况\n0. 返回首页\n'
        prompt choice '请选择步骤: ' || return 0
        case "$choice" in
            0) return 0 ;;
            9) interactive_health_check; continue ;;
        esac
        if [[ ! "$choice" =~ ^[1-8]$ ]] || (( choice > ${#steps[@]} )); then
            log_warn '请选择上面列出的步骤。'; continue
        fi
        result=0
        case "${steps[choice-1]}" in
            web) locked_operation install_crowdsec_core web || result=$? ;;
            website) guided_website_setup || result=$? ;;
            realip) locked_operation manage_real_ip || result=$? ;;
            relay) locked_operation install_crowdsec_core relay || result=$? ;;
            remote) locked_operation manage_remote_bouncer || result=$? ;;
            relaypath) check_relay_path || result=$? ;;
            node) manage_v2bx_node || result=$? ;;
        esac
        if [[ "$result" == 0 ]]; then
            printf '\n本步骤已返回。选择下一项继续，或选择 9 检查当前防护。\n'
        else
            printf '\n本步骤未完成，请先处理上方原因；选择 9 可重新检查。\n'
        fi
    done
}

guided_website_setup() {
    local runtime choice result
    printf '\n网站运行在哪里？\n1. 宿主机 Nginx/OpenResty\n2. Docker host 网络\n3. Docker bridge 网络\n0. 返回\n'
    while true; do
        prompt runtime '请选择 [0-3]: ' || return 0
        case "$runtime" in 0) return 0 ;; 1|2|3) break ;; *) log_warn '无效选项。' ;; esac
    done
    while true; do
        printf '\n网站请求防护 — 按顺序完成适用步骤\n1. 配置网站请求检测引擎\n'
        if [[ "$runtime" == 3 ]]; then
            printf '2. 登记已准备好的私有连接地址\n先准备可从该容器访问的私有 LAPI/AppSec 网关；本工具不创建网关。\n'
        else
            printf '宿主机或 Docker host 网络无需登记 bridge 私有地址。\n'
        fi
        printf '3. 安装或接入网站拦截组件\n4. 发送测试请求验证网站防护（需要确认）\n5. 查看网站请求检测状态\n6. 查看停用、移除与卸载顺序\n0. 返回\n'
        prompt choice '请选择步骤: ' || return 0
        result=0
        case "$choice" in
            1) locked_operation setup_appsec engine-only || result=$? ;;
            2)
                if [[ "$runtime" != 3 ]]; then log_warn '当前运行方式无需此步骤。'; continue; fi
                locked_operation configure_docker_endpoints || result=$? ;;
            3) locked_operation guided_website_bouncer "$runtime" || result=$? ;;
            4) locked_operation verify_appsec || result=$? ;;
            5) check_appsec_status || result=$? ;;
            6) show_website_withdrawal_help ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        if [[ "$result" == 0 ]]; then printf '\n操作已返回，请选择下一步；实际接入以状态和请求验证为准。\n'
        else printf '\n本步骤未完成，请处理上方原因后重试。\n'; fi
    done
}

guided_website_bouncer() {
    local choice service
    printf '\n网站拦截组件\n1. 首次安装组件（已有宿主机组件可复用）\n2. 重新接入已有组件\n0. 返回\n'
    prompt choice '请选择 [0-2]: ' || return 0
    case "$choice" in
        1) install_web_bouncer ;;
        2)
            if [[ "$1" == 1 ]]; then
                prompt service '宿主机服务 [nginx/openresty，留空返回]: ' || return 0
                case "$service" in
                    nginx|openresty)
                        if [[ ! -f "${CS_DIR}/bouncers/crowdsec-${service}-bouncer.conf" ]]; then
                            log_err '未发现已有组件配置，请先选择首次安装。'; return 1
                        fi
                        install_host_web_bouncer "$service" ;;
                    '') return 0 ;;
                    *) log_err '请选择 nginx 或 openresty。'; return 1 ;;
                esac
            else
                link_docker_appsec
            fi ;;
        0|'') return 0 ;;
        *) log_err '无效选项。'; return 1 ;;
    esac
}

check_health_status_raw() {
    health_expect traffic
    health_event traffic pending
    load_node_roles || return 1
    if [[ -z "$NODE_ROLES" ]]; then
        health_expect core
        health_expect logs
        health_expect web
        local legacy=0
        check_web_health_status || legacy=$?
        node_recommendation
        return "$legacy"
    fi
    local result=0 status=0 web=false
    printf '\n按节点用途检查：%s\n' "$(node_role_label)"
    if node_has_role web; then web=true
    elif node_web_deployed; then
        web=true
        log_warn '发现已部署的网站/AppSec 配置，本次仍核查这些组件，避免遗漏故障。'
    fi
    if node_has_role remote; then
        health_expect remote
        health_expect bouncer
        health_expect rules
        log_info '远端执行节点：检测由中心负责，不要求本地 CrowdSec，不检查本地 LAPI 或 SSH 采集。'
        remote_bouncer_status || status=$?
        [[ "$status" != 0 && "$status" != 2 ]] && result=1
        status=0
        check_remote_firewall_status || status=$?
        [[ "$status" != 0 && "$status" != 2 ]] && result=1
        [[ "$result" == 0 ]] && result=2
        if [[ "$web" == true ]]; then
            health_expect web
            # Inspect deployed components without querying local core/LAPI.
            status=0; check_appsec_status offline || status=$?
            [[ "$status" != 0 && "$status" != 2 ]] && result=1
            status=0; check_protection_evidence offline || status=$?
            [[ "$status" != 0 && "$status" != 2 ]] && result=1
        fi
    elif [[ "$web" == true ]] || node_has_role relay || [[ -e "${CS_DIR}/config.yaml" || -L "${CS_DIR}/config.yaml" ]]; then
        health_expect core
        health_expect logs
        [[ "$web" == true ]] && health_expect web
        status=0
        if [[ "$web" == true ]]; then check_web_health_status || status=$?
        else check_web_health_status system || status=$?; fi
        [[ "$status" != 0 && "$status" != 2 ]] && result=1
        [[ "$result" == 0 && "$status" == 2 ]] && result=2
        if node_has_role relay || node_has_role node; then
            health_expect bouncer
            health_expect rules
            status=0; check_relay_status || status=$?
            [[ "$status" != 0 && "$status" != 2 ]] && result=1
            [[ "$result" == 0 && "$status" == 2 ]] && result=2
        fi
    else
        log_info '[尚未验证] 本机系统/SSH 防护未部署；继续独立检查 V2bX。'
        result=2
    fi
    if node_has_role node; then
        health_expect v2bx
        health_expect v2bx_service
        health_expect sockets
        status=0; diagnose_v2bx || status=$?
        [[ "$status" != 0 && "$status" != 2 ]] && result=1
        [[ "$result" == 0 && "$status" == 2 ]] && result=2
    fi
    node_recommendation
    return "$result"
}

check_health_status() { health_report overall "${1:-summary}"; }
interactive_health_check() { health_report overall interactive; }

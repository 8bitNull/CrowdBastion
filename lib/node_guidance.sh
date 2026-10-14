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
        log_info '建议：远端连接状态 --relay-bouncer-status；连接来源和转发路径 --relay-path。连接配置入口 [1] → [6]。'
    elif ! node_core_present; then
        if node_has_role web || [[ -z "$NODE_ROLES" ]]; then
            log_info '建议：安装网站基础防护 [1] → [1]，或 --install-core。'
        else
            log_info '建议：如需本机系统/SSH 防护，安装基础防护 [1] → [5]，或 --install-relay。'
        fi
    elif node_has_role web || node_web_deployed || [[ -z "$NODE_ROLES" ]]; then
        log_info '建议：排查网站 [4] → [2]；真实 IP 检查 --diagnose-real-ip。实际网站接入验证需明确选择 --verify-appsec。'
    else
        log_info '建议：先检查连接来源和转发路径 [4] → [3] → [2]，或 --relay-path；规则引用不等于流量阻断验收。'
    fi
    node_has_role node && log_info '落地建议：检查 V2bX 配置与连接来源 --diagnose-v2bx；运行日志 --v2bx-log-check。'
    return 0
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

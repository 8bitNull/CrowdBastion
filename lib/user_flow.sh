#!/usr/bin/env bash
# The coordinator owns navigation; fixed adapters retain operation safeguards.
flow_tool() { PYTHONDONTWRITEBYTECODE=1 python3 "${SCRIPT_DIR}/lib/crowdbastion_flow_cli.py" "$@"; }

flow_collect() {
    local output="$1" stage
    stage=$(mktemp "${output}.XXXXXXXX") || return 1
    if ! flow_tool snapshot "$CS_DIR" "${USER_FLOW_FILE%/*}" > "$stage"; then
        rm -f -- "$stage"
        return 1
    fi
    mv -f -- "$stage" "$output"
}

flow_choose_goals() (
    local answer online=false program=unknown mode work expected
    work=$(mktemp -d "${TMPDIR:-/tmp}/crowdbastion-goals.XXXXXXXX") || return 1
    trap 'rm -rf -- "$work"' EXIT
    expected=$(flow_tool token "$USER_FLOW_FILE") || return 1
    while true; do
        printf '\n希望这台服务器帮你做什么？（可用空格组合）\n1. 保护服务器登录和系统安全\n2. 保护这台服务器上的网站\n3. 检查代理或中转业务的防护情况\n4. 接收另一台检测中心的封禁结果\n5. 不确定，先检查现有配置\n0. 返回，不保存\n'
        prompt answer '请选择业务目标: ' || return 0
        [[ "$answer" != 0 ]] || return 0
        online=false; program=unknown
        # Validate combinations before asking any dependent questions.
        flow_tool prepare-goals "$USER_FLOW_FILE" "$work/candidate" "$answer" false unknown > /dev/null || continue
        if [[ " $answer " == *' 2 '* ]]; then
            printf '\n网站防护范围：\n1. 检测访问日志中的攻击并执行 IP 封禁\n2. 同时接入网站在线请求检查（需要兼容的网站组件）\n0. 取消本次设置\n'
            prompt mode '请选择 [0-2]: ' || return 0
            case "$mode" in 0) return 0 ;; 1) ;; 2) online=true ;; *) log_warn '请选择列出的范围。'; continue ;; esac
        fi
        if [[ " $answer " == *' 3 '* ]]; then
            printf '\n代理业务程序：\n1. V2bX\n2. 其他程序\n3. 不确定\n0. 取消本次设置\n'
            prompt mode '请选择 [0-3]: ' || return 0
            case "$mode" in 0) return 0 ;; 1) program=v2bx ;; 2) program=other ;; 3) ;; *) continue ;; esac
        fi
        flow_tool prepare-goals "$USER_FLOW_FILE" "$work/candidate" "$answer" "$online" "$program" || continue
        confirm '保存上述防护目标？' || return 0
        locked_operation flow_tool save-goals "$USER_FLOW_FILE" "$work/candidate" "$NODE_ROLES_FILE" "$expected" || return $?
        log_succ '防护目标已保存；接下来根据实际检查推荐步骤。'
        return 0
    done
)

flow_choose_targets() {
    local snapshot="$1" answer expected
    if [[ "$(flow_tool target-count "$snapshot")" == 0 ]]; then
        printf '当前未识别到可处理的网站实例。请先确认 Nginx/OpenResty 或网站容器已启动，保留有效配置读取权限；本工具不代替网站程序部署。\n1. 重新只读识别运行环境\n0. 返回，保留待补充条件\n'
        prompt answer '请选择 [0-1]: ' || return 0
        [[ "$answer" == 1 ]] || return 0
        flow_collect "$snapshot"
        return $?
    fi
    printf '\n选择本次要处理的网站运行实例，可用空格选择多个。\n同一实例内多个域名可能一起受影响；不会将一个实例的结果套用到其他实例。\n'
    flow_tool targets "$snapshot" || return 1
    prompt answer '实例编号（0 返回；未发现实例请先准备网站后重新检查）: ' || return 0
    [[ "$answer" != 0 && -n "$answer" ]] || return 0
    expected=$(flow_tool token "$USER_FLOW_FILE") || return 1
    locked_operation flow_tool select-targets "$USER_FLOW_FILE" "$snapshot" "$answer" "$expected"
}

flow_choose_scope() {
    local snapshot="$1" choice
    printf '\n同时发现本机检测与远端执行配置。选择本次维护范围，两类部署仍保留诊断；不会迁移或删除组件。\n1. 维护本机检测\n2. 维护远端执行\n0. 返回\n'
    prompt choice '请选择 [0-2]: ' || return 0
    case "$choice" in
        1) choice=local ;;
        2) choice=remote ;;
        0) return 0 ;;
        *) return 1 ;;
    esac
    locked_operation flow_tool choose-scope "$USER_FLOW_FILE" "$snapshot" "$choice"
}

flow_diagnose() {
    local key="$1" snapshot="${2:-}" saved mode=''
    saved=$(flow_tool state "$USER_FLOW_FILE" 2>/dev/null) || mode='readonly'
    [[ "$saved" != null ]] || mode='readonly'
    [[ -n "$snapshot" ]] || mode='readonly'
    [[ "$mode" != readonly ]] || printf '流程记录不可用，本次仅进行只读排查；不会提供服务启动。\n'
    if [[ "$mode" == readonly ]]; then health_service_diagnose "$key" readonly
    else health_service_diagnose "$key" '' "$snapshot"; fi
}

flow_start_service() {
    local snapshot="$1" key="$2" action
    [[ "${MAINTENANCE_LOCK_HELD:-}" == true ]] || return 75
    case "$key" in core) action=core_diagnose ;; bouncer) action=bouncer_diagnose ;; *) return 1 ;; esac
    flow_tool guard "$snapshot" "$CS_DIR" "${USER_FLOW_FILE%/*}" - "$action" || return 1
    health_start_service "$key"
}

flow_full_check() (
    local snapshot="$1" work="${2:-${1%/*}}" roles result=0 status extra
    flow_collect "$work/refreshed" || return 1
    mv -f -- "$work/refreshed" "$snapshot" || return 1
    roles=$(flow_tool roles "$snapshot" "$USER_FLOW_FILE") || return 1
    if [[ -z "$roles" ]]; then
        printf '当前没有可确定的检测部署范围；先确认目标或查看代理程序支持范围。\n'
        return 0
    fi
    # Limit the new scope resolver to this read-only subshell. CLI stays unchanged.
    # This preference is consumed dynamically by the existing health functions.
    # shellcheck disable=SC2034
    load_node_roles() { NODE_ROLES=$roles; }
    export CROWDBASTION_HEALTH_EVENTS="$work/full-events"
    : > "$work/full-events"
    printf '正在完整检查适用组件；本步骤不会修改配置或服务…\n'
    check_health_status_raw > "$work/details" 2>&1 || result=$?
    # Dual deployments remain observable after choosing which one to maintain.
    if [[ "$roles" != *remote* && -f "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.remote.json" ]]; then
        for extra in remote_bouncer_status check_remote_firewall_status; do
            status=0
            "$extra" >> "$work/details" 2>&1 || status=$?
            if [[ "$status" != 0 && "$status" != 2 ]]; then result=1
            elif [[ "$status" == 2 && "$result" == 0 ]]; then result=2; fi
        done
    elif [[ "$roles" == *remote* && -f "${CS_DIR}/config.yaml" ]]; then
        status=0
        check_web_health_status system >> "$work/details" 2>&1 || status=$?
        if [[ "$status" != 0 && "$status" != 2 ]]; then result=1
        elif [[ "$status" == 2 && "$result" == 0 ]]; then result=2; fi
    fi
    [[ "$result" == 0 || "$result" == 2 ]] || result=1
    python3 "$SCRIPT_DIR/lib/crowdbastion_health.py" json "$work/full-events" "$result" overall "$roles" "$CS_DIR/config.yaml" > "$work/health" || true
    if flow_tool merge-health "$snapshot" "$work/health" > "$work/combined"; then
        mv -- "$work/combined" "$snapshot" || return 1
    else
        log_warn '完整检查未能汇总；原始输出可在检查详情查看。'
        return 1
    fi
    printf '本次只读检查已采集，请按结果页的下一步处理；实际拦截仍需单独验证。\n'
)

flow_details() {
    local snapshot="$1" work="${2:-${1%/*}}"
    if [[ -s "$work/details" ]]; then show_health_details "$work/details"
    else flow_tool report "$snapshot" "$USER_FLOW_FILE"; fi
}

flow_task_list() {
    local snapshot="$1" answer
    flow_tool tasks "$snapshot" "$USER_FLOW_FILE" || return 1
    prompt answer '输入已暂缓项目编号恢复推荐；0 返回: ' || return 0
    [[ -n "$answer" && "$answer" != 0 ]] || return 0
    locked_operation flow_tool resume-number "$USER_FLOW_FILE" "$snapshot" "$answer"
}

flow_apply() {
    local snapshot="$1" action="$2" target="${3:--}"
    [[ "${MAINTENANCE_LOCK_HELD:-}" == true ]] || { log_err '修改任务需要先取得管理锁。'; return 75; }
    flow_tool guard "$snapshot" "$CS_DIR" "${USER_FLOW_FILE%/*}" "${target:--}" "$action" || return 1
    case "$action" in
        configure_appsec) setup_appsec engine-only ;;
        *) log_err '该操作没有直接修改适配器。'; return 1 ;;
    esac
}

flow_guarded_legacy() {
    local snapshot="$1" action="$2" target="$3" detail="${4:-}"
    [[ "${MAINTENANCE_LOCK_HELD:-}" == true ]] || return 75
    flow_tool guard "$snapshot" "$CS_DIR" "${USER_FLOW_FILE%/*}" "$target" "$action" || return 1
    case "$action:$detail" in
        configure_web_logs:*) install_web_rules && repair_log_acquis ;;
        configure_transport:*) configure_docker_endpoints ;;
        connect_website:reuse) link_docker_appsec ;;
        connect_website:*)
            case "$target" in
                host:nginx) install_host_web_bouncer nginx ;;
                host:openresty) install_host_web_bouncer openresty ;;
                docker:*) install_docker_web_bouncer ;;
                *) return 1 ;;
            esac ;;
        verify_realip:verify)
            if [[ "$target" == host:* ]]; then verify_real_ip_request host
            else verify_real_ip_request; fi ;;
        verify_realip:apply)
            if [[ "$target" == host:* ]]; then repair_cloudflare_real_ip apply host
            else repair_cloudflare_real_ip apply; fi ;;
        *) return 1 ;;
    esac
}

flow_remote_apply() {
    [[ "${MAINTENANCE_LOCK_HELD:-}" == true ]] || return 75
    flow_tool guard "$1" "$CS_DIR" "${USER_FLOW_FILE%/*}" - connect_remote || return 1
    remote_bouncer_change install "$2"
}

flow_install_remote() (
    local snapshot="$1" work
    umask 077
    work=$(mktemp -d "${TMPDIR:-/tmp}/crowdbastion-remote-plan.XXXXXXXX") || return 1
    trap 'rm -rf -- "$work"' EXIT
    remote_bouncer_prepare "$work/approved.json" || return $?
    [[ -f "$work/approved.json" ]] || return 0
    locked_operation flow_remote_apply "$snapshot" "$work/approved.json"
)

flow_observation() {
    local snapshot="$1" ident="$2" path="$3"
    [[ -f "$path" && -f "$USER_FLOW_FILE" ]] || return 0
    locked_operation flow_tool record-observed "$USER_FLOW_FILE" "$snapshot" "$ident" "$path"
}

flow_core_apply() {
    local snapshot="$1" profile="$2" plan="$3"
    [[ "${MAINTENANCE_LOCK_HELD:-}" == true ]] || return 75
    local action=install_core_system
    [[ "$profile" != web ]] || action=install_core_web
    flow_tool guard "$snapshot" "$CS_DIR" "${USER_FLOW_FILE%/*}" - "$action" || return 1
    install_crowdsec_core relay "$plan" apply
}

flow_install_core() (
    local profile="$1" snapshot="$2" work
    umask 077
    work=$(mktemp -d "${TMPDIR:-/tmp}/crowdbastion-core-plan.XXXXXXXX") || return 1
    trap 'rm -rf -- "$work"' EXIT
    # Gather administrator input and explicit approval before acquiring a lock.
    install_crowdsec_core relay "$work/plan" prepare || return $?
    [[ -f "$work/plan" ]] || return 0
    locked_operation flow_core_apply "$snapshot" "$profile" "$work/plan"
)

flow_realip() {
    local target="$1" snapshot="$2" choice
    local runtime=()
    [[ "$target" != host:* ]] || runtime=(host)
    printf '\n核对真实访客 IP：先保留现有代理信任；不确定时先诊断。\n1. 通过正常访问核验访客 IP\n2. 只读检查代理路径与信任配置\n3. 根据已经确认的代理来源修正配置（需另行确认）\n0. 返回\n'
    prompt choice '请选择 [0-3]: ' || return 0
    case "$choice" in
        1) locked_operation flow_guarded_legacy "$snapshot" verify_realip "$target" verify ;;
        2) repair_cloudflare_real_ip diagnose "${runtime[@]}" ;;
        3) locked_operation flow_guarded_legacy "$snapshot" verify_realip "$target" apply ;;
        0) return 0 ;;
        *) log_warn '无效选项。'; return 1 ;;
    esac
}

flow_dispatch() {
    local action="$1" target="$2" snapshot="$3" work="${4:-${3%/*}}"
    # The existing host/container adapters consume this dynamically scoped value.
    # shellcheck disable=SC2034
    local CROWDBASTION_FLOW_TARGET="$target"
    case "$action" in
        choose_goals) flow_choose_goals ;;
        choose_targets) flow_choose_targets "$snapshot" ;;
        choose_scope) flow_choose_scope "$snapshot" ;;
        inspect|check_remote|check_firewall) flow_full_check "$snapshot" "$work" ;;
        core_diagnose) flow_diagnose core "$snapshot" ;;
        bouncer_diagnose) flow_diagnose bouncer "$snapshot" ;;
        v2bx_diagnose) flow_diagnose v2bx "$snapshot" ;;
        observer_diagnose) flow_diagnose observer "$snapshot" ;;
        check_proxy) flow_full_check "$snapshot" "$work" ;;
        logs_diagnose) flow_full_check "$snapshot" "$work"; printf '空闲日志请先产生正常样本；解析失败请核对格式、采集标签与解析器。\n'; check_log_inventory ;;
        install_core_system) flow_install_core relay "$snapshot" ;;
        install_core_web) flow_install_core web "$snapshot" ;;
        connect_remote) flow_install_remote "$snapshot" ;;
        configure_web_logs)
            printf '将为选定实例补齐网站日志采集，并在本机全局补齐 HTTP 检测规则；配置变更备份后可能重启检测服务。其他实例日志接入不在本次范围。\n'
            confirm '查看并补齐上述规则与选定实例采集？' || return 0
            locked_operation flow_guarded_legacy "$snapshot" configure_web_logs "$target" ;;
        configure_appsec)
            printf '将为本机配置网站请求检测引擎，补齐相关规则并按需重启检测服务。\n配置变更使用现有备份；软件包不提供整机事务回滚。网站组件需后续单独接入。\n'
            confirm '按上述范围配置引擎？' || return 0
            locked_operation flow_apply "$snapshot" configure_appsec - ;;
        configure_transport)
            printf '只登记已准备且可达的私有地址，不创建网关、不开放公网监听、不修改容器网络。\n'
            locked_operation flow_guarded_legacy "$snapshot" configure_transport "$target" ;;
        connect_website)
            case "$target" in
                host:nginx|host:openresty) locked_operation flow_guarded_legacy "$snapshot" connect_website "$target" ;;
                docker:*)
                    local reuse_choice
                    printf '1. 首次安装网站拦截组件\n2. 复用并接入已有组件\n0. 返回\n'
                    prompt reuse_choice '请选择 [0-2]: ' || return 0
                    case "$reuse_choice" in
                        1) locked_operation flow_guarded_legacy "$snapshot" connect_website "$target" ;;
                        2) confirm '为选定实例接入已有组件并按需重载？' || return 0; locked_operation flow_guarded_legacy "$snapshot" connect_website "$target" reuse ;;
                        0) return 0 ;;
                        *) return 1 ;;
                    esac ;;
                *) log_err '网站实例不确定，请重新选择。'; return 1 ;;
            esac ;;
        verify_realip) flow_realip "$target" "$snapshot" ;;
        diagnose_log_realip)
            printf '请从独立设备正常访问所选站点，对照本次请求的已知公网 IP 与新访问日志。以下诊断只展示线索；来源未经核验时，日志防护和入口验收保持待确认。\n'
            if [[ "$target" == host:* ]]; then
                CROWDBASTION_FLOW_TARGET="$target" repair_cloudflare_real_ip diagnose host
            else
                CROWDBASTION_FLOW_TARGET="$target" repair_cloudflare_real_ip diagnose
            fi ;;
        verify_website)
            rm -f -- "$work/web-auxiliary.json"
            verify_appsec "$work/web-auxiliary.json" "$snapshot" "$target"
            local verification_status=$?
            if [[ "$verification_status" == 0 && -f "$work/web-auxiliary.json" ]]; then
                flow_observation "$snapshot" "web.verify:$target" "$work/web-auxiliary.json" || return 1
            elif [[ -f "$USER_FLOW_FILE" ]]; then
                local outcome=failed
                [[ "$verification_status" != 0 ]] || outcome=cancelled
                locked_operation flow_tool record "$USER_FLOW_FILE" "$snapshot" "web.verify:$target" "$outcome" || return 1
            fi
            printf '内置请求测试仅是辅助证据；请结合外部请求的唯一标识、真实 IP 和具体规则日志完成关联。证据不足时可选 4 暂缓，保留待验证，不会误报通过。\n'
            return "$verification_status" ;;
        verify_entry)
            local scope_roles
            scope_roles=$(flow_tool roles "$snapshot" "$USER_FLOW_FILE") || return 1
            if [[ " $scope_roles " == *' remote '* ]]; then verify_relay remote
            else verify_relay local; fi ;;
        inspect_proxy)
            rm -f -- "$work/proxy-guidance.json"
            manage_proxy_guidance "$work/proxy-guidance.json"
            flow_observation "$snapshot" proxy.inspect "$work/proxy-guidance.json" ;;
        observer_manage) manage_v2bx_observer ;;
        maintain_firewall) locked_operation manage_firewall_maintenance ;;
        maintain_network) manage_network_configuration ;;
        maintain_ports) manage_port_policy ;;
        *) log_err '未知任务操作，未执行。'; return 1 ;;
    esac
}

flow_next() {
    local work="$1" snapshot="$1/snapshot" choice action target ident _evidence result
    while true; do
        flow_tool step "$snapshot" "$USER_FLOW_FILE" || return 1
        prompt choice '请选择 [0-5]: ' || return 0
        case "$choice" in
            0) return 0 ;;
            1)
                IFS=$'\t' read -r action target ident _evidence < <(flow_tool next "$snapshot" "$USER_FLOW_FILE") || return 1
                case "$action" in
                    choose_goals|choose_targets|choose_scope|inspect|check_remote|check_firewall|check_proxy|observer_diagnose|core_diagnose|bouncer_diagnose|v2bx_diagnose|logs_diagnose|diagnose_log_realip|inspect_proxy|maintain_firewall|maintain_network|maintain_ports) ;;
                    *)
                        if [[ -f "$USER_FLOW_FILE" ]]; then
                            locked_operation flow_tool record "$USER_FLOW_FILE" "$snapshot" "$ident" running || { log_warn '未能保存本次任务，未执行；请检查锁和流程记录。'; continue; }
                        fi ;;
                esac
                result=0
                flow_dispatch "$action" "$target" "$snapshot" "$work" || result=$?
                case "$action" in
                    choose_goals|choose_targets|choose_scope|inspect|check_remote|check_firewall|check_proxy|observer_diagnose|core_diagnose|bouncer_diagnose|v2bx_diagnose|logs_diagnose|diagnose_log_realip|inspect_proxy|verify_website|maintain_firewall|maintain_network|maintain_ports) ;;
                    *)
                        if [[ -f "$USER_FLOW_FILE" ]]; then
                            local outcome=returned
                            [[ "$result" == 0 ]] || outcome=failed
                            locked_operation flow_tool record "$USER_FLOW_FILE" "$snapshot" "$ident" "$outcome" || log_warn '任务记录未能更新；下次将重新核查实际状态。'
                        fi ;;
                esac
                if [[ "$result" != 0 ]]; then
                    log_warn '本步骤未完成，请核对上方失败及恢复说明；不会自动重试。'
                fi
                printf '操作已返回，以复查证据判断本项是否完成；正在重新检查…\n'
                # Keep evidence from an explicitly requested full read-only check.
                case "$action" in
                    inspect|check_remote|check_firewall|check_proxy|logs_diagnose) ;;
                    *) rm -f -- "$work/details"; flow_collect "$snapshot" || return 1 ;;
                esac ;;
            2) flow_details "$snapshot" "$work" ;;
            3) flow_task_list "$snapshot" ;;
            4)
                IFS=$'\t' read -r action target ident _evidence < <(flow_tool next "$snapshot" "$USER_FLOW_FILE") || return 1
                if [[ "$ident" == inspect ]]; then printf '当前没有可暂缓的推荐任务。\n'
                else
                    printf '暂缓会保留未完成或待验证状态；依赖它的步骤不会自动执行。\n'
                    locked_operation flow_tool defer "$USER_FLOW_FILE" "$snapshot" "$ident" || true
                fi ;;
            5) rm -f -- "$work/details"; flow_collect "$snapshot" || return 1 ;;
            *) log_warn '无效选项。' ;;
        esac
    done
}

flow_daily() {
    local choice
    while true; do
        printf '\n日常管理\n1. IP 封禁与放行\n2. 通知与 Telegram\n3. 检测规则维护\n4. 查看源码与定时维护副本版本\n5. 确认后同步维护副本（保留执行时间）\n6. 查看备份与恢复说明\n0. 返回首页\n'
        prompt choice '请选择 [0-6]: ' || return 0
        case "$choice" in
            1) locked_operation manage_firewall_ops ;;
            2) locked_operation manage_telegram ;;
            3) locked_operation manage_waf_rules ;;
            4) show_maintenance_runtime_status ;;
            5) locked_operation sync_maintenance_runtime ;;
            6) printf '本工具配置备份位于 %s。恢复需核对具体变更及对应恢复说明；软件包、业务数据和实时数据库不是整机事务备份。详见 docs/usage-guide.md 的备份与失败恢复。\n' "$UPDATE_BACKUPS" ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
    done
}

flow_advanced() { manage_advanced; }

flow_run() (
    local choice FLOW_WORK
    require_commands python3 || return 1
    umask 077
    FLOW_WORK=$(mktemp -d "${TMPDIR:-/tmp}/crowdbastion-flow.XXXXXXXX") || return 1
    trap 'rm -rf -- "$FLOW_WORK"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    printf '正在只读识别环境与已有部署…\n'
    flow_collect "$FLOW_WORK/snapshot" || return 1
    while true; do
        flow_tool home "$FLOW_WORK/snapshot" "$USER_FLOW_FILE" || return 1
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) flow_next "$FLOW_WORK" ;;
            2) flow_daily; flow_collect "$FLOW_WORK/snapshot" || return 1 ;;
            3) flow_choose_goals; flow_collect "$FLOW_WORK/snapshot" || return 1 ;;
            4) flow_advanced; flow_collect "$FLOW_WORK/snapshot" || return 1 ;;
            0) return 0 ;;
            *) log_warn '无效选项，请输入菜单编号。' ;;
        esac
    done
)

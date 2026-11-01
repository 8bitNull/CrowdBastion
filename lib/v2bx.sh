#!/usr/bin/env bash
# No service/config/decision changes. Optional selectors are operator declarations.
diagnose_v2bx() {
    if [[ -n "${CROWDBASTION_HEALTH_EVENTS:-}" ]]; then diagnose_v2bx_raw
    else health_report node "${1:-summary}"; fi
}

diagnose_v2bx_raw() {
    health_expect v2bx
    health_expect v2bx_service
    health_expect sockets
    require_yaml || return 1
    load_node_roles || return 1
    local args=(--cs-dir "$CS_DIR" --unit "${V2BX_UNIT:-V2bX.service}" --entries "${V2BX_ENTRIES:-}")
    if node_has_role remote; then
        args+=(--bouncer-only)
    elif [[ ! -f "${CS_DIR}/config.yaml" ]] && { node_has_role node || [[ -z "$NODE_ROLES" ]]; }; then
        args+=(--bouncer-only --firewall-optional)
    fi
    [[ -z "${V2BX_CONFIG:-}" ]] || args+=(--config "$V2BX_CONFIG")
    [[ -z "${V2BX_WORKING_DIR:-}" ]] || args+=(--working-dir "$V2BX_WORKING_DIR")
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx.py" "${args[@]}"
}

check_v2bx_logs() {
    local sample_file="${V2BX_LOG_FILE:-}" sample_core="${V2BX_LOG_CORE:-}"
    if [[ -z "$sample_file" ]]; then
        prompt sample_file '本机日志样本路径（q 取消）: ' || return 0
        [[ "$sample_file" != q && -n "$sample_file" ]] || return 0
    fi
    if [[ -z "$sample_core" ]]; then
        prompt sample_core '样本内核 xray/sing/hysteria2（q 取消）: ' || return 0
        [[ "$sample_core" != q && -n "$sample_core" ]] || return 0
    fi
    require_yaml || return 1
    local args=(--file "$sample_file" --core "$sample_core" --unit "${V2BX_UNIT:-V2bX.service}" --relay-cidrs "${V2BX_RELAY_CIDRS:-}")
    [[ -z "${V2BX_LOG_TIMEZONE:-}" ]] || args+=(--timezone "$V2BX_LOG_TIMEZONE")
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_logs.py" "${args[@]}"
}

# Opt-in sample storage only; production acquisition and services are untouched.
observe_v2bx_logs() {
    if [[ -z "${V2BX_LOG_FILE:-}" || -z "${V2BX_LOG_CORE:-}" || -z "${V2BX_OBSERVE_DB:-}" ]]; then
        echo '请设置 V2BX_LOG_FILE、V2BX_LOG_CORE、V2BX_OBSERVE_DB；数据库需放在当前用户的私有目录。'
        return 1
    fi
    require_yaml || return 1
    local args=(--file "$V2BX_LOG_FILE" --core "$V2BX_LOG_CORE" --database "$V2BX_OBSERVE_DB"
        --unit "${V2BX_UNIT:-V2bX.service}" --relay-cidrs "${V2BX_RELAY_CIDRS:-}"
        --duration "${V2BX_OBSERVE_DURATION:-60}" --max-events "${V2BX_OBSERVE_MAX_EVENTS:-100000}")
    [[ -z "${V2BX_LOG_TIMEZONE:-}" ]] || args+=(--timezone "$V2BX_LOG_TIMEZONE")
    [[ -z "${V2BX_OBSERVE_EXPORT:-}" ]] || args+=(--export "$V2BX_OBSERVE_EXPORT")
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_observe.py" "${args[@]}"
}

# Dedicated local service; no CrowdSec rules, acquisition or firewall changes.
v2bx_observer_service() {
    local action="$1" args=()
    require_yaml || return 1
    if [[ "$action" == install ]]; then
        if [[ -z "${V2BX_OBSERVER_CONFIG:-}" ]]; then
            echo '请设置 V2BX_OBSERVER_CONFIG 为私有 JSON 配置文件路径；格式见 V2bX 指南。'
            return 1
        fi
        args+=(--config "$V2BX_OBSERVER_CONFIG")
    fi
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_service.py" "$action" "${args[@]}"
}


manage_v2bx_node() {
    local choice
    while true; do
        printf '\nV2bX 落地节点\n按配置检查、样本分析、持续记录、异常告警的顺序接入；已有配置可直接检查。\n1. 检查节点配置和连接来源\n2. 分析已有日志样本（需路径和内核类型）\n3. 管理持续日志记录\n4. 管理异常告警（先完成持续记录）\n观察与告警不提供业务攻击自动封禁。\n0. 返回\n'
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) diagnose_v2bx interactive ;;
            2) check_v2bx_logs ;;
            3) manage_v2bx_observer; continue ;;
            4) manage_v2bx_alerts; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

show_v2bx_observer_config_help() {
    cat <<'EOF'

准备持续记录配置（本页不创建文件）
将以下单源示例保存为本机私有 JSON 文件，由 root 所有并设置权限 0600。
替换 file 为真实存在的独立内核日志；xray 必须填写实际时区。
{
  "poll_interval": 1,
  "sources": [
    {"name": "xray", "core": "xray", "file": "/var/log/V2bX/xray-error.log", "timezone": "+08:00", "relay_cidrs": ""}
  ]
}
core 支持 xray、sing、hysteria2；relay_cidrs 填实际中转出口网段，以逗号分隔。
不要直接沿用示例时区。每个内核使用独立普通文件，不支持符号链接和 /tmp、/var/tmp 日志。
准备后选择 1 并输入配置绝对路径；仅有 journal 时先使用日志样本分析。
完整格式、多源及容量说明见项目 docs/v2bx-guide.md 的“落地常驻仅观察服务”。
EOF
}

manage_v2bx_observer() {
    local choice
    local V2BX_OBSERVER_CONFIG="${V2BX_OBSERVER_CONFIG:-}"
    while true; do
        printf '\n持续记录落地节点日志\n首次使用可选 5 交互生成配置，或选 4 查看多源示例，再选 1；记录健康后返回落地菜单开启异常告警。\n1. 使用已准备的配置开始记录\n2. 查看记录情况\n3. 停止记录，保留已有数据\n4. 查看配置示例与准备步骤\n5. 交互生成并校验单源配置\n0. 返回\n'
        prompt choice '请选择 [0-5]: ' || return 0
        case "$choice" in
            1)
                if [[ -z "$V2BX_OBSERVER_CONFIG" ]]; then
                    prompt V2BX_OBSERVER_CONFIG '日志记录配置文件路径（留空返回）: ' || return 0
                    [[ -n "$V2BX_OBSERVER_CONFIG" ]] || continue
                fi
                locked_operation v2bx_observer_service install ;;
            2) v2bx_observer_service status ;;
            3) locked_operation v2bx_observer_service disable ;;
            4) show_v2bx_observer_config_help ;;
            5) generate_v2bx_observer_config ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_v2bx_alerts() {
    local choice
    while true; do
        printf '\n落地节点异常告警\n先开启持续日志记录；这里的异常只生成告警。\n开启或停用告警会重启 CrowdSec。\n1. 开启异常告警\n2. 查看告警接入情况\n3. 停用告警，保留已有记录\n0. 返回\n'
        prompt choice '请选择 [0-3]: ' || return 0
        case "$choice" in
            1) locked_operation v2bx_alert_service enable ;;
            2) v2bx_alert_service status ;;
            3) locked_operation v2bx_alert_service disable ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

# Managed observation guard and incremental output; no remediation decisions.
v2bx_alert_service() {
    require_yaml || return 1
    python3 "${SCRIPT_DIR}/lib/crowdsec_v2bx_alerts.py" "$1"
}

#!/usr/bin/env bash
# Generic declaration-only proxy guidance; no V2bX installation dependency.

# All fields are declarations, never backend/config discovery or log support.
protocol_status() {
    python3 "${SCRIPT_DIR}/lib/crowdbastion_protocols.py" \
        --program "${NODE_PROGRAM:-unknown}" --protocol "${NODE_PROTOCOL:-unknown}" \
        --transport "${NODE_TRANSPORT:-}" --version "${NODE_VERSION:-}" \
        --topology "${NODE_TOPOLOGY:-unknown}"
}

# Fixed numbered declarations only. No free-form commands, preference writes or
# environment updates survive the caller's temporary function assignment.
protocol_choose() {
    local destination="$1" title="$2" choice index option
    shift 2
    local options=("$@")
    while true; do
        printf '\n%s\n' "$title"
        for ((index=0; index<${#options[@]}; index++)); do
            option="${options[index]}"
            printf '%s. %s\n' "$((index+1))" "${option#*|}"
        done
        printf '0. 取消并返回\n'
        prompt choice '请选择编号: ' || return 1
        [[ "$choice" != 0 ]] || return 1
        if [[ "$choice" =~ ^[1-9][0-9]?$ ]] && (( 10#$choice <= ${#options[@]} )); then
            option="${options[10#$choice-1]}"
            printf -v "$destination" '%s' "${option%%|*}"
            return 0
        fi
        log_warn '请选择本页列出的编号；不确定时选择“不确定”。'
    done
}

guided_protocol_status() {
    local program protocol transport topology result=0 observation="${1:-}"
    local transports=('unknown|不确定（保持未知，不推断 TCP）')
    printf '\n协议与传输选择（只读）\n选择只用于本次说明，不保存配置、不安装程序或应用调优。\n程序名称不是协议；TLS 仅表示安全层；不确定时保持未知。\n'
    protocol_choose program '运行的是哪个程序？' \
        'v2bx|V2bX（版本及实际运行仍需核验）' \
        'v2node|V2Node（实际仓库/版本未核验）' \
        'unknown|其他程序或不确定' || return 0
    protocol_choose protocol '使用哪种代理协议？' \
        'anytls|AnyTLS' 'vmess|VMess' 'vless|VLESS' \
        'shadowsocks|Shadowsocks' 'shadowsocks2022|Shadowsocks 2022' \
        'trojan|Trojan' 'hysteria1|Hysteria 1' 'hysteria2|Hysteria 2' \
        'tuic|TUIC' 'unknown|不确定' || return 0
    case "$protocol" in
        vmess|vless)
            transports+=('tcp|TCP' 'raw|RAW/TCP' 'ws|WebSocket' 'grpc|gRPC' \
                'httpupgrade|HTTPUpgrade' 'xhttp|XHTTP（还需版本及 HTTP 传输证据）' \
                'quic|QUIC' 'udp|UDP' 'tls|仅确认 TLS，底层传输不确定') ;;
        shadowsocks|shadowsocks2022)
            transports+=('tcp|仅 TCP' 'udp|仅 UDP' 'tcp+udp|TCP 和 UDP') ;;
        trojan|anytls)
            transports+=('tcp|TCP' 'tls|标准 TLS/TCP 外层（需核对实际配置）')
            [[ "$protocol" != anytls ]] || transports+=('udp-over-tcp|UDP-over-TCP（外层仍为 TCP）') ;;
        hysteria1)
            transports+=('udp|UDP' 'quic|QUIC/UDP' 'wechat-video|wechat-video' \
                'faketcp|faketcp（专项审计，不等同内核 TCP）') ;;
        hysteria2)
            transports+=('quic|QUIC/UDP' 'udp|UDP' \
                'faketcp|已明确配置 mimic/faketcp（需实现/版本证据）') ;;
        tuic) transports+=('quic|QUIC/UDP') ;;
    esac
    protocol_choose transport '实际外层传输是什么？请按配置选择。' "${transports[@]}" || return 0
    protocol_choose topology '入口拓扑是什么？' 'unknown|不确定' \
        'direct|客户端直连' 'shared-relay|经共享中转（不能据 socket 识别真实用户）' || return 0
    NODE_PROGRAM="$program" NODE_PROTOCOL="$protocol" NODE_TRANSPORT="$transport" \
        NODE_TOPOLOGY="$topology" NODE_VERSION='' protocol_status || result=$?
    if [[ -n "$observation" && ( "$result" == 0 || "$result" == 2 ) && ! -e "$observation" ]]; then
        flow_tool write-observation "$observation" proxy_guidance || return 1
    fi
    return "$result"
}

manage_proxy_guidance() {
    local choice observation="${1:-}"
    while true; do
        printf '\n代理协议使用导航\n适用指导：AnyTLS、VMess、VLESS、Shadowsocks/2022、Trojan、Hysteria 1/2、TUIC。\n先确认程序、协议、实际传输与中转路径；未知项保持未知。\n1. 交互选择程序、协议和传输，查看指导（只读）\n2. 短时环境压力检查（只读）\n3. 查看 TCP 配置归属与运行值（只读）\n4. 管理选定入口端口策略（修改需另行确认）\n5. 可选 TCP 配置管理（修改需另行确认）\n6. V2bX 专项检测、日志观察与告警\nQUIC 使用程序自身的拥塞控制；TCP 配置核验不代表 QUIC 调优或真实吞吐提升。\n独立代理程序无需套用网站/AppSec 接入；协议指导不代表已有专项日志检测。\n0. 返回\n'
        prompt choice '请选择 [0-6]: ' || return 0
        case "$choice" in
            1) guided_protocol_status "$observation" ;;
            2) environment_tool --human ;;
            3) change_human_action network status ;;
            4) manage_port_policy; continue ;;
            5) manage_network_configuration; continue ;;
            6) manage_v2bx_node; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

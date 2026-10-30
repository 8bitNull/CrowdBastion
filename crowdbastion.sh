#!/usr/bin/env bash
# CrowdBastion：基于 CrowdSec 的服务器防护与运维管理工具。
# 配置修改使用同目录 lib/crowdsec_config.py；完整说明见 readme.md。
set -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MANAGER_FILE="${BASH_SOURCE[0]}"
CONFIG_HELPER="${SCRIPT_DIR}/lib/crowdsec_config.py"
CS_DIR="/etc/crowdsec"
NODE_ROLES_FILE="/var/lib/crowdbastion/node-roles.json"
NODE_ROLES=''
WEBUI_DIR="/opt/crowdsec-web-ui"
CRON_FILE="/etc/cron.d/crowdsec-autoupdate"
# 保留旧版运行标识，以复用已有配置、服务、锁、备份及托管资源。
HUB_RUNNER_DIR="/opt/crowdsec-1key-maintenance"
HUB_LOCK_FILE="/run/lock/crowdsec-1key-hub.lock"
HUB_LOG_FILE="/var/log/crowdsec-1key-hub.log"
# shellcheck source=lib/hub_maintenance.sh
source "${SCRIPT_DIR}/lib/hub_maintenance.sh"
TG_NOTIF_FILE="${CS_DIR}/notifications/crowdsec-1key-telegram.yaml"
CUSTOM_BOT_SCRIPT="/usr/local/lib/crowdsec-1key-bot/crowdsec_bot.py"
CUSTOM_BOT_CONFIG="${CS_DIR}/crowdsec-1key-bot.json"
CUSTOM_BOT_UNIT="/etc/systemd/system/crowdsec-1key-bot.service"
CUSTOM_BOT_STATE="/var/lib/crowdsec-1key-bot"
CUSTOM_BOT_LEGACY="/usr/local/bin/crowdsec_bot.py"
CUSTOM_BOT_CRON_DIR="/etc/cron.d"
# shellcheck source=lib/custom_bot.sh
source "${SCRIPT_DIR}/lib/custom_bot.sh"
NOTIFY_CODE="/usr/local/lib/crowdbastion-notify"
NOTIFY_CONFIG="${CS_DIR}/crowdbastion-notify.json"
NOTIFY_UNIT="/etc/systemd/system/crowdbastion-notify.service"
NOTIFY_STATE="/var/lib/crowdbastion-notify"
# shellcheck source=lib/notify.sh
source "${SCRIPT_DIR}/lib/notify.sh"
PROFILES_FILE="${CS_DIR}/profiles.yaml"
APPSEC_FILE="${CS_DIR}/acquis.d/crowdsec-1key-appsec.yaml"
APPSEC_LINKS="${CS_DIR}/crowdsec-1key-appsec-links.yaml"
APPSEC_DOCKER_LINKS="${CS_DIR}/crowdsec-1key-appsec-docker-links.yaml"
WEB_INSTALLS="${CS_DIR}/crowdsec-1key-web-installs.json"
REALIP_STATE="${CS_DIR}/crowdsec-1key-real-ip.json"
IP_VERIFICATIONS="${CS_DIR}/crowdsec-1key-ip-verifications.json"
DOCKER_ENDPOINTS="${CS_DIR}/crowdsec-1key-docker-endpoints.json"
MAINTENANCE_LOCK='/run/lock/crowdsec-1key.lock'
MAINTENANCE_RUNTIME='/usr/local/lib/crowdsec-1key'
UPDATE_BACKUPS='/var/backups/crowdsec-1key'
UPDATE_LOG='/var/log/crowdsec-1key-update.log'
CORE_RULES_CHANGED=false
source "${SCRIPT_DIR}/lib/maintenance.sh"
# shellcheck source=lib/native_web_bouncer.sh
source "${SCRIPT_DIR}/lib/nginx_reload.sh"
source "${SCRIPT_DIR}/lib/native_web_bouncer.sh"
# shellcheck source=lib/host_web_bouncer.sh
source "${SCRIPT_DIR}/lib/host_web_bouncer.sh"
# shellcheck source=lib/real_ip.sh
source "${SCRIPT_DIR}/lib/real_ip.sh"
source "${SCRIPT_DIR}/lib/private_transport.sh"
# shellcheck source=lib/appsec_audit.sh
source "${SCRIPT_DIR}/lib/appsec_audit.sh"
# shellcheck source=lib/relay.sh
source "${SCRIPT_DIR}/lib/relay.sh"
# shellcheck source=lib/v2bx.sh
source "${SCRIPT_DIR}/lib/v2bx.sh"
# shellcheck source=lib/remote_bouncer.sh
source "${SCRIPT_DIR}/lib/remote_bouncer.sh"
# shellcheck source=lib/health_summary.sh
source "${SCRIPT_DIR}/lib/health_summary.sh"
# shellcheck source=lib/node_guidance.sh
source "${SCRIPT_DIR}/lib/node_guidance.sh"
REMOTE_BINARY="/usr/local/bin/crowdsec-firewall-bouncer"
REMOTE_UNIT="/etc/systemd/system/crowdsec-firewall-bouncer.service"
LOG_REPAIR_FILE="${CS_DIR}/acquis.d/crowdsec-1key-log-repair.yaml"
LOG_REPAIR_STAGE=''
LOG_REPAIR_COUNT=0
LOG_PRESET_FILE=''
WEBUI_IMAGE="ghcr.io/theduffman85/crowdsec-web-ui:latest"
BACKUP_PATHS=()
BACKUP_COPIES=()

log_info() { printf '[INFO] %s\n' "$*"; }
log_succ() { printf '[SUCCESS] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_err() { printf '[ERROR] %s\n' "$*" >&2; }

pause() {
    if [[ -t 0 ]]; then
        read -r -p '按回车键继续...' _ || true
    fi
    return 0
}

prompt() {
    local _prompt_name="$1" _prompt_message="$2"
    read -r -p "$_prompt_message" "${_prompt_name?}"
}

confirm() {
    local answer
    prompt answer "$1 [y/N]: " && [[ "$answer" =~ ^[yY]$ ]]
}

require_commands() {
    local cmd
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_err "缺少命令 ${cmd}，请先安装所需组件。"
            return 1
        fi
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err '该操作需要 root 权限，请使用 sudo bash crowdbastion.sh。'
        return 1
    fi
}

detect_os() {
    OS_ID=linux
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-linux}"
    fi
}

require_yaml() {
    require_commands python3 || return 1
    if [[ ! -f "$CONFIG_HELPER" ]]; then
        log_err '缺少 lib/crowdsec_config.py，请下载完整仓库后运行。'
        return 1
    fi
    if ! python3 -c 'import yaml' 2>/dev/null; then
        log_err '需要 PyYAML：Debian/Ubuntu 安装 python3-yaml；RHEL 系列安装 python3-pyyaml。'
        case "${OS_ID:-linux}" in
            debian|ubuntu)
                log_info '安装命令：sudo apt-get update && sudo apt-get install -y python3-yaml' ;;
            centos|rhel|almalinux|rocky|fedora)
                if command -v dnf >/dev/null 2>&1; then
                    log_info '安装命令：sudo dnf install -y python3-pyyaml'
                else
                    log_info '安装命令：sudo yum install -y python3-pyyaml'
                fi ;;
        esac
        log_info "当前 Python：$(command -v python3)；安装后请验证：sudo python3 -c 'import yaml; print(yaml.__version__)'"
        return 1
    fi
}

yaml_tool() {
    require_yaml || return 1
    python3 "$CONFIG_HELPER" "$@"
}

require_core() {
    require_commands crowdsec cscli systemctl || return 1
    if [[ ! -f "${CS_DIR}/config.yaml" ]]; then
        if node_has_role relay || { node_has_role node && ! node_has_role web; }; then
            log_err '请先通过菜单 [1] → [5] 或 --install-relay 安装本机系统/SSH 基础防护。'
        else
            log_err '请先通过菜单 [1] → [1] 或 --install-core 安装 CrowdSec 核心。'
        fi
        return 1
    fi
}

begin_config_change() {
    local backup path i=0
    BACKUP_PATHS=()
    BACKUP_COPIES=()
    mkdir -p /var/backups/crowdsec-1key || return 1
    backup=$(mktemp -d /var/backups/crowdsec-1key/change.XXXXXXXX) || return 1
    chmod 700 "$backup" || return 1
    for path in "$@"; do
        BACKUP_PATHS+=("$path")
        BACKUP_COPIES+=("${backup}/${i}")
        if [[ -e "$path" || -L "$path" ]]; then
            cp -a -- "$path" "${backup}/${i}" || return 1
        else
            touch "${backup}/${i}.absent" || return 1
        fi
        ((i+=1))
    done
    log_info "修改前备份: ${backup}"
    if [[ -n "$HUB_TX_BACKUP" ]]; then HUB_TX_CONFIG=true; fi
    # shellcheck disable=SC2031 # dynamically scoped by the caller, not exported from a subshell
    if [[ "$CORE_CONFIG_TRACKING" == true ]]; then CORE_CONFIG_PENDING=true; fi
}

restore_config_change() {
    local i
    for i in "${!BACKUP_PATHS[@]}"; do
        if [[ -f "${BACKUP_COPIES[$i]}.absent" ]]; then
            rm -f -- "${BACKUP_PATHS[$i]}" || return 1
        elif [[ -L "${BACKUP_COPIES[$i]}" || -L "${BACKUP_PATHS[$i]}" ]]; then
            cp -a --remove-destination -- "${BACKUP_COPIES[$i]}" "${BACKUP_PATHS[$i]}" || return 1
        else
            cp -a -- "${BACKUP_COPIES[$i]}" "${BACKUP_PATHS[$i]}" || return 1
        fi
    done
    CORE_CONFIG_PENDING=false
    log_warn '已恢复本次修改前的配置。'
}

restore_core_change() {
    local restored=true
    restore_config_change || restored=false
    hub_abort no-load || restored=false
    if [[ "$restored" != true ]]; then log_err '配置或 Hub 恢复不完整，未自动重新加载核心。'; return 1; fi
    if ! crowdsec -t || ! systemctl restart crowdsec || ! systemctl is-active --quiet crowdsec; then
        log_err '原配置加载失败，请手工核验核心服务。'
        return 1
    fi
}

apply_core_config() {
    local operation="${1:-restart}"
    if ! crowdsec -t; then
        log_err 'CrowdSec 配置校验失败，未重启服务。'
        restore_config_change
        hub_abort no-load
        return 1
    fi
    if ! config_change_needed && systemctl is-active --quiet crowdsec; then
        hub_finalize || { hub_abort no-load; return 1; }
        CORE_CONFIG_PENDING=false
        log_info '配置未变化，跳过核心重启。'
        return 0
    fi
    CORE_CONFIG_LOADING="$operation"
    if ! systemctl "$operation" crowdsec || ! systemctl is-active --quiet crowdsec; then
        log_err 'CrowdSec 服务未正常启动，正在回滚配置。'
        restore_core_change || true
        return 1
    fi
    if ! hub_finalize; then
        restore_core_change || true
        return 1
    fi
    CORE_RULES_CHANGED=false
    CORE_CONFIG_LOADING=''
    CORE_CONFIG_PENDING=false
}

install_packages() {
    local requested missing=()
    for requested in "$@"; do
        case "${OS_ID}" in
            debian|ubuntu)
                [[ "$(dpkg-query -W -f='${Status}' "$requested" 2>/dev/null)" == 'install ok installed' ]] || missing+=("$requested") ;;
            centos|rhel|almalinux|rocky|fedora)
                rpm -q "$requested" >/dev/null 2>&1 || missing+=("$requested") ;;
            *) log_err "未支持的系统: ${OS_ID}"; return 1 ;;
        esac
    done
    if ((${#missing[@]} == 0)); then log_info '所需软件包已安装，跳过安装/升级。'; return 0; fi
    case "${OS_ID}" in
        # apt may allocate a PTY for postinst even without an interactive
        # caller. Bouncer 0.0.36 aborts color setup on monochrome terminals.
        debian|ubuntu) NO_COLOR=1 apt-get install -y --no-upgrade "${missing[@]}" ;;
        centos|rhel|almalinux|rocky|fedora)
            if command -v dnf >/dev/null 2>&1; then dnf install -y "${missing[@]}"; else yum install -y "${missing[@]}"; fi ;;
        *) log_err "未支持的系统: ${OS_ID}"; return 1 ;;
    esac
}

install_bouncer_package() {
    local config="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" mode=''
    if [[ -f "$config" ]]; then
        mode=$(yaml_tool bouncer-mode "$config") || return 1
        python3 "${SCRIPT_DIR}/lib/crowdsec_firewall.py" guard "$config" || return 1
        case "$mode" in
            nftables) install_packages nftables crowdsec-firewall-bouncer-nftables; return $? ;;
            iptables|ipset) install_packages iptables ipset crowdsec-firewall-bouncer-iptables; return $? ;;
            *) log_err '已有 Bouncer 的 mode 无效，未自动更换防火墙后端。'; return 1 ;;
        esac
    fi
    log_info '新装使用 iptables/ipset，规避已确认的 nftables 续封缺陷；iptables 可使用 nf_tables 兼容层。'
    install_packages iptables ipset crowdsec-firewall-bouncer-iptables
}

check_firewall_backend() {
    require_yaml || return 1
    python3 "${SCRIPT_DIR}/lib/crowdsec_firewall.py" audit "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml"
}

detect_admin_ip() {
    CURRENT_IP=''
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        CURRENT_IP="${SSH_CLIENT%% *}"
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        CURRENT_IP="${SSH_CONNECTION%% *}"
    fi
}

install_crowdsec_core() (
    local profile="${1:-web}" acquisition_paths=()
    case "$profile" in web|relay) ;; *) log_err '未知安装模式。'; return 1 ;; esac
    remote_bouncer_local_core_guard || return 1
    if [[ -f "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" ]]; then
        require_yaml || return 1
        python3 "${SCRIPT_DIR}/lib/crowdsec_firewall.py" guard "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" || return 1
    fi
    CORE_CONFIG_TRACKING=true
    CORE_CONFIG_PENDING=false
    trap hub_workflow_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    case "${OS_ID}" in
        debian|ubuntu|centos|rhel|almalinux|rocky|fedora) ;;
        *) log_err "当前系统不在安装支持范围: ${OS_ID}"; return 1 ;;
    esac
    require_commands systemctl || return 1
    detect_admin_ip
    if [[ -z "$CURRENT_IP" ]]; then
        prompt CURRENT_IP '管理员公网 IP（留空仅放行内网；Ctrl+D 取消）: ' || return 1
    fi
    local fresh=true
    if command -v crowdsec >/dev/null 2>&1 && [[ -f "${CS_DIR}/config.yaml" ]]; then fresh=false; fi
    [[ "$OS_ID" =~ ^(debian|ubuntu)$ && "$fresh" == true ]] && { apt-get update || return 1; }
    case "$OS_ID" in
        debian|ubuntu) install_packages curl ca-certificates python3 python3-yaml || return 1 ;;
        *) install_packages curl ca-certificates python3 python3-pyyaml || return 1 ;;
    esac
    require_yaml || return 1
    if [[ -n "$CURRENT_IP" ]] && ! yaml_tool ip "$CURRENT_IP"; then
        log_err '管理员 IP 无效，尚未安装 CrowdSec。'
        return 1
    fi
    if [[ "$fresh" == true ]]; then
        local installer
        installer=$(mktemp) || return 1
        if ! curl -fLsS --connect-timeout 10 --max-time 120 https://install.crowdsec.net -o "$installer" || ! bash "$installer"; then
            rm -f "$installer"
            log_err '官方软件源配置失败。'
            return 1
        fi
        rm -f "$installer"
    else
        log_info '已有核心安装，保留软件源及现有版本。'
    fi
    install_packages crowdsec || return 1
    install_bouncer_package || return 1
    require_core || return 1
    if [[ "$profile" == relay ]]; then
        log_info '纯中转节点精简模式：仅补齐系统/SSH 规则与采集；已有 Web/AppSec 配置保留。'
        install_collections crowdsecurity/linux crowdsecurity/sshd crowdsecurity/whitelist-good-actors || return $?
        prepare_relay_logs /var/log/auth.log /var/log/secure || return 1
        acquisition_paths=("$LOG_REPAIR_FILE")
    else
        install_collections crowdsecurity/linux crowdsecurity/sshd crowdsecurity/nginx crowdsecurity/nginx-proxy-manager crowdsecurity/http-cve crowdsecurity/base-http-scenarios crowdsecurity/whitelist-good-actors || return $?
        prepare_log_repair || return 1
        acquisition_paths=("$LOG_REPAIR_FILE" "$LOG_PRESET_FILE")
    fi
    begin_config_change "${CS_DIR}/parsers/s02-enrich/99-admin-whitelist.yaml" "${acquisition_paths[@]}" "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || { cleanup_log_repair; return 1; }
    if ! yaml_tool whitelist "${CS_DIR}/parsers/s02-enrich/99-admin-whitelist.yaml" "$CURRENT_IP" || ! apply_staged_log_repair || ! enable_prometheus_metrics || ! systemctl enable crowdsec || ! apply_core_config; then
        restore_config_change
        cleanup_log_repair
        return 1
    fi
    cleanup_log_repair
    systemctl enable --now crowdsec-firewall-bouncer || return 1
    if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
        log_err 'Firewall Bouncer 未运行，请查看 journalctl -u crowdsec-firewall-bouncer。'
        return 1
    fi
    log_succ 'CrowdSec 和 Firewall Bouncer 服务已启动。'
    log_info '请用菜单 [4] → [1] 检查日志采集和 Bouncer 注册；Docker 转发流量需要对应防火墙链。'
    if [[ "$profile" == relay ]]; then
        log_info '请用 cscli metrics 核验 SSH 日志读取与解析；自定义 SSH unit/日志路径需人工核对。'
        log_info '使用 --relay-status 检查 INPUT/FORWARD 和 IPv4/IPv6 规则；实际中转业务阻断尚未验证。'
        log_info '此模式不提供 gost/realm 专用行为检测、连接限速或带宽型 DDoS 清洗。'
        relay_after_install local
    fi
)

configure_log_acquis() {
    local target="${1:-}"
    if [[ -z "$target" ]]; then target=$(yaml_tool log-acquis-file "$CS_DIR") || return 1; fi
    mkdir -p "$(dirname "$target")" || return 1
    cat > "$target" <<'EOF'
filenames:
  # HTTP 日志；stream-access.log 使用不同格式，不能标记为 nginx HTTP。
  - /opt/1panel/apps/openresty/openresty/log/access.log
  - /opt/1panel/apps/openresty/openresty/log/error.log
  - /opt/1panel/www/sites/*/log/access.log
  - /opt/1panel/www/sites/*/log/error.log
  # 部分安装将 /opt/1panel/1panel/www 挂载到容器 /www。
  - /opt/1panel/1panel/www/sites/*/log/access.log
  - /opt/1panel/1panel/www/sites/*/log/error.log
  # 兼容旧版或其他部署布局。
  - /opt/1panel/apps/openresty/openresty/logs/access.log
  - /opt/1panel/apps/openresty/openresty/logs/error.log
  - /opt/1panel/apps/openresty/openresty/data/sites/*/log/access.log
  - /opt/1panel/apps/openresty/openresty/data/sites/*/log/error.log
  - /home/web/log/nginx/*.log
  - /home/web/log/nginx/*/*.log
  - /var/log/nginx/*.log
labels:
  type: nginx
---
filenames:
  # 科技lion NPM 的默认挂载目录已确认；其他目录仅为候选。
  # 只采集官方 HTTP 日志，排除 stream-* 与 fallback_stream_*。
  - /home/docker/npm/data/logs/*host*_access.log
  - /home/docker/npm/data/logs/*host*_error.log
  - /home/docker/npm/data/logs/fallback_http_access.log
  - /home/docker/npm/data/logs/fallback_http_error.log
  - /home/docker/npm/data/logs/letsencrypt-requests_access.log
  - /home/docker/npm/data/logs/letsencrypt-requests_error.log
  - /opt/npm/data/logs/*host*_access.log
  - /opt/npm/data/logs/*host*_error.log
  - /opt/npm/data/logs/fallback_http_access.log
  - /opt/npm/data/logs/fallback_http_error.log
  - /opt/npm/data/logs/letsencrypt-requests_access.log
  - /opt/npm/data/logs/letsencrypt-requests_error.log
  - /opt/nginx-proxy-manager/data/logs/*host*_access.log
  - /opt/nginx-proxy-manager/data/logs/*host*_error.log
  - /opt/nginx-proxy-manager/data/logs/fallback_http_access.log
  - /opt/nginx-proxy-manager/data/logs/fallback_http_error.log
  - /opt/nginx-proxy-manager/data/logs/letsencrypt-requests_access.log
  - /opt/nginx-proxy-manager/data/logs/letsencrypt-requests_error.log
  - /data/logs/*host*_access.log
  - /data/logs/*host*_error.log
  - /data/logs/fallback_http_access.log
  - /data/logs/fallback_http_error.log
  - /data/logs/letsencrypt-requests_access.log
  - /data/logs/letsencrypt-requests_error.log
  - /var/log/nginx-proxy-manager/*host*_access.log
  - /var/log/nginx-proxy-manager/*host*_error.log
  - /var/log/nginx-proxy-manager/fallback_http_access.log
  - /var/log/nginx-proxy-manager/fallback_http_error.log
  - /var/log/nginx-proxy-manager/letsencrypt-requests_access.log
  - /var/log/nginx-proxy-manager/letsencrypt-requests_error.log
labels:
  type: nginx-proxy-manager
---
filenames:
  - /var/log/auth.log
  - /var/log/secure
labels:
  type: syslog
EOF
    log_info "已配置常见日志路径: ${target}；请用 cscli metrics 核实实际采集。"
}

cleanup_log_repair() {
    if [[ -n "$LOG_REPAIR_STAGE" ]]; then rm -rf -- "$LOG_REPAIR_STAGE"; fi
    LOG_REPAIR_STAGE=''
    LOG_REPAIR_COUNT=0
    LOG_PRESET_FILE=''
}

prepare_log_repair() {
    LOG_REPAIR_FILE=$(yaml_tool log-repair-file "$CS_DIR") || return 1
    LOG_PRESET_FILE=$(yaml_tool web-log-file "$CS_DIR") || return 1
    LOG_REPAIR_STAGE=$(mktemp -d) || return 1
    LOG_REPAIR_COUNT=0
    local containers id image kind mounts service
    configure_log_acquis "${LOG_REPAIR_STAGE}/presets.yaml" >/dev/null || { cleanup_log_repair; return 1; }
    : > "${LOG_REPAIR_STAGE}/mounts.tsv"
    : > "${LOG_REPAIR_STAGE}/discovered.jsonl"
    for service in nginx openresty; do
        command -v "$service" >/dev/null 2>&1 || continue
        if "$service" -T > "${LOG_REPAIR_STAGE}/runtime-nginx.txt" 2>/dev/null; then
            if ! python3 "${SCRIPT_DIR}/lib/crowdsec_host.py" "${LOG_REPAIR_STAGE}/runtime-nginx.txt" "${LOG_REPAIR_STAGE}/runtime-mounts.json" ||
                ! maintenance_tool runtime-logs nginx "${LOG_REPAIR_STAGE}/runtime-mounts.json" "${LOG_REPAIR_STAGE}/runtime-nginx.txt" "${LOG_REPAIR_STAGE}/discovered.jsonl"; then cleanup_log_repair; return 1; fi
        else
            log_warn "宿主机 ${service} 的有效配置读取失败，仅检查已知日志。"
        fi
    done
    if command -v docker >/dev/null 2>&1; then
        if containers=$(docker ps --format '{{.ID}} {{.Image}}'); then
            while read -r id image; do
                [[ -z "$id" ]] && continue
                case "$image" in
                    *nginx-proxy-manager*) kind=nginx-proxy-manager ;;
                    *nginx*|*openresty*) kind=nginx ;;
                    *) continue ;;
                esac
                if ! mounts=$(docker inspect --format '{{json .Mounts}}' "$id"); then
                    log_warn "无法读取 ${id} 的挂载，使用预设路径继续检查。"
                    continue
                fi
                printf '%s\t%s\n' "$kind" "$mounts" >> "${LOG_REPAIR_STAGE}/mounts.tsv" || { cleanup_log_repair; return 1; }
                printf '%s' "$mounts" > "${LOG_REPAIR_STAGE}/runtime-mounts.json"
                if docker exec "$id" nginx -T > "${LOG_REPAIR_STAGE}/runtime-nginx.txt" 2>/dev/null; then
                    maintenance_tool runtime-logs "$kind" "${LOG_REPAIR_STAGE}/runtime-mounts.json" "${LOG_REPAIR_STAGE}/runtime-nginx.txt" "${LOG_REPAIR_STAGE}/discovered.jsonl" || { cleanup_log_repair; return 1; }
                else
                    log_warn "${id} 的运行配置读取失败，仅按挂载与预设发现日志。"
                fi
            done <<< "$containers"
        else
            log_warn 'Docker 不可用，仅检查预设日志目录。'
        fi
    fi
    if ! LOG_REPAIR_COUNT=$(yaml_tool repair-log-acquis "$CS_DIR" "${LOG_REPAIR_STAGE}/presets.yaml" "${LOG_REPAIR_STAGE}/mounts.tsv" "${LOG_REPAIR_STAGE}/repaired.yaml" "${LOG_REPAIR_STAGE}/discovered.jsonl"); then
        cleanup_log_repair
        return 1
    fi
    log_info "日志路径检查完成，待调整 ${LOG_REPAIR_COUNT} 项采集。"
}

apply_staged_log_repair() {
    [[ "$LOG_REPAIR_COUNT" == 0 ]] && return 0
    if [[ -L "$LOG_REPAIR_FILE" ]]; then log_err '修复采集文件是符号链接，未写入。'; return 1; fi
    mkdir -p "$(dirname "$LOG_REPAIR_FILE")" && cp -- "${LOG_REPAIR_STAGE}/repaired.yaml" "$LOG_REPAIR_FILE" || return 1
    if [[ -f "${LOG_REPAIR_STAGE}/repaired.yaml.migrate-presets" ]]; then
        rm -f -- "$LOG_PRESET_FILE" || return 1
    fi
}

repair_log_acquis() {
    require_core && require_yaml || return 1
    prepare_log_repair || return 1
    if [[ "$LOG_REPAIR_COUNT" == 0 ]]; then
        log_info '未发现需要补齐的现有 HTTP 日志；请结合新请求与 cscli metrics 核验。'
        cleanup_log_repair
        return 0
    fi
    if ! confirm '调整上述日志采集并校验、重启 CrowdSec？'; then cleanup_log_repair; return 0; fi
    begin_config_change "$LOG_REPAIR_FILE" "$LOG_PRESET_FILE" || { cleanup_log_repair; return 1; }
    if ! apply_staged_log_repair || ! apply_core_config; then
        restore_config_change
        cleanup_log_repair
        return 1
    fi
    log_succ "已调整 ${LOG_REPAIR_COUNT} 项日志采集；请访问网站后查看 cscli metrics。"
    cleanup_log_repair
}

enable_prometheus_metrics() {
    local port
    port=$(maintenance_tool metrics-port "${CS_DIR}/config.yaml") || return 1
    if ss -H -lntp "sport = :${port}" 2>/dev/null | grep -q .; then
        if ! ss -H -lntp "sport = :${port}" 2>/dev/null | grep -q '"crowdsec"'; then
            log_err "指标端口 ${port} 被其他进程占用，未修改配置。"
            return 1
        fi
    fi
    yaml_tool metrics "${CS_DIR}/config.yaml"
}

install_collections() {
    local inventory temporary missing result=0 comparison=0
    hub_begin install || return $?
    temporary=$(mktemp) || { hub_abort no-load; return 1; }
    if ! cscli collections list -o json > "$temporary" || ! inventory=$(maintenance_tool collections-missing "$temporary" "$@"); then
        rm -f -- "$temporary"
        hub_abort no-load
        return 1
    fi
    rm -f -- "$temporary"
    if [[ -z "$inventory" ]]; then
        log_info '所需规则集合已启用，跳过重复安装。'
        # A previous install in this same transaction still needs final loading.
        if [[ "$HUB_TX_AFTER" != true ]]; then
            if ! hub_record_after || ! hub_finalize; then hub_abort no-load; return 1; fi
        fi
        return 0
    fi
    local requested=()
    while IFS= read -r missing; do [[ -n "$missing" ]] && requested+=("$missing"); done <<< "$inventory"
    HUB_TX_AFTER=false
    cscli hub update && cscli collections install "${requested[@]}" || result=$?
    if ! hub_record_after; then hub_abort no-load; return 1; fi
    if [[ "$result" != 0 ]]; then hub_abort no-load; return "$result"; fi
    maintenance_tool changed "$HUB_TX_BACKUP" || comparison=$?
    if [[ "$comparison" == 0 ]]; then CORE_RULES_CHANGED=true
    elif [[ "$comparison" != 1 ]]; then hub_abort no-load; return 1; fi
}

install_web_rules() (
    trap hub_workflow_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    install_collections crowdsecurity/nginx crowdsecurity/nginx-proxy-manager crowdsecurity/http-cve crowdsecurity/base-http-scenarios crowdsecurity/whitelist-good-actors || return $?
    reload_core_rules || return 1
    log_succ 'Web 日志检测规则已安装并加载。在线请求检查需另外配置 AppSec。'
)

get_registered_machines() {
    require_commands python3 cscli || return 1
    cscli machines list -o json | python3 -c 'import sys,json; data=json.load(sys.stdin); print("\n".join(m.get("machineId",m.get("name","")) for m in data))'
}

verify_and_heal_host_core() {
    # Machine 名称、版本或 Docker 标签不能证明凭据损坏；仅验证真实 LAPI 登录。
    require_core || return 1
    if cscli lapi status; then return 0; fi
    log_err '宿主机 LAPI 登录失败。请检查 local_api_credentials.yaml 与 cscli machines list；不会自动覆盖宿主机凭据。'
    return 1
}

check_and_clean_redundant_instances() {
    require_core || return 1
    log_info '以下为已注册 Machine，名称相似不代表可以删除：'
    cscli machines list || return 1
    if command -v docker >/dev/null 2>&1; then
        docker ps -a --filter "name=crowdsec-web-ui" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' || return 1
    fi
    log_info '只删除你明确选择的凭据；宿主机及当前 WebUI 凭据受保护。'
    local target host credentials active=''
    prompt target '需注销的 Machine 名称（留空取消）: ' || return 0
    [[ -z "$target" ]] && return 0
    credentials=$(yaml_tool client-credentials-path "${CS_DIR}/config.yaml") || return 1
    host=$(yaml_tool get "$credentials" login) || return 1
    if [[ -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]]; then
        active=$(yaml_tool get "${WEBUI_DIR}/data/webui_api_credentials.yaml" login) || return 1
    fi
    if [[ "$target" == "$host" || "$target" == "$active" ]]; then
        log_err '不能注销宿主机或当前 WebUI 的 Machine。'
        return 1
    fi
    confirm "确认注销 Machine ${target}？" || return 0
    cscli machines delete -- "$target" || return 1
    log_succ "已注销 ${target}；其他凭据与容器未受影响。"
}

valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

webui_owned() {
    [[ -f "${WEBUI_DIR}/.crowdsec-1key-managed" ]] || [[ -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]]
}

webui_lapi_status() {
    local temporary result=0
    [[ -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]] || return 1
    temporary=$(mktemp) || return 1
    if ! yaml_tool credentials-config "${CS_DIR}/config.yaml" "${WEBUI_DIR}/data/webui_api_credentials.yaml" "$temporary"; then
        rm -f "$temporary"
        return 1
    fi
    cscli -c "$temporary" lapi status || result=1
    rm -f "$temporary"
    return "$result"
}

webui_compose_up() {
    local override='' result=0
    local compose_args=(-f "${WEBUI_DIR}/docker-compose.yml")
    local up_args=(up -d)
    if [[ -n "${1:-}" ]]; then
        override=$(mktemp) || return 1
        yaml_tool compose-image "$override" "$1" || { rm -f "$override"; return 1; }
        compose_args+=(-f "$override")
        up_args+=(--pull never)
    fi
    if docker compose version >/dev/null 2>&1; then
        docker compose "${compose_args[@]}" "${up_args[@]}" || result=1
    elif command -v docker-compose >/dev/null 2>&1; then
        # Legacy Compose has no --pull never; a local image ID still pins rollback.
        docker-compose "${compose_args[@]}" up -d || result=1
    else
        log_err '需要 Docker Compose 插件才能可靠部署和更新。'
        result=1
    fi
    [[ -n "$override" ]] && rm -f "$override"
    return "$result"
}

rollback_webui() {
    local created="$1" machine="$2" previous="$3" previous_image="${4:-}"
    local core_changed=false
    config_change_needed && core_changed=true
    restore_config_change || return 1
    if [[ "$previous" == true && -f "${WEBUI_DIR}/docker-compose.yml" ]]; then
        if ! webui_compose_up "$previous_image"; then log_err '旧 WebUI 容器自动恢复失败，请使用备份配置手动恢复。'; fi
    elif [[ "$created" == true ]]; then
        docker rm -f crowdsec-web-ui >/dev/null 2>&1 || true
    fi
    if [[ "$created" == true ]]; then cscli machines delete -- "$machine" || log_warn '新建 Machine 注销失败，请手动核验。'; fi
    if [[ "$core_changed" == true ]]; then
        if ! crowdsec -t || ! systemctl restart crowdsec; then log_err 'WebUI 回滚后核心恢复失败。'; fi
    fi
}

deploy_web_ui() (
    require_core && require_yaml && require_commands docker curl ss || return 1
    if ! systemctl is-active --quiet crowdsec || ! cscli lapi status; then log_err 'CrowdSec/LAPI 尚未就绪。'; return 1; fi
    local port=3000 url machine password host host_creds created=false creds compose previous=false previous_image='' old_machine='' rotation="${1:-}"
    local changed=false committed=false
    webui_deploy_exit() {
        local result=$?
        trap - EXIT INT TERM
        if [[ "$changed" == true && "$committed" != true ]]; then
            rollback_webui "$created" "${machine:-}" "$previous" "$previous_image"
        fi
        exit "$result"
    }
    trap webui_deploy_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    prompt port 'WebUI 端口 [3000]: ' || return 1
    port="${port:-3000}"
    valid_port "$port" || { log_err '端口必须在 1–65535 之间。'; return 1; }
    if ss -H -ltn "sport = :${port}" 2>/dev/null | grep -q .; then
        if ! webui_owned || ! webui_owns_port "$port"; then log_err '端口被其他进程占用，请更换端口。'; return 1; fi
    fi
    if docker container inspect crowdsec-web-ui >/dev/null 2>&1 && ! webui_owned; then
        log_err '已有同名容器但缺少本工具凭据，请先检查其归属。'
        return 1
    fi
    log_warn '此上游镜像的 host 网络监听所有接口，无法配置 loopback 绑定；首次管理员注册也会暴露。'
    log_warn '请先用现有防火墙限制此端口，并配置 HTTPS 反向代理。SSH 隧道本身不会隐藏公网端口。'
    confirm '已完成上述访问限制，继续启用此 WebUI 监听端口？' || return 0
    log_info '正在拉取 WebUI 镜像，失败时保留已有容器和凭据。'
    if [[ "$rotation" != rotate && -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]] && ! webui_lapi_status; then
        log_err 'WebUI 独立凭据无法登录 LAPI，已保留现有部署。请检查后重新注册。'
        return 1
    fi
    previous_image=$(docker inspect --format '{{.Image}}' crowdsec-web-ui 2>/dev/null) || previous_image=''
    [[ "$previous_image" =~ ^sha256:[a-f0-9]{64}$ ]] || previous_image=''
    docker pull "$WEBUI_IMAGE" || return 1
    local image_metadata pinned_image metrics_url
    image_metadata=$(mktemp) || return 1
    if ! docker image inspect --format '{{json .RepoDigests}}' "$WEBUI_IMAGE" > "$image_metadata" || ! pinned_image=$(maintenance_tool webui-image "$image_metadata"); then rm -f -- "$image_metadata"; return 1; fi
    rm -f -- "$image_metadata"
    log_info "目标镜像固定为：${pinned_image}；旧镜像：${previous_image:-无}"
    host_creds=$(yaml_tool client-credentials-path "${CS_DIR}/config.yaml") || return 1
    url=$(yaml_tool get "$host_creds" url) || return 1
    host=$(yaml_tool get "$host_creds" login) || return 1
    creds="${WEBUI_DIR}/data/webui_api_credentials.yaml"
    compose="${WEBUI_DIR}/docker-compose.yml"
    mkdir -p "${WEBUI_DIR}/data" || return 1
    chmod 700 "$WEBUI_DIR" "${WEBUI_DIR}/data" || return 1
    [[ -f "$compose" ]] && previous=true
    begin_config_change "$creds" "$compose" "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || return 1
    changed=true
    if [[ -f "$creds" ]]; then
        old_machine=$(yaml_tool get "$creds" login) || return 1
        [[ "$old_machine" != "$host" ]] || { log_err 'WebUI 使用了宿主机凭据，已停止部署。'; return 1; }
    fi
    if [[ -f "$creds" && "$rotation" != rotate ]]; then
        if ! machine=$(yaml_tool get "$creds" login) || ! password=$(yaml_tool get "$creds" password); then restore_config_change; return 1; fi
        [[ "$machine" != "$host" ]] || { log_err 'WebUI 凭据与宿主机相同，已停止部署。'; return 1; }
    else
        machine="webui-1key-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
        if ! cscli machines add "$machine" --auto -f "$creds" --url "$url"; then
            restore_config_change
            return 1
        fi
        created=true
        password=$(yaml_tool get "$creds" password) || return 1
    fi
    chmod 600 "$creds" || return 1
    metrics_url=$(maintenance_tool metrics-url "${CS_DIR}/config.yaml") || return 1
    if ! enable_prometheus_metrics || ! yaml_tool compose "$compose" "$WEBUI_DIR" "$url" "$machine" "$password" "$port" "$pinned_image" "$metrics_url" || ! apply_core_config; then
        return 1
    fi
    local result=0
    webui_compose_up || result=1
    if [[ "$result" -ne 0 ]]; then
        log_err 'WebUI 部署失败，已尝试恢复配置和旧容器，请核验其状态。'
        return 1
    fi
    if ! webui_ready "$port"; then
        log_err 'WebUI 容器未运行，请查看 docker logs crowdsec-web-ui。'
        return 1
    fi
    touch "${WEBUI_DIR}/.crowdsec-1key-managed" || return 1
    committed=true
    if [[ "$rotation" == rotate && -n "$old_machine" && "$old_machine" != "$machine" ]]; then
        cscli machines delete -- "$old_machine" || log_warn "新 WebUI 已运行，但旧 Machine ${old_machine} 注销失败，请人工核验。"
    fi
    log_succ "WebUI 容器健康、HTTP 与 LAPI 均已就绪，访问 http://服务器地址:${port}。"
    log_warn '按上游镜像实际认证功能配置访问保护；建议通过 HTTPS 反向代理访问。'
)

uninstall_web_ui() {
    confirm '删除本工具 WebUI 容器、持久化目录及其独立 Machine？' || return 0
    webui_owned || { log_err '未找到本工具管理的 WebUI。'; return 1; }
    local machine='' host='' credentials
    if [[ -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]]; then
        machine=$(yaml_tool get "${WEBUI_DIR}/data/webui_api_credentials.yaml" login) || return 1
        credentials=$(yaml_tool client-credentials-path "${CS_DIR}/config.yaml") || return 1
        host=$(yaml_tool get "$credentials" login) || return 1
        [[ "$machine" != "$host" ]] || { log_err '检测到宿主机凭据，已停止卸载。'; return 1; }
    fi
    if command -v docker >/dev/null 2>&1 && docker container inspect crowdsec-web-ui >/dev/null 2>&1; then
        docker rm -f crowdsec-web-ui || return 1
    fi
    if [[ -n "$machine" ]]; then cscli machines delete -- "$machine" || return 1; fi
    rm -rf -- "$WEBUI_DIR" || return 1
    log_succ '本工具 WebUI 已删除；其他 Machine 和容器未受影响。'
}

reset_webui_credentials() {
    require_core && require_yaml || return 1
    webui_owned || { log_err '请先部署 WebUI。'; return 1; }
    log_info '检查 WebUI 的独立 Machine 登录；失效时先修复账号，不能以宿主机登录成功代替。'
    local result=0
    webui_lapi_status || result=1
    if confirm '轮换 WebUI 独立凭据并更新容器？'; then deploy_web_ui rotate; else return "$result"; fi
}

manage_web_ui() {
    local choice
    while true; do
        printf '\n网页管理面板\n1. 安装或更新管理面板\n2. 卸载本工具的管理面板\n3. 查看容器日志\n4. 检查或更换登录凭据\n5. 查看节点，选择不再使用的节点并注销\n0. 返回\n'
        prompt choice '请选择 [0-5]: ' || return 0
        case "$choice" in
            1) deploy_web_ui ;;
            2) uninstall_web_ui ;;
            3) require_commands docker && docker logs --tail 100 crowdsec-web-ui ;;
            4) reset_webui_credentials ;;
            5) check_and_clean_redundant_instances ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

install_baseline_collections() {
    install_collections crowdsecurity/linux crowdsecurity/sshd crowdsecurity/nginx crowdsecurity/base-http-scenarios crowdsecurity/http-cve crowdsecurity/whitelist-good-actors
}

reset_waf_to_core_baseline() (
    trap hub_workflow_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    log_info '补齐基础日志检测集合，保留自定义规则和已配置的 AppSec；Hub 场景数量随版本变化。'
    install_baseline_collections || return $?
    reload_core_rules || return 1
    log_succ '基础集合已补齐。'
)

uninstall_specific_waf_collection() {
    require_core || return 1
    cscli collections list || return 1
    local target
    prompt target '集合名称（0 或留空取消）: ' || return 0
    [[ -z "$target" || "$target" == 0 ]] && return 0
    [[ "$target" =~ ^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$ ]] || { log_err '集合名称格式错误。'; return 1; }
    if [[ "$target" == *appsec* ]]; then
        log_err 'AppSec 集合可能仍被数据源引用，请先使用 AppSec 停用入口，再人工检查关联配置。'
        return 1
    fi
    confirm "卸载 ${target}（可能影响依赖集合）？" || return 0
    hub_maintenance remove "$target" || return $?
    log_succ "已卸载 ${target}。"
}

uninstall_all_waf_extensions() {
    require_core || return 1
    confirm '移除已知 Web 日志检测集合？AppSec 与自定义集合保留。' || return 0
    local collection installed
    installed=$(cscli collections list -o json) || return 1
    local collections
    collections=$(printf '%s' "$installed" | python3 -c 'import json,sys; d=json.load(sys.stdin); items=d.get("collections",[]) if isinstance(d,dict) else d; print("\n".join(x["name"] for x in items if x.get("status","enabled") != "disabled"))') || return 1
    local removals=()
    for collection in crowdsecurity/nginx crowdsecurity/nginx-proxy-manager crowdsecurity/http-cve crowdsecurity/base-http-scenarios crowdsecurity/wordpress crowdsecurity/iptables; do
        if printf '%s\n' "$collections" | grep -Fxq "$collection"; then removals+=("$collection"); fi
    done
    if ((${#removals[@]})); then hub_maintenance remove "${removals[@]}" || return $?; fi
    log_succ '已处理已知 Web 日志检测集合。'
}

appsec_default_listener_ready() {
    ss -H -lnt | awk '$4 == "127.0.0.1:7422" {found=1} END {exit !found}'
}

appsec_containers() {
    command -v docker >/dev/null 2>&1 || return 0
    local containers id image name
    containers=$(docker ps --format '{{.ID}} {{.Image}} {{.Names}}') || { log_warn 'Docker 不可用，容器接入检查未完成。'; return 1; }
    while read -r id image name; do
        case "$image" in
            *nginx*|*openresty*) printf '%s %s %s\n' "$id" "$image" "$name" ;;
        esac
    done <<< "$containers"
}

diagnose_appsec_containers() {
    local containers id image name network effective hooks mounts result=0
    containers=$(appsec_containers) || return 1
    while read -r id image name; do
        [[ -z "$id" ]] && continue
        log_info "Web 容器：${name}（${id}，${image}）"
        network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$id") || return 1
        if [[ "$network" == host ]]; then
            log_info 'host 网络：容器可通过 127.0.0.1:7422 连接宿主机 AppSec。'
        else
            diagnose_docker_transport "$id" "$name" "$network" || result=1
        fi
        if ! effective=$(docker exec "$id" nginx -T 2>&1); then
            log_warn '容器 nginx -T 失败，未能核验网站请求处理组件。'
            continue
        fi
        hooks=$(printf '%s' "$effective" | yaml_tool appsec-web-hooks) || return 1
        if [[ "$hooks" != *crowdsec* && -f "$WEB_INSTALLS" ]]; then
            mounts=$(docker inspect --format '{{json .Mounts}}' "$id") || return 1
            if web_tool active-hooks "$WEB_INSTALLS" "$name" <(printf '%s' "$mounts") <(printf '%s' "$effective") >/dev/null 2>&1; then hooks+=crowdsec; fi
        fi
        [[ "$hooks" == *1pwaf* ]] && log_warn '检测到 1Panel WAF 的 Lua 接入；安装 CrowdSec 时需合并请求处理逻辑，保留现有 WAF。'
        if [[ "$hooks" == *crowdsec* ]]; then
            local target file native_targets
            local targets=()
            mounts=$(docker inspect --format '{{json .Mounts}}' "$id") || return 1
            native_targets=$(web_tool targets "$WEB_INSTALLS" "$name") || return 1
            while IFS= read -r target; do [[ -z "$target" ]] || targets+=("$target"); done <<< "$native_targets"
            targets+=("${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf")
            for target in "${targets[@]}"; do
                file=$(printf '%s' "$mounts" | yaml_tool docker-bouncer-path "$target" 2>/dev/null) || continue
                appsec_audit_tool show "$file" || return 1
                appsec_guard_config "$file" "$id" "$target" || return 1
                break
            done
            log_info '配置中发现 CrowdSec 请求处理调用；仍需用实际网站请求确认路由和 AppSec 计数。'
        else
            log_warn '缺少 CrowdSec Web Bouncer 请求处理调用；仅配置 AppSec 引擎不会增加网站请求计数。'
            log_info '官方安装与接入文档：https://docs.crowdsec.net/u/bouncers/openresty/'
        fi
    done <<< "$containers"
    return "$result"
}

link_docker_appsec() (
    local containers id image name selected='' network effective hooks target file mounts stage
    containers=$(appsec_containers) || return 1
    [[ -n "$containers" ]] || { log_err '没有检测到运行中的 Nginx/OpenResty 容器。'; return 1; }
    printf '%s\n' "$containers"
    prompt selected '输入上面容器 ID 或名称（留空取消）: ' || return 0
    [[ -n "$selected" ]] || return 0
    while read -r id image name; do
        if [[ "$selected" == "$id" || "$selected" == "$name" ]]; then selected="$id"; break; fi
    done <<< "$containers"
    [[ "$selected" == "$id" ]] || { log_err '请选择列表中的容器。'; return 1; }
    network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$selected") || return 1
    local work appsec_url='http://127.0.0.1:7422' transport_args=()
    work=$(mktemp -d) || return 1
    local changed=false committed=false
    docker_link_exit() {
        local status=$?
        trap - EXIT INT TERM
        if [[ "$changed" == true && "$committed" != true ]]; then
            if ! restore_config_change || ! nginx_reload_verified docker "$selected"; then
                log_err '容器接入回滚未完成，修改前备份已保留，请核对网站运行配置。'
            fi
            [[ "$status" != 0 ]] || status=1
        fi
        rm -rf -- "$work"
        exit "$status"
    }
    trap docker_link_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ "$network" != host ]]; then
        require_commands ss || return 1
        transport_current "$selected" "$name" "$work" || return 1
        appsec_url=$(web_tool get "$work/transport" appsec_url) || return 1
        transport_args=("$work/transport")
    fi
    effective=$(docker exec "$selected" nginx -T 2>&1) || { log_err '容器 nginx -T 失败，未修改接入。'; return 1; }
    hooks=$(printf '%s' "$effective" | yaml_tool appsec-web-hooks) || return 1
    mounts=$(docker inspect --format '{{json .Mounts}}' "$selected") || return 1
    if [[ "$hooks" != *crowdsec* ]] && web_tool active-hooks "$WEB_INSTALLS" "$name" <(printf '%s' "$mounts") <(printf '%s' "$effective") >/dev/null 2>&1; then hooks+=crowdsec; fi
    [[ "$hooks" == *crowdsec* ]] || { log_err '缺少 CrowdSec Web Bouncer 请求处理调用，请先安装并在网站中启用；现有 1Panel WAF 保留。'; return 1; }
    file=''
    local native_targets=''
    native_targets=$(web_tool targets "$WEB_INSTALLS" "$name") || return 1
    local targets=()
    while IFS= read -r target; do [[ -n "$target" ]] && targets+=("$target"); done <<< "$native_targets"
    targets+=("${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf")
    for target in "${targets[@]}"; do
        if file=$(printf '%s' "$mounts" | yaml_tool docker-bouncer-path "$target" 2>/dev/null); then break; fi
        file=''
    done
    [[ -n "$file" ]] || { log_err '未找到持久化挂载的官方 Web Bouncer 配置；请先按官方文档安装并持久化配置。'; return 1; }
    if [[ "$network" != host ]]; then
        transport_tool config-api "$file" "$work/transport" && transport_tool probe-settings "$file" "$work/transport" "$work/probe" || return 1
        if ! docker exec -i "$selected" curl -fsS --noproxy '*' --connect-timeout 3 --max-time 8 --config - < "$work/probe" > "$work/response" 2>/dev/null ||
            ! transport_tool probe-response "$work/response"; then log_err '已有 Bouncer 无法通过私有 LAPI 认证，未修改接入。'; return 1; fi
    fi
    if [[ -f "$APPSEC_LINKS" ]] && yaml_tool link-owned "$file" "$APPSEC_LINKS" >/dev/null 2>&1; then
        log_err '该配置已有宿主机接入记录，请先停用原接入。'
        return 1
    fi
    appsec_guard_config "$file" "$selected" "$target" || return 1
    confirm "将容器 ${name} 的已有 Web Bouncer 接入 AppSec，并校验、重载？" || return 0
    stage="$work/staged"
    if ! yaml_tool stage-web-bouncer "$file" "$appsec_url" "$stage"; then return 1; fi
    begin_config_change "$file" "$APPSEC_DOCKER_LINKS" || { rm -f -- "$stage"; return 1; }
    changed=true
    yaml_tool link-docker-bouncer "$file" "$APPSEC_DOCKER_LINKS" "$selected" "$target" "$name" "$appsec_url" "${transport_args[@]}" &&
        cp -- "$stage" "$file" && docker exec "$selected" nginx -t || return 1
    if ! config_change_needed; then
        committed=true
        log_info '容器接入配置未变化，跳过重载。'
        return 0
    fi
    nginx_reload_verified docker "$selected" || return 1
    committed=true
    log_succ '容器内已有 Web Bouncer 的 AppSec 地址已配置并重载；请验证实际网站请求和指标。'
)

setup_appsec() (
    CORE_CONFIG_TRACKING=true
    CORE_CONFIG_PENDING=false
    trap hub_workflow_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    require_core && require_yaml && require_commands ss || return 1
    APPSEC_FILE=$(yaml_tool appsec-file "$CS_DIR") || return 1
    local external
    external=$(yaml_tool appsec-existing "$CS_DIR" "$APPSEC_FILE") || return 1
    if [[ -n "$external" ]]; then
        log_warn "已有外部 AppSec 配置，避免重复监听，未改写: ${external}"
        diagnose_appsec_containers || return 1
        return 0
    fi
    log_info '启用官方 AppSec 数据源；Firewall Bouncer 不支持转发 HTTP 请求。'
    install_collections crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules || return $?
    begin_config_change "$APPSEC_FILE" || return 1
    mkdir -p "$(dirname "$APPSEC_FILE")" || return 1
    if ! yaml_tool appsec "$APPSEC_FILE"; then restore_config_change; return 1; fi
    apply_core_config || return 1
    local attempt
    for ((attempt=0; attempt<10; attempt++)); do
        appsec_default_listener_ready && break
        sleep 1
    done
    if ! appsec_default_listener_ready; then
        log_err 'AppSec 配置已写入，但 127.0.0.1:7422 未监听；请检查 journalctl -u crowdsec 和 /var/log/crowdsec.log。网站尚未接入。'
        return 1
    fi
    log_info 'AppSec 配置已校验，127.0.0.1:7422 存在监听；网站接入仍需 Web Bouncer。'
    local choice service file
    diagnose_appsec_containers || return 1
    [[ -f "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" ]] && command -v nginx >/dev/null 2>&1 && printf '1. 接入宿主机 Nginx 已有的网站拦截组件\n'
    [[ -f "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf" ]] && command -v openresty >/dev/null 2>&1 && printf '2. 接入宿主机 OpenResty 已有的网站拦截组件\n'
    printf '3. 接入 Docker 已有的网站拦截组件（需已确认网络可达）\n4. 为 Docker 或宿主机网站安装拦截组件\n0. 仅配置引擎，稍后接入网站\n'
    prompt choice '请选择可用接入项（0 结束）: ' || return 0
    case "$choice" in
        1) service=nginx ;;
        2) service=openresty ;;
        3) link_docker_appsec; return $? ;;
        4) install_web_bouncer; return $? ;;
        0|'')
            log_warn '仅完成引擎配置；网站请求尚未验证，AppSec 计数可为零。'
            return 0 ;;
        *) log_err '无效选项，引擎已配置但 Web Bouncer 未接入。'; return 1 ;;
    esac
    file="${CS_DIR}/bouncers/crowdsec-${service}-bouncer.conf"
    [[ -f "$file" ]] || { log_err "未安装对应 Web Bouncer: ${file}；引擎已配置，网站尚未接入。"; return 1; }
    install_host_web_bouncer "$service" selected
)

check_appsec_status() {
    if [[ "${1:-}" != offline ]]; then require_core || return 1; fi
    require_yaml || return 1
    local addresses address sockets result=0
    addresses=$(yaml_tool appsec-listeners "$CS_DIR") || {
        health_event appsec unknown
        log_err '无法读取有效 AppSec 数据源，健康状态无法确认。'
        return 1
    }
    if [[ -z "$addresses" ]]; then
        if [[ "${1:-}" == optional || "${1:-}" == offline ]]; then
            health_event appsec optional
            log_info 'AppSec: 未部署（可选）。'
            return 0
        fi
        log_err '没有启用的 AppSec 数据源；请先运行 --install-appsec。'
        result=1
    else
        health_expect appsec
        require_commands ss || return 1
        sockets=$(ss -H -lnt) || { log_err '无法读取 AppSec 监听状态。'; return 1; }
        while read -r address; do
            if awk -v address="$address" '$4 == address {found=1} END {exit !found}' <<< "$sockets"; then
                log_info "AppSec 配置地址存在监听：${address}。"
            else
                log_warn "AppSec 配置地址未监听：${address}。"
                health_event appsec fault
                result=1
            fi
        done <<< "$addresses"
    fi
    if [[ "${1:-}" != offline ]]; then
        diagnose_appsec_containers || result=1
        cscli appsec-configs list && cscli metrics show appsec || return 1
    else
        log_info '[尚未验证] 仅检查已部署 AppSec 的配置与监听；请求处理指标由检测中心核验。'
    fi
    local file
    for file in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        [[ ! -f "$file" ]] || appsec_audit_tool show "$file" || result=1
    done
    log_info '确认 Processed/Blocked 随测试请求变化，不能仅凭 HTTP 403 判断 WAF 生效。'
    [[ "$result" == 0 && -n "$addresses" ]] && health_event appsec ok
    return "$result"
}

verify_appsec() {
    require_core && require_yaml && require_commands curl || return 1
    local target='' marker probe metrics_url work http verdict result attempt
    prompt target '输入你管理的网站根地址（如 https://example.com，留空取消）: ' || return 0
    [[ -z "$target" ]] && return 0
    appsec_audit_tool validate-url "$target" || return 1
    marker=$(python3 -c 'import secrets; print(secrets.token_hex(12))') || return 1
    probe="${target%/}/.env?crowdsec_1key_probe=${marker}"
    log_warn '该操作从本机发送 /.env 验证请求；localhost、回环地址或经公网绕回本机的请求可能产生 Self-Report 告警。'
    log_info "优先从另一台设备 GET ${probe}；记录 HTTP 状态、访客 IP、时间和网站日志中的唯一标识 ${marker}。"
    log_info '健康检查使用正常页面或专用 /healthz，避免定时请求攻击路径。'
    confirm '仍从当前主机发送这次 AppSec 验证请求？' || return 0
    work=$(mktemp -d) || return 1
    metrics_url=$(python3 "${SCRIPT_DIR}/lib/crowdsec_detection_diagnose.py" metrics-url "${CS_DIR}/config.yaml" 2>/dev/null) || metrics_url=''
    cscli metrics show appsec || { rm -rf -- "$work"; return 1; }
    : > "$work/before"
    : > "$work/after"
    if [[ -n "$metrics_url" ]] && curl -fsS --max-time 5 "$metrics_url" > "$work/raw"; then
        appsec_audit_tool snapshot "$work/raw" > "$work/before" || : > "$work/before"
    fi
    if ! http=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' "$probe"); then
        log_err 'failed / 失败：验证请求传输失败。'
        rm -rf -- "$work"
        return 1
    fi
    for attempt in 1 2 3; do
        if [[ -n "$metrics_url" ]] && curl -fsS --max-time 5 "$metrics_url" > "$work/raw"; then
            appsec_audit_tool snapshot "$work/raw" > "$work/after" || : > "$work/after"
        fi
        verdict=$(appsec_audit_tool verdict "$http" "$work/before" "$work/after")
        result=$?
        [[ "$verdict" == passed ]] && break
        [[ "$attempt" == 3 ]] || sleep 1
    done
    cscli metrics show appsec || { rm -rf -- "$work"; return 1; }
    log_info "HTTP=${http}；唯一请求标识=${marker}"
    case "$verdict" in
        passed) log_info 'passed / 通过（辅助证据）：HTTP 403，Processed、Blocked 与 crowdsecurity/vpatch-env-access 规则命中均增长。' ;;
        failed) log_err 'failed / 失败：测试未阻断，且 AppSec 请求/阻断/规则计数没有增长。' ;;
        *) log_warn 'inconclusive / 无法判断：HTTP 与 AppSec 请求/阻断/规则证据不足、指标不可读或发生重置。' ;;
    esac
    log_warn '累计指标可能包含同时发生的其他流量，不能单独证明这一次请求经过 AppSec；请在访问日志关联唯一标识、外部访客 IP，并核对具体规则日志。403 也可能来自原有 WAF。'
    rm -rf -- "$work"
    return "$result"
}

rollback_appsec_runtime() {
    APPSEC_FILES_RESTORED=false
    restore_config_change || return 1
    APPSEC_FILES_RESTORED=true
    local target mode=host failed=false
    for target in "$@"; do
        if [[ "$target" == -- ]]; then
            mode=docker
        elif [[ "$mode" == host ]]; then
            nginx_reload_verified "$target" || { log_warn "恢复配置后 ${target} 重载失败。"; failed=true; }
        elif ! nginx_reload_verified docker "$target"; then
            log_warn "恢复配置后容器 ${target} 重载失败。"
            failed=true
        fi
    done
    [[ "$failed" != true ]]
}

disable_appsec() (
    require_core && require_yaml || return 1
    APPSEC_FILE=$(yaml_tool appsec-file "$CS_DIR") || return 1
    if [[ ! -f "$APPSEC_FILE" ]]; then log_info '本工具未配置 AppSec，外部接入保留。'; return 0; fi
    confirm '停用本工具配置的 AppSec？外部数据源和规则集合保留。' || return 0
    local files=("$APPSEC_FILE" "$APPSEC_LINKS") file service
    local reloaded=()
    local docker_links='' container web_target resolved mounts running stage
    local docker_reloaded=()
    if [[ -f "$APPSEC_DOCKER_LINKS" ]]; then
        require_commands docker || return 1
        docker_links=$(yaml_tool docker-appsec-links "$APPSEC_DOCKER_LINKS") || return 1
        while IFS=$'\t' read -r container file web_target; do
            [[ -z "$container" ]] && continue
            running=$(docker inspect --format '{{.State.Running}}' "$container") || return 1
            [[ "$running" == true ]] || { log_err '管理的 Web 容器未运行；请先恢复容器再停用接入。'; return 1; }
            running=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container") || return 1
            if [[ "$running" != host ]]; then
                stage=$(mktemp -d) || return 1
                if ! transport_inspect "$container" "$stage" || ! transport_tool check-link "$APPSEC_DOCKER_LINKS" "$file" "$stage/inspection" "$stage/networks"; then rm -rf -- "$stage"; return 1; fi
                rm -rf -- "$stage"
            elif yaml_tool docker-link-private "$file" "$APPSEC_DOCKER_LINKS" >/dev/null 2>&1; then
                log_err '原 bridge 接入网络已变化，未停用引擎。'; return 1
            fi
            mounts=$(docker inspect --format '{{json .Mounts}}' "$container") || return 1
            resolved=$(printf '%s' "$mounts" | yaml_tool docker-bouncer-path "$web_target") || return 1
            [[ "$resolved" == "$file" ]] || { log_err '容器配置挂载已变化，请先核对接入；未停用引擎。'; return 1; }
            yaml_tool docker-link-current "$file" "$APPSEC_DOCKER_LINKS" || return 1
            appsec_guard_config "$file" "$container" "$web_target" || return 1
            files+=("$file")
        done <<< "$docker_links"
        files+=("$APPSEC_DOCKER_LINKS")
    fi
    for file in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        if [[ -f "$file" && -f "$APPSEC_LINKS" ]] && yaml_tool link-owned "$file" "$APPSEC_LINKS" >/dev/null 2>&1; then appsec_guard_config "$file" || return 1; files+=("$file"); fi
    done
    local committed=false core_apply_started=false APPSEC_FILES_RESTORED=false
    local CORE_CONFIG_TRACKING=false CORE_CONFIG_PENDING=false
    begin_config_change "${files[@]}" || return 1
    appsec_disable_exit() {
        local status=$?
        trap - EXIT INT TERM
        if [[ "$committed" != true ]]; then
            rollback_appsec_runtime "${reloaded[@]}" -- "${docker_reloaded[@]}" ||
                log_err 'AppSec 恢复未完成，修改前备份已保留，请检查网站与核心状态。'
            if [[ "$core_apply_started" == true && "$APPSEC_FILES_RESTORED" == true ]]; then
                if ! crowdsec -t || ! systemctl restart crowdsec || ! systemctl is-active --quiet crowdsec; then
                    log_err '恢复后的 AppSec 核心加载失败，请检查修改前备份。'
                fi
            fi
            [[ "$status" != 0 ]] || status=1
        fi
        [[ -z "$stage" ]] || rm -f -- "$stage"
        exit "$status"
    }
    trap appsec_disable_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for file in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        if [[ ! -f "$file" || ! -f "$APPSEC_LINKS" ]] || ! yaml_tool link-owned "$file" "$APPSEC_LINKS" >/dev/null 2>&1; then continue; fi
        if grep -Fxq 'APPSEC_URL=http://127.0.0.1:7422' "$file"; then
            service=nginx
            [[ "$file" == *openresty* ]] && service=openresty
            reloaded+=("$service")
            yaml_tool unlink-web-bouncer "$file" "$APPSEC_LINKS" && nginx_reload_verified "$service" || return 1
        fi
    done
    while IFS=$'\t' read -r container file web_target; do
        [[ -z "$container" ]] && continue
        stage=$(mktemp) || return 1
        docker_reloaded+=("$container")
        yaml_tool restore-docker-bouncer "$file" "$APPSEC_DOCKER_LINKS" "$stage" &&
            cp -- "$stage" "$file" && nginx_reload_verified docker "$container" || return 1
        rm -f -- "$stage"
    done <<< "$docker_links"
    if [[ -f "$APPSEC_DOCKER_LINKS" ]]; then rm -f -- "$APPSEC_DOCKER_LINKS" || return 1; fi
    rm -f "$APPSEC_FILE" || return 1
    core_apply_started=true
    apply_core_config || return 1
    committed=true
    log_succ '本工具 AppSec 数据源及记录过的 Web Bouncer 地址已恢复；未管理的容器或外部代理请同步停用请求转发。'
)

manage_waf_rules() {
    require_core || return 1
    local choice
    while true; do
        printf '\n检测规则\n1. 添加检测规则\n2. 查看已安装的规则\n3. 更新检测规则\n4. 补齐基础检测规则\n5. 删除不再使用的规则\n0. 返回\n'
        prompt choice '请选择 [0-5]: ' || return 0
        case "$choice" in
            1) manage_rule_installation; continue ;;
            2) cscli collections list ;;
            3) manage_rule_updates; continue ;;
            4) reset_waf_to_core_baseline ;;
            5) manage_rule_removal; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_rule_installation() {
    local choice
    while true; do
        printf '\n添加检测规则\n1. 网站访问日志\n2. WordPress 网站日志\n3. 防火墙日志（需已开启日志记录）\n0. 返回\n'
        prompt choice '请选择 [0-3]: ' || return 0
        case "$choice" in
            1) install_web_rules ;;
            2) install_collections crowdsecurity/wordpress && reload_core_rules ;;
            3) install_collections crowdsecurity/iptables && reload_core_rules ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_rule_updates() {
    local choice
    while true; do
        printf '\n更新检测规则\n1. 现在更新\n2. 设置自动更新\n0. 返回\n'
        prompt choice '请选择 [0-2]: ' || return 0
        case "$choice" in
            1) update_hub_logged ;;
            2) manage_auto_update; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_rule_removal() {
    local choice
    while true; do
        printf '\n删除检测规则\n1. 选择要删除的规则\n2. 移除已知的网站和防火墙日志规则\n0. 返回\n'
        prompt choice '请选择 [0-2]: ' || return 0
        case "$choice" in
            1) uninstall_specific_waf_collection ;;
            2) uninstall_all_waf_extensions ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

enable_auto_update() {
    require_core || return 1
    local minute="${1:-30}" hour="${2:-3}"
    if [[ ! "$minute" =~ ^[0-9]{1,2}$ || ! "$hour" =~ ^[0-9]{1,2}$ ]] || ! ((10#$minute <= 59 && 10#$hour <= 23)); then log_err '分钟应为 0–59，小时应为 0–23。'; return 1; fi
    local cron_service
    cron_service=cron
    [[ "$OS_ID" =~ ^(centos|rhel|almalinux|rocky|fedora)$ ]] && cron_service=crond
    systemctl is-active --quiet "$cron_service" || { log_err "${cron_service} 服务未运行，请先启用。"; return 1; }
    mkdir -p "$(dirname "$CRON_FILE")" || return 1
    local rotation='/etc/logrotate.d/crowdsec-1key'
    begin_config_change "$CRON_FILE" "$rotation" || return 1
    install_maintenance_runtime || return 1
    local runner="${MAINTENANCE_RUNTIME}/current/manager.sh"
    if ! printf '# CrowdSec Hub 更新；服务器时区，使用锁、备份和失败回滚。\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n%s %s * * * root /bin/bash %s --update-hub >/dev/null 2>&1\n' "$((10#$minute))" "$((10#$hour))" "$runner" > "$CRON_FILE"; then restore_config_change; return 1; fi
    if ! chmod 644 "$CRON_FILE"; then restore_config_change; return 1; fi
    if [[ -d "$(dirname "$rotation")" ]]; then
        if ! printf '%s {\n    weekly\n    rotate 8\n    maxsize 5M\n    missingok\n    notifempty\n    compress\n    copytruncate\n    create 0600 root root\n}\n' "$UPDATE_LOG" > "$rotation" || ! chmod 644 "$rotation"; then restore_config_change; return 1; fi
    fi
    log_succ "已设置每天 ${hour}:${minute} 更新 Hub 规则。"
}

manage_auto_update() {
    require_core || return 1
    local choice minute hour
    while true; do
        printf '\n检测规则自动更新（按服务器时间）\n1. 每天 03:30\n2. 自定义时间\n3. 关闭\n4. 查看任务\n0. 返回\n'
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) enable_auto_update ;;
            2)
                prompt minute '分钟 [30]: ' && prompt hour '小时 [3]: ' || return 0
                enable_auto_update "${minute:-30}" "${hour:-3}" ;;
            3) rm -f "$CRON_FILE" && log_succ '定时更新已关闭。' ;;
            4) if [[ -f "$CRON_FILE" ]]; then cat "$CRON_FILE"; else log_info '尚未启用。'; fi ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

firewall_status() {
    # 0: present, 1: confirmed absent, 2: cannot determine. Never treat errors as absence.
    local spec mode pattern output status found=false unknown=false checked=false tool
    spec="${FIREWALL_SPEC_CACHE:-}"
    if [[ -z "$spec" ]]; then spec=$(python3 "${SCRIPT_DIR}/lib/crowdsec_safety.py" firewall-spec "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml") || return 2; fi
    mode=${spec%%$'\n'*}; pattern=${spec#*$'\n'}
    case "$mode" in
        nftables) command -v nft >/dev/null 2>&1 || unknown=true ;;
        iptables) for tool in iptables ip6tables ipset; do command -v "$tool" >/dev/null 2>&1 || unknown=true; done ;;
        ipset) command -v ipset >/dev/null 2>&1 || unknown=true ;;
    esac
    for tool in nft iptables ip6tables ipset; do
        command -v "$tool" >/dev/null 2>&1 || continue
        checked=true
        case "$tool" in
            nft) output=$(nft list tables 2>/dev/null); status=$? ;;
            iptables) output=$(iptables -S 2>/dev/null); status=$? ;;
            ip6tables) output=$(ip6tables -S 2>/dev/null); status=$? ;;
            ipset) output=$(ipset list -name 2>/dev/null); status=$? ;;
        esac
        if [[ "$status" -ne 0 ]]; then unknown=true; continue; fi
        if printf '%s\n' "$output" | grep -Ei -- "$pattern"; then found=true; fi
    done
    if [[ "$found" == true ]]; then log_info '检测到防火墙资源；存在规则不等于阻断已通过流量验证。'; return 0; fi
    if [[ "$unknown" == true || "$checked" == false ]]; then log_err '无法判断防火墙残留：检查依赖、配置或枚举失败。'; return 2; fi
    log_info '成功枚举的防火墙后端未发现默认或已配置的 CrowdSec 资源。'
    return 1
}

safe_manual_ban() {
    local interfaces='[]'
    detect_admin_ip
    if command -v ip >/dev/null 2>&1; then
        interfaces=$(ip -j address show) || { log_err '读取本机接口失败，拒绝封禁。'; return 1; }
    else
        log_err '缺少 ip 命令，不能排除本机接口地址，拒绝封禁。'
        return 1
    fi
    python3 "${SCRIPT_DIR}/lib/crowdsec_safety.py" guard-ban "$1" "$CS_DIR" "$CURRENT_IP" "$interfaces"
}

manage_admin_allowlist() {
    require_core && require_yaml || return 1
    local choice address
    log_warn '中央 AllowList 会使这些来源跳过 AppSec，并影响中央决策过滤；parser whitelist 只保护日志处理。不会自动迁移代理网段。'
    while true; do
        printf '\n管理员 IP 放行名单\n1. 查看\n2. 添加一个 IP\n3. 移除一个 IP\n0. 返回\n'
        prompt choice '请选择 [0-3]: ' || return 0
        case "$choice" in
            1) cscli allowlists list && cscli allowlists inspect crowdsec-1key-admin ;;
            2|3)
                prompt address '管理员 IP（留空取消）: ' || return 0
                [[ -n "$address" ]] || continue
                address=$(yaml_tool normalize-ip "$address") || continue
                confirm '确认此单个 IP 的中央 AllowList 变更（添加会跳过 AppSec）？' || continue
                if [[ "$choice" == 2 ]]; then
                    # Inspect before create: a server/CLI error is never an excuse to overwrite.
                    cscli allowlists list || return 1
                    if ! cscli allowlists inspect crowdsec-1key-admin >/dev/null 2>&1; then
                        confirm '确认创建名为 crowdsec-1key-admin 的中央 AllowList？' || continue
                        cscli allowlists create crowdsec-1key-admin -d 'Explicit administrator addresses managed by crowdsec-1key' || return 1
                    fi
                    cscli allowlists add crowdsec-1key-admin "$address" || return 1
                    python3 "${SCRIPT_DIR}/lib/crowdsec_safety.py" record-admin "$CS_DIR" add "$address" || return 1
                else
                    cscli allowlists remove crowdsec-1key-admin "$address" || return 1
                    python3 "${SCRIPT_DIR}/lib/crowdsec_safety.py" record-admin "$CS_DIR" remove "$address" || return 1
                fi ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
    done
}

diagnose_self_report() {
    require_core || return 1
    log_info '只读 Self-Report 排查：按 loopback、本机接口和明确记录的地址查询警报与决策；不探测公网地址、不自动加白或解封。'
    log_info '核对 source_ip、触发场景及原始日志；可用 cscli alerts inspect <ID> -d 查看详情。'
    log_info "已知公网/NAT 地址只能来自明确记录 ${CS_DIR}/crowdsec-1key-own-addresses.json（JSON IP 字符串数组）；未知公网地址不能据此排除 Self-Report。"
    local result=0 interfaces='[]' addresses address
    if command -v ip >/dev/null 2>&1; then
        interfaces=$(ip -j address show) || { log_warn '接口信息不可读取，诊断不完整。'; interfaces='[]'; result=1; }
    else log_warn '缺少 ip，未核对接口地址。'; result=1; fi
    addresses=$(python3 "${SCRIPT_DIR}/lib/crowdsec_safety.py" known-addresses "$CS_DIR" "$interfaces") || return 1
    while IFS= read -r address; do
        [[ -n "$address" ]] || continue
        cscli decisions list --ip "$address" || result=1
        cscli alerts list --ip "$address" --limit 20 || result=1
    done <<< "$addresses"
    cscli parsers inspect crowdsecurity/whitelists || result=1
    cscli allowlists list || result=1
    log_info 'parser whitelist 只保护日志处理；中央 AllowList 会影响中央决策及 AppSec。CAPI 认证可另行明确执行 cscli capi status（会访问官方 API）。'
    return "$result"
}

repair_firewall_bouncer() (
    require_core && require_yaml && require_commands curl || return 1
    systemctl is-active --quiet crowdsec || { log_err '核心未运行，请先排查核心服务。'; return 1; }
    local cfg="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" key='' url credentials docker_chain=false new_name=''
    local changed=false committed=false
    firewall_repair_exit() {
        local result=$? cleanup_account=true
        trap - EXIT INT TERM
        if [[ "$committed" != true ]]; then
            if [[ "$changed" == true ]]; then
                if ! restore_config_change || ! systemctl restart crowdsec-firewall-bouncer || ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
                    cleanup_account=false
                    log_err 'Bouncer 回滚未完成，保留新增账号；请根据修改前备份恢复服务后核验。'
                fi
            fi
            if [[ -n "$new_name" && "$cleanup_account" == true ]]; then cscli bouncers delete "$new_name" || log_warn '新增 Bouncer 账号清理失败，请人工核验。'; fi
        fi
        exit "$result"
    }
    trap firewall_repair_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    [[ -s "$cfg" ]] || { log_err '缺少官方 Bouncer 配置，请先安装对应软件包。'; return 1; }
    python3 "${SCRIPT_DIR}/lib/crowdsec_firewall.py" guard "$cfg" || return 1
    credentials=$(yaml_tool client-credentials-path "${CS_DIR}/config.yaml") || return 1
    url=$(yaml_tool get "$credentials" url) || return 1
    key=$(yaml_tool bouncer-key "$cfg" 2>/dev/null) || key=''
    if [[ -z "$key" || "$key" == '<API_KEY>' ]]; then
        new_name="crowdsec-1key-firewall-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
        key=$(cscli bouncers add "$new_name" -o raw) || return 1
        [[ "$key" =~ ^[A-Za-z0-9_-]{16,}$ ]] || { log_err '未获取有效 Bouncer 密钥。'; return 1; }
    fi
    if ! curl -fsS --connect-timeout 3 --max-time 5 -H "X-Api-Key: ${key}" "${url%/}/v1/decisions" >/dev/null; then
        log_err 'Bouncer 密钥无法访问 LAPI，请核查 URL 与已注册密钥；不会删除其他 Bouncer。'
        return 1
    fi
    if command -v iptables >/dev/null 2>&1 && iptables -S DOCKER-USER >/dev/null 2>&1; then docker_chain=true; fi
    begin_config_change "$cfg" "${cfg}.local" || return 1
    changed=true
    yaml_tool bouncer "$cfg" "$url" "$key" "$docker_chain" || return 1
    if ! systemctl restart crowdsec-firewall-bouncer || ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
        journalctl -u crowdsec-firewall-bouncer -n 30 --no-pager
        return 1
    fi
    committed=true
    log_succ 'Bouncer 服务已运行；现有其他 Bouncer 凭据保留。'
    cscli bouncers list || return 1
    firewall_status
)

manage_firewall_ops() {
    require_core && require_yaml || return 1
    local choice ip duration reason
    while true; do
        printf '\nIP 封禁与放行\n1. 查看被封禁的 IP\n2. 查看最近的告警\n3. 解封 IP\n4. 封禁 IP\n5. 查看防火墙规则\n6. 查看日志解析情况\n7. 修复防火墙与检测服务的连接\n8. 管理员 IP 放行名单\n9. 排查服务器自身 IP 被封禁的问题\n0. 返回\n'
        prompt choice '请选择 [0-9]: ' || return 0
        case "$choice" in
            1) cscli decisions list ;;
            2) cscli alerts list --limit 20 ;;
            3)
                prompt ip '解封 IP（留空取消）: ' || return 0
                if [[ -n "$ip" ]] && yaml_tool ip "$ip"; then
                    if cscli decisions delete --ip "$ip"; then log_succ 'IP 解封决策已提交。'; else log_err '解封失败。'; fi
                fi ;;
            4)
                prompt ip '封禁 IP（留空取消）: ' || return 0
                if [[ -z "$ip" ]]; then continue; fi
                if ! yaml_tool ip "$ip"; then continue; fi
                ip=$(yaml_tool normalize-ip "$ip") || continue
                prompt duration '时长（Go duration，例如 4h、24h、168h）[24h]: ' && prompt reason '原因 [手动封禁]: ' || return 0
                duration="${duration:-24h}"
                if [[ ! "$duration" =~ ^([0-9]+(\.[0-9]+)?(h|m|s|ms|us|ns))+$ || "$duration" =~ ^0+(\.0+)?(h|m|s|ms|us|ns)$ ]]; then log_err '时长无效，请使用正数 h/m/s 格式；7 天请填写 168h。'; continue; fi
                safe_manual_ban "$ip" || continue
                if cscli decisions add --ip "$ip" --duration "$duration" --reason "${reason:-手动封禁}" --type ban; then
                    log_succ '封禁决策已提交；由 Bouncer 拉取执行。'
                else log_err '添加封禁失败。'; fi ;;
            5) firewall_status ;;
            6) cscli metrics ;;
            7) repair_firewall_bouncer ;;
            8) manage_admin_allowlist; continue ;;
            9) diagnose_self_report ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

bind_crowdsec_console() {
    require_core || return 1
    local token
    prompt token 'Console Enrollment Key（留空取消）: ' || return 0
    [[ -z "$token" ]] && return 0
    if ! cscli console enroll "$token"; then
        log_err 'Console 注册失败。已注册实例需要在确认归属后手动使用 --overwrite；不会自动覆盖。'
        return 1
    fi
    systemctl restart crowdsec && systemctl is-active --quiet crowdsec || return 1
    log_succ '注册请求已提交。请登录 https://app.crowdsec.net 接受注册，再核验实例。'
    log_info '接受注册后运行 sudo cscli console status；请求提交不代表 Console 已完成接受或决策管理已启用。'
}

resolve_telegram_paths() {
    local resolved
    resolved=$(yaml_tool notification-paths "$CS_DIR") || return 1
    TG_NOTIF_FILE="${resolved%%$'\n'*}"
    PROFILES_FILE="${resolved#*$'\n'}"
    TG_PROFILE_PATHS=("$PROFILES_FILE")
    if [[ -f "${PROFILES_FILE}.local" ]]; then TG_PROFILE_PATHS=("${PROFILES_FILE}.local" "$PROFILES_FILE"); fi
}

update_telegram_profiles() {
    local operation="$1" path
    shift
    for path in "${TG_PROFILE_PATHS[@]}"; do
        log_info "通知路由 ${operation}: ${path}（按 local 优先顺序；只覆盖匹配该 profile 的告警）"
        yaml_tool profiles "$path" "$operation" "$@" || return 1
    done
}


setup_telegram_notification() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    local smart_status=0
    notify_tool enabled "$CS_DIR" || smart_status=$?
    if [[ "$smart_status" == 0 ]]; then
        log_err '当前启用了分级通知；请先在 TG 菜单第 6 项恢复原通知模式，再修改通知目标。'; return 1
    elif [[ "$smart_status" != 2 ]]; then return 1; fi
    local token chat endpoint routes
    local delivery="${1:-preserve}" choice
    local -a replaced_routes=()
    prompt token 'Telegram Bot Token: ' && prompt chat 'Chat ID（个人或负数群组 ID）: ' && prompt endpoint 'HTTPS API 端点 [https://api.telegram.org]: ' || return 1
    endpoint="${endpoint:-https://api.telegram.org}"
    if [[ ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ || ! "$chat" =~ ^-?[0-9]+$ ]] || ! yaml_tool url "$endpoint"; then log_err 'Token、Chat ID 或 API 端点格式无效。'; return 1; fi
    if [[ "$delivery" == interactive ]]; then
        printf '\n通知模式：1. 即时通知  2. 批量通知（30 秒或 10 条）\n留空保留当前模式；首次配置默认即时。\n'
        prompt choice '请选择 [留空/1/2]: ' || return 1
        case "$choice" in
            '') delivery=preserve ;;
            1) delivery=immediate ;;
            2) delivery='batch' ;;
            *) log_err '通知模式无效，未修改配置。'; return 1 ;;
        esac
    fi
    [[ -f "$PROFILES_FILE" ]] || { log_err 'profiles.yaml 不存在，无法启用告警。'; return 1; }
    [[ ! -f "$TG_NOTIF_FILE" ]] || log_info '检测到已有本工具 Telegram 配置，将原位更新。'
    routes=$(yaml_tool telegram-routes "$CS_DIR" "$token" "$chat") || return 1
    if [[ -n "$routes" ]]; then
        mapfile -t replaced_routes <<< "$routes"
        log_info "检测到同一机器人/Chat ID 的旧 HTTP 通知通道，将替换其 profile 路由：${replaced_routes[*]}"
    fi
    begin_config_change "$TG_NOTIF_FILE" "${TG_PROFILE_PATHS[@]}" || return 1
    if ! yaml_tool telegram "$TG_NOTIF_FILE" "$token" "$chat" "$endpoint" "$delivery" || ! update_telegram_profiles enable "${replaced_routes[@]}"; then
        restore_config_change
        return 1
    fi
    apply_core_config || return 1
    log_succ 'Telegram 配置已加载，同一目标的旧 HTTP 路由已替换，其他通知通道保留。'
    log_info '不同 Alert ID/规则仍会分别通知；独立 TG 机器人服务不由 HTTP 通知配置控制。'
    log_info '发送告警是出站 HTTPS 请求，不需要额外放行 Telegram 来源网段。'
    if confirm '现在发送一条官方插件测试消息并核对 Telegram API 回执？'; then
        test_telegram_notification || { log_err '配置已加载，投递验证失败。'; return 1; }
    fi
    return 0
}

test_telegram_notification() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    [[ -f "$TG_NOTIF_FILE" ]] || { log_err '请先配置 Telegram。'; return 1; }
    python3 "${SCRIPT_DIR}/lib/crowdsec_telegram.py" test "$CS_DIR"
}

check_telegram_settings() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    if ! crowdsec -t; then
        log_err '[异常] CrowdSec 配置校验失败。'
        return 1
    fi
    log_info '[正常] CrowdSec 配置校验通过；以下检查不发送消息。'
    python3 "${SCRIPT_DIR}/lib/crowdsec_telegram.py" status "$CS_DIR"
}

disable_telegram_notification() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    confirm '停用本工具 Telegram 通知？其他通知通道保留。' || return 0
    local smart_status=0
    notify_tool enabled "$CS_DIR" || smart_status=$?
    if [[ "$smart_status" == 0 ]]; then disable_smart_notifications off; return $?;
    elif [[ "$smart_status" != 2 ]]; then return 1; fi
    begin_config_change "$TG_NOTIF_FILE" "${TG_PROFILE_PATHS[@]}" || return 1
    update_telegram_profiles disable || { restore_config_change; return 1; }
    rm -f "$TG_NOTIF_FILE" || { restore_config_change; return 1; }
    apply_core_config || return 1
    log_succ '本工具 Telegram 通道已停用。'
}

manage_telegram() {
    require_core || return 1
    local choice
    while true; do
        printf '\nTelegram 告警\n1. 设置通知\n2. 发送测试消息并检查是否送达\n3. 查看通知状态，检查重复通知\n4. 停用本工具的通知\n5. 管理交互机器人（查询和按钮操作）\n6. 分级降噪通知\n0. 返回\n'
        prompt choice '请选择 [0-6]: ' || return 0
        case "$choice" in
            1) setup_telegram_notification interactive ;;
            2) test_telegram_notification ;;
            3) check_telegram_settings ;;
            4) disable_telegram_notification ;;
            5) manage_custom_bot; continue ;;
            6) manage_smart_notifications; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

check_web_health_status() {
    health_expect core
    health_expect logs
    if [[ ! -f "${CS_DIR}/config.yaml" ]]; then
        health_event core missing
        require_core
        return 1
    fi
    require_core || { health_event core unknown; return 1; }
    local result=0 evidence=0 firewall_deployed=false units
    printf '\n核心服务:\n'
    health_service core crowdsec || result=1
    if [[ -e "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" || -e "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.local" ]]; then
        firewall_deployed=true
    elif units=$(systemctl list-unit-files --no-legend --no-pager crowdsec-firewall-bouncer.service); then
        if grep -q '^crowdsec-firewall-bouncer\.service[[:space:]]' <<< "$units"; then firewall_deployed=true; fi
    else
        log_err '无法确认 Firewall Bouncer 是否已部署。'
        health_event bouncer unknown
        firewall_deployed=unknown
        result=1
    fi
    if [[ "$firewall_deployed" == true ]]; then
        health_service bouncer crowdsec-firewall-bouncer || result=1
    elif [[ "$firewall_deployed" == false ]]; then
        if node_has_role relay; then health_event bouncer missing; else health_event bouncer optional; fi
        log_info 'Firewall Bouncer: 未部署（可选）。'
    fi
    printf '\nLAPI 登录:\n'
    health_probe api unknown cscli lapi status || result=1
    printf '\n配置校验:\n'
    health_probe config fault crowdsec -t || result=1
    printf '\n注册的 Bouncer 与 Machine:\n'
    health_probe registry unknown cscli bouncers list || result=1
    health_probe registry unknown cscli machines list || result=1
    printf '\n日志采集与解析指标:\n'
    health_probe metrics unknown cscli metrics || result=1
    if [[ "$firewall_deployed" == true ]]; then
        printf '\n防火墙规则:\n'
        local backend_status=0
        check_firewall_backend || backend_status=$?
        if [[ "$backend_status" == 1 ]]; then result=1
        elif [[ "$backend_status" == 2 && "$result" == 0 ]]; then result=2; fi
        firewall_status || result=1
    fi
    if [[ "${1:-web}" == web ]]; then
        check_appsec_status optional || result=1
    else
        log_info '[不适用] AppSec 网站接入：当前用途未部署网站防护。'
    fi
    check_webui_status || { health_event webui unknown; result=1; }
    printf '\n保护证据（正常 / 异常 / 尚未验证）:\n'
    if require_yaml; then
        if [[ "${1:-web}" == web ]]; then check_protection_evidence || evidence=$?
        else check_system_protection_evidence || evidence=$?; fi
    else evidence=2; health_event logs unknown; log_warn '[尚未验证] 缺少结构化检查依赖。'; fi
    [[ "$evidence" == 1 ]] && result=1
    [[ "$result" == 0 && "$evidence" == 2 ]] && result=2
    log_info '检查完成：退出码 1 表示异常，2 表示仍有尚未验证项目。未修改服务、账号或配置。'
    return "$result"
}

smart_audit_and_optimize() (
    CORE_CONFIG_TRACKING=true
    CORE_CONFIG_PENDING=false
    require_core || return 1
    printf '\n资源概况:\n'
    free -m
    df -h /
    check_health_status || true
    local answer item rules=false logs=false metrics=false operation=reload
    local backup_ready=false committed=false core_apply_started=false
    local CORE_RULES_CHANGED=false
    local paths=() selected=()
    log_info '逐项选择基础修复（默认不选），选择完成后还需确认执行。'
    for item in rules logs metrics; do
        case "$item" in
            rules) prompt answer '补齐基础日志检测集合？[y/N]: ' || return 0 ;;
            logs) prompt answer '修复 HTTP 日志采集？[y/N]: ' || return 0 ;;
            metrics) prompt answer '启用 loopback 指标（保留现有端口）？[y/N]: ' || return 0 ;;
        esac
        case "$answer" in
            y|Y) printf -v "$item" '%s' true ;;
            n|N|'') ;;
            *) log_err '请输入 y 或 n；本次修复未执行。'; return 1 ;;
        esac
    done
    if [[ "$rules" == false && "$logs" == false && "$metrics" == false ]]; then
        log_info '未选择修复项目，保持诊断结果。'
        return 0
    fi
    require_yaml || return 1
    # shellcheck disable=SC2329 # invoked by EXIT trap
    optimize_exit() {
        local result=$? config_restored=true restore_needed=false
        trap - EXIT INT TERM
        if [[ "$backup_ready" == true && "$committed" != true && "$CORE_CONFIG_PENDING" == true ]]; then
            restore_needed=true
            restore_config_change || { config_restored=false; log_err '所选配置恢复失败，请使用修改前备份手工恢复。'; }
        fi
        local hub_restored=true
        hub_abort no-load || hub_restored=false
        if [[ "$restore_needed" == true && "$hub_restored" == true && "$config_restored" == true ]]; then
            if [[ "$core_apply_started" == true ]]; then
                if ! crowdsec -t || ! systemctl restart crowdsec || ! systemctl is-active --quiet crowdsec; then
                    log_err '原配置服务恢复失败，请手工核验。'
                fi
            fi
        fi
        cleanup_log_repair
        exit "$result"
    }
    trap optimize_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ "$rules" == true ]]; then selected+=('补齐基础日志检测集合（保留自定义/AppSec）'); fi
    if [[ "$logs" == true ]]; then
        prepare_log_repair || return 1
        selected+=("修复 HTTP 日志采集：待调整 ${LOG_REPAIR_COUNT} 项")
        if [[ "$LOG_REPAIR_COUNT" != 0 ]]; then paths+=("$LOG_REPAIR_FILE" "$LOG_PRESET_FILE"); fi
    fi
    if [[ "$metrics" == true ]]; then
        selected+=('启用 loopback 指标（保留现有端口）')
        paths+=("${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local")
    fi
    printf '\n本次选择的修复项目：\n'
    printf '  - %s\n' "${selected[@]}"
    log_info '配置写入前备份；校验后统一加载，无变化时跳过加载。'
    if [[ "$rules" == true ]]; then log_info '基础集合使用 Hub 事务，配置校验或加载失败时尝试恢复规则及下载数据。'; fi
    confirm '仅应用上述所选项目？' || return 0
    begin_config_change "${paths[@]}" || return 1
    backup_ready=true
    if [[ "$metrics" == true ]]; then enable_prometheus_metrics || return 1; fi
    if [[ "$logs" == true ]]; then apply_staged_log_repair || return 1; fi
    if [[ "$rules" == true ]]; then
        install_baseline_collections || return $?
    fi
    # File changes require restart; rules alone only require reload.
    if CORE_RULES_CHANGED=false config_change_needed; then operation=restart; fi
    core_apply_started=true
    if ! apply_core_config "$operation"; then
        # apply_core_config already attempts configuration/service restoration.
        backup_ready=false
        return 1
    fi
    committed=true
    log_succ '已完成所选基础修复并校验配置；请求识别与实际防护仍需分别核验。'
    if [[ "$logs" == true ]]; then log_info '日志采集请通过新增访问与 cscli metrics 核验。'; fi
    log_info 'SQLite WAL 可使用 --enable-wal，在确认数据库位于本地磁盘后启用官方 db_config.use_wal。'
    log_info '上游不确定时先用 --diagnose-real-ip 或菜单 [4] → [2] → [3] 选择目标并只读诊断；确认代理后再用 --repair-real-ip 修复。'
)

enable_sqlite_wal() {
    require_core && require_yaml || return 1
    log_warn 'SQLite WAL 不适用于网络共享盘；请先确认数据库位于本地磁盘。'
    confirm '确认本地 SQLite 数据库并启用官方 WAL 配置？' || return 0
    begin_config_change "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || return 1
    yaml_tool wal "${CS_DIR}/config.yaml" || { restore_config_change; return 1; }
    apply_core_config || return 1
    log_succ '已通过 db_config.use_wal 启用 WAL；未执行 VACUUM 或临时 PRAGMA。'
}

# The observation ledger is deliberately retained. Require explicit service
# shutdown before removing the core that consumes its published events.
v2bx_purge_preflight() {
    local service info line loaded active enabled
    for service in crowdsec-v2bx-alerts crowdsec-v2bx-observer; do
        loaded='' active='' enabled=''
        info=$(systemctl show --property=LoadState --property=ActiveState --property=UnitFileState "$service.service") || {
            log_err "无法读取 ${service} 状态，未卸载核心。"; return 1;
        }
        while IFS= read -r line; do
            case "$line" in
                LoadState=*) loaded=${line#LoadState=} ;;
                ActiveState=*) active=${line#ActiveState=} ;;
                UnitFileState=*) enabled=${line#UnitFileState=} ;;
            esac
        done <<< "$info"
        if [[ "$loaded" == not-found && "$active" == inactive && -z "$enabled" &&
            ! -e "/etc/systemd/system/$service.service" && ! -L "/etc/systemd/system/$service.service" ]]; then continue; fi
        if [[ "$loaded" == loaded && ( "$active" == inactive || "$active" == failed ) && "$enabled" == disabled ]]; then continue; fi
        log_err "${service} 尚未停用或状态无法确认；请先 --disable-v2bx-alerts，再 --disable-v2bx-observer，随后重试卸载。"
        return 1
    done
}

audit_crowdsec_residuals() {
    local found=false path service
    log_info '残留检查（只读，不自动清理）：'
    for path in "$CS_DIR" /var/lib/crowdsec "$WEBUI_DIR" "$CRON_FILE" "$MAINTENANCE_RUNTIME" \
        /usr/local/lib/crowdsec-v2bx-observer /var/lib/crowdsec-v2bx-observer \
        /usr/local/lib/crowdsec-v2bx-alerts /var/lib/crowdsec-v2bx-alerts \
        /etc/systemd/system/crowdsec-v2bx-observer.service /etc/systemd/system/crowdsec-v2bx-alerts.service; do
        if [[ -e "$path" ]]; then printf '存在: %s\n' "$path"; found=true; fi
    done
    for service in crowdsec crowdsec-firewall-bouncer crowdsec-v2bx-alerts crowdsec-v2bx-observer; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then printf '服务活跃: %s\n' "$service"; found=true; fi
    done
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -a -x crowdsec && found=true
        pgrep -a -x crowdsec-firewall-bouncer && found=true
    fi
    if command -v cscli >/dev/null 2>&1; then log_info 'cscli 仍在 PATH 中。'; found=true; fi
    if command -v docker >/dev/null 2>&1; then docker ps -a --filter 'name=^/crowdsec-web-ui$' --format '{{.Names}} {{.Status}}'; fi
    local firewall_result
    firewall_status; firewall_result=$?
    [[ "$firewall_result" == 0 ]] && found=true
    [[ "$firewall_result" == 2 ]] && return 2
    if [[ "$found" == true ]]; then log_warn '检测到安装组件或残留；需要卸载时请选择明确的卸载入口。'; return 1; fi
    log_info '上述检查未发现残留；自定义服务、规则和软件源需按实际部署另行核验。'
}

deep_purge_residuals() {
    confirm '永久删除 CrowdSec 核心、数据、Bouncer 与本工具 WebUI？' || return 0
    require_commands systemctl python3 || return 1
    case "$OS_ID" in
        debian|ubuntu) require_commands dpkg-query apt-get || return 1 ;;
        centos|rhel|almalinux|rocky|fedora)
            require_commands rpm || return 1
            command -v dnf >/dev/null 2>&1 || require_commands yum || return 1 ;;
        *) log_err '未知系统，未停止服务或修改安装。'; return 1 ;;
    esac
    require_yaml || return 1
    local firewall_result FIREWALL_SPEC_CACHE
    FIREWALL_SPEC_CACHE=$(python3 "${SCRIPT_DIR}/lib/crowdsec_safety.py" firewall-spec "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml") || return 1
    firewall_status >/dev/null 2>&1; firewall_result=$?
    if [[ "$firewall_result" == 2 ]]; then log_err '无法确定防火墙状态，停止卸载。'; return 1; fi
    local real_ip_installs
    real_ip_installs=$(real_ip_tool list "$REALIP_STATE") || return 1
    if [[ -n "$real_ip_installs" ]]; then
        log_err '仍有本工具的真实 IP 配置；请先 --restore-real-ip（Docker）或 --restore-host-real-ip（宿主机）撤销网站配置，再卸载核心。'
        return 1
    fi
    local native_installs
    native_installs=$(web_tool list "$WEB_INSTALLS") || return 1
    if [[ -n "$native_installs" ]]; then
        log_err '仍有本工具的原生 Web Bouncer 安装/待清理记录；请先 --remove-web-bouncer 恢复网站配置，再卸载核心。'
        return 1
    fi
    if [[ -f "$APPSEC_DOCKER_LINKS" ]]; then
        log_err '仍有本工具记录的容器 Web Bouncer 接入。请先停用 AppSec 接入并移除容器内 Web Bouncer，再卸载核心。'
        return 1
    fi
    local web_config
    for web_config in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        if [[ -f "$web_config" ]]; then
            log_err "仍有 Web Bouncer 集成 ${web_config}。请先按上游文档移除 Nginx/OpenResty 集成并验证网站，再卸载核心。"
            return 1
        fi
    done
    v2bx_purge_preflight || return 1
    local packages=() package package_status query_status
    case "$OS_ID" in
        debian|ubuntu)
            for package in crowdsec crowdsec-firewall-bouncer crowdsec-firewall-bouncer-nftables crowdsec-firewall-bouncer-iptables; do
                package_status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null); query_status=$?
                [[ "$query_status" -le 1 ]] || { log_err '软件包查询失败，未停止服务。'; return 1; }
                [[ "$package_status" == 'install ok installed' ]] && packages+=("$package")
            done ;;
        *)
            for package in crowdsec crowdsec-firewall-bouncer crowdsec-firewall-bouncer-nftables crowdsec-firewall-bouncer-iptables; do
                rpm -q "$package" >/dev/null 2>&1; query_status=$?
                [[ "$query_status" -le 1 ]] || { log_err '软件包查询失败，未停止服务。'; return 1; }
                [[ "$query_status" == 0 ]] && packages+=("$package")
            done ;;
    esac
    for package in "${packages[@]}"; do
        if [[ "$package" == crowdsec-firewall-bouncer* && ! -s "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" && ! -s "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.local" ]]; then
            log_err 'Bouncer 软件包存在但配置不可读取，无法核对自定义防火墙资源；未停止服务。'
            return 1
        fi
    done
    purge_smart_notifications || return 1
    purge_custom_bot || return 1
    local service
    for service in crowdsec-firewall-bouncer crowdsec; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then systemctl stop "$service" || return 1; fi
        systemctl disable "$service" 2>/dev/null || true
    done
    # Never use pkill -f: it can match this script and unrelated maintenance processes.
    if webui_owned && command -v docker >/dev/null 2>&1 && docker container inspect crowdsec-web-ui >/dev/null 2>&1; then
        docker rm -f crowdsec-web-ui || return 1
    fi
    # Read custom table names while package-owned configuration still exists.
    firewall_status >/dev/null 2>&1; firewall_result=$?
    if [[ "$firewall_result" != 1 ]]; then
        log_err '服务停止后仍有防火墙资源。请根据 Bouncer 配置人工释放；未删除软件包、配置或数据。'
        return 1
    fi
    if ((${#packages[@]})); then
        case "$OS_ID" in
            debian|ubuntu) apt-get purge -y "${packages[@]}" || return 1 ;;
            *) if command -v dnf >/dev/null 2>&1; then dnf remove -y "${packages[@]}" || return 1; else yum remove -y "${packages[@]}" || return 1; fi ;;
        esac
    fi
    # The official service removes managed chains on shutdown; verify before deleting data.
    firewall_status >/dev/null 2>&1; firewall_result=$?
    if [[ "$firewall_result" != 1 ]]; then
        log_err '默认防火墙资源仍存在。请根据原 Bouncer 配置人工释放，配置和数据已保留。'
        return 1
    fi
    rm -rf -- "$CS_DIR" /var/lib/crowdsec || return 1
    if webui_owned; then rm -rf -- "$WEBUI_DIR" || return 1; fi
    rm -f -- "$CRON_FILE" || return 1
    if [[ -f "${MAINTENANCE_RUNTIME}/.crowdsec-1key-managed" ]]; then rm -rf -- "$MAINTENANCE_RUNTIME" || return 1; fi
    if [[ -f "$HUB_RUNNER_DIR/.crowdsec-1key-owned" ]]; then rm -rf -- "$HUB_RUNNER_DIR" || return 1; fi
    systemctl daemon-reload || return 1
    log_succ '已卸载检测到的软件包并清理数据。备份、系统日志和软件源保留供恢复/排查。'
    log_info '若已注册 Console，请在控制台移除离线实例。'
}

uninstall_crowdsec_all() { deep_purge_residuals; }

manage_uninstall_center() {
    local choice
    while true; do
        printf '\n卸载与清理\n1. 卸载 CrowdSec 并清理本工具数据（需要确认）\n2. 检查是否有残留\n保留备份、系统日志和软件源；网站接入须先撤销，恢复步骤见 README。\n0. 返回\n'
        prompt choice '请选择 [0-2]: ' || return 0
        case "$choice" in
            1) uninstall_crowdsec_all ;;
            2) audit_crowdsec_residuals ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_installation() {
    local choice
    while true; do
        printf '\n安装与接入\n1. 安装检测服务和防火墙防护（网站模式）\n2. 为网站接入防护\n3. 检查或修正访客真实 IP\n4. 设置容器连接检测服务的私有地址\n5. 为纯中转节点安装基础防护\n6. 连接远端检测中心\n0. 返回\n'
        prompt choice '请选择 [0-6]: ' || return 0
        case "$choice" in
            1) install_crowdsec_core ;;
            2) manage_website_protection; continue ;;
            3) manage_real_ip; continue ;;
            4) configure_docker_endpoints ;;
            5) install_crowdsec_core relay ;;
            6) manage_remote_bouncer; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_website_protection() {
    local choice
    while true; do
        printf '\n网站防护接入\n1. 配置网站请求检测并接入网站\n2. 安装网站拦截组件（需先配置请求检测）\n3. 查看网站请求检测状态\n4. 发送测试请求验证网站防护（需要确认）\n5. 设置请求正文检查和检测故障时的处理方式\n6. 停用本工具的网站请求检测\n7. 移除本工具安装的容器网站拦截组件\n0. 返回\n'
        prompt choice '请选择 [0-7]: ' || return 0
        case "$choice" in
            1) setup_appsec ;;
            2) install_web_bouncer ;;
            3) check_appsec_status ;;
            4) verify_appsec ;;
            5) configure_appsec_policy ;;
            6) disable_appsec ;;
            7) remove_docker_web_bouncer ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_real_ip() {
    local target choice label
    local runtime=()
    while true; do
        printf '\n检查访客真实 IP — 选择网站运行位置\n1. Docker Nginx/OpenResty/NPM\n2. 宿主机 Nginx/OpenResty\n0. 返回\n'
        prompt target '请选择 [0-2]: ' || return 0
        case "$target" in
            1) runtime=(); label=Docker ;;
            2) runtime=(host); label=宿主机 ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        while true; do
            printf '\n%s 真实 IP\n1. 检查代理路径和访客真实 IP\n2. 按已确认可信的 CDN 或代理修正配置\n3. 通过正常访问核对日志和拦截组件识别的 IP\n4. 撤销本工具真实 IP 配置\n0. 返回目标选择\n' "$label"
            prompt choice '请选择 [0-4]: ' || return 0
            case "$choice" in
                1) repair_cloudflare_real_ip diagnose "${runtime[@]}" ;;
                2) locked_operation repair_cloudflare_real_ip apply "${runtime[@]}" ;;
                3) locked_operation verify_real_ip_request "${runtime[@]}" ;;
                4) locked_operation repair_cloudflare_real_ip remove "${runtime[@]}" ;;
                0) break ;;
                *) log_warn '无效选项。'; continue ;;
            esac
            pause
        done
    done
}

manage_diagnostics() {
    local choice
    while true; do
        printf '\n检查与修复\n1. 检查整体运行情况\n2. 排查网站问题\n3. 检查中转节点\n4. 管理 V2bX 落地节点\n5. 修复基础配置\n0. 返回\n'
        prompt choice '请选择 [0-5]: ' || return 0
        case "$choice" in
            1) interactive_health_check; continue ;;
            2) manage_website_diagnostics; continue ;;
            3) manage_relay_diagnostics; continue ;;
            4) manage_v2bx_node; continue ;;
            5) manage_basic_repairs; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_website_diagnostics() {
    local choice
    while true; do
        printf '\n排查网站问题\n1. 检查网站日志是否正常采集\n2. 查看网站防护运行情况\n3. 检查或修正访客真实 IP\n4. 补齐漏采的网站日志\n0. 返回\n'
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) check_log_inventory ;;
            2) check_appsec_status ;;
            3) manage_real_ip; continue ;;
            4) locked_operation repair_log_acquis ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_relay_diagnostics() {
    local choice
    while true; do
        printf '\n检查中转节点\n1. 查看中转防护运行情况\n2. 检查连接来源和转发路径\n3. 引导验证中转入口拦截\n0. 返回\n'
        prompt choice '请选择 [0-3]: ' || return 0
        case "$choice" in
            1) check_relay_status ;;
            2) check_relay_path ;;
            3) verify_relay ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_basic_repairs() {
    local choice
    while true; do
        printf '\n修复基础配置\n1. 排查服务器自身 IP 被封禁的问题\n2. 修复防火墙与检测服务的连接\n3. 检查后选择需要修复的项目\n4. 改善日志数据库写入（需使用本地磁盘）\n0. 返回\n'
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) diagnose_self_report ;;
            2) locked_operation repair_firewall_bouncer ;;
            3) locked_operation smart_audit_and_optimize ;;
            4) locked_operation enable_sqlite_wal ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

manage_integrations() {
    local choice
    while true; do
        printf '\n控制台与通知\n1. 网页管理面板\n2. 绑定 CrowdSec 在线控制台\n3. Telegram 通知\n0. 返回\n'
        prompt choice '请选择 [0-3]: ' || return 0
        case "$choice" in
            1) manage_web_ui; continue ;;
            2) bind_crowdsec_console ;;
            3) manage_telegram; continue ;;
            0) return 0 ;;
            *) log_warn '无效选项。'; continue ;;
        esac
        pause
    done
}

show_startup_banner() {
    local banner_cyan='' banner_green='' banner_reset=''
    if [[ -t 1 && "${TERM:-dumb}" != dumb && -z "${NO_COLOR+x}" ]] &&
        command -v tput >/dev/null 2>&1 && tput setaf 6 >/dev/null 2>&1; then
        banner_cyan=$'\033[1;36m'
        banner_green=$'\033[1;32m'
        banner_reset=$'\033[0m'
    fi
    printf '\n%s' "$banner_cyan"
    cat <<'EOF'
   ______                        ______             __  _
  / ____/________ _      _______/ __  /____ ______/ /_(_)___  ____
 / /   / ___/ __ \ | /| / / __  / __  / __ `/ ___/ __/ / __ \/ __ \
/ /___/ /  / /_/ / |/ |/ / /_/ / /_/ / /_/ (__  ) /_/ / /_/ / / / /
\____/_/   \____/|__/|__/\__,_/_____/\__,_/____/\__/_/\____/_/ /_/
EOF
    printf '\n%s%s' "$banner_reset" "$banner_green"
    cat <<'EOF'
 ─────────────────────────────────────────────────────────────────
                      C R O W D B A S T I O N

                    SERVER DEFENSE & OPERATIONS

                         Web / Relay / Node
                        Powered by CrowdSec

                  github.com/8bitNull/CrowdBastion
 ─────────────────────────────────────────────────────────────────
 >> CROWDBASTION v3.0 | Next-Gen Lightweight VPS Sentinel
 >> NPM Host Mode + Firewall Enforcement + Mobile Telegram SOC
 >> 100% Pure Python 3.13 StdLib | Resident Memory < 16MB
 ─────────────────────────────────────────────────────────────────
EOF
    printf '%s\n' "$banner_reset"
}

show_main_menu() {
    local choice roles_status=0
    show_startup_banner
    load_node_roles || roles_status=$?
    if [[ "$roles_status" == 0 && -z "$NODE_ROLES" && -t 0 ]]; then
        locked_operation select_node_roles
    fi
    while true; do
        if load_node_roles; then
            printf '\nCrowdBastion 防护管理中心 — 节点用途：%s\n' "$(node_role_label)"
            node_recommendation
        else
            log_warn '用途配置不可用，请选择 [7] 重新设置；现有专项操作仍可使用。'
        fi
        printf '1. 安装与接入\n2. 检测规则\n3. IP 封禁与放行\n4. 检查与修复\n5. 控制台与通知\n6. 卸载与清理\n7. 设置节点用途\n8. 按用途检查并选择下一步\n0. 退出\n'
        prompt choice '请选择 [0-8]（Ctrl+D 退出）: ' || return 0
        case "$choice" in
            1) locked_operation manage_installation; continue ;;
            2) locked_operation manage_waf_rules; continue ;;
            3) locked_operation manage_firewall_ops; continue ;;
            4) manage_diagnostics; continue ;;
            5) locked_operation manage_integrations; continue ;;
            6) locked_operation manage_uninstall_center; continue ;;
            7) locked_operation select_node_roles ;;
            8) interactive_health_check ;;
            0) return 0 ;;
            *) log_warn '无效选项，请输入菜单编号。' ;;
        esac
    done
}

show_help() {
    cat <<'EOF'
CrowdBastion — 基于 CrowdSec 的服务器防护与运维管理工具
用法：sudo bash crowdbastion.sh [操作]
兼容入口：install-crowdsec-1panel.sh；已有服务和配置沿用旧版运行标识。
不带参数进入交互菜单。命令行保留交互确认，失败返回非零状态。
主菜单：1 安装与接入；2 检测规则；3 IP 封禁与放行；
        4 检查与修复；5 控制台与通知；6 卸载与清理。
节点用途：7（可组合）；按用途检查与下一步：8 或 4 → 1。
首次终端运行显示用途引导；选择只保存偏好。原命令行操作参数保持兼容。

安装和网站接入：
  --install-core       安装检测服务和防火墙防护
  --install-appsec     配置网站请求检测，接入已有的网站拦截组件
  --install-web-bouncer 为 Docker 或宿主机网站安装拦截组件
  --configure-docker-endpoints  设置容器访问检测服务的私有地址（需事先准备）
  --appsec-status      查看网站请求检测的日志、监听和运行状态
  --verify-appsec      确认后发送测试请求，验证网站请求检测是否生效
  --appsec-policy      设置正文及 AppSec/LAPI 故障策略（核对模块能力）
  --disable-appsec     停用本工具的网站请求检测
  --remove-web-bouncer  移除本工具安装的容器网站拦截组件，保留原有网站防护

中转节点和远端检测中心：
  --install-relay      为纯中转节点安装系统和 SSH 检测、防火墙防护
  --relay-status       检查中转节点的防火墙封禁规则，显示简短结论
  --relay-status-details 显示中转检查的技术详情
  --relay-path         检查连接来源、转发路径和防护位置
  --verify-relay       引导验收中转入口拦截（外部结果人工确认，本机只读）
  --install-relay-bouncer   安装防火墙防护并连接远端检测中心
  --configure-relay-bouncer 修改远端检测中心地址和连接密钥
  --relay-bouncer-status    查看远端检测中心连接和防护状态
  --remove-relay-bouncer    移除远端连接配置并停用防护（保留软件包）

V2bX 落地节点：检查、记录日志和异常告警：
  --diagnose-v2bx      检查 V2bX 配置、日志、连接来源，显示简短结论
  --diagnose-v2bx-details 显示落地检查的技术详情
  --v2bx-log-check     检查本机运行日志，隐去敏感信息并报告核验状态
  --v2bx-observe       保存脱敏日志样本（单次采集，不安装常驻服务）
  --install-v2bx-observer 开启持续日志记录（需私有 JSON 配置文件）
  --v2bx-observer-status 查看持续日志记录的服务和采集状态
  --disable-v2bx-observer 停止持续日志记录，保留配置和已有数据
  --enable-v2bx-alerts   开启异常告警（需持续日志记录正常，不自动封禁）
  --v2bx-alerts-status   查看异常告警接入、决策隔离和发布状态
  --disable-v2bx-alerts  停用异常告警，保留已有记录

访客真实 IP 和管理员放行：
  --diagnose-real-ip   上游不确定时只读检查配置、挂载日志及外部请求核对指引
  --repair-real-ip     按可信 CDN/代理和 Header 修复 Docker Nginx/OpenResty/NPM 真实 IP
  --verify-real-ip     关联正常页面请求、访问日志和 Web Bouncer 实际使用的 IP
  --restore-real-ip    撤销本工具的真实 IP 配置并恢复原内容
  --diagnose-host-real-ip  只读诊断宿主机代理信任与日志
  --repair-host-real-ip    修复宿主机 Nginx/OpenResty 真实 IP（需已加载标准 HTTP conf.d）
  --verify-host-real-ip    核验宿主机正常请求的日志与官方 Web Bouncer IP
  --restore-host-real-ip   撤销本工具的宿主机真实 IP 配置
  --admin-allowlist    管理管理员 IP 放行名单（同时跳过网站请求检测）
  --self-report-status 排查服务器自身 IP 被封禁的问题

检测规则、运行检查和修复：
  --install-waf        安装 Web 日志检测规则（不等同于 AppSec）
  --update-hub         更新检测规则（更新失败时恢复备份）
  --enable-cron        每天 03:30 自动更新检测规则
  --reset-baseline     补齐基础检测规则，保留自定义规则和网站请求检测
  --reset-56           兼容旧名称，功能同 --reset-baseline，不保证场景数量
  --uninstall-waf      确认后移除已知的网站和防火墙日志规则
  --status             按已保存用途只读检查，显示简短结论与一个下一步
  --status-details     显示整体检查结论与完整技术详情
  --check-logs         只读检查新增日志、漏采和重复采集
  --repair-logs        按实际网站配置补齐漏采的访问日志
  --repair-bouncer     修复防火墙与检测服务的连接地址
  --optimize           检查基础配置，选择需要修复的项目并确认后应用
  --enable-wal         改善数据库写入（需确认数据库使用本地磁盘）

管理面板和通知：
  --install-webui      安装或更新网页管理面板
  --reset-webui-credentials 检查或更换管理面板登录凭据
  --clean-redundant    查看节点，选择不再使用的节点并注销（不自动批量删除）
  --telegram           Telegram 管理菜单
  --telegram-test      发送官方插件测试消息并核对 Telegram API 回执
  --telegram-smart     启用/更新分级降噪通知（需先配置 TG）
  --telegram-smart-status  查看分级通知队列与健康检查状态
  --telegram-smart-disable 恢复启用分级前的通知模式
  --custom-bot         可选交互机器人管理（官方通知保持独立）

卸载、清理和帮助：
  --check-clean        只读残留检查
  --deep-clean/--purge 确认后卸载并清理数据
  --uninstall          确认后卸载并清理数据
  --help/-h            帮助（不需要 root）
EOF
}

main_operation() {
    if [[ $# -gt 1 ]]; then log_err '每次只能指定一个操作。'; return 1; fi
    case "${1:-}" in --help|-h) show_help; return 0 ;; esac
    check_root || return 1
    detect_os
    case "${1:-}" in
        '') show_main_menu ;;
        --install-core) install_crowdsec_core ;;
        --install-relay) install_crowdsec_core relay ;;
        --install-relay-bouncer) remote_bouncer_change install ;;
        --configure-relay-bouncer) remote_bouncer_change configure ;;
        --relay-bouncer-status) remote_bouncer_status ;;
        --remove-relay-bouncer) remote_bouncer_change remove ;;
        --relay-status) check_relay_status ;;
        --relay-status-details) check_relay_status details ;;
        --relay-path) check_relay_path ;;
        --verify-relay) verify_relay ;;
        --diagnose-v2bx) diagnose_v2bx ;;
        --diagnose-v2bx-details) diagnose_v2bx details ;;
        --v2bx-log-check) check_v2bx_logs ;;
        --v2bx-observe) observe_v2bx_logs ;;
        --install-v2bx-observer) v2bx_observer_service install ;;
        --v2bx-observer-status) v2bx_observer_service status ;;
        --disable-v2bx-observer) v2bx_observer_service disable ;;
        --enable-v2bx-alerts) v2bx_alert_service enable ;;
        --v2bx-alerts-status) v2bx_alert_service status ;;
        --disable-v2bx-alerts) v2bx_alert_service disable ;;
        --install-webui) deploy_web_ui ;;
        --reset-webui-credentials) reset_webui_credentials ;;
        --install-waf) install_web_rules ;;
        --install-appsec) setup_appsec ;;
        --install-web-bouncer) install_web_bouncer ;;
        --remove-web-bouncer) remove_docker_web_bouncer ;;
        --appsec-status) check_appsec_status ;;
        --verify-appsec) verify_appsec ;;
        --verify-real-ip) verify_real_ip_request ;;
        --appsec-policy) configure_appsec_policy ;;
        --disable-appsec) disable_appsec ;;
        --clean-redundant) check_and_clean_redundant_instances ;;
        --repair-bouncer) repair_firewall_bouncer ;;
        --admin-allowlist) manage_admin_allowlist ;;
        --self-report-status) diagnose_self_report ;;
        --repair-logs) repair_log_acquis ;;
        --repair-real-ip) repair_cloudflare_real_ip ;;
        --diagnose-real-ip) repair_cloudflare_real_ip diagnose ;;
        --restore-real-ip) repair_cloudflare_real_ip remove ;;
        --repair-host-real-ip) repair_cloudflare_real_ip apply host ;;
        --diagnose-host-real-ip) repair_cloudflare_real_ip diagnose host ;;
        --verify-host-real-ip) verify_real_ip_request host ;;
        --restore-host-real-ip) repair_cloudflare_real_ip remove host ;;
        --configure-docker-endpoints) configure_docker_endpoints ;;
        --reset-baseline|--reset-56) reset_waf_to_core_baseline ;;
        --uninstall-waf) uninstall_all_waf_extensions ;;
        --check-clean) audit_crowdsec_residuals ;;
        --deep-clean|--purge|--uninstall) deep_purge_residuals ;;
        --enable-cron) enable_auto_update ;;
        --update-hub) update_hub_logged ;;
        --check-logs) check_log_inventory ;;
        --telegram) manage_telegram ;;
        --telegram-test) test_telegram_notification ;;
        --telegram-smart) enable_smart_notifications ;;
        --telegram-smart-status) notify_tool status "$CS_DIR" ;;
        --telegram-smart-disable) disable_smart_notifications ;;
        --custom-bot) manage_custom_bot ;;
        --optimize) smart_audit_and_optimize ;;
        --enable-wal) enable_sqlite_wal ;;
        --status) check_health_status ;;
        --status-details) check_health_status details ;;
        *) log_err "未知参数: $1"; show_help; return 1 ;;
    esac
}

main() {
    if [[ $# -gt 1 ]]; then log_err '每次只能指定一个操作。'; return 1; fi
    case "${1:-}" in
        ''|--help|-h|--status|--status-details|--relay-status-details|--diagnose-v2bx-details|--relay-status|--relay-bouncer-status|--relay-path|--verify-relay|--diagnose-v2bx|--v2bx-log-check|--v2bx-observe|--v2bx-observer-status|--v2bx-alerts-status|--appsec-status|--check-logs|--diagnose-real-ip|--diagnose-host-real-ip|--check-clean|--update-hub|--telegram-smart-status) main_operation "$@" ;;
        *) locked_operation main_operation "$@" ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

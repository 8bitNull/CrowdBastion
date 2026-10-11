#!/usr/bin/env bash
# CrowdSec 管理中心：日志检测、Firewall Bouncer、可选 AppSec 与 WebUI。
# 配置修改使用同目录 lib/crowdsec_config.py；完整说明见 readme.md。
set -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CONFIG_HELPER="${SCRIPT_DIR}/lib/crowdsec_config.py"
CS_DIR="/etc/crowdsec"
WEBUI_DIR="/opt/crowdsec-web-ui"
CRON_FILE="/etc/cron.d/crowdsec-autoupdate"
HUB_RUNNER_DIR="/opt/crowdsec-1key-maintenance"
HUB_LOCK_FILE="/run/lock/crowdsec-1key-hub.lock"
HUB_LOG_FILE="/var/log/crowdsec-1key-hub.log"
# shellcheck source=lib/hub_maintenance.sh
source "${SCRIPT_DIR}/lib/hub_maintenance.sh"
TG_NOTIF_FILE="${CS_DIR}/notifications/crowdsec-1key-telegram.yaml"
PROFILES_FILE="${CS_DIR}/profiles.yaml"
APPSEC_FILE="${CS_DIR}/acquis.d/crowdsec-1key-appsec.yaml"
APPSEC_LINKS="${CS_DIR}/crowdsec-1key-appsec-links.yaml"
APPSEC_DOCKER_LINKS="${CS_DIR}/crowdsec-1key-appsec-docker-links.yaml"
WEB_INSTALLS="${CS_DIR}/crowdsec-1key-web-installs.json"
REALIP_STATE="${CS_DIR}/crowdsec-1key-real-ip.json"
# shellcheck source=lib/native_web_bouncer.sh
source "${SCRIPT_DIR}/lib/native_web_bouncer.sh"
# shellcheck source=lib/host_web_bouncer.sh
source "${SCRIPT_DIR}/lib/host_web_bouncer.sh"
# shellcheck source=lib/real_ip.sh
source "${SCRIPT_DIR}/lib/real_ip.sh"
# shellcheck source=lib/appsec_audit.sh
source "${SCRIPT_DIR}/lib/appsec_audit.sh"
LOG_REPAIR_FILE="${CS_DIR}/acquis.d/crowdsec-1key-log-repair.yaml"
LOG_REPAIR_STAGE=''
LOG_REPAIR_COUNT=0
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
        log_err '该操作需要 root 权限，请使用 sudo bash install-crowdsec-1panel.sh。'
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
        log_err '请先通过菜单 [1] 安装 CrowdSec 核心。'
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
        if [[ -e "$path" ]]; then
            cp -a -- "$path" "${backup}/${i}" || return 1
        else
            touch "${backup}/${i}.absent" || return 1
        fi
        ((i+=1))
    done
    log_info "修改前备份: ${backup}"
}

restore_config_change() {
    local i
    for i in "${!BACKUP_PATHS[@]}"; do
        if [[ -f "${BACKUP_COPIES[$i]}.absent" ]]; then
            rm -f -- "${BACKUP_PATHS[$i]}"
        else
            cp -a -- "${BACKUP_COPIES[$i]}" "${BACKUP_PATHS[$i]}" || return 1
        fi
    done
    log_warn '已恢复本次修改前的配置。'
}

apply_core_config() {
    local operation="${1:-restart}"
    if ! crowdsec -t; then
        log_err 'CrowdSec 配置校验失败，未重启服务。'
        restore_config_change
        return 1
    fi
    if ! systemctl "$operation" crowdsec || ! systemctl is-active --quiet crowdsec; then
        log_err 'CrowdSec 服务未正常启动，正在回滚配置。'
        restore_config_change
        systemctl restart crowdsec || true
        return 1
    fi
}

install_packages() {
    case "${OS_ID}" in
        debian|ubuntu) apt-get install -y "$@" ;;
        centos|rhel|almalinux|rocky|fedora)
            if command -v dnf >/dev/null 2>&1; then dnf install -y "$@"; else yum install -y "$@"; fi ;;
        *) log_err "未支持的系统: ${OS_ID}"; return 1 ;;
    esac
}

install_bouncer_package() {
    if command -v nft >/dev/null 2>&1 || modprobe nf_tables 2>/dev/null; then
        install_packages nftables crowdsec-firewall-bouncer-nftables
    else
        install_packages iptables ipset crowdsec-firewall-bouncer-iptables
    fi
}

detect_admin_ip() {
    CURRENT_IP=''
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        CURRENT_IP="${SSH_CLIENT%% *}"
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        CURRENT_IP="${SSH_CONNECTION%% *}"
    fi
}

install_crowdsec_core() {
    case "${OS_ID}" in
        debian|ubuntu|centos|rhel|almalinux|rocky|fedora) ;;
        *) log_err "当前系统不在安装支持范围: ${OS_ID}"; return 1 ;;
    esac
    require_commands systemctl || return 1
    detect_admin_ip
    if [[ -z "$CURRENT_IP" ]]; then
        prompt CURRENT_IP '管理员公网 IP（留空仅放行内网；Ctrl+D 取消）: ' || return 1
    fi
    [[ "$OS_ID" =~ ^(debian|ubuntu)$ ]] && { apt-get update || return 1; }
    case "$OS_ID" in
        debian|ubuntu) install_packages curl ca-certificates python3 python3-yaml || return 1 ;;
        *) install_packages curl ca-certificates python3 python3-pyyaml || return 1 ;;
    esac
    require_yaml || return 1
    if [[ -n "$CURRENT_IP" ]] && ! yaml_tool ip "$CURRENT_IP"; then
        log_err '管理员 IP 无效，尚未安装 CrowdSec。'
        return 1
    fi
    local installer
    installer=$(mktemp) || return 1
    if ! curl -fLsS --connect-timeout 10 --max-time 120 https://install.crowdsec.net -o "$installer" || ! bash "$installer"; then
        rm -f "$installer"
        log_err '官方软件源配置失败。'
        return 1
    fi
    rm -f "$installer"
    install_packages crowdsec || return 1
    install_bouncer_package || return 1
    require_core || return 1
    prepare_log_repair || return 1
    begin_config_change "${CS_DIR}/parsers/s02-enrich/99-admin-whitelist.yaml" "$LOG_REPAIR_FILE" "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || { cleanup_log_repair; return 1; }
    yaml_tool whitelist "${CS_DIR}/parsers/s02-enrich/99-admin-whitelist.yaml" "$CURRENT_IP" || { restore_config_change; cleanup_log_repair; return 1; }
    apply_staged_log_repair || { restore_config_change; cleanup_log_repair; return 1; }
    cleanup_log_repair
    install_collections crowdsecurity/linux crowdsecurity/sshd crowdsecurity/nginx crowdsecurity/nginx-proxy-manager crowdsecurity/http-cve crowdsecurity/base-http-scenarios crowdsecurity/whitelist-good-actors || { restore_config_change; return 1; }
    enable_prometheus_metrics || { restore_config_change; return 1; }
    systemctl enable crowdsec || return 1
    apply_core_config || return 1
    systemctl enable --now crowdsec-firewall-bouncer || return 1
    if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
        log_err 'Firewall Bouncer 未运行，请查看 journalctl -u crowdsec-firewall-bouncer。'
        return 1
    fi
    log_succ 'CrowdSec 和 Firewall Bouncer 服务已启动。'
    log_info '请用菜单 [9] 检查日志采集和 Bouncer 注册；Docker 转发流量需要对应防火墙链。'
    pause
}

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
}

prepare_log_repair() {
    LOG_REPAIR_FILE=$(yaml_tool log-repair-file "$CS_DIR") || return 1
    LOG_REPAIR_STAGE=$(mktemp -d) || return 1
    LOG_REPAIR_COUNT=0
    local containers id image kind mounts
    configure_log_acquis "${LOG_REPAIR_STAGE}/presets.yaml" >/dev/null || { cleanup_log_repair; return 1; }
    : > "${LOG_REPAIR_STAGE}/mounts.tsv"
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
            done <<< "$containers"
        else
            log_warn 'Docker 不可用，仅检查预设日志目录。'
        fi
    fi
    if ! LOG_REPAIR_COUNT=$(yaml_tool repair-log-acquis "$CS_DIR" "${LOG_REPAIR_STAGE}/presets.yaml" "${LOG_REPAIR_STAGE}/mounts.tsv" "${LOG_REPAIR_STAGE}/repaired.yaml"); then
        cleanup_log_repair
        return 1
    fi
    log_info "日志路径检查完成，待补齐 ${LOG_REPAIR_COUNT} 个文件。"
}

apply_staged_log_repair() {
    [[ "$LOG_REPAIR_COUNT" == 0 ]] && return 0
    if [[ -L "$LOG_REPAIR_FILE" ]]; then log_err '修复采集文件是符号链接，未写入。'; return 1; fi
    mkdir -p "$(dirname "$LOG_REPAIR_FILE")" && cp -- "${LOG_REPAIR_STAGE}/repaired.yaml" "$LOG_REPAIR_FILE"
}

repair_log_acquis() {
    require_core && require_yaml || return 1
    prepare_log_repair || return 1
    if [[ "$LOG_REPAIR_COUNT" == 0 ]]; then
        log_info '未发现需要补齐的现有 HTTP 日志；请结合新请求与 cscli metrics 核验。'
        cleanup_log_repair
        return 0
    fi
    if ! confirm '补齐上述日志采集并校验、重启 CrowdSec？'; then cleanup_log_repair; return 0; fi
    begin_config_change "$LOG_REPAIR_FILE" || { cleanup_log_repair; return 1; }
    if ! apply_staged_log_repair || ! apply_core_config; then
        restore_config_change
        cleanup_log_repair
        return 1
    fi
    log_succ "已补齐 ${LOG_REPAIR_COUNT} 个日志文件。现有采集配置保留；请访问网站后查看 cscli metrics。"
    cleanup_log_repair
}

enable_prometheus_metrics() {
    yaml_tool metrics "${CS_DIR}/config.yaml"
}

install_collections() (
    require_core && require_commands flock || return 1
    mkdir -p -- "$(dirname "$HUB_LOCK_FILE")" || return 1
    exec 9>"$HUB_LOCK_FILE" || return 1
    flock -n 9 || { log_err '已有 Hub 维护任务运行，集合安装未执行。'; return 1; }
    cscli hub update || return 1
    cscli collections install "$@"
)

install_web_rules() {
    install_collections crowdsecurity/nginx crowdsecurity/nginx-proxy-manager crowdsecurity/http-cve crowdsecurity/base-http-scenarios crowdsecurity/whitelist-good-actors || return 1
    crowdsec -t && systemctl reload crowdsec || return 1
    log_succ 'Web 日志检测规则已安装并加载。在线请求检查需另外配置 AppSec。'
}

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
    local target host active=''
    prompt target '需注销的 Machine 名称（留空取消）: ' || return 0
    [[ -z "$target" ]] && return 0
    host=$(yaml_tool get "${CS_DIR}/local_api_credentials.yaml" login) || return 1
    if [[ -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]]; then
        active=$(yaml_tool get "${WEBUI_DIR}/data/webui_api_credentials.yaml" login) || return 1
    fi
    if [[ "$target" == "$host" || "$target" == "$active" ]]; then
        log_err '不能注销宿主机或当前 WebUI 的 Machine。'
        return 1
    fi
    confirm "确认注销 Machine ${target}？" || return 0
    cscli machines delete "$target" || return 1
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

webui_http_ready() {
    local port="$1" code
    code=$(curl -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/api/health") || return 1
    [[ "$code" == 200 ]]
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
    restore_config_change || return 1
    if [[ "$previous" == true && -f "${WEBUI_DIR}/docker-compose.yml" ]]; then
        if ! webui_compose_up "$previous_image"; then log_err '旧 WebUI 容器自动恢复失败，请使用备份配置手动恢复。'; fi
    elif [[ "$created" == true ]]; then
        docker rm -f crowdsec-web-ui >/dev/null 2>&1 || true
    fi
    if [[ "$created" == true ]]; then cscli machines delete "$machine" || log_warn '新建 Machine 注销失败，请手动核验。'; fi
    systemctl restart crowdsec || true
}

deploy_web_ui() {
    require_core && require_yaml && require_commands docker curl || return 1
    if ! systemctl is-active --quiet crowdsec || ! cscli lapi status; then log_err 'CrowdSec/LAPI 尚未就绪。'; return 1; fi
    local port=3000 url machine password host created=false creds compose previous=false previous_image='' old_machine='' image='' rotation="${1:-}"
    prompt port 'WebUI 端口 [3000]: ' || return 1
    port="${port:-3000}"
    valid_port "$port" || { log_err '端口必须在 1–65535 之间。'; return 1; }
    if ss -H -ltn "sport = :${port}" 2>/dev/null | grep -q .; then
        webui_owned || { log_err '端口被占用，请更换端口。'; return 1; }
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
    image=$(docker image inspect --format '{{.Id}}' "$WEBUI_IMAGE") || return 1
    [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || { log_err '无法确认已拉取镜像的不可变身份，未更新部署。'; return 1; }
    url=$(yaml_tool get "${CS_DIR}/local_api_credentials.yaml" url) || return 1
    host=$(yaml_tool get "${CS_DIR}/local_api_credentials.yaml" login) || return 1
    creds="${WEBUI_DIR}/data/webui_api_credentials.yaml"
    compose="${WEBUI_DIR}/docker-compose.yml"
    mkdir -p "${WEBUI_DIR}/data" || return 1
    chmod 700 "$WEBUI_DIR" "${WEBUI_DIR}/data" || return 1
    [[ -f "$compose" ]] && previous=true
    begin_config_change "$creds" "$compose" "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || return 1
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
        password=$(yaml_tool get "$creds" password) || { cscli machines delete "$machine"; restore_config_change; return 1; }
    fi
    chmod 600 "$creds" || return 1
    if ! enable_prometheus_metrics || ! yaml_tool compose "$compose" "$WEBUI_DIR" "$url" "$machine" "$password" "$port" "$image" || ! apply_core_config; then
        [[ "$created" == true ]] && cscli machines delete "$machine"
        restore_config_change
        return 1
    fi
    local result=0
    webui_compose_up || result=1
    if [[ "$result" -ne 0 ]]; then
        rollback_webui "$created" "$machine" "$previous" "$previous_image"
        log_err 'WebUI 部署失败，已尝试恢复配置和旧容器，请核验其状态。'
        return 1
    fi
    local running=false attempt=0
    while ((attempt < 10)); do
        ((attempt+=1))
        running=$(docker inspect --format '{{.State.Running}}' crowdsec-web-ui 2>/dev/null) || running=false
        [[ "$running" == true ]] && webui_http_ready "$port" && break
        running=false
        sleep 1
    done
    if [[ "$running" != true ]]; then
        rollback_webui "$created" "$machine" "$previous" "$previous_image"
        log_err 'WebUI 容器或 HTTP 应用未就绪，请查看 docker logs crowdsec-web-ui。'
        return 1
    fi
    if ! webui_lapi_status; then
        rollback_webui "$created" "$machine" "$previous" "$previous_image"
        log_err 'WebUI 新配置的独立凭据无法登录 LAPI，已尝试恢复旧部署。'
        return 1
    fi
    touch "${WEBUI_DIR}/.crowdsec-1key-managed" || return 1
    if [[ "$rotation" == rotate && -n "$old_machine" && "$old_machine" != "$machine" ]]; then
        cscli machines delete "$old_machine" || log_warn "新 WebUI 已运行，但旧 Machine ${old_machine} 注销失败，请人工核验。"
    fi
    log_succ "WebUI HTTP 应用与独立 LAPI 凭据已就绪，访问 http://服务器地址:${port}。"
    log_warn '已显式启用认证；首次访问请创建管理员账号，并通过 HTTPS 反向代理限制访问。'
}

uninstall_web_ui() {
    confirm '删除本工具 WebUI 容器、持久化目录及其独立 Machine？' || return 0
    webui_owned || { log_err '未找到本工具管理的 WebUI。'; return 1; }
    local machine='' host=''
    if [[ -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]]; then
        machine=$(yaml_tool get "${WEBUI_DIR}/data/webui_api_credentials.yaml" login) || return 1
        host=$(yaml_tool get "${CS_DIR}/local_api_credentials.yaml" login) || return 1
        [[ "$machine" != "$host" ]] || { log_err '检测到宿主机凭据，已停止卸载。'; return 1; }
    fi
    if command -v docker >/dev/null 2>&1 && docker container inspect crowdsec-web-ui >/dev/null 2>&1; then
        docker rm -f crowdsec-web-ui || return 1
    fi
    if [[ -n "$machine" ]]; then cscli machines delete "$machine" || return 1; fi
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
        printf '\nWebUI 管理\n1. 部署/更新（复用凭据）\n2. 卸载本工具 WebUI\n3. 查看容器日志\n4. 检查/轮换独立凭据\n5. 查看节点并选择注销\n0. 返回\n'
        prompt choice '请选择 [0-5]: ' || return 0
        case "$choice" in
            1) deploy_web_ui ;;
            2) uninstall_web_ui ;;
            3) require_commands docker && docker logs --tail 100 crowdsec-web-ui ;;
            4) reset_webui_credentials ;;
            5) check_and_clean_redundant_instances ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
        pause
    done
}

reset_waf_to_core_baseline() {
    log_info '补齐基础日志检测集合，保留自定义规则和已配置的 AppSec；Hub 场景数量随版本变化。'
    install_collections crowdsecurity/linux crowdsecurity/sshd crowdsecurity/nginx crowdsecurity/base-http-scenarios crowdsecurity/http-cve crowdsecurity/whitelist-good-actors || return 1
    crowdsec -t && systemctl reload crowdsec || return 1
    log_succ '基础集合已补齐。'
}

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
    hub_maintenance remove "$target" || return 1
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
    if ((${#removals[@]})); then hub_maintenance remove "${removals[@]}" || return 1; fi
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
    local containers id image name network effective hooks mounts
    containers=$(appsec_containers) || return 1
    while read -r id image name; do
        [[ -z "$id" ]] && continue
        log_info "Web 容器：${name}（${id}，${image}）"
        network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$id") || return 1
        if [[ "$network" == host ]]; then
            log_info 'host 网络：容器可通过 127.0.0.1:7422 连接宿主机 AppSec。'
        else
            log_warn "${network} 网络：容器内 loopback 不指向宿主机，请配置私有网络可达的 AppSec 地址。"
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
}

link_docker_appsec() {
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
    [[ "$network" == host ]] || { log_err '自动接入仅支持 host 网络；其他网络需先按官方文档配置私有网络地址。'; return 1; }
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
    if [[ -f "$APPSEC_LINKS" ]] && yaml_tool link-owned "$file" "$APPSEC_LINKS" >/dev/null 2>&1; then
        log_err '该配置已有宿主机接入记录，请先停用原接入。'
        return 1
    fi
    appsec_guard_config "$file" "$selected" "$target" || return 1
    confirm "将容器 ${name} 的已有 Web Bouncer 接入 AppSec，并校验、重载？" || return 0
    stage=$(mktemp) || return 1
    if ! yaml_tool stage-web-bouncer "$file" 'http://127.0.0.1:7422' "$stage"; then rm -f -- "$stage"; return 1; fi
    begin_config_change "$file" "$APPSEC_DOCKER_LINKS" || { rm -f -- "$stage"; return 1; }
    if ! yaml_tool link-docker-bouncer "$file" "$APPSEC_DOCKER_LINKS" "$selected" "$target" "$name" || ! cp -- "$stage" "$file" || ! docker exec "$selected" nginx -t || ! docker exec "$selected" nginx -s reload; then
        restore_config_change
        if ! docker exec "$selected" nginx -t || ! docker exec "$selected" nginx -s reload; then
            log_warn '恢复配置后容器重载失败，请检查容器运行状态。'
        fi
        rm -f -- "$stage"
        return 1
    fi
    rm -f -- "$stage"
    log_succ '容器内已有 Web Bouncer 的 AppSec 地址已配置并重载；请验证实际网站请求和指标。'
}

setup_appsec() {
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
    install_collections crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules || return 1
    begin_config_change "$APPSEC_FILE" || return 1
    mkdir -p "$(dirname "$APPSEC_FILE")" || return 1
    if ! yaml_tool appsec "$APPSEC_FILE"; then restore_config_change; return 1; fi
    apply_core_config || return 1
    local attempt
    for attempt in {1..10}; do
        appsec_default_listener_ready && break
        sleep 1
    done
    if ! appsec_default_listener_ready; then
        log_err 'AppSec 配置已写入，但 127.0.0.1:7422 未监听；请检查 journalctl -u crowdsec 和 /var/log/crowdsec.log。网站尚未接入。'
        return 1
    fi
    log_info 'AppSec 配置已校验，127.0.0.1:7422 存在监听；网站接入仍需 Web Bouncer。'
    local choice file service
    diagnose_appsec_containers || return 1
    [[ -f "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" ]] && command -v nginx >/dev/null 2>&1 && printf '1. 接入已有宿主机 Nginx Bouncer\n'
    [[ -f "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf" ]] && command -v openresty >/dev/null 2>&1 && printf '2. 接入已有宿主机 OpenResty Bouncer\n'
    printf '3. 接入已有 Docker Web Bouncer（host 网络、持久化配置）\n4. 首次安装 Web Bouncer（Docker/宿主机）\n0. 仅配置引擎，稍后接入网站\n'
    prompt choice '请选择可用接入项（0 结束）: ' || return 0
    case "$choice" in
        1) file="${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf"; service=nginx ;;
        2) file="${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; service=openresty ;;
        3) link_docker_appsec; return $? ;;
        4) install_web_bouncer; return $? ;;
        0|'')
            log_warn '仅完成引擎配置；网站请求尚未验证，AppSec 计数可为零。'
            return 0 ;;
        *) log_err '无效选项，引擎已配置但 Web Bouncer 未接入。'; return 1 ;;
    esac
    [[ -f "$file" ]] || { log_err "未安装对应 Web Bouncer: ${file}；引擎已配置，网站尚未接入。"; return 1; }
    if [[ -f "$APPSEC_DOCKER_LINKS" ]] && yaml_tool docker-link-owned "$file" "$APPSEC_DOCKER_LINKS" >/dev/null 2>&1; then
        log_err '该配置已有容器接入记录，请先停用原接入。'
        return 1
    fi
    appsec_guard_config "$file" || return 1
    require_commands "$service" || return 1
    begin_config_change "$file" "$APPSEC_LINKS" || return 1
    yaml_tool link-web-bouncer "$file" "$APPSEC_LINKS" || { restore_config_change; return 1; }
    if ! "$service" -t || ! systemctl reload "$service"; then
        restore_config_change
        systemctl reload "$service" || true
        log_err 'Web 服务器配置失败，已恢复 Bouncer 配置。'
        return 1
    fi
    log_succ 'Web Bouncer 已配置 APPSEC_URL；请运行 AppSec 验证确认请求被处理。'
}

check_appsec_status() {
    require_core && require_yaml && require_commands ss || return 1
    local addresses address result=0
    addresses=$(yaml_tool appsec-listeners "$CS_DIR") || return 1
    if [[ -z "$addresses" ]]; then
        log_err '没有启用的 AppSec 数据源；请先运行 --install-appsec。'
        result=1
    else
        while read -r address; do
            if ss -H -lnt | awk -v address="$address" '$4 == address {found=1} END {exit !found}'; then
                log_info "AppSec 配置地址存在监听：${address}。"
            else
                log_warn "AppSec 配置地址未监听：${address}。"
                result=1
            fi
        done <<< "$addresses"
    fi
    diagnose_appsec_containers || result=1
    cscli appsec-configs list && cscli metrics show appsec || return 1
    local file
    for file in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        [[ ! -f "$file" ]] || appsec_audit_tool show "$file" || result=1
    done
    log_info '确认 Processed/Blocked 随测试请求变化，不能仅凭 HTTP 403 判断 WAF 生效。'
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
    restore_config_change || return 1
    local target mode=host
    for target in "$@"; do
        if [[ "$target" == -- ]]; then
            mode=docker
        elif [[ "$mode" == host ]]; then
            systemctl reload "$target" || log_warn "恢复配置后 ${target} 重载失败。"
        elif ! docker exec "$target" nginx -t || ! docker exec "$target" nginx -s reload; then
            log_warn "恢复配置后容器 ${target} 重载失败。"
        fi
    done
}

disable_appsec() {
    require_core && require_yaml || return 1
    APPSEC_FILE=$(yaml_tool appsec-file "$CS_DIR") || return 1
    if [[ ! -f "$APPSEC_FILE" ]]; then log_info '本工具未配置 AppSec，外部接入保留。'; return 0; fi
    confirm '停用本工具配置的 AppSec？外部数据源和规则集合保留。' || return 0
    local files=("$APPSEC_FILE" "$APPSEC_LINKS") file service
    local reloaded=()
    local docker_links='' container target resolved mounts running stage
    local docker_reloaded=()
    if [[ -f "$APPSEC_DOCKER_LINKS" ]]; then
        require_commands docker || return 1
        docker_links=$(yaml_tool docker-appsec-links "$APPSEC_DOCKER_LINKS") || return 1
        while IFS=$'\t' read -r container file target; do
            [[ -z "$container" ]] && continue
            running=$(docker inspect --format '{{.State.Running}}' "$container") || return 1
            [[ "$running" == true ]] || { log_err '管理的 Web 容器未运行；请先恢复容器再停用接入。'; return 1; }
            running=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container") || return 1
            [[ "$running" == host ]] || { log_err '管理的 Web 容器网络已变化，未停用引擎。'; return 1; }
            mounts=$(docker inspect --format '{{json .Mounts}}' "$container") || return 1
            resolved=$(printf '%s' "$mounts" | yaml_tool docker-bouncer-path "$target") || return 1
            [[ "$resolved" == "$file" ]] || { log_err '容器配置挂载已变化，请先核对接入；未停用引擎。'; return 1; }
            appsec_guard_config "$file" "$container" "$target" || return 1
            yaml_tool docker-link-current "$file" || return 1
            files+=("$file")
        done <<< "$docker_links"
        files+=("$APPSEC_DOCKER_LINKS")
    fi
    for file in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        if [[ -f "$file" && -f "$APPSEC_LINKS" ]] && yaml_tool link-owned "$file" "$APPSEC_LINKS" >/dev/null 2>&1; then appsec_guard_config "$file" || return 1; files+=("$file"); fi
    done
    begin_config_change "${files[@]}" || return 1
    for file in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        if [[ ! -f "$file" || ! -f "$APPSEC_LINKS" ]] || ! yaml_tool link-owned "$file" "$APPSEC_LINKS" >/dev/null 2>&1; then continue; fi
        if grep -Fxq 'APPSEC_URL=http://127.0.0.1:7422' "$file"; then
            yaml_tool unlink-web-bouncer "$file" "$APPSEC_LINKS" || { rollback_appsec_runtime "${reloaded[@]}" -- "${docker_reloaded[@]}"; return 1; }
            service=nginx
            [[ "$file" == *openresty* ]] && service=openresty
            if ! "$service" -t || ! systemctl reload "$service"; then
                rollback_appsec_runtime "${reloaded[@]}" "$service" -- "${docker_reloaded[@]}"
                return 1
            fi
            reloaded+=("$service")
        fi
    done
    while IFS=$'\t' read -r container file target; do
        [[ -z "$container" ]] && continue
        stage=$(mktemp) || { rollback_appsec_runtime "${reloaded[@]}" -- "${docker_reloaded[@]}"; return 1; }
        if ! yaml_tool restore-docker-bouncer "$file" "$APPSEC_DOCKER_LINKS" "$stage" || ! cp -- "$stage" "$file" || ! docker exec "$container" nginx -t || ! docker exec "$container" nginx -s reload; then
            rollback_appsec_runtime "${reloaded[@]}" -- "${docker_reloaded[@]}" "$container"
            rm -f -- "$stage"
            return 1
        fi
        rm -f -- "$stage"
        docker_reloaded+=("$container")
    done <<< "$docker_links"
    if [[ -f "$APPSEC_DOCKER_LINKS" ]]; then rm -f -- "$APPSEC_DOCKER_LINKS" || { rollback_appsec_runtime "${reloaded[@]}" -- "${docker_reloaded[@]}"; return 1; }; fi
    rm -f "$APPSEC_FILE" || { rollback_appsec_runtime "${reloaded[@]}" -- "${docker_reloaded[@]}"; return 1; }
    if ! apply_core_config; then
        rollback_appsec_runtime "${reloaded[@]}" -- "${docker_reloaded[@]}"
        return 1
    fi
    log_succ '本工具 AppSec 数据源及记录过的 Web Bouncer 地址已恢复；未管理的容器或外部代理请同步停用请求转发。'
}

manage_waf_rules() {
    require_core || return 1
    local choice
    while true; do
        printf '\n日志检测规则与 AppSec WAF\n1. Web 日志检测规则\n2. WordPress 日志规则\n3. iptables 日志规则（需要相应采集）\n4. 已安装集合\n5. 更新 Hub 规则\n6. 补齐基础集合（保留自定义/AppSec）\n7. 指定卸载集合\n8. 移除已知 Web 日志扩展\n9. 配置 AppSec 与 Web Bouncer\n10. AppSec 状态\n11. 验证网站 AppSec\n12. 停用本工具 AppSec\n13. 撤销本工具原生容器 Web Bouncer\n14. 按可信 CDN/代理修复 Docker 真实 IP\n15. 撤销本工具真实 IP 配置\n16. 只读上游链路与真实 IP 诊断\n17. 检查/设置 AppSec 正文与故障策略\n0. 返回\n'
        prompt choice '请选择 [0-17]: ' || return 0
        case "$choice" in
            1) install_web_rules ;;
            2) install_collections crowdsecurity/wordpress && crowdsec -t && systemctl reload crowdsec ;;
            3) install_collections crowdsecurity/iptables && crowdsec -t && systemctl reload crowdsec ;;
            4) cscli collections list ;;
            5) hub_maintenance update ;;
            6) reset_waf_to_core_baseline ;;
            7) uninstall_specific_waf_collection ;;
            8) uninstall_all_waf_extensions ;;
            9) setup_appsec ;;
            10) check_appsec_status ;;
            11) verify_appsec ;;
            12) disable_appsec ;;
            13) remove_docker_web_bouncer ;;
            14) repair_cloudflare_real_ip ;;
            15) repair_cloudflare_real_ip remove ;;
            16) repair_cloudflare_real_ip diagnose ;;
            17) configure_appsec_policy ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
        pause
    done
}

enable_auto_update() {
    require_core && require_yaml || return 1
    local minute="${1:-30}" hour="${2:-3}"
    if [[ ! "$minute" =~ ^[0-9]{1,2}$ || ! "$hour" =~ ^[0-9]{1,2}$ ]] || ! ((10#$minute <= 59 && 10#$hour <= 23)); then log_err '分钟应为 0–59，小时应为 0–23。'; return 1; fi
    local cron_service
    cron_service=cron
    [[ "$OS_ID" =~ ^(centos|rhel|almalinux|rocky|fedora)$ ]] && cron_service=crond
    systemctl is-active --quiet "$cron_service" || { log_err "${cron_service} 服务未运行，请先启用。"; return 1; }
    mkdir -p "$(dirname "$CRON_FILE")" || return 1
    require_commands flock python3 || return 1
    if [[ -L "$HUB_RUNNER_DIR" || ( -e "$HUB_RUNNER_DIR" && ( ! -d "$HUB_RUNNER_DIR" || ! -f "$HUB_RUNNER_DIR/.crowdsec-1key-owned" || -L "$HUB_RUNNER_DIR/.crowdsec-1key-owned" ) ) ]]; then
        log_err '维护目录已存在但不属于本工具，未覆盖。'; return 1
    fi
    local file
    for file in hub_maintenance.sh crowdsec_hub_snapshot.py crowdsec_safety.py; do
        [[ ! -L "$HUB_RUNNER_DIR/$file" ]] || { log_err "维护文件是 symlink，未覆盖。"; return 1; }
    done
    begin_config_change "$CRON_FILE" "$HUB_RUNNER_DIR/hub_maintenance.sh" "$HUB_RUNNER_DIR/crowdsec_hub_snapshot.py" "$HUB_RUNNER_DIR/crowdsec_safety.py" "$HUB_RUNNER_DIR/.crowdsec-1key-owned" || return 1
    mkdir -p "$HUB_RUNNER_DIR" || return 1
    chmod 700 "$HUB_RUNNER_DIR" || return 1
    for file in hub_maintenance.sh crowdsec_hub_snapshot.py crowdsec_safety.py; do
        cp -- "${SCRIPT_DIR}/lib/$file" "$HUB_RUNNER_DIR/$file" || { restore_config_change; return 1; }
        chmod 700 "$HUB_RUNNER_DIR/$file" || { restore_config_change; return 1; }
    done
    touch "$HUB_RUNNER_DIR/.crowdsec-1key-owned" || { restore_config_change; return 1; }
    printf '# CrowdSec Hub 更新；独立维护程序含互斥、快照、校验、回滚及结果日志。\n%s %s * * * root /bin/bash %s/hub_maintenance.sh update\n' "$((10#$minute))" "$((10#$hour))" "$HUB_RUNNER_DIR" > "$CRON_FILE" || { restore_config_change; return 1; }
    chmod 644 "$CRON_FILE" || { restore_config_change; return 1; }
    log_succ "已设置每天 ${hour}:${minute} 更新 Hub 规则。"
}

manage_auto_update() {
    require_core || return 1
    local choice minute hour
    while true; do
        printf '\nHub 定时更新（服务器时区）\n1. 每天 03:30\n2. 自定义时间\n3. 关闭\n4. 查看任务\n0. 返回\n'
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) enable_auto_update ;;
            2)
                prompt minute '分钟 [30]: ' && prompt hour '小时 [3]: ' || return 0
                enable_auto_update "${minute:-30}" "${hour:-3}" ;;
            3) rm -f "$CRON_FILE" && log_succ '定时更新已关闭。' ;;
            4) if [[ -f "$CRON_FILE" ]]; then cat "$CRON_FILE"; else log_info '尚未启用。'; fi ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
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
        printf '\n管理员中央 AllowList\n1. 查看\n2. 明确添加一个 IP\n3. 明确移除一个 IP\n0. 返回\n'
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
            *) log_warn '无效选项。' ;;
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

repair_firewall_bouncer() {
    require_core && require_yaml && require_commands curl || return 1
    systemctl is-active --quiet crowdsec || { log_err '核心未运行，请先排查核心服务。'; return 1; }
    local cfg="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" key='' url docker_chain=false new_name=''
    [[ -s "$cfg" ]] || { log_err '缺少官方 Bouncer 配置，请先安装对应软件包。'; return 1; }
    url=$(yaml_tool get "${CS_DIR}/local_api_credentials.yaml" url) || return 1
    key=$(yaml_tool bouncer-key "$cfg" 2>/dev/null) || key=''
    if [[ -z "$key" || "$key" == '<API_KEY>' ]]; then
        new_name="crowdsec-1key-firewall-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
        key=$(cscli bouncers add "$new_name" -o raw) || return 1
        [[ "$key" =~ ^[A-Za-z0-9_-]{16,}$ ]] || { log_err '未获取有效 Bouncer 密钥。'; cscli bouncers delete "$new_name"; return 1; }
    fi
    if ! curl -fsS --connect-timeout 3 --max-time 5 -H "X-Api-Key: ${key}" "${url%/}/v1/decisions" >/dev/null; then
        [[ -n "$new_name" ]] && cscli bouncers delete "$new_name"
        log_err 'Bouncer 密钥无法访问 LAPI，请核查 URL 与已注册密钥；不会删除其他 Bouncer。'
        return 1
    fi
    if command -v iptables >/dev/null 2>&1 && iptables -S DOCKER-USER >/dev/null 2>&1; then docker_chain=true; fi
    begin_config_change "$cfg" "${cfg}.local" || return 1
    yaml_tool bouncer "$cfg" "$url" "$key" "$docker_chain" || { restore_config_change; return 1; }
    if ! systemctl restart crowdsec-firewall-bouncer || ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
        restore_config_change
        [[ -n "$new_name" ]] && cscli bouncers delete "$new_name"
        systemctl restart crowdsec-firewall-bouncer || true
        journalctl -u crowdsec-firewall-bouncer -n 30 --no-pager
        return 1
    fi
    log_succ 'Bouncer 服务已运行；现有其他 Bouncer 凭据保留。'
    cscli bouncers list || return 1
    firewall_status
}

manage_firewall_ops() {
    require_core && require_yaml || return 1
    local choice ip duration reason
    while true; do
        printf '\n黑名单与防火墙\n1. 活跃决策\n2. 最新警报\n3. 解封 IP\n4. 封禁 IP\n5. 查看防火墙规则\n6. 解析指标\n7. 修复 Bouncer 连接配置\n8. 管理员中央 AllowList\n9. 只读 Self-Report 排查\n0. 返回\n'
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
            8) manage_admin_allowlist ;;
            9) diagnose_self_report ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
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
    local path
    for path in "${TG_PROFILE_PATHS[@]}"; do
        log_info "通知路由 ${1}: ${path}（按 local 优先顺序；只覆盖匹配该 profile 的告警）"
        yaml_tool profiles "$path" "$1" || return 1
    done
}


setup_telegram_notification() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    local token chat endpoint
    prompt token 'Telegram Bot Token: ' && prompt chat 'Chat ID（个人或负数群组 ID）: ' && prompt endpoint 'HTTPS API 端点 [https://api.telegram.org]: ' || return 1
    endpoint="${endpoint:-https://api.telegram.org}"
    if [[ ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ || ! "$chat" =~ ^-?[0-9]+$ ]] || ! yaml_tool url "$endpoint"; then log_err 'Token、Chat ID 或 API 端点格式无效。'; return 1; fi
    [[ -f "$PROFILES_FILE" ]] || { log_err 'profiles.yaml 不存在，无法启用告警。'; return 1; }
    begin_config_change "$TG_NOTIF_FILE" "${TG_PROFILE_PATHS[@]}" || return 1
    if ! yaml_tool telegram "$TG_NOTIF_FILE" "$token" "$chat" "$endpoint" || ! update_telegram_profiles enable; then
        restore_config_change
        return 1
    fi
    apply_core_config || return 1
    log_succ 'Telegram 配置已加载，原有通知通道保留。'
    log_info '发送告警是出站 HTTPS 请求，不需要额外放行 Telegram 来源网段。'
    if confirm '现在使用官方通知插件发送测试消息？'; then
        test_telegram_notification || { log_err '配置已加载，投递验证失败。'; return 1; }
    fi
    return 0
}

test_telegram_notification() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    [[ -f "$TG_NOTIF_FILE" ]] || { log_err '请先配置 Telegram。'; return 1; }
    if cscli notifications test crowdsec_1key_telegram; then
        log_info '通知插件测试已执行，请检查 Telegram 接收情况和返回结果。'
    else
        log_err '通知插件测试失败。请检查 Token、Chat ID、机器人 /start 和 API 端点。'
        return 1
    fi
}

check_telegram_settings() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    [[ -f "$TG_NOTIF_FILE" ]] || { log_warn '尚未配置本工具 Telegram 通道。'; return 1; }
    log_info "通知配置: ${TG_NOTIF_FILE}（不显示 Token）"
    crowdsec -t && cscli notifications list
}

disable_telegram_notification() {
    require_core && require_yaml || return 1
    resolve_telegram_paths || return 1
    confirm '停用本工具 Telegram 通知？其他通知通道保留。' || return 0
    begin_config_change "$TG_NOTIF_FILE" "${TG_PROFILE_PATHS[@]}" || return 1
    update_telegram_profiles disable || { restore_config_change; return 1; }
    rm -f "$TG_NOTIF_FILE" || return 1
    apply_core_config || return 1
    log_succ '本工具 Telegram 通道已停用。'
}

manage_telegram() {
    require_core || return 1
    local choice
    while true; do
        printf '\nTelegram 告警\n1. 配置/更新\n2. 官方插件测试\n3. 检查配置\n4. 停用本工具通道\n0. 返回\n'
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) setup_telegram_notification ;;
            2) test_telegram_notification ;;
            3) check_telegram_settings ;;
            4) disable_telegram_notification ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
        pause
    done
}

check_health_status() {
    require_core || return 1
    local result=0 firewall_deployed=false units addresses
    printf '\n核心服务:\n'
    systemctl is-active crowdsec || result=1
    if [[ -e "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" || -e "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.local" ]]; then
        firewall_deployed=true
    elif units=$(systemctl list-unit-files --no-legend --no-pager crowdsec-firewall-bouncer.service); then
        if grep -q '^crowdsec-firewall-bouncer\.service[[:space:]]' <<< "$units"; then firewall_deployed=true; fi
    else
        log_err '无法确认 Firewall Bouncer 是否已部署。'
        firewall_deployed=unknown
        result=1
    fi
    if [[ "$firewall_deployed" == true ]]; then
        systemctl is-active crowdsec-firewall-bouncer || result=1
    elif [[ "$firewall_deployed" == false ]]; then
        log_info 'Firewall Bouncer: 未部署（可选）。'
    fi
    printf '\nLAPI 登录:\n'
    cscli lapi status || result=1
    printf '\n配置校验:\n'
    crowdsec -t || result=1
    printf '\n注册的 Bouncer 与 Machine:\n'
    cscli bouncers list || result=1
    cscli machines list || result=1
    printf '\n日志采集与解析指标:\n'
    cscli metrics || result=1
    if [[ "$firewall_deployed" == true ]]; then
        printf '\n防火墙规则:\n'
        firewall_status || result=1
    fi
    if addresses=$(yaml_tool appsec-listeners "$CS_DIR"); then
        if [[ -n "$addresses" ]]; then
            check_appsec_status || result=1
        else
            log_info 'AppSec: 未部署（可选）。'
        fi
    else
        log_err '无法读取有效 AppSec 数据源，健康状态无法确认。'
        result=1
    fi
    if webui_owned; then
        local running port
        if ! command -v docker >/dev/null 2>&1; then
            log_err 'WebUI 已部署但 Docker 不可用。'; result=1
        else
            running=$(docker inspect --format '{{.State.Running}}' crowdsec-web-ui 2>/dev/null) || running=false
            if [[ "$running" != true ]]; then log_err 'WebUI 已部署但容器未运行。'; result=1; fi
            port=$(yaml_tool get "${WEBUI_DIR}/docker-compose.yml" services.crowdsec-web-ui.environment.CONFIG_SERVER_PORT) || port=''
            if ! valid_port "$port" || ! webui_http_ready "$port"; then log_err 'WebUI HTTP 应用未就绪。'; result=1; fi
            webui_lapi_status || result=1
        fi
    else
        log_info 'WebUI: 未部署（可选）。'
    fi
    log_info '检查完成，未修改服务、账号或配置。'
    return "$result"
}

auto_heal_broken_parsers() {
    require_core || return 1
    log_info '仅校验配置；损坏的自定义解析器不会被自动删除或移走。'
    crowdsec -t
}

smart_audit_and_optimize() {
    require_core || return 1
    printf '\n资源概况:\n'
    free -m
    df -h /
    check_health_status || true
    log_info '可应用项目：补齐基础集合、按预设目录和 Docker 挂载修复 HTTP 日志采集、启用 loopback 指标。保留现有配置、账号与 AppSec。'
    confirm '应用上述配置？' || return 0
    require_yaml || return 1
    prepare_log_repair || return 1
    begin_config_change "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" "$LOG_REPAIR_FILE" || { cleanup_log_repair; return 1; }
    if ! reset_waf_to_core_baseline || ! enable_prometheus_metrics || ! apply_staged_log_repair || ! apply_core_config; then restore_config_change; cleanup_log_repair; return 1; fi
    cleanup_log_repair
    log_succ '已完成基础修复并校验配置；日志采集请通过新增访问与 cscli metrics 核验。'
    log_info 'SQLite WAL 可使用 --enable-wal，在确认数据库位于本地磁盘后启用官方 db_config.use_wal。'
    log_info '上游不确定时先用 --diagnose-real-ip 或菜单 [3] → [16] 只读核对；确认代理后再用 --repair-real-ip 修复。'
}

enable_sqlite_wal() {
    require_core && require_yaml || return 1
    log_warn 'SQLite WAL 不适用于网络共享盘；请先确认数据库位于本地磁盘。'
    confirm '确认本地 SQLite 数据库并启用官方 WAL 配置？' || return 0
    begin_config_change "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || return 1
    yaml_tool wal "${CS_DIR}/config.yaml" || { restore_config_change; return 1; }
    apply_core_config || return 1
    log_succ '已通过 db_config.use_wal 启用 WAL；未执行 VACUUM 或临时 PRAGMA。'
}

audit_crowdsec_residuals() {
    local found=false path service
    log_info '残留检查（只读，不自动清理）：'
    for path in "$CS_DIR" /var/lib/crowdsec "$WEBUI_DIR" "$CRON_FILE"; do
        if [[ -e "$path" ]]; then printf '存在: %s\n' "$path"; found=true; fi
    done
    for service in crowdsec crowdsec-firewall-bouncer; do
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
        log_err '仍有本工具的真实 IP 配置；请先 --restore-real-ip 撤销网站配置，再卸载核心。'
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
    if [[ -f "$HUB_RUNNER_DIR/.crowdsec-1key-owned" ]]; then rm -rf -- "$HUB_RUNNER_DIR" || return 1; fi
    systemctl daemon-reload || return 1
    log_succ '已卸载检测到的软件包并清理数据。备份、系统日志和软件源保留供恢复/排查。'
    log_info '若已注册 Console，请在控制台移除离线实例。'
}

uninstall_crowdsec_all() { deep_purge_residuals; }

manage_uninstall_center() {
    local choice
    while true; do
        printf '\n卸载与残留检查\n1. 卸载并删除数据（需要确认）\n2. 只读残留检查\n3. 清理残留（同样需要确认）\n0. 返回\n'
        prompt choice '请选择 [0-3]: ' || return 0
        case "$choice" in
            1) uninstall_crowdsec_all ;;
            2) audit_crowdsec_residuals ;;
            3) deep_purge_residuals ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
        pause
    done
}

show_main_menu() {
    local choice
    while true; do
        printf '\nCrowdSec 管理中心 — 首次使用请先安装 [1]，再检查 [9]\n1. 安装核心与 Firewall Bouncer\n2. WebUI 管理\n3. 日志规则与 AppSec WAF\n4. Hub 定时更新\n5. 黑名单与防火墙\n6. 注册 Console\n7. Telegram 告警\n8. 诊断、修复与基础配置优化\n9. 只读健康检查\n10. 卸载与只读残留检查\n0. 退出\n'
        prompt choice '请选择 [0-10]（Ctrl+D 退出）: ' || return 0
        case "$choice" in
            1) install_crowdsec_core ;;
            2) manage_web_ui ;;
            3) manage_waf_rules ;;
            4) manage_auto_update ;;
            5) manage_firewall_ops ;;
            6) bind_crowdsec_console ;;
            7) manage_telegram ;;
            8) smart_audit_and_optimize ;;
            9) check_health_status ;;
            10) manage_uninstall_center ;;
            0) return 0 ;;
            *) log_warn '无效选项，请输入菜单编号。' ;;
        esac
        pause
    done
}

show_help() {
    cat <<'EOF'
用法：sudo bash install-crowdsec-1panel.sh [操作]
不带参数进入交互菜单。命令行保留交互确认，失败返回非零状态。
  --install-core       安装核心与 Firewall Bouncer
  --install-webui      部署/更新 WebUI
  --reset-webui-credentials 检查/轮换 WebUI 独立凭据
  --install-waf        安装 Web 日志检测规则（不等同于 AppSec）
  --install-appsec     识别部署方式，配置引擎并接入已有宿主机/Docker Web Bouncer
  --install-web-bouncer 首次安装 Web Bouncer（Docker/宿主机）
  --remove-web-bouncer  撤销本工具原生容器 Web Bouncer，保留原 WAF
  --appsec-status      只读检查 AppSec 数据源、监听、容器组件与指标
  --verify-appsec      确认后发起标记请求，判定 HTTP 与 AppSec 指标证据
  --appsec-policy      检查/设置 AppSec 正文不可读与故障时策略
  --disable-appsec     停用本工具 AppSec
  --enable-cron        每天 03:30 更新 Hub
  --clean-redundant    查看节点并选择注销（不自动批量删除）
  --repair-bouncer     修复 Bouncer 的 LAPI 地址配置
  --admin-allowlist    明确管理单个管理员 IP 的中央 AllowList（旁路 AppSec）
  --self-report-status 只读查看 Self-Report 相关告警、决策与 AllowLists
  --repair-logs        按现有日志及 Docker 挂载补齐 HTTP 采集，保留原配置
  --repair-real-ip     按可信 CDN/代理和 Header 修复 Docker Nginx/OpenResty/NPM 真实 IP
  --diagnose-real-ip   上游不确定时只读检查配置、挂载日志及外部请求核对指引
  --restore-real-ip    撤销本工具的真实 IP 配置并恢复原内容
  --reset-baseline     补齐基础集合，保留自定义与 AppSec
  --reset-56           兼容旧名称，功能同 --reset-baseline，不保证场景数量
  --uninstall-waf      选择确认后移除已知 Web 日志规则
  --check-clean        只读残留检查
  --deep-clean/--purge 确认后卸载并清理数据
  --telegram           Telegram 管理菜单
  --telegram-test      使用官方通知插件测试
  --optimize           诊断后选择修复日志采集、基础规则与指标配置
  --enable-wal         确认本地 SQLite 后配置官方 use_wal
  --status             只读健康检查
  --uninstall          确认后卸载并清理数据
  --help/-h            帮助（不需要 root）
EOF
}

main() {
    if [[ $# -gt 1 ]]; then log_err '每次只能指定一个操作。'; return 1; fi
    case "${1:-}" in --help|-h) show_help; return 0 ;; esac
    check_root || return 1
    detect_os
    case "${1:-}" in
        '') show_main_menu ;;
        --install-core) install_crowdsec_core ;;
        --install-webui) deploy_web_ui ;;
        --reset-webui-credentials) reset_webui_credentials ;;
        --install-waf) install_web_rules ;;
        --install-appsec) setup_appsec ;;
        --install-web-bouncer) install_web_bouncer ;;
        --remove-web-bouncer) remove_docker_web_bouncer ;;
        --appsec-status) check_appsec_status ;;
        --verify-appsec) verify_appsec ;;
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
        --reset-baseline|--reset-56) reset_waf_to_core_baseline ;;
        --uninstall-waf) uninstall_all_waf_extensions ;;
        --check-clean) audit_crowdsec_residuals ;;
        --deep-clean|--purge|--uninstall) deep_purge_residuals ;;
        --enable-cron) enable_auto_update ;;
        --telegram) manage_telegram ;;
        --telegram-test) test_telegram_notification ;;
        --optimize) smart_audit_and_optimize ;;
        --enable-wal) enable_sqlite_wal ;;
        --status) check_health_status ;;
        *) log_err "未知参数: $1"; show_help; return 1 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

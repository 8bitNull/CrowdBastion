#!/usr/bin/env bash
# CrowdSec 管理中心：日志检测、Firewall Bouncer、可选 AppSec 与 WebUI。
# 配置修改使用同目录 lib/crowdsec_config.py；完整说明见 readme.md。
set -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CONFIG_HELPER="${SCRIPT_DIR}/lib/crowdsec_config.py"
CS_DIR="/etc/crowdsec"
WEBUI_DIR="/opt/crowdsec-web-ui"
CRON_FILE="/etc/cron.d/crowdsec-autoupdate"
TG_NOTIF_FILE="${CS_DIR}/notifications/crowdsec-1key-telegram.yaml"
PROFILES_FILE="${CS_DIR}/profiles.yaml"
APPSEC_FILE="${CS_DIR}/acquis.d/crowdsec-1key-appsec.yaml"
APPSEC_LINKS="${CS_DIR}/crowdsec-1key-appsec-links.yaml"
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
    begin_config_change "${CS_DIR}/parsers/s02-enrich/99-admin-whitelist.yaml" "${CS_DIR}/acquis.d/web-sites.yaml" "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || return 1
    yaml_tool whitelist "${CS_DIR}/parsers/s02-enrich/99-admin-whitelist.yaml" "$CURRENT_IP" || { restore_config_change; return 1; }
    configure_log_acquis || { restore_config_change; return 1; }
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
    local target="${CS_DIR}/acquis.d/web-sites.yaml"
    mkdir -p "$(dirname "$target")" || return 1
    cat > "$target" <<'EOF'
filenames:
  # HTTP 日志；stream-access.log 使用不同格式，不能标记为 nginx HTTP。
  - /opt/1panel/apps/openresty/openresty/log/access.log
  - /opt/1panel/apps/openresty/openresty/log/error.log
  - /opt/1panel/www/sites/*/log/access.log
  - /opt/1panel/www/sites/*/log/error.log
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
  - /home/docker/npm/data/logs/*.log
  - /opt/npm/data/logs/*.log
  - /opt/nginx-proxy-manager/data/logs/*.log
  - /data/logs/*.log
  - /var/log/nginx-proxy-manager/*.log
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

enable_prometheus_metrics() {
    yaml_tool metrics "${CS_DIR}/config.yaml"
}

install_collections() {
    require_core || return 1
    cscli hub update || return 1
    cscli collections install "$@"
}

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
    require_core && require_yaml && require_commands docker || return 1
    if ! systemctl is-active --quiet crowdsec || ! cscli lapi status; then log_err 'CrowdSec/LAPI 尚未就绪。'; return 1; fi
    local port=3000 url machine password host created=false creds compose previous=false previous_image='' old_machine='' rotation="${1:-}"
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
    log_info '正在拉取 WebUI 镜像，失败时保留已有容器和凭据。'
    if [[ "$rotation" != rotate && -f "${WEBUI_DIR}/data/webui_api_credentials.yaml" ]] && ! webui_lapi_status; then
        log_err 'WebUI 独立凭据无法登录 LAPI，已保留现有部署。请检查后重新注册。'
        return 1
    fi
    previous_image=$(docker inspect --format '{{.Image}}' crowdsec-web-ui 2>/dev/null) || previous_image=''
    [[ "$previous_image" =~ ^sha256:[a-f0-9]{64}$ ]] || previous_image=''
    docker pull "$WEBUI_IMAGE" || return 1
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
    if ! enable_prometheus_metrics || ! yaml_tool compose "$compose" "$WEBUI_DIR" "$url" "$machine" "$password" "$port" || ! apply_core_config; then
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
        [[ "$running" == true ]] && break
        sleep 1
    done
    if [[ "$running" != true ]]; then
        rollback_webui "$created" "$machine" "$previous" "$previous_image"
        log_err 'WebUI 容器未运行，请查看 docker logs crowdsec-web-ui。'
        return 1
    fi
    touch "${WEBUI_DIR}/.crowdsec-1key-managed" || return 1
    if [[ "$rotation" == rotate && -n "$old_machine" && "$old_machine" != "$machine" ]]; then
        cscli machines delete "$old_machine" || log_warn "新 WebUI 已运行，但旧 Machine ${old_machine} 注销失败，请人工核验。"
    fi
    log_succ "WebUI 容器已运行，访问 http://服务器地址:${port}。"
    log_warn '按上游镜像实际认证功能配置访问保护；建议通过 HTTPS 反向代理访问。'
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
    cscli collections remove "$target" || return 1
    crowdsec -t && systemctl reload crowdsec || return 1
    log_succ "已卸载 ${target}。"
}

uninstall_all_waf_extensions() {
    require_core || return 1
    confirm '移除已知 Web 日志检测集合？AppSec 与自定义集合保留。' || return 0
    local collection installed
    installed=$(cscli collections list -o json) || return 1
    local collections
    collections=$(printf '%s' "$installed" | python3 -c 'import json,sys; d=json.load(sys.stdin); items=d.get("collections",[]) if isinstance(d,dict) else d; print("\n".join(x["name"] for x in items if x.get("status","enabled") != "disabled"))') || return 1
    for collection in crowdsecurity/nginx crowdsecurity/nginx-proxy-manager crowdsecurity/http-cve crowdsecurity/base-http-scenarios crowdsecurity/wordpress crowdsecurity/iptables; do
        if printf '%s\n' "$collections" | grep -Fxq "$collection"; then
            cscli collections remove "$collection" || return 1
        fi
    done
    install_collections crowdsecurity/linux crowdsecurity/sshd || return 1
    crowdsec -t && systemctl reload crowdsec || return 1
    log_succ '已处理已知 Web 日志检测集合。'
}

setup_appsec() {
    require_core && require_yaml || return 1
    local external
    external=$(yaml_tool appsec-existing "$CS_DIR" "$APPSEC_FILE") || return 1
    if [[ -n "$external" ]]; then
        log_warn "已有外部 AppSec 配置，避免重复监听，未改写: ${external}"
        return 0
    fi
    log_info '启用官方 AppSec 数据源；Firewall Bouncer 不支持转发 HTTP 请求。'
    install_collections crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules || return 1
    begin_config_change "$APPSEC_FILE" || return 1
    if ! yaml_tool appsec "$APPSEC_FILE"; then restore_config_change; return 1; fi
    apply_core_config || return 1
    log_succ 'AppSec 数据源已加载，监听 127.0.0.1:7422。'
    local choice file service
    printf '1. 接入宿主机 Nginx Bouncer\n2. 接入宿主机 OpenResty Bouncer\n0. 仅配置引擎（容器/外部代理需自行接入）\n'
    prompt choice '请选择 [0-2]: ' || return 0
    case "$choice" in
        1) file="${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf"; service=nginx ;;
        2) file="${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; service=openresty ;;
        0|'')
            log_warn '尚未验证 HTTP 转发。1Panel/NPM 容器内的 127.0.0.1 通常不指向宿主机，请按上游文档配置专用网络。'
            return 0 ;;
        *) log_err '无效选项，引擎已配置但 Web Bouncer 未接入。'; return 1 ;;
    esac
    [[ -f "$file" ]] || { log_err "未安装对应 Web Bouncer: ${file}；引擎已配置，网站尚未接入。"; return 1; }
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
    require_core || return 1
    cscli appsec-configs list && cscli metrics show appsec || return 1
    log_info '确认 Processed/Blocked 随测试请求变化，不能仅凭 HTTP 403 判断 WAF 生效。'
}

verify_appsec() {
    require_core && require_commands curl || return 1
    local target=''
    prompt target '输入你管理的网站根地址（如 http://localhost，留空取消）: ' || return 0
    [[ -z "$target" ]] && return 0
    [[ "$target" =~ ^https?://[^[:space:]]+$ ]] || { log_err '网站地址无效。'; return 1; }
    log_info '先查看 AppSec 指标，再请求官方验证路径 /.env。'
    cscli metrics show appsec || return 1
    curl -sS --max-time 15 -I "${target%/}/.env" || return 1
    cscli metrics show appsec || return 1
    log_info '预期 HTTP 403 且 AppSec Processed/Blocked 计数增加；请同时确认具体规则命中。'
}

disable_appsec() {
    require_core && require_yaml || return 1
    if [[ ! -f "$APPSEC_FILE" ]]; then log_info '本工具未配置 AppSec，外部接入保留。'; return 0; fi
    confirm '停用本工具配置的 AppSec？外部数据源和规则集合保留。' || return 0
    local files=("$APPSEC_FILE" "$APPSEC_LINKS") file service
    local reloaded=()
    for file in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        if [[ -f "$file" && -f "$APPSEC_LINKS" ]] && yaml_tool link-owned "$file" "$APPSEC_LINKS" >/dev/null 2>&1; then files+=("$file"); fi
    done
    begin_config_change "${files[@]}" || return 1
    for file in "${files[@]:2}"; do
        if grep -Fxq 'APPSEC_URL=http://127.0.0.1:7422' "$file"; then
            yaml_tool unlink-web-bouncer "$file" "$APPSEC_LINKS" || { restore_config_change; return 1; }
            service=nginx
            [[ "$file" == *openresty* ]] && service=openresty
            if ! "$service" -t || ! systemctl reload "$service"; then
                restore_config_change
                systemctl reload "$service" || true
                for service in "${reloaded[@]}"; do systemctl reload "$service" || true; done
                return 1
            fi
            reloaded+=("$service")
        fi
    done
    rm -f "$APPSEC_FILE" || return 1
    if ! apply_core_config; then
        for service in "${reloaded[@]}"; do systemctl reload "$service" || true; done
        return 1
    fi
    log_succ '本工具 AppSec 数据源已停用；容器或外部代理请同步停用请求转发。'
}

manage_waf_rules() {
    require_core || return 1
    local choice
    while true; do
        printf '\n日志检测规则与 AppSec WAF\n1. Web 日志检测规则\n2. WordPress 日志规则\n3. iptables 日志规则（需要相应采集）\n4. 已安装集合\n5. 更新 Hub 规则\n6. 补齐基础集合（保留自定义/AppSec）\n7. 指定卸载集合\n8. 移除已知 Web 日志扩展\n9. 配置 AppSec 与 Web Bouncer\n10. AppSec 状态\n11. 验证网站 AppSec\n12. 停用本工具 AppSec\n0. 返回\n'
        prompt choice '请选择 [0-12]: ' || return 0
        case "$choice" in
            1) install_web_rules ;;
            2) install_collections crowdsecurity/wordpress && crowdsec -t && systemctl reload crowdsec ;;
            3) install_collections crowdsecurity/iptables && crowdsec -t && systemctl reload crowdsec ;;
            4) cscli collections list ;;
            5) cscli hub update && cscli hub upgrade && crowdsec -t && systemctl reload crowdsec ;;
            6) reset_waf_to_core_baseline ;;
            7) uninstall_specific_waf_collection ;;
            8) uninstall_all_waf_extensions ;;
            9) setup_appsec ;;
            10) check_appsec_status ;;
            11) verify_appsec ;;
            12) disable_appsec ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
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
    begin_config_change "$CRON_FILE" || return 1
    local cscli_path crowdsec_path systemctl_path
    cscli_path=$(type -P cscli) || cscli_path=/usr/bin/cscli
    crowdsec_path=$(type -P crowdsec) || crowdsec_path=/usr/bin/crowdsec
    systemctl_path=$(type -P systemctl) || systemctl_path=/bin/systemctl
    printf '# CrowdSec Hub 更新；使用服务器时区。CAPI 名单由引擎自动同步。\n%s %s * * * root %s hub update && %s hub upgrade && %s -t && %s reload crowdsec\n' "$((10#$minute))" "$((10#$hour))" "$cscli_path" "$cscli_path" "$crowdsec_path" "$systemctl_path" > "$CRON_FILE" || return 1
    chmod 644 "$CRON_FILE" || return 1
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
    local found=false
    if command -v nft >/dev/null 2>&1; then
        local family
        for family in ip ip6 inet; do
            if nft list table "$family" crowdsec 2>/dev/null; then found=true; fi
        done
        if nft list table ip6 crowdsec6 2>/dev/null; then found=true; fi
        local configured table
        configured=$(yaml_tool firewall-tables "${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml" 2>/dev/null) || configured=''
        while read -r family table; do
            [[ -z "$family" || -z "$table" ]] && continue
            if nft list table "$family" "$table" 2>/dev/null; then found=true; fi
        done <<< "$configured"
    fi
    if command -v iptables >/dev/null 2>&1 && iptables -S 2>/dev/null | grep -i crowdsec; then found=true; fi
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -S 2>/dev/null | grep -i crowdsec; then found=true; fi
    if command -v ipset >/dev/null 2>&1 && ipset list -name 2>/dev/null | grep -i crowdsec; then found=true; fi
    [[ "$found" == true ]] || { log_warn '未发现默认 CrowdSec 防火墙资源，自定义 table/chain 或 set-only 模式需人工核验。'; return 1; }
    log_info '以上仅证明规则存在，需结合服务、LAPI 拉取及流量测试确认阻断。'
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
    local choice ip duration reason admin_ip
    while true; do
        printf '\n黑名单与防火墙\n1. 活跃决策\n2. 最新警报\n3. 解封 IP\n4. 封禁 IP\n5. 查看防火墙规则\n6. 解析指标\n7. 修复 Bouncer 连接配置\n0. 返回\n'
        prompt choice '请选择 [0-7]: ' || return 0
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
                detect_admin_ip
                admin_ip=''
                if [[ -n "$CURRENT_IP" ]]; then admin_ip=$(yaml_tool normalize-ip "$CURRENT_IP") || admin_ip=''; fi
                if [[ -n "$admin_ip" && "$ip" == "$admin_ip" ]]; then log_err '不能封禁当前 SSH 管理 IP。'; continue; fi
                if cscli decisions add --ip "$ip" --duration "$duration" --reason "${reason:-手动封禁}" --type ban; then
                    log_succ '封禁决策已提交；由 Bouncer 拉取执行。'
                else log_err '添加封禁失败。'; fi ;;
            5) firewall_status ;;
            6) cscli metrics ;;
            7) repair_firewall_bouncer ;;
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
}

setup_telegram_notification() {
    require_core && require_yaml || return 1
    local token chat endpoint
    prompt token 'Telegram Bot Token: ' && prompt chat 'Chat ID（个人或负数群组 ID）: ' && prompt endpoint 'HTTPS API 端点 [https://api.telegram.org]: ' || return 1
    endpoint="${endpoint:-https://api.telegram.org}"
    if [[ ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ || ! "$chat" =~ ^-?[0-9]+$ ]] || ! yaml_tool url "$endpoint"; then log_err 'Token、Chat ID 或 API 端点格式无效。'; return 1; fi
    [[ -f "$PROFILES_FILE" ]] || { log_err 'profiles.yaml 不存在，无法启用告警。'; return 1; }
    begin_config_change "$TG_NOTIF_FILE" "$PROFILES_FILE" || return 1
    if ! yaml_tool telegram "$TG_NOTIF_FILE" "$token" "$chat" "$endpoint" || ! yaml_tool profiles "$PROFILES_FILE" enable; then
        restore_config_change
        return 1
    fi
    apply_core_config || return 1
    log_succ 'Telegram 配置已加载，原有通知通道保留。'
    log_info '发送告警是出站 HTTPS 请求，不需要额外放行 Telegram 来源网段。'
    if confirm '现在使用官方通知插件发送测试消息？'; then test_telegram_notification; fi
    return 0
}

test_telegram_notification() {
    require_core || return 1
    [[ -f "$TG_NOTIF_FILE" ]] || { log_err '请先配置 Telegram。'; return 1; }
    if cscli notifications test crowdsec_1key_telegram; then
        log_info '通知插件测试已执行，请检查 Telegram 接收情况和返回结果。'
    else
        log_err '通知插件测试失败。请检查 Token、Chat ID、机器人 /start 和 API 端点。'
        return 1
    fi
}

check_telegram_settings() {
    require_core || return 1
    [[ -f "$TG_NOTIF_FILE" ]] || { log_warn '尚未配置本工具 Telegram 通道。'; return 1; }
    log_info "通知配置: ${TG_NOTIF_FILE}（不显示 Token）"
    crowdsec -t && cscli notifications list
}

disable_telegram_notification() {
    require_core && require_yaml || return 1
    confirm '停用本工具 Telegram 通知？其他通知通道保留。' || return 0
    begin_config_change "$TG_NOTIF_FILE" "$PROFILES_FILE" || return 1
    yaml_tool profiles "$PROFILES_FILE" disable || { restore_config_change; return 1; }
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
    local result=0
    printf '\n核心服务:\n'
    systemctl is-active crowdsec || result=1
    systemctl is-active crowdsec-firewall-bouncer || result=1
    printf '\nLAPI 登录:\n'
    cscli lapi status || result=1
    printf '\n配置校验:\n'
    crowdsec -t || result=1
    printf '\n注册的 Bouncer 与 Machine:\n'
    cscli bouncers list || result=1
    cscli machines list || result=1
    printf '\n日志采集与解析指标:\n'
    cscli metrics || result=1
    printf '\n防火墙规则:\n'
    firewall_status || result=1
    if [[ -f "$APPSEC_FILE" ]]; then check_appsec_status || result=1; fi
    if command -v docker >/dev/null 2>&1; then
        docker ps -a --filter 'name=^/crowdsec-web-ui$' --format 'table {{.Names}}\t{{.Status}}' || result=1
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
    require_core && require_yaml || return 1
    printf '\n资源概况:\n'
    free -m
    df -h /
    check_health_status || true
    log_info '可应用项目：补齐基础集合、启用 loopback 指标。保留日志自定义配置、账号与 AppSec。'
    confirm '应用上述配置？' || return 0
    begin_config_change "${CS_DIR}/config.yaml" "${CS_DIR}/config.yaml.local" || return 1
    if ! reset_waf_to_core_baseline || ! enable_prometheus_metrics || ! apply_core_config; then restore_config_change; return 1; fi
    log_succ '已应用并验证基础规则与指标配置。'
    log_info 'SQLite WAL 可使用 --enable-wal，在确认数据库位于本地磁盘后启用官方 db_config.use_wal。'
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
    firewall_status && found=true
    if [[ "$found" == true ]]; then log_warn '检测到安装组件或残留；需要卸载时请选择明确的卸载入口。'; return 1; fi
    log_info '上述检查未发现残留；自定义服务、规则和软件源需按实际部署另行核验。'
}

deep_purge_residuals() {
    confirm '永久删除 CrowdSec 核心、数据、Bouncer 与本工具 WebUI？' || return 0
    require_commands systemctl || return 1
    local web_config
    for web_config in "${CS_DIR}/bouncers/crowdsec-nginx-bouncer.conf" "${CS_DIR}/bouncers/crowdsec-openresty-bouncer.conf"; do
        if [[ -f "$web_config" ]]; then
            log_err "仍有 Web Bouncer 集成 ${web_config}。请先按上游文档移除 Nginx/OpenResty 集成并验证网站，再卸载核心。"
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
    if firewall_status >/dev/null 2>&1; then
        log_err '服务停止后仍有防火墙资源。请根据 Bouncer 配置人工释放；未删除软件包、配置或数据。'
        return 1
    fi
    local packages=() package
    case "$OS_ID" in
        debian|ubuntu)
            for package in crowdsec crowdsec-firewall-bouncer crowdsec-firewall-bouncer-nftables crowdsec-firewall-bouncer-iptables; do
                [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" == 'install ok installed' ]] && packages+=("$package")
            done
            if ((${#packages[@]})); then apt-get purge -y "${packages[@]}" || return 1; fi ;;
        centos|rhel|almalinux|rocky|fedora)
            for package in crowdsec crowdsec-firewall-bouncer crowdsec-firewall-bouncer-nftables crowdsec-firewall-bouncer-iptables; do
                rpm -q "$package" >/dev/null 2>&1 && packages+=("$package")
            done
            if ((${#packages[@]})); then
                if command -v dnf >/dev/null 2>&1; then dnf remove -y "${packages[@]}" || return 1; else yum remove -y "${packages[@]}" || return 1; fi
            fi ;;
        *) log_err '未知系统，未自动删除软件包和数据。'; return 1 ;;
    esac
    # The official service removes managed chains on shutdown; verify before deleting data.
    if firewall_status >/dev/null 2>&1; then
        log_err '默认防火墙资源仍存在。请根据原 Bouncer 配置人工释放，配置和数据已保留。'
        return 1
    fi
    rm -rf -- "$CS_DIR" /var/lib/crowdsec || return 1
    if webui_owned; then rm -rf -- "$WEBUI_DIR" || return 1; fi
    rm -f -- "$CRON_FILE" || return 1
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
        printf '\nCrowdSec 管理中心 — 首次使用请先安装 [1]，再检查 [9]\n1. 安装核心与 Firewall Bouncer\n2. WebUI 管理\n3. 日志规则与 AppSec WAF\n4. Hub 定时更新\n5. 黑名单与防火墙\n6. 注册 Console\n7. Telegram 告警\n8. 诊断与基础配置优化\n9. 只读健康检查\n10. 卸载与只读残留检查\n0. 退出\n'
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
  --install-appsec     配置 AppSec 引擎与已安装的 Web Bouncer
  --appsec-status      查看 AppSec 指标
  --verify-appsec      对用户指定网站执行官方 /.env 验证
  --disable-appsec     停用本工具 AppSec
  --enable-cron        每天 03:30 更新 Hub
  --clean-redundant    查看节点并选择注销（不自动批量删除）
  --repair-bouncer     修复 Bouncer 的 LAPI 地址配置
  --reset-baseline     补齐基础集合，保留自定义与 AppSec
  --reset-56           兼容旧名称，功能同 --reset-baseline，不保证场景数量
  --uninstall-waf      选择确认后移除已知 Web 日志规则
  --check-clean        只读残留检查
  --deep-clean/--purge 确认后卸载并清理数据
  --telegram           Telegram 管理菜单
  --telegram-test      使用官方通知插件测试
  --optimize           诊断后选择应用基础配置
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
        --appsec-status) check_appsec_status ;;
        --verify-appsec) verify_appsec ;;
        --disable-appsec) disable_appsec ;;
        --clean-redundant) check_and_clean_redundant_instances ;;
        --repair-bouncer) repair_firewall_bouncer ;;
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

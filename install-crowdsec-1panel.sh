#!/usr/bin/env bash
# ==============================================================================
# 脚本名称: CrowdSec 终极防护中心 (1Panel & 科技lion 深度适配版)
# 核心功能:
#   1. 内核级拦截 (NFTables/iptables Firewall Bouncer，直接阻断进 Docker 的恶意流量)
#   2. 1Panel & 科技lion (LDNMP/NPM) Web 站点日志全路径自适应采集
#   3. 防自封保护 (自动抓取当前 SSH 客户端公网 IP，固化局域网/Docker 网段白名单)
#   4. 每日定时自动更新 (Hub 规则库 + 威胁情报每日自动同步)
#   5. 精选 Web WAF 与 CVE 漏洞防御规则库一键装配
#   6. 可选轻量级 WebUI 部署 (基于 TheDuffman85/crowdsec-web-ui 容器 + LAPI 自动对接)
#   7. Telegram 实时告警推送与自适应图文取证穿透模板 (告别未知路径/未知UA)
#   8. 智能环境诊断与全方位深度调优 (系统资源感知 + SQLite提速 + 漏采补齐)
#   9. 日常黑名单管理、解除封禁、警报监控与官方 Console 云端控制台绑定
# ==============================================================================

set -o pipefail

# 颜色常量定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LOG_FILE="/var/log/crowdsec_manager.log"
touch "${LOG_FILE}" 2>/dev/null || true

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_succ() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; }

WEBUI_DIR="/opt/crowdsec-web-ui"
CRON_FILE="/etc/cron.d/crowdsec-autoupdate"
TG_NOTIF_FILE="/etc/crowdsec/notifications/http.yaml"
PROFILES_FILE="/etc/crowdsec/profiles.yaml"
TG_WHITELIST_FILE="/etc/crowdsec/parsers/s02-enrich/tg-whitelist.yaml"

# ------------------------------------------------------------------------------
# 1. 基础环境检测与 IP 探测
# ------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "必须使用 root 权限运行此脚本！请使用 'sudo -i' 或以 root 用户登录。"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID:-linux}"
        OS_VERSION="${VERSION_ID:-}"
    else
        OS_ID="linux"
        OS_VERSION=""
    fi
}

detect_admin_ip() {
    CURRENT_IP=""
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        CURRENT_IP=$(echo "${SSH_CLIENT}" | awk '{print $1}')
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        CURRENT_IP=$(echo "${SSH_CONNECTION}" | awk '{print $1}')
    fi

    if [[ -z "${CURRENT_IP}" ]]; then
        CURRENT_IP=$(who -m 2>/dev/null | grep -o -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1 || true)
    fi
}

# ------------------------------------------------------------------------------
# 2. CrowdSec 核心与防火墙 Bouncer 安装
# ------------------------------------------------------------------------------
install_crowdsec_core() {
    clear
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo -e "${BLUE}${BOLD}       [1] 部署/重装 CrowdSec 核心引擎与内核级拦截防火墙         ${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo ""

    detect_admin_ip
    if [[ -n "${CURRENT_IP}" ]]; then
        log_succ "检测到当前远程 SSH 客户端 IP 为: ${BOLD}${CURRENT_IP}${NC} (将自动加入白名单)"
    else
        log_warn "未能自动检测到当前 SSH 客户端 IP。"
        read -r -p "请输入需要放行的管理公网 IP (留空则仅放行私有内网): " CURRENT_IP
    fi

    # 1. 配置官方源
    log_info "正在配置官方 CrowdSec 仓库源..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://install.crowdsec.net | bash || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://install.crowdsec.net | bash || true
    else
        if [[ "${OS_ID}" =~ ^(debian|ubuntu)$ ]]; then
            apt-get update -y && apt-get install -y curl || true
        else
            yum install -y curl || true
        fi
        curl -fsSL https://install.crowdsec.net | bash || true
    fi

    # 2. 检测底层防火墙 (nftables 优先)
    USE_NFTABLES=false
    if command -v nft >/dev/null 2>&1 || modprobe nf_tables 2>/dev/null; then
        USE_NFTABLES=true
        log_info "检测到底层支持 nftables，选用 nftables bouncer（内核 Prerouting 链拦截）！"
    else
        log_warn "未检测到 nftables 支持，选用 iptables bouncer。"
    fi

    # 3. 安装包
    log_info "正在安装 CrowdSec 与 Firewall Bouncer 软件包..."
    if [[ "${OS_ID}" =~ ^(debian|ubuntu)$ ]]; then
        apt-get update -y
        apt-get install -y crowdsec
        if [[ "${USE_NFTABLES}" == "true" ]]; then
            apt-get install -y crowdsec-firewall-bouncer-nftables 2>/dev/null || apt-get install -y crowdsec-firewall-bouncer-iptables 2>/dev/null || apt-get install -y crowdsec-firewall-bouncer || true
        else
            apt-get install -y crowdsec-firewall-bouncer-iptables 2>/dev/null || apt-get install -y crowdsec-firewall-bouncer || true
        fi
    elif [[ "${OS_ID}" =~ ^(centos|rhel|almalinux|rocky|fedora)$ ]]; then
        yum install -y crowdsec
        if [[ "${USE_NFTABLES}" == "true" ]]; then
            yum install -y crowdsec-firewall-bouncer-nftables 2>/dev/null || yum install -y crowdsec-firewall-bouncer-iptables 2>/dev/null || yum install -y crowdsec-firewall-bouncer || true
        else
            yum install -y crowdsec-firewall-bouncer-iptables 2>/dev/null || yum install -y crowdsec-firewall-bouncer || true
        fi
    else
        log_err "当前系统不受官方软件包直接支持: ${OS_ID}"
        return 1
    fi

    # 4. 白名单保护
    log_info "正在配置管理员与 Docker 子网白名单..."
    mkdir -p /etc/crowdsec/parsers/s02-enrich/
    cat << EOF > /etc/crowdsec/parsers/s02-enrich/99-admin-whitelist.yaml
name: custom/admin-whitelist
description: "Whitelist internal subnets, Docker bridges, and admin IP"
whitelist:
  reason: "Admin and internal networks protection"
  ip:
    - "127.0.0.1"
    - "::1"
$( [[ -n "${CURRENT_IP}" ]] && echo "    - \"${CURRENT_IP}\"" )
  cidr:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "100.64.0.0/10"
EOF

    # 5. 配置 1Panel + 科技lion + 原生 Docker 日志采集
    configure_log_acquis

    # 6. 安装基础防护规则集
    log_info "正在安装核心防御规则集..."
    cscli collections install crowdsecurity/linux || true
    cscli collections install crowdsecurity/sshd || true
    cscli collections install crowdsecurity/nginx || true
    cscli collections install crowdsecurity/nginx-proxy-manager || true
    cscli collections install crowdsecurity/http-cve || true
    cscli collections install crowdsecurity/base-http-scenarios || true
    cscli collections install crowdsecurity/whitelist-good-actors || true

    # 7. 配置 Prometheus 运行时指标 (供 WebUI 展现防护组件、解析器等统计)
    enable_prometheus_metrics

    # 8. 预检修复损坏解析器
    auto_heal_broken_parsers

    # 9. 静态检查并重启
    log_info "正在验证配置文件..."
    crowdsec -t || true

    systemctl daemon-reload
    systemctl enable crowdsec || true
    systemctl restart crowdsec || true

    systemctl enable --now crowdsec-firewall-bouncer 2>/dev/null || \
    systemctl enable --now crowdsec-firewall-bouncer-nftables 2>/dev/null || \
    systemctl enable --now crowdsec-firewall-bouncer-iptables 2>/dev/null || true

    log_succ "CrowdSec 核心与防火墙拦截组件部署完成！"
    read -r -p "按回车键返回主菜单..." _
}

# 配置多路径日志采集
configure_log_acquis() {
    log_info "配置 1Panel、科技lion (LDNMP/NPM) 与系统日志动态采集..."
    mkdir -p /etc/crowdsec/acquis.d/

    cat << "EOF" > /etc/crowdsec/acquis.d/web-sites.yaml
# ==============================================================
# Web 访问与错误日志自动采集规则
# 支持 1Panel (OpenResty)、科技lion (LDNMP) 及宿主机 Nginx
# ==============================================================
filenames:
  # 1Panel 默认 OpenResty 及多站点日志路径
  - /opt/1panel/apps/openresty/openresty/logs/*.log
  - /opt/1panel/apps/openresty/openresty/data/sites/*/log/*.log
  - /opt/1panel/apps/openresty/openresty/data/sites/*/log/access.log
  - /opt/1panel/apps/openresty/openresty/data/sites/*/log/error.log
  # 科技lion (kejilion.sh) LDNMP 网站环境日志路径
  - /home/web/log/nginx/*.log
  - /home/web/log/nginx/*/*.log
  # 宿主机原生 Nginx
  - /var/log/nginx/*.log
labels:
  type: nginx
---
# ==============================================================
# Nginx Proxy Manager (NPM) 专用日志采集规则
# 完美适配 Docker 容器部署模式 与 本地宿主机部署模式
# ==============================================================
filenames:
  # 科技lion 及常见 Docker Compose 部署挂载路径
  - /home/docker/npm/data/logs/*.log
  - /opt/npm/data/logs/*.log
  - /opt/nginx-proxy-manager/data/logs/*.log
  - /data/logs/*.log
  # 本地/宿主机原生安装路径
  - /var/log/nginx-proxy-manager/*.log
labels:
  type: nginx-proxy-manager
---
# 系统 SSH 暴力破解防护日志采集
filenames:
  - /var/log/auth.log
  - /var/log/secure
labels:
  type: syslog
EOF
    rm -f /etc/crowdsec/acquis.d/1panel-openresty.yaml 2>/dev/null || true
    log_succ "多环境日志采集规则已配置: /etc/crowdsec/acquis.d/web-sites.yaml"
    log_info "已针对 1Panel、NPM (Docker+本地)、科技lion 提供全方位日志采集适配！"
}

# 开启并配置 CrowdSec Prometheus 运行时指标
enable_prometheus_metrics() {
    log_info "正在配置 CrowdSec 核心 Prometheus 运行时指标 (level: full, 端口: 6060)..."
    if [[ -f "/etc/crowdsec/config.yaml" ]]; then
        if grep -q "prometheus:" /etc/crowdsec/config.yaml; then
            sed -i '/prometheus:/,/listen_port:/s/enabled:.*/enabled: true/' /etc/crowdsec/config.yaml
            sed -i '/prometheus:/,/listen_port:/s/level:.*/level: full/' /etc/crowdsec/config.yaml
            sed -i '/prometheus:/,/listen_port:/s/listen_port:.*/listen_port: 6060/' /etc/crowdsec/config.yaml
        else
            cat << 'EOF' >> /etc/crowdsec/config.yaml

prometheus:
  enabled: true
  level: full
  listen_addr: 127.0.0.1
  listen_port: 6060
EOF
        fi
        log_succ "Prometheus 运行时指标已配置为 full 级别！"
    fi
}

# ------------------------------------------------------------------------------
# 3. 部署 / 管理 本地 CrowdSec-Web-UI (TheDuffman85/crowdsec-web-ui)
# ------------------------------------------------------------------------------
manage_web_ui() {
    clear
    echo -e "${PURPLE}${BOLD}================================================================${NC}"
    echo -e "${PURPLE}${BOLD}   [2] 部署/管理 本地 CrowdSec-Web-UI (TheDuffman85/crowdsec-web-ui)    ${NC}"
    echo -e "${PURPLE}${BOLD}================================================================${NC}"
    echo ""
    echo -e "介绍: 本地轻量化仪表盘，免占用大内存，直接调用本机 CrowdSec LAPI 展现"
    echo -e "开源地址: ${CYAN}https://github.com/TheDuffman85/crowdsec-web-ui${NC}"
    echo ""
    echo -e " ${BOLD}1.${NC} 快速部署 / 更新 CrowdSec WebUI 容器"
    echo -e " ${BOLD}2.${NC} 停止并卸载 CrowdSec WebUI 容器"
    echo -e " ${BOLD}3.${NC} 查看 WebUI 容器运行日志 (最新 100 行)"
    echo -e " ${BOLD}4.${NC} 重置/重新生成 LAPI 连接密钥"
    echo -e " ${BOLD}0.${NC} 返回主菜单"
    echo ""
    read -r -p "请选择操作 [0-4]: " ui_choice

    case "${ui_choice}" in
        1) deploy_web_ui ;;
        2) uninstall_web_ui ;;
        3) 
            if docker ps -a 2>/dev/null | grep -q "crowdsec-web-ui"; then
                echo ""
                docker logs --tail 100 crowdsec-web-ui || true
                echo ""
                read -r -p "按回车键继续..." _
            else
                log_warn "未检测到 crowdsec-web-ui 容器！"
                read -r -p "按回车键继续..." _
            fi
            ;;
        4) reset_webui_credentials ;;
        *) return ;;
    esac
}

deploy_web_ui() {
    # 检查 Docker
    if ! command -v docker >/dev/null 2>&1; then
        log_err "未检测到 Docker！请先通过 1Panel 或科技lion 脚本安装 Docker。"
        read -r -p "按回车键返回..." _
        return
    fi

    # 检查 CrowdSec 是否已安装
    if ! command -v cscli >/dev/null 2>&1; then
        log_err "未检测到 cscli 命令！请先在主菜单中执行 [1] 安装 CrowdSec 核心防护。"
        read -r -p "按回车键返回..." _
        return
    fi

    # 检查 CrowdSec 服务是否正常运行并尝试自愈
    if ! systemctl is-active --quiet crowdsec 2>/dev/null; then
        log_warn "检测到 crowdsec 服务当前未处于运行状态，正在尝试启动并等待 LAPI 就绪..."
        systemctl restart crowdsec || true
        sleep 3
    fi

    if ! systemctl is-active --quiet crowdsec 2>/dev/null; then
        log_err "crowdsec 服务启动失败，Local API (LAPI) 不可用！"
        echo ""
        PORT_8080_OCCUPIED=$(ss -tulpn 2>/dev/null | grep -E ":8080\s" || true)
        if [[ -n "${PORT_8080_OCCUPIED}" ]]; then
            log_err "【原因诊断: 8080 端口冲突】检测到宿主机 8080 端口已被其他进程占用："
            echo -e "${YELLOW}${PORT_8080_OCCUPIED}${NC}"
            echo -e "CrowdSec 默认使用 8080 端口作为 LAPI 服务，如果已被占用，会导致启动失败。"
        fi
        echo ""
        journalctl -u crowdsec -n 12 --no-pager 2>/dev/null || true
        echo ""
        read -r -p "按回车键返回主菜单..." _
        return
    fi

    # 动态探测当前 CrowdSec LAPI 真实监听端口
    LAPI_PORT="8080"
    if [[ -f "/etc/crowdsec/config.yaml" ]]; then
        DETECTED_LAPI_PORT=$(grep -E "listen_uri:" /etc/crowdsec/config.yaml 2>/dev/null | awk '{print $2}' | awk -F':' '{print $NF}' | tr -cd '0-9' || true)
        if [[ -n "${DETECTED_LAPI_PORT}" ]]; then
            LAPI_PORT="${DETECTED_LAPI_PORT}"
        fi
    fi
    log_info "检测到 CrowdSec LAPI 端口为: ${LAPI_PORT}"

    echo ""
    read -r -p "请输入 WebUI 网页访问端口 [默认: 3000]: " WEBUI_PORT
    WEBUI_PORT="${WEBUI_PORT:-3000}"

    mkdir -p "${WEBUI_DIR}/data"

    # 创建/注册 Machine 账号 (生成纯字母数字的安全 ID 与密码)
    RAND_SUFFIX=$(head /dev/urandom 2>/dev/null | tr -dc 'a-z0-9' | head -c 6 || echo "ui1")
    MACHINE_ID="webui-${RAND_SUFFIX}"
    MACHINE_PWD=$(head /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 20 || echo "SecretPass987654")

    log_info "正在向 CrowdSec LAPI 注册独立 Machine 凭据 (用户名: ${MACHINE_ID})..."
    
    # 尝试注册，指定独立凭据文件路径 -f，严禁覆盖宿主机自身的 /etc/crowdsec/local_api_credentials.yaml
    ADD_ERR=""
    WEBUI_CRED_FILE="${WEBUI_DIR}/data/webui_api_credentials.yaml"
    if ! ADD_ERR=$(cscli machines add "${MACHINE_ID}" --password "${MACHINE_PWD}" -f "${WEBUI_CRED_FILE}" --force 2>&1); then
        log_err "创建 CrowdSec Machine 账号失败！cscli 详细错误信息如下:"
        echo -e "${RED}${ADD_ERR}${NC}"
        echo ""
        read -r -p "按回车键返回..." _
        return
    fi

    log_succ "Machine 凭据注册成功: 用户名=${MACHINE_ID}"

    # 自动开启 CrowdSec full 级别 Prometheus 指标并重启核心服务以监听 6060 端口
    enable_prometheus_metrics
    systemctl restart crowdsec || true
    sleep 2

    # 生成 Docker Compose 配置文件
    cat << EOF > "${WEBUI_DIR}/docker-compose.yml"
services:
  crowdsec-web-ui:
    image: ghcr.io/theduffman85/crowdsec-web-ui:latest
    container_name: crowdsec-web-ui
    restart: always
    network_mode: host
    environment:
      CONFIG_INSTANCE_LAPI_URL: "http://127.0.0.1:${LAPI_PORT}"
      CONFIG_INSTANCE_LAPI_AUTH_USERNAME: "${MACHINE_ID}"
      CONFIG_INSTANCE_LAPI_AUTH_PASSWORD: "${MACHINE_PWD}"
      CONFIG_INSTANCE_METRICS_URL: "http://127.0.0.1:6060/metrics"
      CONFIG_SERVER_PORT: "${WEBUI_PORT}"
      CONFIG_UI_TIME_ZONE: "Asia/Shanghai"
      CONFIG_UPDATES_ENABLED: "true"
    volumes:
      - ${WEBUI_DIR}/data:/app/data
EOF

    log_info "正在拉取并启动 crowdsec-web-ui 容器..."
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "${WEBUI_DIR}/docker-compose.yml" up -d --remove-orphans || true
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "${WEBUI_DIR}/docker-compose.yml" up -d --remove-orphans || true
    else
        docker run -d \
          --name crowdsec-web-ui \
          --restart always \
          --network host \
          -e CONFIG_INSTANCE_LAPI_URL="http://127.0.0.1:${LAPI_PORT}" \
          -e CONFIG_INSTANCE_LAPI_AUTH_USERNAME="${MACHINE_ID}" \
          -e CONFIG_INSTANCE_LAPI_AUTH_PASSWORD="${MACHINE_PWD}" \
          -e CONFIG_INSTANCE_METRICS_URL="http://127.0.0.1:6060/metrics" \
          -e CONFIG_SERVER_PORT="${WEBUI_PORT}" \
          -e CONFIG_UI_TIME_ZONE="Asia/Shanghai" \
          -v "${WEBUI_DIR}/data:/app/data" \
          ghcr.io/theduffman85/crowdsec-web-ui:latest || true
    fi

    # 获取本机公网 IP
    detect_admin_ip
    SERVER_IP=$(curl -s --max-time 2 https://api.ipify.org 2>/dev/null || echo "你的VPS公网IP")

    echo ""
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}             🎉 CrowdSec WebUI 部署成功！                       ${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "访问地址: ${CYAN}http://${SERVER_IP}:${WEBUI_PORT}${NC}"
    echo ""
    echo -e "${YELLOW}⚠️ 【安全避坑特别警告】:${NC}"
    echo -e "  该 WebUI 默认未内置登录密码页面！"
    echo -e "  强烈建议在 ${BOLD}1Panel 网站反代${NC} 或 ${BOLD}科技lion NPM${NC} 中为其配置反向代理，"
    echo -e "  并开启 ${BOLD}Basic Auth（密码认证）${NC}，切勿直接让该端口在公网裸奔！"
    echo -e "${GREEN}================================================================${NC}"
    echo ""
    read -r -p "按回车键返回..." _
}

uninstall_web_ui() {
    log_warn "正在停止并删除 crowdsec-web-ui 容器..."
    docker stop crowdsec-web-ui >/dev/null 2>&1 || true
    docker rm crowdsec-web-ui >/dev/null 2>&1 || true
    rm -rf "${WEBUI_DIR}"
    log_succ "CrowdSec WebUI 已彻底卸载！"
    read -r -p "按回车键返回..." _
}

reset_webui_credentials() {
    deploy_web_ui
}

# ------------------------------------------------------------------------------
# 4. WAF 与场景规则库中心 (精选推荐安装)
# ------------------------------------------------------------------------------
manage_waf_rules() {
    clear
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo -e "${CYAN}${BOLD}             [3] WAF 与场景防御规则库中心                       ${NC}"
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo ""
    echo -e " ${BOLD}1.${NC} 【一键装配】终极 Web 站点 WAF 增强套件 (推荐所有网站安装)"
    echo -e "      (包含: HTTP-CVE漏洞拦截, 通用SQLi/XSS/路径穿越, 爬虫扫描, 虚拟补丁)"
    echo -e " ${BOLD}2.${NC} 【扩展防护】WordPress 专属加固套件 (WP爆破/xmlrpc/插件漏洞)"
    echo -e " ${BOLD}3.${NC} 【网络层】端口扫描与恶意探测防护套件 (Portscan & iptables扫描)"
    echo -e " ${BOLD}4.${NC} 查看当前已安装的规则集合列表 (cscli collections list)"
    echo -e " ${BOLD}5.${NC} 立即检查并升级所有已安装规则 (cscli hub upgrade)"
    echo -e " ${BOLD}0.${NC} 返回主菜单"
    echo ""
    read -r -p "请选择操作 [0-5]: " waf_choice

    case "${waf_choice}" in
        1)
            auto_heal_broken_parsers
            log_info "正在安装【终极 Web 站点 WAF 增强套件】..."
            cscli collections install crowdsecurity/nginx || true
            cscli collections install crowdsecurity/nginx-proxy-manager || true
            cscli collections install crowdsecurity/http-cve || true
            cscli collections install crowdsecurity/base-http-scenarios || true
            cscli collections install crowdsecurity/whitelist-good-actors || true
            systemctl reload crowdsec || true
            log_succ "Web WAF 规则库装配完毕，规则已热加载！"
            read -r -p "按回车键继续..." _
            ;;
        2)
            auto_heal_broken_parsers
            log_info "正在安装【WordPress 专属加固套件】..."
            cscli collections install crowdsecurity/wordpress || true
            systemctl reload crowdsec || true
            log_succ "WordPress 场景防护规则已安装！"
            read -r -p "按回车键继续..." _
            ;;
        3)
            auto_heal_broken_parsers
            log_info "正在安装【网络扫描与探测阻断套件】..."
            cscli collections install crowdsecurity/iptables || true
            cscli collections install crowdsecurity/portscan || true
            systemctl reload crowdsec || true
            log_succ "网络层扫描防护规则已安装！"
            read -r -p "按回车键继续..." _
            ;;
        4)
            echo ""
            cscli collections list || true
            echo ""
            read -r -p "按回车键继续..." _
            ;;
        5)
            auto_heal_broken_parsers
            log_info "正在从 CrowdSec Hub 同步更新最新威胁特征..."
            cscli hub update || true
            cscli hub upgrade || true
            systemctl reload crowdsec || true
            log_succ "所有规则库已升级至最新版本！"
            read -r -p "按回车键继续..." _
            ;;
        *) return ;;
    esac
}

# ------------------------------------------------------------------------------
# 5. 每日定时自动更新配置 (Crontab / Systemd)
# ------------------------------------------------------------------------------
manage_auto_update() {
    clear
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}             [4] 每日定时自动更新设置 (Hub 规则 + 威胁名单)     ${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo ""
    if [[ -f "${CRON_FILE}" ]]; then
        echo -e "当前状态: ${GREEN}${BOLD}已开启每日自动更新${NC}"
        echo -e "定时配置: ${CYAN}$(cat "${CRON_FILE}" 2>/dev/null | grep -v '^#' | tr -d '\n')${NC}"
    else
        echo -e "当前状态: ${YELLOW}未开启每日定时任务${NC}"
    fi
    echo ""
    echo -e " ${BOLD}1.${NC} 开启/更新 每日凌晨 03:30 自动更新 (推荐)"
    echo -e "      (自动同步 Hub 场景库、更新 CAPI 社区黑名单、热重载服务)"
    echo -e " ${BOLD}2.${NC} 自定义每日更新时间"
    echo -e " ${BOLD}3.${NC} 关闭每日自动更新"
    echo -e " ${BOLD}0.${NC} 返回主菜单"
    echo ""
    read -r -p "请选择操作 [0-3]: " cron_choice

    case "${cron_choice}" in
        1)
            cat << 'EOF' > "${CRON_FILE}"
# CrowdSec 每日规则库与黑名单自动同步
30 3 * * * root /usr/bin/cscli hub update >/dev/null 2>&1 && /usr/bin/cscli hub upgrade >/dev/null 2>&1 && /bin/systemctl reload crowdsec >/dev/null 2>&1
EOF
            chmod 644 "${CRON_FILE}"
            log_succ "已设置每日凌晨 03:30 自动更新！"
            read -r -p "按回车键继续..." _
            ;;
        2)
            read -r -p "请输入每天执行的分钟 (0-59) [默认 30]: " cron_m
            read -r -p "请输入每天执行的小时 (0-23) [默认 4]: " cron_h
            cron_m="${cron_m:-30}"
            cron_h="${cron_h:-4}"
            cat << EOF > "${CRON_FILE}"
# CrowdSec 每日规则库与黑名单自动同步
${cron_m} ${cron_h} * * * root /usr/bin/cscli hub update >/dev/null 2>&1 && /usr/bin/cscli hub upgrade >/dev/null 2>&1 && /bin/systemctl reload crowdsec >/dev/null 2>&1
EOF
            chmod 644 "${CRON_FILE}"
            log_succ "已设置为每天 ${cron_h}:${cron_m} 自动执行更新！"
            read -r -p "按回车键继续..." _
            ;;
        3)
            rm -f "${CRON_FILE}"
            log_succ "已关闭每日自动更新。"
            read -r -p "按回车键继续..." _
            ;;
        *) return ;;
    esac
}

# ------------------------------------------------------------------------------
# 6. 防火墙与黑名单日常运维
# ------------------------------------------------------------------------------
manage_firewall_ops() {
    clear
    echo -e "${YELLOW}${BOLD}================================================================${NC}"
    echo -e "${YELLOW}${BOLD}             [5] 防火墙黑名单与日常运维管理                     ${NC}"
    echo -e "${YELLOW}${BOLD}================================================================${NC}"
    echo ""
    echo -e " ${BOLD}1.${NC} 查看当前活跃封禁黑名单 (cscli decisions list)"
    echo -e " ${BOLD}2.${NC} 查看最新攻击拦截警报日志 (cscli alerts list)"
    echo -e " ${BOLD}3.${NC} 手动解封某个 IP (cscli decisions delete --ip ...)"
    echo -e " ${BOLD}4.${NC} 手动封禁某个恶意 IP (cscli decisions add --ip ...)"
    echo -e " ${BOLD}5.${NC} 查看内核拦截底层状态 (nft list table inet crowdsec)"
    echo -e " ${BOLD}6.${NC} 查看日志解析度量与计数 (cscli metrics)"
    echo -e " ${BOLD}0.${NC} 返回主菜单"
    echo ""
    read -r -p "请选择操作 [0-6]: " ops_choice

    case "${ops_choice}" in
        1)
            echo ""
            cscli decisions list 2>/dev/null || log_warn "当前暂无活跃封禁记录或服务未就绪"
            echo ""
            read -r -p "按回车键继续..." _
            ;;
        2)
            echo ""
            cscli alerts list --limit 20 2>/dev/null || cscli alerts list -l 20 2>/dev/null || cscli alerts list 2>/dev/null || true
            echo ""
            read -r -p "按回车键继续..." _
            ;;
        3)
            read -r -p "请输入需要解封的 IP 地址: " unban_ip
            if [[ -n "${unban_ip}" ]]; then
                cscli decisions delete --ip "${unban_ip}" 2>/dev/null || cscli decisions delete -i "${unban_ip}" 2>/dev/null || log_warn "未找到针对该 IP 的封禁决策"
                log_succ "解封操作执行完毕！"
            fi
            read -r -p "按回车键继续..." _
            ;;
        4)
            read -r -p "请输入需要封禁的 IP 地址: " ban_ip
            read -r -p "请输入封禁时长 (如 4h, 24h, 7d) [默认 24h]: " ban_time
            read -r -p "请输入封禁原因说明 [默认 '手动封禁']: " ban_reason
            ban_time="${ban_time:-24h}"
            ban_reason="${ban_reason:-手动封禁}"
            if [[ -n "${ban_ip}" ]]; then
                cscli decisions add --ip "${ban_ip}" --duration "${ban_time}" --reason "${ban_reason}" --type ban 2>/dev/null || \
                cscli decisions add -i "${ban_ip}" -d "${ban_time}" -R "${ban_reason}" -t ban 2>/dev/null || log_warn "添加封禁失败，请检查参数"
                log_succ "IP ${ban_ip} 已加入内核黑名单！"
            fi
            read -r -p "按回车键继续..." _
            ;;
        5)
            echo ""
            if command -v nft >/dev/null 2>&1; then
                nft list table inet crowdsec 2>/dev/null || iptables -L -n -v 2>/dev/null | grep -E "crowdsec|CROWDSEC" || echo "未找到活动中的 crowdsec 防火墙表/链"
            else
                iptables -L -n -v 2>/dev/null | grep -E "crowdsec|CROWDSEC" || echo "未找到 iptables crowdsec 链"
            fi
            echo ""
            read -r -p "按回车键继续..." _
            ;;
        6)
            echo ""
            cscli metrics 2>/dev/null || true
            echo ""
            read -r -p "按回车键继续..." _
            ;;
        *) return ;;
    esac
}

# ------------------------------------------------------------------------------
# 7. 绑定 CrowdSec 官方 Console 云端大屏
# ------------------------------------------------------------------------------
bind_crowdsec_console() {
    clear
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo -e "${CYAN}${BOLD}       [6] 绑定 CrowdSec Console 官方云端控制台                 ${NC}"
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo ""
    echo -e "CrowdSec Console (${CYAN}https://app.crowdsec.net${NC}) 是官方免费提供的云端控制台："
    echo -e "  - 0 内存开销，提供全球攻击态势大屏、威胁信誉查询"
    echo -e "  - 支持多台 VPS 统一管理与跨机协同"
    echo ""
    read -r -p "请输入在 app.crowdsec.net 获取的 Enrollment Key (Token): " console_token
    if [[ -n "${console_token}" ]]; then
        cscli console enroll "${console_token}" 2>&1 || true
        systemctl restart crowdsec || true
        log_succ "已提交绑定！若 Token 有效，数据将在几分钟内同步上报至控制台。"
    else
        log_warn "输入为空，取消绑定。"
    fi
    read -r -p "按回车键继续..." _
}

# ------------------------------------------------------------------------------
# 8. Telegram 告警推送与取证优化中心
# ------------------------------------------------------------------------------
setup_telegram_notification() {
    echo ""
    echo -e "${PURPLE}${BOLD}--- [配置 Telegram 实时告警推送机器人] ---${NC}"
    read -r -p "请输入 Telegram Bot Token (形如 123456:ABC-DEF...): " TG_BOT_TOKEN
    read -r -p "请输入接收告警的 Chat ID (个人ID或群组负数ID): " TG_CHAT_ID
    read -r -p "请输入 Telegram API 端点 [默认: https://api.telegram.org]: " TG_API_HOST
    TG_API_HOST="${TG_API_HOST:-https://api.telegram.org}"
    TG_API_HOST="${TG_API_HOST%/}"

    if [[ -z "${TG_BOT_TOKEN}" || -z "${TG_CHAT_ID}" ]]; then
        log_err "Bot Token 或 Chat ID 不能为空！"
        read -r -p "按回车键返回..." _
        return
    fi

    mkdir -p /etc/crowdsec/notifications/
    mkdir -p /etc/crowdsec/parsers/s02-enrich/

    # 1. 部署自适应全场景穿透取证模板
    log_info "正在写入 Telegram 自适应穿透取证通知配置..."
    cat << EOF > "${TG_NOTIF_FILE}"
type: http
name: http_default
log_level: info

format: |
  {
    "chat_id": "${TG_CHAT_ID}",
    "parse_mode": "HTML",
    "text": "{{range . -}}🚨 <b>【CrowdSec 威胁拦截警报】</b>\n━━━━━━━━━━━━━━━━━━\n🌐 <b>攻击来源:</b> <code>{{.Source.IP}}</code> ({{.Source.Cn}} {{.Source.AsName}})\n🛡️ <b>触发场景:</b> <code>{{.Scenario}}</code>\n⏱️ <b>封禁时长:</b> <code>{{(index .Decisions 0).Duration}}</code>\n\n📋 <b>【攻击穿透取证】:</b>\n{{- if or (contains .Scenario \"nginx\") (contains .Scenario \"http\") (contains .Scenario \"wordpress\") }}\n🎯 <b>刺探目标:</b> <code>{{ index .Meta \"http_path\" | default (index .Meta \"target_uri\" | default \"全站探测/批量扫描\") }}</code>\n🤖 <b>客户端指纹:</b> <code>{{ index .Meta \"http_user_agent\" | default \"无 UA (裸脚本/扫描器特征)\" }}</code>\n{{- else if contains .Scenario \"ssh\" }}\n🔑 <b>攻击服务:</b> <code>SSH 登录爆破 (端口 22)</code>\n👤 <b>尝试用户名:</b> <code>{{ index .Meta \"target_user\" | default \"未知用户\" }}</code>\n{{- else }}\n⚡ <b>攻击类型:</b> <code>系统/网络层恶意行为</code>\n{{- end }}\n━━━━━━━━━━━━━━━━━━\n<i>由 1Panel & CrowdSec 内核级防火墙自动防御</i>{{end -}}"
  }

url: ${TG_API_HOST}/bot${TG_BOT_TOKEN}/sendMessage
method: POST
headers:
  Content-Type: "application/json"
EOF
    chmod 600 "${TG_NOTIF_FILE}"

    # 2. 联动 profiles.yaml 激活通知
    if [[ -f "${PROFILES_FILE}" ]]; then
        if grep -q "notifications:" "${PROFILES_FILE}"; then
            if ! grep -q "http_default" "${PROFILES_FILE}"; then
                sed -i '/notifications:/a\  - http_default' "${PROFILES_FILE}"
            fi
        else
            sed -i '/duration:/a\notifications:\n  - http_default' "${PROFILES_FILE}"
        fi
    fi

    # 3. 部署合法的 Telegram Webhook/API 官方白名单
    cat << 'EOF' > "${TG_WHITELIST_FILE}"
name: custom/telegram-whitelist
description: "Whitelist Telegram official IP ranges"
whitelist:
  reason: "Telegram bot webhook official CIDR"
  cidr:
    - "149.154.160.0/20"
    - "91.108.4.0/22"
    - "91.108.8.0/22"
    - "91.108.12.0/22"
    - "91.108.16.0/22"
    - "91.108.20.0/22"
    - "91.108.56.0/22"
EOF

    # 4. 校验配置并重启
    crowdsec -t || true
    systemctl restart crowdsec || true
    log_succ "Telegram 告警配置已成功写入并热加载生效！"

    # 5. 询问是否立即发送测试通知
    read -r -p "是否现在发送一条测试通知检验 Telegram 推送是否畅通? [Y/n]: " do_test
    if [[ ! "${do_test}" =~ ^[nN]$ ]]; then
        test_telegram_notification
    else
        read -r -p "按回车键继续..." _
    fi
}

test_telegram_notification() {
    echo ""
    log_info "正在检验当前 Telegram 配置并尝试发送测试消息..."
    if [[ ! -f "${TG_NOTIF_FILE}" ]]; then
        log_err "未找到 Telegram 配置文件 (${TG_NOTIF_FILE})，请先选择 [1] 进行配置！"
        read -r -p "按回车键继续..." _
        return
    fi

    local TG_BOT_TOKEN
    local TG_CHAT_ID
    local TG_API_HOST

    TG_BOT_TOKEN=$(grep -oE "bot[0-9]+:[A-Za-z0-9_-]+" "${TG_NOTIF_FILE}" 2>/dev/null | sed 's/^bot//' || true)
    TG_CHAT_ID=$(grep -oE '"chat_id":\s*"[^"]+"' "${TG_NOTIF_FILE}" 2>/dev/null | cut -d'"' -f4 || true)
    TG_API_HOST=$(grep -oE "https://[^/]+/bot" "${TG_NOTIF_FILE}" 2>/dev/null | sed 's|/bot$||' || echo "https://api.telegram.org")

    if [[ -z "${TG_BOT_TOKEN}" || -z "${TG_CHAT_ID}" ]]; then
        log_err "无法从 ${TG_NOTIF_FILE} 中提取有效的 Token 或 Chat ID！"
        read -r -p "按回车键继续..." _
        return
    fi

    log_info "目标端点: ${TG_API_HOST} | Chat ID: ${TG_CHAT_ID}"
    local TEST_PAYLOAD
    TEST_PAYLOAD=$(cat << EOF
{
  "chat_id": "${TG_CHAT_ID}",
  "parse_mode": "HTML",
  "text": "🎉 <b>【CrowdSec 告警通道测试成功】</b>\n━━━━━━━━━━━━━━━━━━\n恭喜！你的 Telegram 告警机器人配置准确无误。\n\n<b>【取证特性】:</b>\n✅ Web 攻击: 实时提取 URL 刺探目标与客户端指纹\n✅ SSH 攻击: 智能展示爆破用户名与端口，告别未知路径\n✅ 内核拦截: 毫秒级阻断并推送通知"
}
EOF
)

    local RESP
    RESP=$(curl -s -m 10 -X POST "${TG_API_HOST}/bot${TG_BOT_TOKEN}/sendMessage" \
      -H "Content-Type: application/json" \
      -d "${TEST_PAYLOAD}" 2>&1 || true)

    if echo "${RESP}" | grep -q '"ok":true'; then
        log_succ "测试消息推送成功！请检查你的 Telegram 是否已经收到来自机器人的测试消息。"
    else
        log_err "测试消息发送失败！Telegram API 返回结果如下:"
        echo -e "${RED}${RESP}${NC}"
        echo ""
        log_warn "排错提示:"
        echo -e "  1. 若提示 'Unauthorized': 说明 Bot Token 填写错误。"
        echo -e "  2. 若提示 'chat not found': 请确保你的 Telegram 账号已经主动给该 Bot 发送过至少一条消息 (/start)。"
        echo -e "  3. 若网络超时: 说明国内 VPS 无法直连 api.telegram.org，需在配置中填写 TG 反代域名。"
    fi
    read -r -p "按回车键继续..." _
}

check_telegram_settings() {
    clear
    echo -e "${PURPLE}${BOLD}================================================================${NC}"
    echo -e "${PURPLE}${BOLD}           🔍 Telegram 告警配置深度体检与健康诊断               ${NC}"
    echo -e "${PURPLE}${BOLD}================================================================${NC}"
    echo ""

    local PASS_COUNT=0

    # 1. 检查 http.yaml
    if [[ -f "${TG_NOTIF_FILE}" ]]; then
        echo -e "  [✔] 告警配置文件存在: ${GREEN}${TG_NOTIF_FILE}${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "  [✘] 告警配置文件不存在: ${RED}${TG_NOTIF_FILE}${NC}"
    fi

    # 2. 检查 profiles.yaml 关联
    if [[ -f "${PROFILES_FILE}" ]] && grep -q "http_default" "${PROFILES_FILE}" 2>/dev/null; then
        echo -e "  [✔] Profiles 策略关联: ${GREEN}已绑定 http_default 触发通道${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "  [✘] Profiles 策略关联: ${YELLOW}未检测到 http_default 关联，告警将不会触发推送${NC}"
    fi

    # 3. 检查白名单语法
    if [[ -f "${TG_WHITELIST_FILE}" ]]; then
        if grep -q "custom/telegram-whitelist" "${TG_WHITELIST_FILE}" 2>/dev/null; then
            echo -e "  [✔] Telegram 回源白名单: ${GREEN}语法规范正常 (已放行官方 IP 范围)${NC}"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo -e "  [!] Telegram 回源白名单: ${YELLOW}已存在但名称非标准${NC}"
        fi
    else
        echo -e "  [!] Telegram 回源白名单: ${YELLOW}未建立回源白名单 (可能增加误杀风险)${NC}"
    fi

    # 4. 检查网络连通性
    local TG_API_HOST
    TG_API_HOST=$(grep -oE "https://[^/]+/bot" "${TG_NOTIF_FILE}" 2>/dev/null | sed 's|/bot$||' || echo "https://api.telegram.org")
    if curl -s -m 5 -I "${TG_API_HOST}" >/dev/null 2>&1; then
        echo -e "  [✔] Telegram 端点连通性: ${GREEN}网络正常访问 (${TG_API_HOST})${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "  [✘] Telegram 端点连通性: ${RED}网络连接超时 (${TG_API_HOST})${NC}"
    fi

    echo ""
    echo -e "体检评分: ${BOLD}${PASS_COUNT}/4 项通过${NC}"
    echo ""
    read -r -p "按回车键继续..." _
}

disable_telegram_notification() {
    log_warn "正在关闭 Telegram 告警推送..."
    if [[ -f "${PROFILES_FILE}" ]]; then
        sed -i '/http_default/d' "${PROFILES_FILE}" 2>/dev/null || true
    fi
    if [[ -f "${TG_NOTIF_FILE}" ]]; then
        mv "${TG_NOTIF_FILE}" "${TG_NOTIF_FILE}.bak" 2>/dev/null || true
    fi
    systemctl restart crowdsec || true
    log_succ "Telegram 告警推送已彻底停用并重载！"
    read -r -p "按回车键继续..." _
}

manage_telegram() {
    while true; do
        clear
        echo -e "${PURPLE}${BOLD}================================================================${NC}"
        echo -e "${PURPLE}${BOLD}          📱 Telegram 实时告警推送与智能穿透取证中心            ${NC}"
        echo -e "${PURPLE}${BOLD}================================================================${NC}"
        echo ""
        
        # 探测当前配置状态
        local TG_STATUS="${YELLOW}未配置${NC}"
        local CURRENT_BOT_TOKEN=""
        local CURRENT_CHAT_ID=""
        local CURRENT_API_HOST="https://api.telegram.org"
        
        if [[ -f "${TG_NOTIF_FILE}" ]] && grep -q "api.telegram.org\|bot" "${TG_NOTIF_FILE}" 2>/dev/null; then
            CURRENT_BOT_TOKEN=$(grep -oE "bot[0-9]+:[A-Za-z0-9_-]+" "${TG_NOTIF_FILE}" 2>/dev/null | sed 's/^bot//' || true)
            CURRENT_CHAT_ID=$(grep -oE '"chat_id":\s*"[^"]+"' "${TG_NOTIF_FILE}" 2>/dev/null | cut -d'"' -f4 || true)
            CURRENT_API_HOST=$(grep -oE "https://[^/]+/bot" "${TG_NOTIF_FILE}" 2>/dev/null | sed 's|/bot$||' || echo "https://api.telegram.org")
            
            if [[ -n "${CURRENT_BOT_TOKEN}" && -n "${CURRENT_CHAT_ID}" ]]; then
                if grep -q "http_default" "${PROFILES_FILE}" 2>/dev/null; then
                    TG_STATUS="${GREEN}${BOLD}已启用并在 profiles.yaml 联动生效${NC}"
                else
                    TG_STATUS="${YELLOW}已配置但未在 profiles.yaml 中激活${NC}"
                fi
            fi
        fi

        echo -e "当前状态: ${TG_STATUS}"
        if [[ -n "${CURRENT_BOT_TOKEN}" ]]; then
            local MASKED_TOKEN="${CURRENT_BOT_TOKEN:0:6}******${CURRENT_BOT_TOKEN: -4}"
            echo -e "机器人Token: ${CYAN}${MASKED_TOKEN}${NC}"
            echo -e "推送Chat ID: ${CYAN}${CURRENT_CHAT_ID}${NC}"
            echo -e "API 端点:   ${CYAN}${CURRENT_API_HOST}${NC}"
        fi
        echo ""
        echo -e " ${BOLD}1.${NC} 配置 / 重新绑定 Telegram 告警机器人 (自动部署自适应取证模板)"
        echo -e " ${BOLD}2.${NC} 发送即时测试通知 (全面诊断 Token、Chat ID 与网络连通性)"
        echo -e " ${BOLD}3.${NC} 深度体检相关配置是否准确 (检查语法、Profiles绑定、回源白名单)"
        echo -e " ${BOLD}4.${NC} 关闭 / 卸载 Telegram 告警推送"
        echo -e " ${BOLD}0.${NC} 返回主菜单"
        echo ""
        read -r -p "请选择操作 [0-4]: " tg_choice

        case "${tg_choice}" in
            1) setup_telegram_notification ;;
            2) test_telegram_notification ;;
            3) check_telegram_settings ;;
            4) disable_telegram_notification ;;
            0) return ;;
            *)
                log_warn "无效选项，请重新输入！"
                sleep 1
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# 9. 综合状态健康检查
# ------------------------------------------------------------------------------
check_health_status() {
    clear
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo -e "${BLUE}${BOLD}             系统状态与配置健康检查                             ${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo ""
    echo -e "【1. 核心进程状态】:"
    systemctl status crowdsec --no-pager 2>/dev/null | head -n 8 || true
    echo ""
    echo -e "【2. Firewall Bouncer 状态】:"
    if systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null; then
        systemctl status crowdsec-firewall-bouncer --no-pager 2>/dev/null | head -n 8 || true
    elif systemctl is-active --quiet crowdsec-firewall-bouncer-nftables 2>/dev/null; then
        systemctl status crowdsec-firewall-bouncer-nftables --no-pager 2>/dev/null | head -n 8 || true
    elif systemctl is-active --quiet crowdsec-firewall-bouncer-iptables 2>/dev/null; then
        systemctl status crowdsec-firewall-bouncer-iptables --no-pager 2>/dev/null | head -n 8 || true
    else
        systemctl status crowdsec-firewall-bouncer* --no-pager 2>/dev/null | head -n 8 || log_warn "未找到运行中的 Bouncer 服务！"
    fi
    echo ""
    echo -e "【3. Bouncer 注册节点】:"
    cscli bouncers list 2>/dev/null || true
    echo ""
    echo -e "【4. 本地 WebUI 容器状态】:"
    if docker ps -a 2>/dev/null | grep -q "crowdsec-web-ui"; then
        docker ps -f name=crowdsec-web-ui --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
    else
        echo "未部署本地 crowdsec-web-ui 容器"
    fi
    echo ""
    echo -e "【5. 语法静态校验 (crowdsec -t)】:"
    crowdsec -t 2>&1 || true
    echo ""
    read -r -p "按回车键返回主菜单..." _
}

# ------------------------------------------------------------------------------
# 10. 卸载清理模块
# ------------------------------------------------------------------------------
uninstall_crowdsec_all() {
    clear
    echo -e "${RED}${BOLD}================================================================${NC}"
    echo -e "${RED}${BOLD}             完全卸载 CrowdSec 防护套件                         ${NC}"
    echo -e "${RED}${BOLD}================================================================${NC}"
    echo ""
    log_warn "此操作将停用并卸载 CrowdSec 引擎、Bouncer 防火墙、本地 WebUI、Telegram 配置及全部规则！"
    read -r -p "确定要彻底卸载吗? [y/N]: " confirm_uninstall
    if [[ ! "${confirm_uninstall}" =~ ^[yY]$ ]]; then
        log_info "用户取消卸载。"
        read -r -p "按回车键返回..." _
        return
    fi

    # 停止容器
    if docker ps -a 2>/dev/null | grep -q "crowdsec-web-ui"; then
        docker stop crowdsec-web-ui >/dev/null 2>&1 || true
        docker rm crowdsec-web-ui >/dev/null 2>&1 || true
    fi
    rm -rf "${WEBUI_DIR}" "${CRON_FILE}"

    # 停止服务并卸载软件包
    systemctl stop crowdsec crowdsec-firewall-bouncer* 2>/dev/null || true
    systemctl disable crowdsec crowdsec-firewall-bouncer* 2>/dev/null || true

    if [[ "${OS_ID}" =~ ^(debian|ubuntu)$ ]]; then
        apt-get remove --purge -y crowdsec crowdsec-firewall-bouncer* 2>/dev/null || true
    else
        yum remove -y crowdsec crowdsec-firewall-bouncer* 2>/dev/null || true
    fi

    rm -rf /etc/crowdsec /var/lib/crowdsec
    log_succ "CrowdSec 及相关组件已从系统中完全移除。"
    read -r -p "按回车键返回主菜单..." _
}

# ------------------------------------------------------------------------------
# 自动探测并自愈损坏的自定义白名单与解析器 (Auto-Heal Broken YAMLs)
# ------------------------------------------------------------------------------
auto_heal_broken_parsers() {
    # 针对 tg-whitelist.yaml 的专项自动检测与修复
    if [[ -f "${TG_WHITELIST_FILE}" ]]; then
        local CHECK_TG
        CHECK_TG=$(crowdsec -t 2>&1 || true)
        if echo "${CHECK_TG}" | grep -q "failed to parse ${TG_WHITELIST_FILE}"; then
            log_warn "检测到 tg-whitelist.yaml 语法损坏，正在自动校准为标准 YAML 语法..."
            cat << 'EOF' > "${TG_WHITELIST_FILE}"
name: custom/telegram-whitelist
description: "Whitelist Telegram official IP ranges"
whitelist:
  reason: "Telegram bot webhook official CIDR"
  cidr:
    - "149.154.160.0/20"
    - "91.108.4.0/22"
    - "91.108.8.0/22"
    - "91.108.12.0/22"
    - "91.108.16.0/22"
    - "91.108.20.0/22"
    - "91.108.56.0/22"
EOF
            log_succ "已自动修复 tg-whitelist.yaml 语法格式！"
        fi
    fi

    # 通用容错：如果依然存在任何阻断性 YAML 错误，安全隔离为 .broken.bak
    local TEST_CHECK
    TEST_CHECK=$(crowdsec -t 2>&1 || true)
    if echo "${TEST_CHECK}" | grep -q "failed to parse /etc/crowdsec/parsers/s02-enrich/"; then
        local FAULTY_FILE
        FAULTY_FILE=$(echo "${TEST_CHECK}" | grep -oE "/etc/crowdsec/parsers/s02-enrich/[^:]+\.ya?ml" | head -n 1 || true)
        if [[ -n "${FAULTY_FILE}" && -f "${FAULTY_FILE}" ]]; then
            log_warn "发现无法解析的白名单文件: ${FAULTY_FILE}，已安全隔离为 .broken.bak 避免引擎崩溃..."
            mv "${FAULTY_FILE}" "${FAULTY_FILE}.broken.bak"
        fi
    fi
}

# ------------------------------------------------------------------------------
# 智能环境诊断与全方位深度调优引擎 (Smart Audit & Optimization)
# ------------------------------------------------------------------------------
smart_audit_and_optimize() {
    clear
    echo -e "${PURPLE}${BOLD}================================================================${NC}"
    echo -e "${PURPLE}${BOLD}       🔍 CrowdSec 智能环境诊断与全方位性能/规则深度调优          ${NC}"
    echo -e "${PURPLE}${BOLD}================================================================${NC}"
    echo ""
    auto_heal_broken_parsers
    log_info "正在对当前 VPS 系统架构、运行服务、日志链路及 CrowdSec 引擎进行全方位体检..."
    echo ""

    # 1. 资源检测
    TOTAL_RAM_MB=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo "0")
    FREE_RAM_MB=$(free -m 2>/dev/null | awk '/Mem:/ {print $7}' || echo "0")
    CPU_CORES=$(nproc 2>/dev/null || echo "1")
    DISK_AVAIL=$(df -h / 2>/dev/null | awk 'NR==2 {print $4}' || echo "未知")

    # 2. 检测运行中的 Web 栈
    DETECT_1PANEL=false
    DETECT_NPM=false
    DETECT_LDNMP=false
    DETECT_HOST_NGINX=false
    DETECT_WORDPRESS=false

    if docker ps 2>/dev/null | grep -Eiq "1panel.*openresty" || [[ -d "/opt/1panel/apps/openresty" ]]; then
        DETECT_1PANEL=true
    fi
    if docker ps 2>/dev/null | grep -Eiq "nginx-proxy-manager|npm" || [[ -d "/home/docker/npm" ]] || [[ -d "/data/logs" ]]; then
        DETECT_NPM=true
    fi
    if [[ -d "/home/web/log/nginx" ]]; then
        DETECT_LDNMP=true
    fi
    if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
        DETECT_HOST_NGINX=true
    fi
    if docker ps 2>/dev/null | grep -Eiq "wordpress" || [[ -d "/home/web/html" ]]; then
        DETECT_WORDPRESS=true
    fi

    # 3. 检查 SQLite WAL 模式
    DB_FILE="/var/lib/crowdsec/data/crowdsec.db"
    IS_WAL_MODE=false
    if [[ -f "${DB_FILE}" ]]; then
        DB_JOURNAL="delete"
        if command -v sqlite3 >/dev/null 2>&1; then
            DB_JOURNAL=$(sqlite3 "${DB_FILE}" "PRAGMA journal_mode;" 2>/dev/null || echo "unknown")
        elif command -v python3 >/dev/null 2>&1; then
            DB_JOURNAL=$(python3 -c "import sqlite3; conn=sqlite3.connect('${DB_FILE}'); print(conn.execute('PRAGMA journal_mode;').fetchone()[0])" 2>/dev/null || echo "unknown")
        fi
        if [[ "${DB_JOURNAL,,}" == "wal" ]]; then
            IS_WAL_MODE=true
        fi
    fi

    # 4. 检查 Prometheus 与 Metrics 端点
    METRICS_READY=false
    if grep -q "level: full" /etc/crowdsec/config.yaml 2>/dev/null && ss -tulpn 2>/dev/null | grep -q ":6060"; then
        METRICS_READY=true
    fi

    # 5. 检查已安装规则集
    INSTALLED_COLLECTIONS=$(cscli collections list -o raw 2>/dev/null || echo "")
    HAS_NPM_COLLECTION=false
    HAS_WAF_COLLECTION=false
    HAS_WP_COLLECTION=false

    if echo "${INSTALLED_COLLECTIONS}" | grep -q "crowdsecurity/nginx-proxy-manager"; then
        HAS_NPM_COLLECTION=true
    fi
    if echo "${INSTALLED_COLLECTIONS}" | grep -q "crowdsecurity/http-cve"; then
        HAS_WAF_COLLECTION=true
    fi
    if echo "${INSTALLED_COLLECTIONS}" | grep -q "crowdsecurity/wordpress"; then
        HAS_WP_COLLECTION=true
    fi

    # 6. 检查自动更新定时任务
    HAS_AUTO_CRON=false
    if [[ -f "${CRON_FILE}" ]]; then
        HAS_AUTO_CRON=true
    fi

    # ---------------- 打印体检报告 ----------------
    echo -e "${BOLD}=================== [VPS 系统与组件诊断报告] ===================${NC}"
    echo -e "  硬件概况: CPU ${BOLD}${CPU_CORES}核${NC} | 内存 ${BOLD}${TOTAL_RAM_MB}MB${NC} (可用: ${FREE_RAM_MB}MB) | 磁盘可用: ${BOLD}${DISK_AVAIL}${NC}"
    
    echo -e "\n【运行环境检测】:"
    echo -e "  - 1Panel OpenResty: $( [[ "$DETECT_1PANEL" == "true" ]] && echo -e "${GREEN}已检测到运行${NC}" || echo -e "${YELLOW}未检测到${NC}" )"
    echo -e "  - Nginx Proxy Manager (NPM): $( [[ "$DETECT_NPM" == "true" ]] && echo -e "${GREEN}已检测到运行${NC}" || echo -e "${YELLOW}未检测到${NC}" )"
    echo -e "  - 科技lion LDNMP 站点: $( [[ "$DETECT_LDNMP" == "true" ]] && echo -e "${GREEN}已检测到运行${NC}" || echo -e "${YELLOW}未检测到${NC}" )"
    echo -e "  - WordPress 站点: $( [[ "$DETECT_WORDPRESS" == "true" ]] && echo -e "${GREEN}已检测到运行${NC}" || echo -e "${YELLOW}未检测到${NC}" )"

    echo -e "\n【性能与防御健康度评估】:"
    if [[ "$IS_WAL_MODE" == "true" ]]; then
        echo -e "  [✔] SQLite 引擎模式: ${GREEN}已启用 WAL 极速高并发写入模式${NC}"
    else
        echo -e "  [!] SQLite 引擎模式: ${YELLOW}当前为传统模式，高并发日志解析易引发锁库，推荐开启 WAL 模式 (提速 5-10 倍)${NC}"
    fi

    if [[ "$METRICS_READY" == "true" ]]; then
        echo -e "  [✔] Prometheus 运行时指标: ${GREEN}已启用 full 级全量指标 (端口: 6060)${NC}"
    else
        echo -e "  [!] Prometheus 运行时指标: ${YELLOW}未完全就绪，WebUI 无法展现全量组件吞吐图表${NC}"
    fi

    if [[ "$DETECT_NPM" == "true" && "$HAS_NPM_COLLECTION" == "false" ]]; then
        echo -e "  [!] NPM 规则完备性: ${YELLOW}检测到 NPM 运行，但缺少 crowdsecurity/nginx-proxy-manager 专有规则${NC}"
    else
        echo -e "  [✔] NPM 规则匹配: ${GREEN}正常${NC}"
    fi

    if [[ "$HAS_WAF_COLLECTION" == "true" ]]; then
        echo -e "  [✔] Web WAF 核心规则: ${GREEN}已装配 (HTTP-CVE / 通用 Web 攻击)${NC}"
    else
        echo -e "  [!] Web WAF 核心规则: ${YELLOW}缺少核心 Web 攻击防护规则${NC}"
    fi

    if [[ "$HAS_AUTO_CRON" == "true" ]]; then
        echo -e "  [✔] 威胁情报每日更新: ${GREEN}已启用自动定时更新${NC}"
    else
        echo -e "  [!] 威胁情报每日更新: ${YELLOW}未启用每日定时维护，特征库可能逐渐过时${NC}"
    fi
    echo -e "${BOLD}=================================================================${NC}"
    echo ""

    # 询问是否执行深度调优
    read -r -p "诊断完成！是否立即应用上述【最优性能与防御调优方案】? [Y/n]: " do_optimize
    if [[ "${do_optimize}" =~ ^[nN]$ ]]; then
        log_info "已取消调优操作。"
        read -r -p "按回车键返回主菜单..." _
        return
    fi

    echo ""
    log_info "正在执行系统级深度调优优化..."

    # 优化 1: 启用 SQLite WAL 高并发模式与自动碎片整理
    if [[ -f "${DB_FILE}" ]]; then
        log_info "1. 正在将 SQLite 升级为 WAL (Write-Ahead Logging) 极速并发模式..."
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "${DB_FILE}" "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; VACUUM;" >/dev/null 2>&1 || true
        elif command -v python3 >/dev/null 2>&1; then
            python3 -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
conn.execute('PRAGMA journal_mode=WAL;')
conn.execute('PRAGMA synchronous=NORMAL;')
conn.execute('VACUUM;')
conn.close()
" 2>/dev/null || true
        fi
        log_succ "SQLite WAL 模式与同步优化已成功应用！"
    fi

    # 优化 2: 重新校准日志采集链路
    log_info "2. 重新校准并对齐 1Panel / NPM / 科技lion 日志采集链路..."
    configure_log_acquis

    # 优化 3: 补全缺失场景规则
    auto_heal_broken_parsers
    log_info "3. 补齐与当前 VPS 匹配的场景规则库..."
    cscli collections install crowdsecurity/linux || true
    cscli collections install crowdsecurity/sshd || true
    cscli collections install crowdsecurity/nginx || true
    cscli collections install crowdsecurity/http-cve || true
    cscli collections install crowdsecurity/base-http-scenarios || true
    cscli collections install crowdsecurity/whitelist-good-actors || true
    if [[ "$DETECT_NPM" == "true" ]]; then
        cscli collections install crowdsecurity/nginx-proxy-manager || true
    fi
    if [[ "$DETECT_WORDPRESS" == "true" ]]; then
        cscli collections install crowdsecurity/wordpress || true
    fi

    # 优化 4: 激活 Prometheus full 指标与 WebUI 端口打通
    log_info "4. 激活 Prometheus full 级指标与 WebUI 端点..."
    enable_prometheus_metrics

    # 如果有 WebUI，确保注入了 CONFIG_INSTANCE_METRICS_URL
    if [[ -f "${WEBUI_DIR}/docker-compose.yml" ]]; then
        if ! grep -q "CONFIG_INSTANCE_METRICS_URL" "${WEBUI_DIR}/docker-compose.yml"; then
            sed -i '/CONFIG_INSTANCE_LAPI_AUTH_PASSWORD:/a\      CONFIG_INSTANCE_METRICS_URL: "http://127.0.0.1:6060/metrics"' "${WEBUI_DIR}/docker-compose.yml"
            docker compose -f "${WEBUI_DIR}/docker-compose.yml" up -d 2>/dev/null || docker-compose -f "${WEBUI_DIR}/docker-compose.yml" up -d 2>/dev/null || true
        fi
    fi

    # 优化 5: 开启每日自动更新
    if [[ ! -f "${CRON_FILE}" ]]; then
        log_info "5. 自动配置每日凌晨 03:30 自动规则库与威胁黑名单同步任务..."
        cat << 'EOF' > "${CRON_FILE}"
# CrowdSec 每日规则库与黑名单自动同步
30 3 * * * root /usr/bin/cscli hub update >/dev/null 2>&1 && /usr/bin/cscli hub upgrade >/dev/null 2>&1 && /bin/systemctl reload crowdsec >/dev/null 2>&1
EOF
        chmod 644 "${CRON_FILE}"
    fi

    # 重启核心服务
    log_info "6. 验证配置并热重启 CrowdSec 引擎..."
    crowdsec -t || true
    systemctl restart crowdsec || true
    systemctl restart crowdsec-firewall-bouncer* 2>/dev/null || true

    echo ""
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}             🎉 全系统深度调优优化已全部完成！                 ${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "  - 数据库并发能力:  ${GREEN}已开启 WAL 读写分离模式，消除锁库与磁盘卡顿${NC}"
    echo -e "  - 日志解析链条:    ${GREEN}已全量覆盖 1Panel + NPM (专有标签) + 科技lion${NC}"
    echo -e "  - 规则场景适配:    ${GREEN}已根据当前运行架构自动补齐并更新最新规则${NC}"
    echo -e "  - 运行时指标感知:  ${GREEN}Prometheus full 级指标已激活 (127.0.0.1:6060)${NC}"
    echo -e "  - 长期运维防护:    ${GREEN}每日凌晨 03:30 自动同步全球最新黑名单${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo ""
    read -r -p "按回车键返回主菜单..." _
}

# ------------------------------------------------------------------------------
# 主菜单 UI
# ------------------------------------------------------------------------------
show_main_menu() {
    while true; do
        clear
        echo -e "${BLUE}${BOLD}"
        cat << "EOF"
  ██████╗██████╗  ██████╗ ██╗    ██╗██████╗ ███████╗███████╗ ██████╗
 ██╔════╝██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║     ██████╔╝██║   ██║██║ █╗ ██║██║  ██║███████╗█████╗  ██║     
 ██║     ██╔══██╗██║   ██║██║███╗██║██║  ██║╚════██║██╔══╝  ██║     
 ╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝██████╔╝███████║███████╗╚██████╗
  ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
EOF
        echo -e "${NC}"
        echo -e "   ${BOLD}1Panel & 科技lion 终极防护中心 (内核级拦截 + WAF + WebUI)${NC}"
        echo -e "${BLUE}================================================================${NC}"
        echo -e " ${BOLD}[1]${NC} 部署/重装 CrowdSec 核心防护 (内核拦截 + 1Panel/科技lion全路径采集)"
        echo -e " ${BOLD}[2]${NC} 部署/管理 本地 CrowdSec-Web-UI (基于 TheDuffman85 容器)"
        echo -e " ${BOLD}[3]${NC} WAF 与场景规则库中心 (一键装配 Web-CVE / 通用WAF / WordPress)"
        echo -e " ${BOLD}[4]${NC} 每日定时自动更新设置 (Hub 规则库 + 威胁情报每日同步)"
        echo -e " ${BOLD}[5]${NC} 防火墙黑名单与日常运维 (查看封禁、手动拉黑/解封、查看度量)"
        echo -e " ${BOLD}[6]${NC} 绑定 CrowdSec Console 官方云端大屏 (免资源消耗、可视化)"
        echo -e " ${BOLD}[7]${NC} 📱 Telegram 告警推送与取证优化 (配置/测试/检测设置/自适应模板)"
        echo -e " ${BOLD}[8]${NC} 🔍 智能环境诊断与全方位深度调优 (系统资源感知 + SQLite提速 + 漏采补齐)"
        echo -e " ${BOLD}[9]${NC} 系统状态与配置健康检查 (服务自检、Bouncer状态、静态校验)"
        echo -e " ${BOLD}[10]${NC} 完全卸载 CrowdSec 及组件"
        echo -e " ${BOLD}[0]${NC} 退出脚本"
        echo -e "${BLUE}================================================================${NC}"
        read -r -p "请输入选项 [0-10]: " main_choice

        case "${main_choice}" in
            1) install_crowdsec_core ;;
            2) manage_web_ui ;;
            3) manage_waf_rules ;;
            4) manage_auto_update ;;
            5) manage_firewall_ops ;;
            6) bind_crowdsec_console ;;
            7) manage_telegram ;;
            8) smart_audit_and_optimize ;;
            9) check_health_status ;;
            10) uninstall_crowdsec_all ;;
            0) 
                echo -e "${GREEN}感谢使用！保持服务器安全无虞。${NC}"
                exit 0
                ;;
            *)
                log_warn "无效选项，请重新输入！"
                sleep 1
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# 脚本入口
# ------------------------------------------------------------------------------
main() {
    check_root
    detect_os

    # 如果有传递命令行参数，支持直接静默执行对应功能
    if [[ $# -gt 0 ]]; then
        case "$1" in
            --install-core) install_crowdsec_core ;;
            --install-webui) deploy_web_ui ;;
            --install-waf)
                cscli collections install crowdsecurity/nginx || true
                cscli collections install crowdsecurity/http-cve || true
                cscli collections install crowdsecurity/base-http-scenarios || true
                cscli collections install crowdsecurity/whitelist-good-actors || true
                systemctl reload crowdsec || true
                ;;
            --enable-cron)
                cat << 'EOF' > "${CRON_FILE}"
# CrowdSec 每日规则库与黑名单自动同步
30 3 * * * root /usr/bin/cscli hub update >/dev/null 2>&1 && /usr/bin/cscli hub upgrade >/dev/null 2>&1 && /bin/systemctl reload crowdsec >/dev/null 2>&1
EOF
                chmod 644 "${CRON_FILE}"
                ;;
            --telegram) manage_telegram ;;
            --telegram-test) test_telegram_notification ;;
            --optimize) smart_audit_and_optimize ;;
            --uninstall) uninstall_crowdsec_all ;;
            *)
                echo "未知参数: $1"
                echo "用法: $0 [--install-core | --install-webui | --install-waf | --enable-cron | --telegram | --optimize | --uninstall]"
                exit 1
                ;;
        esac
        exit 0
    fi

    # 默认进入交互式主菜单
    show_main_menu
}

main "$@"

#!/usr/bin/env bash
# Remote-only workflow: never invokes cscli or mutates the CrowdSec core.
remote_bouncer_tool() {
    timeout 15s python3 "${SCRIPT_DIR}/lib/crowdsec_remote_bouncer.py" "$1" "$REMOTE_CONFIG"
}

remote_bouncer_input() {
    # Disable tracing before reading credentials; callers run in a subshell.
    set +x
    local remote_url remote_key
    read -r -p '远端 LAPI URL（HTTPS 或私网 HTTP）: ' remote_url || return 1
    read -r -s -p '中心分配的 Bouncer API 密钥（隐藏输入）: ' remote_key || return 1
    printf '\n' >&2
    printf '%s\n%s\n' "$remote_url" "$remote_key" |
        python3 -c 'import json,sys; print(json.dumps({"url":sys.stdin.readline().rstrip("\n"),"key":sys.stdin.readline().rstrip("\n")}))' > "$1"
    unset remote_key
}

remote_bouncer_release() {
    local stage="$1" arch asset digest archive unpack
    case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) log_err 'Bouncer-only 安装仅支持 amd64/arm64。'; return 1 ;; esac
    asset="crowdsec-firewall-bouncer-linux-${arch}.tgz"
    curl -fLsS --connect-timeout 10 --max-time 60 "https://api.github.com/repos/crowdsecurity/cs-firewall-bouncer/releases/tags/v0.0.36" -o "$stage/release.json" || return 1
    digest=$(python3 - "$stage/release.json" "$asset" <<'PY'
import json,re,sys
items=[x for x in json.load(open(sys.argv[1]))['assets'] if x['name']==sys.argv[2]]
if len(items)!=1 or not re.fullmatch('sha256:[0-9a-f]{64}',items[0].get('digest') or ''): sys.exit(1)
print(items[0]['digest'].split(':')[1])
PY
    ) || { log_err '官方 release 元数据缺少可信 SHA256，拒绝安装。'; return 1; }
    archive="$stage/bouncer.tgz"
    curl -fLsS --connect-timeout 10 --max-time 120 "https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/v0.0.36/${asset}" -o "$archive" || return 1
    printf '%s  %s\n' "$digest" "$archive" | sha256sum -c - >/dev/null || return 1
    unpack="$stage/unpack"
    mkdir "$unpack" || return 1
    # Extract only expected regular release files; no archive paths/links run.
    if ! python3 - "$archive" "$unpack" <<'PY'
import pathlib,sys,tarfile
wanted=['crowdsec-firewall-bouncer','config/crowdsec-firewall-bouncer.yaml']
with tarfile.open(sys.argv[1]) as tar:
 for suffix in wanted:
  member=tar.getmember('crowdsec-firewall-bouncer-v0.0.36/'+suffix)
  if not member.isfile() or member.size>100*1024*1024: sys.exit(1)
  path=pathlib.Path(sys.argv[2])/pathlib.Path(suffix).name
  path.write_bytes(tar.extractfile(member).read())
PY
    then return 1; fi
    mkdir -p "$(dirname "$REMOTE_CONFIG")" "$(dirname "$REMOTE_BINARY")" "$(dirname "$REMOTE_UNIT")" || return 1
    install -m 0755 "$unpack/crowdsec-firewall-bouncer" "$REMOTE_BINARY" || return 1
    # shellcheck disable=SC2016
    sed 's/${BACKEND}/nftables/g; s/${API_KEY}//g' "$unpack/crowdsec-firewall-bouncer.yaml" > "$REMOTE_CONFIG" || return 1
    chmod 600 "$REMOTE_CONFIG" || return 1
    cat > "$REMOTE_UNIT" <<EOF
# Managed by crowdsec-1key remote-bouncer-v1
[Unit]
Description=CrowdSec remote Firewall Bouncer (crowdsec-1key)
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
ExecStart=$REMOTE_BINARY -c $REMOTE_CONFIG
ExecStartPre=$REMOTE_BINARY -c $REMOTE_CONFIG -t
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

remote_bouncer_change() (
    set +x
    local action="$1" stage success=false active=false enabled_state=disabled enable_touched=false fresh=false service_touched=false
    local paths copies index path
    if [[ "$action" == install ]]; then
        case "$OS_ID" in
            debian|ubuntu) install_packages python3 python3-yaml curl ca-certificates ;;
            centos|rhel|almalinux|rocky|fedora) install_packages python3 python3-pyyaml curl ca-certificates ;;
            *) log_err '未支持的 Bouncer-only 平台。'; return 1 ;;
        esac || return 1
    fi
    require_yaml && require_commands python3 timeout systemctl || return 1
    REMOTE_CONFIG="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml"
    stage=$(mktemp -d) || return 1
    chmod 700 "$stage" || return 1
    paths=("${REMOTE_CONFIG}.local" "${REMOTE_CONFIG}.remote.json")
    copies=(local state)
    # Called by EXIT trap.
    # shellcheck disable=SC2329
    remote_bouncer_rollback() {
        local result=$?
        if [[ "$success" != true ]]; then
            for index in "${!paths[@]}"; do
                path="${paths[$index]}"
                if [[ -f "$stage/${copies[$index]}" ]]; then
                    cp -p -- "$stage/${copies[$index]}" "$path" || log_err 'Bouncer 回滚复制失败。'
                else rm -f -- "$path"; fi
            done
            if [[ "$fresh" == true ]]; then
                systemctl stop crowdsec-firewall-bouncer >/dev/null 2>&1 || true
                systemctl disable crowdsec-firewall-bouncer >/dev/null 2>&1 || true
                rm -f -- "$REMOTE_BINARY" "$REMOTE_UNIT"
                rm -f -- "$REMOTE_CONFIG"
                systemctl daemon-reload >/dev/null 2>&1 || true
            elif [[ "$service_touched" == true ]]; then
                if [[ "$active" == true ]]; then systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || log_err '原 Bouncer 服务状态未恢复，请手动检查。'
                else systemctl stop crowdsec-firewall-bouncer >/dev/null 2>&1 || true; fi
                if [[ "$enable_touched" == true ]]; then
                    case "$enabled_state" in
                        enabled) systemctl enable crowdsec-firewall-bouncer >/dev/null 2>&1 || log_err '原服务启用状态未恢复。' ;;
                        enabled-runtime) systemctl disable crowdsec-firewall-bouncer >/dev/null 2>&1; systemctl enable --runtime crowdsec-firewall-bouncer >/dev/null 2>&1 || log_err '原临时启用状态未恢复。' ;;
                        disabled) systemctl disable crowdsec-firewall-bouncer >/dev/null 2>&1 || log_err '原服务停用状态未恢复。' ;;
                    esac
                fi
            fi
        fi
        rm -rf -- "$stage"
        return "$result"
    }
    # Guards precede installing, stopping or backing up anything.
    if [[ "$action" == remove ]]; then remote_bouncer_tool owned || { rm -rf "$stage"; return 1; }
    else remote_bouncer_tool guard || { rm -rf "$stage"; return 1; }; fi
    for index in "${!paths[@]}"; do
        [[ ! -f "${paths[$index]}" ]] || cp -p -- "${paths[$index]}" "$stage/${copies[$index]}" || { rm -rf "$stage"; return 1; }
    done
    systemctl is-active --quiet crowdsec-firewall-bouncer && active=true
    enabled_state=$(systemctl is-enabled crowdsec-firewall-bouncer 2>/dev/null) || true
    [[ -n "$enabled_state" ]] || enabled_state=disabled
    trap remote_bouncer_rollback EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ "$action" == remove ]]; then
        service_touched=true
        systemctl stop crowdsec-firewall-bouncer || return 1
        case "$enabled_state" in
            enabled|enabled-runtime|disabled)
                enable_touched=true
                systemctl disable crowdsec-firewall-bouncer || return 1 ;;
        esac
        remote_bouncer_tool remove || return 1
        success=true
        log_succ '已移除托管远端配置并停用 Firewall Bouncer；基础配置、二进制与包保留。'
        return 0
    fi
    remote_bouncer_input "$stage/input.json" || return 1
    remote_bouncer_tool preflight < "$stage/input.json" || return 1
    if [[ "$action" == install && ! -f "$REMOTE_CONFIG" ]]; then
        # Reject an existing unit/binary rather than replace another install.
        if command -v crowdsec-firewall-bouncer >/dev/null 2>&1 || [[ -e "$REMOTE_BINARY" || -L "$REMOTE_BINARY" || -e "$REMOTE_UNIT" || -L "$REMOTE_UNIT" ]] || systemctl cat crowdsec-firewall-bouncer >/dev/null 2>&1; then
            log_err '存在其他 Bouncer 安装但基础配置缺失，拒绝覆盖。'; return 1
        fi
        require_commands curl sha256sum install || return 1
        # Runtime packages only: never run upstream install.sh or package postinst
        # (they may register a bouncer against the existing local core).
        install_packages nftables || return 1
        fresh=true
        remote_bouncer_release "$stage" || return 1
    fi
    remote_bouncer_tool apply < "$stage/input.json" || return 1
    # Unit ExecStartPre performs official -t validation; no credential args.
    service_touched=true
    systemctl restart crowdsec-firewall-bouncer && systemctl is-active --quiet crowdsec-firewall-bouncer || return 1
    if [[ "$action" == install && "$fresh" == true ]]; then
        # A nonexistent old unit reports not-found; enable the new managed unit.
        enable_touched=true
        systemctl enable crowdsec-firewall-bouncer || return 1
    elif [[ "$action" == install ]]; then
        case "$enabled_state" in
            disabled) enable_touched=true; systemctl enable crowdsec-firewall-bouncer || return 1 ;;
            enabled|enabled-runtime|static|indirect|generated|transient) ;;
            *) log_err 'Bouncer 服务启用状态不支持自动更改。'; return 1 ;;
        esac
    fi
    success=true
    log_succ '远端 Firewall Bouncer 已配置；未修改 CrowdSec 核心或其他 Bouncer。'
)

remote_bouncer_status() {
    require_yaml && require_commands timeout || return 1
    REMOTE_CONFIG="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml"
    remote_bouncer_tool status || return 1
    systemctl is-active --quiet crowdsec-firewall-bouncer || { log_warn 'Firewall Bouncer 未运行。'; return 1; }
    log_info '服务运行；不会自动采集 SSH 日志，状态输出不代表真实业务阻断已验证。'
}

manage_remote_bouncer() {
    local choice
    while true; do
        printf '\n连接远端检测中心\n1. 安装防火墙防护并接入远端检测中心\n2. 修改检测中心地址和连接密钥\n3. 查看连接和运行状态\n4. 移除本工具的远端配置并停用防护\n0. 返回\n'
        prompt choice '请选择 [0-4]: ' || return 0
        case "$choice" in
            1) remote_bouncer_change install ;;
            2) remote_bouncer_change configure ;;
            3) remote_bouncer_status ;;
            4) remote_bouncer_change remove ;;
            0) return 0 ;;
            *) log_warn '无效选项。' ;;
        esac
    done
}

# /etc standalone units shadow distro /usr/lib units even after remote removal.
# Check before the local-core workflow creates traps, prompts or changes state.
remote_bouncer_local_core_guard() {
    local marker="${CS_DIR}/bouncers/crowdsec-firewall-bouncer.yaml.remote.json"
    local line standalone=false
    if [[ -e "$marker" || -L "$marker" ]]; then
        log_err '检测到托管远端 Bouncer 状态；远端到本地核心的自动迁移不支持，请先人工核对远端配置及 standalone unit/二进制。'
        return 1
    fi
    # Never follow a unit symlink: its target may contain unrelated credentials.
    # Irregular or masked units need manual review before local installation.
    if [[ -L "$REMOTE_UNIT" || ( -e "$REMOTE_UNIT" && ! -f "$REMOTE_UNIT" ) ]]; then
        log_err '已有 Firewall Bouncer unit 是符号链接或非普通文件，拒绝自动迁移，请人工核对。'
        return 1
    fi
    # Read only ordinary files without invoking systemctl or writing a target.
    if [[ -f "$REMOTE_UNIT" ]]; then
        if [[ ! -r "$REMOTE_UNIT" ]]; then
            log_err '无法读取已有 Firewall Bouncer unit，拒绝自动迁移，请人工核对。'
            return 1
        fi
        while IFS= read -r line || [[ -n "$line" ]]; do
            case "$line" in
                '# Managed by crowdsec-1key remote-bouncer-v1'|'Description=CrowdSec remote Firewall Bouncer (crowdsec-1key)') standalone=true; break ;;
            esac
        done < "$REMOTE_UNIT"
    fi
    if [[ "$standalone" == true ]]; then
        log_err '检测到保留的 standalone 远端 Bouncer unit；远端到本地核心的自动迁移不支持，请人工核对 unit/二进制/基础配置，未执行本地安装。'
        return 1
    fi
    return 0
}

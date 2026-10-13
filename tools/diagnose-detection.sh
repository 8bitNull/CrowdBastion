#!/usr/bin/env bash
# Read-only evidence collection. Does not change acquisition, whitelists or services.
set -o pipefail

audit_window=0
if [[ $# -ne 0 ]]; then
    if [[ $# -eq 2 && $1 == --window && $2 =~ ^([1-9]|[1-5][0-9]|60)$ ]]; then
        audit_window=$2
    else
        printf '用法：sudo bash tools/diagnose-detection.sh [--window 1..60（秒）]\n' >&2
        exit 1
    fi
fi

if [[ $EUID -ne 0 ]]; then
    printf '请使用 sudo bash tools/diagnose-detection.sh\n' >&2
    exit 1
fi
for command in python3 cscli curl; do
    command -v "$command" >/dev/null 2>&1 || { printf '缺少命令：%s\n' "$command" >&2; exit 1; }
done
audit_tmp=$(mktemp -d) || exit 1
trap 'rm -rf -- "$audit_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
audit_result=0
audit_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
audit_config="${CROWDSEC_CONFIG:-/etc/crowdsec/config.yaml}"
audit_helper="${audit_script_dir}/lib/crowdsec_detection_diagnose.py"

printf '\n采集、解析与 AppSec 指标（当前累计值）\n'
cscli metrics || audit_result=1
cscli metrics show appsec || audit_result=1
printf '\n白名单命中来源；unknown 不代表解析失败\n'
if audit_metrics_url=$(python3 "$audit_helper" metrics-url "$audit_config") &&
   curl -fsS --connect-timeout 3 --max-time 10 "$audit_metrics_url" > "$audit_tmp/metrics"; then
    grep '^cs_node_wl_hits_ok_total' "$audit_tmp/metrics" || true
    if (( audit_window > 0 )); then
        printf '\n采样 %s 秒窗口增量；并发流量不能归因到单次请求。\n' "$audit_window"
        sleep "$audit_window"
        if curl -fsS --connect-timeout 3 --max-time 10 "$audit_metrics_url" > "$audit_tmp/metrics-after"; then
            python3 "$audit_helper" metrics-delta "$audit_tmp/metrics" "$audit_tmp/metrics-after" || audit_result=1
        else
            printf '第二次指标读取失败，无法判断窗口增量。\n'; audit_result=1
        fi
    fi
else
    printf '无法读取有效 Prometheus 端点，请核对配置、监听和权限。\n'
    audit_result=1
fi

audit_nginx() {
    python3 "$audit_helper" nginx "$1" "$2" "${3:-container}"
}

printf '\nWeb 运行配置与最近访问日志 IP\n'
printf '[]' > "$audit_tmp/host-mounts"
for audit_runtime in nginx openresty; do
    if command -v "$audit_runtime" >/dev/null 2>&1; then
        printf '\n宿主机 %s\n' "$audit_runtime"
        if "$audit_runtime" -T > "$audit_tmp/nginx" 2>&1; then
            audit_nginx "$audit_tmp/nginx" "$audit_tmp/host-mounts" host || audit_result=1
        else
            printf '运行配置读取失败。\n'; audit_result=1
        fi
    fi
done
if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.ID}} {{.Image}} {{.Names}}' > "$audit_tmp/containers"; then
        while read -r audit_id audit_image audit_name; do
            case "$audit_image" in *nginx*|*openresty*) ;; *) continue ;; esac
            printf '\n容器 %s（%s）\n' "$audit_name" "$audit_image"
            if docker exec "$audit_id" nginx -T > "$audit_tmp/nginx" 2>&1 &&
               docker inspect --format '{{json .Mounts}}' "$audit_id" > "$audit_tmp/mounts"; then
                audit_nginx "$audit_tmp/nginx" "$audit_tmp/mounts" || audit_result=1
            else
                printf '运行配置或挂载读取失败。\n'; audit_result=1
            fi
        done < "$audit_tmp/containers"
    else
        audit_result=1
    fi
fi

printf '\nSSH 失败认证样本与离线解析（不制造真实登录失败）\n'
if command -v journalctl >/dev/null 2>&1 &&
   journalctl -u ssh.service -u sshd.service --since '24 hours ago' -n 1000 --no-pager -o short > "$audit_tmp/ssh"; then
    grep -E 'Failed password|Invalid user|authentication failure|Failed keyboard-interactive|Unable to negotiate' "$audit_tmp/ssh" > "$audit_tmp/failures" || true
    head -n 5 "$audit_tmp/failures" > "$audit_tmp/sample"
    if [[ -s "$audit_tmp/sample" ]]; then
        printf '现存失败日志样本：\n'
        cat "$audit_tmp/sample"
        cscli explain --file "$audit_tmp/sample" --type syslog -v || audit_result=1
    else
        printf '所检查的最近 journal 中没有失败样本；不能据此判断 SSH 防护有效或失效。\n'
    fi
else
    printf 'SSH journal 无法读取。\n'; audit_result=1
fi
printf '\n离线 sshd-session 兼容性样本（不是服务器真实事件）：\n'
printf '%s localhost sshd-session[99999]: Failed password for invalid user audit-test from 198.51.100.254 port 54321 ssh2\n' "$(LC_ALL=C date -u '+%b %e %T')" > "$audit_tmp/synthetic"
cscli explain --file "$audit_tmp/synthetic" --type syslog -v || audit_result=1
printf '\n检查完成；配置、白名单、日志文件与运行服务均未修改。\n'
printf '真实 AppSec 请求验证另用：sudo bash crowdbastion.sh --verify-appsec\n'
exit "$audit_result"

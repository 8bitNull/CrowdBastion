#!/usr/bin/env bash
# Read-only evidence collection. Does not change acquisition, whitelists or services.
set -o pipefail

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

printf '\n采集、解析与 AppSec 指标（当前累计值）\n'
cscli metrics || audit_result=1
cscli metrics show appsec || audit_result=1
printf '\n白名单命中来源；unknown 不代表解析失败\n'
if curl -fsS --connect-timeout 3 --max-time 10 http://127.0.0.1:6060/metrics > "$audit_tmp/metrics"; then
    grep '^cs_node_wl_hits_ok_total' "$audit_tmp/metrics" || true
else
    printf '无法读取默认 loopback 指标端口，请核对实际 prometheus 配置。\n'
    audit_result=1
fi

audit_nginx() {
    python3 - "$1" "$2" <<'PY'
import collections
import ipaddress
import json
from pathlib import Path
import re
import sys
text = Path(sys.argv[1]).read_text()
mounts = json.loads(Path(sys.argv[2]).read_text())
print('真实 IP / 日志 / 请求钩子相关配置：')
selected = re.compile(r'^\s*(?:server_name|set_real_ip_from|real_ip_header|real_ip_recursive|log_format|access_log|access_by_lua(?:_file|_block)?|proxy_set_header\s+(?:Host|X-Real-IP|X-Forwarded-For))\b')
for line in text.splitlines():
    if selected.search(line) or re.search(r'\b(?:cs|crowdsec)\.Allow\s*\(', line):
        print(line.strip())
if re.search(r'set_real_ip_from\s+["\']?(?:0\.0\.0\.0/0|::/0)["\']?\s*;', text):
    print('需核查：信任范围包含所有地址，不能据此认定转发头可信。')
seen = set()
for raw in re.findall(r'^\s*access_log\s+("[^"]+"|\'[^\']+\'|[^\s;]+)', text, re.M):
    remote = raw.strip('"\'')
    if not remote.startswith('/') or '$' in remote or remote.startswith('/dev/'):
        continue
    matches = [m for m in mounts if remote == m['Destination'].rstrip('/') or remote.startswith(m['Destination'].rstrip('/')+'/')]
    if mounts and not matches:
        continue
    if matches:
        mount = max(matches, key=lambda m: len(m['Destination'].rstrip('/')))
        local = Path(mount['Source'])/remote[len(mount['Destination'].rstrip('/')):].lstrip('/')
    else:
        local = Path(remote)
    if str(local) in seen or not local.is_file():
        continue
    seen.add(str(local))
    # Read only the tail, even when production logs are large.
    with local.open('rb') as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell()-65536))
        lines = stream.read().decode(errors='replace').splitlines()[-20:]
    ips = []
    for line in lines:
        candidate = line.split()[0] if line.split() else ''
        try:
            ipaddress.ip_address(candidate)
            ips.append(candidate)
        except ValueError:
            pass
    print('\n日志：'+str(local))
    if not ips:
        print('最近日志首字段不是可识别 IP；需结合自定义 log_format 判断，不能判定配置异常。')
    for ip, count in collections.Counter(ips).most_common(5):
        address = ipaddress.ip_address(ip)
        kind = '公网' if address.is_global else '非公网/保留地址'
        print(f'首字段 IP {ip}: {count} 条，{kind}')
print('\n以上仅是配置和日志证据；实际访客 IP 与 Web Bouncer 使用的 IP 仍需关联同一次请求确认。')
PY
}

printf '\nWeb 运行配置与最近访问日志 IP\n'
printf '[]' > "$audit_tmp/host-mounts"
for audit_runtime in nginx openresty; do
    if command -v "$audit_runtime" >/dev/null 2>&1; then
        printf '\n宿主机 %s\n' "$audit_runtime"
        if "$audit_runtime" -T > "$audit_tmp/nginx" 2>&1; then
            audit_nginx "$audit_tmp/nginx" "$audit_tmp/host-mounts" || audit_result=1
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
printf '真实 AppSec 请求验证另用：sudo bash install-crowdsec-1panel.sh --verify-appsec\n'
exit "$audit_result"

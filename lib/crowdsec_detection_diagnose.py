#!/usr/bin/env python3
"""Read-only detection evidence shared by the diagnostic entrypoints."""
import ipaddress
import json
import math
from pathlib import Path
import re
import sys

from crowdsec_config import merged_config
from crowdsec_realip_diagnose import log_evidence


def metrics_url(config):
    data = merged_config(str(config)).get('prometheus', {})
    if not isinstance(data, dict) or data.get('enabled') is not True:
        raise ValueError('Prometheus 未启用，请核对有效配置')
    host = str(data.get('listen_addr') or '127.0.0.1')
    if host in ('0.0.0.0', '::', '[::]'):
        host = '127.0.0.1' if host == '0.0.0.0' else '::1'
    # Bind address is an IP, not an arbitrary URL supplied to curl.
    address = ipaddress.ip_address(host.strip('[]'))
    port = data.get('listen_port', 6060)
    if isinstance(port, bool) or not re.fullmatch(r'\d+', str(port)) or not 1 <= int(port) <= 65535:
        raise ValueError('Prometheus 端口无效')
    return f'http://{"["+str(address)+"]" if address.version == 6 else address}:{int(port)}/metrics'


def range_changes(owned, ranges):
    previous = set(owned.get('ranges', []))
    current = set(ranges)
    return sorted(current-previous), sorted(previous-current)


def counter_snapshot(raw):
    names = set(re.findall(r'^# TYPE (cs_\w+) counter$', raw, re.M))
    values = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'(cs_\w+)(\{.*\})?\s+(\S+)(?:\s+\d+)?', line)
        if not match or match[1] not in names:
            continue
        value = float(match[3])
        if not math.isfinite(value) or value < 0:
            raise ValueError('指标计数不是有效的非负有限值')
        values[match[1]+(match[2] or '')] = value
    return values


def counter_deltas(before, after):
    first, second = counter_snapshot(before), counter_snapshot(after)
    return [(key, second[key]-first[key] if key in first and key in second and second[key] >= first[key] else None)
            for key in sorted(first.keys() | second.keys())]


def print_nginx(effective, mounts, host=False):
    print('真实 IP / 日志 / 请求钩子相关配置：')
    selected = re.compile(r'^\s*(?:server_name|set_real_ip_from|real_ip_header|real_ip_recursive|log_format|access_log|access_by_lua(?:_file|_block)?|proxy_set_header\s+(?:Host|X-Real-IP|X-Forwarded-For))\b')
    for line in effective.splitlines():
        if selected.search(line) or re.search(r'\b(?:cs|crowdsec)\.Allow\s*\(', line):
            print(line.strip())
    if re.search(r'set_real_ip_from\s+["\']?(?:0\.0\.0\.0/0|::/0)["\']?\s*;', effective):
        print('需核查：信任范围包含所有地址，不能据此认定转发头可信。')
    reports = log_evidence(effective, mounts, host=host)
    for entry in reports:
        print('\n日志：'+entry['path'])
        print('最近日志时间：'+(entry['latest'] or '无法读取'))
        print(f"已采样 {entry['sampled']} 条（最多 64KiB / 20 条）。")
        if not entry['ips']:
            print('未识别客户端字段；需核对自定义 log_format，不能判定配置异常。')
        for address, count in entry['ips']:
            kind = '公网' if ipaddress.ip_address(address).is_global else '非公网/保留地址'
            print(f'日志客户端 IP {address}: {count} 条，{kind}')
    if not reports:
        print('未找到可读取的 HTTP 日志；已排除 stream、未挂载、符号链接及上下文不明来源。')
    print('以上仅是配置和日志证据；实际访客 IP 与 Web Bouncer 使用的 IP 仍需关联同一次请求确认。')


def main(args):
    action, *args = args
    if action == 'metrics-url':
        print(metrics_url(args[0]))
    elif action == 'metrics-delta':
        before, after = args
        rows = counter_deltas(Path(before).read_text(), Path(after).read_text())
        changed = [(key, value) for key, value in rows if value != 0]
        for key, value in changed[:80]:
            print(f'{key}: '+('无法判断（计数重置或序列新增/消失）' if value is None else f'+{value:g}'))
        if len(changed) > 80:
            print(f'仅展示前 80 项，共 {len(changed)} 项变化。')
        if not rows:
            raise ValueError('未找到带 TYPE counter 声明的 CrowdSec 指标，不能判断窗口增量')
        if not changed:
            print('已读取的 CrowdSec counter 指标在窗口内没有变化；不能据此认定防护失效。')
    elif action == 'nginx':
        effective, mounts, mode = args
        print_nginx(Path(effective).read_text(), json.loads(Path(mounts).read_text()), mode == 'host')
    elif action == 'range-diff':
        plan, state, name = args
        proposal = json.loads(Path(plan).read_text())
        previous = json.loads(Path(state).read_text()).get(name, {}) if Path(state).exists() else {}
        added, removed = range_changes(previous, proposal['ranges'])
        print('本次网段变更：新增 '+(', '.join(added) or '无')+'；移除 '+(', '.join(removed) or '无'))
        if previous and not previous.get('ranges'):
            print('旧管理记录未保存网段清单；请结合原配置核对，不能据此认为全部新增。')
    else:
        raise ValueError('未知诊断操作')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('诊断失败: '+str(error), file=sys.stderr)
        sys.exit(1)

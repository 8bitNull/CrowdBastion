"""Read-only Bouncer decision snapshots and referenced ipset coverage."""
from bisect import bisect_right
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import urllib.request

import yaml
from crowdsec_config import merged_config


class EvidenceError(ValueError):
    """Only fixed diagnostics may cross the credential-reading boundary."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise EvidenceError('决策检查拒绝重定向。')


def seconds(value):
    if not isinstance(value, str):
        raise EvidenceError('决策时长格式无效。')
    if value.startswith('-'):
        return 0
    parts = re.findall(r'(\d+(?:\.\d+)?)(ns|us|µs|ms|h|m|s)', value)
    if not parts or ''.join(n+u for n, u in parts) != value:
        raise EvidenceError('决策时长格式无效。')
    scale = {'h': 3600, 'm': 60, 's': 1, 'ms': .001, 'us': .000001, 'µs': .000001, 'ns': 1e-9}
    return sum(float(n)*scale[u] for n, u in parts)


def networks(rows, minleft=15):
    result = set()
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceError('决策记录格式无效。')
        if row.get('type') == 'ban' and str(row.get('scope', '')).lower() in ('ip', 'range') and seconds(row.get('duration', '0s')) > minleft:
            result.add(ipaddress.ip_network(row['value'], strict=False))
    return result


def live(config):
    try:
        data = merged_config(config)
        for field in ('origins', 'scopes', 'scenarios_containing', 'scenarios_not_containing'):
            if data.get(field):
                raise EvidenceError('存在自定义决策过滤，自动入核比对尚未支持。')
        if data.get('supported_decisions_types', ['ban']) != ['ban']:
            raise EvidenceError('自定义决策类型尚未支持自动比对。')
        url, key = data['api_url'], data['api_key']
        from crowdsec_remote_bouncer import validate
        url = validate(url, key)
        if data.get('insecure_skip_verify') or any(data.get(k) for k in ('cert_path', 'key_path', 'ca_cert_path')):
            raise EvidenceError('自定义 TLS 认证尚未支持自动决策检查。')
        request = urllib.request.Request(url+'v1/decisions', headers={'X-Api-Key': key})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=10) as response:
            payload = response.read(32*1024*1024+1)
        if len(payload) > 32*1024*1024:
            raise EvidenceError('决策响应超过检查容量。')
        rows = json.loads(payload)
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise EvidenceError('决策响应格式无效。')
        networks(rows, 0)
        return rows
    except EvidenceError:
        raise
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        raise EvidenceError('无法读取有效决策（配置、认证、TLS 或连接错误）；未输出凭据。') from None


def membership(expected, references, payload):
    created, actual = {}, {4: set(), 6: set()}
    for line in payload.splitlines():
        words = shlex.split(line)
        if len(words) >= 3 and words[0] == 'create':
            if 'family' not in words:
                continue
            family = words[words.index('family')+1]
            created[words[1]] = 4 if family == 'inet' else 6 if family == 'inet6' else None
    for version, names in references.items():
        for name in names:
            if created.get(name) != version:
                raise EvidenceError('实际引用的集合不存在或地址族不匹配。')
    for line in payload.splitlines():
        words = shlex.split(line)
        if len(words) >= 3 and words[0] == 'add':
            for version, names in references.items():
                if words[1] in names:
                    if 'nomatch' in words[3:]:
                        raise EvidenceError('引用集合存在排除项，无法证明完整封禁。')
                    net = ipaddress.ip_network(words[2], strict=False)
                    if net.version != version:
                        raise EvidenceError('集合成员地址族不匹配。')
                    actual[version].add(net)
    missing = 0
    for version in (4, 6):
        collapsed = list(ipaddress.collapse_addresses(actual[version]))
        starts = [int(net.network_address) for net in collapsed]
        for net in (n for n in expected if n.version == version):
            index = bisect_right(starts, int(net.network_address))-1
            if index < 0 or not net.subnet_of(collapsed[index]):
                missing += 1
    return {'expected': len(expected), 'kernel': sum(map(len, actual.values())), 'missing': missing}


def inspect(config, docker=None):
    from crowdsec_firewall_runtime import iptables_references, docker_present, run, PathCoverageError
    try:
        data = merged_config(config)
        if data.get('mode') != 'iptables':
            return {'state': 'unknown', 'reason': '当前后端尚未支持此入核检查。'}
        refs = iptables_references(config, docker_present() if docker is None else docker)
        rows = live(config)
        expected = networks(rows)
        # Read expected decisions before the kernel, allowing normal sync to
        # catch up. Near-expiry decisions are excluded from this snapshot.
        report = membership(expected, refs, run(['ipset', 'save']).stdout)
        report['state'] = 'pending' if report['missing'] else 'ok'
        return report
    except PathCoverageError:
        return {'state': 'fault', 'reason': '防火墙执行入口或引用规则不完整。'}
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, subprocess.SubprocessError):
        return {'state': 'unknown', 'reason': '无法完整核对适用决策及实际引用的内核集合；请查看配置和连接状态。'}


def wait(config, seconds=30, docker=None):
    deadline = time.monotonic()+seconds
    while True:
        report = inspect(config, docker)
        if report['state'] == 'ok':
            return report
        if report['state'] == 'unknown' or time.monotonic() >= deadline:
            if report['state'] == 'pending':
                report = {**report, 'state': 'fault'}
            return report
        time.sleep(2)


def render(report):
    from crowdbastion_health import emit
    state = report['state']
    emit('decisions', 'required')
    emit('decisions', state)
    label = {'ok': '[已检查]', 'fault': '[异常]', 'pending': '[等待同步]', 'unknown': '[尚未验证]'}[state]
    if 'missing' in report:
        print(f"{label} 决策入核：适用网络 {report['expected']}，实际集合网络 {report['kernel']}，遗漏 {report['missing']}。")
    else:
        print(label+' 决策入核：'+report['reason'])
    return 0 if state == 'ok' else 1 if state == 'fault' else 2


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--wait', type=int, default=0, choices=range(0, 61))
    args = parser.parse_args()
    raise SystemExit(render(wait(args.config, args.wait) if args.wait else inspect(args.config)))
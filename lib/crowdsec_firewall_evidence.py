"""Read-only Bouncer decision snapshots and referenced ipset coverage."""
from bisect import bisect_right
import http.client
import ipaddress
import json
from pathlib import Path
import re
import shlex
import ssl
import subprocess
import time
import urllib.error
import urllib.request

import yaml
from crowdsec_config import merged_config


class EvidenceError(ValueError):
    """Only fixed diagnostics may cross the credential-reading boundary."""
    def __init__(self, message, phase='api_response', error_code='api_response_invalid', retryable=False, duration_seconds=0):
        super().__init__(message)
        self.phase = phase
        self.error_code = error_code
        self.retryable = retryable
        self.duration_seconds = duration_seconds
        self.phase_duration_seconds = duration_seconds
        self.phases = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise EvidenceError('决策检查拒绝重定向。', 'api_request', 'api_redirect_refused')


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


def live(config, *, timings=None):
    """Return rows; optionally append timings measured at actual boundaries."""
    started = time.monotonic()
    phase = 'config_read'
    phase_started = started
    timings = [] if timings is None else timings
    first_timing = len(timings)

    def record(code='none', retryable=False):
        now = time.monotonic()
        timings.append({'phase': phase, 'duration_seconds': round(now-phase_started, 6),
                        'error_code': code, 'retryable': retryable})
        return now

    def advance(next_phase):
        nonlocal phase, phase_started
        phase_started = record()
        phase = next_phase

    def failed(error):
        now = record(error.error_code, error.retryable)
        error.duration_seconds = round(now-started, 6)
        error.phase_duration_seconds = timings[-1]['duration_seconds']
        error.phases = timings[first_timing:]
        return error

    try:
        data = merged_config(config)
        for field in ('origins', 'scopes', 'scenarios_containing', 'scenarios_not_containing'):
            if data.get(field):
                raise EvidenceError('存在自定义决策过滤，自动入核比对尚未支持。', phase, 'custom_filter_unsupported')
        if data.get('supported_decisions_types', ['ban']) != ['ban']:
            raise EvidenceError('自定义决策类型尚未支持自动比对。', phase, 'custom_filter_unsupported')
        url, key = data['api_url'], data['api_key']
        from crowdsec_remote_bouncer import validate
        url = validate(url, key)
        if data.get('insecure_skip_verify') or any(data.get(k) for k in ('cert_path', 'key_path', 'ca_cert_path')):
            raise EvidenceError('自定义 TLS 认证尚未支持自动决策检查。', phase, 'custom_tls_unsupported')
        request = urllib.request.Request(url+'v1/decisions', headers={'X-Api-Key': key})
        advance('api_request')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=10) as response:
            payload = response.read(32*1024*1024+1)
        advance('api_response')
        if len(payload) > 32*1024*1024:
            raise EvidenceError('决策响应超过检查容量。')
        rows = json.loads(payload)
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise EvidenceError('决策响应格式无效。')
        networks(rows, 0)
        record()
        return rows
    except EvidenceError as error:
        failed(error)
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, yaml.YAMLError, http.client.HTTPException) as error:
        code, retryable = 'config_invalid', False
        if phase == 'api_response':
            code = 'api_response_invalid'
        elif phase == 'api_request':
            retryable = True
            code = 'api_connection_failed'
            if isinstance(error, urllib.error.HTTPError):
                code = 'api_auth_failed' if error.code in (401, 403) else 'api_http_error'
                retryable = error.code == 429 or error.code >= 500
            elif isinstance(error, TimeoutError) or isinstance(getattr(error, 'reason', None), TimeoutError):
                code = 'api_timeout'
            elif isinstance(error, ssl.SSLError) or isinstance(getattr(error, 'reason', None), ssl.SSLError):
                code, retryable = 'api_tls_error', False
        raise failed(EvidenceError('决策检查未完成；按阶段和错误码核对配置、API 或连接，未输出凭据。',
                                   phase, code, retryable)) from None


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
    from crowdsec_firewall_runtime import iptables_references, docker_present, run, PathCoverageError, IncompletePathError
    started = time.monotonic()
    phase = 'config_read'
    phase_started = started
    phases = []
    phase_timed_by_live = False
    def advance(next_phase):
        nonlocal phase, phase_started
        now = time.monotonic()
        phases.append({'phase': phase, 'duration_seconds': round(now-phase_started, 6),
                       'error_code': 'none', 'retryable': False})
        phase, phase_started = next_phase, now

    def finish(report, code='none', retryable=False, failure_phase=None):
        now = time.monotonic()
        if not phase_timed_by_live:
            phases.append({'phase': phase, 'duration_seconds': round(now-phase_started, 6),
                           'error_code': code, 'retryable': retryable})
        return {**report, 'phase': failure_phase or phase, 'error_code': code,
                'duration_seconds': round(now-started, 6), 'retryable': retryable, 'phases': phases}
    try:
        data = merged_config(config)
        if data.get('mode') != 'iptables':
            return finish({'state': 'unknown', 'reason': '当前后端尚未支持此入核检查。'}, 'backend_unsupported')
        advance('rules_read')
        nested_timings = []
        try:
            refs = iptables_references(config, docker_present() if docker is None else docker,
                                       timings=nested_timings)
        finally:
            # Successful and failed idle-chain probes overlap rules_read.
            phases.extend({**entry, 'nested': True} for entry in nested_timings)
        advance('api_request')
        phase_timed_by_live = True
        # live() owns config/request/body/response timing, including errors.
        # Do not append the whole call again under an API phase name.
        rows = live(config, timings=phases)
        phase = 'decision_selection'
        phase_started = time.monotonic()
        phase_timed_by_live = False
        expected = networks(rows)
        # Read expected decisions before the kernel, allowing normal sync to
        # catch up. Near-expiry decisions are excluded from this snapshot.
        advance('ipset_read')
        payload = run(['ipset', 'save']).stdout
        advance('ipset_compare')
        report = membership(expected, refs, payload)
        report['state'] = 'pending' if report['missing'] else 'ok'
        advance('decision_coverage')
        return finish(report, 'decisions_pending' if report['missing'] else 'none', bool(report['missing']))
    except PathCoverageError:
        return finish({'state': 'fault', 'reason': '防火墙执行入口或引用规则不完整。'}, 'firewall_path_incomplete')
    except IncompletePathError as error:
        diagnostic = getattr(error, 'diagnostic', None)
        return finish({'state': 'unknown', 'reason': '无法确认空链对应地址族的有效决策；请按阶段和错误码检查。'},
                      diagnostic.error_code if isinstance(diagnostic, EvidenceError) else 'rules_decisions_unknown',
                      diagnostic.retryable if isinstance(diagnostic, EvidenceError) else True,
                      diagnostic.phase if isinstance(diagnostic, EvidenceError) else 'rules_read')
    except EvidenceError as error:
        # Membership errors share the fixed exception type but belong to the
        # comparison phase, whereas live API failures retain their own stage.
        api = phase in ('api_request', 'decision_selection', 'rules_read')
        return finish({'state': 'unknown', 'reason': '无法完整核对适用决策及实际引用的内核集合；请按阶段和错误码检查。'},
                      error.error_code if api else 'ipset_membership_invalid',
                      error.retryable if api else False, error.phase if api else phase)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, yaml.YAMLError, subprocess.SubprocessError):
        codes = {'config_read': 'config_invalid', 'rules_read': 'rules_read_failed', 'ipset_read': 'ipset_read_failed',
                 'api_request': 'api_connection_failed', 'decision_selection': 'api_response_invalid', 'ipset_compare': 'ipset_membership_invalid'}
        return finish({'state': 'unknown', 'reason': '无法完整核对适用决策及实际引用的内核集合；请按阶段和错误码检查。'},
                      codes[phase], phase in ('rules_read', 'ipset_read', 'api_request'))


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
    if 'phase' in report:
        print(f"  phase={report['phase']} error_code={report['error_code']} duration_seconds={report['duration_seconds']:.3f} retryable={str(report['retryable']).lower()}")
        print('  阶段耗时：'+', '.join(f"{entry['phase']}={entry['duration_seconds']:.3f}s"+
              (' (nested)' if entry.get('nested') else '') for entry in report.get('phases', [])))
    return 0 if state == 'ok' else 1 if state == 'fault' else 2


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--wait', type=int, default=0, choices=range(0, 61))
    args = parser.parse_args()
    raise SystemExit(render(wait(args.config, args.wait) if args.wait else inspect(args.config)))

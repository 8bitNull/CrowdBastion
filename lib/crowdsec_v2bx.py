#!/usr/bin/env python3
"""Bounded, read-only V2bX inventory. Never emit raw configs, commands or logs."""
import argparse
import contextlib
import glob
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True

import yaml

from crowdsec_config import acquisition_locations, go_glob
from crowdsec_relay_paths import endpoint

CORES = {'xray', 'sing', 'hysteria2'}
PROTOCOLS = {'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria', 'hysteria2',
             'tuic', 'anytls', 'socks', 'http', 'naive'}
LEVELS = {'debug', 'info', 'warn', 'warning', 'error', 'none', 'off', 'fatal', 'panic'}
ENTRIES = {'direct', 'relay-preserve', 'relay-proxy', 'mixed', 'unknown'}
MAX_CONFIG = 2 * 1024 * 1024


class InputError(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError('invalid_arguments')


def mapping(value):
    return value if isinstance(value, dict) else {}


def enum(value, allowed):
    return value if isinstance(value, str) and value in allowed else 'unknown'


def ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) and '%' not in value else None
    except ValueError:
        return None


def read_regular(path, limit, tail=False):
    """O_NONBLOCK + fstat avoids blocking on FIFOs, including replacement races."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            size = os.fstat(stream.fileno())
            if not stat.S_ISREG(size.st_mode):
                return None, 'not_regular'
            if size.st_size > limit:
                if not tail:
                    return None, 'too_large'
                stream.seek(-limit, os.SEEK_END)
                stream.readline()  # discard the partial first line
            data = stream.read(limit + 1)
            if len(data) > limit:
                return None, 'too_large'
            return data.decode('utf-8', errors='replace'), 'readable'
    except FileNotFoundError:
        return None, 'missing'
    except (OSError, ValueError):
        return None, 'unreadable'


def jsonc(text):
    # Same supported syntax as upstream TrimNodeReader: comments and trailing
    # commas, not arbitrary JSON5. Strings (including URLs) remain untouched.
    token = r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/'
    clean = re.sub(token, lambda m: m[0] if m[0].startswith('"') else ' ', text)
    clean = re.sub(r'"(?:\\.|[^"\\])*"|,\s*(?=[}\]])',
                   lambda m: m[0] if m[0].startswith('"') else '', clean)
    try:
        data = json.loads(clean)
    except (ValueError, RecursionError):
        raise InputError('invalid_config') from None
    if not isinstance(data, dict):
        raise InputError('invalid_config')
    return data


def config_read(path):
    text, status = read_regular(path, MAX_CONFIG)
    if text is None:
        raise InputError(status)
    return jsonc(text)


def command(args):
    if not shutil.which(args[0]):
        return None, 'tool_missing'
    try:
        # Outputs are bounded by the fixed queries (journal -n, systemctl show,
        # ss listeners). Never expose stdout/stderr, even on failure.
        result = subprocess.run(args, capture_output=True, text=True, timeout=15,
                                errors='replace')
    except (OSError, subprocess.TimeoutExpired):
        return None, 'read_failed'
    if result.returncode:
        return None, 'read_failed'
    if len(result.stdout) > MAX_CONFIG:
        return None, 'too_large'
    return result.stdout, 'readable'


def runtime(unit):
    text, status = command(['systemctl', 'show', unit, '--no-pager',
                            '--property=LoadState,ActiveState,MainPID,WorkingDirectory'])
    fields = dict(line.split('=', 1) for line in (text or '').splitlines() if '=' in line)
    pid = fields.get('MainPID', '')
    pid = int(pid) if re.fullmatch(r'[0-9]{1,10}', pid) else 0
    report = {'service_status': status,
              'load': enum(fields.get('LoadState'), {'loaded', 'not-found', 'masked', 'error'}),
              'active': enum(fields.get('ActiveState'), {'active', 'inactive', 'failed', 'activating', 'deactivating'}),
              'main_pid': pid, 'version': None, 'version_status': 'unverified',
              'config_origin': 'default_candidate'}
    return report, fields


def running_config(pid):
    if not pid:
        return None
    try:
        comm = Path('/proc') / str(pid) / 'comm'
        if comm.read_text().strip().lower() != 'v2bx':
            return None
        # proc pseudo-files have size zero; read directly with a bounded read.
        with (comm.parent / 'cmdline').open('rb') as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            return None
        args = raw.decode('utf-8').split('\0')
        for index, arg in enumerate(args):
            if arg in ('--config', '-c') and index + 1 < len(args):
                candidate = args[index + 1]
                if Path(candidate).is_absolute():
                    return Path(candidate)
            if arg.startswith('--config=') and Path(arg[9:]).is_absolute():
                return Path(arg[9:])
    except (OSError, ValueError, UnicodeError):
        pass
    return None


def declarations(value, count):
    result = {}
    if not value:
        return result
    for part in value.split(','):
        matched = re.fullmatch(r'([1-9][0-9]*):([a-z-]+)', part.strip())
        if not matched:
            raise InputError('invalid_entries')
        index, mode = int(matched[1]), matched[2]
        if index > count or index in result or mode not in ENTRIES:
            raise InputError('invalid_entries')
        result[index] = mode
    return result


def node_read(raw, working_dir):
    if not isinstance(raw, dict):
        raise InputError('invalid_config')
    if not raw.get('Include'):
        return raw, 'local'
    include = raw['Include']
    if not isinstance(include, str):
        raise InputError('invalid_config')
    if re.match(r'^https?://', include, re.I):
        return {}, 'remote_include_not_read'
    target = Path(include)
    if not target.is_absolute():
        if working_dir is None:
            return {}, 'relative_include_unresolved'
        target = working_dir / target
    try:
        data = config_read(target)
    except InputError:
        return {}, 'local_include_unreadable'
    if data.get('Include'):
        return {}, 'nested_include_unverified'
    return data, 'local_include'


def node_report(raw, index, cores, mode, working_dir):
    data, state = node_read(raw, working_dir)
    api = mapping(data.get('ApiConfig')) if 'ApiConfig' in data else data
    options = mapping(data.get('Options')) if 'Options' in data else data
    core = 'unknown'
    if options.get('CoreName'):
        selected = [c for c in cores if (c.get('Name') or c.get('Type')) == options['CoreName']]
        if len(selected) == 1:
            core = enum(selected[0].get('Type'), CORES)
    elif options.get('Core') in CORES:
        selected = [c for c in cores if c.get('Type') == options['Core']]
        if len(selected) == 1:
            core = options['Core']
    node_id = api.get('NodeID')
    node_id = node_id if type(node_id) is int and 0 < node_id < 2**63 else None
    enforcement = {'direct': 'landing_if_packet_source_verified',
                   'relay-preserve': 'landing_if_packet_source_verified',
                   'relay-proxy': 'relay_if_trusted_source_verified',
                   'mixed': 'per_path_verification_required',
                   'unknown': 'per_path_verification_required'}[mode]
    limits = mapping(options.get('LimitConfig'))
    return {'index': index, 'node_id': node_id, 'config_status': state,
            'core': core, 'protocol': enum(api.get('NodeType'), PROTOCOLS),
            'listen_ip': ip(options.get('ListenIP', '0.0.0.0')) if state in ('local', 'local_include') else None,
            'port_status': 'panel_or_runtime_required',
            'transport_status': 'panel_or_runtime_required',
            'proxy_protocol_declared': options.get('EnableProxyProtocol') is True,
            'proxy_protocol_support_status': 'version_and_transport_required',
            'entry_declared': mode, 'source_status': 'unverified',
            'enforcement': enforcement,
            'limit_fields_present': [key for key in ('SpeedLimit', 'DeviceLimit', 'ConnLimit') if key in limits],
            'limit_effect_status': 'unverified'}


def socket_report(pid):
    text, status = command(['ss', '-H', '-lntup'])
    sockets = []
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] not in ('tcp', 'udp'):
            continue
        local = endpoint(parts[4])
        if local is None or local[1] is None:
            continue
        owner = bool(pid and re.search(r'\bpid='+str(pid)+r'\b', line))
        address = local[0].rpartition(':')[0].strip('[]')
        if address != '*' and ip(address) is None:
            continue
        sockets.append({'network': parts[0], 'address': address, 'port': local[1],
                        'service_pid_match': owner, 'node_mapping_status': 'unverified'})
    return sockets, status


def sample_report(text):
    counts = {'lines': 0, 'connected': 0, 'disconnected': 0, 'source_present': 0,
              'failure_candidates': 0, 'ordinary_errors': 0, 'unclassified': 0}
    for line in (text or '').splitlines()[-200:]:
        counts['lines'] += 1
        try:
            data = mapping(json.loads(line))
        except (ValueError, RecursionError):
            data = {}
        msg = data.get('msg')
        if msg in ('client connected', 'client disconnected'):
            counts['connected' if msg == 'client connected' else 'disconnected'] += 1
            address = data.get('addr')
            local = endpoint(address) if isinstance(address, str) else None
            if local and ip(local[0].rpartition(':')[0].strip('[]')):
                counts['source_present'] += 1
        elif re.search(r'authentication failed|invalid user|invalid authentication', line, re.I):
            counts['failure_candidates'] += 1
        elif re.search(r'timeout|timed out|connection refused|limited .* by (ip|conn)', line, re.I):
            counts['ordinary_errors'] += 1
        else:
            counts['unclassified'] += 1
    return counts


def acquisitions(root):
    try:
        config = Path(root) / 'config.yaml'
        for candidate in (config, Path(str(config) + '.local')):
            if candidate == config or candidate.exists():
                _, status = read_regular(candidate, MAX_CONFIG)
                if status != 'readable':
                    return [], 'read_failed'
        # Existing project function honors config.yaml.local and custom locations.
        with contextlib.redirect_stdout(None):
            directory, single, _ = acquisition_locations(root)
        files = ([single] if single else []) + sorted(glob.glob(glob.escape(directory)+'/*.yaml')) + sorted(glob.glob(glob.escape(directory)+'/*.yml'))
        docs = []
        for filename in dict.fromkeys(files):
            if not Path(filename).exists():
                continue
            text, status = read_regular(filename, MAX_CONFIG)
            if status != 'readable':
                return [], 'read_failed'
            parsed = list(yaml.safe_load_all(text))
            if any(d is not None and not isinstance(d, dict) for d in parsed):
                return [], 'invalid_config'
            docs.extend(d for d in parsed if d)
        return docs, 'readable'
    except (OSError, ValueError, TypeError, yaml.YAMLError, RecursionError):
        return [], 'unverified'


def acquisition_report(path, unit, docs, state):
    if state != 'readable':
        return 0, 'unverified'
    matches = 0
    constrained = False
    for doc in docs:
        source = doc.get('source', 'file')
        if path is None and source == 'journalctl':
            filters = doc.get('journalctl_filter', [])
            if not isinstance(filters, list) or any(not isinstance(f, str) for f in filters):
                constrained = True
                continue
            units = [f.split('=', 1)[1] for f in filters if f.startswith('_SYSTEMD_UNIT=')]
            if not units or unit in units:
                matches += 1
                constrained |= not filters or any(not f.startswith('_SYSTEMD_UNIT=') for f in filters)
        elif path is not None and source == 'file':
            patterns = doc.get('filenames', [])
            if isinstance(patterns, str):
                patterns = [patterns]
            if not isinstance(patterns, list):
                constrained = True
                continue
            patterns = patterns + ([doc['filename']] if doc.get('filename') else [])
            found = False
            for pattern in patterns:
                if not isinstance(pattern, str):
                    constrained = True
                    continue
                if any(Path(p).resolve() == path.resolve() for p in go_glob(pattern)):
                    found = True
            matches += int(found)
    if path is None:
        status = 'overlap_or_constrained' if constrained or matches > 1 else 'configured' if matches else 'not_configured'
    else:
        status = 'duplicate_possible' if matches > 1 else 'configured' if matches else 'not_configured'
        if constrained:
            status = 'unverified'
    return matches, status


def logs_report(data, cores, unit, journal, journal_status, working_dir, docs, acquisition_status):
    logs = []
    declarations_list = [('Log.Output', 'manager', mapping(data.get('Log')).get('Output'), False)]
    for index, core in enumerate(cores, 1):
        kind = enum(core.get('Type'), CORES)
        log = mapping(core.get('Log'))
        if kind == 'hysteria2':
            # This upstream schema exposes only Log.Level, not Log.Output.
            declarations_list.append((f'Cores[{index}].Log', kind, None, False))
            continue
        keys = ('AccessPath', 'ErrorPath') if kind == 'xray' else ('Output',)
        for key in keys:
            disabled = (kind == 'xray' and key == 'AccessPath' and not log.get(key)) or (kind == 'sing' and log.get('Disable') is True)
            declarations_list.append((f'Cores[{index}].Log.{key}', kind, log.get(key), disabled))
    for ref, core, location, disabled in declarations_list:
        path = None
        if disabled:
            text, state, source = None, 'disabled', 'disabled'
        elif isinstance(location, str) and location:
            candidate = Path(location)
            path = candidate if candidate.is_absolute() else working_dir / candidate if working_dir else None
            if path is None:
                text, state = None, 'relative_path_unresolved'
            else:
                text, state = read_regular(path, 65536, tail=True)
            source = 'file'
        else:
            source = 'journal_candidate'
            text, state = journal, journal_status
        matches, acquired = (0, 'not_applicable') if disabled else acquisition_report(path, unit, docs, acquisition_status) if source != 'file' or path else (0, 'unverified')
        logs.append({'config_ref': ref, 'core': core, 'source': source,
                     'read_status': state, 'acquisition_matches': matches,
                     'acquisition_status': acquired, 'sample': sample_report(text),
                     'evidence_scope': 'shared_unit' if source == 'journal_candidate' else 'declared_file',
                     'detection_status': 'unverified'})
    return logs


def inspect(options):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service', options.unit):
        raise InputError('invalid_unit')
    # Explicit configuration is validated before any local commands.
    data = config_read(Path(options.config)) if options.config else None
    if data is not None:
        nodes = data.get('Nodes', [])
        if not isinstance(nodes, list) or len(nodes) > 256:
            raise InputError('invalid_config')
        entries = declarations(options.entries, len(nodes))
    else:
        entries = {}
        if options.entries:
            declarations(options.entries, 256)
    current, fields = runtime(options.unit)
    if data is None:
        chosen = running_config(current['main_pid'])
        current['config_origin'] = 'running_process' if chosen else 'default_candidate'
        data = config_read(chosen or Path('/etc/V2bX/config.json'))
    else:
        current['config_origin'] = 'operator_selected'
    cores, nodes = data.get('Cores', []), data.get('Nodes', [])
    if not isinstance(cores, list) or not isinstance(nodes, list) or len(cores) > 32 or len(nodes) > 256:
        raise InputError('invalid_config')
    if any(not isinstance(c, dict) for c in cores):
        raise InputError('invalid_config')
    entries = declarations(options.entries, len(nodes))
    wd = options.working_dir or fields.get('WorkingDirectory')
    working_dir = Path(wd) if isinstance(wd, str) and Path(wd).is_absolute() else None
    node_reports = [node_report(n, i, cores, entries.get(i, 'unknown'), working_dir)
                    for i, n in enumerate(nodes, 1)]
    journal, journal_status = command(['journalctl', '--unit='+options.unit, '--no-pager',
                                        '--lines=200', '--output=cat'])
    # Version is historical journal evidence, not the installed/running binary.
    versions = re.findall(r'^V2bX (v?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?) \(A V2board backend based on multi core\)', journal or '', re.M)
    if versions:
        current['version'] = versions[-1]
        current['version_status'] = 'journal_candidate'
    docs, acquisition_status = acquisitions(options.cs_dir)
    sockets, socket_status = socket_report(current['main_pid'])
    # Reuse existing local-only Bouncer audit; discard all raw output.
    audit = Path(__file__).with_name('crowdsec_relay.py')
    references = {family: {chain: False for chain in ('INPUT', 'FORWARD')}
                  for family in ('ipv4', 'ipv6')}
    try:
        checked = subprocess.run([sys.executable, str(audit), 'audit', options.cs_dir],
                                 capture_output=True, text=True, timeout=20)
        bouncer = {0: 'local_references_present', 2: 'unverified'}.get(checked.returncode, 'check_failed')
        lines = set(checked.stdout.splitlines())
        for family, label in (('ipv4', 'IPv4'), ('ipv6', 'IPv6')):
            for chain in ('INPUT', 'FORWARD'):
                references[family][chain] = f'{label} {chain}: 已发现来源 IP 集合封禁规则引用' in lines
    except (OSError, subprocess.TimeoutExpired):
        bouncer = 'check_failed'
    return {'config_status': 'readable', 'runtime': current,
            'cores': [{'index': i, 'type': enum(c.get('Type'), CORES),
                       'log_level': enum(mapping(c.get('Log')).get('Level'), LEVELS),
                       'logging_disabled_declared': mapping(c.get('Log')).get('Disable') is True,
                       'custom_config_declared': bool(c.get('OriginalPath') or c.get('InboundConfigPath'))}
                      for i, c in enumerate(cores, 1)],
            'nodes': node_reports, 'sockets': sockets, 'socket_status': socket_status,
            'acquisition_status': acquisition_status,
            'logs': logs_report(data, cores, options.unit, journal, journal_status,
                                working_dir, docs, acquisition_status),
            'bouncer_status': bouncer, 'bouncer_references': references,
            'end_to_end_status': 'unverified'}


def display(report):
    print('V2bX 只读诊断：配置声明、本机证据和端到端验证分别报告。')
    if report['config_status'] != 'readable':
        print('[异常] 配置/输入不可用：'+report['config_status'])
        return
    r = report['runtime']
    print(f"服务：{r['load']}/{r['active']}；读取={r['service_status']}；配置来源={r['config_origin']}")
    print('版本（仅历史 journal 候选）：'+(r['version'] or '尚未验证'))
    for c in report['cores']:
        print(f"内核 #{c['index']}：{c['type']}；日志级别={c['log_level']}；自定义内核配置声明={c['custom_config_declared']}")
    for n in report['nodes']:
        print(f"节点 #{n['index']}：{n['core']}/{n['protocol']}；监听 IP={n['listen_ip'] or '未知'}；入口声明={n['entry_declared']}")
        print(f"  配置={n['config_status']}；PROXY protocol 声明={n['proxy_protocol_declared']}；封禁位置建议={n['enforcement']}")
        print('  [尚未验证] 端口/传输通常由面板下发；日志 IP、数据包 IP、限制字段效果需实际核验。')
    print('本机 socket 读取：'+report['socket_status'])
    for s in report['sockets']:
        if s['service_pid_match']:
            print(f"  服务 PID 匹配：{s['network']} {s['address']}:{s['port']}；节点归属尚未验证")
    for log in report['logs']:
        sample = log['sample']
        print(f"日志 {log['config_ref']}：{log['source']}/{log['read_status']}；采集={log['acquisition_status']}（匹配 {log['acquisition_matches']}）")
        print(f"  有界样本：连接={sample['connected']}，断开={sample['disconnected']}，失败候选={sample['failure_candidates']}，普通错误={sample['ordinary_errors']}；专用检测尚未验证")
    print('Bouncer 本地证据：'+report['bouncer_status']+'；不等于实际业务阻断。')
    for family, chains in report['bouncer_references'].items():
        for chain, found in chains.items():
            print(f"  {family} {chain}："+('已发现来源集合封禁规则引用' if found else '尚未发现可识别引用'))
    print('[尚未验证] 混合入口需逐路径核验：直连落地封禁；中转保源需验证；代理中转需可信来源并在可见用户 IP 的节点执行。')
    print('中转汇聚错误不应封禁中转 IP；PROXY protocol 不改变数据包源 IP。日志原文、凭据和路径不输出。')
    print('journal 候选为整个 unit 的共享样本，不能据此归因某个内核；文件采集存在不证明事件被正确解析。')
    print('下一步：提供各内核/协议脱敏失败事件及路径证据，再接入专用规则；本工具不配置限速或带宽清洗。')


def main(args):
    parser = Parser(description='V2bX 只读诊断；未进行端到端验证时返回 2。')
    parser.add_argument('--config', help='明确选择本机配置文件')
    parser.add_argument('--cs-dir', default='/etc/crowdsec')
    parser.add_argument('--unit', default='V2bX.service')
    parser.add_argument('--working-dir', help='相对 Include/日志路径的实际工作目录')
    parser.add_argument('--entries', default='', help='1:direct,2:relay-proxy；按 Nodes 顺序声明')
    parser.add_argument('--json', action='store_true')
    try:
        options = parser.parse_args(args)
        report = inspect(options)
        code = 1 if report['runtime']['service_status'] in ('read_failed', 'too_large') or report['socket_status'] in ('read_failed', 'too_large') else 2
    except (InputError, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        report = {'config_status': str(error) if isinstance(error, InputError) else 'read_failed'}
        code = 1
    if '--json' in args:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        display(report)
    return code


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

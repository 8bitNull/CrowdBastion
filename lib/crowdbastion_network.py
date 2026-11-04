#!/usr/bin/env python3
"""Opt-in selected per-network TCP defaults; configuration checks are not throughput tests.

Recovery imports stdlib only. No config text is evaluated and no sysctl loader
is executed. Ordinary tests inject host commands and use a filesystem root.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys

from crowdbastion_change import (Engine, ROOT, command, canonical, file_state,
                                 file_value, json_read, private_profile_read, write_file)
from crowdbastion_ux import code_fingerprint, read_regular, runtime_cron_matches, validate_private_destination

REASONS = {
    'net.ipv4.tcp_syn_retries': 'Restore local-kernel active handshake retry tolerance.',
    'net.ipv4.tcp_synack_retries': 'Restore local-kernel passive handshake retry tolerance.',
    'net.ipv4.tcp_orphan_retries': 'Restore kernel orphan retry policy; zero does not mean no retries.',
    'net.ipv4.tcp_fin_timeout': 'Restore orphan FIN_WAIT_2 lifetime, not all TCP connection lifetimes.',
    'net.ipv4.tcp_autocorking': 'Restore kernel small-write coalescing policy.',
    'net.ipv4.tcp_no_metrics_save': 'Restore kernel connection metrics caching policy.',
    'net.ipv4.tcp_tw_reuse': 'Restore this kernel TIME_WAIT reuse scope.',
}
LAYERS = ('etc/sysctl.d', 'run/sysctl.d', 'usr/local/lib/sysctl.d', 'usr/lib/sysctl.d', 'lib/sysctl.d')
OWNED_NAME = '99-zz-crowdbastion-network.conf'
PROFILE = Path('/var/lib/crowdbastion/network.json')
# Fixed internal code reads ONLY the seven per-net keys. Never accepts config
# code, writes, global tcp_mem, core buffers, or arbitrary caller paths.
DEFAULT_SCRIPT = ('import json,pathlib; keys='+repr(tuple(REASONS))+'; '
                  'print(json.dumps({k:pathlib.Path("/proc/sys",k.replace(".","/")).read_text().strip() for k in keys}))')

class CheckError(ValueError):
    def __init__(self, phase, error_code, retryable=False, duration_seconds=None):
        super().__init__('network local baseline unavailable')
        self.diagnostic = {'phase': phase, 'error_code': error_code, 'retryable': retryable,
                           'scope': 'local_service_api_baseline'}
        if duration_seconds is not None: self.diagnostic['duration_seconds'] = duration_seconds


def validate(profile):
    if (not isinstance(profile, dict) or set(profile) != {'version', 'loader', 'keys', 'sources'} or
            type(profile['version']) is not int or profile['version'] != 1 or
            profile['loader'] not in ('systemd', 'procps') or
            not isinstance(profile['keys'], list) or not profile['keys'] or
            any(not isinstance(key, str) or key not in REASONS for key in profile['keys']) or
            len(set(profile['keys'])) != len(profile['keys']) or
            not isinstance(profile['sources'], list) or
            any(not isinstance(path, str) or not Path(path).is_absolute() for path in profile['sources']) or
            len(set(profile['sources'])) != len(profile['sources'])):
        raise ValueError('invalid network profile')
    return profile


def parse_assignments(text):
    rows, unsupported = [], []
    for number, line in enumerate(text.splitlines(), 1):
        text = line.strip()
        if not text or text.startswith(('#', ';')): continue
        # Accept complete plain assignments only. Inline/complex syntax is
        # intentionally unknown rather than borrowing shell comment rules.
        match = re.fullmatch(r'-?([A-Za-z0-9_./]+)\s*=\s*([A-Za-z0-9_+-]+(?:\s+[A-Za-z0-9_+-]+)*)', text)
        if match:
            key = match[1].replace('/', '.')
            if key.startswith('net.'):
                rows.append({'key': key, 'value': ' '.join(match[2].split()), 'line': number})
        elif re.match(r'-?net[./]', text) or not re.match(r'-?[A-Za-z0-9_]+[./]', text):
            # Includes, shell/dynamic syntax and unknown loader directives are
            # not proof of absence; output only locations, never source text.
            unsupported.append(number)
    return rows, unsupported


def runtime_status(manager, runtime, cron):
    result = {'state': 'unknown', 'manager': str(manager), 'current': str(runtime/'current/manager.sh'), 'active': []}
    try:
        source = code_fingerprint(manager)
        result['source_sha256'] = source
        current = runtime/'current/manager.sh'
        if current.exists() or current.is_symlink():
            result['current_sha256'] = code_fingerprint(current)
            result['current_matches_source'] = result['current_sha256'] == source
        else: result['current_sha256'] = None
        if cron.exists() or cron.is_symlink():
            data = read_regular(cron, 65536)
            result['cron_sha256'] = hashlib.sha256(data).hexdigest()
            for line in data.decode('utf-8').splitlines():
                text = line.strip()
                if not text or text.startswith('#') or '--update-hub' not in text: continue
                fields = text.split(None, 2 if text.startswith('@') else 6)
                user = 1 if text.startswith('@') else 5
                if len(fields) != user+2 or fields[user] != 'root': raise ValueError('unknown maintenance cron')
                words = shlex.split(fields[-1], comments=True)
                if (len(words) < 3 or words[0] not in ('bash', '/bin/bash', '/usr/bin/bash') or
                        words[2] != '--update-hub' or not Path(words[1]).is_absolute()):
                    raise ValueError('unknown maintenance command')
                if words[3:] not in ([], ['>/dev/null', '2>&1'], ['>', '/dev/null', '2>&1']):
                    raise ValueError('unsupported maintenance command suffix')
                active = Path(words[1]); digest = code_fingerprint(active)
                if not runtime_cron_matches(cron, active): raise ValueError('unknown cron')
                result['active'].append({'manager': str(active), 'real_path': str(active.resolve(strict=True)),
                    'schedule': ' '.join(fields[:user]), 'sha256': digest, 'matches_source': digest == source})
        else: result['cron_sha256'] = None
        result['state'] = 'known'
    except (OSError, ValueError, UnicodeError): pass
    return result


def alias_ownership(path, *, directory=False, expected=None):
    """Inspect original and resolved link chains; never trust only the target.

    Root-owned sticky outer ancestors support fixture/shared /tmp layouts, but
    the immediate configuration directory/layer must not be writable by others.
    Link mode bits are not meaningful; their owner and every parent are checked.
    """
    path = Path(path); pending = [(path, directory)]; visited = set(); chain = {}; trusted = True
    try:
        while pending:
            candidate, is_directory = pending.pop()
            identity = (str(candidate), is_directory)
            if identity in visited: continue
            visited.add(identity)
            if len(visited) > 64: raise ValueError('alias chain too complex')
            for part in (candidate, *candidate.parents):
                strict = part == candidate.parent or is_directory and part == candidate
                try:
                    info = part.lstat(); mode = info.st_mode; uid = info.st_uid; gid = info.st_gid
                except FileNotFoundError:
                    if expected is None or part != path and part not in path.parents: raise
                    mode = (stat.S_IFREG | expected['mode']) if part == path else (stat.S_IFDIR | 0o755)
                    uid, gid = expected['uid'], expected['gid']
                record = {'uid': uid, 'gid': gid, 'mode': stat.S_IMODE(mode)}
                safe = uid == os.geteuid()
                if stat.S_ISLNK(mode):
                    target = os.readlink(part); record.update(kind='symlink', target=target)
                    target_path = Path(target) if Path(target).is_absolute() else part.parent/target
                    pending.append((target_path, part != candidate or is_directory))
                elif stat.S_ISDIR(mode):
                    record['kind'] = 'directory'
                    safe = safe and (not mode & 0o022 or bool(mode & stat.S_ISVTX) and not strict)
                elif stat.S_ISREG(mode) and part == candidate and not is_directory:
                    record['kind'] = 'file'; safe = safe and not mode & 0o022
                elif part == Path('/dev/null') and stat.S_ISCHR(mode) and not is_directory:
                    record['kind'] = 'mask-device'
                else:
                    record['kind'] = 'unsupported'; safe = False
                chain[str(part)] = record; trusted = trusted and safe
        return {'trusted': trusted, 'chain': dict(sorted(chain.items()))}
    except (OSError, ValueError):
        return {'trusted': False, 'chain': dict(sorted(chain.items())), 'error_code': 'alias_unreadable'}


class Backend:
    def __init__(self, root=ROOT, *, host_root=Path('/'), manager=None, runtime=Path('/usr/local/lib/crowdsec-1key'),
                 cron=Path('/etc/cron.d/crowdsec-autoupdate'), run=command, probe=None):
        self.root = Path(root); self.host_root = Path(host_root)
        self.manager = Path(manager) if manager else Path(__file__).resolve().parent.parent/'crowdbastion.sh'
        self.runtime = Path(runtime); self.cron = Path(cron); self.run = run
        self.owned = self.host_root/'etc/sysctl.d'/OWNED_NAME
        self.state_path = self.root/'network-state.json'
        self.probe = probe or self.local_probe
        self.baseline = None; self.forward = False; self.diagnostic = None; self.metadata = None
    def proc_path(self, key):
        if key not in REASONS: raise ValueError('unsupported key')
        return self.host_root/'proc/sys'/key.replace('.', '/')
    def audit(self):
        files, paths, problems, choices = {}, {}, [], {}
        for directory in LAYERS:
            path = self.host_root/directory
            try:
                if not path.exists():
                    if path.is_symlink(): raise ValueError('broken layer')
                    continue
                if not alias_ownership(path, directory=True)['trusted']:
                    problems.append({'path': str(path), 'error_code': 'layer_ownership_unsafe'})
                for entry in sorted(path.iterdir()):
                    if entry.name.endswith('.conf'):
                        paths[str(entry)] = entry
                        choices.setdefault(entry.name, entry)
            except (OSError, ValueError): problems.append({'path': str(path), 'error_code': 'layer_unreadable'})
        legacy = self.host_root/'etc/sysctl.conf'
        if legacy.exists() or legacy.is_symlink(): paths[str(legacy)] = legacy
        for alias, entry in paths.items():
            try:
                real = entry.resolve(strict=True)
                alias_state = alias_ownership(entry)
                # Distribution /dev/null masks are declarations of no config.
                if str(real) == '/dev/null':
                    row = files.setdefault('/dev/null', {'real_path': '/dev/null', 'aliases': [], 'alias_targets': {},
                        'sha256': None, 'assignments': [], 'unsupported_lines': [], 'masked': True,
                        'uid': 0, 'gid': 0, 'mode': None, 'trusted': True, 'target_trusted': True, 'alias_ownership': {}})
                    row['alias_ownership'][alias] = alias_state; row['trusted'] = row['trusted'] and alias_state['trusted']
                    row['aliases'].append(alias); row['alias_targets'][alias] = os.readlink(entry) if entry.is_symlink() else None
                    paths[alias] = '/dev/null'; continue
                data = read_regular(real, 1024*1024)
                text = data.decode('utf-8')
                rows, unsupported = parse_assignments(text)
                info = real.stat()
                trusted = info.st_uid == os.geteuid() and not info.st_mode & 0o022
                try: validate_private_destination(real)
                except (ValueError, OSError): trusted = False
                if str(real) not in files:
                    files[str(real)] = {'real_path': str(real), 'aliases': [], 'alias_targets': {}, 'sha256': hashlib.sha256(data).hexdigest(),
                                       'assignments': rows, 'unsupported_lines': unsupported, 'masked': False,
                                       'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
                                       'trusted': trusted, 'target_trusted': trusted, 'alias_ownership': {}}
                files[str(real)]['alias_ownership'][alias] = alias_state
                files[str(real)]['trusted'] = files[str(real)]['trusted'] and alias_state['trusted']
                files[str(real)]['aliases'].append(alias)
                files[str(real)]['alias_targets'][alias] = os.readlink(entry) if entry.is_symlink() else None
                paths[alias] = str(real)
            except (OSError, ValueError, UnicodeError):
                paths[alias] = None
                problems.append({'path': alias, 'error_code': 'source_unreadable'})
        ordered = [str(choices[name]) for name in sorted(choices)]
        loaders = {}
        for loader in ('systemd', 'procps'):
            sequence = ordered + ([str(legacy)] if loader == 'procps' and str(legacy) in paths else [])
            effective, active_unknown = {}, False
            for alias in sequence:
                real = paths.get(alias)
                if real is None:
                    if any(row['path'] == alias for row in problems): active_unknown = True
                    continue
                row = files[real]
                if row['unsupported_lines'] or not row['target_trusted'] or not row['alias_ownership'][alias]['trusted']: active_unknown = True
                for assignment in row['assignments']:
                    effective[assignment['key']] = dict(assignment, path=alias, real_path=real)
            loaders[loader] = {'state': 'unknown' if problems or active_unknown else 'known',
                               'sequence': sequence, 'effective': effective}
        running = {}
        keys = set(REASONS) | {item['key'] for row in files.values() for item in row['assignments']}
        for key in sorted(keys):
            try:
                value = read_regular(self.host_root/'proc/sys'/key.replace('.', '/'), 4096).decode('ascii').strip()
                running[key] = value if re.fullmatch(r'[A-Za-z0-9_+.-]+(?:\s+[A-Za-z0-9_+.-]+)*', value) else None
            except (ValueError, OSError, UnicodeError): running[key] = None
        runtime = runtime_status(self.manager, self.runtime, self.cron)
        owned = {'path': str(self.owned), 'state': 'unknown'}
        try:
            previous = load_state(self)
            current = file_state(self.owned)
            if previous is None: owned['state'] = 'absent' if current is None else 'foreign'
            else: owned['state'] = 'managed' if current == previous['owned'] else 'drift'
        except (ValueError, OSError, KeyError, TypeError): pass
        return {'version': 1, 'state': 'unknown' if problems or runtime['state'] == 'unknown' or owned['state'] == 'unknown' or
                any(row['state'] == 'unknown' for row in loaders.values()) else 'audited', 'files': list(files.values()),
                'loaders': loaders, 'running': running, 'problems': problems, 'runtime': runtime, 'owned_file': owned,
                'verification': 'selected configuration only; relay throughput untested'}
    def defaults(self, keys):
        try:
            values = json.loads(self.run(['unshare', '--net', '--', '/usr/bin/python3', '-I', '-S', '-c', DEFAULT_SCRIPT]))
            if (not isinstance(values, dict) or any(key not in REASONS for key in values) or
                    any(not isinstance(values.get(key), str) or not re.fullmatch(r'\d+', values[key]) for key in keys)):
                raise ValueError('defaults unavailable')
            return {'state': 'known', 'values': {key: values[key] for key in keys}, 'source': 'local-kernel-transient-netns'}
        except (OSError, ValueError, subprocess.SubprocessError):
            return {'state': 'unknown', 'values': {}, 'error_code': 'kernel_defaults_unavailable'}
    def read(self, resource):
        if not isinstance(resource, dict): raise ValueError('invalid resource')
        if set(resource) == {'kind', 'key'} and resource['kind'] == 'sysctl':
            value = read_regular(self.proc_path(resource['key']), 128).decode('ascii').strip()
            if not re.fullmatch(r'\d+', value): raise ValueError('invalid selected value')
            return value
        if set(resource) == {'kind', 'path'} and resource['kind'] == 'file' and resource['path'] in (str(self.owned), str(self.state_path)):
            return file_state(Path(resource['path']))
        raise ValueError('invalid resource')
    def write(self, resource, before, after):
        if self.read(resource) != before: raise ValueError('resource drift')
        if resource['kind'] == 'sysctl':
            if not isinstance(after, str) or not re.fullmatch(r'\d+', after): raise ValueError('invalid selected value')
            # Writing a single proc entry avoids sysctl name/options ambiguity.
            with open(self.proc_path(resource['key']), 'w', encoding='ascii') as stream: stream.write(after+'\n')
            if self.read(resource) != after: raise ValueError('readback failed')
            if self.forward and after == self.metadata['defaults'].get(resource['key']): self.check_baseline()
        else:
            if self.forward and Path(resource['path']) == self.owned and after == self.metadata['owned_after']:
                self.check_baseline()
                if stamp(self.audit()) != self.metadata['before_stamp']: raise ValueError('configuration drift')
            write_file(Path(resource['path']), before, after)
    def local_probe(self):
        services = {}
        for unit in ('crowdsec.service', 'crowdsec-firewall-bouncer.service', 'docker.service', 'V2bX.service', 'v2bx.service'):
            output = self.run(['systemctl', 'show', unit, '--property=LoadState,ActiveState,MainPID,NRestarts'])
            fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
            if fields.get('LoadState') == 'not-found': continue
            if fields.get('LoadState') != 'loaded' or not all(k in fields for k in ('ActiveState', 'MainPID', 'NRestarts')):
                raise CheckError('service_baseline', 'service_status_unknown')
            services[unit] = [fields['ActiveState'], fields['MainPID'], fields['NRestarts']]
        if not services or not any(row[0] == 'active' for row in services.values()):
            raise CheckError('service_baseline', 'active_service_baseline_unavailable')
        # Dependencies are lazy: timed rollback must work on system Python even
        # when caller used a venv and system Python lacks PyYAML.
        try:
            from crowdsec_firewall_evidence import live, EvidenceError
        except ImportError: raise CheckError('api_baseline', 'api_dependency_unavailable') from None
        try: live(self.host_root/'etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
        except EvidenceError as error:
            raise CheckError(error.phase, error.error_code, error.retryable, error.duration_seconds) from None
        return {'services': services, 'api': 'ok'}
    def check_baseline(self):
        try:
            current = self.probe()
            if current != self.baseline: raise CheckError('service_baseline', 'service_baseline_changed')
        except CheckError as error:
            self.diagnostic = error.diagnostic; raise
    def preflight(self, metadata):
        validate(metadata['profile'])
        if stamp(self.audit()) != metadata['before_stamp']: raise ValueError('configuration drift')
        self.metadata = metadata
        try:
            self.baseline = metadata['baseline']
            self.check_baseline()
        except CheckError as error:
            self.diagnostic = error.diagnostic; raise
        self.forward = True
    def verify(self, metadata):
        self.baseline = metadata['baseline']; self.metadata = metadata
        self.check_baseline()
        report = self.audit()
        if stamp(report) != metadata['after_stamp'] or report['owned_file']['state'] != 'managed': return False
        return all(report['running'][key] == value and
                   report['loaders'][metadata['profile']['loader']]['effective'].get(key, {}).get('value') == value
                   for key, value in metadata['defaults'].items())


def stamp(report):
    return {'files': [{key: row[key] for key in ('real_path', 'aliases', 'alias_targets', 'sha256', 'uid', 'gid', 'mode', 'masked', 'trusted', 'target_trusted', 'alias_ownership')} for row in sorted(report['files'], key=lambda row: row['real_path'])],
            'loaders': {key: value['sequence'] for key, value in report['loaders'].items()},
            'loader_states': {key: value['state'] for key, value in report['loaders'].items()},
            'problems': report['problems'], 'runtime': report['runtime']}


def load_state(backend):
    if not backend.state_path.exists(): return None
    state = json_read(backend.state_path)
    if not isinstance(state, dict) or set(state) != {'version', 'owned'} or type(state['version']) is not int or state['version'] != 1: raise ValueError('invalid network state')
    return state


def make_plan(backend, profile):
    validate(profile)
    report = backend.audit(); defaults = backend.defaults(profile['keys']); blockers = []
    loader = report['loaders'][profile['loader']]
    if loader['state'] != 'known': blockers.append('unsupported_or_unreadable_configuration')
    if report['runtime']['state'] != 'known': blockers.append('maintenance_runtime_unknown')
    if any(not row['matches_source'] for row in report['runtime']['active']): blockers.append('maintenance_runtime_drift')
    if defaults['state'] != 'known': blockers.append('kernel_defaults_unavailable')
    if report['owned_file']['state'] not in ('absent', 'managed'): blockers.append('owned_file_drift_or_foreign')
    known = {row['real_path'] for row in report['files']}
    if any(path not in known for path in profile['sources']): blockers.append('unknown_approved_source')
    changes = []
    for key in profile['keys']:
        competing, later = [], False
        for alias in loader['sequence']:
            row = next((row for row in report['files'] if alias in row['aliases']), None)
            if row is None or row['real_path'] == str(backend.owned): continue
            if any(item['key'] == key for item in row['assignments']):
                if row['real_path'] not in competing: competing.append(row['real_path'])
                if (profile['loader'] == 'procps' and alias == str(backend.host_root/'etc/sysctl.conf') or
                        Path(alias).name > OWNED_NAME): later = True
        if any(path not in profile['sources'] for path in competing): blockers.append('competing_source_not_acknowledged')
        if later: blockers.append('later_selected_override')
        if report['running'][key] is None: blockers.append('selected_running_value_unknown')
        changes.append({'key': key, 'before': report['running'][key], 'after': defaults['values'].get(key),
                        'reason': REASONS[key], 'competing_sources': competing})
    return {'version': 1, 'state': 'blocked' if blockers else 'ready', 'blockers': sorted(set(blockers)),
            'profile': profile, 'changes': changes, 'defaults': defaults, 'audit': report,
            'persistence': 'selected-overrides', 'owned_path': str(backend.owned),
            'verification': 'selected configuration and local baseline only; relay throughput untested'}


def apply_network(backend, profile, *, engine=None):
    validate(profile); engine = engine or Engine(backend.root, backend)
    prepared = make_plan(backend, profile)
    if prepared['state'] != 'ready': raise ValueError('network plan blocked')
    before_owned = file_state(backend.owned)
    old_text = base64.b64decode(before_owned['content']).decode('utf-8') if before_owned else (
        '# CrowdBastion owned selected TCP defaults; earlier assignments remain reported.\n')
    remaining = set(profile['keys']); lines = []
    for line in old_text.splitlines(keepends=True):
        match = re.fullmatch(r'(net\.ipv4\.tcp_[a-z_]+) = \d+\n?', line)
        if match and match[1] in remaining:
            key = match[1]; line = key+' = '+prepared['defaults']['values'][key]+'\n'; remaining.remove(key)
        lines.append(line)
    text = ''.join(lines)
    text += ''.join(key+' = '+prepared['defaults']['values'][key]+'\n' for key in profile['keys'] if key in remaining)
    after = file_value(text, 0o644)
    if (file_state(backend.owned) == after and
            all(row['before'] == row['after'] for row in prepared['changes'])):
        # Repeated apply still samples the environment under the shared lock.
        from crowdbastion_change import maintenance_lock
        with maintenance_lock(engine.lock_path):
            engine.guard()
            pending = [row for row in engine.status().get('transactions', []) if row['state'] not in ('committed', 'rolled_back', 'preparation_incomplete')]
            if pending:
                ident = engine.select('network')
                return engine.status(ident)
            baseline = backend.probe()
            current = backend.audit()
            if (stamp(current) != stamp(prepared['audit']) or current['owned_file']['state'] != 'managed' or
                    any(current['running'].get(key) != value for key, value in prepared['defaults']['values'].items())):
                raise ValueError('configuration drift')
            return {'version': 1, 'state': 'verified', 'kind': 'network', 'unchanged': True, 'traffic_tested': False,
                    'baseline': baseline}
    def prepare(runtime):
        fresh = make_plan(backend, profile)
        if fresh['state'] != 'ready' or stamp(fresh['audit']) != stamp(prepared['audit']) or fresh['defaults'] != prepared['defaults'] or fresh['changes'] != prepared['changes']:
            raise ValueError('network plan changed')
        # Baseline before each key is compared to this stable local baseline.
        baseline = backend.probe()
        effects = [{'resource': {'kind': 'sysctl', 'key': row['key']}, 'before': row['before'], 'after': row['after']}
                   for row in fresh['changes'] if row['before'] != row['after']]
        before_stamp = stamp(fresh['audit'])
        after_stamp = json.loads(json.dumps(before_stamp))
        after_stamp['files'] = [row for row in after_stamp['files'] if row['real_path'] != str(backend.owned)]
        after_stamp['files'].append({'real_path': str(backend.owned), 'aliases': [str(backend.owned)],
                                    'alias_targets': {str(backend.owned): None}, 'masked': False, 'trusted': True, 'target_trusted': True,
                                    'alias_ownership': {str(backend.owned): alias_ownership(backend.owned, expected=after)},
                                    'uid': after['uid'], 'gid': after['gid'], 'mode': after['mode'],
                                    'sha256': hashlib.sha256(text.encode()).hexdigest()})
        # Inventory order is canonicalized independently of directory iteration.
        after_stamp['files'].sort(key=lambda row: row['real_path'])
        for loader in after_stamp['loaders']:
            sequence = after_stamp['loaders'][loader]
            sequence = [path for path in sequence if Path(path).name != OWNED_NAME]
            legacy = str(backend.host_root/'etc/sysctl.conf')
            suffix = [legacy] if loader == 'procps' and legacy in sequence else []
            sequence = sorted([path for path in sequence if not suffix or path != legacy] + [str(backend.owned)], key=lambda path: Path(path).name)
            after_stamp['loaders'][loader] = sequence + suffix
        before = file_state(backend.owned)
        if before != after: effects.append({'resource': {'kind': 'file', 'path': str(backend.owned)}, 'before': before, 'after': after})
        state = file_value(canonical({'version': 1, 'owned': after}).decode())
        effects.append({'resource': {'kind': 'file', 'path': str(backend.state_path)}, 'before': file_state(backend.state_path), 'after': state})
        return effects, {'profile': profile, 'defaults': fresh['defaults']['values'], 'baseline': baseline,
                         'before_stamp': before_stamp, 'after_stamp': after_stamp, 'owned_after': after}
    dependencies = [Path(__file__).parent/name for name in ('crowdbastion_network.py', 'crowdsec_firewall_evidence.py', 'crowdsec_config.py', 'crowdsec_remote_bouncer.py')]
    try:
        result = engine.apply('network', [], prepare=prepare, runtime_files=dependencies)
        if backend.diagnostic: result['diagnostic'] = backend.diagnostic
        return result
    finally: backend.forward = False


def transaction_adapter(root): return Backend(root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'plan', 'apply', 'verify', 'commit', 'rollback'))
    parser.add_argument('--config', type=Path, default=PROFILE)
    parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--id')
    parser.add_argument('--manager', type=Path); parser.add_argument('--runtime', type=Path, default=Path('/usr/local/lib/crowdsec-1key'))
    parser.add_argument('--cron', type=Path, default=Path('/etc/cron.d/crowdsec-autoupdate'))
    args = parser.parse_args(argv)
    if os.geteuid() != 0: raise ValueError('root required')
    backend = Backend(args.root, manager=args.manager, runtime=args.runtime, cron=args.cron); engine = Engine(args.root, backend)
    if args.action in ('verify', 'commit', 'rollback'):
        ident = engine.select('network', args.id)
        result = getattr(engine, args.action)(ident)
    elif args.action == 'status':
        result = backend.audit()
        result['transactions'] = [row for row in engine.status().get('transactions', []) if row.get('kind') == 'network']
    else:
        profile = validate(private_profile_read(args.config))
        result = make_plan(backend, profile) if args.action == 'plan' else apply_network(backend, profile, engine=engine)
    if backend.diagnostic: result['diagnostic'] = backend.diagnostic
    print(json.dumps(result, sort_keys=True))
    if result.get('error_code') == 'apply_failed': return 1
    return 0 if result.get('state') in ('audited', 'ready', 'verified', 'staged', 'committed', 'rolled_back') else 1


def cli(argv=None):
    from crowdbastion_change import ChangeRefused
    from crowdbastion_environment import EnvironmentNotReady
    try: return main(argv)
    except EnvironmentNotReady as error:
        print(json.dumps(error.report, sort_keys=True)); return 75
    except BlockingIOError:
        print(json.dumps({'version': 1, 'state': 'refused', 'error_code': 'change_busy', 'retryable': True})); return 75
    except ChangeRefused as error:
        print(json.dumps(error.report, sort_keys=True)); return 1
    except CheckError as error:
        print(json.dumps({'version': 1, 'state': 'refused', 'error_code': 'network_baseline_unavailable', 'diagnostic': error.diagnostic})); return 1
    except (ValueError, OSError, KeyError, TypeError, IndexError, ImportError, subprocess.SubprocessError):
        print(json.dumps({'version': 1, 'state': 'refused', 'error_code': 'network_change_refused'})); return 1


if __name__ == '__main__': sys.exit(cli())

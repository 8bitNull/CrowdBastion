#!/usr/bin/env python3
"""Opt-in, deny-only host/Docker ingress policy. No executable configuration."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

PREFIX = 'CBP_'
PARENTS = ('INPUT', 'DOCKER-USER')
DEFAULT_ROOT = Path('/var/lib/crowdbastion/changes')
PROFILE = Path('/var/lib/crowdbastion/port-policy.json')


def cidrs(values):
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError('invalid sources')
    result = []
    for value in values:
        if not isinstance(value, str): raise ValueError('invalid source')
        network = ipaddress.ip_network(value, strict=True)
        if (network.prefixlen == 0 or network.is_unspecified or network.is_loopback or
                network.is_multicast or network.is_link_local or str(network) != value):
            raise ValueError('unsafe source')
        result.append(value)
    if len(result) != len(set(result)): raise ValueError('duplicate source')
    return result


def validate(data):
    if (not isinstance(data, dict) or set(data) != {'version', 'topology', 'ingress'} or
            type(data['version']) is not int or data['version'] != 1):
        raise ValueError('invalid policy')
    topology = data['topology']
    if (not isinstance(topology, dict) or set(topology) != {'kind', 'relay_sources'} or
            topology['kind'] not in ('direct', 'shared-relay', 'unknown')):
        raise ValueError('invalid topology')
    relay = cidrs(topology['relay_sources'])
    if (topology['kind'] == 'shared-relay') != bool(relay): raise ValueError('invalid relay declaration')
    ingress = data['ingress']
    if not isinstance(ingress, list) or not 1 <= len(ingress) <= 128: raise ValueError('invalid ingress')
    seen = set()
    for row in ingress:
        if (not isinstance(row, dict) or set(row) != {'interface', 'protocol', 'port', 'mode', 'sources'} or
                not isinstance(row['interface'], str) or
                not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}', row['interface']) or
                row['interface'] == 'lo' or row['protocol'] not in ('tcp', 'udp') or
                type(row['port']) is not int or not 1 <= row['port'] <= 65535 or
                row['mode'] not in ('public', 'local', 'sources')):
            raise ValueError('invalid ingress selector')
        sources = cidrs(row['sources'])
        if (row['mode'] == 'sources') != bool(sources): raise ValueError('invalid mode sources')
        selector = (row['interface'], row['protocol'], row['port'])
        if selector in seen: raise ValueError('duplicate selector')
        seen.add(selector)
    return copy.deepcopy(data)


def desired(data, *, docker=True):
    validate(data)
    docker_required = docker
    graph = {'4': {}, '6': {}}
    for row in data['ingress']:
        if row['mode'] == 'public': continue
        name = PREFIX + hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:20]
        for family in ('4', '6'):
            target = graph[family]
            target[name] = [['-s', source, '-j', 'RETURN'] for source in row['sources']
                            if ipaddress.ip_network(source).version == int(family)] + [['-j', 'DROP']]
            base = ['-i', row['interface'], '-p', row['protocol']]
            host = base + ['--dport', str(row['port']), '-j', name]
            docker_rule = base + ['-m', 'conntrack', '--ctorigdstport', str(row['port']), '--ctdir', 'ORIGINAL', '-j', name]
            target.setdefault('INPUT', []).append(host)
            if docker_required: target.setdefault('DOCKER-USER', []).append(docker_rule)
    return graph



def equivalent_graph(left, right):
    def normalized(graph):
        result = copy.deepcopy(graph)
        for table in result.values():
            for parent in PARENTS:
                if parent in table: table[parent] = sorted(table[parent])
        return result
    return normalized(left) == normalized(right)


def canonical_owned_rule(rule):
    """Normalize only the exact owned conntrack selector we support.

    libxt_conntrack saves original destination port before direction. Preserve
    every token of foreign/conditional rules so normalization cannot hide drift.
    """
    if (len(rule) == 12 and rule[0] == '-i' and rule[2] == '-p' and
            rule[3] in ('tcp', 'udp') and rule[4:6] == ['-m', 'conntrack'] and
            rule[-2] == '-j' and re.fullmatch(r'CBP_[a-f0-9]{20}', rule[-1])):
        options = rule[6:10]
        if (options[:2] == ['--ctdir', 'ORIGINAL'] and options[2] == '--ctorigdstport' and
                options[3].isdigit() and 1 <= int(options[3]) <= 65535):
            return rule[:6] + options[2:] + options[:2] + rule[-2:]
    return rule


def parse_rules(text):
    if not isinstance(text, str) or len(text) > 8 * 1024 * 1024: raise ValueError('rules unavailable')
    result = {}
    for line in text.splitlines():
        words = shlex.split(line)
        if not words: continue
        if words[0] in ('-P', '-N') and len(words) in (2, 3):
            if words[1] in result: raise ValueError('duplicate chain')
            result[words[1]] = []
        elif words[0] == '-A' and len(words) > 3 and words[1] in result:
            rule = words[2:]
            # libxt_tcp/udp is implicit for --dport; normalize its -S spelling.
            for protocol in ('tcp', 'udp'):
                if '-p' in rule and rule[rule.index('-p') + 1] == protocol:
                    for index in range(len(rule) - 1):
                        if rule[index:index+2] == ['-m', protocol]:
                            del rule[index:index+2]; break
            result[words[1]].append(canonical_owned_rule(rule))
        else: raise ValueError('unreadable rules')
    if 'INPUT' not in result: raise ValueError('rules unavailable')
    return result


def admin_ports(sockets, current):
    ports = set()
    try:
        for line in sockets.splitlines():
            if '"sshd"' not in line and '"sshd-session"' not in line: continue
            words = line.split()
            if len(words) < 6: raise ValueError('invalid ssh sockets')
            port = int(words[3].rsplit(':', 1)[1])
            if not 1 <= port <= 65535: raise ValueError('invalid ssh port')
            ports.add(port)
        if current:
            source, source_port, destination, port = current.split()
            ipaddress.ip_address(source); ipaddress.ip_address(destination)
            if not 1 <= int(source_port) <= 65535 or not 1 <= int(port) <= 65535: raise ValueError('invalid connection')
            ports.add(int(port))
    except (ValueError, IndexError): return {'state': 'unknown', 'ports': []}
    return {'state': 'known' if ports else 'unknown', 'ports': sorted(ports)}


def crowdsec_first(table, parent):
    rules = table.get(parent)
    if not isinstance(rules, list) or not rules: return False
    first = rules[0]
    if '-j' not in first: return False
    target = first[first.index('-j') + 1]
    return first == ['-j', target] and target in table and bool(re.fullmatch(r'crowdsec[-_A-Za-z0-9]*', target, re.I))


def check_ownership(current, managed, *, docker=True):
    for family in ('4', '6'):
        table = current.get(family)
        old = managed.get(family, {})
        if not isinstance(table, dict) or not isinstance(old, dict): raise ValueError('rules unavailable')
        forward = table.get('FORWARD', [])
        if docker and not (forward[:1] == [['-j', 'DOCKER-USER']] or
                crowdsec_first(table, 'FORWARD') and forward[1:2] == [['-j', 'DOCKER-USER']]):
            raise ValueError('docker forwarding path unknown')
        if any(name.startswith(PREFIX) and name not in old for name in table): raise ValueError('unknown ownership')
        if not docker and any(name.startswith('DOCKER') for name in table): raise ValueError('docker state ambiguous')
        for parent in (PARENTS if docker else ('INPUT',)):
            if not crowdsec_first(table, parent): raise ValueError('crowdsec path unknown')
            owned = old.get(parent, [])
            if table[parent][1:1+len(owned)] != owned: raise ValueError('managed rule drift')
            for rule in table[parent]:
                if any(token.startswith(PREFIX) for token in rule) and rule not in owned:
                    raise ValueError('unknown reference')
            if any(table[parent].count(rule) != 1 for rule in owned): raise ValueError('duplicate owned reference')
        for name, rules in old.items():
            if name not in PARENTS and (not name.startswith(PREFIX) or table.get(name) != rules):
                raise ValueError('managed chain drift')
        for name, rules in table.items():
            if name in PARENTS or name.startswith(PREFIX): continue
            if any(any(word.startswith(PREFIX) for word in rule) for rule in rules):
                raise ValueError('foreign reference')


def make_plan(data, current, managed, interfaces, admin, *, docker=True):
    data = validate(data)
    if any(row['interface'] not in interfaces for row in data['ingress']): raise ValueError('interface unavailable')
    restricted = [row for row in data['ingress'] if row['mode'] != 'public']
    if restricted and (admin.get('state') != 'known' or any(row['protocol'] == 'tcp' and row['port'] in admin['ports'] for row in restricted)):
        raise ValueError('management protection')
    check_ownership(current, managed, docker=docker)
    new = desired(data, docker=docker); working = copy.deepcopy(current); effects = []
    def step(family, chain, after):
        before = working[family].get(chain)
        effects.append({'resource': {'kind': 'chain', 'family': family, 'chain': chain},
                        'before': copy.deepcopy(before), 'after': copy.deepcopy(after)})
        if after is None: working[family].pop(chain)
        else: working[family][chain] = copy.deepcopy(after)
    for family in ('4', '6'):
        old = managed.get(family, {}); target = new[family]
        for name, rules in target.items():
            if name in PARENTS or name in old: continue
            step(family, name, [])
            for rule in rules: step(family, name, working[family][name] + [rule])
        for parent in (PARENTS if docker else ('INPUT',)):
            want = target.get(parent, []); previous = old.get(parent, [])
            # New restrictions precede previous ones until old rules are removed.
            for rule in reversed(want):
                if rule not in previous:
                    rules = copy.deepcopy(working[family][parent]); rules.insert(1, rule); step(family, parent, rules)
            for rule in previous:
                if rule not in want:
                    rules = copy.deepcopy(working[family][parent]); rules.remove(rule); step(family, parent, rules)
            # Selectors are disjoint. Keep surviving jump order and publish
            # the exact actual order, avoiding any removal of an existing
            # restriction solely to reorder unrelated ports.
            if want: target[parent] = [rule for rule in working[family][parent] if rule in want]
        for name, rules in old.items():
            if name in PARENTS or name in target: continue
            while working[family][name]: step(family, name, working[family][name][:-1])
            step(family, name, None)
    return {'version': 1, 'state': 'ready', 'effects': effects, 'managed': new,
            'scope': data, 'docker_required': docker, 'verification': 'rules-only; external traffic acceptance required'}


def lifecycle(runtime, root, unit_dir):
    """Owned retrying verifier/reapply, plus Docker/Bouncer post-start hooks."""
    runtime, root, unit_dir = map(Path, (runtime, root, unit_dir))
    for path in (runtime, root):
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)): raise ValueError('unsafe runtime')
    service = (f'[Unit]\nDescription=CrowdBastion selected ingress policy\n'
               'After=docker.service crowdsec-firewall-bouncer.service\nStartLimitIntervalSec=0\n'
               f'[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {runtime}/crowdbastion_port_policy.py reapply --root {root}\n'
               'Environment=PYTHONDONTWRITEBYTECODE=1\nRestart=on-failure\nRestartSec=5s\nTimeoutStartSec=60s\n')
    timer = ('[Unit]\nDescription=Verify CrowdBastion ingress policy and retry lost rules\n'
             '[Timer]\nOnActiveSec=30s\nOnUnitInactiveSec=30s\nAccuracySec=1s\n'
             '[Install]\nWantedBy=timers.target\n')
    hook = ('[Service]\nExecStartPost=/usr/bin/systemctl --no-block start crowdbastion-port-policy.service\n')
    return {str(unit_dir/'crowdbastion-port-policy.service'): service,
            str(unit_dir/'crowdbastion-port-policy.timer'): timer,
            str(unit_dir/'docker.service.d/60-crowdbastion-port-policy.conf'): hook,
            str(unit_dir/'crowdsec-firewall-bouncer.service.d/60-crowdbastion-port-policy.conf'): hook}


def reapply_plan(data, current, managed, interfaces, admin, *, docker=True):
    """Recover only wholly absent owned rules/chains, never changed existing ones."""
    surviving = copy.deepcopy(managed)
    for family in ('4', '6'):
        for name in list(surviving.get(family, {})):
            if name not in PARENTS and name not in current[family]: del surviving[family][name]
        for parent in (PARENTS if docker else ('INPUT',)):
            previous = managed.get(family, {}).get(parent, [])
            surviving.setdefault(family, {})[parent] = [rule for rule in previous if rule in current[family].get(parent, [])]
    return make_plan(data, current, surviving, interfaces, admin, docker=docker)


class Backend:
    """All host commands injected through run(argv); no shell strings."""
    def __init__(self, root=DEFAULT_ROOT, *, run=None, unit_dir=Path('/etc/systemd/system')):
        from crowdbastion_change import command
        self.root = Path(root); self.run = run or command; self.unit_dir = Path(unit_dir)
        self.state_path = self.root/'port-policy-state.json'
    def tables(self):
        return {family: parse_rules(self.run([binary, '-w', '5', '-S']))
                for family, binary in (('4', 'iptables'), ('6', 'ip6tables'))}
    def docker_required(self, current=None):
        current = self.tables() if current is None else current
        if any(name.startswith('DOCKER') for table in current.values() for name in table): return True
        info = dict(line.split('=', 1) for line in self.run(['systemctl', 'show', 'docker.service', '--property=LoadState,ActiveState']).splitlines() if '=' in line)
        if set(info) != {'LoadState', 'ActiveState'} or info['LoadState'] not in ('loaded', 'not-found', 'masked'):
            raise ValueError('docker state unknown')
        if info['ActiveState'] in ('active', 'activating', 'deactivating', 'reloading'): return True
        if info['ActiveState'] not in ('inactive', 'failed'): raise ValueError('docker state unknown')
        processes = self.run(['ps', '-eo', 'comm=']).splitlines()
        if not processes: raise ValueError('docker process state unknown')
        return any(name.strip().startswith(('dockerd', 'docker-proxy')) for name in processes)
    def interfaces(self):
        data = json.loads(self.run(['ip', '-j', 'link', 'show']))
        if not isinstance(data, list): raise ValueError('interfaces unavailable')
        return [row['ifname'] for row in data if isinstance(row, dict) and isinstance(row.get('ifname'), str) and row['ifname'] != 'lo']
    def admin(self): return admin_ports(self.run(['ss', '-H', '-lntp']), os.environ.get('SSH_CONNECTION', ''))
    def _file(self, resource):
        path = Path(resource['path'])
        allowed = {str(self.state_path), *lifecycle(Path('/runtime'), self.root, self.unit_dir)}
        if str(path) not in allowed: raise ValueError('unmanaged file')
        return path
    def read(self, resource):
        from crowdbastion_change import file_state
        if resource.get('kind') == 'chain':
            if (set(resource) != {'kind', 'family', 'chain'} or resource['family'] not in ('4', '6') or
                    not isinstance(resource['chain'], str) or
                    resource['chain'] not in PARENTS and not re.fullmatch(r'CBP_[a-f0-9]{20}', resource['chain'])):
                raise ValueError('invalid resource')
            return self.tables()[resource['family']].get(resource['chain'])
        if resource.get('kind') == 'file' and set(resource) == {'kind', 'path'}:
            return file_state(self._file(resource))
        if resource == {'kind': 'policy-timer'}:
            state = self.run(['systemctl', 'show', '--property=UnitFileState', '--value', 'crowdbastion-port-policy.timer']).strip()
            if state not in ('enabled', 'disabled', '', 'not-found'): raise ValueError('unknown timer ownership')
            return state == 'enabled'
        raise ValueError('invalid resource')
    def write(self, resource, before, after):
        from crowdbastion_change import write_file
        if self.read(resource) != before: raise ValueError('resource drift')
        if resource['kind'] == 'file':
            path = self._file(resource); write_file(path, before, after)
            if path != self.state_path: self.run(['systemctl', 'daemon-reload'])
            return
        if resource['kind'] == 'policy-timer':
            if type(before) is not bool or type(after) is not bool: raise ValueError('invalid timer state')
            self.run(['systemctl', 'enable' if after else 'disable', '--now', 'crowdbastion-port-policy.timer']); return
        name = resource['chain']
        if name.startswith(PREFIX):
            # A drifted parent may still reference this restrictive leaf during
            # recovery. Preserve the full restriction until every live caller
            # is detached; independent resources can continue to recover.
            table = self.tables()[resource['family']]
            if any(name in rule for rules in table.values() for rule in rules):
                raise ValueError('referenced managed leaf')
        argv = ['iptables' if resource['family'] == '4' else 'ip6tables', '-w', '5']
        if before is None and after == []: argv += ['-N', name]
        elif before == [] and after is None: argv += ['-X', name]
        elif isinstance(before, list) and isinstance(after, list) and len(after) == len(before) + 1:
            for index in range(len(after)):
                if before == after[:index] + after[index+1:]:
                    argv += ['-I', name, str(index+1)] + after[index]; break
            else: raise ValueError('non-atomic chain change')
        elif isinstance(before, list) and isinstance(after, list) and len(before) == len(after) + 1:
            for index in range(len(before)):
                if after == before[:index] + before[index+1:]: argv += ['-D', name] + before[index]; break
            else: raise ValueError('non-atomic chain change')
        else: raise ValueError('non-atomic chain change')
        self.run(argv)
    def preflight(self, metadata):
        validate(metadata['policy'])
        if self.docker_required() and not metadata.get('docker_required', True): raise ValueError('docker coverage changed')
        if any(row['interface'] not in self.interfaces() for row in metadata['policy']['ingress']): raise ValueError('interface unavailable')
        admin = self.admin()
        if any(row['mode'] != 'public' and (admin['state'] != 'known' or
                row['protocol'] == 'tcp' and row['port'] in admin['ports']) for row in metadata['policy']['ingress']):
            raise ValueError('management protection')
    def verify(self, metadata):
        self.preflight(metadata)
        current = self.tables(); check_ownership(current, metadata['managed'], docker=metadata.get('docker_required', True))
        if not equivalent_graph(desired(metadata['policy'], docker=metadata.get('docker_required', True)), metadata['managed']): return False
        if metadata.get('lifecycle'):
            from crowdbastion_change import file_state
            if any(file_state(Path(path)) != expected for path, expected in metadata['lifecycle'].items()): return False
            if not self.read({'kind': 'policy-timer'}): return False
            self.run(['systemctl', 'is-active', '--quiet', 'crowdbastion-port-policy.timer'])
        return True


def transaction_adapter(root): return Backend(root)


def load_policy(path):
    from crowdbastion_change import private_profile_read
    return validate(private_profile_read(Path(path)))


def load_state(backend):
    from crowdbastion_change import json_read
    if not backend.state_path.exists(): return {'version': 1, 'policy': None, 'managed': {}, 'lifecycle': {}, 'docker_required': False}
    state = json_read(backend.state_path)
    if (not isinstance(state, dict) or set(state) != {'version', 'policy', 'managed', 'lifecycle', 'docker_required'} or
            type(state['version']) is not int or state['version'] != 1 or not isinstance(state['managed'], dict) or
            not isinstance(state['lifecycle'], dict) or type(state['docker_required']) is not bool):
        raise ValueError('invalid managed state')
    validate(state['policy'])
    if not equivalent_graph(desired(state['policy'], docker=state['docker_required']), state['managed']): raise ValueError('invalid owned graph')
    return state


def plan(backend, data, *, reapply=False):
    state = load_state(backend)
    from crowdbastion_change import file_state
    paths = lifecycle(Path('/runtime'), backend.root, backend.unit_dir)
    if set(state['lifecycle']) - set(paths): raise ValueError('unknown lifecycle ownership')
    for path in paths:
        if file_state(Path(path)) != state['lifecycle'].get(path): raise ValueError('lifecycle drift')
    if not state['lifecycle'] and backend.read({'kind': 'policy-timer'}): raise ValueError('unowned timer')
    builder = reapply_plan if reapply else make_plan
    current = backend.tables()
    docker = backend.docker_required(current) or state['docker_required']
    result = builder(data, current, state['managed'], backend.interfaces(), backend.admin(), docker=docker)
    selectors = {(row['interface'], row['protocol'], row['port']) for row in data['ingress']}
    result['released_selectors'] = [{key: row[key] for key in ('interface', 'protocol', 'port')}
                                    for row in (state['policy'] or {}).get('ingress', [])
                                    if (row['interface'], row['protocol'], row['port']) not in selectors]
    return result


def apply_policy(backend, data, *, engine=None):
    from crowdbastion_change import Engine, canonical, file_state, file_value, maintenance_lock
    data = validate(data)
    engine = engine or Engine(backend.root, backend)
    with maintenance_lock(engine.lock_path):
        existing = load_state(backend)
        plan(backend, data)  # Reject unknown ownership before any state/runtime publication.
        if existing['policy'] == data and backend.verify(existing):
            pending = [row for row in engine.status().get('transactions', []) if row['state'] not in ('committed', 'rolled_back', 'preparation_incomplete')]
            if pending: return engine.status(engine.select('port-policy'))
            return {'version': 1, 'state': 'verified', 'unchanged': True, 'traffic_tested': False}
    def prepare(runtime):
        old = load_state(backend)
        prepared = plan(backend, data)
        effects = prepared['effects']
        texts = lifecycle(runtime, backend.root, backend.unit_dir)
        values = {path: file_value(text, 0o644) for path, text in texts.items()}
        for path, after in values.items():
            before = file_state(Path(path))
            if before != old['lifecycle'].get(path): raise ValueError('lifecycle ownership conflict')
            if before != after: effects.append({'resource': {'kind': 'file', 'path': path}, 'before': before, 'after': after})
        timer = {'kind': 'policy-timer'}; enabled = backend.read(timer)
        if not old['lifecycle'] and enabled: raise ValueError('unowned timer')
        if not enabled: effects.append({'resource': timer, 'before': False, 'after': True})
        state = {'version': 1, 'policy': data, 'managed': prepared['managed'], 'lifecycle': values, 'docker_required': prepared['docker_required']}
        before = file_state(backend.state_path); after = file_value(canonical(state).decode())
        if before != after: effects.append({'resource': {'kind': 'file', 'path': str(backend.state_path)}, 'before': before, 'after': after})
        return effects, {'policy': data, 'managed': prepared['managed'], 'lifecycle': values, 'docker_required': prepared['docker_required']}
    return engine.apply('port-policy', [], prepare=prepare)


def reapply(backend, *, engine=None):
    from crowdbastion_change import Engine, canonical, file_state, file_value
    state = load_state(backend)
    if state['policy'] is None: raise ValueError('policy absent')
    engine = engine or Engine(backend.root, backend)
    prepared = plan(backend, state['policy'], reapply=True)
    metadata = {'policy': state['policy'], 'managed': prepared['managed'], 'lifecycle': state['lifecycle'], 'docker_required': prepared['docker_required']}
    if prepared['managed'] != state['managed'] or prepared['docker_required'] != state['docker_required']:
        updated = dict(state, managed=prepared['managed'], docker_required=prepared['docker_required'])
        prepared['effects'].append({'resource': {'kind': 'file', 'path': str(backend.state_path)},
                                    'before': file_state(backend.state_path), 'after': file_value(canonical(updated).decode())})
    # Normal reapplication verifies without deleting or replacing a single rule.
    if not prepared['effects']:
        if not backend.verify(metadata): raise ValueError('verification failed')
        return {'version': 1, 'state': 'verified', 'scope': state['policy'], 'traffic_tested': False}
    result = engine.apply('port-policy', prepared['effects'], metadata=metadata)
    if result['state'] == 'staged': return engine.commit(result['id'])
    return result


def main(argv=None):
    from crowdbastion_change import Engine
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'status', 'verify', 'commit', 'rollback', 'reapply'))
    parser.add_argument('--config', type=Path, default=PROFILE)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT); parser.add_argument('--id')
    args = parser.parse_args(argv)
    if os.geteuid() != 0: raise ValueError('root required')
    backend = Backend(args.root); engine = Engine(args.root, backend)
    if args.action in ('verify', 'commit', 'rollback'):
        ident = engine.select('port-policy', args.id)
        result = getattr(engine, args.action)(ident)
    elif args.action == 'reapply': result = reapply(backend)
    elif args.action == 'apply': result = apply_policy(backend, load_policy(args.config))
    elif args.action == 'plan':
        result = plan(backend, load_policy(args.config))
        # No raw foreign rules/configs; expose selected scope and finite count.
        count = len(result['effects'])
        result = {key: value for key, value in result.items() if key not in ('effects', 'managed')}
        result['effect_count'] = count
        result['candidate_interfaces'] = backend.interfaces()
    else:
        state = load_state(backend)
        result = {'version': 1, 'state': 'absent', 'transactions': [row for row in engine.status().get('transactions', []) if row.get('kind') == 'port-policy']}
        if state['policy'] is not None:
            result.update(scope=state['policy'], traffic_tested=False, docker_required=state['docker_required'])
            try: result['state'] = 'verified' if backend.verify(state) else 'drift'
            except (ValueError, OSError, subprocess.SubprocessError):
                result.update(state='unknown', error_code='policy_verification_failed')
    print(json.dumps(result, sort_keys=True))
    if args.action in ('apply', 'reapply') and result.get('error_code') == 'apply_failed': return 1
    return 0 if result.get('state') in ('ready', 'absent', 'verified', 'staged', 'committed', 'rolled_back') else 1


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
    except (ValueError, OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError):
        print(json.dumps({'version': 1, 'state': 'refused', 'error_code': 'port_policy_refused'})); return 1


if __name__ == '__main__': sys.exit(cli())

"""Policy behavior with real iptables-shaped data; no host firewall commands."""
import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    policy = importlib.import_module('crowdbastion_port_policy')
except ModuleNotFoundError:
    policy = None


def config(mode='sources', sources=None):
    return {'version': 1, 'topology': {'kind': 'shared-relay', 'relay_sources': ['198.51.100.0/24']},
            'ingress': [{'interface': 'eth0', 'protocol': 'tcp', 'port': 443,
                         'mode': mode, 'sources': ['198.51.100.0/24'] if sources is None else sources}]}


def tables():
    return {str(f): {'INPUT': [['-j', 'CROWDSEC'], ['-j', 'ACCEPT']],
                     'DOCKER-USER': [['-j', 'CROWDSEC'], ['-j', 'RETURN']],
                     'FORWARD': [['-j', 'DOCKER-USER']], 'CROWDSEC': []}
            for f in (4, 6)}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(policy, 'port policy module missing')

    def test_strict_schema_rejects_unsafe_or_ambiguous_inputs(self):
        self.assertEqual(policy.validate(config()), config())
        for key, value in [('interface', 'eth0;id'), ('interface', 'lo'), ('interface', 'eth+'),
                           ('protocol', 'icmp'), ('port', True), ('port', 0), ('port', '443'),
                           ('sources', []), ('sources', ['0.0.0.0/0']),
                           ('sources', ['198.51.100.1/24']), ('mode', 'allow')]:
            candidate = config(); candidate['ingress'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                policy.validate(candidate)
        for change in (lambda c: c.update(extra=1), lambda c: c.update(version=True),
                       lambda c: c['topology'].update(kind='guessed'),
                       lambda c: c['ingress'].append(copy.deepcopy(c['ingress'][0]))):
            candidate = config(); change(candidate)
            with self.assertRaises(ValueError): policy.validate(candidate)

    def test_rule_graph_denies_unmatched_family_and_uses_original_dnat_direction(self):
        graph = policy.desired(config())
        for family in ('4', '6'):
            input_jump = graph[family]['INPUT'][0]
            docker_jump = graph[family]['DOCKER-USER'][0]
            self.assertEqual(input_jump[:6], ['-i', 'eth0', '-p', 'tcp', '--dport', '443'])
            self.assertIn('--ctorigdstport', docker_jump)
            self.assertIn('--ctdir', docker_jump)
            self.assertEqual(docker_jump[docker_jump.index('--ctdir') + 1], 'ORIGINAL')
            self.assertNotIn('--sport', json.dumps(graph)); self.assertNotIn('ACCEPT', json.dumps(graph))
            name = input_jump[-1]
            self.assertEqual(graph[family][name][-1], ['-j', 'DROP'])
            self.assertEqual(len(graph[family][name]), 2 if family == '4' else 1)
        self.assertEqual(policy.desired(config('public', [])), {'4': {}, '6': {}})
        local = policy.desired(config('local', []))
        self.assertEqual(local['4'][local['4']['INPUT'][0][-1]], [['-j', 'DROP']])

    def test_management_ports_refuse_without_automatic_current_source_exemption(self):
        for admin in ({'state': 'unknown', 'ports': []}, {'state': 'known', 'ports': [443, 22]}):
            with self.assertRaises(ValueError): policy.make_plan(config(), tables(), {}, ['eth0'], admin)
        result = policy.make_plan(config(), tables(), {}, ['eth0'], {'state': 'known', 'ports': [22]})
        self.assertTrue(result['effects']); self.assertEqual(result['state'], 'ready')

    def test_missing_chain_unknown_ownership_and_unreadable_rules_refuse(self):
        for mutate in (lambda t: t['6'].pop('DOCKER-USER'),
                       lambda t: t['4'].update(CBP_foreign=[]),
                       lambda t: t['4']['INPUT'].insert(0, ['-j', 'ACCEPT'])):
            current = tables(); mutate(current)
            with self.assertRaises(ValueError):
                policy.make_plan(config(), current, {}, ['eth0'], {'state': 'known', 'ports': [22]})
        with self.assertRaises(ValueError): policy.parse_rules('*filter\nCOMMIT')

    def test_plan_preserves_first_crowdsec_and_unrelated_order_and_is_idempotent(self):
        initial = tables()
        plan = policy.make_plan(config(), initial, {}, ['eth0'], {'state': 'known', 'ports': [22]})
        current = copy.deepcopy(initial)
        for effect in plan['effects']:
            r = effect['resource']; self.assertEqual(current[r['family']].get(r['chain']), effect['before'])
            if effect['after'] is None: current[r['family']].pop(r['chain'])
            else: current[r['family']][r['chain']] = copy.deepcopy(effect['after'])
        for family in ('4', '6'):
            self.assertEqual(current[family]['INPUT'][0], ['-j', 'CROWDSEC'])
            self.assertEqual(current[family]['INPUT'][-1], ['-j', 'ACCEPT'])
        second = policy.make_plan(config(), current, plan['managed'], ['eth0'], {'state': 'known', 'ports': [22]})
        self.assertEqual(second['effects'], [])
        public = policy.make_plan(config('public', []), current, plan['managed'], ['eth0'], {'state': 'known', 'ports': [22]})
        for effect in public['effects']:
            r = effect['resource']
            if effect['after'] is None: current[r['family']].pop(r['chain'])
            else: current[r['family']][r['chain']] = copy.deepcopy(effect['after'])
        self.assertEqual(current, initial)

    def test_rules_parse_real_output_and_ss_admin_multiple_ports(self):
        self.assertEqual(policy.parse_rules('-P INPUT ACCEPT\n-N DOCKER-USER\n-N CROWDSEC\n-A INPUT -j CROWDSEC\n-A DOCKER-USER -j CROWDSEC\n')['INPUT'], [['-j', 'CROWDSEC']])
        info = policy.admin_ports('LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=4,fd=3))\nLISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=4,fd=4))\n', '203.0.113.4 12345 192.0.2.1 22')
        self.assertEqual(info, {'state': 'known', 'ports': [22, 2222]})
        self.assertEqual(policy.admin_ports('LISTEN 0 1 *:443 *:*\n', '')['state'], 'unknown')


if __name__ == '__main__': unittest.main()


def kernel_rule(rule):
    """Representative xtables save spelling, independent of policy builders."""
    import re
    import shlex
    text = shlex.join(rule)
    text = re.sub(r'--ctdir ORIGINAL --ctorigdstport ([0-9]+)', r'--ctorigdstport \1 --ctdir ORIGINAL', text)
    words = shlex.split(text)
    if '--dport' in words and '-p' in words:
        protocol = words[words.index('-p') + 1]
        if protocol in ('tcp', 'udp') and not any(words[i:i+2] == ['-m', protocol] for i in range(len(words)-1)):
            index = words.index('-p') + 2
            words[index:index] = ['-m', protocol]
    return words


class Host:
    """Interprets only the fixed commands issued by the real backend."""
    def __init__(self):
        self.tables = tables(); self.commands = []; self.enabled = False; self.active = False
    def __call__(self, argv):
        import shlex
        self.commands.append(list(argv))
        if argv[0] in ('iptables', 'ip6tables'):
            family = '4' if argv[0] == 'iptables' else '6'; table = self.tables[family]
            args = argv[3:]; action = args[0]
            if action == '-S':
                lines = [('-P '+name+' ACCEPT') if name == 'INPUT' else '-N '+name for name in table]
                lines += [shlex.join(['-A', name] + kernel_rule(row)) for name, rows in table.items() for row in rows]
                return '\n'.join(lines)+'\n'
            name = args[1]
            if action == '-N':
                if name in table: raise ValueError('exists')
                table[name] = []
            elif action == '-X':
                if table[name] or any(name in rule for rows in table.values() for rule in rows): raise ValueError('referenced')
                del table[name]
            elif action == '-I': table[name].insert(int(args[2])-1, kernel_rule(args[3:]))
            elif action == '-D': table[name].remove(kernel_rule(args[2:]))
            else: raise AssertionError(argv)
            return ''
        if argv == ['ip', '-j', 'link', 'show']:
            return json.dumps([{'ifname': 'lo'}, {'ifname': 'eth0'}])
        if argv == ['ss', '-H', '-lntp']:
            return 'LISTEN 0 128 *:22 *:* users:(("sshd",pid=5,fd=3))\n'
        if argv[:2] == ['systemctl', 'show']: return ('enabled' if self.enabled else 'disabled')+'\n'
        if argv[:2] == ['systemctl', 'enable']: self.enabled = True; self.active = True; return ''
        if argv[:2] == ['systemctl', 'disable']: self.enabled = False; self.active = False; return ''
        if argv[:3] == ['systemctl', 'is-active', '--quiet']:
            if not self.active: raise ValueError('inactive')
            return ''
        if argv == ['systemctl', 'daemon-reload']: return ''
        raise AssertionError(argv)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(policy, 'port policy module missing')
        self.host = Host(); self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
    def test_real_backend_applies_finite_rules_and_exactly_rolls_back(self):
        backend = policy.Backend(self.root/'changes', run=self.host, unit_dir=self.root/'units')
        initial = copy.deepcopy(self.host.tables)
        plan = policy.make_plan(config(), backend.tables(), {}, backend.interfaces(), backend.admin())
        for effect in plan['effects']: backend.write(effect['resource'], effect['before'], effect['after'])
        self.assertTrue(backend.verify({'policy': config(), 'managed': plan['managed'], 'lifecycle': {}}))
        for effect in reversed(plan['effects']): backend.write(effect['resource'], effect['after'], effect['before'])
        self.assertEqual(self.host.tables, initial)
        forbidden = ('-F', '--flush', '-P', '--policy', 'iptables-restore', '--sport')
        for argv in self.host.commands:
            for token in forbidden: self.assertNotIn(token, argv)
    def test_lifecycle_uses_stable_runtime_and_reapply_keeps_existing_rules(self):
        import crowdbastion_change as change
        self.assertTrue(hasattr(policy, 'lifecycle'), 'policy lifecycle missing')
        runtime = Path('/var/lib/crowdbastion/changes/' + 'a'*32 + '/runtime')
        files = policy.lifecycle(runtime, Path('/var/lib/crowdbastion/changes'), Path('/etc/systemd/system'))
        service = files['/etc/systemd/system/crowdbastion-port-policy.service']
        self.assertIn(str(runtime)+'/crowdbastion_port_policy.py reapply', service)
        self.assertIn('Restart=on-failure', service)
        self.assertIn('After=docker.service crowdsec-firewall-bouncer.service', service)
        self.assertNotIn('ExecStop=', service)
        self.assertIn('--no-block start crowdbastion-port-policy.service', files['/etc/systemd/system/docker.service.d/60-crowdbastion-port-policy.conf'])
        self.assertNotIn('restart docker', json.dumps(files))
        current = tables(); graph = policy.desired(config())
        for family in ('4', '6'):
            for name, rows in graph[family].items():
                if name in ('INPUT', 'DOCKER-USER'): current[family][name][1:1] = copy.deepcopy(rows)
                else: current[family][name] = copy.deepcopy(rows)
        self.assertEqual(policy.reapply_plan(config(), current, graph, ['eth0'], {'state': 'known', 'ports': [22]})['effects'], [])
        del current['6'][next(n for n in graph['6'] if n.startswith('CBP_'))]
        current['6']['INPUT'] = [['-j', 'CROWDSEC'], ['-j', 'ACCEPT']]
        current['6']['DOCKER-USER'] = [['-j', 'CROWDSEC'], ['-j', 'RETURN']]
        recovering = policy.reapply_plan(config(), current, graph, ['eth0'], {'state': 'known', 'ports': [22]})
        self.assertTrue(recovering['effects'])
        self.assertTrue(all(e['resource']['family'] == '6' for e in recovering['effects']))
        current['4'][next(n for n in graph['4'] if n.startswith('CBP_'))][-1] = ['-j', 'RETURN']
        with self.assertRaises(ValueError): policy.reapply_plan(config(), current, graph, ['eth0'], {'state': 'known', 'ports': [22]})


class LifecycleIntegration(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(policy, 'policy module missing')
        import crowdbastion_change as change
        from test_change_transactions import Timer
        self.change = change; self.timer = Timer(); self.host = Host()
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.base.chmod(0o700)
        self.backend = policy.Backend(self.base/'changes', run=self.host, unit_dir=self.base/'units')
        self.engine = change.Engine(self.backend.root, self.backend, scheduler=self.timer, guard=lambda: None,
                                    lock_path=self.base/'maintenance.lock')
    def test_staged_apply_fresh_commit_and_public_update_restore_only_owned_rules(self):
        result = policy.apply_policy(self.backend, config(), engine=self.engine)
        self.assertEqual(result['state'], 'staged')
        self.assertTrue(self.host.active)
        self.assertEqual(self.engine.commit(result['id'])['state'], 'committed')
        before = len([c for c in self.host.commands if c[0] in ('iptables', 'ip6tables') and c[3] != '-S'])
        self.assertEqual(policy.reapply(self.backend, engine=self.engine)['state'], 'verified')
        after = len([c for c in self.host.commands if c[0] in ('iptables', 'ip6tables') and c[3] != '-S'])
        self.assertEqual(after, before)
        result = policy.apply_policy(self.backend, config('public', []), engine=self.engine)
        self.assertEqual(result['state'], 'staged')
        self.assertEqual(self.host.tables, tables())
        self.assertEqual(self.engine.rollback(result['id'])['state'], 'rolled_back')
        self.assertTrue(self.backend.verify(policy.load_state(self.backend)))
    def test_unowned_lifecycle_file_and_changed_source_rule_refuse_without_rule_writes(self):
        self.backend.unit_dir.mkdir()
        (self.backend.unit_dir/'crowdbastion-port-policy.service').write_text('foreign service')
        with self.assertRaises(ValueError): policy.apply_policy(self.backend, config(), engine=self.engine)
        self.assertEqual(self.host.tables, tables())
        self.assertEqual(self.timer.armed, [])
    def test_restart_recovery_commits_only_missing_managed_effects(self):
        ident = policy.apply_policy(self.backend, config(), engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        expected = copy.deepcopy(self.host.tables)
        self.host.tables['6'] = tables()['6']
        result = policy.reapply(self.backend, engine=self.engine)
        self.assertEqual(result['state'], 'committed')
        self.assertEqual(self.host.tables, expected)


class PolicySafetyTests(unittest.TestCase):
    setUp = PolicyTests.setUp
    def test_conditional_crowdsec_jump_and_unreachable_docker_user_refuse(self):
        for modify in (lambda t: t['4']['INPUT'].__setitem__(0, ['-p', 'tcp', '-j', 'CROWDSEC']),
                       lambda t: t['6']['FORWARD'].insert(0, ['-j', 'ACCEPT']),
                       lambda t: t['4'].pop('FORWARD')):
            current = tables(); modify(current)
            with self.assertRaises(ValueError):
                policy.make_plan(config(), current, {}, ['eth0'], {'state': 'known', 'ports': [22]})


class PersistenceSafety(unittest.TestCase):
    setUp = LifecycleIntegration.setUp
    def test_status_verifier_detects_owned_service_drift(self):
        ident = policy.apply_policy(self.backend, config(), engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        state = policy.load_state(self.backend)
        (self.backend.unit_dir/'crowdbastion-port-policy.service').write_text('foreign after commit')
        self.assertFalse(self.backend.verify(state))
    def test_repeated_apply_is_noop_after_independently_verified_commit(self):
        ident = policy.apply_policy(self.backend, config(), engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        before = list(self.host.commands); timers = len(self.timer.armed)
        result = policy.apply_policy(self.backend, config(), engine=self.engine)
        self.assertEqual(result['state'], 'verified')
        self.assertTrue(result['unchanged'])
        self.assertEqual(len(self.timer.armed), timers)
        self.assertTrue(all(c[0] not in ('iptables', 'ip6tables') or c[3] == '-S' for c in self.host.commands[len(before):]))


class SelectedScope(unittest.TestCase):
    setUp = PolicyTests.setUp
    def test_udp_and_both_source_families_are_limited_to_explicit_interface_port(self):
        data = config(sources=['198.51.100.0/24', '2001:db8:1234::/48'])
        data['ingress'][0].update(interface='eth1', protocol='udp', port=8443)
        graph = policy.desired(data)
        for family, source in (('4', '198.51.100.0/24'), ('6', '2001:db8:1234::/48')):
            name = graph[family]['INPUT'][0][-1]
            self.assertEqual(graph[family][name], [['-s', source, '-j', 'RETURN'], ['-j', 'DROP']])
            self.assertEqual(graph[family]['INPUT'], [['-i', 'eth1', '-p', 'udp', '--dport', '8443', '-j', name]])
            self.assertEqual(graph[family]['DOCKER-USER'], [['-i', 'eth1', '-p', 'udp', '-m', 'conntrack', '--ctorigdstport', '8443', '--ctdir', 'ORIGINAL', '-j', name]])
        prepared = policy.make_plan(data, tables(), {}, ['eth0', 'eth1'], {'state': 'known', 'ports': [22]})
        self.assertTrue(all(e['resource']['chain'] != 'FORWARD' for e in prepared['effects']))


class HostOnly(unittest.TestCase):
    setUp = PolicyTests.setUp
    def test_explicit_absent_docker_allows_host_input_without_missing_docker_chains(self):
        current = tables()
        for family in ('4', '6'):
            del current[family]['DOCKER-USER']; del current[family]['FORWARD']
        prepared = policy.make_plan(config(), current, {}, ['eth0'], {'state': 'known', 'ports': [22]}, docker=False)
        self.assertTrue(prepared['effects'])
        for family in ('4', '6'):
            self.assertNotIn('DOCKER-USER', prepared['managed'][family])
        with self.assertRaises(ValueError):
            policy.make_plan(config(), current, {}, ['eth0'], {'state': 'known', 'ports': [22]}, docker=True)
    def test_runtime_absence_evidence_and_docker_later_requires_coverage(self):
        import crowdbastion_change as change
        from test_change_transactions import Timer
        host = Host()
        for family in ('4', '6'):
            del host.tables[family]['DOCKER-USER']; del host.tables[family]['FORWARD']
        def run(argv):
            if argv == ['systemctl', 'show', 'docker.service', '--property=LoadState,ActiveState']:
                return 'LoadState=not-found\nActiveState=inactive\n'
            if argv == ['ps', '-eo', 'comm=']: return 'systemd\nsshd\npython3\n'
            return host(argv)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); base.chmod(0o700)
            backend = policy.Backend(base/'changes', run=run, unit_dir=base/'units')
            engine = change.Engine(backend.root, backend, scheduler=Timer(), guard=lambda: None, lock_path=base/'maintenance.lock')
            result = policy.apply_policy(backend, config(), engine=engine)
            self.assertEqual(result['state'], 'staged')
            self.assertEqual(engine.commit(result['id'])['state'], 'committed')
            self.assertFalse(policy.load_state(backend)['docker_required'])
            for family in ('4', '6'):
                host.tables[family]['DOCKER-USER'] = [['-j', 'CROWDSEC'], ['-j', 'RETURN']]
                host.tables[family]['FORWARD'] = [['-j', 'DOCKER-USER']]
            result = policy.reapply(backend, engine=engine)
            self.assertEqual(result['state'], 'committed')
            self.assertTrue(policy.load_state(backend)['docker_required'])
            self.assertTrue(any('CBP_' in token for rule in host.tables['6']['DOCKER-USER'] for token in rule))


class MultipleSelectors(unittest.TestCase):
    setUp = LifecycleIntegration.setUp
    def test_adding_selector_preserves_existing_enforcement_and_rollback(self):
        ident = policy.apply_policy(self.backend, config(), engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        initial = copy.deepcopy(self.host.tables)
        data = config(); extra = copy.deepcopy(data['ingress'][0]); extra['port'] = 8443; data['ingress'].append(extra)
        start = len(self.host.commands)
        result = policy.apply_policy(self.backend, data, engine=self.engine)
        self.assertEqual(result['state'], 'staged')
        for command in self.host.commands[start:]:
            if command[:1] == ['iptables'] and command[3:5] == ['-D', 'INPUT']:
                self.fail('existing selector must remain enforced during additions')
        self.assertTrue(self.backend.verify(policy.load_state(self.backend)))
        self.assertEqual(self.engine.rollback(result['id'])['state'], 'rolled_back')
        self.assertEqual(self.host.tables, initial)


class SerializationRecovery(unittest.TestCase):
    setUp = LifecycleIntegration.setUp
    def test_real_save_spelling_supports_staged_verify_rollback_and_retry(self):
        initial = copy.deepcopy(self.host.tables)
        result = policy.apply_policy(self.backend, config(), engine=self.engine)
        self.assertEqual(result['state'], 'staged', result)
        self.assertIn('--ctorigdstport 443 --ctdir ORIGINAL', self.host(['iptables', '-w', '5', '-S']))
        self.assertEqual(self.engine.verify(result['id'])['state'], 'verified')
        self.assertTrue(self.backend.verify(policy.load_state(self.backend)))
        self.assertEqual(self.engine.rollback(result['id'])['state'], 'rolled_back')
        self.assertEqual(self.host.tables, initial)
        writes = [a for a in self.host.commands if a[0] in ('iptables', 'ip6tables') and a[3] != '-S']
        self.assertEqual(self.engine.rollback(result['id'])['state'], 'rolled_back')
        self.assertEqual([a for a in self.host.commands if a[0] in ('iptables', 'ip6tables') and a[3] != '-S'], writes)
    def test_owned_order_normalization_preserves_foreign_and_changed_rule_drift(self):
        name = 'CBP_' + 'a'*20
        def read(options, target=name):
            return policy.parse_rules('-P INPUT ACCEPT\n-N DOCKER-USER\n-N '+name+'\n-A DOCKER-USER -i eth0 -p tcp -m conntrack '+options+' -j '+target+'\n')['DOCKER-USER']
        before = '--ctdir ORIGINAL --ctorigdstport 443'
        saved = '--ctorigdstport 443 --ctdir ORIGINAL'
        self.assertEqual(read(before), read(saved))
        self.assertNotEqual(read(before, 'FOREIGN'), read(saved, 'FOREIGN'))
        self.assertNotEqual(read(saved), read('--ctorigdstport 443 --ctdir REPLY'))
        ident = policy.apply_policy(self.backend, config(), engine=self.engine)['id']
        name = next(n for n in self.host.tables['4'] if n.startswith('CBP_'))
        self.host.tables['4'][name][-1] = ['-j', 'RETURN']
        self.assertEqual(self.engine.rollback(ident)['state'], 'rollback_incomplete')
        self.assertEqual(self.host.tables['4'][name][-1], ['-j', 'RETURN'])

class DriftSafeLeafRecovery(unittest.TestCase):
    setUp = LifecycleIntegration.setUp
    def test_parent_drift_keeps_referenced_leaf_restriction_until_retry(self):
        import copy
        ident = policy.apply_policy(self.backend, config(), engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        old = copy.deepcopy(self.host.tables)
        staged = policy.apply_policy(self.backend, config('local', []), engine=self.engine)
        selected = next(name for name in self.host.tables['4'] if name.startswith(policy.PREFIX) and
                        ['-j', name] == self.host.tables['4']['INPUT'][1][-2:])
        restriction = copy.deepcopy(self.host.tables['4'][selected])
        external = ['-p', 'tcp', '--dport', '9999', '-j', 'RETURN']
        self.host.tables['4']['INPUT'].append(external)
        self.assertEqual(self.engine.rollback(staged['id'])['state'], 'rollback_incomplete')
        self.assertEqual(self.host.tables['4'][selected], restriction)
        self.assertEqual(self.host.tables['6'], old['6'])
        self.assertIn(external, self.host.tables['4']['INPUT'])
        self.assertNotIn(staged['id'], self.timer.cancelled)
        self.host.tables['4']['INPUT'].remove(external)
        self.assertEqual(self.engine.rollback(staged['id'])['state'], 'rolled_back')
        self.assertEqual(self.host.tables, old)
        self.assertIn(staged['id'], self.timer.cancelled)

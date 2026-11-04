"""Business goals, evidence-based recommendations and private resume state."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))

try:
    import crowdbastion_flow as flow
except ImportError:
    flow = None


class Preferences(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(flow, 'user flow module is not implemented')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'state/user-flow.json'

    def test_absent_load_does_not_create_directory(self):
        self.assertIsNone(flow.load_state(self.path))
        self.assertFalse(self.path.parent.exists())

    def test_resume_roundtrip_is_private_and_contains_only_intent(self):
        state = flow.new_state(['web', 'system'], online_requests=True)
        state['selected_targets'] = ['host:nginx']
        state['deferred']['web.verify:host:nginx'] = {
            'fingerprint': 'a' * 64, 'reason': 'later', 'at': 123.0}
        flow.save_state(self.path, state)
        self.assertEqual(flow.load_state(self.path), state)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_projection_does_not_call_generic_proxy_v2bx(self):
        for goals, program, expected in (
            (['system'], 'unknown', ['relay']),
            (['web', 'system'], 'unknown', ['web']),
            (['proxy'], 'unknown', []),
            (['proxy'], 'v2bx', ['node']),
            (['remote', 'proxy'], 'v2bx', ['remote', 'node']),
        ):
            with self.subTest(goals=goals, program=program):
                self.assertEqual(flow.project_roles(goals, program), expected)
        for goals in (['remote', 'system'], ['remote', 'web'], ['web', 'web'], ['banana']):
            with self.assertRaises(ValueError):
                flow.new_state(goals)

    def test_invalid_state_cannot_replace_existing_preferences(self):
        valid = flow.new_state(['system'])
        flow.save_state(self.path, valid)
        before = self.path.read_bytes()
        for mutate in (
            lambda s: s.update(version=True),
            lambda s: s.update(api_key='DO-NOT-STORE'),
            lambda s: s.update(last_task='$(touch /tmp/pwned)'),
            lambda s: s.update(selected_targets=['../../etc/shadow']),
            lambda s: s.update(online_requests='yes'),
            lambda s: s['outcomes'].update({'system.install': {'state': 'done', 'at': 0, 'fingerprint': 'a' * 64}}),
        ):
            state = copy.deepcopy(valid)
            mutate(state)
            with self.assertRaises(ValueError):
                flow.save_state(self.path, state)
            self.assertEqual(self.path.read_bytes(), before)

    def test_corrupt_json_and_symlink_fifo_or_writable_state_are_refused(self):
        self.path.parent.mkdir(mode=0o700)
        self.path.write_text('{')
        self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            flow.load_state(self.path)
        self.path.unlink()
        target = self.root / 'other'
        target.write_text('unchanged')
        self.path.symlink_to(target)
        for operation in (lambda: flow.load_state(self.path),
                          lambda: flow.save_state(self.path, flow.new_state(['system']))):
            with self.assertRaises((ValueError, OSError)):
                operation()
        self.assertEqual(target.read_text(), 'unchanged')
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises((ValueError, OSError)):
            flow.load_state(self.path)
        self.path.unlink()
        flow.save_state(self.path, flow.new_state(['system']))
        self.path.chmod(0o666)
        with self.assertRaises((ValueError, OSError)):
            flow.load_state(self.path)

    def test_unsafe_ancestor_is_refused_without_creating_state(self):
        self.path.parent.mkdir(mode=0o777)
        self.path.parent.chmod(0o777)
        with self.assertRaises((ValueError, OSError)):
            flow.save_state(self.path, flow.new_state(['system']))
        self.assertFalse(self.path.exists())
        self.path.parent.chmod(0o700)
        self.path.parent.rmdir()
        self.path.parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            flow.save_state(self.path, flow.new_state(['system']))


def snapshot(core=True):
    return {'version': 1, 'checked_at': 123.0, 'fingerprint': 'a'*64, 'fingerprint_complete': True,
            'inventory': {'core': core, 'bouncer': core, 'remote': False, 'appsec': False,
                          'v2bx': False, 'observer': False},
            'checks': {'core': 'ok' if core else 'missing', 'config': 'ok', 'api': 'ok',
                       'logs': 'ok', 'bouncer': 'ok' if core else 'missing', 'rules': 'ok'},
            'targets': [], 'pending': [], 'limitations': []}


class Recommendations(unittest.TestCase):
    def task(self, report, ident):
        return next(t for t in report['tasks'] if t['id'] == ident)

    def test_existing_deployment_without_goals_is_not_reinstalled(self):
        result = flow.report(snapshot(), None)
        self.assertNotIn('install_core', result['recommended']['action'])
        self.assertEqual(result['recommended']['action'], 'choose_goals')
        self.assertTrue(all(t['action'] not in ('install_core_system', 'install_core_web') for t in result['tasks']))

    def test_fresh_host_asks_business_goal_then_installs_only_selected_scope(self):
        self.assertEqual(flow.report(snapshot(False), None)['recommended']['action'], 'choose_goals')
        state = flow.new_state(['system'])
        result = flow.report(snapshot(False), state)
        self.assertEqual(result['recommended']['action'], 'install_core_system')
        self.assertFalse(any(t['action'] in ('configure_appsec', 'connect_website') for t in result['tasks']))

    def test_broken_configuration_precedes_service_restart(self):
        facts = snapshot()
        facts['checks'].update(core='fault', config='fault')
        result = flow.report(facts, flow.new_state(['system']))
        self.assertEqual(result['recommended']['id'], 'core.config')
        self.assertEqual(self.task(result, 'core.service')['state'], 'blocked')

    def test_known_fault_in_deployed_website_is_not_hidden_by_system_goal(self):
        facts = snapshot()
        facts['inventory']['appsec'] = True
        facts['checks']['appsec'] = 'fault'
        result = flow.report(facts, flow.new_state(['system']))
        self.assertEqual(result['recommended']['action'], 'inspect')
        self.assertIn('网站', result['recommended']['reason'])

    def test_unknown_or_idle_logs_do_not_recommend_reinstall(self):
        for status in ('unknown', 'pending'):
            facts = snapshot()
            facts['checks']['logs'] = status
            result = flow.report(facts, flow.new_state(['system']))
            self.assertEqual(result['recommended']['action'], 'logs_diagnose')
            self.assertNotIn('安装', result['recommended']['title'])

    def test_remote_only_and_proxy_only_do_not_require_local_core(self):
        facts = snapshot(False)
        facts['inventory']['remote'] = True
        facts['checks'].update(bouncer='ok', remote='ok', rules='ok')
        result = flow.report(facts, flow.new_state(['remote']))
        self.assertEqual(result['recommended']['action'], 'verify_entry')
        self.assertFalse(any(t['id'].startswith('core.') for t in result['tasks']))
        facts['inventory']['remote'] = False
        result = flow.report(facts, flow.new_state(['proxy'], program='other'))
        self.assertEqual(result['recommended']['action'], 'inspect_proxy')
        self.assertFalse(any('install_core' in t['action'] for t in result['tasks']))

    def test_multiple_web_instances_require_selection_and_target_evidence(self):
        facts = snapshot()
        facts['checks']['web_rules'] = 'ok'
        facts['targets'] = [dict(id='host:nginx', label='nginx', runtime='nginx', network='host',
                                 owned=False, connected=False, transport=True, config_hash='b'*64,
                                 realip='unknown', request_verification='pending', web_logs='ok'),
                            dict(id='host:openresty', label='openresty', runtime='openresty', network='host',
                                 owned=False, connected=False, transport=True, config_hash='c'*64,
                                 realip='unknown', request_verification='pending', web_logs='ok')]
        state = flow.new_state(['web'], online_requests=True)
        self.assertEqual(flow.report(facts, state)['recommended']['action'], 'choose_targets')
        state['selected_targets'] = ['host:nginx']
        result = flow.report(facts, state)
        self.assertFalse(any(t['target'] == 'host:openresty' for t in result['tasks']))
        self.assertEqual(result['recommended']['action'], 'configure_appsec')
        facts['inventory']['appsec'] = True
        facts['checks']['appsec'] = 'ok'
        result = flow.report(facts, state)
        self.assertEqual(result['recommended']['action'], 'connect_website')
        self.assertNotEqual(self.task(result, 'web.connect:host:nginx')['state'], 'done')

    def test_bridge_connection_depends_on_private_transport_and_engine(self):
        facts = snapshot()
        facts['checks']['web_rules'] = 'ok'
        ident = 'docker:'+'b'*64
        facts['targets'] = [dict(id=ident, label='edge', runtime='docker', network='bridge',
                                 owned=False, connected=False, transport=False, config_hash='b'*64,
                                 realip='unknown', request_verification='pending', web_logs='ok')]
        state = flow.new_state(['web'], online_requests=True)
        state['selected_targets'] = [ident]
        result = flow.report(facts, state)
        self.assertEqual(self.task(result, 'web.transport:'+ident)['state'], 'blocked')
        facts['inventory']['appsec'] = True
        facts['checks']['appsec'] = 'ok'
        result = flow.report(facts, state)
        self.assertEqual(result['recommended']['action'], 'configure_transport')
        self.assertEqual(self.task(result, 'web.connect:'+ident)['state'], 'blocked')

    def test_migration_and_transactions_precede_fresh_setup(self):
        for kind, action in (('firewall', 'maintain_firewall'), ('network', 'maintain_network'), ('port-policy', 'maintain_ports')):
            facts = snapshot(False)
            facts['pending'] = [{'kind': kind, 'state': 'staged', 'deadline': 200}]
            result = flow.report(facts, flow.new_state(['system']))
            self.assertEqual(result['recommended']['action'], action)

    def test_deferral_is_evidence_bound_and_never_turns_verification_green(self):
        facts = snapshot()
        state = flow.new_state(['system'])
        task = flow.report(facts, state)['recommended']
        self.assertEqual(task['action'], 'verify_entry')
        state['deferred'][task['id']] = {'fingerprint': task['evidence_fingerprint'], 'reason': 'later', 'at': 123.0}
        result = flow.report(facts, state)
        self.assertEqual(self.task(result, 'entry.verify')['state'], 'deferred')
        self.assertEqual(result['recommended']['action'], 'inspect')
        self.assertIn('待验证', result['conclusion'])
        facts['fingerprint'] = 'd'*64
        self.assertEqual(flow.report(facts, state)['recommended']['action'], 'verify_entry')

    def test_successful_return_cannot_complete_unverified_task(self):
        facts = snapshot(False)
        state = flow.new_state(['system'])
        task = flow.report(facts, state)['recommended']
        state['outcomes'][task['id']] = {'fingerprint': task['evidence_fingerprint'], 'state': 'returned', 'at': 123.0}
        result = flow.report(facts, state)
        self.assertNotEqual(self.task(result, task['id'])['state'], 'done')

    def test_failed_task_keeps_explicit_retry_without_automatic_execution(self):
        facts = snapshot(False)
        state = flow.new_state(['system'])
        task = flow.report(facts, state)['recommended']
        state['outcomes'][task['id']] = {'fingerprint': task['evidence_fingerprint'], 'state': 'failed', 'at': 123.0}
        task = flow.report(facts, state)['recommended']
        self.assertEqual(task['state'], 'failed')
        self.assertEqual(task['action'], 'install_core_system')

    def test_selected_instance_disappearing_requires_selection_again(self):
        state = flow.new_state(['web'], online_requests=True)
        state['selected_targets'] = ['host:nginx']
        result = flow.report(snapshot(), state)
        self.assertEqual(result['recommended']['action'], 'choose_targets')
        self.assertFalse(any(t['action'] == 'connect_website' for t in result['tasks']))

    def test_switching_goal_to_remote_does_not_migrate_existing_local_core(self):
        result = flow.report(snapshot(), flow.new_state(['remote']))
        self.assertEqual(result['recommended']['action'], 'choose_goals')
        self.assertTrue(any(t['id'] == 'deployment.conflict' for t in result['tasks']))

    def test_deployed_website_fault_precedes_unrelated_entry_verification(self):
        facts = snapshot()
        facts['inventory']['appsec'] = True
        facts['checks'].update(appsec='ok', web='fault', web_container='fault')
        result = flow.report(facts, flow.new_state(['system']))
        self.assertEqual(result['recommended']['action'], 'inspect')
        self.assertLess(result['recommended']['priority'], 60)
        self.assertTrue(any(t['id'] == 'component.web_container' for t in result['tasks']))

    def test_scoped_historical_verification_is_consumed_without_global_health_claim(self):
        facts = snapshot()
        facts['acceptance'] = {'valid': True, 'summary': '历史验收：仅 TCP/IPv4/INPUT 端口 443'}
        result = flow.report(facts, flow.new_state(['system']))
        self.assertEqual(self.task(result, 'entry.verify')['state'], 'done')
        self.assertEqual(result['recommended']['action'], 'inspect')
        self.assertIn('待验证', result['conclusion'])

    def test_dual_deployment_scope_confirmation_has_a_persisted_exit(self):
        facts = snapshot()
        facts['inventory']['remote'] = True
        facts['checks']['remote'] = 'ok'
        state = flow.new_state(['system'])
        self.assertEqual(flow.report(facts, state)['recommended']['action'], 'choose_scope')
        state['deployment_scope'] = {'choice': 'local', 'fingerprint': facts['fingerprint']}
        self.assertFalse(any(t['id'] == 'deployment.conflict' for t in flow.report(facts, state)['tasks']))
        facts['fingerprint'] = 'd'*64
        self.assertEqual(flow.report(facts, state)['recommended']['action'], 'choose_scope')

    def test_explicitly_uncertain_goal_keeps_inspection_instead_of_reasking(self):
        result = flow.report(snapshot(False), flow.new_state([]))
        self.assertEqual(result['recommended']['action'], 'inspect')
        self.assertFalse(any('install_core' in t['action'] for t in result['tasks']))


if __name__ == '__main__':
    unittest.main()

"""Read-only discovery: unknown is not healthy and all commands share a budget."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
try:
    import crowdbastion_flow_probe as probe
except ImportError:
    probe = None


class Discovery(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(probe, 'bounded discovery is not implemented')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cs = self.root / 'etc/crowdsec'
        self.state = self.root / 'var/lib/crowdbastion'
        self.calls = []
        self.answers = {}

    def runner(self, args, timeout):
        self.calls.append((args, timeout))
        code, output = self.answers.get(tuple(args), (127, ''))
        return subprocess.CompletedProcess(args, code, output, '')

    def discover(self, **kwargs):
        return probe.discover(self.cs, self.state, runner=self.runner, **kwargs)

    def install(self):
        self.cs.mkdir(parents=True)
        (self.cs / 'config.yaml').write_text('api: {}\n')
        self.answers[('systemctl', 'show', 'crowdsec', '--property=LoadState,ActiveState')] = (0, 'LoadState=loaded\nActiveState=active\n')
        self.answers[('crowdsec', '-t')] = (0, '')
        self.answers[('cscli', 'lapi', 'status')] = (0, '')

    def test_fresh_host_does_not_default_to_website_or_create_state(self):
        report = self.discover()
        self.assertFalse(report['inventory']['core'])
        self.assertEqual(report['checks']['core'], 'missing')
        self.assertEqual(report['targets'], [])
        self.assertFalse(self.state.exists())
        self.assertFalse(self.cs.exists())

    def test_loaded_service_and_config_are_distinct_evidence(self):
        self.install()
        self.answers[('crowdsec', '-t')] = (1, 'SECRET CONFIG ERROR')
        report = self.discover()
        self.assertEqual(report['checks']['core'], 'ok')
        self.assertEqual(report['checks']['config'], 'fault')
        self.assertNotIn('SECRET', json.dumps(report))

    def test_failed_query_is_unknown_even_if_output_says_inactive(self):
        self.install()
        self.answers[('systemctl', 'show', 'crowdsec', '--property=LoadState,ActiveState')] = (1, 'LoadState=loaded\nActiveState=inactive\n')
        self.assertEqual(self.discover()['checks']['core'], 'unknown')

    def test_idle_and_unparsable_logs_get_different_states(self):
        self.install()
        for counters, expected in (({'reads': 0, 'parsed': 0}, 'pending'),
                                   ({'reads': 8, 'parsed': 0}, 'fault'),
                                   ({'reads': 8, 'parsed': 8}, 'ok')):
            self.answers[('cscli', 'metrics', 'show', 'acquisition', '-o', 'json')] = (0, json.dumps({'acquisition': {'/var/log/auth.log': counters}}))
            with self.subTest(expected=expected):
                self.assertEqual(self.discover()['checks']['logs'], expected)

    def test_zero_budget_does_not_run_commands_or_infer_healthy(self):
        self.install()
        report = self.discover(budget=0)
        self.assertEqual(self.calls, [])
        self.assertEqual(report['checks']['core'], 'unknown')
        self.assertTrue(report['limitations'])

    def test_timeout_is_partial_unknown_with_remaining_evidence(self):
        self.install()
        def runner(args, timeout):
            if args[0] == 'systemctl':
                raise subprocess.TimeoutExpired(args, timeout)
            return self.runner(args, timeout)
        report = probe.discover(self.cs, self.state, runner=runner, budget=1)
        self.assertEqual(report['checks']['core'], 'unknown')
        self.assertEqual(report['checks']['config'], 'ok')
        self.assertTrue(all(0 < timeout <= 1 for _, timeout in self.calls))

    def test_multiple_runtime_instances_are_candidates_not_selected_sites(self):
        self.answers[('nginx', '-T')] = (0, '# configuration file /etc/nginx/nginx.conf:\nhttp { server { server_name one.test two.test; } }')
        self.answers[('docker', 'ps', '--no-trunc', '--format', '{{json .}}')] = (0, json.dumps({'ID': 'a'*64, 'Names': 'edge', 'Image': 'nginx:alpine'}))
        self.answers[('docker', 'inspect', 'a'*64)] = (0, json.dumps([{'Id': 'a'*64, 'Name': '/edge', 'HostConfig': {'NetworkMode': 'bridge'}, 'Config': {'Image': 'nginx:alpine'}, 'State': {'Running': True}, 'Mounts': []}]))
        self.answers[('docker', 'exec', 'a'*64, 'nginx', '-T')] = (0, 'http { server { server_name edge.test; } }')
        report = self.discover()
        self.assertEqual([t['id'] for t in report['targets']], ['host:nginx', 'docker:'+'a'*64])
        self.assertEqual(report['targets'][1]['network'], 'bridge')
        self.assertFalse(report['targets'][0]['owned'])
        self.assertNotIn('selected', report['targets'][0])

    def test_remote_and_local_conflict_is_preserved_as_fact(self):
        self.install()
        b = self.cs/'bouncers'
        b.mkdir()
        (b/'crowdsec-firewall-bouncer.yaml.remote.json').write_text('{}')
        report = self.discover()
        self.assertTrue(report['inventory']['remote'])
        self.assertTrue(report['inventory']['core'])

    def test_pending_transaction_is_visible_without_configured_goals(self):
        tx = self.state/'changes'/('b'*32)
        tx.mkdir(parents=True)
        (tx/'manifest.json').write_text(json.dumps({'kind': 'network'}))
        (tx/'journal.json').write_text(json.dumps({'state': 'staged', 'deadline': time.time()+500}))
        report = self.discover()
        self.assertEqual(report['pending'][0]['kind'], 'network')
        self.assertEqual(report['pending'][0]['state'], 'staged')

    def test_probe_does_not_expose_remote_key_or_raw_configuration(self):
        self.install()
        (self.cs/'local_api_credentials.yaml').write_text('password: FLOW_SECRET_CANARY\n')
        before = {str(p): p.read_bytes() for p in self.cs.rglob('*') if p.is_file()}
        report = self.discover()
        self.assertNotIn('FLOW_SECRET_CANARY', json.dumps(report))
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.cs.rglob('*') if p.is_file()})
        self.assertFalse(self.state.exists())
        self.assertFalse(any(any(x in args for x in ('restart', 'reload', 'start', 'install', 'apply')) for args, _ in self.calls))

    def test_configuration_changes_invalidate_fingerprint(self):
        self.install()
        before = self.discover()['fingerprint']
        (self.cs/'config.yaml').write_text('api: {changed: true}\n')
        self.assertNotEqual(self.discover()['fingerprint'], before)

    def test_registered_config_and_arbitrary_lua_hook_do_not_prove_connection(self):
        self.install()
        b = self.cs/'bouncers'
        b.mkdir()
        (b/'crowdsec-nginx-bouncer.conf').write_text('APPSEC_URL=http://127.0.0.1:7422\n')
        self.answers[('nginx', '-T')] = (0, 'http { access_by_lua_file unrelated.lua; # crowdsec\n }')
        target = self.discover()['targets'][0]
        self.assertFalse(target['connected'])
        self.assertNotEqual(target['realip'], 'verified')

    def test_validator_distinguishes_valid_hooks_from_current_ip_verification(self):
        self.install()
        acquisitions = self.cs/'acquis.d'
        acquisitions.mkdir()
        (self.cs/'config.yaml').write_text(json.dumps({'crowdsec_service': {'acquisition_dir': str(acquisitions)}}))
        (acquisitions/'appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\n')
        self.answers[('ss', '-H', '-lnt')] = (0, 'LISTEN 0 128 127.0.0.1:7422 0.0.0.0:*\n')
        b = self.cs/'bouncers'
        b.mkdir()
        (b/'crowdsec-nginx-bouncer.conf').write_text('APPSEC_URL=http://127.0.0.1:7422\n')
        self.answers[('nginx', '-T')] = (0, 'http { access_by_lua_file crowdsec.lua; }')
        for status, expected in ((0, 'verified'), (2, 'unknown')):
            def runner(args, timeout):
                if args[0] == 'env':
                    Path(args[1].split('=', 1)[1]).write_text('web\trequired\nweb\tok\n')
                    return subprocess.CompletedProcess(args, status, 'PRIVATE SOURCE DETAILS', '')
                return self.runner(args, timeout)
            result = probe.discover(self.cs, self.state, runner=runner)
            self.assertTrue(result['targets'][0]['connected'])
            self.assertEqual(result['targets'][0]['realip'], expected)
            self.assertNotIn('PRIVATE SOURCE DETAILS', json.dumps(result))

    def test_corrupt_legacy_roles_are_not_silently_ignored(self):
        self.state.mkdir(parents=True)
        (self.state/'node-roles.json').write_text('{')
        result = self.discover()
        self.assertTrue(result['scope_issue'])

    def test_private_endpoint_registration_is_not_current_connectivity_evidence(self):
        self.cs.mkdir(parents=True)
        (self.cs/'crowdsec-1key-docker-endpoints.json').write_text(json.dumps({'edge': {'api_url': 'http://172.18.0.1:18080', 'appsec_url': 'http://172.18.0.1:17422'}}))
        self.answers[('docker', 'ps', '--no-trunc', '--format', '{{json .}}')] = (0, json.dumps({'ID': 'a'*64, 'Names': 'edge', 'Image': 'nginx:alpine'}))
        self.answers[('docker', 'inspect', 'a'*64)] = (0, json.dumps([{'Id': 'a'*64, 'Name': '/edge', 'HostConfig': {'NetworkMode': 'bridge'}, 'State': {'Running': True}}]))
        self.answers[('docker', 'exec', 'a'*64, 'nginx', '-T')] = (0, 'http {}')
        self.assertFalse(self.discover()['targets'][0]['transport'])

    def test_valid_relay_history_has_scope_and_is_invalidated_by_config_change(self):
        from crowdbastion_ux import save_acceptance
        self.install()
        save_acceptance(self.state/'relay-acceptance.json', self.cs,
                        {'target': '203.0.113.8', 'port': 443, 'protocol': 'TCP', 'family': 'ip', 'hook': 'input'}, 0)
        result = self.discover()
        self.assertTrue(result['acceptance']['valid'])
        self.assertIn('TCP', result['acceptance']['summary'])
        self.assertNotEqual(result['checks'].get('traffic'), 'verified')
        (self.cs/'config.yaml').write_text('api: {changed: true}\n')
        self.assertFalse(self.discover()['acceptance']['valid'])


if __name__ == '__main__':
    unittest.main()

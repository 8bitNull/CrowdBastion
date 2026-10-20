"""Read-only dashboard observations use the same verdicts as host health checks."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))


class HealthCollectorTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('crowdsec_bot_health'),
                             'dashboard health collector is not implemented')
        import crowdsec_bot_health
        self.health = crowdsec_bot_health
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'config.yaml'
        self.config.write_text('config_paths: {}\n')
        self.roles = self.root / 'node-roles.json'
        self.now = 100.0
        self.wall = 1_750_000_000.0
        self.calls = []
        self.responses = {}
        self.elapsed = 0.0
        self.addCleanup(patch.stopall)
        patch.object(self.health.time, 'monotonic', side_effect=lambda: self.now).start()
        patch.object(self.health.time, 'time', side_effect=lambda: self.wall).start()
        patch.object(self.health.subprocess, 'run', side_effect=self.run_probe).start()

    def role(self, *roles):
        self.roles.write_text(json.dumps({'version': 1, 'roles': list(roles)}))

    def firewall(self, suffix=''):
        directory = self.root / 'bouncers'
        directory.mkdir(exist_ok=True)
        (directory / ('crowdsec-firewall-bouncer.yaml' + suffix)).write_text('api_key: fixture-private-key\n')

    def command(self, *args):
        return ('cscli', '-c', str(self.config), *args)

    def run_probe(self, args, **kwargs):
        self.assertIsInstance(args, list)
        self.assertNotIn('shell', kwargs)
        self.assertGreater(kwargs['timeout'], 0)
        self.assertLessEqual(kwargs['timeout'], 5)
        self.assertTrue(kwargs['capture_output'])
        self.assertTrue(kwargs['text'])
        self.calls.append((tuple(args), kwargs['timeout']))
        self.now += min(self.elapsed, kwargs['timeout'])
        if self.elapsed > kwargs['timeout']:
            raise subprocess.TimeoutExpired(args, kwargs['timeout'], output='private-timeout-output')
        if args == ['systemctl', 'is-active', 'crowdsec']:
            response = (0, 'active\n')
        elif args == ['systemctl', 'is-active', 'crowdsec-firewall-bouncer']:
            response = (0, 'active\n')
        elif tuple(args) == self.command('lapi', 'status'):
            response = (0, 'You can successfully interact with Local API (LAPI)\n')
        elif tuple(args) == self.command('bouncers', 'list', '-o', 'json'):
            response = (0, json.dumps([{'name': 'fixture', 'revoked': False, 'type': 'firewall-bouncer', 'last_pull': '2026-10-20T12:00:00Z', 'api_key': 'private-registry-value'}]))
        elif tuple(args) == self.command('metrics', 'show', 'acquisition', '-o', 'json'):
            response = (0, '{"acquisition":{"file:/var/log/nginx/access.log":{"reads":20,"parsed":20,"unparsed":0}}}')
        else:
            self.fail('unexpected command, possible mutation or external probe: ' + repr(args))
        response = self.responses.get(tuple(args), response)
        if isinstance(response, Exception):
            raise response
        return subprocess.CompletedProcess(args, response[0], response[1], 'private-stderr-value')

    def collect(self):
        return self.health.HealthCollector(str(self.config), str(self.roles)).collect()

    def test_default_local_uses_configured_path_and_remains_unverified(self):
        report = self.collect()
        self.assertEqual(report['checked_at'], self.wall)
        self.assertEqual(report['checks']['core'], 'ok')
        self.assertEqual(report['checks']['api'], 'ok')
        self.assertEqual(report['checks']['logs'], 'ok')
        self.assertEqual(report['checks']['bouncer'], 'optional')
        self.assertEqual(report['checks']['traffic'], 'pending')
        self.assertEqual(report['summary']['verdict'], '运行检查通过，实际拦截待验证')
        self.assertIn('本地', report['scope'])
        self.assertNotIn('private', json.dumps(report))
        self.assertEqual({args for args, _ in self.calls}, {
            ('systemctl', 'is-active', 'crowdsec'), self.command('lapi', 'status'),
            self.command('bouncers', 'list', '-o', 'json'),
            self.command('metrics', 'show', 'acquisition', '-o', 'json')})

    def test_configured_firewall_bouncer_is_checked_even_for_web_role(self):
        self.role('web')
        self.firewall('.local')
        self.responses[('systemctl', 'is-active', 'crowdsec-firewall-bouncer')] = (3, 'inactive\n')
        report = self.collect()
        self.assertEqual(report['checks']['bouncer'], 'fault')
        self.assertEqual(report['summary']['verdict'], '发现问题，需要处理')
        self.assertIn('防火墙', report['summary']['attention'])

    def test_web_bouncer_is_not_mistaken_for_firewall_deployment(self):
        (self.root / 'bouncers').mkdir()
        (self.root / 'bouncers/crowdsec-nginx-bouncer.conf').write_text('API_KEY=private\n')
        self.assertEqual(self.collect()['checks']['bouncer'], 'optional')
        self.assertFalse(any('crowdsec-firewall-bouncer' in args for args, _ in self.calls))

    def test_relay_requires_firewall_configuration(self):
        self.role('relay')
        report = self.collect()
        self.assertEqual(report['checks']['bouncer'], 'missing')
        self.assertEqual(report['summary']['verdict'], '部署尚未完成')
        self.assertFalse(any('crowdsec-firewall-bouncer' in args for args, _ in self.calls))

    def test_remote_never_probes_local_core_lapi_registry_or_logs(self):
        self.role('remote', 'node')
        self.firewall()
        report = self.collect()
        self.assertEqual(report['checks']['bouncer'], 'ok')
        self.assertEqual(report['checks']['remote'], 'unknown')
        for key in ('core', 'api', 'registry', 'metrics', 'logs'):
            self.assertEqual(report['checks'][key], 'optional')
        self.assertEqual(report['summary']['verdict'], '检查未完成，暂时无法判断')
        self.assertIn('远端', report['scope'])
        self.assertEqual([args for args, _ in self.calls], [('systemctl', 'is-active', 'crowdsec-firewall-bouncer')])

    def test_remote_without_firewall_is_missing_not_local_core_failure(self):
        self.role('remote')
        report = self.collect()
        self.assertEqual(report['checks']['bouncer'], 'missing')
        self.assertEqual(report['checks']['core'], 'optional')
        self.assertEqual(self.calls, [])

    def test_corrupt_or_unsafe_roles_cannot_silently_fall_back_to_local(self):
        for contents in ('not json', '{"version":1,"roles":["remote","web"]}', '{"version":1,"roles":["arbitrary"]}'):
            with self.subTest(contents=contents):
                self.roles.write_text(contents)
                report = self.collect()
                self.assertEqual(report['checks']['check'], 'unknown')
                self.assertEqual(report['summary']['verdict'], '检查未完成，暂时无法判断')
                self.assertEqual(self.calls, [])
        self.roles.write_text('{"version":1,"roles":["web"]}')
        self.roles.chmod(0o666)
        self.assertEqual(self.collect()['checks']['check'], 'unknown')
        self.assertEqual(self.calls, [])

    def test_role_symlink_is_not_followed(self):
        target = self.root / 'other.json'
        target.write_text('{"version":1,"roles":["web"]}')
        self.roles.symlink_to(target)
        self.assertEqual(self.collect()['checks']['check'], 'unknown')
        self.assertEqual(self.calls, [])

    def test_cache_reuses_report_for_thirty_seconds_using_monotonic_time(self):
        collector = self.health.HealthCollector(str(self.config), str(self.roles))
        first = collector.collect()
        self.responses[('systemctl', 'is-active', 'crowdsec')] = (3, 'inactive\n')
        self.now += 29.999
        self.wall -= 600
        cached = collector.collect()
        self.assertEqual(cached, first)
        self.assertEqual(len(self.calls), 4)
        self.now += 0.0011
        fresh = collector.collect()
        self.assertEqual(fresh['checks']['core'], 'fault')
        self.assertEqual(fresh['checked_at'], self.wall)
        self.assertEqual(len(self.calls), 8)

    def test_four_slow_probes_exhaust_total_budget_and_leave_logs_unknown(self):
        self.firewall()
        self.elapsed = 5
        report = self.collect()
        self.assertEqual(self.now, 120)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(report['checks']['metrics'], 'unknown')
        self.assertEqual(report['checks']['logs'], 'unknown')
        self.assertEqual(report['summary']['verdict'], '检查未完成，暂时无法判断')

    def test_final_call_timeout_is_limited_to_remaining_budget(self):
        self.firewall()
        self.elapsed = 4.5
        report = self.collect()
        self.assertEqual(self.calls[-1][1], 2.0)
        self.assertEqual(self.now, 120)
        self.assertEqual(report['checks']['logs'], 'unknown')
        self.assertEqual(report['checks']['traffic'], 'pending')

    def test_probe_errors_are_unknown_without_echoing_exception_or_output(self):
        for error in (FileNotFoundError('private-command-detail'), subprocess.TimeoutExpired('private-command-detail', 5, output='private-output'), OSError('private-error')):
            with self.subTest(error=error):
                self.responses[('systemctl', 'is-active', 'crowdsec')] = error
                report = self.collect()
                self.assertEqual(report['checks']['core'], 'unknown')
                self.assertNotIn('private', json.dumps(report))

    def test_known_systemd_states_distinguish_fault_missing_and_unknown(self):
        for response, want in (((3, 'inactive\n'), 'fault'), ((3, 'failed\n'), 'fault'), ((4, 'unknown\n'), 'missing'), ((1, 'private-secret'), 'unknown'), ((0, 'private-secret'), 'unknown')):
            with self.subTest(response=response):
                self.responses[('systemctl', 'is-active', 'crowdsec')] = response
                report = self.collect()
                self.assertEqual(report['checks']['core'], want)
                self.assertNotIn('private', json.dumps(report))

    def test_lapi_failure_is_fault_and_missing_config_is_missing(self):
        self.responses[self.command('lapi', 'status')] = (1, 'private-lapi-key')
        self.assertEqual(self.collect()['checks']['api'], 'fault')
        self.calls.clear()
        self.config.unlink()
        self.assertEqual(self.collect()['checks']['api'], 'missing')
        self.assertFalse(any(args[0] == 'cscli' for args, _ in self.calls))

    def test_registry_empty_is_missing_and_malformed_is_unknown(self):
        for output, want in (('[]', 'missing'), ('{}', 'unknown'), ('private-json', 'unknown'), ('[null]', 'unknown')):
            with self.subTest(output=output):
                self.responses[self.command('bouncers', 'list', '-o', 'json')] = (0, output)
                report = self.collect()
                self.assertEqual(report['checks']['registry'], want)
                self.assertNotIn('private', json.dumps(report))

    def test_revoked_registration_cannot_be_reported_as_healthy(self):
        for revoked, want in ((True, 'fault'), (False, 'ok'), ('false', 'unknown'), (None, 'unknown')):
            with self.subTest(revoked=revoked):
                self.responses[self.command('bouncers', 'list', '-o', 'json')] = (0, json.dumps([{'name': 'fixture-private-name', 'revoked': revoked}]))
                report = self.collect()
                self.assertEqual(report['checks']['registry'], want)
                self.assertNotIn('private', json.dumps(report))

    def test_registration_without_revocation_evidence_is_unknown(self):
        for row in ({'name': 'fixture'}, {'name': 'fixture', 'valid': True}):
            with self.subTest(row=row):
                self.responses[self.command('bouncers', 'list', '-o', 'json')] = (0, json.dumps([row]))
                self.assertEqual(self.collect()['checks']['registry'], 'unknown')

    def test_configuration_path_is_passed_as_one_literal_argument(self):
        unusual = self.root / 'config $(touch injected); secret.yaml'
        self.config.rename(unusual)
        self.config = unusual
        report = self.collect()
        self.assertEqual(report['checks']['api'], 'ok')
        self.assertIn((self.command('lapi', 'status'), 5), self.calls)
        self.assertFalse((self.root / 'injected').exists())

    def test_log_evidence_distinguishes_fault_idle_empty_and_success(self):
        for sources, want in (({'auth': {'reads': 10, 'parsed': 0}}, 'fault'),
                              ({'auth': {'reads': 0, 'parsed': 0}}, 'pending'),
                              ({}, 'pending'),
                              ({'auth': {'reads': 10, 'parsed': 9}}, 'ok'),
                              ({'auth': {'reads': 10, 'parsed': 9}, 'web': {'reads': 0}}, 'pending'),
                              ({'auth': {'reads': 10, 'parsed': 9}, 'web': {'reads': 2}}, 'fault')):
            with self.subTest(sources=sources):
                self.responses[self.command('metrics', 'show', 'acquisition', '-o', 'json')] = (0, json.dumps({'acquisition': sources}))
                self.assertEqual(self.collect()['checks']['logs'], want)

    def test_malformed_and_negative_metrics_are_unknown_not_good_parsing(self):
        invalid = ['private-invalid-json', '[]', '{"acquisition":[]}', '{"acquisition":{"auth":null}}']
        for count in (-1, True, '10', float('nan'), float('inf')):
            invalid.append(json.dumps({'acquisition': {'private-source': {'reads': count, 'parsed': 10}}}))
        for output in invalid:
            with self.subTest(output=output):
                self.responses[self.command('metrics', 'show', 'acquisition', '-o', 'json')] = (0, output)
                report = self.collect()
                self.assertEqual(report['checks']['metrics'], 'unknown')
                self.assertEqual(report['checks']['logs'], 'unknown')
                self.assertNotIn('private', json.dumps(report))

    def test_collection_does_not_modify_configuration_or_roles(self):
        self.role('relay')
        self.firewall()
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.collect()
        after = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(after, before)


if __name__ == '__main__':
    unittest.main()

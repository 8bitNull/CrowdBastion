"""Read-only decision snapshots and actually referenced kernel sets."""
import ipaddress
import http.client
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import crowdsec_firewall_evidence as evidence


class Evidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name)/'bouncer.yaml'
        self.config.write_text('mode: iptables\napi_url: http://127.0.0.1:8080/\napi_key: private-canary\n')

    def rows(self):
        return [dict(value='198.51.100.7', type='ban', scope='Ip', duration='1h'),
                dict(value='2001:db8::/64', type='ban', scope='Range', duration='1m'),
                dict(value='192.0.2.1', type='ban', scope='Ip', duration='3s'),
                dict(value='192.0.2.2', type='captcha', scope='Ip', duration='1h')]

    def test_selects_applicable_long_lived_bans(self):
        self.assertEqual(evidence.networks(self.rows()), {ipaddress.ip_network('198.51.100.7/32'), ipaddress.ip_network('2001:db8::/64')})

    def test_coverage_uses_only_referenced_sets_and_accepts_supernets(self):
        expected = evidence.networks(self.rows())
        refs = {4: {'v4'}, 6: {'v6'}}
        text = 'create v4 hash:net family inet\ncreate v6 hash:net family inet6\nadd v4 198.51.100.0/24\nadd unused 192.0.2.0/24\nadd v6 2001:db8::/48\n'
        self.assertEqual(evidence.membership(expected, refs, text)['missing'], 0)
        text = text.replace('add v4 ', 'add unused ')
        self.assertEqual(evidence.membership(expected, refs, text)['missing'], 1)

    def test_missing_or_wrong_family_set_is_not_healthy(self):
        with self.assertRaises(ValueError):
            evidence.membership(set(), {4: {'v4'}, 6: set()}, '')
        with self.assertRaises(ValueError):
            evidence.membership(set(), {4: {'v4'}, 6: set()}, 'create v4 hash:net family inet6\n')

    def test_nomatch_cannot_count_as_enforced_ban(self):
        for rows in ('add v4 198.51.100.7 nomatch\n', 'add v4 198.51.100.0/24\nadd v4 198.51.100.7 nomatch\n'):
            with self.subTest(rows=rows), self.assertRaises(evidence.EvidenceError):
                evidence.membership({ipaddress.ip_network('198.51.100.7/32')}, {4: {'v4'}, 6: set()}, 'create v4 hash:net family inet\n'+rows)

    def test_custom_filters_are_explicitly_unknown(self):
        for field in ('origins', 'scopes', 'scenarios_containing', 'scenarios_not_containing'):
            with self.subTest(field=field):
                with self.config.open('a') as out:
                    out.write(f'{field}: [custom]\n')
                with self.assertRaises(evidence.EvidenceError):
                    evidence.live(self.config)

    def test_snapshot_never_consumes_stream_or_discloses_credentials(self):
        requests = []
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return json.dumps(self_rows).encode()
        self_rows = self.rows()
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                return Response()
        with patch.object(evidence.urllib.request, 'build_opener', return_value=Opener()):
            self.assertEqual(evidence.live(self.config), self_rows)
        self.assertEqual(requests[0].full_url, 'http://127.0.0.1:8080/v1/decisions')
        self.assertEqual(requests[0].get_method(), 'GET')
        with patch.object(evidence.urllib.request, 'build_opener', side_effect=ValueError('private-canary')):
            with self.assertRaises(evidence.EvidenceError) as error:
                evidence.live(self.config)
        self.assertNotIn('private-canary', str(error.exception))

    def test_wait_retries_missing_but_has_deadline(self):
        reports = [dict(state='pending', missing=1), dict(state='ok', missing=0)]
        with patch.object(evidence, 'inspect', side_effect=reports), patch.object(evidence.time, 'sleep'):
            self.assertEqual(evidence.wait(self.config, seconds=2)['state'], 'ok')
        with patch.object(evidence, 'inspect', return_value=reports[0]), patch.object(evidence.time, 'monotonic', side_effect=[0, 5]):
            self.assertEqual(evidence.wait(self.config, seconds=2)['state'], 'fault')

    def test_api_failures_have_distinct_safe_diagnostics(self):
        cases = [
            (TimeoutError('private-canary'), 'api_timeout', True),
            (http.client.IncompleteRead(b'private-canary'), 'api_connection_failed', True),
            (urllib.error.URLError(TimeoutError('private-canary')), 'api_timeout', True),
            (urllib.error.HTTPError('http://private-canary/', 401, 'private-canary', {}, None), 'api_auth_failed', False),
            (urllib.error.HTTPError('http://private-canary/', 403, 'private-canary', {}, None), 'api_auth_failed', False),
            (urllib.error.HTTPError('http://private-canary/', 503, 'private-canary', {}, None), 'api_http_error', True),
        ]
        for error, code, retryable in cases:
            with self.subTest(code=code), patch.object(evidence.urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = error
                with self.assertRaises(evidence.EvidenceError) as caught:
                    evidence.live(self.config)
                self.assertEqual(caught.exception.error_code, code)
                self.assertEqual(caught.exception.phase, 'api_request')
                self.assertEqual(caught.exception.retryable, retryable)
                self.assertGreaterEqual(caught.exception.duration_seconds, 0)
                self.assertNotIn('private-canary', str(caught.exception))

    def test_malformed_api_response_is_not_authentication_failure(self):
        with patch.object(evidence.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{private-canary'
            with self.assertRaises(evidence.EvidenceError) as caught:
                evidence.live(self.config)
        self.assertEqual(caught.exception.phase, 'api_response')
        self.assertEqual(caught.exception.error_code, 'api_response_invalid')
        self.assertFalse(caught.exception.retryable)
        self.assertNotIn('private-canary', str(caught.exception))

    def test_inspect_distinguishes_rules_and_ipset_read_failures(self):
        import crowdsec_firewall_runtime as runtime
        for stage in ('rules_read', 'ipset_read'):
            with self.subTest(stage=stage), patch.object(runtime, 'run', side_effect=ValueError('private-canary')), patch.object(evidence, 'live', return_value=[]):
                if stage == 'ipset_read':
                    with patch.object(runtime, 'iptables_references', return_value={4: set(), 6: set()}):
                        report = evidence.inspect(self.config, docker=False)
                else:
                    report = evidence.inspect(self.config, docker=False)
                self.assertEqual(report['state'], 'unknown')
                self.assertEqual(report['phase'], stage)
                self.assertEqual(report['error_code'], stage+'_failed')
                self.assertTrue(report['retryable'])
                self.assertGreaterEqual(report['duration_seconds'], 0)
                self.assertNotIn('private-canary', json.dumps(report))

    def test_empty_chain_api_timeout_retains_api_diagnostic(self):
        import crowdsec_firewall_runtime as runtime
        empty = '-N CROWDSEC_CHAIN\n-A INPUT -j CROWDSEC_CHAIN\n-A FORWARD -j CROWDSEC_CHAIN\n'
        with patch.object(runtime, 'run', return_value=subprocess.CompletedProcess([], 0, empty)), patch.object(evidence.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = TimeoutError('private-canary')
            report = evidence.inspect(self.config, docker=False)
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual(report['phase'], 'api_request')
        self.assertEqual(report['error_code'], 'api_timeout')
        self.assertNotIn('private-canary', json.dumps(report))

    def test_redirect_is_classified_as_request_failure(self):
        with patch.object(evidence.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = lambda *a, **kw: evidence.NoRedirect().redirect_request()
            with self.assertRaises(evidence.EvidenceError) as caught:
                evidence.live(self.config)
        self.assertEqual(caught.exception.phase, 'api_request')
        self.assertEqual(caught.exception.error_code, 'api_redirect_refused')

    def test_successful_inspection_times_each_read_and_comparison_phase(self):
        import crowdsec_firewall_runtime as runtime
        clock = [0.0]
        def delayed(seconds, result):
            def call(*args, **kwargs):
                clock[0] += seconds
                return result
            return call
        original_membership = evidence.membership
        def compare(*args):
            clock[0] += 30
            return original_membership(*args)
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit):
                clock[0] += 2
                return b'[]'
        class Opener:
            def open(self, *args, **kwargs):
                clock[0] += 3
                return Response()
        with patch.object(evidence.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(runtime, 'iptables_references', side_effect=delayed(5, {4: set(), 6: set()})), patch.object(evidence.urllib.request, 'build_opener', return_value=Opener()), patch.object(evidence.json, 'loads', side_effect=delayed(7, [])), patch.object(runtime, 'run', side_effect=delayed(20, subprocess.CompletedProcess([], 0, ''))), patch.object(evidence, 'membership', side_effect=compare):
            report = evidence.inspect(self.config, docker=False)
        self.assertIn('phases', report)
        self.assertEqual(report['state'], 'ok')
        entries = {entry['phase']: entry for entry in report['phases']}
        for phase in ('config_read', 'rules_read', 'api_request', 'ipset_read', 'ipset_compare'):
            self.assertIn(phase, entries)
            self.assertGreaterEqual(entries[phase]['duration_seconds'], 0)
            self.assertEqual(entries[phase]['error_code'], 'none')
        self.assertEqual(entries['rules_read']['duration_seconds'], 5)
        self.assertEqual(entries['api_request']['duration_seconds'], 5)
        self.assertEqual(entries['api_response']['duration_seconds'], 7)
        self.assertEqual(entries['ipset_read']['duration_seconds'], 20)
        self.assertEqual(entries['ipset_compare']['duration_seconds'], 30)
        self.assertEqual(report['duration_seconds'], 67)

    def timed_probe(self, *, empty_chain=False, invalid_response=False):
        """Real live()/coverage with independently timed external boundaries."""
        import crowdsec_firewall_runtime as runtime
        import contextlib
        clock = [0.0]
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit):
                clock[0] += 2
                return b'[]'
        class Opener:
            def open(self, *args, **kwargs):
                clock[0] += 3
                return Response()
        def parse(payload):
            clock[0] += 7
            if invalid_response:
                raise ValueError('private-canary')
            return []
        empty = '-N CROWDSEC_CHAIN\n-A INPUT -j CROWDSEC_CHAIN\n-A FORWARD -j CROWDSEC_CHAIN\n'
        def command(argv):
            return subprocess.CompletedProcess(argv, 0, empty if argv[0] in ('iptables', 'ip6tables') else '')
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(evidence.time, 'monotonic', side_effect=lambda: clock[0]))
            stack.enter_context(patch.object(evidence.urllib.request, 'build_opener', return_value=Opener()))
            stack.enter_context(patch.object(evidence.json, 'loads', side_effect=parse))
            stack.enter_context(patch.object(runtime, 'run', side_effect=command))
            if not empty_chain:
                stack.enter_context(patch.object(runtime, 'iptables_references', return_value={4: set(), 6: set()}))
            return evidence.inspect(self.config, docker=False)

    def test_real_live_response_failure_times_only_failed_processing_phase(self):
        report = self.timed_probe(invalid_response=True)
        self.assertEqual(report['phase'], 'api_response')
        entries = {entry['phase']: entry for entry in report['phases']}
        self.assertEqual(entries['api_request']['duration_seconds'], 5)
        self.assertEqual(entries['api_response']['duration_seconds'], 7)
        self.assertEqual(entries['api_response']['error_code'], 'api_response_invalid')
        self.assertEqual(report['duration_seconds'], 12)
        self.assertNotIn('private-canary', json.dumps(report))

    def test_successful_idle_chain_probe_has_separate_nested_api_timings(self):
        report = self.timed_probe(empty_chain=True)
        self.assertEqual(report['state'], 'ok')
        entries = {entry['phase']: entry for entry in report['phases'] if entry.get('nested')}
        self.assertIn('api_request', entries)
        self.assertEqual(entries['api_request']['duration_seconds'], 5)
        self.assertEqual(entries['api_response']['duration_seconds'], 7)
        direct = {entry['phase']: entry for entry in report['phases'] if not entry.get('nested')}
        self.assertEqual(direct['api_request']['duration_seconds'], 5)
        self.assertEqual(direct['api_response']['duration_seconds'], 7)
        self.assertEqual(direct['rules_read']['duration_seconds'], 12)
        self.assertEqual(report['duration_seconds'], 24)

    def test_failed_idle_chain_probe_has_separate_nested_response_timing(self):
        report = self.timed_probe(empty_chain=True, invalid_response=True)
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual(report['phase'], 'api_response')
        entries = {entry['phase']: entry for entry in report['phases'] if entry.get('nested')}
        self.assertIn('api_request', entries)
        self.assertEqual(entries['api_request']['duration_seconds'], 5)
        self.assertEqual(entries['api_response']['duration_seconds'], 7)
        self.assertEqual(entries['api_response']['error_code'], 'api_response_invalid')
        self.assertNotIn('private-canary', json.dumps(report))

    def test_failed_read_keeps_completed_phase_timings_and_failure_duration(self):
        import crowdsec_firewall_runtime as runtime
        with patch.object(runtime, 'run', side_effect=TimeoutError('private-canary')):
            report = evidence.inspect(self.config, docker=False)
        self.assertIn('phases', report)
        self.assertEqual([entry['phase'] for entry in report['phases']], ['config_read', 'rules_read'])
        self.assertEqual(report['phases'][-1]['error_code'], 'rules_read_failed')
        self.assertGreaterEqual(report['phases'][-1]['duration_seconds'], 0)
        self.assertNotIn('private-canary', json.dumps(report))

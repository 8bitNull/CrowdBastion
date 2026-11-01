"""Read-only decision snapshots and actually referenced kernel sets."""
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
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
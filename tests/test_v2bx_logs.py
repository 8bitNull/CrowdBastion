"""Source-backed synthetic log fixtures, never production traffic evidence."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_workflows

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT/'lib/crowdsec_v2bx_logs.py'
STAMP = '2026/10/13 12:00:00.123456'


class V2bXLogs(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.exists(), 'V2bX offline log adapter is missing')
        sys.path.insert(0, str(ROOT/'lib'))
        self.addCleanup(sys.path.remove, str(ROOT/'lib'))
        spec = importlib.util.spec_from_file_location('v2bx_logs_test', HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def parse(self, line, core, offset='+00:00'):
        return self.helper.parse_line(line, core, offset)

    def test_sing_quic_explicit_rejection_contract_and_negative_branches(self):
        for protocol in ('tuic', 'hysteria', 'hysteria2'):
            fields = {'schema_version': 1, 'core': 'sing', 'protocol': protocol,
                      'event_type': 'auth_rejected', 'addr': '[2001:db8::8]:12345'}
            prefix = '+0000 2026-10-13 12:00:00 ERROR v2bx-auth/'+protocol+': '
            line = prefix+'v2bx-observation '+json.dumps(fields)
            item, status = self.parse(line, 'sing')
            self.assertEqual(status, 'parsed')
            self.assertEqual(item['protocol'], protocol)
            self.assertEqual(item['source_ip'], '2001:db8::8')
            self.assertEqual(item['event_type'], 'auth_failure')
            self.assertTrue(self.helper.eligible(item))
            self.assertNotIn('panel.invalid', json.dumps(item))
            self.assertIsNone(self.parse(line.replace('v2bx-auth/'+protocol+':', 'inbound/'+protocol+'[http://panel.invalid]:'), 'sing')[0])
            for key, value in [('schema_version', True), ('schema_version', 2), ('core', 'hysteria2'),
                               ('protocol', 'vmess'), ('event_type', 'observations_dropped'),
                               ('event_type', 'bandwidth_policy_rejected'), ('addr', 'host.invalid:12345')]:
                changed = dict(fields); changed[key] = value
                self.assertIsNone(self.parse(prefix+'v2bx-observation '+json.dumps(changed), 'sing')[0])
            self.assertIsNone(self.parse(line.replace(' ERROR ', ' INFO '), 'sing')[0])
            for reason in ('authentication timeout', 'authentication: unknown user', 'BBR disabled by server', '404'):
                self.assertIsNone(self.parse(prefix+reason, 'sing')[0])

    def test_experimental_hy2_explicit_rejection_contract(self):
        fields = {'schema_version': 1, 'core': 'hysteria2', 'protocol': 'hysteria2',
                  'event_type': 'auth_rejected', 'addr': '[2001:db8::7]:12345'}
        console = '2026-10-13T12:00:00Z\tERROR\tv2bx authentication rejected\t'+json.dumps(fields)
        structured = json.dumps(dict(fields, time=1791892800000, level='error', msg='v2bx authentication rejected'))
        for line in (console, structured):
            item, status = self.parse(line, 'hysteria2')
            self.assertEqual(status, 'parsed')
            self.assertEqual(item['event_type'], 'auth_failure')
            self.assertEqual(item['source_ip'], '2001:db8::7')
            self.assertTrue(self.helper.eligible(item))
        for key, value in [('schema_version', 2), ('schema_version', True), ('core', 'sing'),
                           ('protocol', 'tuic'), ('event_type', 'bandwidth_policy_rejected'),
                           ('addr', 'host.invalid:12345')]:
            changed = dict(fields); changed[key] = value
            self.assertIsNone(self.parse('2026-10-13T12:00:00Z\tERROR\tv2bx authentication rejected\t'+json.dumps(changed), 'hysteria2')[0])
        for level in ('INFO', 'DEBUG', 'WARN'):
            self.assertIsNone(self.parse(console.replace('\tERROR\t', '\t'+level+'\t'), 'hysteria2')[0])
        for msg in ('404', 'bandwidth policy rejected', 'v2bx authentication observations dropped'):
            self.assertIsNone(self.parse(console.replace('v2bx authentication rejected', msg), 'hysteria2')[0])

    def test_xray_failures_have_source_time_protocol_and_no_raw_reason(self):
        cases = [
            ('proxy/vless/encoding: invalid request user id', 'vless', 'auth_failure'),
            ('proxy/vmess/encoding: invalid user > API_SECRET', 'vmess', 'auth_failure'),
            ('proxy/trojan: not a valid user', 'trojan', 'fallback_candidate'),
            ('proxy/trojan: not trojan protocol', 'trojan', 'fallback_candidate'),
        ]
        for reason, protocol, kind in cases:
            with self.subTest(protocol=protocol, reason=reason):
                event, status = self.parse(STAMP+' from 198.51.100.7:12345 rejected  '+reason, 'xray')
                self.assertEqual(status, 'parsed')
                self.assertEqual(event['source_ip'], '198.51.100.7')
                self.assertEqual(event['timestamp'], '2026-10-13T12:00:00.123456Z')
                self.assertEqual(event['protocol'], protocol)
                self.assertEqual(event['event_type'], kind)
                self.assertTrue(event['observation_only'])
                self.assertEqual(event['source_status'], 'unverified')
                self.assertNotIn('API_SECRET', json.dumps(event))

    def test_xray_trojan_fallback_candidates_are_not_failure_observations(self):
        sample = self.base/'fallback.log'
        sample.write_text(''.join(STAMP+' from 198.51.100.7:123 rejected  proxy/trojan: '+reason+'\n'
                                  for reason in ('not a valid user', 'not trojan protocol')))
        report = self.helper.inspect_file(sample, 'xray', '+00:00')
        self.assertEqual(report['failure_observations'], 0)
        self.assertEqual(report['categories'], {'fallback_candidate': 2})

    def test_physical_lines_cannot_be_split_into_injected_events(self):
        sample = self.base/'control.log'
        valid = STAMP+' from 198.51.100.7:123 rejected  proxy/vless/encoding: invalid request user id'
        for separator in ('\v', '\f', '\x85', '\u2028', '\u2029', '\x7f'):
            with self.subTest(separator=repr(separator)):
                sample.write_text('credential prefix'+separator+valid+'\n')
                report = self.helper.inspect_file(sample, 'xray', '+00:00')
                self.assertEqual(report['events'], [])
                self.assertEqual(report['lines'], 1)
                self.assertEqual(report['ignored'], {'invalid_control': 1})
        sample.write_bytes((valid+'\r\n').encode())
        self.assertEqual(self.helper.inspect_file(sample, 'xray', '+00:00')['failure_observations'], 1)

    def test_source_is_not_guessed_from_destination_or_unrelated_errors(self):
        line = STAMP+' from 198.51.100.7:12345 accepted tcp:203.0.113.99:443 [UUID_SECRET] email: EMAIL_SECRET'
        event, status = self.parse(line, 'xray')
        self.assertEqual(status, 'parsed')
        self.assertEqual(event['source_ip'], '198.51.100.7')
        self.assertEqual(event['event_type'], 'connection_open')
        self.assertNotIn('203.0.113.99', json.dumps(event))
        for line in ('[Warning] connection ends > invalid user 198.51.100.7',
                     STAMP+' from 198.51.100.7:12345 rejected  EOF',
                     STAMP+' from 198.51.100.7:12345 rejected  network timeout > invalid user',
                     STAMP+' from 198.51.100.7:12345 rejected  tcp:host.invalid:443 invalid user'):
            self.assertIsNone(self.parse(line, 'xray')[0])

    def test_ipv6_and_utc_conversion(self):
        event, _ = self.parse(STAMP+' from [2001:db8::7]:443 rejected  proxy/trojan: not a valid user', 'xray', '+08:00')
        self.assertEqual(event['source_ip'], '2001:db8::7')
        self.assertEqual(event['timestamp'], '2026-10-13T04:00:00.123456Z')
        for endpoint in ('host.invalid:443', '[fe80::1%UUID_SECRET]:443', '198.51.100.7:70000', '0.0.0.0:443'):
            self.assertIsNone(self.parse(STAMP+' from '+endpoint+' rejected  proxy/trojan: not a valid user', 'xray')[0])

    def test_missing_timezone_and_invalid_dates_are_not_current_time(self):
        line = STAMP+' from 198.51.100.7:123 rejected  proxy/trojan: not a valid user'
        self.assertEqual(self.parse(line, 'xray', None)[1], 'time_unverified')
        self.assertIsNone(self.parse(line.replace('10/13', '99/99'), 'xray')[0])
        self.assertIsNone(self.parse(line, 'xray', '+99:00')[0])

    def test_anytls_explicit_rejection_without_fallback_is_observation(self):
        prefix = '+0000 2026-10-13 12:00:00 ERROR [123 0ms] inbound/anytls[[http://PANEL_SECRET]-anytls:10]: process connection from [2001:db8::8]:123: '
        item, status = self.parse(prefix+'unknown user password: fallback disabled', 'sing')
        self.assertEqual(status, 'parsed')
        self.assertEqual(item['event_type'], 'auth_failure')
        self.assertEqual(item['protocol'], 'anytls')
        self.assertTrue(self.helper.eligible(item))
        self.assertNotIn('PANEL_SECRET', json.dumps(item))
        for reason in ('unknown user password', 'unknown user password: fallback enabled',
                       'TLS handshake: timeout', 'EOF', 'connect: connection refused'):
            item, _ = self.parse(prefix+reason, 'sing')
            self.assertFalse(item and self.helper.eligible(item))

    def test_shadowsocks_integrity_is_not_authentication_or_ban_evidence(self):
        prefix = '+0000 2026-10-13 12:00:00 ERROR [123 0ms] inbound/shadowsocks[test]: process connection from 198.51.100.8:123: '
        reason = 'shadowsocks: serve TCP from 198.51.100.8:123: chacha20poly1305: message authentication failed'
        item, status = self.parse(prefix+reason, 'sing')
        self.assertEqual(status, 'parsed')
        self.assertEqual(item['event_type'], 'integrity_failure')
        self.assertEqual(item['protocol'], 'shadowsocks')
        self.assertFalse(self.helper.eligible(item))
        for bad in (reason.replace('198.51.100.8:123', '198.51.100.9:123'),
                    reason.replace('chacha20poly1305:', 'unknown wrapper:'),
                    'read tcp: timeout > '+reason):
            self.assertIsNone(self.parse(prefix+bad, 'sing')[0])

    def test_sourceless_quic_authentication_and_embedded_addresses_not_guessed(self):
        for protocol, reason in [('tuic', 'handle uni stream: authentication: unknown user ACCOUNT_SECRET'),
                                 ('hysteria', 'authentication failed, auth_str=ACCOUNT_SECRET'),
                                 ('hysteria2', 'authentication failed from 198.51.100.8:123')]:
            line = '+0000 2026-10-13 12:00:00 ERROR inbound/'+protocol+'[node]: connection failed: '+reason
            item, status = self.parse(line, 'sing')
            self.assertIsNone(item)
            self.assertNotIn('ACCOUNT_SECRET', status)

    def test_sing_exact_vless_reason_drops_uuid_and_tag(self):
        line = '+0800 2026-10-13 12:00:00 ERROR [123 1ms] inbound/vless[ACCOUNT_SECRET]: process connection from [2001:db8::8]:123: unknown UUID: 11111111-2222-3333-4444-555555555555'
        event, status = self.parse(line, 'sing')
        self.assertEqual(status, 'parsed')
        self.assertEqual(event['timestamp'], '2026-10-13T04:00:00Z')
        self.assertEqual(event['event_type'], 'auth_failure')
        self.assertEqual(event['source_ip'], '2001:db8::8')
        self.assertNotIn('ACCOUNT_SECRET', json.dumps(event))
        self.assertNotIn('11111111', json.dumps(event))

    def test_real_v2bx_sing_nested_node_tag_is_parsed_without_panel_url(self):
        line = '+0000 2026-10-13 12:00:00 ERROR [123 0ms] inbound/vless[[http://PANEL_SECRET:28900]-vless:6]: process connection from 198.51.100.8:123: unknown UUID: 11111111-2222-4333-8444-555555555555'
        event, status = self.parse(line, 'sing')
        self.assertEqual(status, 'parsed')
        self.assertEqual(event['source_ip'], '198.51.100.8')
        self.assertEqual(event['event_type'], 'auth_failure')
        self.assertNotIn('PANEL_SECRET', json.dumps(event))
        self.assertIsNone(self.parse(line.replace(']-vless:6]', '-vless:6]'), 'sing')[0])

    def test_real_xray_vmess_drain_wrapper_retains_explicit_auth_reason(self):
        prefix = STAMP+' from 198.51.100.7:123 rejected  '
        reason = 'common/drain: common/drain: unable to drain connection > read tcp 192.0.2.1:29001->198.51.100.7:123: i/o timeout > proxy/vmess/encoding: invalid user > user do not exist'
        event, status = self.parse(prefix+reason, 'xray')
        self.assertEqual(status, 'parsed')
        self.assertEqual(event['source_ip'], '198.51.100.7')
        self.assertEqual(event['event_type'], 'auth_failure')
        self.assertNotIn('192.0.2.1', json.dumps(event))
        self.assertIsNone(self.parse(prefix+reason.split(' > proxy/')[0], 'xray')[0])
        self.assertIsNone(self.parse(prefix+reason.replace('proxy/vmess/encoding: invalid user', 'destination message contains invalid user'), 'xray')[0])

    def test_sing_bad_request_is_rejection_not_proof_of_auth_attack(self):
        for protocol, reason in [('vmess', 'bad request'), ('trojan', 'bad request: fallback disabled')]:
            line = '+0000 2026-10-13 12:00:00 ERROR inbound/'+protocol+'[node]: process connection from 198.51.100.8:123: '+reason
            event, _ = self.parse(line, 'sing')
            self.assertEqual(event['event_type'], 'protocol_rejection')
        line = '+0000 2026-10-13 12:00:00 ERROR inbound/vless[node]: process connection from 198.51.100.8:123: TLS handshake: timeout'
        event, _ = self.parse(line, 'sing')
        self.assertEqual(event['event_type'], 'network_error')
        for reason in ('destination example.invalid contains unknown UUID', 'flow mismatch: expected xtls-rprx-vision',
                       'unknown UUID: SECRET', 'Limited USER_SECRET by ip or conn'):
            line = '+0000 2026-10-13 12:00:00 ERROR inbound/vless[node]: process connection from 198.51.100.8:123: '+reason
            self.assertIsNone(self.parse(line, 'sing')[0])

    def test_sing_relative_clock_needs_journal_envelope_and_sgr_is_removed(self):
        msg = '\x1b[31mERROR\x1b[0m[0001] inbound/vless[node]: process connection from 198.51.100.8:123: unknown UUID: 11111111-2222-3333-4444-555555555555'
        self.assertEqual(self.parse(msg, 'sing')[1], 'time_unverified')
        envelope = json.dumps({'_SYSTEMD_UNIT': 'V2bX.service', '__REALTIME_TIMESTAMP': '1791892800000000', 'MESSAGE': msg})
        event, _ = self.parse(envelope, 'sing')
        self.assertEqual(event['time_basis'], 'journal_receipt')
        self.assertEqual(event['event_type'], 'auth_failure')
        self.assertIsNone(self.parse(envelope.replace('V2bX.service', 'other.service'), 'sing')[0])

    def test_hysteria_console_and_json_connections_never_become_auth_failure(self):
        fields = {'addr': '[2001:db8::9]:443', 'uuid': 'UUID_SECRET', 'error': 'authentication failed TARGET_SECRET'}
        console = '2026-10-13T12:00:00Z\tINFO\tclient connected\t'+json.dumps(fields)
        event, _ = self.parse(console, 'hysteria2')
        self.assertEqual(event['event_type'], 'connection_open')
        event, _ = self.parse(json.dumps({**fields, 'time': 1791892800000, 'level': 'info', 'msg': 'client disconnected'}), 'hysteria2')
        self.assertEqual(event['event_type'], 'connection_close')
        self.assertNotIn('SECRET', json.dumps(event))
        self.assertIsNone(self.parse(json.dumps({**fields, 'time': 1791892800000, 'msg': 'authentication failed'}), 'hysteria2')[0])

    def test_multiline_invalid_json_and_oversized_lines_never_echo(self):
        for line in ('UUID_SECRET', '{"msg": "API_SECRET"', 'a'*10000,
                     STAMP+' from 198.51.100.7:123 rejected  proxy/trojan: not a valid user\nAPI_SECRET'):
            event, status = self.parse(line, 'xray')
            self.assertIsNone(event)
            self.assertNotIn('SECRET', status)

    def test_relay_cidrs_exclude_failures_and_file_is_unchanged(self):
        sample = self.base/'sample.log'
        sample.write_text(STAMP+' from 198.51.100.7:123 rejected  proxy/vless/encoding: invalid request user id\n'
                          +STAMP+' from 203.0.113.8:123 rejected  proxy/vless/encoding: invalid request user id\n')
        before = sample.read_bytes()
        result = subprocess.run([sys.executable, str(HELPER), '--file', str(sample), '--core', 'xray',
                                 '--timezone', '+00:00', '--relay-cidrs', '198.51.100.0/24'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['failure_observations'], 1)
        self.assertEqual(data['events'][0]['source_status'], 'relay_address')
        self.assertEqual(sample.read_bytes(), before)

    def test_fifo_missing_and_large_file_errors_are_bounded(self):
        for filename in ('missing', 'fifo', 'large'):
            target = self.base/filename
            if filename == 'fifo':
                os.mkfifo(target)
            elif filename == 'large':
                target.write_bytes(b'a'*(1024*1024+1))
            result = subprocess.run([sys.executable, str(HELPER), '--file', str(target), '--core', 'sing'],
                                    text=True, capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(str(target), result.stdout+result.stderr)

    def test_events_only_exports_failures_and_keeps_observation_flag(self):
        sample = self.base/'sample.log'
        sample.write_text(STAMP+' from 198.51.100.7:123 rejected  proxy/vless/encoding: invalid request user id\n'
                          +STAMP+' from 198.51.100.7:123 accepted tcp:TARGET_SECRET:443\n')
        result = subprocess.run([sys.executable, str(HELPER), '--file', str(sample), '--core', 'xray',
                                 '--timezone', '+00:00', '--events-only'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]['observation_only'])
        self.assertNotIn('TARGET_SECRET', result.stdout+result.stderr)


class LogCheckRouting(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_cli_and_menu_are_read_only(self):
        overrides = 'check_v2bx_logs() { record LOGCHECK; return 2; }; locked_operation() { record LOCK; return 99; }'
        result = self.run_shell('main --v2bx-log-check', overrides=overrides)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.commands(), 'LOGCHECK\n')
        self.trace.write_text('')
        result = self.run_shell('manage_diagnostics', '13\n0\n', overrides=overrides)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.commands(), 'LOGCHECK\n')

    def test_observation_cli_does_not_use_production_mutation_lock(self):
        result = self.run_shell('main --v2bx-observe', overrides='observe_v2bx_logs() { record OBSERVE; return 2; }; locked_operation() { record LOCK; return 99; }')
        self.assertEqual(result.returncode,2)
        self.assertEqual(self.commands(),'OBSERVE\n')

    def test_cancel_or_eof_does_not_read_logs_or_mutate(self):
        result = self.run_shell('check_v2bx_logs', 'q\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands(), '')
        self.assertEqual(self.run_shell('check_v2bx_logs').returncode, 0)


if __name__ == '__main__':
    unittest.main()

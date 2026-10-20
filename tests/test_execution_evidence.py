"""Real file input: refuse forged/mismatched receipts and bound reads."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def receipt(**changes):
    data = dict(v=1, ip='192.0.2.10', status=403, cause='lapi_ban', time=1000,
                upstream='', request_id='a'*32)
    data.update(changes)
    return ('2026/10/19 21:08:08 [error] 12#12: *2 [lua] execution.lua:22: emit(): CB_EXEC_V1 '+
            json.dumps(data)+' while logging request, client: 192.0.2.10, server: example\n')


class ExecutionEvidence(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT/'lib/crowdsec_execution.py').is_file(), 'execution evidence reader is missing')
        spec = importlib.util.spec_from_file_location('execution', ROOT/'lib/crowdsec_execution.py')
        self.reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.reader)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.log = self.dir/'proxy-host-1_error.log'

    def query(self, **kwargs):
        return self.reader.query([str(self.dir)], '192.0.2.10', 950, now=1100, **kwargs)

    def test_real_receipts_deduplicate_and_filter_ip_and_time(self):
        self.log.write_text(receipt()+receipt()+receipt(request_id='b'*32, cause='appsec_rule')+
                            receipt(ip='192.0.2.11')+receipt(time=949)+receipt(time=1101))
        result = self.query()
        self.assertEqual(result['state'], 'observed')
        self.assertEqual(result['count'], 2)
        self.assertEqual(set(result['causes']), {'lapi_ban', 'appsec_rule'})

    def test_business_status_and_embedded_forgery_are_not_evidence(self):
        self.log.write_text('request: "'+receipt()+'"\n'+receipt(upstream='127.0.0.1:8000')+
                            receipt(status=200)+receipt(request_id='client-forged')+receipt(v=True)+
                            receipt(cause='unknown')+receipt(status=True))
        self.assertEqual(self.query()['state'], 'empty')

    def test_missing_or_symlink_logs_are_unavailable_not_empty(self):
        self.assertEqual(self.query()['state'], 'unavailable')
        target = self.dir/'secret.txt'; target.write_text(receipt())
        self.log.symlink_to(target)
        self.assertEqual(self.query()['state'], 'unavailable')

    def test_tail_read_is_bounded_and_reports_sampling(self):
        self.log.write_text(receipt(time=960)+'x'*90000+'\n'+receipt(time=1010, request_id='b'*32))
        result = self.query()
        self.assertEqual(result['count'], 1)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(result['bytes_read'], 65536)

    def test_rotation_and_unterminated_partial_lines(self):
        (self.dir/'proxy-host-1_error.log.1').write_text(receipt())
        self.log.write_text(receipt(request_id='b'*32).rstrip('\n'))
        self.assertEqual(self.query()['count'], 1)

    def test_generic_nginx_error_log_name_is_read(self):
        (self.dir/'error.log').write_text(receipt())
        self.assertEqual(self.query()['state'], 'observed')

    def test_truncated_files_are_separate_from_read_errors_and_scan_limits(self):
        self.log.write_text('x'*70000+'\n'+receipt())
        result = self.reader.query([str(self.dir), str(self.dir/'missing')], '192.0.2.10', 950, now=1100)
        self.assertEqual(result.get('truncated_files'), 1)
        self.assertEqual(result['errors'], 1)
        self.assertFalse(result.get('scan_limited', True))
        for n in range(130):
            (self.dir/f'proxy-{n}_error.log').write_text('')
        result = self.query()
        self.assertTrue(result.get('scan_limited'))
        self.assertEqual(result['logs_read'], 128)

    def firewall(self, replies, config=None, ip='192.0.2.10'):
        config = config if config is not None else {'mode': 'nftables', 'nftables': {'ipv4': {'enabled': True}}}
        def run(args, **kwargs):
            self.assertIn(args[1], ('-j', 'get'))
            self.assertEqual(args[0], 'nft')
            if args[1] == 'get':
                self.assertEqual(args[2], 'element')
                self.assertEqual(args[-3:], ['{', str(__import__('ipaddress').ip_address(ip)), '}'])
            else:
                self.assertEqual(args[2:5], ['-t', 'list', 'table'])
            self.assertGreater(kwargs['timeout'], 0)
            self.assertLessEqual(kwargs['timeout'], 5)
            self.assertFalse(kwargs.get('shell', False))
            value = next(outputs)
            if isinstance(value, Exception):
                raise value
            return subprocess.CompletedProcess(args, *value)
        outputs = iter(replies)
        with patch.object(self.reader, 'subprocess', create=True) as process:
            process.run.side_effect = run
            process.TimeoutExpired = subprocess.TimeoutExpired
            return self.reader.firewall_membership(config, ip)

    def metadata(self, family='ip', table='crowdsec', name='crowdsec-blacklists-crowdsec', kind='ipv4_addr', table_handle=1, set_handle=2):
        return (0, json.dumps({'nftables': [
            {'table': {'family': family, 'name': table, 'handle': table_handle}},
            {'set': {'family': family, 'table': table, 'name': name, 'type': kind, 'handle': set_handle}}]}), '')

    def test_firewall_membership_uses_configured_sets_and_real_text_reply(self):
        config = {'mode': 'nftables', 'blacklists_ipv6': ['custom'], 'nftables': {'ipv6': {'enabled': True, 'table': 'custom6'}}}
        reply = 'table ip6 custom6 { set custom-cscli { elements = { 2001:db8::1 timeout 4h expires 3h } } }'
        result = self.firewall([self.metadata('ip6', 'custom6', 'custom-cscli', 'ipv6_addr'), (0, reply, '')], config, '2001:db8::1')
        self.assertEqual(result['state'], 'present')
        self.assertEqual(result['sets'], ['custom-cscli'])

    def test_firewall_absence_requires_successful_metadata_and_all_lookups(self):
        missing = (1, '', 'Error: Could not process rule: No such file or directory\nget element ip crowdsec crowdsec-blacklists-crowdsec { 192.0.2.10 }')
        result = self.firewall([self.metadata(), missing, self.metadata()])
        self.assertEqual(result['state'], 'absent')
        result = self.firewall([self.metadata(), missing, (1, '', 'Operation not permitted')])
        self.assertEqual(result['state'], 'unavailable')

    def test_recreated_table_or_set_cannot_produce_negative_evidence(self):
        missing = (1, '', 'Error: Could not process rule: No such file or directory')
        for table_handle, set_handle in [(1, 3), (2, 2), (None, 2), (1, None)]:
            with self.subTest(table_handle=table_handle, set_handle=set_handle):
                result = self.firewall([self.metadata(), missing,
                    self.metadata(table_handle=table_handle, set_handle=set_handle)])
                self.assertEqual(result['state'], 'unavailable')
        without_identity = self.metadata(table_handle=None, set_handle=None)
        self.assertEqual(self.firewall([without_identity, missing, without_identity])['state'], 'unavailable')

    def test_firewall_errors_never_become_negative_evidence(self):
        for reply in [(1, '', 'Operation not permitted'), (0, 'not json', ''), subprocess.TimeoutExpired('nft', 5)]:
            with self.subTest(reply=reply):
                self.assertEqual(self.firewall([reply])['state'], 'unavailable')
        self.assertEqual(self.firewall([self.metadata(), (0, '', '')])['state'], 'unavailable')
        self.assertEqual(self.firewall([self.metadata(), (1, '', 'Permission denied')])['state'], 'unavailable')
        self.assertEqual(self.firewall([(0, '{"nftables": []}', '')])['state'], 'unavailable')

    def test_set_only_ignores_unrelated_origin_named_sets(self):
        config = {'mode': 'nftables', 'blacklists_ipv4': 'deny4',
                  'nftables': {'ipv4': {'table': 'shared', 'set-only': True}}}
        metadata = json.dumps({'nftables': [
            {'table': {'family': 'ip', 'name': 'shared', 'handle': 1}},
            {'set': {'family': 'ip', 'table': 'shared', 'name': 'deny4', 'type': 'ipv4_addr', 'handle': 2}},
            {'set': {'family': 'ip', 'table': 'shared', 'name': 'deny4-unrelated', 'type': 'ipv4_addr', 'handle': 3}}]})
        def run(args, **kwargs):
            if args[1] == '-j':
                return subprocess.CompletedProcess(args, 0, metadata, '')
            if args[5] == 'deny4':
                return subprocess.CompletedProcess(args, 1, '', 'Error: Could not process rule: No such file or directory')
            return subprocess.CompletedProcess(args, 0, 'elements = { 192.0.2.10 timeout 4h }', '')
        with patch.object(self.reader.subprocess, 'run', side_effect=run):
            result = self.reader.firewall_membership(config, '192.0.2.10')
        self.assertEqual(result['state'], 'absent')
        self.assertEqual(result['sets'], ['deny4'])

    def test_set_only_can_find_the_exact_configured_set(self):
        config = {'mode': 'nftables', 'blacklists_ipv4': 'deny4',
                  'nftables': {'ipv4': {'table': 'shared', 'set-only': True}}}
        result = self.firewall([self.metadata('ip', 'shared', 'deny4'),
                               (0, 'elements = { 192.0.2.10 timeout 4h }', '')], config)
        self.assertEqual(result['state'], 'present')
        self.assertEqual(result['sets'], ['deny4'])

    def test_managed_mode_ignores_unused_exact_name(self):
        config = {'mode': 'nftables', 'blacklists_ipv4': 'deny4',
                  'nftables': {'ipv4': {'table': 'shared', 'set-only': False}}}
        result = self.firewall([self.metadata('ip', 'shared', 'deny4'),
                               (0, 'elements = { 192.0.2.10 timeout 4h }', '')], config)
        self.assertEqual(result['state'], 'unavailable')

    def test_empty_optional_names_use_official_defaults(self):
        for family, nft_family, table, prefix, kind, ip in [
                ('ipv4', 'ip', 'crowdsec', 'crowdsec-blacklists', 'ipv4_addr', '192.0.2.10'),
                ('ipv6', 'ip6', 'crowdsec6', 'crowdsec6-blacklists', 'ipv6_addr', '2001:db8::1')]:
            for empty in ['', None]:
                with self.subTest(family=family, empty=empty):
                    config = {'mode': 'nftables', 'blacklists_'+family: empty,
                              'nftables': {family: {'table': empty}}}
                    result = self.firewall([self.metadata(nft_family, table, prefix+'-crowdsec', kind),
                                           (0, 'elements = { '+ip+' timeout 4h }', '')], config, ip)
                    self.assertEqual(result['state'], 'present')

    def test_scoped_ipv6_is_rejected_before_nft_parser(self):
        with patch.object(self.reader.subprocess, 'run') as run:
            result = self.reader.firewall_membership({'mode': 'nftables'}, 'fe80::1%eth0 }; flush ruleset; #')
            self.assertEqual(result['state'], 'unavailable')
            self.assertEqual(run.call_count, 0)

    def test_globally_disabled_ipv6_is_not_queried(self):
        with patch.object(self.reader.subprocess, 'run') as run:
            result = self.reader.firewall_membership({'mode': 'nftables', 'disable_ipv6': True}, '2001:db8::1')
            self.assertEqual(result['state'], 'unsupported')
            self.assertEqual(run.call_count, 0)

    def test_disabled_ipv4_defaults_to_not_queried(self):
        with patch.object(self.reader.subprocess, 'run') as run:
            result = self.reader.firewall_membership({'mode': 'nftables', 'disable_ipv4': True}, '192.0.2.10')
            self.assertEqual(result['state'], 'unsupported')
            self.assertEqual(run.call_count, 0)

    def test_explicit_family_enabled_overrides_global_disable(self):
        for family, nft_family, table, prefix, kind, ip in [
                ('ipv4', 'ip', 'crowdsec', 'crowdsec-blacklists', 'ipv4_addr', '192.0.2.10'),
                ('ipv6', 'ip6', 'crowdsec6', 'crowdsec6-blacklists', 'ipv6_addr', '2001:db8::1')]:
            with self.subTest(family=family):
                config = {'mode': 'nftables', 'disable_'+family: True,
                          'nftables': {family: {'enabled': True}}}
                result = self.firewall([self.metadata(nft_family, table, prefix+'-crowdsec', kind),
                                       (0, 'elements = { '+ip+' timeout 4h }', '')], config, ip)
                self.assertEqual(result['state'], 'present')

    def test_firewall_unsupported_or_bad_config_does_not_run_commands(self):
        for config, state in [({}, 'unavailable'), ({'mode': 'iptables'}, 'unsupported'),
                              ({'mode': 'nftables', 'nftables': {'ipv4': {'enabled': False}}}, 'unsupported'),
                              ({'mode': 'nftables', 'nftables': {'ipv4': {'table': '-bad'}}}, 'unavailable')]:
            with self.subTest(config=config):
                with patch.object(self.reader, 'subprocess', create=True) as process:
                    result = self.reader.firewall_membership(config, '192.0.2.10')
                    self.assertEqual(result['state'], state)
                    process.run.assert_not_called()

    def test_window_is_clamped_to_24_hours(self):
        self.log.write_text(receipt(time=1000))
        result = self.reader.query([str(self.dir)], '192.0.2.10', 0, now=90000)
        self.assertEqual(result['state'], 'empty')
        self.assertEqual(result['since'], 3600)


if __name__ == '__main__':
    unittest.main()

"""Exercise diagnostic output and read-only boundaries using local fixtures."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import test_workflows

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'lib/crowdsec_v2bx.py'


class V2bXDiagnosis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.config = self.base / 'config.json'
        self.cs = self.base / 'crowdsec'
        self.cs.mkdir()
        self.acquis = self.cs / 'acquis.d'
        self.acquis.mkdir()
        (self.cs / 'config.yaml').write_text(
            'crowdsec_service:\n  acquisition_dir: '+str(self.acquis)+'\n')
        self.trace = self.base / 'trace'
        self.trace.touch()
        self.command('systemctl', 'LoadState=loaded\nActiveState=active\nMainPID=0\nWorkingDirectory=/\n')
        self.command('ss', 'tcp LISTEN 0 128 [::]:443 [::]:* users:(("V2bX",pid=123,fd=6))\n'
                     'udp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:(("OTHER_SECRET",pid=456,fd=7))\n')
        self.command('journalctl', 'V2bX v0.4.1 (A V2board backend based on multi core)\n')

    def command(self, name, output, code=0):
        target = self.bin / name
        target.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> '+shlex.quote(str(self.trace))+
                          '\nprintf "%s\\n" '+shlex.quote(output)+'\nexit '+str(code)+'\n')
        target.chmod(0o755)

    def write_config(self, nodes=None, cores=None):
        self.config.write_text(json.dumps({
            'Log': {'Level': 'info'},
            'Cores': cores if cores is not None else [
                {'Type': 'xray', 'Log': {'Level': 'warning'}},
                {'Type': 'sing', 'Log': {'Level': 'error'}},
                {'Type': 'hysteria2', 'Log': {'Level': 'error'}}],
            'Nodes': nodes if nodes is not None else [
                {'Core': 'xray', 'NodeType': 'vless', 'NodeID': 12, 'ApiKey': 'API_SECRET'},
                {'ApiConfig': {'NodeType': 'shadowsocks', 'NodeID': 13},
                 'Options': {'Core': 'sing', 'ListenIP': '::'}},
                {'Core': 'hysteria2', 'NodeType': 'hysteria2', 'NodeID': 14}]}))

    def run_helper(self, *args):
        self.assertTrue(HELPER.exists(), 'V2bX diagnostic helper is not implemented')
        return subprocess.run([sys.executable, str(HELPER), '--config', str(self.config),
                               '--cs-dir', str(self.cs), '--json', *args],
                              env={**os.environ, 'PATH': str(self.bin)},
                              text=True, capture_output=True, timeout=10)

    def report(self, *args):
        result = self.run_helper(*args)
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        return json.loads(result.stdout)

    def test_three_cores_nested_config_and_panel_fields_remain_unverified(self):
        self.write_config()
        data = self.report()
        self.assertEqual([n['core'] for n in data['nodes']], ['xray', 'sing', 'hysteria2'])
        self.assertEqual([n['protocol'] for n in data['nodes']], ['vless', 'shadowsocks', 'hysteria2'])
        self.assertEqual(data['nodes'][1]['listen_ip'], '::')
        self.assertEqual(data['nodes'][0]['port_status'], 'panel_or_runtime_required')
        self.assertEqual(data['nodes'][0]['source_status'], 'unverified')
        self.assertEqual(data['runtime']['version'], 'v0.4.1')
        self.assertEqual(data['sockets'][0]['address'], '::')
        self.assertFalse(data['sockets'][0]['service_pid_match'])

    def test_secrets_never_echo_from_allowlisted_fields_or_logs(self):
        log = self.base / 'API_SECRET.log'
        log.write_text(json.dumps({'msg': 'client connected', 'addr': '[2001:db8::1]:5678',
                                   'uuid': 'UUID_SECRET', 'reqAddr': 'TARGET_SECRET'})+'\n'
                       'authentication failed API_SECRET UUID_SECRET\n'
                       'timeout PRIVATE_KEY_SECRET\n')
        self.write_config(nodes=[{'Core': 'xray', 'NodeType': 'PROTOCOL_SECRET',
                                 'ListenIP': 'ADDRESS_SECRET', 'NodeID': 'NODE_SECRET',
                                 'Name': 'NAME_SECRET', 'SpeedLimit': 'RATE_SECRET'}],
                          cores=[{'Type': 'xray', 'Name': 'CORE_SECRET',
                                  'Log': {'Level': 'LEVEL_SECRET', 'ErrorPath': str(log)}}])
        data = self.report()
        output = json.dumps(data)
        for secret in ('API_SECRET', 'UUID_SECRET', 'TARGET_SECRET', 'PRIVATE_KEY_SECRET',
                       'PROTOCOL_SECRET', 'ADDRESS_SECRET', 'NODE_SECRET', 'NAME_SECRET',
                       'CORE_SECRET', 'LEVEL_SECRET', 'RATE_SECRET', 'OTHER_SECRET'):
            self.assertNotIn(secret, output)
        sample = data['logs'][2]['sample']
        self.assertEqual(sample['connected'], 1)
        self.assertEqual(sample['source_present'], 1)
        self.assertEqual(sample['failure_candidates'], 1)
        self.assertEqual(sample['ordinary_errors'], 1)
        self.assertEqual(data['logs'][2]['detection_status'], 'unverified')

    def test_json_comments_trailing_commas_do_not_break_urls(self):
        self.config.write_text('''{
          // comment
          "Cores": [{"Type":"sing",}],
          "Nodes": [{"Core":"sing", "NodeType":"trojan", "ApiHost":"https://panel.invalid/a//b",}],
          /* block */ "Log": {"Level":"info",},
        }''')
        data = self.report()
        self.assertEqual(data['nodes'][0]['protocol'], 'trojan')

    def test_local_include_and_remote_include_never_fetch_network(self):
        include = self.base / 'node.json'
        include.write_text('{"ApiConfig":{"NodeType":"vmess"},"Options":{"Core":"xray"}}')
        self.write_config(nodes=[{'Include': str(include)}, {'Include': 'https://API_SECRET.invalid/node'}])
        data = self.report()
        self.assertEqual(data['nodes'][0]['protocol'], 'vmess')
        self.assertEqual(data['nodes'][1]['config_status'], 'remote_include_not_read')
        self.assertIsNone(data['nodes'][1]['listen_ip'])
        self.assertNotIn('API_SECRET', json.dumps(data))

    def test_custom_core_name_resolves_without_exposing_name(self):
        self.write_config(cores=[{'Type': 'sing', 'Name': 'CORE_SECRET'}],
                          nodes=[{'CoreName': 'CORE_SECRET', 'NodeType': 'trojan'}])
        data = self.report()
        self.assertEqual(data['nodes'][0]['core'], 'sing')
        self.assertNotIn('CORE_SECRET', json.dumps(data))

    def test_automatic_core_selection_is_not_guessed(self):
        self.write_config(nodes=[{'NodeType': 'trojan'}])
        self.assertEqual(self.report()['nodes'][0]['core'], 'unknown')

    def test_entry_declarations_do_not_promote_trust(self):
        self.write_config(nodes=[{'Core': 'xray', 'NodeType': 'vless', 'EnableProxyProtocol': True},
                                 {'Core': 'sing', 'NodeType': 'trojan'},
                                 {'Core': 'hysteria2', 'NodeType': 'hysteria2'}])
        data = self.report('--entries', '1:relay-proxy,2:direct,3:mixed')
        self.assertTrue(data['nodes'][0]['proxy_protocol_declared'])
        self.assertEqual(data['nodes'][0]['enforcement'], 'relay_if_trusted_source_verified')
        self.assertEqual(data['nodes'][1]['enforcement'], 'landing_if_packet_source_verified')
        self.assertEqual(data['nodes'][2]['enforcement'], 'per_path_verification_required')
        self.assertTrue(all(n['source_status'] == 'unverified' for n in data['nodes']))

    def test_file_acquisition_local_override_and_duplicates(self):
        log = self.base / 'error.log'
        log.write_text('normal network timeout\n')
        alt = self.cs / 'custom-acquis'
        alt.mkdir()
        (self.cs / 'config.yaml.local').write_text('crowdsec_service:\n  acquisition_dir: '+str(alt)+'\n')
        (alt / 'a.yaml').write_text('filenames:\n - '+str(self.base / '*.log')+'\nlabels:\n type: SECRET_LABEL\n')
        (alt / 'b.yaml').write_text('filename: '+str(log)+'\nlabels:\n type: v2bx\n')
        self.write_config(cores=[{'Type': 'xray', 'Log': {'ErrorPath': str(log)}}])
        data = self.report()
        self.assertEqual(data['logs'][2]['acquisition_matches'], 2)
        self.assertEqual(data['logs'][2]['acquisition_status'], 'duplicate_possible')
        self.assertNotIn('SECRET_LABEL', json.dumps(data))

    def test_broad_and_constrained_journal_sources_are_not_full_coverage(self):
        self.write_config()
        (self.acquis / 'a.yaml').write_text('source: journalctl\njournalctl_filter: []\nlabels:\n type: syslog\n')
        (self.acquis / 'b.yaml').write_text('source: journalctl\njournalctl_filter:\n - _SYSTEMD_UNIT=V2bX.service\n - PRIORITY=3\n')
        data = self.report()
        self.assertEqual(data['logs'][0]['acquisition_status'], 'overlap_or_constrained')
        self.assertEqual(data['logs'][0]['acquisition_matches'], 2)

    def test_missing_logs_and_fifo_are_not_read_or_called_healthy(self):
        fifo = self.base / 'fifo'
        os.mkfifo(fifo)
        self.write_config(cores=[{'Type': 'xray', 'Log': {
            'ErrorPath': str(self.base/'missing.log'), 'AccessPath': str(fifo)}}])
        logs = self.report()['logs']
        self.assertEqual(logs[1]['read_status'], 'not_regular')
        self.assertEqual(logs[2]['read_status'], 'missing')

    def test_missing_tools_and_config_have_distinct_safe_statuses(self):
        self.write_config()
        for target in self.bin.iterdir():
            target.unlink()
        data = self.report()
        self.assertEqual(data['runtime']['service_status'], 'tool_missing')
        self.assertEqual(data['socket_status'], 'tool_missing')
        self.config.unlink()
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['config_status'], 'missing')

    def test_malformed_input_never_echoes_raw_error(self):
        for text in ('API_SECRET not json', '{"Nodes":"UUID_SECRET"}', '{"Cores":["PRIVATE_SECRET"]}'):
            with self.subTest(text=text):
                self.config.write_text(text)
                result = self.run_helper()
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('SECRET', result.stdout+result.stderr)

    def test_invalid_selectors_do_not_execute_commands(self):
        self.write_config()
        for entries in ('0:direct', '999:direct', '1:SECRET', '1:direct,1:mixed'):
            result = self.run_helper('--entries', entries)
            self.assertEqual(result.returncode, 1)
        self.assertEqual(self.trace.read_text(), '')

    def test_config_log_and_acquisition_files_unchanged_and_commands_read_only(self):
        self.write_config()
        before = {p: p.read_bytes() for p in self.base.rglob('*') if p.is_file() and p != self.trace}
        self.report()
        after = {p: p.read_bytes() for p in self.base.rglob('*') if p.is_file() and p != self.trace}
        self.assertEqual(before, after)
        commands = self.trace.read_text().splitlines()
        self.assertTrue(any(c.startswith('show ') for c in commands))
        self.assertTrue(any(c.startswith('-H -lntup') for c in commands))
        self.assertTrue(any(c.startswith('--unit=V2bX.service ') for c in commands))
        self.assertFalse(any(word in self.trace.read_text() for word in ('restart', 'reload', 'decisions', 'curl')))

    def test_empty_access_path_is_disabled_not_a_journal_source(self):
        self.write_config(cores=[{'Type': 'xray', 'Log': {'AccessPath': ''}}])
        data = self.report()
        self.assertEqual(data['logs'][1]['source'], 'disabled')
        self.assertEqual(data['logs'][1]['sample']['lines'], 0)

    def test_disabled_sing_logging_is_reported(self):
        self.write_config(cores=[{'Type': 'sing', 'Log': {'Disable': True, 'Output': ''}}])
        data = self.report()
        self.assertTrue(data['cores'][0]['logging_disabled_declared'])
        self.assertEqual(data['logs'][1]['source'], 'disabled')

    def test_relative_include_requires_actual_working_directory(self):
        include = self.base / 'included.json'
        include.write_text('{"Core":"sing","NodeType":"trojan"}')
        self.write_config(nodes=[{'Include': 'included.json'}])
        self.command('systemctl', 'LoadState=loaded\nActiveState=active\nMainPID=0\n')
        data = self.report()
        self.assertEqual(data['nodes'][0]['config_status'], 'relative_include_unresolved')
        data = self.report('--working-dir', str(self.base))
        self.assertEqual(data['nodes'][0]['protocol'], 'trojan')

    def test_failed_local_queries_do_not_echo_errors_or_look_successful(self):
        self.write_config()
        self.command('ss', 'UUID_SECRET permission denied', 1)
        result = self.run_helper()
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertEqual(data['socket_status'], 'read_failed')
        self.assertNotIn('UUID_SECRET', result.stdout+result.stderr)

    def test_scoped_ipv6_never_echoes_arbitrary_scope_strings(self):
        self.write_config(nodes=[{'Core': 'sing', 'NodeType': 'trojan',
                                 'ListenIP': 'fe80::1%API_SECRET'}])
        self.command('ss', 'tcp LISTEN 0 128 [fe80::1%UUID_SECRET]:443 [::]:*\n')
        data = self.report()
        self.assertIsNone(data['nodes'][0]['listen_ip'])
        self.assertNotIn('SECRET', json.dumps(data))

    def test_non_xray_proxy_flag_is_a_declaration_not_a_support_claim(self):
        self.write_config(nodes=[{'Core': 'sing', 'NodeType': 'trojan',
                                 'EnableProxyProtocol': True}])
        data = self.report()
        self.assertTrue(data['nodes'][0]['proxy_protocol_declared'])
        self.assertEqual(data['nodes'][0]['proxy_protocol_support_status'], 'version_and_transport_required')
        self.assertEqual(data['nodes'][0]['source_status'], 'unverified')

    def test_hysteria2_ignored_output_field_is_not_read_as_core_log(self):
        log = self.base / 'ignored.log'
        log.write_text('authentication failed UUID_SECRET\n')
        self.write_config(cores=[{'Type': 'hysteria2', 'Log': {'Output': str(log)}}])
        data = self.report()
        self.assertEqual(data['logs'][1]['source'], 'journal_candidate')
        self.assertEqual(data['logs'][1]['sample']['failure_candidates'], 0)

    def test_reuses_bouncer_input_forward_evidence_without_claiming_blocking(self):
        self.write_config()
        bouncers = self.cs / 'bouncers'
        bouncers.mkdir()
        (bouncers/'crowdsec-firewall-bouncer.yaml').write_text('mode: iptables\n')
        self.command('ipset', 'crowdsec-blacklists\n')
        self.command('iptables', '-A INPUT -m set --match-set crowdsec-blacklists src -j DROP\n')
        self.command('ip6tables', '')
        data = self.report()
        self.assertTrue(data['bouncer_references']['ipv4']['INPUT'])
        self.assertFalse(data['bouncer_references']['ipv4']['FORWARD'])
        self.assertEqual(data['end_to_end_status'], 'unverified')

    def test_nonregular_crowdsec_config_cannot_block_diagnosis(self):
        self.write_config()
        config = self.cs / 'config.yaml'
        config.unlink()
        os.mkfifo(config)
        data = self.report()
        self.assertEqual(data['acquisition_status'], 'read_failed')


class V2bXRouting(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_cli_bypasses_lock_and_propagates_unverified(self):
        result = self.run_shell('main --diagnose-v2bx', overrides=
                               'diagnose_v2bx() { record V2BX; return 2; }; '
                               'locked_operation() { record LOCK; return 99; }')
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertEqual(self.commands(), 'V2BX\n')

    def test_menu_routes_without_lock_and_eof_exits(self):
        result = self.run_shell('manage_diagnostics', '12\n0\n', overrides=
                               'diagnose_v2bx() { record V2BX; }; locked_operation() { record LOCK; return 99; }')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.commands(), 'V2BX\n')
        self.assertEqual(self.run_shell('manage_diagnostics').returncode, 0)


if __name__ == '__main__':
    unittest.main()

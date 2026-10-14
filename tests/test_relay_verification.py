"""Guided acceptance uses explicit external observations and read-only fixtures."""
import contextlib
import copy
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_workflows

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))


def fixture(source=False, packets=10, family='ip', hook='input', origin='cscli'):
    address = '1.1.1.1' if family == 'ip' else '2606:4700:4700::1111'
    table = 'crowdsec' if family == 'ip' else 'crowdsec6'
    name = ('crowdsec-blacklists' if family == 'ip' else 'crowdsec6-blacklists') + '-' + origin
    return {'nftables': [
        {'set': {'family': family, 'table': table, 'name': name,
                 'elem': [{'elem': {'val': address}}] if source else []}},
        {'chain': {'family': family, 'table': table, 'name': 'ban', 'hook': hook}},
        {'counter': {'family': family, 'table': table, 'name': name, 'packets': packets}},
        {'rule': {'family': family, 'table': table, 'chain': 'ban', 'handle': 9,
                  'expr': [{'match': {'op': '==', 'left': {'payload': {'protocol': family, 'field': 'saddr'}},
                                     'right': '@'+name}}, {'counter': name}, {'drop': None}]}}]}


class RelayVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = importlib.import_module('crowdbastion_relay_verify')

    def evidence(self, **options):
        family = options.get('family', 'ip')
        return self.tool.nft_evidence(fixture(**options), family,
                                     'crowdsec' if family == 'ip' else 'crowdsec6',
                                     {'crowdsec-blacklists' if family == 'ip' else 'crowdsec6-blacklists'},
                                     options.get('hook', 'input'),
                                     '1.1.1.1' if family == 'ip' else '2606:4700:4700::1111')

    def run_wizard(self, answers=None, snapshots=None, remote=False):
        inputs = iter(answers or [
            '9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y',
            '1', '1', 'y', '2', '1', 'y', '1', '1'])
        reads = iter(snapshots or [self.evidence(), self.evidence(source=True),
                                  self.evidence(source=True, packets=14), self.evidence(packets=14)])
        output = io.StringIO()
        def ask(prompt):
            output.write(prompt+'\n')
            try:
                return next(inputs)
            except StopIteration:
                raise EOFError from None
        with contextlib.redirect_stdout(output):
            status = self.tool.verify('/unused', remote=remote, ask=ask,
                                      snapshot=lambda scope: next(reads),
                                      env={'SSH_CONNECTION': '4.2.2.2 1234 9.9.9.9 22'})
        return status, output.getvalue()

    def test_complete_acceptance_has_one_scoped_manual_conclusion(self):
        code, text = self.run_wizard()
        self.assertEqual(code, 0, text)
        self.assertEqual(text.count('验收结论：'), 1)
        self.assertIn('本次入口验证通过（人工确认）', text)
        self.assertIn('9.9.9.9:8443', text)
        self.assertIn('TCP / IPv4 / INPUT', text)
        self.assertIn('外部连接结果由操作者确认', text)
        self.assertIn('--duration 2m', text)
        self.assertNotIn('全节点防护通过', text)
        self.assertNotIn('decisions delete --ip', text)

    def test_reachable_banned_source_is_a_failure_even_if_counter_increases(self):
        answers = ['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y',
                   '1', '1', 'y', '1', '1', 'y', '1', '1']
        code, text = self.run_wizard(answers)
        self.assertEqual(code, 1, text)
        self.assertIn('本次入口验证未通过', text)
        self.assertIn('测试来源仍能建立新连接', text)

    def test_control_failure_prevents_pass(self):
        answers = ['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y',
                   '1', '1', 'y', '2', '2', 'y', '1', '1']
        code, text = self.run_wizard(answers)
        self.assertEqual(code, 1, text)
        self.assertIn('正常对照来源也无法连接', text)

    def test_missing_rule_counter_growth_is_incomplete(self):
        code, text = self.run_wizard(snapshots=[self.evidence(), self.evidence(source=True),
                                              self.evidence(source=True), self.evidence()])
        self.assertEqual(code, 2, text)
        self.assertIn('验证未完成', text)
        self.assertIn('计数', text)

    def test_rule_counter_reset_is_not_growth(self):
        code, text = self.run_wizard(snapshots=[self.evidence(), self.evidence(source=True, packets=20),
                                              self.evidence(source=True, packets=2), self.evidence(packets=2)])
        self.assertEqual(code, 2, text)

    def test_missing_post_ban_membership_does_not_request_blocked_test(self):
        code, text = self.run_wizard(snapshots=[self.evidence(), self.evidence()])
        self.assertEqual(code, 2, text)
        self.assertIn('尚未同步', text)
        self.assertIn('2 分钟', text)
        self.assertNotIn('本次入口验证通过', text)

    def test_expiry_during_blocked_test_is_incomplete(self):
        code, text = self.run_wizard(snapshots=[self.evidence(), self.evidence(source=True),
                                              self.evidence(packets=14), self.evidence(packets=14)])
        self.assertEqual(code, 2, text)
        self.assertIn('验证未完成', text)

    def test_initial_ban_is_not_overwritten_or_treated_as_baseline(self):
        code, text = self.run_wizard(snapshots=[self.evidence(source=True)])
        self.assertEqual(code, 2, text)
        self.assertIn('已经在封禁集合', text)
        self.assertNotIn('decisions add', text)

    def test_recovery_failure_is_a_failure(self):
        answers = ['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y',
                   '1', '1', 'y', '2', '1', 'y', '2', '1']
        code, text = self.run_wizard(answers)
        self.assertEqual(code, 1, text)
        self.assertIn('测试来源未恢复连接', text)

    def test_pending_cleanup_cannot_pass(self):
        code, text = self.run_wizard(snapshots=[self.evidence(), self.evidence(source=True),
                                              self.evidence(source=True, packets=14), self.evidence(source=True, packets=14)])
        self.assertEqual(code, 2, text)
        self.assertIn('仍在封禁集合', text)

    def test_missing_firewall_after_cleanup_cannot_pass(self):
        absent = {'matched': False, 'present': False, 'rule_counters': {}, 'source_counters': {}}
        code, text = self.run_wizard(snapshots=[self.evidence(), self.evidence(source=True),
                                              self.evidence(source=True, packets=14), absent])
        self.assertEqual(code, 2, text)
        self.assertNotIn('本次入口验证通过', text)

    def test_cancel_after_ban_explains_expiry_and_preserves_failure_precedence(self):
        prefix = ['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y', '1', '1', 'y']
        code, text = self.run_wizard(prefix+['q'])
        self.assertEqual(code, 2, text)
        self.assertIn('2 分钟', text)
        code, text = self.run_wizard(prefix+['1', '1', 'q'])
        self.assertEqual(code, 1, text)
        self.assertIn('测试来源仍能建立新连接', text)

    def test_unknown_external_result_cannot_pass(self):
        answers = ['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y',
                   '1', '1', 'y', '0', '1', 'y', '1', '1']
        code, text = self.run_wizard(answers)
        self.assertEqual(code, 2, text)

    def test_management_shared_and_mismatched_sources_stop_before_ban(self):
        for source, control in [('4.2.2.2', '8.8.8.8'), ('1.1.1.1', '1.1.1.1'), ('1.1.1.1', '9.9.9.9'),
                                ('1.1.1.1', '2001:4860:4860::8888')]:
            with self.subTest(source=source, control=control):
                code, text = self.run_wizard(['9.9.9.9', '8443', '1', '1', source, control, '', 'y'])
                self.assertEqual(code, 2, text)
                self.assertNotIn('decisions add', text)

    def test_manual_admin_entry_cannot_override_detected_ssh_source(self):
        answers = ['9.9.9.9', '8443', '1', '1', '4.2.2.2', '8.8.8.8', '3.3.3.3', 'y',
                   '1', '1', 'y', '2', '1', 'y', '1', '1']
        code, text = self.run_wizard(answers)
        self.assertEqual(code, 2, text)
        self.assertNotIn('decisions add', text)

    def test_udp_demands_application_response_not_send_success(self):
        answers = ['9.9.9.9', '5353', '2', '2', '1.1.1.1', '8.8.8.8', '', 'y',
                   '1', '1', 'y', '2', '1', 'y', '1', '1']
        snapshots = [self.evidence(hook='forward'), self.evidence(source=True, hook='forward'),
                     self.evidence(source=True, packets=14, hook='forward'), self.evidence(packets=14, hook='forward')]
        code, text = self.run_wizard(answers, snapshots)
        self.assertEqual(code, 0, text)
        self.assertIn('应用响应', text)
        self.assertIn('UDP / IPv4 / FORWARD', text)

    def test_remote_mode_instructs_center_without_cscli_or_mutations(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('no commands in injected workflow')):
            code, text = self.run_wizard(remote=True)
        self.assertEqual(code, 0, text)
        self.assertIn('仅在远端检测中心执行', text)
        self.assertNotIn('API 密钥', text)

    def test_ipv6_origin_set_is_bound_to_correct_namespace_and_source(self):
        item = self.evidence(source=True, family='ip6', hook='forward', origin='CAPI')
        self.assertTrue(item['matched'])
        self.assertTrue(item['present'])
        self.assertTrue(item['source_counters'])
        data = fixture(source=True)
        data['nftables'][1]['chain']['hook'] = 'forward'
        item = self.tool.nft_evidence(data, 'ip', 'crowdsec', {'crowdsec-blacklists'}, 'input', '1.1.1.1')
        self.assertFalse(item['matched'])

    def test_foreign_negative_destination_and_accept_rules_cannot_supply_evidence(self):
        for mutation in ['other_table', 'negated', 'destination', 'accept', 'unknown_set']:
            with self.subTest(mutation=mutation):
                data = fixture(source=True)
                rule = data['nftables'][-1]['rule']
                if mutation == 'other_table':
                    rule['table'] = 'other'
                elif mutation == 'negated':
                    rule['expr'][0]['match']['op'] = '!='
                elif mutation == 'destination':
                    rule['expr'][0]['match']['left']['payload']['field'] = 'daddr'
                elif mutation == 'accept':
                    rule['expr'][-1] = {'accept': None}
                else:
                    rule['expr'][0]['match']['right'] = '@foreign'
                item = self.tool.nft_evidence(data, 'ip', 'crowdsec', {'crowdsec-blacklists'}, 'input', '1.1.1.1')
                self.assertFalse(item['matched'])
                self.assertFalse(item['source_counters'])

    def test_counter_must_follow_source_match_and_precede_final_verdict(self):
        for order in [(1, 0, 2), (0, 2, 1)]:
            data = fixture(source=True)
            expressions = data['nftables'][-1]['rule']['expr']
            data['nftables'][-1]['rule']['expr'] = [expressions[index] for index in order]
            item = self.tool.nft_evidence(data, 'ip', 'crowdsec', {'crowdsec-blacklists'}, 'input', '1.1.1.1')
            self.assertFalse(item['matched'])
            self.assertFalse(item['source_counters'])

    def test_extra_predicates_cannot_supply_unrelated_entry_counter_evidence(self):
        for extra in [
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': 53}},
                {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'eth1'}},
                {'ct': {'key': 'state'}}, {'limit': {'rate': 1, 'per': 'second'}}]:
            with self.subTest(extra=extra):
                data = fixture(source=True)
                data['nftables'][-1]['rule']['expr'].insert(1, extra)
                item = self.tool.nft_evidence(data, 'ip', 'crowdsec', {'crowdsec-blacklists'}, 'input', '1.1.1.1')
                self.assertFalse(item['matched'])
                self.assertFalse(item['source_counters'])

    def test_unrelated_counter_is_not_used_for_test_source(self):
        data = fixture(source=True)
        data['nftables'].extend(fixture(source=False, packets=999, origin='CAPI')['nftables'][::2])
        item = self.tool.nft_evidence(data, 'ip', 'crowdsec', {'crowdsec-blacklists'}, 'input', '1.1.1.1')
        self.assertEqual(list(item['source_counters'].values()), [10])

    def test_parse_errors_and_eof_produce_one_incomplete_conclusion(self):
        for answers in [['q'], ['not-an-ip'], ['9.9.9.9', '0'], ['9.9.9.9', '8443']]:
            with self.subTest(answers=answers):
                code, text = self.run_wizard(answers)
                self.assertEqual(code, 2, text)
                self.assertEqual(text.count('验收结论：'), 1)
                self.assertNotIn('decisions add', text)

    def test_interrupt_after_showing_ban_retains_recovery_instructions(self):
        answers = iter(['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y', '1', '1'])
        def ask(prompt):
            try:
                return next(answers)
            except StopIteration:
                raise KeyboardInterrupt from None
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = self.tool.verify('/unused', ask=ask, snapshot=lambda scope: self.evidence(),
                                    env={'SSH_CONNECTION': '4.2.2.2 1234 9.9.9.9 22'})
        self.assertEqual(code, 130)
        self.assertEqual(output.getvalue().count('验收结论：'), 1)
        self.assertIn('2 分钟', output.getvalue())
        self.assertIn('本次原因：crowdbastion-verify-', output.getvalue())

    def test_actual_config_and_nft_reads_are_read_only_in_remote_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'bouncers').mkdir()
            config = root/'bouncers/crowdsec-firewall-bouncer.yaml'
            config.write_text('mode: nftables\napi_key: secret-do-not-print\n')
            before = config.read_bytes()
            records = iter([fixture(), fixture(source=True), fixture(source=True, packets=14), fixture(packets=14)])
            commands = []
            def command(args, **kwargs):
                commands.append(args)
                return subprocess.CompletedProcess(args, 0, json.dumps(next(records)), '')
            inputs = iter(['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y', '1', '1', 'y', '2', '1', 'y', '1', '1'])
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch('subprocess.run', side_effect=command):
                code = self.tool.verify(root, remote=True, ask=lambda label: next(inputs),
                                        env={'SSH_CLIENT': '4.2.2.2 1234 22'})
            self.assertEqual(code, 0, output.getvalue())
            self.assertEqual(commands, [['nft', '-j', 'list', 'ruleset']]*4)
            self.assertEqual(config.read_bytes(), before)
            self.assertNotIn('secret-do-not-print', output.getvalue())

    def test_malformed_yaml_is_incomplete_without_exposing_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'bouncers').mkdir()
            (root/'bouncers/crowdsec-firewall-bouncer.yaml').write_text('mode: [nftables\napi_key: secret-do-not-print\n')
            inputs = iter(['9.9.9.9', '8443', '1', '1', '1.1.1.1', '8.8.8.8', '', 'y'])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = self.tool.verify(root, ask=lambda label: next(inputs), env={'SSH_CLIENT': '4.2.2.2 1234 22'})
            self.assertEqual(code, 2, output.getvalue())
            self.assertNotIn('secret-do-not-print', output.getvalue())
            self.assertNotIn('Traceback', output.getvalue())


class ShellVerification(unittest.TestCase):
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    setUp = test_workflows.Workflows.setUp

    def test_cli_is_read_only_and_preserves_incomplete_exit(self):
        run = self.run_shell('main --verify-relay', overrides='''
verify_relay() { record VERIFY; return 2; }
locked_operation() { record UNEXPECTED_LOCK; return 99; }
''')
        self.assertEqual(run.returncode, 2, run.stdout+run.stderr)
        self.assertIn('VERIFY', self.commands())
        self.assertNotIn('UNEXPECTED_LOCK', self.commands())

    def test_relay_menu_exposes_third_option(self):
        run = self.run_shell('manage_relay_diagnostics', '3\n0\n', overrides='verify_relay() { record VERIFY; return 2; }')
        self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
        self.assertIn('VERIFY', self.commands())
        self.assertIn('引导验证', run.stdout)

    def test_successful_install_keeps_success_even_when_postcheck_fails(self):
        run = self.run_shell('relay_after_install local', overrides='''
check_relay_status() { record CHECK "$@"; printf '检查结论：发现问题，需要处理\n'; return 1; }
verify_relay() { record UNEXPECTED_VERIFY; }
''')
        self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
        self.assertIn('CHECK', self.commands())
        self.assertIn('安装已完成', run.stdout)
        self.assertNotIn('UNEXPECTED_VERIFY', self.commands())

    def test_remote_after_install_selects_remote_check_without_cscli(self):
        run = self.run_shell('relay_after_install remote', overrides='''
check_relay_status() { record CHECK "$@"; return 2; }
cscli() { record UNEXPECTED_CSCLI; return 99; }
''')
        self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
        self.assertIn('CHECK summary remote', self.commands())
        self.assertNotIn('UNEXPECTED_CSCLI', self.commands())

    def test_wrapper_dispatches_remote_without_credentials_or_network(self):
        run = self.run_shell('verify_relay', 'q\n', overrides='''
load_node_roles() { NODE_ROLES=remote; }
python3() { record PYTHON "$@"; return 2; }
cscli() { record UNEXPECTED_CSCLI; return 99; }
''')
        self.assertEqual(run.returncode, 2, run.stdout+run.stderr)
        self.assertIn('--remote', self.commands())
        self.assertIn('crowdbastion_relay_verify.py', self.commands())
        self.assertNotIn('UNEXPECTED_CSCLI', self.commands())


if __name__ == '__main__':
    unittest.main()

"""Interactive declarations and routes; host effects stay in temporary fixtures."""
import json
import os
import subprocess
import unittest

import workflow_fixture as test_workflows
import test_node_guidance


class ProtocolNavigation(unittest.TestCase):
    setUp = test_workflows.WorkflowFixtureMixin.setUp
    run_shell = test_workflows.WorkflowFixtureMixin.run_shell
    commands = test_workflows.WorkflowFixtureMixin.commands
    run_terminal = test_node_guidance.Guidance.run_terminal

    def test_protocol_choices_use_actual_capabilities_without_writes(self):
        # program, protocol, transport, topology -> actual profile classification.
        cases = [
            ('2\n1\n4\n3\n', 'v2node', 'anytls', 'udp-over-tcp', 'tcp'),
            ('1\n2\n4\n2\n', 'v2bx', 'vmess', 'ws', 'tcp'),
            ('1\n3\n10\n1\n', 'v2bx', 'vless', 'tls', 'unknown'),
            ('3\n4\n4\n1\n', 'unknown', 'shadowsocks', 'tcp+udp', 'tcp+udp'),
            ('3\n5\n3\n1\n', 'unknown', 'shadowsocks2022', 'udp', 'udp'),
            ('3\n6\n3\n1\n', 'unknown', 'trojan', 'tls', 'tcp'),
            ('3\n7\n5\n1\n', 'unknown', 'hysteria1', 'faketcp', 'faketcp'),
            ('3\n8\n2\n1\n', 'unknown', 'hysteria2', 'quic', 'udp+quic'),
            ('3\n9\n2\n1\n', 'unknown', 'tuic', 'quic', 'udp+quic'),
            ('3\n10\n1\n1\n', 'unknown', 'unknown', 'unknown', 'unknown'),
        ]
        before = (self.config/'config.yaml').read_bytes()
        for answers, program, protocol, transport, network in cases:
            with self.subTest(protocol=protocol):
                p = self.run_shell('guided_protocol_status', answers)
                self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
                self.assertIn(f'程序={program}；', p.stdout)
                self.assertIn(f'协议={protocol}；传输={transport}；网络={network}', p.stdout)
                self.assertIn('运行状态尚未验证', p.stdout)
        self.assertEqual((self.config/'config.yaml').read_bytes(), before)
        self.assertFalse((self.base/'var/lib/crowdbastion/node-roles.json').exists())
        self.assertEqual(self.commands(), '')

    def test_cancel_or_eof_at_each_stage_does_not_query_or_mutate(self):
        for answers in ('0\n', '', '1\n0\n', '1\n', '1\n1\n0\n',
                        '1\n1\n', '1\n1\n2\n0\n', '1\n1\n2\n'):
            with self.subTest(answers=answers):
                p = self.run_shell('guided_protocol_status', answers)
                self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
                self.assertNotIn('协议能力只读画像（声明', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_invalid_selection_is_not_executed_and_environment_is_preserved(self):
        target = self.base/'must-not-exist'
        action = '''NODE_PROGRAM=unknown; NODE_PROTOCOL=vless; NODE_TRANSPORT=tls
guided_protocol_status
result=$?
printf '\nafter=%s/%s/%s;result=%s\n' "$NODE_PROGRAM" "$NODE_PROTOCOL" "$NODE_TRANSPORT" "$result"
'''
        p = self.run_shell(action, f'$(touch {target})\n01\n3\n9\n2\n1\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('协议=tuic；传输=quic；网络=udp+quic', p.stdout)
        self.assertIn('after=unknown/vless/tls;result=2', p.stdout)
        self.assertFalse(target.exists())
        self.assertEqual(self.commands(), '')

    def test_new_routes_are_reachable_without_changing_existing_roles(self):
        role_file = self.base/'var/lib/crowdbastion/node-roles.json'
        role_file.parent.mkdir(parents=True)
        role_file.write_text(json.dumps({'version': 1, 'roles': ['node']}))
        role_file.chmod(0o600)
        before = role_file.read_bytes()
        overrides = '''
manage_proxy_guidance() { printf 'GENERIC-NAV-REACHED\\n'; }
guided_protocol_status() { printf 'DECLARATION-WIZARD-REACHED\\n'; return 2; }
pause() { :; }
'''
        for action, answers, expected in (
                ('manage_quick_actions', '9\n0\n', 'GENERIC-NAV-REACHED'),
                ('manage_diagnostics', '10\n0\n', 'GENERIC-NAV-REACHED'),
                ('guided_setup', '8\n0\n', 'GENERIC-NAV-REACHED'),
                ('manage_v2bx_node', '5\n0\n', 'DECLARATION-WIZARD-REACHED')):
            with self.subTest(action=action):
                p = self.run_shell(action, answers, overrides)
                self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
                self.assertIn(expected, p.stdout)
                self.assertEqual(role_file.read_bytes(), before)
        self.assertNotRegex(self.commands(), r'enable|restart|reload|apt-get|decisions add')

    def test_generic_menu_can_query_and_return_without_installing(self):
        p = self.run_shell('manage_proxy_guidance', '1\n3\n8\n2\n1\n0\n',
                           'pause() { :; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('协议=hysteria2；传输=quic；网络=udp+quic', p.stdout)
        self.assertIn('用户态', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_home_to_protocol_wizard_and_back_is_fully_readonly(self):
        p = self.run_shell('show_main_menu',
                           '4\n11\n1\n3\n1\n4\n3\n0\n0\n0\n',
                           'pause() { :; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('协议=anytls；传输=udp-over-tcp；网络=tcp', p.stdout)
        self.assertIn('共享中转 socket 不能识别真实用户', p.stdout)
        self.assertFalse((self.base/'var/lib/crowdbastion/node-roles.json').exists())
        self.assertEqual(self.commands(), '')

    def test_copied_runtime_can_guide_after_source_files_are_unavailable(self):
        installed = self.run_shell('install_maintenance_runtime')
        self.assertEqual(installed.returncode, 0, installed.stdout+installed.stderr)
        runtime = self.base/'usr/local/lib/crowdsec-1key/current/manager.sh'
        self.source.unlink()
        (self.base/'lib').rename(self.base/'unavailable-source-lib')
        trace_before = self.trace.read_bytes()
        p = subprocess.run(['bash', '-c', 'source "$1"; guided_protocol_status',
                            'runtime-check', str(runtime)],
                           input='3\n9\n2\n1\n', capture_output=True, text=True,
                           env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                           cwd=self.base, timeout=10)
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertIn('协议=tuic；传输=quic；网络=udp+quic', p.stdout)
        self.assertNotIn('No such file', p.stderr)
        self.assertEqual(self.trace.read_bytes(), trace_before)

    def test_terminal_confirmation_names_correct_kind_and_decline_stops_apply(self):
        for kind, question in (
                ('network', '恢复已选 TCP 项的本机内核默认值？未提交变更将在 15 分钟后自动回退。'),
                ('port-policy', '应用已选端口策略？未提交的变更将在 15 分钟后自动回退。')):
            with self.subTest(kind=kind):
                self.trace.write_text('')
                tool = 'network_tool' if kind == 'network' else 'port_policy_tool'
                overrides = f'''{tool}() {{
 record "{kind}-tool $*"
 printf '%s\\n' '{{"version":1,"state":"ready","changes":[],"scope":{{"ingress":[]}}}}'
}}
'''
                p = self.run_terminal(f'main --{kind}-apply', 'n\n', overrides)
                self.assertEqual(p.returncode, 0, p.stdout)
                self.assertIn(question+' [y/N]: ', p.stdout)
                self.assertEqual(self.commands(), f'{kind}-tool plan\n')

"""Consumer-visible CLI/menu outcomes, with no host mutation commands."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import unittest
from unittest.mock import patch

import crowdbastion_environment as environment
import crowdbastion_network as network
import crowdbastion_port_policy as policy
import test_change_transactions as transaction_fixture

ROOT = Path(__file__).resolve().parents[1]


class IntegrationCLI(unittest.TestCase):
    def shell(self, command, report=None, code=0, answer=''):
        script = 'source '+shlex.quote(str(ROOT/'crowdbastion.sh'))+'\n'+r'''
check_root() { return 0; }
detect_os() { return 0; }
locked_operation() { printf 'LOCKED\n'; MAINTENANCE_LOCK_HELD=true "$@"; }
network_tool() { if [[ "$1" == plan ]]; then printf '{"version":1,"state":"ready","changes":[]}\n'; else printf '%s\n' "$REPORT"; return "$RESULT_CODE"; fi; }
port_policy_tool() { if [[ "$1" == plan ]]; then printf '{"version":1,"state":"ready","scope":{"ingress":[]}}\n'; else printf '%s\n' "$REPORT"; return "$RESULT_CODE"; fi; }
pause() { :; }
'''+command
        return subprocess.run(['bash', '-c', script], input=answer, text=True, capture_output=True,
                              env=dict(os.environ, REPORT=json.dumps(report or {}), RESULT_CODE=str(code)), timeout=8)

    def test_noop_staged_and_recovered_failure_have_distinct_outcomes(self):
        for family in ('network', 'port-policy'):
            for report, code, expected, absent in (
                ({'version': 1, 'state': 'verified', 'unchanged': True}, 0, '无需变更', '已暂存'),
                ({'version': 1, 'state': 'staged', 'id': '1'*32}, 0, '已暂存', '无需变更'),
                ({'version': 1, 'state': 'rolled_back', 'error_code': 'apply_failed'}, 1, '应用失败', '已暂存'),
            ):
                with self.subTest(family=family, state=report['state']):
                    result = self.shell('main --'+family+'-apply', report, code, 'y\n')
                    self.assertEqual(result.returncode, code, result.stdout+result.stderr)
                    self.assertIn(expected, result.stdout)
                    self.assertNotIn(absent, result.stdout)
                    self.assertNotIn('"state"', result.stdout)

    def test_refusals_explain_pending_kind_verification_and_expiry(self):
        for report, expected in (
            ({'state': 'refused', 'error_code': 'pending_change', 'pending_kind': 'port-policy'}, '端口策略'),
            ({'state': 'verification_failed', 'refusal_code': 'transaction_expired'}, '已过期'),
            ({'state': 'verification_failed'}, '核验未通过'),
            ({'state': 'unstable', 'error_code': 'persistent_io_wait', 'phase': 'environment_sample', 'windows': [{'secret': 'CANARY'}]}, '压力'),
        ):
            code = 75 if report['state'] == 'unstable' else 1
            result = self.shell('main --network-commit', report, code)
            self.assertEqual(result.returncode, code)
            self.assertIn(expected, result.stdout)
            self.assertNotIn('CANARY', result.stdout+result.stderr)
            self.assertNotIn('"state"', result.stdout)

    def test_existing_pending_verified_transaction_does_not_claim_new_change(self):
        result = self.shell('main --port-policy-apply', {'state': 'verified', 'id': '1'*32}, answer='y\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn('未提交事务', result.stdout)
        self.assertNotIn('已暂存', result.stdout)

    def test_menu_status_exposes_pending_transaction_even_without_policy(self):
        result = self.shell('change_human_action port-policy status',
                            {'state': 'absent', 'transactions': [{'kind': 'port-policy', 'state': 'rollback_incomplete'}]})
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('未完成', result.stdout)
        self.assertNotIn('尚无', result.stdout)

    def test_new_diagnostic_entries_route_without_renumbering_old_actions(self):
        prelude = '''
interactive_health_check() { printf 'OLD_HEALTH\\n'; }
environment_tool() { printf 'ENV %s\\n' "$*"; }
protocol_status() { printf 'PROTOCOL\\n'; return 2; }
'''
        result = self.shell(prelude+'manage_diagnostics', answer='1\n6\n7\n1\n0\n8\n2\n0\n9\n0\n',
                            report={'state': 'absent', 'transactions': []})
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('OLD_HEALTH', result.stdout)
        self.assertIn('ENV --human', result.stdout)
        self.assertIn('PROTOCOL', result.stdout)
        self.assertIn('TCP', result.stdout)
        self.assertIn('端口', result.stdout)
        self.assertNotIn('LOCKED', result.stdout)
        self.assertNotIn('"transactions"', result.stdout)

    def test_menu_rollback_remains_available_during_firewall_migration(self):
        command = r'''
unset -f locked_operation
source "$SCRIPT_DIR/lib/maintenance.sh"
maintenance_lock_acquire() { return 0; }
firewall_migration_pending() { return 0; }
hub_workflow_exit() { :; }
locked_operation network_action rollback
'''
        result = self.shell(command, {'state': 'rolled_back'})
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('已回退', result.stdout)

    def test_menu_mutation_uses_existing_lock_and_confirmation(self):
        result = self.shell('manage_network_configuration', {'state': 'staged'}, answer='3\ny\n0\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('LOCKED', result.stdout)
        self.assertIn('已暂存', result.stdout)


class EnvironmentOutput(unittest.TestCase):
    def test_human_guard_and_json_status_each_use_one_complete_sample(self):
        report = {'version': 1, 'state': 'unknown', 'phase': 'environment_sample',
                  'error_code': 'proc_unreadable', 'reason': '无法确认环境；暂缓修改。',
                  'windows': [{'iowait_percent': 42}], 'retryable': True}
        for args in ([], ['--guard', '--human']):
            output = io.StringIO()
            with patch.object(environment, 'check_environment', side_effect=[report]) as sample, contextlib.redirect_stdout(output):
                code = environment.main(args)
            self.assertEqual(sample.call_count, 1)
            if args:
                self.assertEqual(code, 75)
                self.assertEqual(output.getvalue().strip(), report['reason'])
            else:
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output.getvalue()), report)

    def test_shell_guard_preserves_refusal_and_requests_human_output(self):
        script = 'source '+shlex.quote(str(ROOT/'crowdbastion.sh'))+'\n'+r'''
MAINTENANCE_LOCK_HELD=true
environment_tool() { printf '%s\n' "$*"; return 75; }
environment_change_guard
'''
        result = subprocess.run(['bash', '-c', script], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 75)
        self.assertIn('--human', result.stdout)
        self.assertIn('--guard', result.stdout)


class TransactionPresentation(unittest.TestCase):
    setUp = transaction_fixture.TransactionTests.setUp
    apply = transaction_fixture.TransactionTests.apply

    def test_actual_pending_kind_is_structured_and_resource_state_is_preserved(self):
        self.apply()
        writes = list(self.adapter.writes)
        for action in (lambda: self.engine.apply('network', self.effects), lambda: self.engine.select('network')):
            with self.assertRaises(ValueError) as refused:
                action()
            self.assertEqual(getattr(refused.exception, 'report', {}).get('pending_kind'), 'port-policy')
            self.assertEqual(getattr(refused.exception, 'report', {}).get('error_code'), 'pending_change')
        self.assertEqual(writes, self.adapter.writes)

    def test_expired_commit_keeps_recovery_eligible_and_explains_refusal(self):
        result = self.apply()
        for times in ([result['deadline']], [result['deadline']-1, result['deadline']]):
            with patch('crowdbastion_change.time.time', side_effect=times):
                report = self.engine.commit(result['id'])
            self.assertEqual(report['state'], 'verification_failed')
            self.assertEqual(report.get('refusal_code'), 'transaction_expired')
        self.assertEqual(self.engine.status(result['id'])['state'], 'staged')
        self.assertEqual(self.timer.cancelled, [])

    def test_python_cli_boundaries_keep_typed_refusal_json(self):
        import crowdbastion_change as change
        error = change.ChangeRefused('pending_change', 'port-policy')
        for module in (network, policy):
            output = io.StringIO()
            with patch.object(module, 'main', side_effect=error), contextlib.redirect_stdout(output):
                code = module.cli(['commit'])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue()),
                             {'version': 1, 'state': 'refused', 'error_code': 'pending_change', 'pending_kind': 'port-policy'})

    def test_copied_presenter_runs_with_system_python_without_checkout(self):
        ident = self.apply()['id']
        helper = self.engine.root/ident/'runtime/crowdbastion_ux.py'
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c', 'import runpy,sys; sys.path.insert(0, sys.argv[1]); sys.argv=sys.argv[2:]; runpy.run_path(sys.argv[0], run_name="__main__")', str(helper.parent), str(helper), 'change-result', 'network', 'apply', '0'],
                                input='{"state":"verified","unchanged":true}', cwd='/', text=True,
                                capture_output=True, env=dict(os.environ, PYTHONPATH='/nonexistent'), timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('无需变更', result.stdout)


class GuideExamples(unittest.TestCase):
    def test_json_examples_are_consumed_by_actual_profile_validators(self):
        for name, validator in (('port-policy.md', policy.validate), ('network-configuration.md', network.validate)):
            examples = re.findall(r'```json\n(.*?)\n```', (ROOT/'docs'/name).read_text(), re.S)
            self.assertTrue(examples)
            for example in examples:
                validator(json.loads(example))

"""Run the actual single-operation dispatch, replacing only external helpers."""
from pathlib import Path
import json
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PortCLI(unittest.TestCase):
    def run_shell(self, action, data=''):
        script = 'source '+shlex.quote(str(ROOT/'crowdbastion.sh'))+'\n'+r'''
check_root() { return 0; }
detect_os() { return 0; }
port_policy_tool() { local state; case "$1" in status) state=verified ;; plan) state=ready ;; apply) state=staged ;; verify) state=verified ;; commit) state=committed ;; rollback) state=rolled_back ;; esac; printf '{"version":1,"state":"%s","changes":[],"scope":{"ingress":[]}}\n' "$state"; }
locked_operation() { printf 'locked\n'; MAINTENANCE_LOCK_HELD=true "$@"; }
'''+action
        return subprocess.run(['bash', '-c', script], input=data, text=True, capture_output=True, timeout=8)
    def test_readonly_actions_bypass_lock_and_mutation_actions_use_lock(self):
        for action in ('plan', 'status'):
            result = self.run_shell('main --port-policy-'+action)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['state'], {'plan': 'ready', 'status': 'verified'}[action])
            self.assertNotIn('locked', result.stdout)
        for action in ('verify', 'commit', 'rollback'):
            result = self.run_shell('main --port-policy-'+action)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('locked', result.stdout); self.assertIn({'verify': '核验通过', 'commit': '已提交', 'rollback': '已回退'}[action], result.stdout)
    def test_apply_confirmation_and_single_operation_constraint(self):
        result = self.run_shell('main --port-policy-apply', 'n\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('计划可执行', result.stdout); self.assertNotIn('已暂存', result.stdout)
        result = self.run_shell('main --port-policy-apply', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('已暂存', result.stdout)
        result = self.run_shell('main --port-policy-plan --port-policy-apply', 'y\n')
        self.assertNotEqual(result.returncode, 0); self.assertNotIn('\"state\"', result.stdout)
    def test_help_discovers_all_operations(self):
        result = self.run_shell('main --help')
        self.assertEqual(result.returncode, 0)
        for action in ('plan', 'status', 'apply', 'verify', 'commit', 'rollback'):
            self.assertIn('--port-policy-'+action, result.stdout)


class SafeErrors(unittest.TestCase):
    def test_environment_and_lock_refusal_are_retryable_without_exception_text(self):
        import contextlib
        import io
        from unittest.mock import patch
        import crowdbastion_port_policy as policy
        from crowdbastion_environment import EnvironmentNotReady
        self.assertTrue(hasattr(policy, 'cli'), 'safe CLI error boundary missing')
        for error, code in ((EnvironmentNotReady({'version': 1, 'state': 'unknown', 'phase': 'environment_sample', 'error_code': 'proc_unreadable', 'retryable': True}), 75),
                            (BlockingIOError('SECRET'), 75), (ValueError('SECRET'), 1)):
            output = io.StringIO()
            with patch.object(policy, 'main', side_effect=error), contextlib.redirect_stdout(output):
                self.assertEqual(policy.cli([]), code)
            self.assertNotIn('SECRET', output.getvalue())


class ApplyFailureExit(unittest.TestCase):
    def test_failed_apply_that_successfully_rolls_back_still_returns_failure(self):
        import contextlib
        import io
        from unittest.mock import patch
        import crowdbastion_port_policy as policy
        with patch.object(policy, 'load_policy', return_value={}), patch.object(policy, 'apply_policy', return_value={'version': 1, 'state': 'rolled_back', 'error_code': 'apply_failed'}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(policy.main(['apply']), 1)

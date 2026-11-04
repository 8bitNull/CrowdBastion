"""Exercise the real main single-operation dispatch with external work replaced."""
from pathlib import Path
import json
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]

class NetworkCLI(unittest.TestCase):
    def run_shell(self, command, answer=''):
        script = 'source '+shlex.quote(str(ROOT/'crowdbastion.sh'))+'\n'+r'''
check_root() { return 0; }
detect_os() { return 0; }
network_tool() { local state; case "$1" in status) state=audited ;; plan) state=ready ;; apply) state=staged ;; verify) state=verified ;; commit) state=committed ;; rollback) state=rolled_back ;; esac; printf '{"version":1,"state":"%s","changes":[],"scope":{"ingress":[]}}\n' "$state"; }
locked_operation() { printf 'locked\n'; MAINTENANCE_LOCK_HELD=true "$@"; }
'''+command
        return subprocess.run(['bash', '-c', script], input=answer, text=True, capture_output=True, timeout=8)
    def test_readonly_and_mutating_dispatch_and_single_operation(self):
        for action in ('status', 'plan'):
            result = self.run_shell('main --network-'+action)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['state'], {'status': 'audited', 'plan': 'ready'}[action]); self.assertNotIn('locked', result.stdout)
        for action in ('verify', 'commit', 'rollback'):
            result = self.run_shell('main --network-'+action)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn({'verify': '核验通过', 'commit': '已提交', 'rollback': '已回退'}[action], result.stdout); self.assertIn('locked', result.stdout)
        result = self.run_shell('main --network-plan --network-apply', 'y\n')
        self.assertNotEqual(result.returncode, 0); self.assertNotIn('\"state\"', result.stdout)
    def test_apply_presents_plan_and_honors_confirmation(self):
        result = self.run_shell('main --network-apply', 'n\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('计划可执行', result.stdout); self.assertNotIn('已暂存', result.stdout)
        result = self.run_shell('main --network-apply', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr); self.assertIn('已暂存', result.stdout)
    def test_help_lists_all_six_operations(self):
        result = self.run_shell('main --help')
        self.assertEqual(result.returncode, 0)
        for action in ('status', 'plan', 'apply', 'verify', 'commit', 'rollback'):
            self.assertIn('--network-'+action, result.stdout)

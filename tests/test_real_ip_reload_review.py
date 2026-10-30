"""Real-IP changes and diagnostic cleanup require accepted Nginx reloads."""
import shlex
import unittest
import test_workflows
import test_real_ip_workflows

class RealIPReloadReview(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    fixture = test_real_ip_workflows.RealIPWorkflows.fixture

    def test_both_adapters_propagate_failed_reload_verification(self):
        for service in ['', 'nginx', 'openresty']:
            with self.subTest(service=service):
                self.trace.write_text('')
                overrides = 'REALIP_HOST_SERVICE='+shlex.quote(service)+'''\nNATIVE_ID=web
nginx_reload_verified() { record verified "$@"; return 37; }
'''
                result = self.run_shell('real_ip_web_command -s reload', overrides=overrides)
                self.assertEqual(result.returncode, 37)
                self.assertEqual(self.commands().strip(), 'verified '+(service or 'docker web'))

    def test_silent_reload_rejection_restores_real_ip_configuration_and_registry(self):
        overrides = self.fixture().replace("'exec '*' nginx -s reload') nginx_test_reload;;",
                                            "'exec '*' nginx -s reload') record silent_rejection;;")
        overrides += '\nsleep() { command sleep "$@"; }\n'
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n1\ny\n', overrides, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('silent_rejection', self.commands())
        self.assertFalse(self.target.exists())
        self.assertFalse(self.state.exists())
        self.assertNotIn('SUCCESS', result.stdout)
        self.assertIn('重载失败', result.stderr)

    def test_diagnostic_restore_must_be_confirmed_before_recording_success(self):
        target=self.base/'diagnostic.lua';target.write_text('original hook\n')
        overrides='DIAGNOSTIC_LUA='+shlex.quote(str(target))+'''
real_ip_select_runtime() { NATIVE_ID=web; NATIVE_NAME=web; return 0; }
real_ip_runtime_mounts() { printf '[]' > "$2"; }
request_audit_tool() {
 case "$1" in
  plan) printf '{"target":"%s","url":"https://example.test/","wait_seconds":1}' "$DIAGNOSTIC_LUA" > "${!#}";;
  stage) printf diagnostic > "$DIAGNOSTIC_LUA";;
  verify) printf '{}' > "$3";;
  record) record audit-record;;
 esac
}
reload_count=0
nginx_reload_verified() { ((reload_count+=1)); record verified "$reload_count"; [[ "$reload_count" == 1 ]]; }
'''
        result=self.run_shell('verify_real_ip_request', 'https://example.test/\n198.51.100.9\n1\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), 'original hook\n')
        self.assertIn('verified 2', self.commands())
        self.assertNotIn('audit-record', self.commands())

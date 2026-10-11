"""Verification sends a live attack-path probe only after informed confirmation."""
import unittest
import test_workflows


class AppSecVerification(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_declined_loopback_probe_sends_no_request(self):
        result = self.run_shell('verify_appsec', 'http://localhost\nn\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('Self-Report', result.stdout+result.stderr)
        self.assertNotIn('curl ', self.commands())

    def test_eof_before_confirmation_sends_no_request(self):
        result = self.run_shell('verify_appsec', 'https://example.com\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('curl ', self.commands())

    def test_confirmed_probe_preserves_metrics_checks(self):
        result = self.run_shell('verify_appsec', 'https://example.com\ny\n')
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('inconclusive', result.stderr)
        self.assertIn('curl -sS --max-time 15 -o /dev/null -w %{http_code} https://example.com/.env?crowdsec_1key_probe=', self.commands())
        self.assertEqual(self.commands().count('cscli metrics show appsec'), 2)
        self.assertIn('Self-Report', result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()

"""Remote preview is read-only until an explicit private plan is approved."""
import json
import os
from pathlib import Path
import unittest

import yaml
from workflow_fixture import WorkflowFixtureMixin
import test_remote_bouncer as remote_tests


class RemotePlan(WorkflowFixtureMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.plan = self.base / 'approved.json'
        self.file = self.config / 'bouncers/crowdsec-firewall-bouncer.yaml'
        self.file.parent.mkdir()
        self.file.write_text('mode: iptables\napi_key: original\n')
        self.url = 'http://127.0.0.1:8080/'
        self.secret = 'remote-plan-secret-do-not-log'

    def prepare(self, answers, overrides=''):
        return self.run_shell(f'remote_bouncer_prepare {self.plan}', answers,
                              'install_packages() { record packages "$@"; }\n' + overrides)

    def test_eof_or_declined_preview_has_no_host_effects_or_approved_file(self):
        for answers in ['', self.url + '\n', self.url + '\n' + self.secret + '\n',
                        self.url + '\n' + self.secret + '\nn\n']:
            with self.subTest(answers=answers):
                result = self.prepare(answers)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.plan.exists())
                self.assertEqual(self.commands(), '')
                self.assertEqual(self.file.read_text(), 'mode: iptables\napi_key: original\n')

    def test_prepare_publishes_private_plan_only_after_confirmation(self):
        result = self.prepare(self.url + '\n' + self.secret + '\ny\n',
                              'python3() { command python3 -S "$@"; }')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.plan.is_file())
        self.assertEqual(self.plan.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.plan.stat().st_uid, os.geteuid())
        self.assertEqual(self.commands(), '')
        for impact in ['python3', 'curl', 'iptables', 'ipset', '.local', '.remote.json', 'restart', 'enable', '回滚']:
            self.assertIn(impact, result.stdout + result.stderr)
        self.assertNotIn(self.secret, result.stdout + result.stderr)

    def test_prepare_refuses_lock_held_without_reading_input(self):
        result = self.prepare('', 'MAINTENANCE_LOCK_HELD=true\nread() { record unexpected-read; return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.commands(), '')
        self.assertFalse(self.plan.exists())

    def test_empty_prepared_argument_never_falls_back_to_interactive_install(self):
        result = self.run_shell('remote_bouncer_change install ""', overrides='''
MAINTENANCE_LOCK_HELD=true
install_packages() { record packages "$@"; }
remote_bouncer_input() { record unexpected-input; return 99; }
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.commands(), '')

    def test_prepared_apply_uses_approved_credentials_without_input_or_confirmation(self):
        self.url = remote_tests.RemoteConfig.server(self)
        result = self.prepare(self.url + '\n' + self.secret + '\ny\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.plan.exists())
        result = self.run_shell(f'remote_bouncer_change install {self.plan}', overrides='''
MAINTENANCE_LOCK_HELD=true
install_packages() { record packages "$@"; }
remote_bouncer_input() { record unexpected-input; return 99; }
confirm() { record unexpected-confirm; return 99; }
relay_after_install() { return 0; }
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        local = yaml.safe_load(Path(str(self.file) + '.local').read_text())
        self.assertEqual(local['api_url'], self.url)
        self.assertEqual(local['api_key'], self.secret)
        self.assertNotIn('unexpected-', self.commands())
        self.assertIn('packages python3 python3-yaml curl ca-certificates', self.commands())
        self.assertIn('systemctl restart crowdsec-firewall-bouncer', self.commands())
        self.assertNotIn(self.secret, result.stdout + result.stderr + self.commands())

    def test_unsafe_or_corrupt_prepared_plan_fails_before_packages_and_service(self):
        valid = {'version': 1, 'action': 'install', 'url': self.url, 'key': self.secret}
        scenarios = [
            ('public', valid, 0o644), ('bad-json', '{broken', 0o600),
            ('bad-url', {**valid, 'url': 'http://public.example/'}, 0o600),
            ('bad-key', {**valid, 'key': 'injected\nheader'}, 0o600),
            ('unapproved', {'url': self.url, 'key': self.secret}, 0o600),
            ('extra-fields', {**valid, 'approve': True}, 0o600),
            ('symlink', valid, 0o600), ('hardlink', valid, 0o600),
            ('directory', valid, 0o600), ('parent-link', valid, 0o600),
        ]
        if os.geteuid() == 0:
            scenarios.append(('foreign-owner', valid, 0o600))
        for name, payload, mode in scenarios:
            with self.subTest(name=name):
                original = self.base / ('unsafe-' + name)
                original.write_text(payload if isinstance(payload, str) else json.dumps(payload))
                original.chmod(mode)
                candidate = original
                if name == 'symlink':
                    candidate = self.base / 'plan-link'; candidate.symlink_to(original)
                elif name == 'hardlink':
                    candidate = self.base / 'plan-hardlink'; os.link(original, candidate)
                elif name == 'directory':
                    candidate = self.base / 'plan-directory'; candidate.mkdir()
                elif name == 'parent-link':
                    parent = self.base / 'linked-parent'; parent.symlink_to(self.base, target_is_directory=True)
                    candidate = parent / original.name
                elif name == 'foreign-owner':
                    os.chown(original, 65534, 65534)
                self.trace.write_text('')
                result = self.run_shell(f'remote_bouncer_change install {candidate}', overrides='''
MAINTENANCE_LOCK_HELD=true
install_packages() { record packages "$@"; }
remote_bouncer_input() { record unexpected-input; return 99; }
''')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.commands(), '')
                self.assertFalse(Path(str(self.file) + '.local').exists())
                self.assertNotIn(self.secret, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

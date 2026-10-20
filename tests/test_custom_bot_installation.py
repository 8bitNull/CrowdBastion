"""Installed bot remains self-contained and all helper changes roll back together."""
import os
from pathlib import Path
import subprocess
import unittest

import test_custom_bot
import test_workflows


class BotInstallation(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    setup_bot = test_custom_bot.BotService.setup_bot

    def helpers(self):
        root = self.base / 'usr/local/lib/crowdsec-1key-bot'
        return [root / (name+'.py') for name in ('crowdsec_bot_api', 'crowdsec_bot_actions',
                'crowdsec_bot_health', 'crowdbastion_health', 'crowdbastion_node')]

    def test_install_bundles_helpers_and_runtime_query_needs_no_checkout(self):
        result = self.setup_bot()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        for helper in self.helpers():
            self.assertTrue(helper.is_file(), helper)
            self.assertEqual(helper.stat().st_mode & 0o777, 0o600)
        installed = self.helpers()[0].with_name('crowdsec_bot.py')
        state = self.base / 'var/lib/crowdsec-1key-bot'
        before = list(state.iterdir())
        env = dict(os.environ, PYTHONPATH='', PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run(['python3', str(installed), '--config',
                                 str(self.config/'crowdsec-1key-bot.json'), '--runtime-status'],
                                cwd='/', env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('轮询', result.stdout)
        self.assertNotIn('123:ABC', result.stdout+result.stderr)
        self.assertEqual(list(state.iterdir()), before)

    def test_upgrade_start_failure_restores_every_helper(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        original = {}
        for helper in self.helpers():
            helper.write_text('# old installed version\n')
            original[helper] = helper.read_bytes()
        result = self.setup_bot('systemctl() { record systemctl "$@"; [[ "$1" != show ]] || printf "LoadState=loaded\\nFragmentPath=%s\\n" "$CUSTOM_BOT_UNIT"; [[ "$*" != "restart crowdsec-1key-bot.service" ]]; }')
        self.assertNotEqual(result.returncode, 0)
        for helper, content in original.items():
            self.assertEqual(helper.read_bytes(), content)

    def test_helper_symlink_blocks_upgrade_without_touching_target(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        helper = self.helpers()[0]
        helper.unlink()
        target = self.base / 'foreign.py'
        target.write_text('keep')
        helper.symlink_to(target)
        result = self.setup_bot()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(helper.is_symlink())
        self.assertEqual(target.read_text(), 'keep')

    def test_core_purge_removes_all_bundled_helpers(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        result = self.run_shell('deep_purge_residuals', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(all(not path.exists() for path in self.helpers()))

    def test_inactive_service_check_still_shows_runtime_record_status(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        result = self.run_shell('check_custom_bot', overrides='systemctl() { record systemctl "$@"; if [[ "$1" == is-active ]]; then echo inactive; return 3; fi; return 0; }')
        self.assertEqual(result.returncode, 1)
        self.assertIn('轮询', result.stdout)


if __name__ == '__main__':
    unittest.main()

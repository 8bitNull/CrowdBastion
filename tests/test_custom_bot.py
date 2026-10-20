"""User bot regressions; no real commands, services or Telegram messages."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_workflows

ROOT = Path(__file__).resolve().parents[1]


class CustomBot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        sys.path.insert(0, str(ROOT/'lib'))
        self.addCleanup(sys.path.remove, str(ROOT/'lib'))
        source = Path(os.environ.get('CROWDSEC_BOT_TEST_SOURCE', ROOT/'lib/crowdsec_bot.py'))
        spec = importlib.util.spec_from_file_location('tested_custom_bot', source)
        self.bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bot)
        self.bot.CSCLI_CONFIG = str(self.base/'config.yaml')
        self.bot.DB_PATH = str(self.base/'db.sqlite')
        conn = sqlite3.connect(self.bot.DB_PATH)
        conn.execute('CREATE TABLE alerts (id INTEGER, source_ip TEXT, source_country TEXT, source_as_name TEXT, scenario TEXT, created_at TEXT)')
        conn.execute("INSERT INTO alerts VALUES (42, '203.0.113.20', '', '', 'crowdsecurity/vpatch-env-access', '2026-10-13')")
        conn.commit()
        conn.close()
        self.alert = {'id': 42, 'scenario': 'crowdsecurity/vpatch-env-access', 'source': {'value': '203.0.113.20'},
                      'start_at': '2026-10-13', 'decisions': [], 'events': [
                          {'meta': [{'key': 'uri', 'value': '/.env'}, {'key': 'user_agent', 'value': 'Real-UA <test>'},
                                    {'key': 'method', 'value': 'GET'}]}]}

    def forensic(self, alert=None):
        with patch.object(self.bot, 'run_cmd', return_value=json.dumps([alert or self.alert])) as run:
            text, keyboard = self.bot.module_forensics(42)
        return text, keyboard, run

    def test_json_inspect_event_meta_shows_matching_path_and_ua(self):
        text, _, run = self.forensic()
        self.assertIn('/.env', text)
        self.assertIn('Real-UA &lt;test&gt;', text)
        args = run.call_args.args[0]
        self.assertIsInstance(args, list)
        self.assertIn('--details', args)
        self.assertIn('json', args)
        self.assertNotIn('--no-metrics', args)

    def test_appsec_context_arrays_are_parsed_without_claiming_drop(self):
        self.alert['events'] = []
        self.alert['meta'] = [{'key': 'target_uri', 'value': '["/wp-login.php"]'},
                              {'key': 'user_agent', 'value': '["Context-UA"]'}]
        text, _, _ = self.forensic()
        self.assertIn('/wp-login.php', text)
        self.assertIn('Context-UA', text)
        self.assertNotIn('DROP', text)
        self.assertIn('未附带', text)

    def test_multi_context_ua_is_not_attached_to_one_event(self):
        self.alert['events'][0]['meta'] = [{'key': 'uri', 'value': '/.env'}]
        self.alert['meta'] = [{'key': 'target_uri', 'value': '["/.env", "/other"]'},
                              {'key': 'user_agent', 'value': '["One-UA", "Other-UA"]'}]
        text, _, _ = self.forensic()
        self.assertNotIn('Other-UA', text)
        self.assertIn('未记录', text)

    def test_missing_ua_and_empty_ua_are_distinct(self):
        self.alert['events'][0]['meta'] = [{'key': 'http_path', 'value': '/test'}, {'key': 'http_user_agent', 'value': ''}]
        text, _, _ = self.forensic()
        self.assertIn('未提供 UA', text)
        self.alert['events'][0]['meta'].pop()
        text, _, _ = self.forensic()
        self.assertIn('未记录 UA', text)

    def test_query_failure_is_reported_instead_of_unknown_fields(self):
        with patch.object(self.bot, 'run_cmd', side_effect=RuntimeError('inspect failed')):
            text, keyboard = self.bot.module_forensics(42)
        self.assertIn('查询失败', text)
        self.assertIsNone(keyboard)

    def test_ban_rejects_shell_input_without_executing(self):
        with patch.object(self.bot, 'run_cmd', return_value='') as run:
            text = self.bot.action_ban('203.0.113.20; touch /tmp/unsafe')
        self.assertFalse(run.called)
        self.assertIn('无效', text)

    def test_action_failure_is_not_reported_as_success(self):
        with patch.object(self.bot, 'run_cmd', side_effect=RuntimeError('command failed')):
            text = self.bot.action_unban('203.0.113.20')
        self.assertIn('失败', text)
        self.assertNotIn('已解封', text)

    def test_read_only_command_failure_returns_visible_response(self):
        with patch.object(self.bot, 'run_cmd', side_effect=RuntimeError('missing docker')):
            text = self.bot.module_command(['docker', 'ps'], '容器状态')
        self.assertIn('失败', text)

    def test_invalid_duration_is_rejected(self):
        with patch.object(self.bot, 'run_cmd', return_value='') as run:
            text = self.bot.action_ban('203.0.113.20', '4h; reboot')
        self.assertFalse(run.called)
        self.assertIn('无效', text)

    def test_ban_rejects_local_interface_and_mapped_loopback_addresses(self):
        for address in ('127.0.0.1', '0.0.0.0', '::1', '::', '::ffff:127.0.0.1', '203.0.113.5'):
            with self.subTest(address=address), patch.object(self.bot, 'run_cmd', return_value='[{"addr_info":[{"local":"203.0.113.5"}]}]') as run:
                text = self.bot.action_ban(address)
                self.assertNotIn('已添加', text)
                self.assertFalse(any('decisions' in call.args[0] for call in run.call_args_list))

    def test_ban_rejects_recorded_admin_and_own_addresses(self):
        parser = self.base/'parsers/s02-enrich/99-admin-whitelist.yaml'
        parser.parent.mkdir(parents=True)
        parser.write_text('whitelist:\n  ip: [203.0.113.5]\n')
        (self.base/'crowdsec-1key-own-addresses.json').write_text('["203.0.113.6"]')
        (self.base/'crowdsec-1key-admin-addresses.json').write_text('["203.0.113.7"]')
        for address in ('203.0.113.5', '203.0.113.6', '203.0.113.7'):
            with self.subTest(address=address), patch.object(self.bot, 'run_cmd', return_value='[]') as run:
                text = self.bot.action_ban(address)
                self.assertNotIn('已添加', text)
                self.assertFalse(any('decisions' in call.args[0] for call in run.call_args_list))

    def test_ban_refuses_unreadable_interface_or_safety_configuration(self):
        for output in ('invalid json', '{}', '[{"addr_info":null}]'):
            with self.subTest(output=output), patch.object(self.bot, 'run_cmd', return_value=output) as run:
                self.assertNotIn('已添加', self.bot.action_ban('203.0.113.20'))
                self.assertFalse(any('decisions' in call.args[0] for call in run.call_args_list))
        parser = self.base/'parsers/s02-enrich/99-admin-whitelist.yaml'
        parser.parent.mkdir(parents=True)
        parser.write_text('whitelist: [private-config-value\n')
        with patch.object(self.bot, 'run_cmd', return_value='[]') as run:
            text = self.bot.action_ban('203.0.113.20')
        self.assertNotIn('private-config-value', text)
        self.assertNotIn('已添加', text)
        self.assertFalse(any('decisions' in call.args[0] for call in run.call_args_list))

    def test_ban_submits_unprotected_address_after_reading_interfaces(self):
        with patch.object(self.bot, 'run_cmd', side_effect=['[]', '']) as run:
            text = self.bot.action_ban('203.0.113.20', '2h')
        self.assertIn('已添加', text)
        self.assertEqual(run.call_args_list[0].args[0], ['ip', '-j', 'address', 'show'])
        self.assertEqual(run.call_args_list[1].args[0], ['cscli', 'decisions', 'add', '--ip', '203.0.113.20', '--duration', '2h', '--reason', 'manual_tg'])

    def test_ban_refuses_parseable_but_invalid_protected_address_records(self):
        for filename, content in (('crowdsec-1key-admin-addresses.json', '{}'),
                                  ('parsers/s02-enrich/99-admin-whitelist.yaml', '[]\n'),
                                  ('crowdsec-1key-admin-addresses.json', '[true]'),
                                  ('crowdsec-1key-own-addresses.json', '[1234]'),
                                  ('parsers/s02-enrich/99-admin-whitelist.yaml', 'whitelist: {ip: [1234]}\n')):
            with self.subTest(filename=filename):
                path = self.base/filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                with patch.object(self.bot, 'run_cmd', return_value='[]') as run:
                    self.assertNotIn('已添加', self.bot.action_ban('203.0.113.20'))
                    self.assertFalse(any('decisions' in call.args[0] for call in run.call_args_list))
                path.unlink()

    def test_ban_refuses_dangling_safety_record_links(self):
        for filename in ('crowdsec-1key-admin-addresses.json', 'crowdsec-1key-own-addresses.json'):
            with self.subTest(filename=filename):
                path = self.base/filename
                path.symlink_to(self.base/'unavailable-records')
                try:
                    with patch.object(self.bot, 'run_cmd', side_effect=['[]', '']) as run:
                        self.assertNotIn('已添加', self.bot.action_ban('203.0.113.20'))
                        self.assertFalse(any('decisions' in call.args[0] for call in run.call_args_list))
                finally:path.unlink()

    def test_send_message_uses_configured_chat_after_import(self):
        self.bot.ADMIN_CHAT_ID = -999
        with patch.object(self.bot, 'tg_request', return_value={'ok': True}) as send:
            self.bot.send_message('test')
        self.assertEqual(send.call_args.args[1]['chat_id'], -999)

    def test_authorization_requires_user_and_chat(self):
        self.bot.ADMIN_USER_ID, self.bot.ADMIN_CHAT_ID = 123, -999
        self.assertTrue(self.bot.authorized({'from': {'id': 123}, 'chat': {'id': -999}}))
        self.assertFalse(self.bot.authorized({'from': {'id': 123}, 'chat': {'id': -998}}))
        self.assertFalse(self.bot.authorized({'from': {'id': 456}, 'chat': {'id': -999}}))

    def test_whitelist_first_creation_writes_valid_yaml_and_checks_before_reload(self):
        self.bot.WHITELIST_FILE = str(self.base/'tg-whitelist.yaml')
        with patch.object(self.bot, 'run_cmd', return_value='') as run:
            text = self.bot.action_whitelist('203.0.113.20')
        import yaml
        data = yaml.safe_load(Path(self.bot.WHITELIST_FILE).read_text())
        self.assertEqual(data['whitelist']['ip'], ['203.0.113.20'])
        self.assertIn('已加入', text)
        self.assertEqual(run.call_args_list[0].args[0][0], 'crowdsec')
        self.assertEqual(run.call_args_list[1].args[0], ['systemctl', 'reload', 'crowdsec'])

    def test_whitelist_failed_validation_removes_new_file(self):
        self.bot.WHITELIST_FILE = str(self.base/'tg-whitelist.yaml')
        with patch.object(self.bot, 'run_cmd', side_effect=[RuntimeError('invalid'), '']):
            text = self.bot.action_whitelist('203.0.113.20')
        self.assertFalse(Path(self.bot.WHITELIST_FILE).exists())
        self.assertIn('已恢复', text)

    def test_unknown_whitelist_file_is_preserved(self):
        path = self.base/'tg-whitelist.yaml'
        path.write_text('whitelist:\n  ip: [203.0.113.1]\n')
        self.bot.WHITELIST_FILE = str(path)
        before = path.read_bytes()
        with patch.object(self.bot, 'run_cmd') as run:
            text = self.bot.action_whitelist('203.0.113.20')
        self.assertFalse(run.called)
        self.assertEqual(path.read_bytes(), before)
        self.assertIn('未修改', text)

    def test_whitelist_write_failure_does_not_claim_it_was_loaded(self):
        self.bot.WHITELIST_FILE = str(self.base/'tg-whitelist.yaml')
        with patch.object(self.bot, 'replace_private', side_effect=OSError('disk full')), patch.object(self.bot, 'run_cmd') as run:
            text = self.bot.action_whitelist('203.0.113.20')
        self.assertFalse(run.called)
        self.assertNotIn('已加载', text)
        self.assertIn('失败', text)

    def test_single_instance_lock_rejects_same_token(self):
        first = self.base/'lock'
        import fcntl
        with first.open('w') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            real_open = os.open
            with patch.object(self.bot.os, 'open', side_effect=lambda *_args, **kw: real_open(str(first), os.O_RDWR)):
                with self.assertRaises(RuntimeError):
                    self.bot.acquire_instance_lock()

    def test_default_main_does_not_start_automatic_alert_thread(self):
        self.bot.STATE_DIR = str(self.base/'state')
        with patch.object(self.bot, 'register_bot_commands'), patch.object(self.bot, 'send_message') as send, \
             patch.object(self.bot, 'tg_request', side_effect=SystemExit), patch.object(self.bot, 'Thread') as thread:
            with self.assertRaises(SystemExit):
                self.bot.main()
        self.assertFalse(thread.called)
        self.assertFalse(send.called, "service restart must not send unsolicited chat messages")

    def test_update_offset_is_scoped_to_bot_token(self):
        self.bot.STATE_DIR = str(self.base/'state')
        self.bot.BOT_TOKEN = '123:AAA'
        self.bot.save_offset(123)
        first = self.bot.offset_path()
        self.bot.BOT_TOKEN = '456:BBB'
        self.bot.save_offset(456)
        second = self.bot.offset_path()
        self.assertNotEqual(first, second)
        self.assertEqual(Path(first).read_text(), '123')
        self.assertEqual(Path(second).read_text(), '456')


class BotService(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def setup_bot(self, overrides=''):
        return self.run_shell('setup_custom_bot', '123:ABC\n-123\n456\n\n\n', overrides, timeout=10)

    def test_optional_bot_install_is_separate_from_official_notifications(self):
        profile = (self.config/'profiles.yaml').read_bytes()
        result = self.setup_bot()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        config = self.config/'crowdsec-1key-bot.json'
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        settings = json.loads(config.read_text())
        self.assertEqual(settings['admin_user_id'], 456)
        self.assertEqual(settings['chat_id'], -123)
        self.assertEqual((self.config/'profiles.yaml').read_bytes(), profile)
        self.assertNotIn('123:ABC', result.stdout+result.stderr)
        self.assertIn('restart crowdsec-1key-bot.service', self.commands())
        self.assertNotIn('restart crowdsec\n', self.commands())

    def test_install_bundles_ban_guard_and_purge_removes_it(self):
        result = self.setup_bot()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        helper = self.base/'usr/local/lib/crowdsec-1key-bot/crowdsec_safety.py'
        self.assertTrue(helper.is_file())
        execution = helper.with_name('crowdsec_execution.py')
        self.assertTrue(execution.is_file())
        check = subprocess.run(['python3', str(helper), 'guard-ban', '127.0.0.1', str(self.config), '', '[]'], capture_output=True, text=True)
        self.assertNotEqual(check.returncode, 0)
        self.assertIn('不能封禁', check.stderr)
        result = self.run_shell('deep_purge_residuals', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(helper.exists())
        self.assertFalse(execution.exists())

    def test_failed_bot_start_restores_existing_config(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        config = self.config/'crowdsec-1key-bot.json'
        before = config.read_bytes()
        result = self.setup_bot('systemctl() { record systemctl "$@"; [[ "$1" != show ]] || printf "LoadState=loaded\\nFragmentPath=%s\\n" "$CUSTOM_BOT_UNIT"; [[ "$*" != "restart crowdsec-1key-bot.service" ]]; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_bytes(), before)

    def test_foreign_bot_service_is_preserved_and_blocks_install(self):
        result = self.setup_bot('systemctl() { record systemctl "$@"; if [[ "$1" == list-unit-files ]]; then echo "crowdsec-bot.service enabled"; fi; return 0; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.config/'crowdsec-1key-bot.json').exists())
        self.assertNotIn('stop crowdsec-bot', self.commands())

    def test_same_name_vendor_service_is_not_overridden(self):
        result = self.setup_bot('systemctl() { record systemctl "$@"; [[ "$1" != show ]] || printf "LoadState=loaded\\nFragmentPath=/usr/lib/systemd/system/crowdsec-1key-bot.service\\n"; return 0; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.config/'crowdsec-1key-bot.json').exists())
        self.assertNotIn('restart', self.commands())
        self.assertIn('归属未知', result.stdout+result.stderr)

    def test_disabled_cron_comment_does_not_block_install(self):
        result = self.setup_bot('crontab() { echo "# */3 * * * * python3 /usr/local/bin/crowdsec_bot.py"; }')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_stop_custom_bot_does_not_disable_official_channel(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        result = self.run_shell('disable_custom_bot', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue((self.config/'crowdsec-1key-bot.json').exists())
        self.assertIn('disable --now crowdsec-1key-bot.service', self.commands())

    def test_status_is_read_only_and_menu_exits_on_eof(self):
        self.assertEqual(self.run_shell('manage_custom_bot').returncode, 0)
        result = self.run_shell('check_custom_bot')
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertNotIn('restart', self.commands())

    def test_core_purge_stops_and_removes_managed_bot(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        result = self.run_shell('deep_purge_residuals', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('disable --now crowdsec-1key-bot.service', self.commands())
        self.assertFalse((self.base/'etc/systemd/system/crowdsec-1key-bot.service').exists())
        self.assertFalse((self.base/'usr/local/lib/crowdsec-1key-bot/crowdsec_bot.py').exists())


if __name__ == '__main__':
    unittest.main()

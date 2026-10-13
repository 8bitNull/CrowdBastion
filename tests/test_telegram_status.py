"""Read-only TG diagnostics, effective profile ordering and evidence boundaries."""
import json
from pathlib import Path
import subprocess
import unittest

import yaml
import test_workflows

ROOT = test_workflows.ROOT


class TelegramStatus(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def setup_channel(self):
        result = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\nn\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        return self.config/'notifications/crowdsec-1key-telegram.yaml'

    def report(self, units='', cron=''):
        unit_file = self.base/'units.txt'
        unit_file.write_text(units)
        cron_root = self.base/'cron'
        cron_root.mkdir(exist_ok=True)
        crontab = self.base/'crontab.txt'
        crontab.write_text(cron)
        result = subprocess.run(['python3', str(ROOT/'lib/crowdsec_telegram.py'), 'status', str(self.config),
                                 '--units', str(unit_file), '--cron-dir', str(cron_root),
                                 '--crontab', str(crontab), '--json'], capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 1, 2), result.stderr)
        self.assertTrue(result.stdout, result.stderr)
        self.assertNotIn('123:ABC', result.stdout+result.stderr)
        return result, json.loads(result.stdout)

    def test_valid_config_does_not_claim_delivery_or_real_traffic_validation(self):
        self.setup_channel()
        before = {p: p.read_bytes() for p in self.config.rglob('*') if p.is_file()}
        result, data = self.report()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(data['configuration']['state'], 'normal')
        self.assertEqual(data['routing']['state'], 'normal')
        self.assertEqual(data['delivery']['state'], 'unknown')
        self.assertEqual(data['traffic']['state'], 'unknown')
        self.assertEqual({p: p.read_bytes() for p in self.config.rglob('*') if p.is_file()}, before)

    def test_unconfigured_is_distinguished_from_missing_route(self):
        result, data = self.report()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(data['configuration']['state'], 'unconfigured')
        self.setup_channel()
        (self.config/'profiles.yaml').write_text('name: no_tg\nfilters: [Alert.Remediation == true]\n')
        result, data = self.report()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(data['routing']['state'], 'abnormal')

    def test_local_profiles_are_first_and_continue_is_only_a_possible_duplicate(self):
        self.setup_channel()
        (self.config/'profiles.yaml.local').write_text('name: earlier\nfilters: [Alert.Remediation == true]\non_success: continue\nnotifications: [crowdsec_1key_telegram]\n')
        result, data = self.report()
        self.assertEqual(result.returncode, 2)
        self.assertEqual([p['name'] for p in data['routing']['profiles']], ['earlier', 'default_ip_remediation'])
        self.assertEqual(data['duplicates']['continuing_profiles'], ['earlier'])

    def test_same_destination_legacy_routes_and_repeated_entries_are_reported(self):
        self.setup_channel()
        (self.config/'notifications/old.yaml').write_text(yaml.safe_dump({'type': 'http', 'name': 'http_default',
            'url': 'https://api.telegram.org/bot123:ABC/sendMessage',
            'format': '{"chat_id":"-123", "text":"old"}'}))
        profile = self.config/'profiles.yaml'
        data = yaml.safe_load(profile.read_text())
        data['notifications'] += ['crowdsec_1key_telegram', 'http_default']
        profile.write_text(yaml.safe_dump(data))
        result, data = self.report()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(data['duplicates']['same_destination'], ['http_default'])
        self.assertEqual(data['duplicates']['repeated_profiles'], ['default_ip_remediation'])

    def test_external_service_and_cron_are_candidates_without_exposing_commands(self):
        self.setup_channel()
        result, data = self.report('crowdsec-tg-bot.service enabled\ntelegram-alert.service disabled\nunrelated.service enabled\n',
                                   '* * * * * /opt/telegram_bot.py --token 123:ABC\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(data['external']['services'], ['crowdsec-tg-bot.service', 'telegram-alert.service'])
        self.assertEqual(data['external']['cron'], ['root crontab'])
        self.assertNotIn('/opt/telegram_bot.py', json.dumps(data))

    def test_stale_or_malformed_evidence_does_not_claim_success(self):
        self.setup_channel()
        evidence = self.config/'crowdsec-1key-telegram-test.json'
        for text in ('{broken', json.dumps({'fingerprint': 'stale', 'accepted': True, 'checked_at': 1})):
            evidence.write_text(text)
            result, data = self.report()
            self.assertEqual(result.returncode, 2)
            self.assertEqual(data['delivery']['state'], 'unknown')

    def test_check_menu_is_read_only_and_does_not_send_messages(self):
        self.setup_channel()
        self.trace.write_text('')
        result = self.run_shell('check_telegram_settings')
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('真实攻击取证', result.stdout)
        self.assertNotIn('notifications test', self.commands())
        self.assertNotIn('systemctl restart', self.commands())

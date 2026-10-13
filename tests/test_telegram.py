"""Telegram migration regressions; optional tests render with the official plugin.

CROWDSEC_TEST_RELEASE=/path/to/crowdsec-v1.8.1 python3 -m unittest discover -s tests -p test_telegram.py
"""
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import unittest

import yaml
import test_workflows

ROOT = test_workflows.ROOT


class TelegramRoutes(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def helper(self, *args):
        return subprocess.run(['python3', str(ROOT/'lib/crowdsec_config.py'), *map(str, args)], text=True, capture_output=True)

    def test_delivery_mode_defaults_to_immediate_and_preserves_batch_on_update(self):
        path = self.config/'notifications/crowdsec-1key-telegram.yaml'
        args = ('telegram', path, '123:ABC', '-123', 'https://api.telegram.org')
        result = self.helper(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(yaml.safe_load(path.read_text())['group_threshold'], 1)
        result = self.helper(*args, 'batch')
        self.assertEqual(result.returncode, 0, result.stderr)
        batch = yaml.safe_load(path.read_text())
        self.assertEqual((batch['group_wait'], batch['group_threshold']), ('30s', 10))
        result = self.helper(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(yaml.safe_load(path.read_text()), batch)
        result = self.helper(*args, 'immediate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(yaml.safe_load(path.read_text())['group_threshold'], 1)

    def test_invalid_delivery_mode_leaves_notification_unchanged(self):
        path = self.config/'notifications/crowdsec-1key-telegram.yaml'
        args = ('telegram', path, '123:ABC', '-123', 'https://api.telegram.org')
        self.assertEqual(self.helper(*args).returncode, 0)
        original = path.read_bytes()
        result = self.helper(*args, 'invalid')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_bytes(), original)

    def legacy(self):
        folder = self.config/'notifications'
        folder.mkdir()
        docs = [
            {'type': 'http', 'name': 'http_default', 'url': 'https://api.telegram.org/bot123:ABC/sendMessage',
             'format': '{"chat_id":"-123", "text":"old"}'},
            {'type': 'http', 'name': 'other_chat', 'url': 'https://api.telegram.org/bot123:ABC/sendMessage',
             'format': '{"chat_id":"-456", "text":"other"}'},
            {'type': 'http', 'name': 'email', 'url': 'https://example.com/notify', 'format': '{{ . | toJson }}'},
        ]
        (folder/'http.yaml').write_text(yaml.safe_dump_all(docs))
        profile = self.config/'profiles.yaml'
        profile.write_text(profile.read_text()+'notifications: [http_default, other_chat, email, crowdsec_1key_telegram, crowdsec_1key_telegram]\n')
        local = self.config/'profiles.yaml.local'
        local.write_text('name: earlier\nfilters: [Alert.Remediation == true]\non_success: break\nnotifications: [http_default, email]\n')
        return profile, local, folder/'http.yaml'

    def test_setup_replaces_only_same_bot_chat_routes_and_deduplicates(self):
        profile, local, legacy = self.legacy()
        old = legacy.read_bytes()
        for _ in range(2):
            result = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\nn\n')
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(yaml.safe_load(profile.read_text())['notifications'], ['other_chat', 'email', 'crowdsec_1key_telegram'])
        self.assertEqual(yaml.safe_load(local.read_text())['notifications'], ['email', 'crowdsec_1key_telegram'])
        self.assertEqual(legacy.read_bytes(), old)

    def test_migration_rolls_back_all_routes_on_validation_failure(self):
        profile, local, legacy = self.legacy()
        before = [p.read_bytes() for p in (profile, local, legacy)]
        result = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\nn\n', 'crowdsec() { return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([p.read_bytes() for p in (profile, local, legacy)], before)
        self.assertFalse((self.config/'notifications/crowdsec-1key-telegram.yaml').exists())

    def test_legacy_proxy_endpoint_and_go_dict_chat_are_migrated(self):
        folder = self.config/'notifications'
        folder.mkdir()
        (folder/'legacy.yml').write_text(yaml.safe_dump({'type': 'http', 'name': 'old_proxy',
            'url': 'https://telegram.example/proxy/bot123:ABC/sendMessage',
            'format': '{{ dict "chat_id" "-123" "text" "old" | toJson }}'}))
        profile = self.config/'profiles.yaml'
        profile.write_text(profile.read_text()+'notifications: [old_proxy]\n')
        result = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\nn\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(yaml.safe_load(profile.read_text())['notifications'], ['crowdsec_1key_telegram'])

    def test_mixed_literal_and_dynamic_chat_route_is_preserved(self):
        folder = self.config/'notifications'
        folder.mkdir()
        (folder/'mixed.yaml').write_text(yaml.safe_dump({'type': 'http', 'name': 'mixed',
            'url': 'https://api.telegram.org/bot123:ABC/sendMessage',
            'format': '{{ $chat := "-456" }}{{ if . }}{"chat_id":"-123"}{{ else }}{"chat_id":{{ $chat | toJson }}}{{ end }}'}))
        profile = self.config/'profiles.yaml'
        profile.write_text(profile.read_text()+'notifications: [mixed]\n')
        result = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\nn\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(yaml.safe_load(profile.read_text())['notifications'], ['mixed', 'crowdsec_1key_telegram'])


@unittest.skipUnless(os.environ.get('CROWDSEC_TEST_RELEASE'), 'set CROWDSEC_TEST_RELEASE for official plugin checks')
class TelegramRendering(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp

    def setUp(self):
        test_workflows.Workflows.setUp(self)
        release = Path(os.environ['CROWDSEC_TEST_RELEASE'])
        cfg = yaml.safe_load((release/'config/config.yaml').read_text())
        for folder in ['data', 'hub', 'plugins']:
            (self.base/folder).mkdir()
        shutil.copy(release/'cmd/notification-http/notification-http', self.base/'plugins/notification-http')
        cfg['config_paths'].update(config_dir=str(self.config), data_dir=str(self.base/'data'), hub_dir=str(self.base/'hub'), index_path=str(self.base/'hub/.index.json'), notification_dir=str(self.config/'notifications'), plugin_dir=str(self.base/'plugins'))
        cfg['api']['server']['profiles_path'] = str(self.config/'profiles.yaml')
        cfg['api']['server']['console_path'] = str(self.config/'console.yaml')
        cfg['api']['server']['online_client'] = None
        cfg['api']['client']['credentials_path'] = str(self.config/'local_api_credentials.yaml')
        cfg['db_config']['db_path'] = str(self.base/'data/crowdsec.db')
        cfg['plugin_config'] = {'user': 'root', 'group': 'root'}
        (self.config/'config.yaml').write_text(yaml.safe_dump(cfg))
        self.received = []
        received = self.received
        self.http_code = 200
        self.api_reply = {'ok': True, 'result': {'message_id': 42}}
        owner = self

        class Receiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(owner.http_code)
                self.end_headers()
                self.wfile.write(json.dumps(owner.api_reply).encode())

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        notification = self.config/'notifications/crowdsec-1key-telegram.yaml'
        result = subprocess.run(['python3', str(ROOT/'lib/crowdsec_config.py'), 'telegram', str(notification), '123:ABC', '-123', 'https://api.telegram.org'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = yaml.safe_load(notification.read_text())
        data['url'] = f'http://127.0.0.1:{server.server_port}/test'
        notification.write_text(yaml.safe_dump(data))
        self.cscli = release/'cmd/crowdsec-cli/cscli'

    def render(self, alert):
        result = subprocess.run([str(self.cscli), '-c', str(self.config/'config.yaml'), 'notifications', 'test', 'crowdsec_1key_telegram', '--alert', json.dumps(alert, ensure_ascii=False)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(self.received, result.stdout+result.stderr)
        self.assertNotIn('parse_mode', self.received[-1])
        return self.received[-1]['text']

    def event(self, **meta):
        return {'meta': [{'key': k, 'value': v} for k, v in meta.items()]}

    def test_zero_id_is_not_presented_as_persistent_alert_id(self):
        text = self.render({'id': 0, 'scenario': 'http-test'})
        self.assertNotIn('Alert #0', text)
        self.assertIn('实时告警', text)

    def test_decision_is_not_reported_as_verified_bouncer_enforcement(self):
        text = self.render({'scenario': 'http-test', 'decisions': [{'type': 'ban', 'duration': '4h'}]})
        self.assertIn('ban / 4h', text)
        self.assertIn('未验证 Bouncer 实际拦截', text)
        self.assertNotIn('DROP', text)

    def test_missing_decision_and_simulation_are_explicit(self):
        text = self.render({'scenario': 'http-test', 'decisions': [], 'simulated': True})
        self.assertIn('未附带处置决策', text)
        self.assertIn('模拟告警', text)

    def test_false_simulation_flag_is_not_treated_as_a_truthy_pointer(self):
        text = self.render({'scenario': 'http-test', 'simulated': False})
        self.assertNotIn('模式: 模拟告警', text)

    def test_real_event_meta_paths_and_ua_are_rendered_and_json_escaped(self):
        path = '/probe?q="quoted"&x=<script>\\test'
        ua = 'scanner "quoted"\n<script>&\\test'
        text = self.render({'id': 156, 'scenario': 'crowdsecurity/patch-CVE-2026-63030', 'source': {'value': '2001:db8::1'}, 'events': [self.event(http_path=path, http_user_agent=ua, http_verb='GET')]})
        for value in [path, ua, 'GET', '156', '2001:db8::1']:
            self.assertIn(value, text)

    def test_alert_context_is_fallback_when_events_are_absent(self):
        text = self.render({'scenario': 'http-test', 'meta': self.event(target_uri='/context', user_agent='Context-UA')['meta']})
        self.assertIn('/context', text)
        self.assertIn('Context-UA', text)

    def test_real_appsec_context_completes_matching_event_evidence(self):
        ua = 'CrowdSec integration test'
        text = self.render({'kind': 'waf', 'scenario': 'crowdsecurity/vpatch-env-access',
                            'events': [self.event(uri='/.env')],
                            'meta': self.event(target_uri=json.dumps(['/.env']),
                                               user_agent=json.dumps([ua]), method=json.dumps(['GET']))['meta']})
        self.assertIn('刺探目标: GET /.env', text)
        self.assertIn('客户端指纹: '+ua, text)
        self.assertNotIn('未记录 UA', text)

    def test_context_from_different_path_is_not_paired_with_event(self):
        text = self.render({'kind': 'waf', 'scenario': 'http-test',
                            'events': [self.event(uri='/first')],
                            'meta': self.event(target_uri=json.dumps(['/other']), user_agent=json.dumps(['Other-UA']))['meta']})
        self.assertIn('事件未记录 UA', text)

    def test_empty_first_event_does_not_hide_later_evidence(self):
        text = self.render({'scenario': 'http-test', 'events': [self.event(service='http'), self.event(http_path='/later', http_user_agent='Later-UA')]})
        self.assertIn('/later', text)
        self.assertIn('Later-UA', text)

    def test_missing_data_and_empty_ua_are_distinguished(self):
        text = self.render({'scenario': 'http-test', 'events': [self.event(http_path='/no-ua', http_user_agent='-')]})
        self.assertIn('未提供 UA', text)
        text = self.render({'scenario': 'ssh-test', 'source': None})
        self.assertIn('未携带 HTTP 请求元数据', text)

    def test_request_samples_keep_path_ua_pairs_and_bound_message_size(self):
        events = [self.event(http_path='/first', http_user_agent='UA-first'), self.event(http_path='/second', http_user_agent='UA-second')]
        text = self.render({'scenario': 'http-test', 'events': events})
        self.assertIn('/first', text)
        self.assertIn('/second', text)
        self.assertLess(text.index('/first'), text.index('UA-first'))
        self.assertLess(text.index('UA-first'), text.index('/second'))
        self.assertLess(text.index('/second'), text.index('UA-second'))
        text = self.render({'scenario': 'http-test', 'events': [self.event(http_path='中'*2000+str(i), http_user_agent='测'*2000+str(i)) for i in range(4)]})
        self.assertLessEqual(len(text), 4096)
        self.assertEqual(text.count('请求样本'), 3)


@unittest.skipUnless(os.environ.get('CROWDSEC_TEST_RELEASE'), 'set CROWDSEC_TEST_RELEASE for official receipt checks')
class TelegramReceipts(unittest.TestCase):
    setUp = TelegramRendering.setUp

    def check_receipt(self):
        return subprocess.run(['python3', str(ROOT/'lib/crowdsec_telegram.py'), 'test', str(self.config),
                               '--cscli', str(self.cscli)], capture_output=True, text=True, timeout=45)

    def test_official_plugin_single_message_has_verified_api_receipt(self):
        before = (self.config/'notifications/crowdsec-1key-telegram.yaml').read_bytes()
        result = self.check_receipt()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(len(self.received), 1)
        self.assertIn('API 已接受', result.stdout)
        self.assertEqual((self.config/'notifications/crowdsec-1key-telegram.yaml').read_bytes(), before)
        evidence = self.config/'crowdsec-1key-telegram-test.json'
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
        self.assertTrue(json.loads(evidence.read_text())['accepted'])
        self.assertNotIn('123:ABC', evidence.read_text()+result.stdout+result.stderr)

    def test_successful_receipt_expires_on_configuration_change_or_after_24_hours(self):
        profile = self.config/'profiles.yaml'
        configured = yaml.safe_load(profile.read_text())
        configured['notifications'] = ['crowdsec_1key_telegram']
        profile.write_text(yaml.safe_dump(configured))
        self.assertEqual(self.check_receipt().returncode, 0)
        unit_file = self.base/'empty-units'
        unit_file.write_text('')
        args = ['python3', str(ROOT/'lib/crowdsec_telegram.py'), 'status', str(self.config),
                '--units', str(unit_file), '--crontab', str(unit_file), '--cron-dir', str(self.base/'empty-cron'), '--json']
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)['delivery']['state'], 'normal')
        evidence = self.config/'crowdsec-1key-telegram-test.json'
        data = json.loads(evidence.read_text())
        data['checked_at'] -= 86401
        evidence.write_text(json.dumps(data))
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)['delivery']['state'], 'unknown')
        self.assertEqual(self.check_receipt().returncode, 0)
        profile.write_text(profile.read_text()+'# configuration changed\n')
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)['delivery']['state'], 'unknown')

    def test_http_rejection_fails_even_if_official_cli_exits_successfully(self):
        for status in (401, 429):
            self.http_code = status
            self.api_reply = {'ok': False, 'error_code': status, 'description': 'secret 123:ABC'}
            result = self.check_receipt()
            self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
            self.assertIn('API 拒绝', result.stdout+result.stderr)
            self.assertNotIn('123:ABC', result.stdout+result.stderr)

    def test_ok_false_overrides_http_200_and_clears_prior_success(self):
        self.assertEqual(self.check_receipt().returncode, 0)
        self.api_reply = {'ok': False, 'error_code': 400}
        result = self.check_receipt()
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        evidence = json.loads((self.config/'crowdsec-1key-telegram-test.json').read_text())
        self.assertFalse(evidence['accepted'])

    def test_cli_exit_zero_without_delivery_is_not_success(self):
        fake = self.base/'empty-cscli'
        fake.write_text('#!/bin/sh\nexit 0\n')
        fake.chmod(0o755)
        self.cscli = fake
        result = self.check_receipt()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('未收到', result.stdout+result.stderr)
        self.assertEqual(self.received, [])

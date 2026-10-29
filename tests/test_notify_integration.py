"""Official HTTP plugin -> policy queue -> real transport -> loopback fake API."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
import crowdsec_notify as notify
import crowdsec_notify_setup as setup
import crowdsec_telegram as telegram
from crowdsec_bot_api import TelegramClient
import test_telegram


@unittest.skipUnless(os.environ.get('CROWDSEC_TEST_RELEASE'), 'set CROWDSEC_TEST_RELEASE for official plugin checks')
class OfficialNotificationPipeline(unittest.TestCase):
    def setUp(self):
        test_telegram.TelegramRendering.setUp(self)
        notification = self.config/'notifications/crowdsec-1key-telegram.yaml'
        current = yaml.safe_load(notification.read_text())
        self.fake_api = current['url'].rsplit('/', 1)[0]
        current['url'] = 'https://api.telegram.org/bot123:ABC/sendMessage'
        notification.write_text(yaml.safe_dump(current))
        profile = self.config/'profiles.yaml'
        profile.write_text(profile.read_text()+'notifications: [crowdsec_1key_telegram]\n')
        setup.prepare(str(self.config), str(self.base/'notify-state'), str(self.config/'bot.json'))
        config_path = self.config/notify.CONFIG_NAME
        self.worker_config = notify.load_config(config_path)
        self.store = notify.Store(self.worker_config)
        self.addCleanup(self.store.close)
        self.server = notify.make_server(dict(self.worker_config, port=0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.worker_config['port'] = self.server.server_port
        setup.save(config_path, self.worker_config)
        setup.prepare(str(self.config), str(self.base/'notify-state'), str(self.config/'bot.json'))
        self.client = TelegramClient('https://api.telegram.org/bot123:ABC', str(self.base/'transport'), '123:ABC')
        # Test-only endpoint replacement. Production validation still requires HTTPS.
        self.client._base_url = self.fake_api+'/bot123:ABC'

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def send(self, payload):
        return self.client.request('sendMessage', payload) is not None, None

    def post_alert(self, data):
        result = subprocess.run([str(self.cscli), '-c', str(self.config/'config.yaml'),
            'notifications', 'test', 'crowdsec_1key_telegram', '--alert', json.dumps(data)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_official_projection_ingests_and_deduplicates_without_forwarding_request_logs(self):
        data = {'id': 23, 'scenario': 'crowdsecurity/http-probing', 'simulated': False,
                'start_at': '2026-10-29T00:00:00Z', 'source': {'scope': 'Ip', 'value': '192.0.2.5'},
                'events': [{'meta': [{'key': 'http_path', 'value': 'PRIVATE-PATH'*1000}]}]}
        with patch.object(self.store, 'ingest', wraps=self.store.ingest) as ingest:
            self.post_alert(data)
            emitted = ingest.call_args.args[0]
        self.assertEqual(set(emitted[0]), {'id', 'scenario', 'simulated', 'source', 'start_at'})
        # cscli deliberately replaces start_at on each test invocation. A transport
        # retry replays the emitted body, not a newly generated synthetic alert.
        replay = urllib.request.Request(f'http://127.0.0.1:{self.server.server_port}/alerts',
            data=json.dumps(emitted).encode(), headers={'Authorization': 'Bearer '+self.worker_config['secret']})
        with urllib.request.urlopen(replay, timeout=5) as response:
            self.assertEqual(json.load(response), {'accepted': 0})
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
        self.assertEqual(self.received, [])
        now = time.time()+3601
        self.store.schedule(now)
        self.assertTrue(self.store.deliver_one(self.send, now))
        self.assertEqual(len(self.received), 1)
        self.assertIn('新增 1 条', self.received[0]['text'])
        self.assertNotIn('PRIVATE-PATH', json.dumps(self.received))
        self.assertTrue(self.received[0]['disable_notification'])

    def test_official_test_command_requires_a_real_transport_receipt(self):
        stop = threading.Event()
        def work():
            while not stop.is_set():
                now = time.time()
                self.store.schedule(now)
                self.store.deliver_one(self.send, now)
                stop.wait(0.02)
        worker = threading.Thread(target=work)
        worker.start()
        try:
            self.assertEqual(telegram.test_notification(str(self.config), str(self.cscli)), 0)
        finally:
            stop.set()
            worker.join(20)
        self.assertEqual(len(self.received), 1)
        self.assertIn('分级通知测试', self.received[0]['text'])
        report = telegram.inspect_settings(str(self.config))
        self.assertEqual(report['configuration']['mode'], 'smart')
        self.assertEqual(report['delivery']['state'], 'normal')


if __name__ == '__main__':
    unittest.main()

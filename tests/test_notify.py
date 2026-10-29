"""Notification policy, durability and loopback boundary tests. No Telegram traffic."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
import crowdsec_notify as notify
from crowdsec_notify_client import request
import test_workflows


def configuration(root):
    return {'version': 1, 'enabled': True, 'node': 'test-node', 'bot_token': '123:ABC',
            'chat_id': '-123', 'secret': 'a'*64, 'api_endpoint': 'https://api.telegram.org',
            'state_dir': str(root/'state'), 'crowdsec_config': str(root/'config.yaml'),
            'bot_config': str(root/'bot.json'), 'port': 7423, 'policy': copy.deepcopy(notify.DEFAULT_POLICY)}


def alert(identifier=1, scenario='crowdsecurity/http-probing', **extra):
    return {'id': identifier, 'scenario': scenario, 'start_at': '2026-10-29T00:00:00Z',
            'source': {'value': f'192.0.2.{identifier % 254 + 1}'}, 'simulated': False, **extra}


class NotificationPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = configuration(self.root)
        self.store = notify.Store(self.config, now=1000)
        self.addCleanup(lambda: self.store.close())
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)
        return True, None

    def tick(self, now):
        self.store.schedule(now)
        return self.store.deliver_one(self.send, now)

    def restart(self):
        self.store.close()
        self.store = notify.Store(self.config, now=9999)

    def incident(self):
        return self.store.db.execute('SELECT * FROM incidents ORDER BY first DESC').fetchone()

    def test_many_sources_are_one_silent_hourly_digest_and_empty_windows_are_silent(self):
        self.store.ingest([alert(i) for i in range(1, 151)], 1010)
        self.assertFalse(self.tick(4599))
        self.assertTrue(self.tick(4600))
        self.assertEqual(len(self.sent), 1)
        self.assertIn('新增 150 条告警，涉及 1 类事件', self.sent[0]['text'])
        self.assertIn('来源 150 个', self.sent[0]['text'])
        self.assertTrue(self.sent[0]['disable_notification'])
        self.assertFalse(self.tick(8201))

    def test_ingress_retry_deduplicates_across_restart_but_reused_id_with_new_time_does_not(self):
        self.assertEqual(self.store.ingest([alert()], 1010), 1)
        self.restart()
        self.assertEqual(self.store.ingest([alert()], 1011), 0)
        self.assertEqual(self.store.ingest([alert(start_at='2026-10-30T00:00:00Z')], 1012), 1)
        self.tick(4600)
        self.assertIn('新增 2 条', self.sent[0]['text'])

    def test_unknown_first_notification_and_cooldown_survive_restart(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.assertTrue(self.tick(1010))
        self.assertFalse(self.sent[0]['disable_notification'])
        self.store.ingest([alert(2, 'new-rule')], 1100)
        self.restart()
        self.assertFalse(self.tick(1200))
        self.assertTrue(self.tick(2811))
        self.assertIn('新增 1 条', self.sent[-1]['text'])

    def test_critical_upgrade_bypasses_cooldown_and_pending_digest(self):
        self.store.ingest([alert(1, 'trusted')], 1010)
        self.tick(1010)
        self.store.ingest([alert(3)], 1100)
        self.store.schedule(4600)
        self.store.policy['critical_scenarios'] = ['trusted']
        self.store.ingest([alert(2, 'trusted')], 4600)
        self.tick(4600)
        self.assertIn('紧急告警', self.sent[-1]['text'])
        self.assertFalse(self.sent[-1]['disable_notification'])

    def test_simulation_never_pages_even_if_rule_is_explicitly_critical(self):
        self.store.policy['critical_scenarios'] = ['trusted']
        self.store.ingest([alert(1, 'trusted', simulated=True, meta=[{'key': 'severity', 'value': 'critical'}])], 1010)
        self.assertFalse(self.tick(1010))
        self.tick(4600)
        self.assertTrue(self.sent[0]['disable_notification'])
        self.assertIn('模拟', self.sent[0]['text'])

    def test_attacker_metadata_cannot_set_severity_or_service(self):
        self.store.ingest([alert(meta=[{'key': 'severity', 'value': 'critical'}, {'key': 'service', 'value': 'root'}])], 1010)
        self.assertFalse(self.tick(1010))
        self.assertEqual(self.incident()['level'], 0)

    def test_surge_requires_multiple_active_minutes(self):
        self.store.ingest([alert(i) for i in range(1, 101)], 1020)
        self.assertFalse(self.tick(1020))
        self.store.ingest([alert(101)], 1080)
        self.assertFalse(self.tick(1080))
        self.store.ingest([alert(102)], 1140)
        self.assertTrue(self.tick(1140))
        self.assertIn('需要关注', self.sent[-1]['text'])

    def test_multiple_unknown_rules_share_a_notification_budget(self):
        self.store.ingest([alert(1, 'unknown1')], 1010)
        self.tick(1010)
        self.store.ingest([alert(i, 'unknown'+str(i)) for i in range(2, 20)], 1011)
        self.assertFalse(self.tick(1011))
        self.assertTrue(self.tick(1071))
        self.assertEqual(len(self.sent), 2)
        self.assertIn('涉及 18 类事件', self.sent[-1]['text'])

    def test_failures_keep_queue_and_new_arrivals_are_coalesced_after_restart(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.store.schedule(1010)
        self.assertFalse(self.store.deliver_one(lambda p: (False, None), 1010))
        self.store.ingest([alert(2, 'new-rule')], 1011)
        self.restart()
        self.assertFalse(self.tick(1014))
        self.assertTrue(self.tick(1016))
        self.assertIn('新增 2 条', self.sent[-1]['text'])
        self.assertEqual(self.store.status(1016)['pending'], 0)

    def test_retry_after_is_persisted_and_respected_by_critical_queue(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.store.schedule(1010)
        self.store.deliver_one(lambda p: (False, 180), 1010)
        self.store.policy['critical_scenarios'] = ['critical']
        self.store.ingest([alert(2, 'critical')], 1011)
        self.restart()
        self.assertFalse(self.tick(1189))
        self.assertTrue(self.tick(1191))
        self.assertIn('紧急告警', self.sent[-1]['text'])

    def test_arrival_during_delivery_is_not_marked_delivered(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.store.schedule(1010)
        def concurrent_send(payload):
            self.store.ingest([alert(2, 'new-rule')], 1011)
            return self.send(payload)
        self.store.deliver_one(concurrent_send, 1010)
        self.assertEqual(self.incident()['reported'], 1)
        self.assertEqual(self.incident()['count'], 2)
        self.tick(2811)
        self.assertIn('新增 1 条', self.sent[-1]['text'])

    def fault(self, start=1000, state='fault'):
        for now in range(start, start+61, 20):
            self.store.observe({'core': state}, now)

    def test_health_debounce_ack_recovery_and_relapse(self):
        self.store.observe({'core': 'fault'}, 1000)
        self.assertFalse(self.tick(1000))
        for now in (1020, 1040, 1060):
            self.store.observe({'core': 'fault'}, now)
        self.assertTrue(self.tick(1060))
        identifier = self.incident()['id']
        self.assertTrue(self.store.acknowledge(identifier))
        self.restart()
        self.assertFalse(self.tick(1400))
        for now in range(1400, 1521, 20):
            self.store.observe({'core': 'ok'}, now)
        self.assertTrue(self.tick(1520))
        self.assertIn('故障恢复', self.sent[-1]['text'])
        self.assertFalse(self.tick(1540))
        self.fault(1600)
        self.assertTrue(self.tick(1660))
        self.assertNotEqual(self.incident()['id'], identifier)

    def test_gap_does_not_count_as_continuous_failure_and_unknown_is_not_recovery(self):
        self.store.observe({'core': 'fault'}, 1000)
        self.store.observe({'core': 'fault'}, 1200)
        self.assertFalse(self.tick(1200))
        self.fault(1200)
        self.tick(1260)
        for now in range(1280, 1461, 20):
            self.store.observe({'core': 'unknown'}, now)
        self.assertEqual(self.incident()['state'], 'open')
        self.assertEqual(self.incident()['level'], 2)

    def test_unknown_health_escalates_to_fault_despite_attention_cooldown(self):
        self.fault(state='unknown')
        self.tick(1060)
        self.assertIn('需要关注', self.sent[-1]['text'])
        self.fault(1080)
        self.tick(1140)
        self.assertIn('紧急告警', self.sent[-1]['text'])

    def test_unacknowledged_reminders_are_spaced_from_successful_delivery(self):
        self.fault()
        self.tick(1060)
        self.assertFalse(self.tick(1359))
        self.assertTrue(self.tick(1361))
        self.assertFalse(self.tick(1960))
        self.assertTrue(self.tick(1962))
        self.assertFalse(self.tick(2861))
        self.assertTrue(self.tick(2863))
        self.assertFalse(self.tick(6462))

    def test_upgrade_removes_stale_pending_attention(self):
        self.store.ingest([alert(1, 'trusted')], 1010)
        self.store.schedule(1010)
        self.store.policy['critical_scenarios'] = ['trusted']
        self.store.ingest([alert(2, 'trusted')], 1011)
        self.tick(1011)
        self.assertIn('紧急告警', self.sent[0]['text'])
        self.assertFalse(self.tick(1012))

    def test_recovery_replaces_unsent_fault_and_describes_missed_delivery(self):
        self.fault()
        self.store.schedule(1060)
        for now in range(1080, 1201, 20):
            self.store.observe({'core': 'ok'}, now)
        self.tick(1200)
        self.assertEqual(len(self.sent), 1)
        self.assertIn('异常期间的通知尚未确认送达', self.sent[0]['text'])

    def test_config_and_database_are_private_and_unknown_policy_is_rejected(self):
        path = self.root/'notify.json'
        path.write_text(json.dumps(self.config))
        self.assertEqual(notify.load_config(path)['node'], 'test-node')
        self.assertEqual(os.stat(self.store.database_path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.root/'state').st_mode & 0o777, 0o700)
        self.config['policy']['typo'] = 5
        path.write_text(json.dumps(self.config))
        with self.assertRaises(ValueError):
            notify.load_config(path)

    def test_large_unicode_messages_stay_within_telegram_limit(self):
        self.store.ingest([alert(i, '😀'*100+str(i)) for i in range(1, 20)], 1010)
        self.tick(1010)
        self.assertLessEqual(len(self.sent[0]['text'].encode('utf-16-le'))//2, 4096)

    def test_destination_change_never_replays_old_chat_queue_with_new_credentials(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.store.schedule(1010)
        other = notify.Store(dict(self.config, chat_id='456', bot_token='456:DEF'), now=1011)
        try:
            self.assertNotEqual(other.database_path, self.store.database_path)
            self.assertFalse(other.deliver_one(self.send, 2000))
        finally:
            other.close()
        self.assertTrue(self.store.deliver_one(self.send, 2000))
        self.assertEqual(self.sent[-1]['chat_id'], '-123')

    def test_undelivered_critical_is_retained_across_long_gap_in_alerts(self):
        self.store.policy['critical_scenarios'] = ['critical']
        self.store.ingest([alert(1, 'critical')], 1010)
        self.store.ingest([alert(2, 'critical')], 5000)
        self.assertTrue(self.tick(5000))
        self.assertEqual(self.incident()['count'], 2)
        self.assertEqual(self.incident()['reported'], 2)

    def test_buttons_require_a_matching_bot_with_callback_support(self):
        bot = {'bot_token': self.config['bot_token'], 'chat_id': self.config['chat_id']}
        Path(self.config['bot_config']).write_text(json.dumps(bot))
        self.assertIsNone(self.store._buttons('a'*24))
        bot['notification_callbacks'] = 1
        Path(self.config['bot_config']).write_text(json.dumps(bot))
        self.assertEqual(self.store._buttons('a'*24)['inline_keyboard'][0][0]['callback_data'], 'na:'+'a'*24)
        bot['chat_id'] = 789
        Path(self.config['bot_config']).write_text(json.dumps(bot))
        self.assertIsNone(self.store._buttons('a'*24))


class NotificationHTTP(unittest.TestCase):
    send = NotificationPolicy.send
    tick = NotificationPolicy.tick

    def setUp(self):
        NotificationPolicy.setUp(self)
        config = dict(self.config, port=0)
        self.server = notify.make_server(config, self.store)
        self.config['port'] = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def post(self, data, secret=None):
        message = urllib.request.Request(f'http://127.0.0.1:{self.server.server_port}/alerts',
            data=json.dumps(data).encode(), headers={'Authorization': 'Bearer '+(secret or self.config['secret'])})
        with urllib.request.urlopen(message, timeout=2) as response:
            return json.load(response)

    def test_authentication_and_atomic_batch_rejection(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.post([alert()], secret='wrong')
        self.assertEqual(error.exception.code, 403)
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.post([alert(), {'scenario': 42}])
        self.assertEqual(error.exception.code, 400)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 0)
        self.assertEqual(self.post([alert()]), {'accepted': 1})
        self.assertEqual(self.post([alert()]), {'accepted': 0})

    def test_queue_receipt_is_distinct_from_telegram_acceptance(self):
        result = request(self.config, 'test', [alert()])
        self.assertFalse(request(self.config, 'receipt', {'id': result['test_id']})['accepted'])
        self.tick(9999999999)
        self.assertTrue(request(self.config, 'receipt', {'id': result['test_id']})['accepted'])

    def test_disk_failure_returns_retryable_status(self):
        with patch.object(self.store, 'ingest', side_effect=OSError('disk full')):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.post([alert()])
        self.assertEqual(error.exception.code, 503)


class NotificationInstallation(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    OVERRIDES = '''
notify_ready() { return 0; }
systemctl() {
 record systemctl "$@"
 if [[ "$1" == show ]]; then
  if [[ -f "$NOTIFY_UNIT" ]]; then printf 'LoadState=loaded\\nFragmentPath=%s\\nActiveState=active\\nUnitFileState=enabled\\n' "$NOTIFY_UNIT"; else echo 'LoadState=not-found'; fi
 fi
 return 0
}
'''

    def setup_telegram(self):
        result = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\nn\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        return self.config/'notifications/crowdsec-1key-telegram.yaml'

    def enable(self, overrides=''):
        return self.run_shell('enable_smart_notifications', overrides=self.OVERRIDES+overrides)

    def test_enable_restore_preserves_decisions_and_original_delivery_configuration(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        profiles = (self.config/'profiles.yaml').read_bytes()
        result = self.enable()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('/alerts', notification.read_text())
        self.assertEqual((self.config/'profiles.yaml').read_bytes(), profiles)
        config = json.loads((self.config/'crowdbastion-notify.json').read_text())
        self.assertEqual(config['policy']['digest_seconds'], 3600)
        result = self.run_shell('disable_smart_notifications', overrides=self.OVERRIDES)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(notification.read_bytes(), original)

        self.assertFalse(json.loads((self.config/'crowdbastion-notify.json').read_text())['enabled'])

    def test_failed_core_validation_restores_direct_route_and_service_files(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        result = self.enable('\ncrowdsec() { return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(notification.read_bytes(), original)
        self.assertFalse((self.config/'crowdbastion-notify.json').exists())
        self.assertFalse((self.base/'etc/systemd/system/crowdbastion-notify.service').exists())

    def test_failed_readiness_does_not_switch_crowdsec_to_unavailable_worker(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        result = self.enable('\nnotify_ready() { return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(notification.read_bytes(), original)

    def test_disable_all_stops_worker_and_removes_notification_routes(self):
        notification = self.setup_telegram()
        self.assertEqual(self.enable().returncode, 0)
        result = self.run_shell('disable_telegram_notification', 'y\n', self.OVERRIDES)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(notification.exists())
        self.assertNotIn('notifications:', (self.config/'profiles.yaml').read_text())
        self.assertIn('disable --now crowdbastion-notify.service', self.commands())

    def test_unknown_unit_is_not_overwritten(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        unit = self.base/'etc/systemd/system/crowdbastion-notify.service'
        unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\nExecStart=/other/program\n')
        result = self.enable()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('/other/program', unit.read_text())
        self.assertEqual(notification.read_bytes(), original)

    def test_invalid_update_does_not_stop_running_notification_service(self):
        self.setup_telegram()
        self.assertEqual(self.enable().returncode, 0)
        path = self.config/'crowdbastion-notify.json'
        config = json.loads(path.read_text())
        config['policy']['typo'] = 0
        path.write_text(json.dumps(config))
        self.trace.write_text('')
        self.assertNotEqual(self.enable().returncode, 0)
        self.assertNotIn('stop crowdbastion-notify', self.commands())
        self.assertNotIn('restart crowdbastion-notify', self.commands())


class NotificationBot(unittest.TestCase):
    send = NotificationPolicy.send
    tick = NotificationPolicy.tick
    incident = NotificationPolicy.incident
    fault = NotificationPolicy.fault
    stop_server = NotificationHTTP.stop_server

    def setUp(self):
        NotificationHTTP.setUp(self)
        spec = importlib.util.spec_from_file_location('notification_bot', ROOT/'lib/crowdsec_bot.py')
        self.bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bot)
        self.bot.CSCLI_CONFIG = self.config['crowdsec_config']
        self.bot.BOT_TOKEN = self.config['bot_token']
        self.bot.ADMIN_USER_ID, self.bot.ADMIN_CHAT_ID = 12, -123
        (self.root/notify.CONFIG_NAME).write_text(json.dumps(self.config))
        self.fault()
        self.tick(1060)
        self.identifier = self.incident()['id']

    def callback(self, prefix='na', user=12, chat=-123):
        return {'callback_query': {'id': 'c', 'from': {'id': user}, 'data': prefix+':'+self.identifier,
                'message': {'message_id': 1, 'chat': {'id': chat}}}}

    def test_only_authorized_admin_in_bound_chat_can_acknowledge(self):
        with patch.object(self.bot, 'tg_request'):
            self.bot.handle_update(self.callback(user=13))
            self.bot.handle_update(self.callback(chat=-124))
            self.assertEqual(self.incident()['ack'], 0)
            self.bot.handle_update(self.callback())
        self.assertEqual(self.incident()['ack'], 1)
        self.assertEqual(self.incident()['state'], 'open')

    def test_detail_is_read_only_and_foreign_destination_cannot_acknowledge(self):
        with patch.object(self.bot, 'tg_request') as telegram:
            self.bot.handle_update(self.callback('nd'))
            self.assertTrue(any(call.args[0] == 'sendMessage' for call in telegram.call_args_list))
            self.assertEqual(self.incident()['ack'], 0)
            self.bot.BOT_TOKEN = '456:DIFFERENT'
            self.bot.handle_update(self.callback())
        self.assertEqual(self.incident()['ack'], 0)


if __name__ == '__main__':
    unittest.main()

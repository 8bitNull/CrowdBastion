"""Regressions discovered by repeated notification review. No host/TG mutations."""
import json
import os
import socket
import subprocess
from pathlib import Path
import sys
import threading
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import yaml
import test_notify as fixtures
import test_custom_bot_api as transport_fixtures
import crowdsec_bot_api as transport
import crowdsec_notify_setup as setup
from crowdsec_notify_client import request

notify = fixtures.notify


class PolicyReview(unittest.TestCase):
    setUp = fixtures.NotificationPolicy.setUp
    send = fixtures.NotificationPolicy.send
    tick = fixtures.NotificationPolicy.tick
    fault = fixtures.NotificationPolicy.fault
    incident = fixtures.NotificationPolicy.incident

    def test_broken_optional_bot_configuration_cannot_block_critical_delivery(self):
        Path(self.config['bot_config']).write_text('[]')
        self.fault()
        self.assertTrue(self.tick(1060))
        self.assertIn('紧急告警', self.sent[0]['text'])
        self.assertNotIn('reply_markup', self.sent[0])

    def test_non_object_service_configuration_has_a_controlled_validation_error(self):
        path = self.root/'notify.json'
        path.write_text('[]')
        with self.assertRaises(ValueError):
            notify.load_config(path)

    def test_new_confirmed_failure_retracts_queued_recovery_of_same_component(self):
        self.fault()
        self.tick(1060)
        for now in range(1080, 1201, 20):
            self.store.observe({'core': 'ok'}, now)
        self.store.schedule(1200)
        self.store.deliver_one(lambda p: (False, None), 1200)
        self.fault(1220)
        self.assertTrue(self.tick(1280))
        self.assertIn('紧急告警', self.sent[-1]['text'])
        self.assertFalse(self.tick(1281))

    def test_component_removed_from_monitoring_does_not_keep_reminding_or_claim_recovery(self):
        self.fault()
        self.tick(1060)
        self.store.observe({'core': 'optional'}, 1100)
        self.tick(1400)
        self.assertEqual(self.store.status(1400)['open_critical'], 0)
        self.assertNotIn('故障仍待处理', self.sent[-1]['text'])
        self.assertNotIn('故障恢复', self.sent[-1]['text'])

    def test_resumed_monitoring_cancels_an_unsent_scope_removal_message(self):
        self.fault()
        self.tick(1060)
        self.store.observe({'core': 'optional'}, 1100)
        self.store.observe({'core': 'ok'}, 1120)
        self.assertFalse(self.tick(1120))
        self.assertEqual(len(self.sent), 1)

    def test_failed_pending_delivery_is_reported_until_that_queue_item_succeeds(self):
        self.fault()
        self.store.schedule(1060)
        self.store.deliver_one(lambda payload: (False, None), 1060)
        path = self.root/notify.CONFIG_NAME
        path.write_text(json.dumps(self.config))
        with patch.object(sys, 'argv', ['notify', 'status', str(self.root)]), \
                patch.object(setup, 'request', return_value=self.store.status(1061)):
            self.assertEqual(setup.main(), 1)
        # Another successful message does not resolve this failed queue item.
        identifier = self.store.test_message(1061)
        self.store.deliver_one(self.send, 1061)
        self.assertTrue(self.store._get('test:'+identifier))
        self.assertEqual(self.store.status(1062)['state'], 'delivery_failed')
        self.assertTrue(self.tick(1066))
        self.assertEqual(self.store.status(1066)['state'], 'ready')

    def test_api_backoff_survives_failure_to_write_optional_transport_diagnostics(self):
        self.fault()
        response = transport_fixtures.Response({'ok': False, 'error_code': 429,
            'parameters': {'retry_after': 300}})
        opener = transport_fixtures.Opener([response])
        with patch.object(notify, 'Store', return_value=self.store), \
                patch.object(notify, 'make_server', return_value=MagicMock()), \
                patch.object(notify.threading, 'Thread'), \
                patch.object(notify.time, 'time', return_value=1100), \
                patch.object(notify.time, 'sleep', side_effect=SystemExit), \
                patch.object(transport.urllib.request, 'build_opener', return_value=opener), \
                patch.object(transport, '_write_state', side_effect=OSError('diagnostics unavailable')):
            with self.assertRaises(SystemExit):
                notify.run(self.config)
        self.assertGreaterEqual(self.store._get('api_retry'), 1400)

    def test_status_fails_if_health_collection_stalls_while_sender_is_alive(self):
        path = self.root/notify.CONFIG_NAME
        path.write_text(json.dumps(self.config))
        report = {'pending': 0, 'open_critical': 0, 'heartbeat_age': 1,
                  'health_age': 3600, 'last_delivery': 0, 'last_failure': 0}
        with patch.object(sys, 'argv', ['notify', 'status', str(self.root)]), \
                patch.object(setup, 'request', return_value=report):
            self.assertEqual(setup.main(), 1)

    def test_optional_bot_fifo_is_rejected_without_blocking_the_sender(self):
        path = Path(self.config['bot_config'])
        os.mkfifo(path)
        self.fault()
        script = '''import json, sys
from crowdsec_notify import Store
store = Store(json.load(sys.stdin))
sent = []
store.schedule(1060)
store.deliver_one(lambda payload: (sent.append(payload) is None, None), 1060)
print(json.dumps(sent))
store.close()
'''
        env = {**os.environ, 'PYTHONPATH': str(fixtures.ROOT/'lib')+os.pathsep+os.environ.get('PYTHONPATH', '')}
        result = subprocess.run([sys.executable, '-c', script], input=json.dumps(self.config),
                                text=True, capture_output=True, timeout=5, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('紧急告警', json.loads(result.stdout)[0]['text'])

    def test_status_respects_configured_health_interval_and_initial_unknown_state(self):
        report = {'heartbeat_age': 1, 'health_age': 1500}
        self.assertEqual(setup.worker_state(report, 600), 'ready')
        self.assertEqual(setup.worker_state({'heartbeat_age': 1, 'health_age': None}), 'health_pending')

    def test_failed_http_receiver_thread_causes_worker_restart(self):
        receiver, health = MagicMock(), MagicMock()
        receiver.is_alive.return_value = False
        health.is_alive.return_value = True
        with patch.object(notify, 'Store', return_value=self.store), \
                patch.object(notify, 'make_server', return_value=MagicMock()), \
                patch.object(notify.threading, 'Thread', side_effect=[receiver, health]), \
                patch.object(notify.time, 'sleep', side_effect=SystemExit), \
                patch.object(notify, 'TelegramClient') as client:
            with self.assertRaises(ValueError):
                notify.run(self.config)
        client.return_value.request.assert_not_called()


class InstallationReview(unittest.TestCase):
    setUp = fixtures.NotificationInstallation.setUp
    run_shell = fixtures.NotificationInstallation.run_shell
    commands = fixtures.NotificationInstallation.commands
    setup_telegram = fixtures.NotificationInstallation.setup_telegram
    enable = fixtures.NotificationInstallation.enable
    OVERRIDES = fixtures.NotificationInstallation.OVERRIDES

    def test_existing_worker_update_without_notification_route_does_not_claim_success(self):
        notification = self.setup_telegram()
        self.assertEqual(self.enable().returncode, 0)
        original = notification.read_bytes()
        profile = self.config/'profiles.yaml'
        config = yaml.safe_load(profile.read_text())
        config.pop('notifications')
        profile.write_text(yaml.safe_dump(config))
        self.trace.write_text('')
        result = self.enable()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(notification.read_bytes(), original)
        self.assertNotIn('restart crowdbastion-notify', self.commands())
        self.assertNotIn('stop crowdbastion-notify', self.commands())

    def test_first_install_rollback_disables_before_removing_unit_file(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        overrides = '''
systemctl() {
 record systemctl "$@"
 case "$*" in
  show*) echo 'LoadState=not-found';;
  'enable crowdbastion-notify.service') ln -s "$NOTIFY_UNIT" "$NOTIFY_UNIT.enabled";;
  'disable crowdbastion-notify.service') [[ -f "$NOTIFY_UNIT" ]] || return 1; rm -f "$NOTIFY_UNIT.enabled";;
  'restart crowdbastion-notify.service') return 1;;
 esac
 return 0
}
'''
        result = self.enable(overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(notification.read_bytes(), original)
        enabled = self.base/'etc/systemd/system/crowdbastion-notify.service.enabled'
        self.assertFalse(enabled.is_symlink(), result.stdout+result.stderr)
        self.assertNotIn('回滚不完整', result.stderr)

    def test_unreadable_previous_service_state_stops_update_before_mutation(self):
        notification = self.setup_telegram()
        self.assertEqual(self.enable().returncode, 0)
        original = notification.read_bytes()
        self.trace.write_text('')
        overrides = '''
systemctl() {
 record systemctl "$@"
 if [[ "$*" == *ActiveState* || "$1" == is-active ]]; then return 1; fi
 if [[ "$1" == show ]]; then printf 'LoadState=loaded\\nFragmentPath=%s\\n' "$NOTIFY_UNIT"; fi
 return 0
}
'''
        result = self.enable(overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(notification.read_bytes(), original)
        self.assertNotIn('restart crowdbastion-notify', self.commands())
        self.assertNotIn('stop crowdbastion-notify', self.commands())

    def test_runtime_enablement_is_preserved_when_update_rolls_back(self):
        self.setup_telegram()
        self.assertEqual(self.enable().returncode, 0)
        self.trace.write_text('')
        overrides = '''
systemctl() {
 record systemctl "$@"
 if [[ "$1" == show ]]; then
  printf 'LoadState=loaded\\nFragmentPath=%s\\nActiveState=active\\nUnitFileState=enabled-runtime\\n' "$NOTIFY_UNIT"
 fi
 return 0
}
notify_ready() { return 1; }
'''
        self.assertNotEqual(self.enable(overrides).returncode, 0)
        commands = self.commands()
        self.assertIn('disable crowdbastion-notify.service', commands)
        self.assertIn('enable --runtime crowdbastion-notify.service', commands)


class ReceiverReview(unittest.TestCase):
    setUp = fixtures.NotificationHTTP.setUp
    stop_server = fixtures.NotificationHTTP.stop_server

    def test_incomplete_requests_are_bounded_and_do_not_prevent_later_ingress(self):
        ready = threading.Event()
        entered = []
        lock = threading.Lock()
        original = self.server.RequestHandlerClass.setup

        def started(handler):
            original(handler)
            with lock:
                entered.append(True)
                if len(entered) == 16:
                    ready.set()

        clients = []
        with patch.object(self.server.RequestHandlerClass, 'setup', started):
            try:
                for _ in range(16):
                    clients.append(socket.create_connection(self.server.server_address, timeout=2))
                self.assertTrue(ready.wait(3))
                with self.assertRaises(urllib.error.HTTPError) as failure:
                    request(self.config, 'status')
                self.assertEqual(failure.exception.code, 503)
            finally:
                for client in clients:
                    client.close()
        deadline = notify.time.monotonic()+3
        while True:
            try:
                self.assertEqual(request(self.config, 'status')['pending'], 0)
                break
            except urllib.error.HTTPError:
                if notify.time.monotonic() >= deadline:
                    raise
                notify.time.sleep(0.01)


if __name__ == '__main__':
    unittest.main()

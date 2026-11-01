"""Approved notification cadence and concurrent delivery; no Telegram traffic."""
import unittest

import test_notify as fixtures

alert = fixtures.alert


class NotificationNoise(unittest.TestCase):
    send = fixtures.NotificationPolicy.send
    tick = fixtures.NotificationPolicy.tick
    restart = fixtures.NotificationPolicy.restart
    incident = fixtures.NotificationPolicy.incident

    def setUp(self):
        fixtures.NotificationPolicy.setUp(self)
        self.config['policy'].update(attention_interval_seconds=3600, digest_seconds=21600)
        self.store.policy.update(self.config['policy'])

    def test_first_attention_is_timely_and_new_rules_share_hour_across_restart(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.assertTrue(self.tick(1010))
        self.store.ingest([alert(2, 'other-rule'), alert(3, 'new-rule')], 1100)
        self.restart()
        self.assertFalse(self.tick(4609))
        self.assertTrue(self.tick(4611))
        self.assertIn('新增 2 条告警，涉及 2 类事件', self.sent[-1]['text'])
        self.assertFalse(self.tick(8212))

    def test_ordinary_waits_six_hours_and_empty_windows_are_silent(self):
        self.store.ingest([alert()], 1010)
        self.restart()
        self.assertFalse(self.tick(22599))
        self.assertTrue(self.tick(22601))
        self.assertTrue(self.sent[0]['disable_notification'])
        self.assertIn('新增 1 条告警', self.sent[0]['text'])
        self.assertFalse(self.tick(44202))

    def replaced_during_send(self, ordinary=False, accepted=True, retry_after=None):
        scenario = 'crowdsecurity/http-probing' if ordinary else 'new-rule'
        now = 22600 if ordinary else 1010
        self.store.ingest([alert(1, scenario)], 1010)
        self.store.schedule(now)
        def concurrent_send(payload):
            self.store.ingest([alert(2, scenario)], now+1)
            self.store.schedule(now+1)
            if accepted:
                self.send(payload)
            return accepted, retry_after
        self.assertEqual(self.store.deliver_one(concurrent_send, now), accepted)
        return now

    def test_attention_replaced_during_success_waits_hour_without_losing_new_event(self):
        now = self.replaced_during_send()
        self.assertEqual(self.incident()['reported'], 1)
        self.assertEqual(self.incident()['count'], 2)
        self.assertFalse(self.store.deliver_one(self.send, now+2))
        self.restart()
        self.assertFalse(self.tick(now+3599))
        self.assertTrue(self.tick(now+3602))
        self.assertIn('新增 1 条告警', self.sent[-1]['text'])

    def test_digest_replaced_during_success_waits_six_hours_without_losing_new_event(self):
        now = self.replaced_during_send(ordinary=True)
        self.assertFalse(self.store.deliver_one(self.send, now+2))
        self.restart()
        self.assertFalse(self.tick(now+21599))
        self.assertTrue(self.tick(now+21602))
        self.assertIn('新增 1 条告警', self.sent[-1]['text'])

    def test_failure_of_replaced_attention_keeps_backoff_and_unsent_counts_after_restart(self):
        now = self.replaced_during_send(accepted=False)
        self.assertEqual(self.store.status(now+1)['retrying'], 1)
        self.restart()
        self.assertFalse(self.tick(now+4))
        self.assertTrue(self.tick(now+6))
        self.assertIn('新增 2 条告警', self.sent[-1]['text'])

    def test_failure_of_replaced_digest_keeps_backoff(self):
        now = self.replaced_during_send(ordinary=True, accepted=False)
        self.assertEqual(self.store.status(now+1)['retrying'], 1)
        self.assertFalse(self.tick(now+4))
        self.assertTrue(self.tick(now+6))
        self.assertIn('新增 2 条告警', self.sent[-1]['text'])

    def test_replaced_snapshot_429_retains_retry_diagnostics_and_global_backoff(self):
        now = self.replaced_during_send(accepted=False, retry_after=180)
        self.assertEqual(self.store.status(now+1)['retrying'], 1)
        self.store.policy['critical_scenarios'] = ['critical']
        self.store.ingest([alert(3, 'critical')], now+2)
        self.config['policy']['critical_scenarios'] = ['critical']
        self.restart()
        self.assertFalse(self.tick(now+179))
        self.assertTrue(self.tick(now+181))
        self.assertIn('紧急告警', self.sent[-1]['text'])

    def test_due_aggregate_cannot_bypass_window_or_starve_critical(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.store.schedule(1010)
        # Simulate an aggregate persisted before another completed send closed the window.
        with self.store.transaction():
            self.store._set('attention', 4610)
        self.assertFalse(self.store.deliver_one(self.send, 1011))
        self.store.policy['critical_scenarios'] = ['critical']
        self.store.ingest([alert(2, 'critical')], 1012)
        self.assertTrue(self.tick(1012))
        self.assertIn('紧急告警', self.sent[-1]['text'])
        critical = self.store.db.execute('SELECT id FROM incidents WHERE level=2').fetchone()[0]
        self.assertTrue(self.store.acknowledge(critical))
        self.assertFalse(self.tick(1013))
        self.assertTrue(self.tick(4611))
        self.assertIn('需要关注', self.sent[-1]['text'])

    def test_stale_digest_cannot_bypass_persisted_window(self):
        self.store.ingest([alert()], 1010)
        self.store.schedule(22600)
        with self.store.transaction():
            self.store._set('digest', 22600)
        self.restart()
        self.assertFalse(self.store.deliver_one(self.send, 22601))
        self.assertTrue(self.tick(44201))


if __name__ == '__main__':
    unittest.main()

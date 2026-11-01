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

    def test_grouping_preserves_service_and_simulation_boundaries(self):
        scenario = 'crowdsecurity/http-probing'
        self.config['scenario_services'] = {scenario: 'edge-a'}
        self.store.ingest([alert(1, scenario), alert(2, scenario, simulated=True)], 1010)
        self.config['scenario_services'][scenario] = 'edge-b'
        self.store.ingest([alert(3, scenario)], 1011)
        self.assertTrue(self.tick(22600))
        text = self.sent[-1]['text']
        self.assertIn('新增 3 条告警，涉及 3 类事件', text)
        self.assertIn('模拟 · edge-a', text)
        self.assertIn('• edge-a', text)
        self.assertIn('• edge-b', text)

    def test_digest_six_line_limit_counts_rule_groups_and_preserves_all_snapshots(self):
        scenarios = self.store.policy['routine_scenarios'][:7]
        self.store.ingest([alert(i+1, scenario) for i, scenario in enumerate(scenarios)], 1010)
        self.store.ingest([alert(8, scenarios[0])], 3000)
        self.store.ingest([alert(9, scenarios[0])], 5000)
        self.assertTrue(self.tick(22600))
        text = self.sent[-1]['text']
        self.assertIn('新增 9 条告警，涉及 7 类事件', text)
        self.assertIn('• '+scenarios[0]+'：新增 3 条', text)
        self.assertEqual(text.count('\n• '), 6)
        self.assertIn('另有 1 类事件', text)
        self.assertEqual(self.store.db.execute('SELECT SUM(reported) FROM incidents').fetchone()[0], 9)
        self.assertFalse(self.tick(44201))

    def test_recovery_after_failed_fault_send_keeps_unconfirmed_delivery_note(self):
        for now in (1000, 1020, 1040, 1060):
            self.store.observe({'core': 'fault'}, now)
        self.store.schedule(1060)
        def concurrent_failure(payload):
            for now in range(1080, 1201, 20):
                self.store.observe({'core': 'ok'}, now)
            return False, None
        self.assertFalse(self.store.deliver_one(concurrent_failure, 1060))
        self.restart()
        self.assertTrue(self.tick(1201))
        self.assertIn('异常期间的通知尚未确认送达', self.sent[-1]['text'])

    def test_relapse_during_old_fault_send_does_not_recreate_cancelled_recovery(self):
        for now in (1000, 1020, 1040, 1060):
            self.store.observe({'core': 'fault'}, now)
        self.store.schedule(1060)
        old_identifier = self.incident()['id']
        def concurrent_relapse(payload):
            for now in range(1080, 1201, 20):
                self.store.observe({'core': 'ok'}, now)
            for now in range(1220, 1281, 20):
                self.store.observe({'core': 'fault'}, now)
            return self.send(payload)
        self.assertTrue(self.store.deliver_one(concurrent_relapse, 1060))
        self.assertNotEqual(self.incident()['id'], old_identifier)
        self.assertTrue(self.tick(1281))
        self.assertIn('紧急告警', self.sent[-1]['text'])
        self.assertFalse(self.tick(1282))
        self.assertEqual(self.store.status(1282)['pending'], 0)

    def test_six_hour_digest_merges_idle_incidents_of_same_rule_and_sources(self):
        scenario = 'crowdsecurity/http-probing'
        for identifier, now, source in [(1, 1010, '192.0.2.10'), (2, 3000, '192.0.2.10'),
                                        (3, 6000, '192.0.2.11')]:
            self.store.ingest([alert(identifier, scenario, source={'value': source})], now)
        self.assertTrue(self.tick(22600))
        text = self.sent[-1]['text']
        self.assertIn('新增 3 条告警，涉及 1 类事件', text)
        self.assertEqual(text.count('• '+scenario), 1)
        self.assertIn('留存记录来源 2 个', text)
        self.assertEqual(self.store.db.execute('SELECT SUM(reported) FROM incidents').fetchone()[0], 3)
        self.assertFalse(self.tick(44201))

    def test_hourly_attention_merges_unsent_idle_incidents_of_same_rule(self):
        self.store.ingest([alert(1, 'new-rule')], 1010)
        self.assertTrue(self.tick(1010))
        self.store.ingest([alert(2, 'new-rule')], 3000)
        self.store.ingest([alert(3, 'new-rule')], 4900)
        self.assertTrue(self.tick(4901))
        self.assertIn('新增 2 条告警，涉及 1 类事件', self.sent[-1]['text'])
        self.assertEqual(self.sent[-1]['text'].count('• new-rule'), 1)
        self.assertFalse(self.tick(8502))

    def test_routine_upgraded_during_success_keeps_sent_counts_and_pages_new_counts(self):
        self.store.policy.update(surge_count=2, surge_minutes=1)
        scenario = 'crowdsecurity/http-probing'
        self.store.ingest([alert(1, scenario)], 22600)
        self.store.schedule(22600)
        def concurrent_send(payload):
            self.store.ingest([alert(2, scenario)], 22601)
            return self.send(payload)
        self.assertTrue(self.store.deliver_one(concurrent_send, 22600))
        row = self.incident()
        self.assertEqual((row['level'], row['count'], row['reported']), (1, 2, 1))
        self.assertEqual((row['notified'], row['reminder'], row['next_notice']), (0, 0, 0))
        self.restart()
        self.assertTrue(self.tick(22602))
        self.assertIn('需要关注', self.sent[-1]['text'])
        self.assertIn('新增 1 条告警', self.sent[-1]['text'])

    def test_attention_upgraded_during_success_preserves_critical_first_notice(self):
        self.store.ingest([alert(1, 'trusted')], 1010)
        self.store.schedule(1010)
        def concurrent_send(payload):
            self.store.policy['critical_scenarios'] = ['trusted']
            self.store.ingest([alert(2, 'trusted')], 1011)
            return self.send(payload)
        self.assertTrue(self.store.deliver_one(concurrent_send, 1010))
        row = self.incident()
        self.assertEqual((row['level'], row['count'], row['reported']), (2, 2, 1))
        self.assertEqual((row['notified'], row['reminder'], row['next_notice']), (0, 0, 0))
        self.restart()
        self.assertTrue(self.tick(1012))
        self.assertIn('紧急告警', self.sent[-1]['text'])
        self.assertEqual(self.incident()['reminder'], 1)

    def health_changes_during_send(self, optional=False):
        for now in (1000, 1020, 1040, 1060):
            self.store.observe({'core': 'fault'}, now)
        self.store.schedule(1060)
        def concurrent_send(payload):
            if optional:
                self.store.observe({'core': 'optional'}, 1080)
            else:
                for now in range(1080, 1201, 20):
                    self.store.observe({'core': 'ok'}, now)
            return self.send(payload)
        self.assertTrue(self.store.deliver_one(concurrent_send, 1060))
        self.assertTrue(self.tick(1201))
        self.assertNotIn('异常期间的通知尚未确认送达', self.sent[-1]['text'])

    def test_recovery_during_successful_fault_send_reports_confirmed_delivery(self):
        self.health_changes_during_send()
        self.assertIn('故障恢复', self.sent[-1]['text'])

    def test_scope_change_during_successful_fault_send_reports_confirmed_delivery(self):
        self.health_changes_during_send(optional=True)
        self.assertIn('停止监测', self.sent[-1]['text'])

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

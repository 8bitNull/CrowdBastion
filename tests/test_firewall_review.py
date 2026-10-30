"""Cycle-review regressions: bypasses, ownership, interrupted workers and rollback."""
import json
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

import crowdsec_firewall_migrate as migrate
import crowdsec_firewall_runtime as runtime
import test_firewall_runtime as prior


class RuntimeReview(unittest.TestCase):
    setUp = prior.RuntimeTests.setUp
    rules = prior.RuntimeTests.rules
    coverage = prior.RuntimeTests.coverage

    def test_accept_or_return_inside_bouncer_chain_cannot_prove_protection(self):
        for action in ('ACCEPT', 'RETURN'):
            rules = '-A CROWDSEC_CHAIN -j '+action+'\n'+self.rules()
            self.assertEqual(self.coverage(v4=rules), 'fault')

    def test_rule_enumeration_failure_is_unknown_not_confirmed_absence(self):
        with patch.object(runtime, 'run', side_effect=ValueError('query failed')):
            with self.assertRaises(ValueError):
                runtime.chain_coverage(self.config, True)

    def test_known_startup_fault_is_not_lost_when_another_probe_fails(self):
        events = []
        with patch.object(runtime, 'cron_risks', return_value=['root-cron:4']), \
             patch.object(runtime, 'restore_services', side_effect=ValueError('unreadable')), \
             patch.object(runtime, 'docker_present', return_value=False), \
             patch.object(runtime, 'chain_coverage', return_value='ok'), \
             patch.object(runtime, 'emit', side_effect=lambda *event: events.append(event)):
            self.assertEqual(runtime.audit(self.config), 1)
        self.assertIn(('firewall_startup', 'fault'), events)

    def test_legacy_vps_dropin_is_reused_without_rewrite(self):
        self.dropin.write_bytes(runtime.LEGACY_ORDER)
        before = self.dropin.stat().st_ino
        with patch.object(runtime, 'docker_present', return_value=True):
            runtime.write_startup(self.config, self.dropin)
        self.assertEqual(self.dropin.read_bytes(), runtime.LEGACY_ORDER)
        self.assertEqual(self.dropin.stat().st_ino, before)

    def test_earlier_enabled_service_survives_later_unreadable_service(self):
        def command(argv, **kwargs):
            if 'netfilter-persistent.service' in argv:
                return subprocess.CompletedProcess(argv, 0, 'loaded\n' if 'show' in argv else 'enabled\n')
            return subprocess.CompletedProcess(argv, 1, '')
        events = []
        with patch.object(runtime, 'cron_risks', return_value=[]), \
             patch.object(runtime, 'run', side_effect=command), \
             patch.object(runtime, 'docker_present', return_value=False), \
             patch.object(runtime, 'chain_coverage', return_value='ok'), \
             patch.object(runtime, 'emit', side_effect=lambda *event: events.append(event)):
            self.assertEqual(runtime.audit(self.config), 1)
        self.assertIn(('firewall_startup', 'fault'), events)


class MigrationReview(unittest.TestCase):
    setUp = prior.MigrationTests.setUp
    snapshot = prior.MigrationTests.snapshot
    switched = prior.MigrationTests.switched

    def test_unreferenced_ipset_cannot_satisfy_decision_coverage(self):
        with patch.object(migrate, 'live', return_value=self.rows), \
             patch.object(migrate, 'iptables_references', return_value={4: {'crowdsec-blacklists-0'}, 6: set()}), \
             patch.object(migrate, 'run', return_value=subprocess.CompletedProcess([], 0,
                 'add crowdsec-blacklists-9 198.51.100.7\n')):
            with self.assertRaises(ValueError):
                self.tx.membership()

    def test_unreferenced_native_set_in_another_table_cannot_supply_coverage(self):
        payload = prior.native_payload()
        good = payload['nftables'][0]['set']
        unrelated = dict(good, table='unrelated')
        good['elem'] = []
        payload['nftables'].append({'set': unrelated})
        with patch.object(migrate, 'live', return_value=self.rows), patch.object(migrate, 'run', return_value=
                subprocess.CompletedProcess([], 0, json.dumps(payload))):
            with self.assertRaises(ValueError):
                self.tx.membership(native=True)

    def test_native_membership_requires_both_hooks(self):
        payload = prior.native_payload()
        payload['nftables'] = [item for item in payload['nftables']
                              if item.get('chain', {}).get('hook') != 'forward'
                              and item.get('rule', {}).get('chain') != 'forward']
        with patch.object(migrate, 'live', return_value=self.rows), patch.object(migrate, 'run', return_value=
                subprocess.CompletedProcess([], 0, json.dumps(payload))):
            with self.assertRaises(ValueError):
                self.tx.membership(native=True)

    def test_native_early_accept_does_not_count_as_covered(self):
        payload = prior.native_payload()
        payload['nftables'].insert(2, {'rule': {'family': 'ip', 'table': 'crowdsec', 'chain': 'input',
                                               'expr': [{'accept': None}]}})
        with patch.object(migrate, 'live', return_value=self.rows), patch.object(migrate, 'run', return_value=
                subprocess.CompletedProcess([], 0, json.dumps(payload))):
            with self.assertRaises(ValueError):
                self.tx.membership(native=True)

    def test_same_content_symlink_is_drift_and_is_not_overwritten(self):
        self.switched()
        target = self.root/'administrator-local'
        target.write_bytes(self.tx.local.read_bytes())
        self.tx.local.unlink()
        self.tx.local.symlink_to(target)
        with self.assertRaises(ValueError):
            self.tx.rollback()
        self.assertTrue(self.tx.local.is_symlink())
        self.assertFalse(self.tx.marker('rolled-back'))

    def test_rollback_restores_original_permission_mode(self):
        self.tx.local.write_text('api_key: prior\n')
        self.tx.local.chmod(0o640)
        self.switched()
        self.tx.rollback()
        self.assertEqual(self.tx.local.stat().st_mode & 0o777, 0o640)

    def test_snapshot_failure_does_not_leave_an_unrecoverable_pending_transaction(self):
        real = migrate.atomic
        def fail(path, data):
            if Path(path).name == 'files.json':
                raise OSError('backup disk failure')
            real(path, data)
        with patch.object(self.tx, 'preflight', return_value=(self.identity, self.rows)), \
             patch.object(migrate, 'atomic', side_effect=fail):
            with self.assertRaises(OSError):
                self.tx.start()
        self.assertTrue(self.tx.marker('rolled-back'))
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.commands, [])

    def test_insufficient_timer_window_never_launches_flow(self):
        self.switched()
        metadata = self.tx.metadata()
        metadata['created'] = time.time()-200
        (self.state/'transaction.json').write_text(json.dumps(metadata))
        with patch.object(migrate.subprocess, 'run') as runner:
            with self.assertRaises(ValueError):
                self.tx.verify()
        runner.assert_not_called()
        self.assertFalse(self.tx.marker('flow-launching'))

    def test_rollback_cleans_interrupted_worker_before_stopping_bouncer(self):
        self.switched()
        self.tx.mark('flow-launching')  # Parent died even before flow-active exists.
        events = []
        def command(argv, **kwargs):
            events.append(argv)
            return subprocess.CompletedProcess(argv, 0, 'not-found\n' if '--property=LoadState' in argv else '')
        with patch.object(migrate, 'run', side_effect=command), \
             patch.object(migrate.subprocess, 'run', side_effect=command):
            self.tx.rollback()
        cleanup = next(i for i, argv in enumerate(events) if 'cleanup' in argv)
        stop = events.index(['systemctl', 'stop', runtime.UNIT])
        self.assertLess(cleanup, stop)
        self.assertFalse(self.tx.marker('flow-launching'))

    def test_failed_flow_cleanup_preserves_new_config_and_protection(self):
        self.switched()
        self.tx.mark('flow-active')
        with patch.object(migrate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(ValueError):
                self.tx.rollback()
        self.assertFalse(self.tx.marker('rolled-back'))
        self.assertIn(b'mode: iptables', self.tx.local.read_bytes())
        self.assertNotIn(['systemctl', 'stop', runtime.UNIT], self.commands)

    def test_native_parser_accepts_archived_real_vps_structure(self):
        archive = Path(__file__).resolve().parents[1]/'docs/audit/2026-10-19-second-vps-readonly-evidence.json'
        records = json.loads(archive.read_text())['firewall']['nft_structure_and_counters']
        refs = migrate.native_references({'nftables': records}, self.config)
        self.assertEqual(set(refs), {(4, 'input'), (4, 'forward'), (6, 'input'), (6, 'forward')})
        self.assertTrue(all(refs.values()))

    def test_business_chain_in_nat_cannot_be_hidden_as_bouncer_change(self):
        self.switched()
        before = '*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
        after = before.replace('COMMIT', ':CROWDSEC_CHAIN - [0:0]\n-A CROWDSEC_CHAIN -j ACCEPT\nCOMMIT', 1)
        for binary in ('iptables', 'ip6tables'):
            (self.state/(binary+'.before')).write_text(before)
        with patch.object(migrate, 'chain_coverage', return_value='ok'), \
             patch.object(self.tx, 'admin'), patch.object(migrate, 'run', return_value=
                 subprocess.CompletedProcess([], 0, after)):
            with self.assertRaises(ValueError):
                self.tx.rules()


class FlowReview(unittest.TestCase):
    setUp = prior.FlowTests.setUp
    rows = prior.FlowTests.rows

    def test_lapi_cleanup_failure_does_not_skip_rule_and_interface_cleanup(self):
        (self.root/'flow-active').touch()
        commands = []
        def command(argv, *args, **kwargs):
            commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, 'not-found\n' if '--property=LoadState' in argv
                                               else '[]' if '-j' in argv else '')
        with patch.object(self.flow, 'decisions', side_effect=ValueError('api down')), \
             patch.object(self.flow, 'run', side_effect=command):
            with self.assertRaises(ValueError):
                self.flow.cleanup()
        self.assertIn(['iptables', '-S', 'INPUT'], commands)
        self.assertIn(['ip', 'link', 'del', 'cbfw-in'], commands)
        self.assertTrue((self.root/'flow-active').exists())

    def test_cleanup_failure_cannot_return_a_successful_flow(self):
        def setup():
            self.flow.OWNS = True
        with patch.object(self.flow, 'setup', side_effect=setup), \
             patch.object(self.flow, 'poll', return_value=self.rows(False)), \
             patch.object(self.flow, 'add', side_effect=RuntimeError('test cancelled')), \
             patch.object(self.flow, 'cleanup', side_effect=ValueError('cleanup failed')):
            with self.assertRaises(ValueError):
                self.flow.main('after')
        report = json.loads((self.root/'flow-after.json').read_text())
        self.assertFalse(report['passed'])
        self.assertNotEqual(report['cleanup'], 'done')

    def test_renewal_wait_starts_after_initial_decision_commands_complete(self):
        clock = [100.0]
        probe_times = []
        def add(duration, reason):
            clock[0] += 15  # Slow cscli calls must not shorten the original TTL wait.
        def probe():
            probe_times.append(clock[0])
            return self.rows(True)
        def sleep(seconds):
            clock[0] += seconds
        live = [dict(value=source, id=index, duration='90s', scenario=self.flow.TAG+'-renew')
                for index, source in enumerate(self.flow.SOURCES)]
        with patch.object(self.flow, 'setup'), patch.object(self.flow, 'add', side_effect=add), \
             patch.object(self.flow, 'poll', return_value=self.rows(False)), \
             patch.object(self.flow.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.flow.time, 'sleep', side_effect=sleep), \
             patch.object(self.flow, 'probe', side_effect=probe), \
             patch.object(self.flow, 'decisions', return_value=live), \
             patch.object(self.flow, 'run', return_value=subprocess.CompletedProcess([], 0)):
            self.flow.main('after')
        self.assertGreaterEqual(probe_times[0], 100+15+46)


class ManagerReview(unittest.TestCase):
    import test_workflows as workflows
    setUp = workflows.Workflows.setUp
    run_shell = workflows.Workflows.run_shell
    commands = workflows.Workflows.commands

    def test_pending_migration_blocks_other_mutations_but_allows_read_only_check(self):
        overrides = 'mkdir -p "$FIREWALL_MIGRATION_STATE"'
        result = self.run_shell('locked_operation true', overrides=overrides)
        self.assertEqual(result.returncode, 75, result.stdout+result.stderr)
        result = self.run_shell('main --firewall-check', overrides=overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('check_firewall_runtime', self.commands())

    def test_maintenance_menu_cannot_apply_startup_repair_during_migration(self):
        overrides = 'mkdir -p "$FIREWALL_MIGRATION_STATE"'
        result = self.run_shell('main --firewall-maintenance', '2\n', overrides)
        self.assertEqual(result.returncode, 75, result.stdout+result.stderr)
        self.assertNotIn('repair_firewall_startup', self.commands())

    def test_pending_migration_blocks_cron_hub_entry_too(self):
        result = self.run_shell('hub_maintenance update', overrides='mkdir -p "$FIREWALL_MIGRATION_STATE"')
        self.assertEqual(result.returncode, 75, result.stdout+result.stderr)
        self.assertNotIn('cscli hub update', self.commands())

    def test_completed_transaction_no_longer_blocks_manager(self):
        overrides = 'mkdir -p "$FIREWALL_MIGRATION_STATE"\ntouch "$FIREWALL_MIGRATION_STATE/committed"'
        result = self.run_shell('locked_operation true', overrides=overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()

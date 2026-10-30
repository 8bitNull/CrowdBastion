"""Acceptance-derived checks, with no host firewall or service mutations."""
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml
import crowdsec_firewall_runtime as runtime
import crowdsec_firewall_migrate as migrate


def native_payload():
    records = []
    for family, table, name, value in (
            ('ip', 'crowdsec', 'crowdsec-blacklists-cscli', {'elem': {'val': '198.51.100.7', 'expires': 90000}}),
            ('ip6', 'crowdsec6', 'crowdsec6-blacklists-capi', {'prefix': {'addr': '2001:db8::', 'len': 48}})):
        records.append({'set': {'family': family, 'table': table, 'name': name, 'elem': [value]}})
        for hook in ('input', 'forward'):
            records.append({'chain': {'family': family, 'table': table, 'name': hook, 'hook': hook}})
            records.append({'rule': {'family': family, 'table': table, 'chain': hook, 'expr': [
                {'match': {'op': '==', 'left': {'payload': {'protocol': family, 'field': 'saddr'}}, 'right': '@'+name}},
                {'drop': None}]}})
    return {'nftables': records}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root/'bouncer.yaml'
        self.config.write_text('mode: iptables\napi_key: private-canary\n')
        self.local = Path(str(self.config)+'.local')
        self.dropin = self.root/'dropin.conf'

    def test_cron_scan_finds_both_families_and_rc_local_without_exposing_command(self):
        spool = self.root/'spool/crontabs'
        spool.mkdir(parents=True)
        (spool/'root').write_text('# @reboot iptables-restore < old\n@reboot /sbin/iptables-restore < private\n@reboot ip6tables-restore < private\n')
        (self.root/'rc.local').write_text('nft -f /etc/nftables.conf\n')
        (self.root/'cron.d').mkdir()
        (self.root/'cron.d/managed').write_text('0 * * * * root iptables-restore --noflush < private\n')
        risks = runtime.cron_risks(self.root, self.root/'spool')
        self.assertEqual(len(risks), 4)
        self.assertNotIn('private', '\n'.join(risks))
        self.assertEqual((spool/'root').read_text().count('@reboot'), 3)

    def test_permission_error_does_not_mean_no_startup_risk(self):
        (self.root/'crontab').touch()
        with patch.object(Path, 'read_text', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                runtime.cron_risks(self.root, self.root/'spool')

    def test_family_overrides_preserved_and_all_required_chains_added(self):
        self.local.write_text('api_key: local-canary\niptables_v4_chains: [CUSTOM4]\niptables_v6_chains: [CUSTOM6]\n')
        before = self.config.read_bytes()
        with patch.object(runtime, 'docker_present', return_value=True):
            runtime.write_startup(self.config, self.dropin)
            again = self.local.read_bytes()
            runtime.write_startup(self.config, self.dropin)
        data = yaml.safe_load(self.local.read_text())
        self.assertEqual(self.local.read_bytes(), again)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(data['api_key'], 'local-canary')
        self.assertEqual(data['iptables_v6_chains'], ['CUSTOM6', 'INPUT', 'FORWARD', 'DOCKER-USER'])
        self.assertEqual(data['iptables_v4_chains'], ['CUSTOM4', 'INPUT', 'FORWARD', 'DOCKER-USER'])
        self.assertEqual(self.dropin.read_bytes(), runtime.ORDER)
        self.assertEqual(self.local.stat().st_mode & 0o777, 0o600)

    def test_no_docker_does_not_create_docker_dependency_or_chain(self):
        with patch.object(runtime, 'docker_present', return_value=False):
            runtime.write_startup(self.config, self.dropin)
        self.assertEqual(yaml.safe_load(self.local.read_text())['iptables_v6_chains'], ['INPUT', 'FORWARD'])
        self.assertFalse(self.dropin.exists())

    def test_conflicting_dropin_rejected_before_local_write(self):
        self.dropin.write_text('[Unit]\nAfter=other.service\n')
        with patch.object(runtime, 'docker_present', return_value=True):
            with self.assertRaises(ValueError):
                runtime.write_startup(self.config, self.dropin)
        self.assertFalse(self.local.exists())

    def rules(self):
        return '\n'.join('-A '+c+' -j CROWDSEC_CHAIN' for c in ('INPUT', 'FORWARD', 'DOCKER-USER'))+'\n-A CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists-0 src -j DROP\n'

    def coverage(self, v4=None, v6=None):
        def execute(argv):
            output = (v6 if argv[0] == 'ip6tables' else v4) or self.rules()
            if argv[0] == 'ip6tables':
                output = output.replace('crowdsec-blacklists', 'crowdsec6-blacklists')
            return subprocess.CompletedProcess(argv, 0, output)
        with patch.object(runtime, 'run', side_effect=execute):
            return runtime.chain_coverage(self.config, True)

    def test_coverage_requires_both_families(self):
        self.assertEqual(self.coverage(), 'ok')
        self.assertEqual(self.coverage(v6='-P INPUT ACCEPT\n'), 'fault')

    def test_coverage_refuses_accept_before_bouncer(self):
        self.assertEqual(self.coverage(v4='-A INPUT -j ACCEPT\n'+self.rules()), 'fault')

    def test_coverage_refuses_conditional_jump_or_empty_drop_chain(self):
        self.assertEqual(self.coverage(v4=self.rules().replace('-A INPUT -j', '-A INPUT -p tcp -j')), 'fault')
        self.assertEqual(self.coverage(v4=self.rules().replace(' src -j DROP', ' dst -j DROP')), 'fault')

    def test_negated_or_unrelated_drop_set_does_not_prove_coverage(self):
        self.assertEqual(self.coverage(v4=self.rules().replace('--match-set', '! --match-set')), 'fault')
        self.assertEqual(self.coverage(v4=self.rules().replace('crowdsec-blacklists-0', 'unrelated')), 'fault')

    def test_disabled_family_is_not_dual_stack_success(self):
        self.local.write_text('disable_ipv6: true\n')
        self.assertEqual(self.coverage(), 'unknown')

    def test_restore_service_enabled_is_reported(self):
        with patch.object(runtime, 'run', side_effect=lambda argv, **kw: subprocess.CompletedProcess(
                argv, 0, 'loaded\n' if 'show' in argv else 'enabled\n' if 'netfilter-persistent.service' in argv else 'disabled\n')):
            self.assertEqual(runtime.restore_services(), ['netfilter-persistent.service'])

    def test_unreadable_docker_status_keeps_paths_unknown(self):
        events = []
        with patch.object(runtime, 'emit', side_effect=lambda *x: events.append(x)), \
             patch.object(runtime, 'cron_risks', side_effect=PermissionError), \
             patch.object(runtime, 'docker_present', side_effect=ValueError('unreadable')), \
             patch.object(runtime, 'chain_coverage') as coverage:
            self.assertEqual(runtime.audit(self.config), 2)
        coverage.assert_not_called()
        self.assertIn(('firewall_paths', 'unknown'), events)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root/'bouncer.yaml'
        self.config.write_text('mode: nftables\napi_url: http://127.0.0.1:8080/\napi_key: secret-canary\n')
        self.state = self.root/'transaction'
        self.dropin = self.root/'systemd/order.conf'
        self.tx = migrate.Migration(self.state, self.config, self.dropin)
        self.original = self.config.read_bytes()
        self.identity = ['203.0.113.4', '41000', '203.0.113.5', '53322']
        self.commands = []
        def execute(argv, **kw):
            self.commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, 'not-found\n' if '--property=LoadState' in argv else '')
        self.run = patch.object(migrate, 'run', side_effect=execute).start()
        self.addCleanup(patch.stopall)
        patch.object(self.tx, 'wait_coverage').start()
        patch.object(migrate, 'iptables_references', return_value={4: {'crowdsec-blacklists-0', 'crowdsec-blacklists-2'}, 6: {'crowdsec6-blacklists-0', 'crowdsec6-blacklists-2'}}).start()
        self.rows = [{'type': 'ban', 'scope': 'Ip', 'value': '198.51.100.7', 'duration': '2m'}]

    def snapshot(self):
        self.tx.snapshot(self.identity, self.rows)

    def switched(self):
        self.snapshot()
        self.tx.mark('switch-started')
        migrate.atomic(self.tx.local, (self.state/'local.applied').read_bytes())
        migrate.atomic(self.dropin, runtime.ORDER)
        self.tx.mark('awaiting-verification')

    def test_snapshot_retains_credentials_and_immutable_rollback_helpers(self):
        self.tx.local.write_text('api_key: local-secret\ncustom: keep\n')
        self.snapshot()
        applied = yaml.safe_load((self.state/'local.applied').read_text())
        self.assertEqual(applied['api_key'], 'local-secret')
        self.assertEqual(applied['custom'], 'keep')
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertTrue((self.state/'crowdsec_firewall_flow.py').is_file())
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)

    def test_rollback_restores_existing_local_and_absent_dropin(self):
        self.tx.local.write_text('api_key: local-secret\n')
        self.switched()
        self.tx.rollback()
        self.assertEqual(self.tx.local.read_text(), 'api_key: local-secret\n')
        self.assertFalse(self.dropin.exists())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertTrue(self.tx.marker('rolled-back'))
        self.tx.rollback()  # Idempotent.

    def test_rollback_refuses_later_administrator_change(self):
        self.switched()
        self.tx.local.write_text('api_key: changed-later\n')
        with self.assertRaises(ValueError):
            self.tx.rollback()
        self.assertEqual(self.tx.local.read_text(), 'api_key: changed-later\n')
        self.assertFalse(any('stop' in cmd for cmd in self.commands))

    def test_base_removal_is_drift(self):
        self.switched()
        self.config.unlink()
        with self.assertRaises(ValueError):
            self.tx.drift()

    def test_partial_write_rollback_accepts_original_or_applied_files(self):
        self.snapshot()
        self.tx.mark('switch-started')
        migrate.atomic(self.tx.local, (self.state/'local.applied').read_bytes())
        self.tx.rollback()
        self.assertFalse(self.tx.local.exists())
        self.assertFalse(self.dropin.exists())

    def test_committed_transaction_never_rolls_back(self):
        self.switched()
        self.tx.mark('committed')
        self.tx.rollback()
        self.assertEqual(yaml.safe_load(self.tx.local.read_text())['mode'], 'iptables')
        self.assertEqual(self.commands.count(['systemctl', 'stop', runtime.UNIT]), 0)

    def test_kernel_membership_accepts_superset_but_rejects_missing_ipv6(self):
        rows = self.rows+[{'type': 'ban', 'scope': 'Range', 'value': '2001:db8::/64', 'duration': '2m'}]
        with patch.object(migrate, 'live', return_value=rows), patch.object(migrate, 'run', return_value=
                subprocess.CompletedProcess([], 0, 'add crowdsec-blacklists-2 198.51.100.0/24\nadd crowdsec6-blacklists-2 2001:db8::/48\n')):
            self.assertEqual(self.tx.membership()['missing'], 0)
        with patch.object(migrate, 'live', return_value=rows), patch.object(migrate, 'run', return_value=
                subprocess.CompletedProcess([], 0, 'add unrelated 198.51.100.7\n')):
            with self.assertRaises(ValueError):
                self.tx.membership()

    def test_native_rollback_coverage_reads_prefix_and_timed_elements(self):
        rows = self.rows+[{'type': 'ban', 'scope': 'Range', 'value': '2001:db8::/64', 'duration': '2m'}]
        payload = native_payload()
        with patch.object(migrate, 'live', return_value=rows), patch.object(migrate, 'run', return_value=
                subprocess.CompletedProcess([], 0, json.dumps(payload))):
            self.assertEqual(self.tx.membership(native=True)['missing'], 0)

    def test_expiring_decisions_do_not_cause_false_missing(self):
        with patch.object(migrate, 'live', return_value=[dict(self.rows[0], duration='5s')]):
            self.assertEqual(self.tx.membership()['expected'], 0)

    def test_old_ssh_connection_cannot_commit_even_after_flow(self):
        self.switched()
        self.tx.mark('flow-verified')
        with patch.object(migrate, 'ssh_identity', return_value=self.identity):
            with self.assertRaises(ValueError):
                self.tx.commit()
        self.assertFalse(self.tx.marker('committed'))

    def test_new_ssh_alone_is_not_sufficient_to_commit(self):
        self.switched()
        with patch.object(migrate, 'ssh_identity', return_value=[self.identity[0], '42000', *self.identity[2:]]):
            with self.assertRaises(ValueError):
                self.tx.commit()
        self.assertFalse(self.tx.marker('committed'))

    def test_expired_window_cannot_commit(self):
        self.switched()
        data = self.tx.metadata()
        data['created'] = time.time()-500
        (self.state/'transaction.json').write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.tx.pending()

    def test_incomplete_flow_cleanup_does_not_allow_commit(self):
        self.switched()
        def flow(*args, **kwargs):
            if 'cleanup' in args[0]:
                return subprocess.CompletedProcess([], 0)
            (self.state/'flow-after.json').write_text('{"passed":true,"cleanup":"failed"}')
            return subprocess.CompletedProcess([], 0)
        with patch.object(migrate.subprocess, 'run', side_effect=flow):
            with self.assertRaises(ValueError):
                self.tx.verify()
        self.assertFalse(self.tx.marker('flow-verified'))

    def test_successful_staged_migration_requires_flow_then_new_ssh(self):
        with patch.object(self.tx, 'preflight', return_value=(self.identity, self.rows)), \
             patch.object(self.tx, 'hold'), patch.object(self.tx, 'admin'), \
             patch.object(self.tx, 'rules'):
            self.tx.start()
            self.assertTrue(self.tx.marker('awaiting-verification'))
            self.assertFalse(self.tx.marker('committed'))
            timer = next(i for i, cmd in enumerate(self.commands) if cmd[0] == 'systemd-run')
            stop = self.commands.index(['systemctl', 'stop', runtime.UNIT])
            self.assertLess(timer, stop)
            def flow(*args, **kwargs):
                if 'cleanup' in args[0]:
                    return subprocess.CompletedProcess([], 0)
                (self.state/'flow-after.json').write_text('{"passed":true,"cleanup":"done"}')
                return subprocess.CompletedProcess([], 0)
            with patch.object(migrate.subprocess, 'run', side_effect=flow):
                self.tx.verify()
            with patch.object(migrate, 'ssh_identity', return_value=[self.identity[0], '42000', *self.identity[2:]]), \
                 patch.object(self.tx, 'membership'):
                self.tx.commit()
            self.assertTrue(self.tx.marker('committed'))
            self.assertIn(['systemctl', 'stop', migrate.TIMER+'.timer'], self.commands)
            applied = yaml.safe_load(self.tx.local.read_text())
            self.assertEqual(applied['iptables_v6_chains'], ['INPUT', 'FORWARD', 'DOCKER-USER'])

    def test_boot_restore_conflict_stops_before_transaction_creation(self):
        with patch.object(migrate, 'cron_risks', return_value=['root-cron:2']):
            with self.assertRaises(ValueError):
                self.tx.start()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.commands, [])

    def test_nonroot_custom_unit_is_rejected_before_switch(self):
        self.run.side_effect = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, 'crowdsec\n')
        with patch.object(migrate, 'cron_risks', return_value=[]), \
             patch.object(migrate, 'restore_services', return_value=[]), \
             patch.object(migrate.shutil, 'which', return_value='/usr/bin/mock'):
            with self.assertRaises(migrate.MigrationError):
                self.tx.start()
        self.assertFalse(self.state.exists())

    def test_custom_chain_configuration_is_not_silently_migrated(self):
        self.config.write_text('mode: nftables\niptables_chain: CUSTOM\n')
        with patch.object(migrate, 'cron_risks', return_value=[]), \
             patch.object(migrate, 'restore_services', return_value=[]):
            with self.assertRaises(ValueError):
                self.tx.start()
        self.assertFalse(self.state.exists())

    def test_switch_failure_runs_rollback_and_keeps_backup(self):
        real = migrate.atomic
        with patch.object(self.tx, 'preflight', return_value=(self.identity, self.rows)), \
             patch.object(self.tx, 'hold'), patch.object(self.tx, 'admin'), \
             patch.object(migrate, 'atomic', wraps=migrate.atomic) as write:
            # Fail only the live drop-in write, after local override was applied.
            def fail(path, data):
                if Path(path) == self.dropin:
                    raise OSError('disk failure')
                real(path, data)
            write.side_effect = fail
            with self.assertRaises(OSError):
                self.tx.start()
        self.assertTrue(self.tx.marker('rolled-back'))
        self.assertFalse(self.tx.local.exists())
        self.assertTrue((self.state/'base.before').exists())

    def test_admin_rule_uses_recorded_ipv6_and_ssh_port(self):
        self.identity = ['2001:db8::2', '41000', '2001:db8::1', '2222']
        self.snapshot()
        self.run.side_effect = lambda argv, **kw: subprocess.CompletedProcess(argv, 1 if '-C' in argv else 0, '')
        self.tx.admin(True)
        argv = self.run.call_args.args[0]
        self.assertEqual(argv[0], 'ip6tables')
        self.assertIn('2222', argv)
        self.assertNotIn('53322', argv)

    def test_lapi_library_errors_never_disclose_api_key(self):
        with patch.object(migrate, '_live', side_effect=ValueError('Invalid header secret-canary')):
            with self.assertRaises(migrate.MigrationError) as error:
                migrate.live(self.config)
        self.assertNotIn('secret-canary', str(error.exception))

    def test_malformed_yaml_diagnostics_do_not_disclose_key(self):
        self.config.write_text('api_key: [secret-canary\n')
        with self.assertRaises(migrate.MigrationError) as error:
            migrate.live(self.config)
        self.assertNotIn('secret-canary', str(error.exception))

    def test_time_parser_and_ban_filter(self):
        self.assertEqual(migrate.seconds('1m2.5s'), 62.5)
        self.assertEqual(migrate.seconds('-2s'), 0)
        with self.assertRaises(ValueError):
            migrate.seconds('garbage')
        self.assertEqual(migrate.networks(self.rows), {ipaddress.ip_network('198.51.100.7/32')})


class StartupTransactions(unittest.TestCase):
    import test_workflows as workflows
    setUp = workflows.Workflows.setUp
    run_shell = workflows.Workflows.run_shell
    commands = workflows.Workflows.commands

    def setup_config(self):
        config = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        config.parent.mkdir()
        config.write_text('mode: iptables\napi_key: preserve\n')
        local = Path(str(config)+'.local')
        local.write_text('api_key: preserve\n')
        overrides = '''
source "$SCRIPT_DIR/lib/firewall.sh"
FIREWALL_DROPIN="$TRACE.order"
firewall_write_startup() {
 printf 'api_key: preserve\\niptables_v4_chains: [INPUT, FORWARD]\\n' > "$1.local"
 printf '[Unit]\\nAfter=docker.service\\n' > "$FIREWALL_DROPIN"
}
check_firewall_runtime() { return 0; }
'''
        return local, overrides

    def test_failure_restores_override_and_removes_new_dropin(self):
        local, overrides = self.setup_config()
        overrides += '''
systemctl() {
 record systemctl "$@"
 if [[ "$1" == restart && ! -f "$TRACE.restart-attempt" ]]; then
  touch "$TRACE.restart-attempt"; return 1
 fi
 return 0
}
'''
        result = self.run_shell('repair_firewall_startup', overrides=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(local.read_text(), 'api_key: preserve\n')
        self.assertFalse(Path(str(self.trace)+'.order').exists())
        self.assertEqual(self.commands().count('restart crowdsec-firewall-bouncer'), 2)

    def test_repeat_startup_repair_does_not_restart(self):
        _, overrides = self.setup_config()
        result = self.run_shell('repair_firewall_startup && repair_firewall_startup', overrides=overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands().count('restart crowdsec-firewall-bouncer'), 1)

    def test_unchanged_config_with_lost_rules_still_restarts_to_repair(self):
        _, overrides = self.setup_config()
        overrides += '''
check_firewall_runtime() {
 local count=0
 [[ ! -f "$TRACE.check-count" ]] || read -r count < "$TRACE.check-count"
 count=$((count+1)); printf '%s\\n' "$count" > "$TRACE.check-count"
 [[ "$count" != 2 ]]
}
'''
        result = self.run_shell('repair_firewall_startup && repair_firewall_startup', overrides=overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands().count('restart crowdsec-firewall-bouncer'), 2)

    def test_chain_failure_rolls_back_startup_changes(self):
        local, overrides = self.setup_config()
        overrides += '\ncheck_firewall_runtime() { return 1; }\n'
        result = self.run_shell('repair_firewall_startup', overrides=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(local.read_text(), 'api_key: preserve\n')
        self.assertFalse(Path(str(self.trace)+'.order').exists())


class FlowTests(unittest.TestCase):
    def setUp(self):
        import crowdsec_firewall_flow as flow
        self.flow = flow
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patches = [patch.object(flow, 'BASE', self.root), patch.object(flow, 'OWNS', False)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def rows(self, blocked):
        return [dict(source=src, destination=dst, protocol=proto, reachable=not blocked if src in self.flow.SOURCES else True)
                for src in self.flow.SOURCES+self.flow.CONTROL
                for dst in (['198.18.233.1', '198.18.234.2'] if ':' not in src else ['fd42:cb:1::1', 'fd42:cb:2::2'])
                for proto in ['tcp', 'udp']]

    def test_empty_or_incomplete_probe_cannot_pass(self):
        self.assertFalse(self.flow.expect([], True))
        self.assertFalse(self.flow.expect(self.rows(True)[:-1], True))
        self.assertTrue(self.flow.expect(self.rows(True), True))
        self.assertFalse(self.flow.expect(self.rows(True), False))
        self.assertTrue(self.flow.expect(self.rows(False), False))

    def test_control_failure_cannot_pass_blocking_test(self):
        rows = self.rows(True)
        for row in rows:
            if row['source'] in self.flow.CONTROL:
                row['reachable'] = False
        self.assertFalse(self.flow.expect(rows, True))

    def test_existing_flow_failure_never_cleans_someone_elses_resources(self):
        with patch.object(self.flow, 'setup', side_effect=ValueError('collision')), \
             patch.object(self.flow, 'cleanup') as cleanup:
            with self.assertRaises(ValueError):
                self.flow.main('after')
        cleanup.assert_not_called()
        self.assertEqual(json.loads((self.root/'flow-after.json').read_text())['cleanup'], 'not-started')

    def test_route_collision_stops_before_creating_resources(self):
        def command(argv, **kwargs):
            output = '[{"dst":"198.18.0.0/15"}]' if 'route' in argv else '[]'
            return subprocess.CompletedProcess(argv, 0, output)
        with patch.object(self.flow, 'run', side_effect=command) as runner:
            with self.assertRaises(ValueError):
                self.flow.setup()
        self.assertFalse((self.root/'flow-active').exists())
        self.assertFalse(any(call.args[0][0] == 'systemd-run' for call in runner.call_args_list))

    def test_cleanup_failure_preserves_active_marker_for_timer_retry(self):
        (self.root/'flow-active').touch()
        rows = [{'scenario': self.flow.TAG+'-short', 'value': self.flow.SOURCES[0], 'id': 123}]
        with patch.object(self.flow, 'decisions', return_value=rows), \
             patch.object(self.flow, 'run', side_effect=ValueError('delete failed')):
            with self.assertRaises(ValueError):
                self.flow.cleanup()
        self.assertTrue((self.root/'flow-active').exists())


if __name__ == '__main__':
    unittest.main()

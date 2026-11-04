"""Offline ownership/loader and network transaction tests; never host sysctl writes."""
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import crowdbastion_change as change
from test_change_transactions import Timer, Resources

try: network = importlib.import_module('crowdbastion_network')
except ModuleNotFoundError: network = None

KEY = 'net.ipv4.tcp_syn_retries'
OTHER = 'net.ipv4.tcp_fin_timeout'

class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(network, 'ownership-aware network module missing')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.base.chmod(0o700)
        self.host = self.base/'host'
        for directory in ('etc/sysctl.d', 'run/sysctl.d', 'usr/local/lib/sysctl.d', 'usr/lib/sysctl.d', 'proc/sys/net/ipv4', 'etc/cron.d'):
            (self.host/directory).mkdir(parents=True)
        for key, value in ((KEY, '3'), (OTHER, '15'), ('net.ipv4.tcp_mem', '100 200 300'), ('net.ipv4.tcp_congestion_control', 'bbr')):
            (self.host/'proc/sys'/key.replace('.', '/')).write_text(value+'\n')
        self.manager = self.base/'alternate/crowdbastion.sh'; self.manager.parent.mkdir()
        self.manager.write_text('# fixture manager\n'); (self.manager.parent/'lib').mkdir()
        (self.manager.parent/'lib/helper.py').write_text('# helper\n')
        self.profile = {'version': 1, 'loader': 'systemd', 'keys': [KEY, OTHER], 'sources': []}
        self.calls = []; self.probes = []
        def run(argv):
            self.calls.append(argv)
            if argv[:2] == ['unshare', '--net']:
                return json.dumps({KEY: '6', OTHER: '60'})
            raise AssertionError('unexpected host command '+repr(argv))
        self.backend = network.Backend(self.base/'changes', host_root=self.host, manager=self.manager,
            runtime=self.base/'runtime', cron=self.host/'etc/cron.d/job', run=run,
            probe=lambda: self.probes.append(True) or {'services': {'crowdsec': ['active', '123', '0']}, 'api': 'ok'})
        self.timer = Timer()
        self.engine = change.Engine(self.base/'changes', self.backend, scheduler=self.timer,
            guard=lambda: None, lock_path=self.base/'maintenance.lock')
    def config(self, path, text):
        path = self.host/path; path.write_text(text); return path
    def test_aliases_same_basename_and_loader_precedence_are_distinguished(self):
        self.config('usr/lib/sysctl.d/20-vendor.conf', KEY+'=2\n')
        self.config('etc/sysctl.d/20-vendor.conf', KEY+'=4\n')
        legacy = self.config('etc/sysctl.conf', KEY+'=5\nvm.swappiness=10\n')
        (self.host/'etc/sysctl.d/99-sysctl.conf').symlink_to('../sysctl.conf')
        report = self.backend.audit()
        self.assertEqual(report['loaders']['systemd']['effective'][KEY]['value'], '5')
        self.assertEqual(report['loaders']['procps']['effective'][KEY]['value'], '5')
        row = next(row for row in report['files'] if row['real_path'] == str(legacy))
        self.assertEqual(len(row['aliases']), 2)
        self.assertEqual(len(row['assignments']), 1)
        self.assertNotIn('vm.swappiness', json.dumps(report))
        (self.host/'etc/sysctl.d/99-sysctl.conf').unlink()
        report = self.backend.audit()
        self.assertEqual(report['loaders']['systemd']['effective'][KEY]['value'], '4')
        self.assertEqual(report['loaders']['procps']['effective'][KEY]['value'], '5')
        self.assertEqual(report['running'][KEY], '3')
    def test_dynamic_network_syntax_is_unknown_never_executed(self):
        marker = self.base/'EXECUTED'
        self.config('etc/sysctl.d/10-host.conf', KEY+'=$(touch '+str(marker)+')\nnet.ipv4.tcp_* = 0\n')
        report = network.make_plan(self.backend, self.profile)
        self.assertEqual(report['state'], 'blocked'); self.assertFalse(marker.exists())
        self.assertNotIn('touch', json.dumps(report))
    def test_namespace_failure_has_readable_plan_and_no_writes(self):
        self.backend.run = lambda argv: (_ for _ in ()).throw(OSError('SECRET'))
        self.assertEqual(network.make_plan(self.backend, self.profile)['defaults']['state'], 'unknown')
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text(), '3\n')
        self.assertFalse(self.backend.owned.exists()); self.assertEqual(self.timer.armed, [])
    def test_global_and_unsupported_keys_refuse_before_namespace_commands(self):
        for key in ('net.ipv4.tcp_mem', 'net.core.rmem_max', 'net.ipv4.ip_forward', 'net.ipv4.tcp_syn_retries;echo x'):
            with self.assertRaises(ValueError): network.make_plan(self.backend, dict(self.profile, keys=[key]))
        self.assertEqual(self.calls, [])
    def test_alternate_active_cron_and_current_runtime_are_recognized(self):
        self.backend.runtime.mkdir(); (self.backend.runtime/'current').symlink_to(self.manager.parent, target_is_directory=True)
        manager = self.backend.runtime/'current/manager.sh'; (self.manager.parent/'manager.sh').symlink_to(self.manager.name)
        self.backend.cron.write_text('17 3 * * 2 root bash '+str(manager)+' --update-hub >/dev/null 2>&1\n')
        report = self.backend.audit()['runtime']
        self.assertEqual(report['state'], 'known'); self.assertEqual(report['active'][0]['schedule'], '17 3 * * 2')
        self.assertEqual(report['active'][0]['matches_source'], True)
    def test_unknown_later_overrides_block_and_plain_earlier_overrides_reported(self):
        path = self.config('etc/sysctl.d/20-custom.conf', KEY+'=2\nnet.ipv4.tcp_mem=100 200 300\n')
        report = network.make_plan(self.backend, self.profile)
        self.assertEqual(report['state'], 'blocked')
        self.profile['sources'] = [str(path)]
        report = network.make_plan(self.backend, self.profile)
        self.assertEqual(report['state'], 'ready'); self.assertEqual(report['persistence'], 'selected-overrides')
        self.assertEqual(report['changes'][0]['competing_sources'], [str(path)])
        self.config('etc/sysctl.d/zz-local.conf', KEY+'=9\n')
        self.assertEqual(network.make_plan(self.backend, self.profile)['state'], 'blocked')
    def test_per_key_reads_and_baseline_before_persistence_unchanged_keys_and_repeat(self):
        report = network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertEqual(report['state'], 'staged'); self.assertGreaterEqual(len(self.probes), 3)
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text().strip(), '6')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_fin_timeout').read_text().strip(), '60')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_mem').read_text().strip(), '100 200 300')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_congestion_control').read_text().strip(), 'bbr')
        self.assertEqual(self.engine.commit(report['id'])['state'], 'committed')
        original = self.backend.owned.read_bytes()
        repeated = network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertTrue(repeated['unchanged']); self.assertEqual(self.backend.owned.read_bytes(), original)
    def test_api_failure_restores_without_persisting_and_preserves_diagnostic(self):
        count = [0]
        def probe():
            count[0] += 1
            if count[0] > 2: raise network.CheckError('api_request', 'api_timeout', True)
            return {'services': {}, 'api': 'ok'}
        self.backend.probe = probe
        report = network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertEqual(report['state'], 'rolled_back'); self.assertEqual(report['error_code'], 'apply_failed')
        self.assertEqual(report['diagnostic']['error_code'], 'api_timeout')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text().strip(), '3')
        self.assertFalse(self.backend.owned.exists())
    def test_guard_and_file_ownership_refuse_without_mutating(self):
        self.engine.guard = lambda: (_ for _ in ()).throw(ValueError('unstable'))
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertFalse(self.backend.owned.exists()); self.assertEqual(self.probes, [])
        self.backend.owned.write_text('# current user config\n'+KEY+'=7\n')
        self.assertEqual(network.make_plan(self.backend, self.profile)['state'], 'blocked')
    def test_rollback_partial_drift_continues_and_retry_is_safe(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        (self.host/'proc/sys/net/ipv4/tcp_syn_retries').write_text('9\n')
        self.assertEqual(self.engine.rollback(ident)['state'], 'rollback_incomplete')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_fin_timeout').read_text().strip(), '15')
        self.assertFalse(self.backend.owned.exists()); self.assertEqual(self.timer.cancelled, [])
        (self.host/'proc/sys/net/ipv4/tcp_syn_retries').write_text('6\n')
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
    def test_recovery_snapshot_imports_on_system_python_without_site_packages(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        runtime = self.base/'changes'/ident/'runtime'
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c',
            'import sys; sys.path.insert(0, sys.argv[1]); import crowdbastion_network as n; n.transaction_adapter(sys.argv[2]); print("ok")',
            str(runtime), str(self.base/'changes')], cwd='/', text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stdout.strip(), 'ok')

class MoreNetworkSafety(unittest.TestCase):
    setUp = NetworkTests.setUp
    config = NetworkTests.config
    def test_recovery_snapshot_rolls_back_offline_without_api_or_checkout(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        runtime = self.base/'changes'/ident/'runtime'
        code = '''import sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
import crowdbastion_network as n
from crowdbastion_change import Engine
class Timer:
 def disarm(self, ident): pass
backend = n.Backend(Path(sys.argv[2]), host_root=Path(sys.argv[3]), probe=lambda: (_ for _ in ()).throw(AssertionError('API on rollback')))
e = Engine(Path(sys.argv[2]), backend, scheduler=Timer(), guard=lambda: (_ for _ in ()).throw(AssertionError('guard on rollback')), lock_path=Path(sys.argv[4]))
print(e.rollback(sys.argv[5])['state'])
'''
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c', code, str(runtime), str(self.base/'changes'),
            str(self.host), str(self.base/'maintenance.lock'), ident], cwd='/', text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stdout.strip(), 'rolled_back')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text().strip(), '3')
        self.assertFalse(self.backend.owned.exists())
    def test_same_resource_rollback_after_interrupted_postread_preserves_retry(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        read = self.backend.read; failures = [True]
        def interrupted(resource):
            if resource == {'kind': 'sysctl', 'key': OTHER} and read(resource) == '15' and failures[0]:
                failures[0] = False; raise OSError('interrupted read')
            return read(resource)
        self.backend.read = interrupted
        self.assertEqual(self.engine.rollback(ident)['state'], 'rollback_incomplete')
        self.assertEqual(self.timer.cancelled, [])
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
    def test_commit_checks_sources_runtime_and_deadline_after_verification(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.manager.write_text('# changed manager\n')
        self.assertEqual(self.engine.commit(ident)['state'], 'verification_failed'); self.assertEqual(self.timer.cancelled, [])
        self.manager.write_text('# fixture manager\n')
        import time
        times = [time.time(), 10**12]
        with patch('crowdbastion_change.time.time', side_effect=times):
            self.assertEqual(self.engine.commit(ident)['state'], 'verification_failed')
        self.assertEqual(self.timer.cancelled, [])
    def test_new_source_drift_between_keys_and_persistence_rolls_back(self):
        count = [0]
        def probe():
            count[0] += 1
            if count[0] == 4:
                self.config('etc/sysctl.d/zz-foreign.conf', KEY+'=9\n')
            return {'services': {}, 'api': 'ok'}
        self.backend.probe = probe
        report = network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertEqual(report['state'], 'rolled_back'); self.assertFalse(self.backend.owned.exists())
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text().strip(), '3')
    def test_inline_command_and_multiple_cron_commands_are_unknown(self):
        self.config('etc/sysctl.d/10-host.conf', KEY+'=6; touch /tmp/not-executed\n')
        self.assertEqual(self.backend.audit()['loaders']['systemd']['state'], 'unknown')
        self.backend.cron.write_text('17 3 * * 2 root bash '+str(self.manager)+' --update-hub && bash /old/manager --update-hub\n')
        self.assertEqual(self.backend.audit()['runtime']['state'], 'unknown')
    def test_explicit_kind_selection_and_global_pending_invariant(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.assertEqual(self.engine.status(ident)['kind'], 'network')
        for identifier in (ident, None):
            with self.assertRaises(ValueError): self.engine.select('port-policy', identifier)
        with self.assertRaises(ValueError): self.engine.apply('port-policy', [])
        self.assertEqual(self.engine.select('network'), ident)
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        port_engine = change.Engine(self.engine.root, Resources(), scheduler=self.timer, guard=lambda: None, lock_path=self.engine.lock_path)
        port = port_engine.apply('port-policy', [])['id']
        for identifier in (port, None):
            with self.assertRaises(ValueError): self.engine.select('network', identifier)
    def test_network_cli_refuses_port_kind_for_explicit_and_implicit_actions(self):
        port_engine = change.Engine(self.engine.root, Resources(), scheduler=self.timer, guard=lambda: None, lock_path=self.engine.lock_path)
        ident = port_engine.apply('port-policy', [])['id']
        for action in ('verify', 'commit', 'rollback'):
            for explicit in ([], ['--id', ident]):
                with patch.object(network, 'Backend', return_value=self.backend), patch.object(network, 'Engine', return_value=self.engine), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(network.cli([action]+explicit), 1)
        self.assertEqual(self.engine.status(ident)['state'], 'staged')

    def test_port_cli_refuses_network_kind_without_mutation(self):
        import crowdbastion_port_policy as policy
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        for action in ('verify', 'commit', 'rollback'):
            for explicit in ([], ['--id', ident]):
                with patch('crowdbastion_change.Engine', return_value=self.engine), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(policy.cli([action]+explicit), 1)
        self.assertEqual(self.engine.status(ident)['state'], 'staged')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text().strip(), '6')
    def test_audit_compares_configured_global_and_nonselected_running_values_without_mutation(self):
        self.config('etc/sysctl.d/20-preserved.conf', 'net.ipv4.tcp_mem=10 20 30\nnet.ipv4.tcp_congestion_control=bbr\n')
        report = self.backend.audit()
        self.assertEqual(report['running']['net.ipv4.tcp_mem'], '100 200 300')
        self.assertEqual(report['running']['net.ipv4.tcp_congestion_control'], 'bbr')
        self.assertEqual(report['loaders']['systemd']['effective']['net.ipv4.tcp_mem']['value'], '10 20 30')
    def test_procps_legacy_last_override_refuses_even_with_acknowledged_source(self):
        path = self.config('etc/sysctl.conf', KEY+'=9\n')
        profile = dict(self.profile, loader='procps', sources=[str(path)])
        report = network.make_plan(self.backend, profile)
        self.assertEqual(report['state'], 'blocked'); self.assertIn('later_selected_override', report['blockers'])
        self.assertEqual(report['audit']['loaders']['procps']['effective'][KEY]['value'], '9')
        self.assertNotIn(KEY, report['audit']['loaders']['systemd']['effective'])
    def test_owned_basename_replaces_lower_priority_filename_in_effective_sequence(self):
        path = self.config('run/sysctl.d/99-zz-crowdbastion-network.conf', KEY+'=2\n')
        self.profile['sources'] = [str(path)]
        result = network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertEqual(result['state'], 'staged')
        self.assertEqual(self.engine.verify(result['id'])['state'], 'verified')
        self.assertEqual(path.read_text(), KEY+'=2\n')
    def test_same_value_key_is_persisted_but_not_written_as_runtime_effect(self):
        (self.host/'proc/sys/net/ipv4/tcp_syn_retries').write_text('6\n')
        result = network.apply_network(self.backend, self.profile, engine=self.engine)
        manifest = json.loads((self.engine.root/result['id']/'manifest.json').read_text())
        selected = [effect['resource']['key'] for effect in manifest['effects'] if effect['resource']['kind'] == 'sysctl']
        self.assertEqual(selected, [OTHER]); self.assertIn(KEY+' = 6', self.backend.owned.read_text())
    def test_source_metadata_drift_and_unsafe_ownership_are_not_hidden(self):
        path = self.config('etc/sysctl.d/20-host.conf', KEY+'=2\n')
        self.profile['sources'] = [str(path)]
        report = network.make_plan(self.backend, self.profile)
        row = next(row for row in report['audit']['files'] if row['real_path'] == str(path))
        self.assertEqual(row['uid'], os.geteuid()); self.assertEqual(row['mode'], 0o644)
        path.chmod(0o666)
        self.assertEqual(network.make_plan(self.backend, self.profile)['state'], 'blocked')
    def test_dev_null_masks_report_aliases_without_reading_device(self):
        self.config('usr/lib/sysctl.d/20-vendor.conf', KEY+'=9\n')
        mask = self.host/'etc/sysctl.d/20-vendor.conf'; mask.symlink_to('/dev/null')
        report = self.backend.audit()
        self.assertNotIn(KEY, report['loaders']['systemd']['effective'])
        row = next(row for row in report['files'] if row['real_path'] == '/dev/null')
        self.assertEqual(row['aliases'], [str(mask)]); self.assertTrue(row['masked'])
    def test_parameter_checks_happen_before_persistence(self):
        observations = []
        def probe():
            observations.append(((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text().strip(),
                (self.host/'proc/sys/net/ipv4/tcp_fin_timeout').read_text().strip(), self.backend.owned.exists()))
            return {'services': {}, 'api': 'ok'}
        self.backend.probe = probe
        result = network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertEqual(result['state'], 'staged')
        self.assertEqual(observations[:4], [('3','15',False),('3','15',False),('6','15',False),('6','60',False)])
        self.assertEqual(observations[-1], ('6','60',False))
    def test_unchanged_port_apply_cannot_select_pending_network_transaction(self):
        import crowdbastion_port_policy as policy
        from test_port_policy import Host, config
        host = Host(); backend = policy.Backend(self.engine.root, run=host, unit_dir=self.base/'units')
        engine = change.Engine(self.engine.root, backend, scheduler=self.timer, guard=lambda: None, lock_path=self.engine.lock_path)
        ident = policy.apply_policy(backend, config(), engine=engine)['id']
        self.assertEqual(engine.commit(ident)['state'], 'committed')
        network_id = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        with self.assertRaises(ValueError): policy.apply_policy(backend, config(), engine=engine)
        self.assertEqual(self.engine.status(network_id)['state'], 'staged')
    def test_selected_runtime_drift_during_prepare_and_unchanged_checks_refuses(self):
        original = self.backend.defaults; reads = [0]
        def defaults(keys):
            reads[0] += 1
            if reads[0] == 2: (self.host/'proc/sys/net/ipv4/tcp_syn_retries').write_text('8\n')
            return original(keys)
        self.backend.defaults = defaults
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertFalse(self.backend.owned.exists()); self.assertEqual(self.timer.armed, [])
        self.backend.defaults = original
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        def drift_probe():
            (self.host/'proc/sys/net/ipv4/tcp_syn_retries').write_text('9\n')
            return {'services': {}, 'api': 'ok'}
        self.backend.probe = drift_probe
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
    def test_unchanged_network_apply_cannot_select_pending_port_transaction(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        port_engine = change.Engine(self.engine.root, Resources(), scheduler=self.timer, guard=lambda: None, lock_path=self.engine.lock_path)
        port_id = port_engine.apply('port-policy', [])['id']
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertEqual(port_engine.status(port_id)['state'], 'staged')
    def test_changed_prepared_old_value_is_not_silently_replanned(self):
        audit = self.backend.audit; count = [0]
        def changed():
            count[0] += 1
            if count[0] == 2: (self.host/'proc/sys/net/ipv4/tcp_syn_retries').write_text('8\n')
            return audit()
        self.backend.audit = changed
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.assertFalse(self.backend.owned.exists()); self.assertEqual(self.timer.armed, [])
    def test_fixed_recovery_dispatcher_runs_terminal_network_manifest_without_checkout(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        runtime = self.engine.root/ident/'runtime'
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c',
            'import sys; sys.path.insert(0,sys.argv[1]); from crowdbastion_change import main; raise SystemExit(main(sys.argv[2:]))',
            str(runtime), 'rollback', '--root', str(self.engine.root), '--id', ident], cwd='/',
            text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'rolled_back')
    def test_api_timeout_diagnostics_survive_lazy_forward_boundary(self):
        from crowdsec_firewall_evidence import EvidenceError
        error = EvidenceError('SECRET url token body', 'api_request', 'api_timeout', True, 10.5)
        self.backend.run = lambda argv: 'LoadState=loaded\nActiveState=active\nMainPID=123\nNRestarts=0\n'
        with patch('crowdsec_firewall_evidence.live', side_effect=error):
            with self.assertRaises(network.CheckError) as captured: self.backend.local_probe()
        self.assertEqual(captured.exception.diagnostic['error_code'], 'api_timeout')
        self.assertEqual(captured.exception.diagnostic['duration_seconds'], 10.5)
        self.assertNotIn('SECRET', str(captured.exception)+json.dumps(captured.exception.diagnostic))
    def test_narrower_profile_preserves_previously_owned_unselected_entries(self):
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        narrowed = dict(self.profile, keys=[KEY])
        result = network.apply_network(self.backend, narrowed, engine=self.engine)
        self.assertTrue(result.get('unchanged'))
        self.assertIn(OTHER+' = 60\n', self.backend.owned.read_text())
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_fin_timeout').read_text().strip(), '60')
    def test_status_distinguishes_managed_foreign_and_drifted_owned_file(self):
        self.assertEqual(self.backend.audit()['owned_file']['state'], 'absent')
        self.backend.owned.write_text('# foreign\n')
        self.assertEqual(self.backend.audit()['owned_file']['state'], 'foreign')
        self.backend.owned.unlink()
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.assertEqual(self.backend.audit()['owned_file']['state'], 'managed')
        self.backend.owned.write_text('# changed by user\n')
        self.assertEqual(self.backend.audit()['owned_file']['state'], 'drift')
        self.assertEqual(self.engine.rollback(ident)['state'], 'rollback_incomplete')
    def test_unreadable_source_and_broken_owned_link_remain_readable_unknown_plan(self):
        self.backend.owned.symlink_to('missing-target.conf')
        report = network.make_plan(self.backend, self.profile)
        self.assertEqual(report['state'], 'blocked'); self.assertEqual(report['audit']['state'], 'unknown')
        self.assertEqual(report['audit']['owned_file']['state'], 'unknown')
        self.assertTrue(self.backend.owned.is_symlink())

class AliasOwnership(unittest.TestCase):
    setUp = NetworkTests.setUp
    config = NetworkTests.config
    def alias(self):
        target = self.config('etc/sysctl.conf', KEY+'=2\n')
        alias = self.host/'run/sysctl.d/20-mutable.conf'; alias.symlink_to(target)
        self.profile['sources'] = [str(target)]
        return target, alias
    def unchanged_runtime(self):
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_syn_retries').read_text(), '3\n')
        self.assertEqual((self.host/'proc/sys/net/ipv4/tcp_fin_timeout').read_text(), '15\n')
        self.assertFalse(self.backend.owned.exists()); self.assertEqual(self.timer.armed, [])
    def test_mutable_alias_directory_refuses_acknowledged_trusted_target_before_write(self):
        target, alias = self.alias(); alias.parent.chmod(0o777)
        report = network.make_plan(self.backend, self.profile)
        row = next(row for row in report['audit']['files'] if row['real_path'] == str(target))
        self.assertEqual(report['state'], 'blocked'); self.assertFalse(row['trusted'])
        self.assertEqual(report['audit']['loaders']['systemd']['state'], 'unknown')
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.unchanged_runtime(); self.assertEqual(self.probes, [])
    def test_mutable_mask_alias_and_layer_symlink_chain_are_unknown(self):
        mask = self.host/'run/sysctl.d/20-mask.conf'; mask.symlink_to('/dev/null')
        mask.parent.chmod(0o777)
        report = network.make_plan(self.backend, self.profile)
        self.assertEqual(report['state'], 'blocked')
        row = next(row for row in report['audit']['files'] if row['masked'])
        self.assertFalse(row['trusted'])
        mask.unlink(); mask.parent.chmod(0o755); mask.parent.rmdir()
        safe = self.host/'etc/alternate-sysctl.d'; safe.mkdir()
        self.config('etc/alternate-sysctl.d/20-host.conf', KEY+'=2\n')
        mask.parent.symlink_to(safe, target_is_directory=True)
        (self.host/'run').chmod(0o777)
        self.profile['sources'] = [str(safe/'20-host.conf')]
        self.assertEqual(network.make_plan(self.backend, self.profile)['state'], 'blocked')
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.unchanged_runtime()
    def test_alias_permissions_drift_during_locked_prepare_refuses_before_write(self):
        _, alias = self.alias()
        self.assertEqual(network.make_plan(self.backend, self.profile)['state'], 'ready')
        self.engine.guard = lambda: alias.parent.chmod(0o777)
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.unchanged_runtime(); self.assertEqual(self.probes, [])
    def test_alias_permissions_drift_after_prepare_is_in_preflight_stamp(self):
        _, alias = self.alias()
        def probe():
            alias.parent.chmod(0o777)
            return {'services': {}, 'api': 'ok'}
        self.backend.probe = probe
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.unchanged_runtime()
    def test_trusted_aliases_apply_and_permission_drift_blocks_verify_and_commit(self):
        _, alias = self.alias()
        (self.host/'lib').symlink_to('usr/lib', target_is_directory=True)
        ident = network.apply_network(self.backend, self.profile, engine=self.engine)['id']
        self.assertEqual(self.engine.verify(ident)['state'], 'verified')
        alias.parent.chmod(0o777)
        self.assertEqual(self.engine.verify(ident)['state'], 'verification_failed')
        self.assertEqual(self.engine.commit(ident)['state'], 'verification_failed')
        self.assertEqual(self.timer.cancelled, [])
        alias.parent.chmod(0o755)
        self.assertEqual(self.engine.verify(ident)['state'], 'verified')
    def test_empty_mutable_layer_cannot_gain_unobserved_overrides(self):
        (self.host/'run/sysctl.d').chmod(0o777)
        self.assertEqual(network.make_plan(self.backend, self.profile)['state'], 'blocked')
        with self.assertRaises(ValueError): network.apply_network(self.backend, self.profile, engine=self.engine)
        self.unchanged_runtime()

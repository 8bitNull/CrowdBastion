import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AlertManagement(unittest.TestCase):
    def setUp(self):
        helper = ROOT/'lib/crowdsec_v2bx_alerts.py'
        self.assertTrue(helper.exists(), 'observation alert manager is missing')
        sys.path.insert(0, str(ROOT/'lib'));self.addCleanup(sys.path.remove, str(ROOT/'lib'))
        spec = importlib.util.spec_from_file_location('alerts_test', helper)
        self.mod = importlib.util.module_from_spec(spec);spec.loader.exec_module(self.mod)
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name);self.cs = self.base/'etc/crowdsec'
        self.cs.mkdir(parents=True)
        (self.cs/'acquis.d').mkdir();(self.cs/'parsers/s01-parse').mkdir(parents=True);(self.cs/'scenarios').mkdir()
        self.profiles = self.cs/'profiles.yaml'
        self.original = b'# preserve this exact profile\nname: existing\nfilters: [true]\ndecisions: [{type: ban, duration: 4h}]\non_success: break\n'
        self.profiles.write_bytes(self.original)
        import yaml
        (self.cs/'config.yaml').write_text(yaml.safe_dump({'config_paths': {'config_dir': str(self.cs)}, 'crowdsec_service': {'acquisition_path': str(self.cs/'acquis.yaml'), 'acquisition_dir': str(self.cs/'acquis.d')}, 'api': {'server': {'profiles_path': str(self.profiles)}}}))
        (self.cs/'acquis.yaml').write_text('filenames: [/var/log/auth.log]\nlabels: {type: syslog}\n')
        self.calls = []
        def control(*args):
            self.calls.append(args)
            return 'active' if args[0] == 'is-active' else ''
        class Collector:
            def __init__(inner):
                inner.state = self.base/'collector';inner.state.mkdir(mode=0o700)
                inner.config = self.base/'collector-config.json'
                inner.config.write_text(json.dumps({'sources': [{'name': 'sing'}]}));inner.config.chmod(0o600)
            def managed(inner):pass
            def status(inner):return {'status': 'observing'}
        self.manager = self.mod.AlertManager(self.base, control, lambda *args: '', Collector())
        self.manager.wait_ready = lambda: None

    def test_enable_guard_first_disable_preserves_existing_and_evidence(self):
        self.manager.enable()
        self.assertTrue(self.profiles.read_bytes().startswith(self.mod.GUARD))
        self.assertTrue(self.profiles.read_bytes().endswith(self.original))
        marker = self.manager.state/'keep.txt';marker.write_text('EVIDENCE')
        self.manager.disable()
        self.assertEqual(self.profiles.read_bytes(), self.original)
        self.assertEqual(marker.read_text(), 'EVIDENCE')
        self.assertFalse(self.manager.acquisition.exists())
        self.assertFalse(self.manager.parser.exists());self.assertFalse(self.manager.scenario.exists())

    def test_failed_validation_restores_profile_and_created_assets(self):
        def fail(*args):raise RuntimeError('validation failed')
        self.manager.command = fail
        with self.assertRaises(RuntimeError):self.manager.enable()
        self.assertEqual(self.profiles.read_bytes(), self.original)
        self.assertFalse(self.manager.acquisition.exists());self.assertFalse(self.manager.unit.exists())

    def test_existing_acquisition_wildcard_rejected_before_changes(self):
        (self.cs/'acquis.d/other.yaml').write_text('filenames: ["'+str(self.manager.state/'*.ndjson')+'"]\nlabels: {type: syslog}\n')
        with self.assertRaises(ValueError):self.manager.enable()
        self.assertEqual(self.profiles.read_bytes(), self.original)
        self.assertFalse(self.manager.code.exists())

    def test_disable_preserves_external_profile_tail_edits(self):
        self.manager.enable()
        with self.profiles.open('ab') as stream:stream.write(b'\n# external update\n')
        self.manager.disable()
        self.assertEqual(self.profiles.read_bytes(), self.original+b'\n# external update\n')

    def test_external_rule_change_blocks_disable(self):
        self.manager.enable();self.manager.parser.write_text('external change')
        with self.assertRaises(ValueError):self.manager.disable()
        self.assertTrue(self.manager.acquisition.exists())
        self.assertTrue(self.profiles.read_bytes().startswith(self.mod.GUARD))

    def test_status_read_only_and_no_install_overwrite(self):
        self.assertEqual(self.manager.status()['status'], 'not_installed')
        self.assertFalse(self.calls)
        self.manager.enable()
        with self.assertRaises(ValueError):self.manager.enable()

    def test_failed_rollback_restart_keeps_backup_and_state(self):
        def fail(*args):raise RuntimeError('validation failed')
        def control(*args):
            if args[0] == 'restart':raise RuntimeError('restore restart failed')
            return 'active' if args[0] == 'is-active' else ''
        self.manager.command = fail;self.manager.control = control
        with self.assertRaises(RuntimeError):self.manager.enable()
        self.assertTrue((self.manager.code/'profiles.before').exists())
        self.assertTrue(self.manager.state.exists())
        self.assertEqual(self.profiles.read_bytes(), self.original)

    def test_duplicate_run_never_clobbers_status(self):
        import fcntl
        self.manager.enable()
        target = self.manager.state/'status.json';target.write_text('{"status":"publishing"}');target.chmod(0o600)
        with (self.manager.state/'daemon.lock').open('w') as stream:
            (self.manager.state/'daemon.lock').chmod(0o600)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.mod.run(self.manager), 1)
        self.assertEqual(json.loads(target.read_text())['status'], 'publishing')

    def test_run_recovers_stale_metrics_file_before_reporting_failure(self):
        self.manager.enable()
        stale = self.manager.state/'status.json.new';stale.write_text('partial');stale.chmod(0o600)
        # No source DB fixture: failure still must produce a readable fixed status.
        self.assertEqual(self.mod.run(self.manager), 1)
        self.assertFalse(stale.exists())
        self.assertEqual(json.loads((self.manager.state/'status.json').read_text())['status'], 'failed')

    def test_failed_mkdir_never_removes_concurrently_created_directory(self):
        def control(*args):
            if args == ('is-active', 'crowdsec'):
                self.manager.code.mkdir(parents=True, mode=0o700)
                (self.manager.code/'external-evidence').write_text('KEEP')
                return 'active'
            return ''
        self.manager.control = control
        with self.assertRaises(FileExistsError):self.manager.enable()
        self.assertEqual((self.manager.code/'external-evidence').read_text(), 'KEEP')

    def test_stale_acquisition_metrics_never_release_backlog(self):
        from unittest.mock import patch
        self.manager.enable()
        manager = self.manager
        published = []
        class FakePublisher:
            def __init__(inner, *args):
                inner.output = manager.state/'events.ndjson';inner.saved = {'cursors': {}, 'size': 0}
            def bind_consumer(inner, value):pass
            def probe(inner):pass
            def publish(inner):
                published.append(True)
                import signal
                signal.raise_signal(signal.SIGTERM)
                return 0
            def close(inner):pass
        self.manager.control = lambda *args: 'a'*32 if args[0] == 'show' else 'active'
        self.manager.command = lambda *args: json.dumps({'acquisition': {str(manager.state/'events.ndjson'): {'reads': 5}}})
        with patch.object(self.mod, 'Publisher', FakePublisher), patch.object(self.mod.time, 'sleep', lambda value: None):
            self.assertEqual(self.mod.run(manager), 1)
        self.assertFalse(published)

    def test_publishing_status_requires_healthy_collector(self):
        self.manager.enable()
        import time
        status = self.manager.state/'status.json'
        status.write_text(json.dumps({'status': 'publishing', 'heartbeat': time.time()}));status.chmod(0o600)
        self.manager.collector.status = lambda: {'status': 'needs_attention'}
        self.assertEqual(self.manager.status()['status'], 'needs_attention')

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
LINE = '+0000 2026-10-13 12:00:00 ERROR inbound/anytls[node]: process connection from 198.51.100.8:123: unknown user password: fallback disabled\n'


class LandingService(unittest.TestCase):
    def setUp(self):
        self.helper = ROOT/'lib/crowdsec_v2bx_service.py'
        self.assertTrue(self.helper.exists(), 'landing observer service is missing')
        sys.path.insert(0, str(ROOT/'lib'))
        self.addCleanup(sys.path.remove, str(ROOT/'lib'))
        spec = importlib.util.spec_from_file_location('landing_service_test', self.helper)
        self.mod = importlib.util.module_from_spec(spec);spec.loader.exec_module(self.mod)
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.log = self.base/'sing.log';self.log.write_text(LINE)
        self.config = self.base/'config.json'
        self.data = {'poll_interval': .5, 'sources': [{'name': 'sing', 'core': 'sing', 'file': str(self.log), 'relay_cidrs': '198.51.100.8/32'}]}
        self.save()

    def save(self):
        self.config.write_text(json.dumps(self.data));self.config.chmod(0o600)

    def test_strict_configuration_and_duplicate_inode(self):
        self.assertEqual(self.mod.load_config(self.config)['sources'][0]['core'], 'sing')
        duplicate = self.base/'duplicate.log';os.link(self.log, duplicate)
        self.data['sources'].append({'name': 'other', 'core': 'xray', 'file': str(duplicate)})
        self.save()
        with self.assertRaises(ValueError):self.mod.load_config(self.config)

    def test_unknown_keys_and_symlink_source_rejected(self):
        self.data['secret'] = 'TOKEN';self.save()
        with self.assertRaises(ValueError):self.mod.load_config(self.config)
        del self.data['secret']
        linked = self.base/'linked.log';linked.symlink_to(self.log)
        self.data['sources'][0]['file'] = str(linked);self.save()
        with self.assertRaises(ValueError):self.mod.load_config(self.config)

    def start(self, state):
        process = subprocess.Popen([sys.executable, str(self.helper), 'run', '--config', str(self.config), '--state', str(state)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:process.kill()
            process.communicate(timeout=5)
        self.addCleanup(cleanup)
        return process

    def wait_status(self, state):
        end = time.monotonic()+8
        while time.monotonic() < end:
            try:
                report = json.loads((state/'status.json').read_text())
                if report.get('sources', {}).get('sing', {}).get('events', 0) >= 1:return report
            except (FileNotFoundError, json.JSONDecodeError):pass
            time.sleep(.05)
        self.fail('no observer heartbeat')

    def test_term_restart_resume_and_relay_exclusion(self):
        state = self.base/'state';state.mkdir(mode=0o700)
        process = self.start(state);report = self.wait_status(state)
        self.assertEqual(report['sources']['sing']['failure_observations'], 0)
        process.terminate();out, err = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, (out, err))
        with self.log.open('a') as stream:stream.write(LINE)
        process = self.start(state)
        end = time.monotonic()+8
        while time.monotonic() < end:
            report = self.wait_status(state)
            if report['sources']['sing']['events'] == 2:break
            time.sleep(.05)
        self.assertEqual(report['sources']['sing']['events'], 2)
        process.terminate();process.communicate(timeout=5)
        with sqlite3.connect(state/'sing.sqlite') as db:
            records = [json.loads(r[0]) for r in db.execute('SELECT payload FROM events')]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r['source_status'] == 'relay_address' for r in records))
        self.assertNotIn('unknown user password', (state/'status.json').read_text())

    def test_capacity_stops_with_fixed_reason(self):
        self.data['sources'][0]['max_events'] = 1;self.save()
        self.log.write_text(LINE*2)
        state = self.base/'state';state.mkdir(mode=0o700)
        process = self.start(state);out, err = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 1)
        report = json.loads((state/'status.json').read_text())
        self.assertEqual(report['reason'], 'observation_capacity_reached')
        self.assertNotIn(b'unknown user password', out+err)

    def manager(self, fail=False):
        calls = []
        def systemctl(*args):
            calls.append(args)
            if fail and args[:2] == ('enable', '--now'):raise RuntimeError('mock start failed')
            if args[:2] == ('enable', '--now'):
                sources = {item['name']: {'source_present': True} for item in self.data['sources']}
                target = manager.state/'status.json'
                target.write_text(json.dumps({'status': 'running', 'heartbeat': time.time(), 'sources': sources}))
                target.chmod(0o600)
            return 'active' if args[0] == 'is-active' else ''
        manager = self.mod.Manager(self.base/'host', systemctl, lambda: None, startup_timeout=.3)
        return manager, calls

    def test_install_and_disable_preserve_state(self):
        manager, calls = self.manager();manager.install(self.config)
        self.assertIn(('enable', '--now', self.mod.UNIT), calls)
        marker = manager.state/'keep.sqlite';marker.write_text('KEEP')
        manager.disable()
        self.assertEqual(marker.read_text(), 'KEEP')
        self.assertIn(('disable', '--now', self.mod.UNIT), calls)
        self.assertTrue(manager.config.exists())
        with self.assertRaises(ValueError):manager.install(self.config)

    def test_install_start_failure_rolls_back(self):
        manager, calls = self.manager(fail=True)
        with self.assertRaises(RuntimeError):manager.install(self.config)
        self.assertFalse(manager.unit.exists())
        self.assertFalse(manager.code.exists())
        self.assertFalse(manager.state.exists())

    def test_external_unit_and_symlink_target_never_overwritten(self):
        manager, calls = self.manager()
        manager.unit.parent.mkdir(parents=True)
        manager.unit.write_text('EXTERNAL')
        with self.assertRaises(ValueError):manager.install(self.config)
        self.assertEqual(manager.unit.read_text(), 'EXTERNAL');self.assertFalse(calls)

    def test_status_is_read_only_and_unverified(self):
        manager, calls = self.manager()
        report = manager.status()
        self.assertEqual(report['status'], 'not_installed');self.assertFalse(calls)
        self.assertFalse((self.base/'host').exists())

    def test_duplicate_daemon_does_not_clobber_live_heartbeat(self):
        state = self.base/'state';state.mkdir(mode=0o700)
        process = self.start(state);self.wait_status(state)
        duplicate = self.start(state);duplicate.communicate(timeout=5)
        self.assertEqual(duplicate.returncode, 1)
        self.assertEqual(json.loads((state/'status.json').read_text())['status'], 'running')
        process.terminate();process.communicate(timeout=5)

    def test_three_independent_cores_and_missing_source_health(self):
        for name in ('xray', 'hysteria2'):
            log = self.base/(name+'.log');log.touch()
            self.data['sources'].append({'name': name, 'core': name, 'file': str(log), 'timezone': '+00:00'})
        self.save()
        state = self.base/'state';state.mkdir(mode=0o700)
        process = self.start(state);report = self.wait_status(state)
        self.assertEqual(set(report['sources']), {'sing', 'xray', 'hysteria2'})
        self.log.unlink()
        end = time.monotonic()+5
        while time.monotonic() < end:
            report = json.loads((state/'status.json').read_text())
            if not report['sources']['sing']['source_present']:break
            time.sleep(.05)
        self.assertFalse(report['sources']['sing']['source_present'])
        process.terminate();process.communicate(timeout=5)

    def test_stale_status_temp_after_crash_is_recovered(self):
        state = self.base/'state';state.mkdir(mode=0o700)
        (state/'status.json.new').write_text('partial');(state/'status.json.new').chmod(0o600)
        process = self.start(state);self.wait_status(state)
        process.terminate();process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_status_detects_stale_heartbeat_and_changed_installation(self):
        manager, calls = self.manager();manager.install(self.config)
        (manager.state/'status.json').write_text(json.dumps({'status': 'running', 'heartbeat': time.time()-3600, 'sources': {}}))
        (manager.state/'status.json').chmod(0o600)
        self.assertEqual(manager.status()['status'], 'needs_attention')
        manager.unit.write_text('changed')
        with self.assertRaises(ValueError):manager.disable()

    def test_private_config_and_xray_timezone_required(self):
        self.config.chmod(0o644)
        with self.assertRaises(ValueError):self.mod.load_config(self.config)
        self.data['sources'][0]['core'] = 'xray';self.save()
        with self.assertRaises(ValueError):self.mod.load_config(self.config)


    def test_install_requires_fresh_complete_running_heartbeat(self):
        manager = self.mod.Manager(self.base/'host', lambda *args: 'active' if args[0] == 'is-active' else '', lambda: None, startup_timeout=.2)
        with self.assertRaises(RuntimeError):manager.install(self.config)
        self.assertFalse(manager.unit.exists());self.assertFalse(manager.code.exists())

    def test_unit_chmod_failure_removes_exclusively_created_unit(self):
        from unittest.mock import patch
        manager, calls = self.manager()
        original = Path.chmod
        def fail_unit(path, mode, **kwargs):
            if path == manager.unit:raise OSError('chmod failure')
            return original(path, mode, **kwargs)
        with patch.object(Path, 'chmod', fail_unit):
            with self.assertRaises(OSError):manager.install(self.config)
        self.assertFalse(manager.unit.exists());self.assertFalse(manager.code.exists())

    def test_installed_helpers_run_and_disable_with_real_daemon(self):
        processes = []
        def control(*args):
            if args[:2] == ('enable', '--now'):
                process = subprocess.Popen([sys.executable, str(manager.code/'crowdsec_v2bx_service.py'), 'run', '--config', str(manager.config), '--state', str(manager.state)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                processes.append(process)
            elif args[0] == 'is-active':
                return 'active' if processes and processes[-1].poll() is None else 'inactive'
            elif args[:2] == ('disable', '--now'):
                for process in processes:
                    if process.poll() is None:process.terminate()
                    process.communicate(timeout=5)
            return ''
        def cleanup():
            for process in processes:
                if process.poll() is None:process.kill()
                process.communicate(timeout=5)
        self.addCleanup(cleanup)
        manager = self.mod.Manager(self.base/'host', control, lambda: None, startup_timeout=5)
        manager.install(self.config)
        self.assertEqual(manager.status()['status'], 'observing')
        manager.disable()
        self.assertEqual(manager.status()['status'], 'needs_attention')
        with sqlite3.connect(manager.state/'sing.sqlite') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)

    def test_runtime_dependency_failure_precedes_mutation(self):
        manager, calls = self.manager()
        def fail_runtime():raise RuntimeError('missing yaml')
        manager.runtime_check = fail_runtime
        with self.assertRaises(RuntimeError):manager.install(self.config)
        self.assertFalse(manager.code.exists());self.assertFalse(calls)

    def test_same_name_vendor_unit_is_rejected(self):
        calls = []
        def control(*args):
            calls.append(args)
            return 'loaded'
        manager = self.mod.Manager(self.base/'host', control, lambda: None)
        with self.assertRaises(ValueError):manager.install(self.config)
        self.assertFalse(manager.unit.exists());self.assertEqual(len(calls), 1)

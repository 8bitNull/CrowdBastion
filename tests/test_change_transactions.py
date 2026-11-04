"""Real private journals and CAS resources with injected external mutations."""
import copy
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest

try: change = importlib.import_module('crowdbastion_change')
except ModuleNotFoundError: change = None


class Resources:
    def __init__(self):
        self.values = {'a': 'before-a', 'b': 'before-b'}
        self.fail = set(); self.writes = []; self.accept = True
    def read(self, resource): return self.values.get(resource['name'])
    def write(self, resource, before, after):
        name = resource['name']
        if self.read(resource) != before: raise ValueError('drift')
        if (name, after) in self.fail: raise OSError('SECRET')
        self.writes.append((name, after)); self.values[name] = after
    def verify(self, metadata): return self.accept


class Timer:
    def __init__(self): self.armed = []; self.cancelled = []
    def arm(self, root, ident, runtime, deadline): self.armed.append((root, ident, runtime, deadline))
    def disarm(self, ident): self.cancelled.append(ident)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(change, 'guarded transaction engine missing')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.base.chmod(0o700)
        self.adapter = Resources(); self.timer = Timer(); self.guards = []
        self.engine = change.Engine(self.base/'changes', self.adapter, scheduler=self.timer,
                                    guard=lambda: self.guards.append(True), lock_path=self.base/'maintenance.lock')
        self.effects = [{'resource': {'kind': 'fixture', 'name': name}, 'before': 'before-'+name,
                         'after': 'after-'+name} for name in ('a', 'b')]
    def apply(self): return self.engine.apply('port-policy', self.effects, metadata={'scope': 'fixture'})

    def test_guard_refusal_has_no_runtime_or_resource_mutation(self):
        def refuse(): raise ValueError('SECRET')
        self.engine.guard = refuse
        with self.assertRaises(ValueError): self.apply()
        self.assertFalse((self.base/'changes').exists()); self.assertEqual(self.adapter.writes, [])

    def test_runtime_is_complete_private_and_independent_manifest_is_immutable(self):
        result = self.apply(); ident = result['id']
        self.assertEqual(result['state'], 'staged'); self.assertEqual(len(self.guards), 1)
        tx = self.base/'changes'/ident
        for helper in ('crowdbastion_change.py', 'crowdbastion_port_policy.py', 'crowdbastion_environment.py', 'crowdbastion_ux.py', 'crowdbastion_node.py'):
            self.assertTrue((tx/'runtime'/helper).is_file())
            self.assertEqual((tx/'runtime'/helper).stat().st_mode & 0o777, 0o600)
        before = (tx/'manifest.json').read_bytes()
        self.assertEqual(self.engine.verify(ident)['state'], 'verified')
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        self.assertEqual((tx/'manifest.json').read_bytes(), before)
        self.assertEqual(self.engine.rollback(ident)['state'], 'committed')
        self.assertEqual(self.adapter.values['a'], 'after-a')

    def test_commit_freshly_checks_resources_and_independent_verifier(self):
        result = self.apply(); ident = result['id']
        self.assertEqual(self.engine.verify(ident)['state'], 'verified')
        self.adapter.accept = False
        self.assertEqual(self.engine.commit(ident)['state'], 'verification_failed')
        self.assertEqual(self.timer.cancelled, [])
        self.adapter.accept = True; self.adapter.values['a'] = 'foreign'
        self.assertEqual(self.engine.commit(ident)['state'], 'verification_failed')
        self.assertEqual(self.engine.rollback(ident)['state'], 'rollback_incomplete')
        self.assertEqual(self.adapter.values, {'a': 'foreign', 'b': 'before-b'})
        self.assertEqual(self.timer.cancelled, [])
        self.adapter.values['a'] = 'after-a'
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        writes = list(self.adapter.writes)
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        self.assertEqual(self.adapter.writes, writes)

    def test_partial_failure_continues_other_resources_and_retry_does_not_duplicate(self):
        ident = self.apply()['id']
        self.adapter.fail.add(('b', 'before-b'))
        report = self.engine.rollback(ident)
        self.assertEqual(report['state'], 'rollback_incomplete')
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertEqual(self.adapter.values, {'a': 'before-a', 'b': 'after-b'})
        self.assertEqual(self.timer.cancelled, [])
        self.adapter.fail.clear(); self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        self.assertEqual(self.adapter.writes.count(('a', 'before-a')), 1)

    def test_failed_apply_recovers_completed_effect_and_pending_transaction_blocks_new_apply(self):
        self.adapter.fail.add(('b', 'after-b'))
        result = self.apply()
        self.assertEqual(result['state'], 'rolled_back')
        self.assertEqual(self.adapter.values, {'a': 'before-a', 'b': 'before-b'})
        self.adapter.fail.clear(); result = self.apply()
        with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.engine.rollback(result['id'])['state'], 'rolled_back')

    def test_manifest_tampering_and_unowned_state_directory_refused(self):
        ident = self.apply()['id']; tx = self.base/'changes'/ident
        data = json.loads((tx/'manifest.json').read_text()); data['effects'][0]['after'] = 'evil'
        (tx/'manifest.json').write_text(json.dumps(data))
        with self.assertRaises(ValueError): self.engine.rollback(ident)
        root = self.base/'foreign'; root.mkdir()
        engine = change.Engine(root, self.adapter, scheduler=self.timer, guard=lambda: None, lock_path=self.base/'maintenance.lock')
        with self.assertRaises(ValueError): engine.apply('port-policy', self.effects)

    def test_global_lock_conflict_refuses_before_mutating(self):
        import fcntl
        with open(self.base/'maintenance.lock', 'w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): self.apply()
        self.assertEqual(self.adapter.writes, [])


if __name__ == '__main__': unittest.main()


class MoreTransactionSafety(unittest.TestCase):
    setUp = TransactionTests.setUp
    apply = TransactionTests.apply
    def test_expired_transaction_cannot_commit_before_timer_gets_lock(self):
        from unittest.mock import patch
        ident = self.apply()['id']
        with patch('crowdbastion_change.time.time', return_value=10**12):
            self.assertEqual(self.engine.commit(ident)['state'], 'verification_failed')
        self.assertEqual(self.timer.cancelled, [])
    def test_inherited_shell_lock_is_reused_without_deadlock(self):
        import subprocess
        helper = Path(change.__file__).resolve().parent
        script = 'exec 9>"$1"\nflock -n 9\nMAINTENANCE_LOCK_HELD=true PYTHONPATH="$2" python3 -c \'from pathlib import Path; import sys; from crowdbastion_change import maintenance_lock; c=maintenance_lock(Path(sys.argv[1])); c.__enter__(); print("held"); c.__exit__(None,None,None)\' "$1"'
        result = subprocess.run(['bash', '-c', script, 'fixture', str(self.base/'maintenance.lock'), str(helper)], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(result.stdout.strip(), 'held')
    def test_apply_holds_lock_against_commit_and_timer_rollback(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        entered = threading.Event(); release = threading.Event()
        write = self.adapter.write
        def slow(resource, before, after):
            if resource['name'] == 'a' and after == 'after-a': entered.set(); release.wait(3)
            return write(resource, before, after)
        self.adapter.write = slow
        with ThreadPoolExecutor(max_workers=1) as pool:
            applying = pool.submit(self.apply)
            self.assertTrue(entered.wait(3))
            ident = self.timer.armed[0][1]
            try:
                with self.assertRaises(BlockingIOError): self.engine.commit(ident)
                with self.assertRaises(BlockingIOError): self.engine.rollback(ident)
            finally: release.set()
            self.assertEqual(applying.result()['state'], 'staged')
        self.assertEqual(self.engine.commit(ident)['state'], 'committed')
        self.assertEqual(self.engine.rollback(ident)['state'], 'committed')
    def test_interrupted_started_effect_is_recovered_from_observed_postimage(self):
        ident = self.apply()['id']; path = self.base/'changes'/ident/'journal.json'
        journal = json.loads(path.read_text()); journal['state'] = 'applying'; journal['items'][-1] = 'started'
        path.write_text(json.dumps(journal))
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        self.assertEqual(self.adapter.values, {'a': 'before-a', 'b': 'before-b'})


class SchedulerTests(unittest.TestCase):
    def test_persistent_deadline_and_retry_units_use_verified_stable_paths(self):
        self.assertIsNotNone(change, 'transaction engine missing')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); base.chmod(0o700)
            units = base/'units'; units.mkdir()
            calls = []
            scheduler = change.SystemdScheduler(units, run=lambda argv: calls.append(argv) or '')
            ident = '1'*32; root = base/'changes'; runtime = root/ident/'runtime'
            scheduler.arm(root, ident, runtime, 1793707200)
            service, timer = scheduler.paths(ident)
            self.assertIn(str(runtime)+'/crowdbastion_change.py rollback', service.read_text())
            self.assertIn('Persistent=true', timer.read_text())
            self.assertIn('OnUnitInactiveSec=60s', timer.read_text())
            self.assertTrue(any(a[:3] == ['systemctl', 'enable', '--now'] for a in calls))
            with self.assertRaises(ValueError): scheduler.arm(root, ident, runtime, 1793707200)
    def test_duplicate_json_keys_are_refused(self):
        self.assertIsNotNone(change, 'transaction engine missing')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); base.chmod(0o700)
            path = base/'bad.json'; path.write_text('{"version": 1, "version": 2}'); path.chmod(0o600)
            with self.assertRaises(ValueError): change.json_read(path)
    def test_unfinished_preparation_does_not_block(self):
        fixture = TransactionTests('test_global_lock_conflict_refuses_before_mutating'); fixture.setUp()
        try:
            change.initialize(fixture.engine.root)
            (fixture.engine.root/('2'*32)).mkdir(mode=0o700)
            result = fixture.apply()
            self.assertEqual(result['state'], 'staged')
        finally: fixture.doCleanups()


class DetachedRuntime(unittest.TestCase):
    setUp = TransactionTests.setUp
    apply = TransactionTests.apply
    def test_snapshot_cli_runs_without_checkout_or_pythonpath(self):
        import subprocess
        ident = self.apply()['id']
        runtime = self.base/'changes'/ident/'runtime'
        environment = dict(os.environ, PYTHONPATH='/nonexistent', PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run(['python3', str(runtime/'crowdbastion_change.py'), 'status', '--root', str(self.engine.root), '--id', ident],
                                cwd=self.base, env=environment, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'staged')


class ReviewRecoveryBoundaries(unittest.TestCase):
    setUp = TransactionTests.setUp
    apply = TransactionTests.apply
    def test_postinverse_read_failure_defers_earlier_same_resource_until_retry(self):
        class TransientRead(Resources):
            fail_postread = False
            fail_once = True
            def read(self, resource):
                if self.fail_postread:
                    self.fail_postread = False
                    raise OSError('transient read failure')
                return super().read(resource)
            def write(self, resource, before, after):
                super().write(resource, before, after)
                if before == 'after-a' and after == 'middle-a' and self.fail_once:
                    self.fail_once = False
                    self.fail_postread = True
        adapter = TransientRead(); self.engine.adapter = adapter
        def effect(name, before, after):
            return {'resource': {'kind': 'fixture', 'name': name}, 'before': before, 'after': after}
        effects = [effect('a', 'before-a', 'middle-a'), effect('b', 'before-b', 'after-b'),
                   effect('a', 'middle-a', 'after-a')]
        ident = self.engine.apply('port-policy', effects)['id']
        self.assertEqual(self.engine.rollback(ident)['state'], 'rollback_incomplete')
        self.assertEqual(adapter.values, {'a': 'middle-a', 'b': 'before-b'})
        self.assertEqual(self.timer.cancelled, [])
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        self.assertEqual(adapter.values, {'a': 'before-a', 'b': 'before-b'})
        self.assertEqual(adapter.writes.count(('a', 'middle-a')), 2)  # one forward, one inverse
        self.assertEqual(adapter.writes.count(('a', 'before-a')), 1)
        self.assertEqual(adapter.writes.count(('b', 'before-b')), 1)
        self.assertEqual(self.timer.cancelled, [ident])
        writes = list(adapter.writes)
        self.assertEqual(self.engine.rollback(ident)['state'], 'rolled_back')
        self.assertEqual(adapter.writes, writes)
    def test_verification_crossing_deadline_cannot_publish_commit(self):
        from unittest.mock import patch
        with patch('crowdbastion_change.time.time', return_value=100):
            result = self.apply()
        with patch('crowdbastion_change.time.time', return_value=result['deadline']-1) as now:
            def verify(metadata):
                now.return_value = result['deadline'] + 1
                return True
            self.adapter.verify = verify
            self.assertEqual(self.engine.commit(result['id'])['state'], 'verification_failed')
        self.assertEqual(self.engine.status(result['id'])['state'], 'staged')
        self.assertEqual(self.timer.cancelled, [])
        self.assertEqual(self.engine.rollback(result['id'])['state'], 'rolled_back')
        self.assertEqual(self.adapter.values, {'a': 'before-a', 'b': 'before-b'})

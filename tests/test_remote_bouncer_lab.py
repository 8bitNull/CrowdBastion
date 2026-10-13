import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).parent))
import verify_remote_bouncer as lab

class RemoteLabTests(unittest.TestCase):
    def test_acceptance_requires_every_real_condition(self):
        conditions = {name: True for name in lab.REQUIRED}
        self.assertTrue(lab.accepted_remote(conditions))
        for name in lab.REQUIRED:
            self.assertFalse(lab.accepted_remote({**conditions, name: False}))
        self.assertFalse(lab.accepted_remote({}))

    def test_wrong_key_requires_failed_process_and_auth_rejection(self):
        self.assertTrue(lab.authentication_rejected(1, 'API error: access forbidden'))
        self.assertTrue(lab.authentication_rejected(1, 'HTTP 403'))
        self.assertFalse(lab.authentication_rejected(0, 'HTTP 403'))
        self.assertFalse(lab.authentication_rejected(1, 'connect: connection refused'))

    def test_staging_never_mutates_original_credentials_or_database(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'source'; source.mkdir(); data=source/'data'; data.mkdir()
            cred=source/'credentials'; cred.write_text('secret original')
            db=data/'crowdsec.db'; db.write_text('original database')
            cfg={'api':{'client':{'credentials_path':str(cred)}}, 'config_paths':{'data_dir':str(data)}, 'db_config':{'db_path':str(db)}, 'common':{'log_dir':str(source)}}
            for failure in (False, True):
                dest=root/str(failure); dest.mkdir()
                staged=lab.stage_core_state(cfg,dest)
                try:
                    Path(staged['api']['client']['credentials_path']).write_text('new secret')
                    Path(staged['db_config']['db_path']).write_text('new decision')
                    if failure: raise RuntimeError('failed experiment')
                except RuntimeError: pass
                self.assertEqual(cred.read_text(),'secret original')
                self.assertEqual(db.read_text(),'original database')
                self.assertEqual(cfg['db_config']['db_path'],str(db))
                self.assertEqual(Path(staged['api']['client']['credentials_path']).stat().st_mode & 0o777,0o600)

    def test_guard_rejects_original_namespaces(self):
        import os
        with self.assertRaises(RuntimeError):
            lab.guard(os.stat('/proc/self/ns/net').st_ino, os.stat('/proc/self/ns/mnt').st_ino)

    def test_guard_requires_private_mount_namespace(self):
        import os
        with self.assertRaises(RuntimeError):
            lab.guard(-1, os.stat('/proc/self/ns/mnt').st_ino)
        with self.assertRaises(RuntimeError):
            lab.guard(-1)

    def test_outer_cleanup_allows_inner_sigkill_sweep(self):
        import os, tempfile, time, subprocess
        with tempfile.TemporaryDirectory() as tmp:
            pidfile=Path(tmp)/'child.pid'
            child_code='import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'
            worker_code=('import sys,time; sys.path.insert(0, '+repr(str(Path(__file__).parent))+'); from relay_network_lab import Processes; '
                         '\nwith Processes(grace=.2) as inner:\n child=inner.start([sys.executable, \"-c\", '+repr(child_code)+']); open('+repr(str(pidfile))+', \"w\").write(str(child.pid)); time.sleep(30)')
            with self.assertRaises(ValueError):
                with lab.Processes(grace=1) as outer:
                    worker=outer.start([sys.executable,'-c',worker_code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    deadline=time.monotonic()+5
                    while not pidfile.exists() and time.monotonic()<deadline: time.sleep(.01)
                    self.assertTrue(pidfile.exists())
                    child_pid=int(pidfile.read_text())
                    time.sleep(.1)
                    raise ValueError('outer failure')
            self.assertIsNotNone(worker.poll())
            with self.assertRaises(ProcessLookupError): os.kill(child_pid,0)

    def test_failure_cleans_owned_processes(self):
        import subprocess
        with self.assertRaises(ValueError):
            with lab.Processes(grace=.1) as owned:
                child = owned.start([sys.executable, '-c', 'import time; time.sleep(30)'])
                raise ValueError('experiment failed')
        self.assertIsNotNone(child.poll())

if __name__ == '__main__': unittest.main()

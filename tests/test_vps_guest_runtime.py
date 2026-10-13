import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

class RuntimeTests(unittest.TestCase):
    def load(self):
        path=Path(__file__).with_name('vps_guest_runtime.py')
        self.assertTrue(path.exists(), 'bounded guest runtime is missing')
        spec=importlib.util.spec_from_file_location('guest_runtime',path)
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        return m

    def test_conflicting_properties_are_not_healthy(self):
        m=self.load()
        self.assertTrue(m.service_healthy('ActiveState=active\nSubState=running\nResult=success\n'))
        self.assertFalse(m.service_healthy('ActiveState=active\nActiveState=failed\nSubState=running\nResult=success\n'))
        self.assertFalse(m.service_healthy('ActiveState=activating\nSubState=auto-restart\nResult=timeout\n'))

    def test_ready_after_deadline_is_rejected(self):
        m=self.load();now=[0]
        def probe():now[0]=6;return True
        self.assertFalse(m.wait_ready(probe,timeout=5,clock=lambda:now[0],sleep=lambda _:None))

    def test_nonzero_nft_read_is_not_absence(self):
        m=self.load()
        self.assertFalse(m.nft_synced(1,'operation not permitted','198.51.100.77',False))
        self.assertTrue(m.nft_synced(0,'{}','198.51.100.77',False))
        self.assertTrue(m.nft_synced(0,'198.51.100.77','198.51.100.77',True))

    def test_secret_is_scrubbed_and_output_bounded(self):
        m=self.load();secret='lab-credential-example-12345'
        scrub=m.Scrubber([secret])
        out=scrub.summary('api_key: '+secret+'\n'+secret+'\n'+'文'*10000,limit=4096)
        self.assertNotIn(secret,out);self.assertLessEqual(len(out.encode()),4096)

    def test_config_secrets_are_collected_once(self):
        m=self.load()
        self.assertTrue(hasattr(m.Scrubber,'from_configs'))
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'credentials.yaml';p.write_text('api:\n  client:\n    password: tiny-private-value\n')
            scrub=m.Scrubber.from_configs([p])
            p.write_text('invalid: [')
            self.assertNotIn('tiny-private-value',scrub.summary('connection failed tiny-private-value'))

    def test_recursive_yaml_is_bounded_and_still_scrubbed(self):
        m=self.load()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'credentials.yaml';p.write_text('root: &root\n  password: tiny-private-value\n  recursive: *root\n')
            scrub=m.Scrubber.from_configs([p])
            self.assertNotIn('tiny-private-value',scrub.summary('tiny-private-value'))

    def test_inactive_probe_errors_are_not_removal(self):
        m=self.load()
        self.assertTrue(hasattr(m,'service_removed'))
        self.assertTrue(m.service_removed(0,'ActiveState=inactive\n',1,'disabled\n'))
        for rc in (124,False,-15,1):
            self.assertFalse(m.service_removed(rc,'ActiveState=inactive\n',1,'disabled\n'))
        self.assertFalse(m.service_removed(0,'ActiveState=inactive\n',124,'disabled\n'))

    def test_timeout_kills_descendant_that_ignores_term(self):
        m=self.load()
        with tempfile.TemporaryDirectory() as td:
            pidfile=Path(td)/'child.pid'
            child="import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
            parent="import subprocess,sys,pathlib,time;p=subprocess.Popen([sys.executable,'-c',sys.argv[2]]);pathlib.Path(sys.argv[1]).write_text(str(p.pid));print('started',flush=True);time.sleep(60)"
            rc,out,elapsed=m.run_bounded([sys.executable,'-c',parent,str(pidfile),child],timeout=.5)
            self.assertEqual(rc,124);self.assertIn('started',out);self.assertLess(elapsed,3)
            pid=int(pidfile.read_text());status=Path('/proc')/str(pid)/'status'
            deadline=time.monotonic()+1
            while status.exists() and 'State:\tZ' not in status.read_text() and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertTrue(not status.exists() or 'State:\tZ' in status.read_text())

    def test_timeout_reaps_descendant_in_separate_session(self):
        m=self.load()
        with tempfile.TemporaryDirectory() as td:
            pidfile=Path(td)/'child.pid'
            child="import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
            parent="import subprocess,sys,pathlib,time;p=subprocess.Popen([sys.executable,'-c',sys.argv[2]],start_new_session=True);pathlib.Path(sys.argv[1]).write_text(str(p.pid));time.sleep(60)"
            rc,_,_=m.run_bounded([sys.executable,'-c',parent,str(pidfile),child],timeout=.4)
            pid=int(pidfile.read_text());status=Path('/proc')/str(pid)/'status'
            deadline=time.monotonic()+1
            while status.exists() and 'State:\tZ' not in status.read_text() and time.monotonic()<deadline:time.sleep(.01)
            alive=status.exists() and 'State:\tZ' not in status.read_text()
            if alive:
                import signal
                os.kill(pid,signal.SIGKILL)
            self.assertEqual(rc,124);self.assertFalse(alive,'setsid child survived timeout')

    def test_success_and_failure_exit_are_preserved(self):
        m=self.load()
        rc,out,_=m.run_bounded([sys.executable,'-c',"print('ok');raise SystemExit(29)"],timeout=3)
        self.assertEqual(rc,29);self.assertEqual(out.strip(),'ok')

if __name__=='__main__':unittest.main()

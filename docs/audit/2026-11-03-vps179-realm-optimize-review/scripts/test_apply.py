"""Failure-path tests for the archived rollout helper; no SSH or host services."""
import ast,contextlib,io,json,subprocess,tempfile,types,unittest,sys
from pathlib import Path
SOURCE=Path(__file__).with_name('apply.py')

class ApplyRecoveryTests(unittest.TestCase):
 def execute_failure(self,exc,unlink_error=False):
  tree=ast.parse(SOURCE.read_text());node=next(n for n in tree.body if isinstance(n,ast.Try))
  context=self
  class OwnedFile:
   def exists(self):return True
   def is_symlink(self):return False
   def read_bytes(self):return b'data'
   def unlink(self):raise OSError('injected disk error')
   def __str__(self):return '/owned/file'
  owned=OwnedFile()
  with tempfile.TemporaryDirectory() as tmp:
   recovered=Path(tmp)/'core-recovered'
   def command(args,timeout=45):
    if args==['systemctl','restart','crowdsec']:raise exc
    return ''
   def recover(args,**kwargs):
    if args==['systemctl','restart','crowdsec']:recovered.write_text('recovery invoked')
    return types.SimpleNamespace(returncode=0)
   import hashlib
   created=[];result={'new_files':{'/owned/file':hashlib.sha256(b'data').hexdigest()}}
   def cancelling(args,timeout=45):
    if args==['systemctl','restart','crowdsec']:
     if unlink_error:created.append(owned)
     raise exc
    return ''
   ns={'files':{},'created':created,'restarted':[],'r':result,'base':Path(tmp),'cmd':cancelling,'subprocess':types.SimpleNamespace(run=recover),'json':json,'hashlib':hashlib,'signal':__import__('signal')}
   # Only the operational transaction runs; no top-level paths, locks or services.
   with contextlib.redirect_stdout(io.StringIO()):
    try:exec(compile(ast.Module(body=[node],type_ignores=[]),'apply-transaction','exec'),ns)
    except BaseException:pass
   return recovered.exists(),result
 def test_keyboard_interrupt_recovers_attempted_core_restart(self):
  ok,_=self.execute_failure(KeyboardInterrupt());self.assertTrue(ok,'cancellation bypassed rollback')
 def test_remove_failure_does_not_skip_core_recovery(self):
  ok,r=self.execute_failure(RuntimeError('restart failed'),True);self.assertTrue(ok,'file cleanup failure skipped service recovery');self.assertEqual(r.get('status'),'rollback_incomplete')

if __name__=='__main__':unittest.main(verbosity=2)

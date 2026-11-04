import ast,contextlib,io,json,subprocess,tempfile,types,unittest
from pathlib import Path

class RolloutFailureTests(unittest.TestCase):
 def test_failed_core_restart_is_retried_after_rollback(self):
  tree=ast.parse(Path('/tmp/realm179-apply-opt.py').read_text());node=next(n for n in tree.body if isinstance(n,ast.Try))
  with tempfile.TemporaryDirectory() as tmp:
   recovery=Path(tmp)/'recovered'
   def command(args,timeout=45):
    if args==['systemctl','restart','crowdsec']:raise RuntimeError('injected service restart failure')
    return ''
   def recover(args,**kwargs):
    if args==['systemctl','restart','crowdsec']:recovery.write_text('core recovery attempted with restored config')
    return types.SimpleNamespace(returncode=0)
   ns={'files':{},'created':[],'restarted':[],'r':{'new_files':{}},'base':Path(tmp),'cmd':command,'subprocess':types.SimpleNamespace(run=recover),'json':json}
   with contextlib.redirect_stdout(io.StringIO()):
    try:exec(compile(ast.Module(body=[node],type_ignores=[]),'rollout','exec'),ns)
    except RuntimeError:pass
   self.assertTrue(recovery.exists(),'rollback failed to retry a service whose restart had failed')
 def test_cleanup_continues_after_decision_delete_timeout(self):
  tree=ast.parse(Path('/tmp/realm179-enforce-test.py').read_text());node=next(n for n in tree.body if isinstance(n,ast.Try))
  proc=subprocess.Popen(['python3','-c','import time; time.sleep(30)'])
  calls=0
  def command(args,*a,**kw):
   nonlocal calls
   calls+=1
   if calls==1:raise subprocess.TimeoutExpired(args,20)
   return types.SimpleNamespace(returncode=0 if args[:2]!=['ip','link'] else 1,stdout='[]' if args[:3]==['cscli','decisions','list'] else '')
  with tempfile.TemporaryDirectory() as tmp:
   ns={'decision_attempted':True,'cmd':command,'test':'203.0.113.242','reason':'owned-test','wait_member':lambda wanted:[], 'r':{'cleanup':{},'status':'failed'},'echo':proc,'subprocess':subprocess,'created_veth':False,'created_ns':False,'ns':'test-owned','vh':'test-owned','base':Path(tmp),'json':json}
   try:
    with contextlib.redirect_stdout(io.StringIO()):
     try:exec(compile(ast.Module(body=node.finalbody,type_ignores=[]),'cleanup','exec'),ns)
     except subprocess.TimeoutExpired:pass
    self.assertIsNotNone(proc.poll(),'decision-delete timeout prevented stopping the owned UDP process')
    self.assertTrue(ns['r']['cleanup'].get('namespace_absent'),'remaining cleanup steps were skipped')
   finally:
    if proc.poll() is None:proc.terminate();proc.wait(timeout=5)

if __name__=='__main__':unittest.main(verbosity=2)

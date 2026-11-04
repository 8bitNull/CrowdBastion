"""Exercise rollback with missing runtime state and drift in an isolated fixture."""
import tempfile,json,hashlib,subprocess,sys
from pathlib import Path
source=Path(__file__).with_name('rollback.py').read_text()
base_expression="Path('/var/backups/crowdbastion/tcp-retune-20261103')"
runtime_expression="Path('/proc/sys/'+k.replace('.','/'))"
# Refuse to execute if a changed rollback can no longer be redirected fully
# into the fixture. Never fall back to production paths in this test.
assert source.count(base_expression)==1
assert source.count(runtime_expression)==1
def sha(v):return hashlib.sha256(v).hexdigest()
with tempfile.TemporaryDirectory(prefix='crowdbastion216-rollback-') as folder:
 base=Path(folder)
 before=b'original\n';after=b'candidate\n'
 original=base/'original';original.write_bytes(before)
 restored=base/'config';restored.write_bytes(after)
 added=base/'new-config';added.write_bytes(after)
 keys=['net.ipv4.tcp_syn_retries','net.ipv4.tcp_synack_retries','net.ipv4.tcp_fin_timeout']
 old=['3','2','15'];targets=['6','5','60']
 for i,k in enumerate(keys):
  p=base/'proc'/k.replace('.','/');p.parent.mkdir(parents=True,exist_ok=True)
  if i!=1:p.write_text(targets[i])
 manifest={'files':[{'path':str(restored),'before':sha(before),'after':sha(after),'backup':str(original),'mode':0o600},{'path':str(added),'before':None,'after':sha(after),'backup':None,'mode':0o600}], 'runtime_before':dict(zip(keys,old)), 'changes':dict(zip(keys,targets))}
 (base/'manifest.json').write_text(json.dumps(manifest))
 code=source.replace(base_expression,'Path('+repr(str(base))+')').replace(runtime_expression, "Path(str(base/'proc')+'/'+k.replace('.','/'))")
 assert base_expression not in code and runtime_expression not in code
 script=base/'test-rollback.py';script.write_text(code)
 first=subprocess.run([sys.executable,str(script)],capture_output=True,text=True)
 assert first.returncode==1,first.stderr
 report=json.loads((base/'rollback-result.json').read_text())
 assert len(report['errors'])==1 and 'tcp_synack_retries' in report['errors'][0]
 assert restored.read_bytes()==before and not added.exists()
 for i in [0,2]:assert (base/'proc'/keys[i].replace('.','/')).read_text().strip()==old[i]
 missing=base/'proc'/keys[1].replace('.','/');missing.write_text(targets[1])
 second=subprocess.run([sys.executable,str(script)],capture_output=True,text=True)
 assert second.returncode==0,second.stderr
 assert json.loads((base/'rollback-result.json').read_text())=={'rolled_back':True,'errors':[]}
 missing.write_text('99')
 third=subprocess.run([sys.executable,str(script)],capture_output=True,text=True)
 assert third.returncode==1 and missing.read_text()=='99'
 print(json.dumps({'checks':{'remaining_parameters_restore_after_one_missing_key':True,'file_restore_and_new_file_removal':True,'retry_finishes_partial_rollback':True,'foreign_runtime_change_preserved':True},'production_state_modified':False}))

# NEW_BACKUP and EXPECTED_HELPER_SHA256 are injected from installation evidence.
import hashlib,json,os,runpy,stat,time
from pathlib import Path
os.umask(0o077)
old=Path('/var/backups/crowdbastion/vps167-optimize-20261102T034616Z')
new=Path(NEW_BACKUP)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def record(p):
 s=p.lstat();r={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
 if p.is_symlink():r['target']=os.readlink(p)
 elif p.is_file():r.update(sha256=sha(p),size=s.st_size)
 else:assert p.is_dir();r['directory']=True
 return r
assert sha(old/'manifest.json')=='1d78f7c7b09006cd25ad4eb911846147ce0e111562d449120b100396f1344dbe'
assert sha(new/'rollback-manager-v2.py')==EXPECTED_HELPER_SHA256
ns=runpy.run_path(str(new/'rollback-manager-v2.py'),run_name='seal_read_only');stage=ns['load_stage']()
from crowdsec_bot_runtime import maintenance_guard
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 check=ns['restore'](stage,check_only=True)
 before=json.loads((old/'manifest.json').read_text())
 for name,value in before['items'].items():assert record(Path(name))==value,'original sealed object changed'
 items={str(p):record(p) for p in [new,new/'rollback-manager-v2.py',new/'installation.json']}
 assert items[str(new)]['mode']==0o700
 for p in [new/'rollback-manager-v2.py',new/'installation.json']:
  assert record(p)['mode']==0o600 and record(p)['uid']==0
 manifest={'sealed_at':time.time(),'items':items,'original_stable_items_unchanged':len(before['items']),'rollback_check':check,'production_rollback_executed':False}
 with (new/'manifest.json').open('x') as stream:stream.write(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
 assert sha(new/'manifest.json')==hashlib.sha256((json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode()).hexdigest()
 print(json.dumps({'sealed_at':manifest['sealed_at'],'backup':str(new),'manifest_sha256':sha(new/'manifest.json'),'items':len(items),'stable_files':2,'original_stable_items_unchanged':len(before['items']),'rollback_check':check,'production_rollback_executed':False},ensure_ascii=False,indent=2))

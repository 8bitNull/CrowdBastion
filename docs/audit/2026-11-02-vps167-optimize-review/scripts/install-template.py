# HELPER_B64 is injected from the tested template; this file contains no credentials.
import base64,datetime,hashlib,json,os,runpy,stat,subprocess,time
from pathlib import Path
os.umask(0o077)
old=Path('/var/backups/crowdbastion/vps167-optimize-20261102T034616Z')
manifest_sha='1d78f7c7b09006cd25ad4eb911846147ce0e111562d449120b100396f1344dbe'
stage_sha='5e02ec9d234d985defd44724374e58d34bbf5af3ae774534ebb9f4e3680a69ef'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def record(p):
 s=p.lstat();r={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
 if p.is_symlink():r['target']=os.readlink(p)
 elif p.is_file():r.update(sha256=sha(p),size=s.st_size)
 else:assert p.is_dir();r['directory']=True
 return r

def check_original():
 assert sha(old/'manifest.json')==manifest_sha
 data=json.loads((old/'manifest.json').read_text())
 for name,value in data['items'].items():assert record(Path(name))==value,'sealed object changed'
 return len(data['items'])
assert os.geteuid()==0 and sha(old/'stage.json')==stage_sha
checked=check_original()
ns=runpy.run_path(str(old/'rollback-manager.py'),run_name='review_load_only');stage=ns['load_stage']()
from crowdsec_bot_runtime import maintenance_guard
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
new=old.parent/('vps167-optimize-review-'+stamp)
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 check_original()
 parent=new.parent.stat();assert parent.st_uid==0 and not parent.st_mode&0o022 and not new.parent.is_symlink()
 new.mkdir(mode=0o700)
 header='BACKUP='+repr(str(old))+'\nSTAGE_SHA256='+repr(stage_sha)+'\nRESULT_DIRECTORY='+repr(str(new))+'\n'
 helper=new/'rollback-manager-v2.py'
 with helper.open('xb') as stream:stream.write(header.encode()+base64.b64decode(HELPER_B64))
 helper.chmod(0o600)
p=subprocess.run(['python3','-B',str(helper),'--check'],capture_output=True,text=True,timeout=20)
assert p.returncode==0,(p.returncode,p.stderr)
r={'installed_at':time.time(),'review_backup':str(new),'rollback_helper':str(helper),'helper_sha256':sha(helper),'template_sha256':hashlib.sha256(base64.b64decode(HELPER_B64)).hexdigest(),'original_manifest_sha256':manifest_sha,'original_stage_sha256':stage_sha,'original_stable_items_rechecked':check_original(),'check_exit':p.returncode,'check_result':json.loads(p.stdout),'active_state_changed':False,'production_rollback_executed':False}
(new/'installation.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n');(new/'installation.json').chmod(0o600)
print(json.dumps(r,ensure_ascii=False,indent=2))

from pathlib import Path
import subprocess,json,hashlib,os,fcntl,time,datetime
base=Path('/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z');baseline=json.loads((base/'baseline.json').read_text());stage=base/'stage'
lock=open('/run/lock/crowdsec-1key.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
for name,digest in baseline['protected_sha256'].items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest,('changed protected file',name)
assert json.loads((base/'staged-result.json').read_text())['config_validation']['exit']==0
files={Path('/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml'):(stage/'parsers/s01-parse/20-realm-forwardx-observation.yaml').read_bytes(),Path('/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml'):(stage/'acquis.d/crowdbastion-realm-forwardx.yaml').read_bytes(),Path('/etc/systemd/journald.conf.d/60-crowdbastion-storage-cap.conf'):b'# CrowdBastion realm protection rollout: bound log storage without forced vacuum.\n[Journal]\nSystemMaxUse=128M\nSystemKeepFree=512M\nRuntimeMaxUse=32M\nRuntimeKeepFree=16M\n'}
for p in files:assert not p.exists() and not p.is_symlink(),('refuse overwrite',str(p))
created=[];restarted=[]
def cmd(args,timeout=45):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if p.returncode:raise RuntimeError(str(args)+': '+p.stdout[-1000:]+p.stderr[-1500:])
 return p.stdout
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backup':str(base),'new_files':{},'restarted':restarted}
try:
 for p,data in files.items():
  p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
  assert not p.parent.is_symlink() and p.parent.stat().st_uid==0
  tmp=p.with_name('.'+p.name+'.realm-opt-tmp')
  fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  os.chmod(tmp,0o644);os.replace(tmp,p);created.append(p);r['new_files'][str(p)]=hashlib.sha256(data).hexdigest()
 r['live_config_validation']=cmd(['crowdsec','-t'])[-2000:]
 # These are the only restarted services; realm and Firewall Bouncer stay running.
 restarted.append('systemd-journald');cmd(['systemctl','restart','systemd-journald'])
 cmd(['systemctl','is-active','systemd-journald'])
 restarted.append('crowdsec');cmd(['systemctl','restart','crowdsec'])
 deadline=time.monotonic()+20
 while True:
  mainpid=cmd(['systemctl','show','crowdsec','-p','MainPID','--value']).strip()
  children=[]
  for process in Path('/proc').glob('[0-9]*'):
   try:
    if (process/'comm').read_text().strip()!='journalctl':continue
    status=(process/'status').read_text()
    if 'PPid:\t'+mainpid+'\n' not in status:continue
    argv=(process/'cmdline').read_bytes().decode().split('\0')
    if '_SYSTEMD_UNIT=forwardx-realm-both-56017.service' in argv and '_SYSTEMD_UNIT=forwardx-realm-both-58372.service' in argv:children.append({'pid':process.name,'argv':argv})
   except (FileNotFoundError,PermissionError):pass
  if children:r['realm_journal_followers']=children;break
  if time.monotonic()>=deadline:raise RuntimeError('realm journal follower not running under CrowdSec')
  time.sleep(.2)
 m=json.loads(cmd(['cscli','metrics','show','-o','json']))
 r['realm_acquisition_metrics']={k:v for k,v in m.get('acquisition',{}).items() if 'forwardx-realm' in k}
 r['metrics_note']='Acquisition metrics appear after the first new event; follower existence and validated config establish readiness, not live event parsing.'
 r['service_states']=cmd(['systemctl','show','forwardx-realm-both-56017','forwardx-realm-both-58372','forwardx-agent','crowdsec','crowdsec-firewall-bouncer','-p','Id','-p','MainPID','-p','NRestarts','-p','ActiveState'])
 assert 'MainPID=505\n' in r['service_states'] and 'MainPID=511\n' in r['service_states'] and 'MainPID=2109\n' in r['service_states']
 for name,digest in baseline['protected_sha256'].items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest,('protected file changed',name)
 r['protected_hashes_unchanged']=True
 r['journal_effective']=cmd(['systemd-analyze','cat-config','systemd/journald.conf'])[-1000:]
 r['journal_disk']=cmd(['journalctl','--disk-usage'])
 r['status']='applied'
except Exception as e:
 r['status']='rolled_back';r['error']=str(e)
 for p in reversed(created):
  if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest()==r['new_files'][str(p)]:p.unlink()
 for u in restarted:
  try:
   recovery=subprocess.run(['systemctl','restart',u],capture_output=True,timeout=45)
   if recovery.returncode:r.setdefault('rollback_errors',[]).append(u+': restart failed')
  except Exception as recovery_error:r.setdefault('rollback_errors',[]).append(u+': '+str(recovery_error))
 if r.get('rollback_errors'):r['status']='rollback_incomplete'
 (base/'apply-result.json').write_text(json.dumps(r,ensure_ascii=False,indent=2));print(json.dumps(r,ensure_ascii=False,indent=2));raise
(base/'apply-result.json').write_text(json.dumps(r,ensure_ascii=False,indent=2));print(json.dumps(r,ensure_ascii=False,indent=2))

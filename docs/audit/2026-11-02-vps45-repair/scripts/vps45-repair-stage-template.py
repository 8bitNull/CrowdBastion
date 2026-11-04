from pathlib import Path
import base64,datetime,hashlib,io,json,os,shutil,stat,subprocess,sys,tarfile
os.umask(0o077)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
release=Path('/opt/crowdbastion/releases/vps45-repair-20261102-'+METADATA['fingerprint'][:12])
backup=Path('/var/backups/crowdbastion/vps45-repair-'+stamp)
runtime=Path('/usr/local/lib/crowdsec-1key');current=runtime/'current'
maintenance=runtime/('release-vps45-repair-20261102-'+METADATA['fingerprint'][:12])
root=Path('/root/crowdsec-1key');next_root=Path('/root/.crowdsec-1key.vps45-next-'+stamp)
unit=Path('/etc/systemd/system/crowdbastion-vps45-static.service');policy=Path('/usr/local/lib/crowdbastion-vps45-static')

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(argv):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=30);assert p.returncode==0,(argv[0],p.returncode);return p.stdout

def private_parent(p):
 for path in [p,*p.parents]:
  if path.exists():
   s=path.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,str(path)

def snapshot(paths):
 result={}
 for path in paths:
  p=Path(path)
  for q in [p,*sorted(p.rglob('*'))] if p.is_dir() and not p.is_symlink() else [p]:
   if q.is_symlink():result[str(q)]={'link':os.readlink(q)}
   elif q.is_file():result[str(q)]={'sha256':sha(q),'mode':stat.S_IMODE(q.stat().st_mode),'uid':q.stat().st_uid}
 return result

assert os.geteuid()==0
for p in [release,backup,maintenance,next_root,unit,policy]:
 private_parent(p.parent);assert not p.exists() and not p.is_symlink(),str(p)
assert current.is_symlink() and os.readlink(current)==PREFLIGHT['entries'][str(current)]['target']
assert run(['crontab','-u','root','-l'])==PREFLIGHT['root_crontab']
for binary,expected in PREFLIGHT['rules'].items():assert run([binary,'-w','5','-S'])==expected
assert sha('/etc/cron.d/crowdsec-autoupdate')==PREFLIGHT['entries']['/etc/cron.d/crowdsec-autoupdate']['sha256']
for path in ['/usr/local/bin/crowdbastion','/usr/local/bin/crowdbastion.sh','/root/crowdbastion.sh','/root/install-crowdsec-1panel.sh']:
 assert not Path(path).exists() and not Path(path).is_symlink(),path
raw=base64.b64decode(PACKAGE);assert hashlib.sha256(raw).hexdigest()==METADATA['tar_sha256']
release.mkdir(mode=0o700,parents=True);release.chmod(0o700)
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tar:
 assert len(tar.getmembers())==len(METADATA['file_hashes'])
 for member in tar.getmembers():
  assert member.name in METADATA['file_hashes'] and member.isfile()
  p=release/member.name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  content=tar.extractfile(member).read();assert hashlib.sha256(content).hexdigest()==METADATA['file_hashes'][member.name]
  with p.open('xb') as stream:stream.write(content)
  p.chmod(0o700 if p.name=='crowdbastion.sh' else 0o600)
(release/'manager.sh').write_bytes((release/'crowdbastion.sh').read_bytes());(release/'manager.sh').chmod(0o700)
(release/'install-crowdsec-1panel.sh').symlink_to('crowdbastion.sh')
sys.path.insert(0,str(release/'lib'))
from crowdsec_bot_runtime import maintenance_guard
from crowdsec_maintenance import runtime_preflight,fingerprint
from crowdbastion_ux import code_fingerprint
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 runtime_preflight(runtime)
 assert code_fingerprint(release/'crowdbastion.sh')==METADATA['fingerprint']
 assert run(['crontab','-u','root','-l'])==PREFLIGHT['root_crontab']
 backup.mkdir(mode=0o700,parents=True);backup.chmod(0o700)
 assert backup.stat().st_dev==root.stat().st_dev
 shutil.copytree(release,maintenance,symlinks=True)
 shutil.copytree(root,next_root,symlinks=True)
 shutil.rmtree(next_root/'lib');shutil.copytree(release/'lib',next_root/'lib')
 for name in ['crowdbastion.sh','manager.sh','readme.md']:
  shutil.copy2(release/name,next_root/name)
 assert code_fingerprint(next_root/'crowdbastion.sh')==METADATA['fingerprint']
 registry=Path('/etc/crowdsec/crowdsec-1key-web-installs.json')
 web=json.loads(registry.read_text());protected_paths=['/etc/crowdsec','/var/lib/crowdbastion/node-roles.json','/etc/cron.d/crowdsec-autoupdate','/etc/systemd/system/crowdsec-firewall-bouncer.service.d','/etc/iptables/rules.v4','/etc/iptables/rules.v6']
 protected_paths += [entry[k] for entry in web.values() for k in ['host_assets','host_target']]
 protected=snapshot(protected_paths)
 (backup/'protected-before.json').write_text(json.dumps(protected,indent=2)+'\n')
 with tarfile.open(backup/'config-and-web.before.tar.gz','w:gz') as tar:
  for path in protected_paths:
   if Path(path).exists():tar.add(path,arcname=str(Path(path)).lstrip('/'))
 (backup/'root.crontab.before').write_text(PREFLIGHT['root_crontab'])
 for binary in ['iptables','ip6tables']:(backup/(binary+'-save.before.txt')).write_text(run([binary+'-save']))
 (backup/'apply.py.prepared').write_text(STATIC_CODE)
 (backup/'static.service.prepared').write_text(STATIC_UNIT)
 stage={'stamp':stamp,'release':str(release),'backup':str(backup),'root':str(root),'next_root':str(next_root),'maintenance':str(maintenance),'old_pointer':os.readlink(current),'fingerprint':METADATA['fingerprint'],'original_source_fingerprint':fingerprint(root),'protected_paths':protected_paths,'static_unit':str(unit),'static_policy':str(policy),'static_code_sha256':sha(backup/'apply.py.prepared'),'static_unit_sha256':sha(backup/'static.service.prepared'),'root_crontab_sha256':sha(backup/'root.crontab.before'),'rules_before':PREFLIGHT['rules']}
 (backup/'stage.json').write_text(json.dumps(stage,indent=2)+'\n')
 for p in [backup,release,maintenance,next_root]:
  for q in [p,*p.rglob('*')]:
   if not q.is_symlink():q.chmod(0o700 if q.is_dir() or q.name in ('crowdbastion.sh','manager.sh') else 0o600)
 assert run(['bash',str(release/'crowdbastion.sh'),'--help'])
print(json.dumps({'backup':str(backup),'release':str(release),'maintenance':str(maintenance),'fingerprint':METADATA['fingerprint'],'protected_files':len(protected),'stage_sha256':sha(backup/'stage.json'),'prepared':True}))

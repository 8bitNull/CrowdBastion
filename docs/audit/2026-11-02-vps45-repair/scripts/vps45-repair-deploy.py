BACKUP='/var/backups/crowdbastion/vps45-repair-20261102T024205Z'
STAGE_SHA256='3a15ba7dbcb3805fe361131f91029fe8c53f15109afa35eeb869e19410ed719f'
from pathlib import Path
import hashlib,json,os,signal,subprocess,sys,time
os.umask(0o077)
backup=Path(BACKUP);stage=json.loads((backup/'stage.json').read_text());release=Path(stage['release']);root=Path(stage['root']);next_root=Path(stage['next_root']);current=Path('/usr/local/lib/crowdsec-1key/current');unit=Path(stage['static_unit']);policy=Path(stage['static_policy'])
sys.path.insert(0,str(release/'lib'))
from crowdsec_bot_runtime import maintenance_guard
from crowdsec_maintenance import fingerprint
from crowdbastion_ux import code_fingerprint
import crowdsec_existing_deployment as cron
import importlib.util
spec=importlib.util.spec_from_file_location('static',backup/'apply.py.prepared');
# The prepared filename has no .py suffix; load with an explicit source loader.
from importlib.machinery import SourceFileLoader
spec=importlib.util.spec_from_loader('static',SourceFileLoader('static',str(backup/'apply.py.prepared')));static=importlib.util.module_from_spec(spec);spec.loader.exec_module(static)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(argv,check=True,timeout=30):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
 if check and p.returncode:raise RuntimeError('Command failed: '+argv[0])
 return p

def snapshot(paths):
 result={}
 for name in paths:
  p=Path(name)
  for q in [p,*sorted(p.rglob('*'))] if p.is_dir() and not p.is_symlink() else [p]:
   if q.is_symlink():result[str(q)]={'link':os.readlink(q)}
   elif q.is_file():result[str(q)]={'sha256':sha(q),'mode':q.stat().st_mode&0o777,'uid':q.stat().st_uid}
 return result

def save(name,value):
 p=backup/name
 with p.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
 p.chmod(0o600)

def atomic_pointer(target):
 link=current.parent/('.vps45-pointer-'+stage['stamp']);assert not link.exists() and not link.is_symlink()
 link.symlink_to(target);os.replace(link,current)

def interrupted(signum,frame):raise RuntimeError('Deployment interrupted.')
signal.signal(signal.SIGINT,interrupted);signal.signal(signal.SIGTERM,interrupted)
assert sha(backup/'stage.json')==STAGE_SHA256
assert code_fingerprint(release/'crowdbastion.sh')==stage['fingerprint']
assert sha(backup/'apply.py.prepared')==stage['static_code_sha256']
assert sha(backup/'static.service.prepared')==stage['static_unit_sha256']
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 assert fingerprint(root)==stage['original_source_fingerprint']
 assert code_fingerprint(next_root/'crowdbastion.sh')==stage['fingerprint']
 assert snapshot(stage['protected_paths'])==json.loads((backup/'protected-before.json').read_text())
 assert os.readlink(current)==stage['old_pointer']
 assert cron._cron_read()==(backup/'root.crontab.before').read_bytes()
 assert cron.cron_list()==[{'index':1,'family':'IPv4'},{'index':2,'family':'IPv6'}]
 for binary,value in stage['rules_before'].items():
  assert run([binary,'-w','5','-S']).stdout==value
  assert run([binary,'-w','5','-S',static.CHAIN],False).returncode==1
 assert not unit.exists() and not unit.is_symlink() and not policy.exists() and not policy.is_symlink()
 static_committed=False
 try:
  policy.mkdir(mode=0o700);(policy/'apply.py').write_bytes((backup/'apply.py.prepared').read_bytes());(policy/'apply.py').chmod(0o600)
  unit.write_bytes((backup/'static.service.prepared').read_bytes());unit.chmod(0o644)
  verification=run(['systemd-analyze','verify',str(unit)],False)
  (backup/'static-unit-verify.txt').write_text(verification.stdout+verification.stderr)
  assert verification.returncode==0
  run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',unit.name])
  assert run(['systemctl','is-active',unit.name]).stdout.strip()=='active'
  assert run(['systemctl','is-enabled',unit.name]).stdout.strip()=='enabled'
  for binary,expected in stage['rules_before'].items():
   actual=run([binary,'-w','5','-S']).stdout
   filtered='\n'.join(line for line in actual.splitlines() if static.CHAIN not in line)+'\n'
   assert filtered==expected
  for index in (1,2):
   attempt=backup/('cron-'+str(index));attempt.mkdir(mode=0o700);cron.cron_disable(attempt,index)
  after=cron._disabled(cron._disabled((backup/'root.crontab.before').read_bytes(),1),2)
  assert cron._cron_read()==after
  (backup/'root.crontab.after').write_bytes(after)
  save('static-committed.json',{'time':time.time(),'unit':str(unit),'policy':str(policy),'cron_entries_disabled':2,'rules_preserved':True})
  static_committed=True
 except BaseException:
  for index in (2,1):
   attempt=backup/('cron-'+str(index))
   if (attempt/cron.RECORD).is_file():cron.cron_restore(attempt)
  run(['systemctl','disable','--now',unit.name],False)
  for binary in ['ip6tables','iptables']:
   actual=run([binary,'-w','5','-S',static.CHAIN],False)
   if actual.returncode==0:
    import shlex
    observed=[shlex.split(s) for s in actual.stdout.splitlines() if s.startswith('-A ')]
    expected=[['-A',static.CHAIN,*r] for r in static.RULES];assert observed==expected[:len(observed)]
    jump=[binary,'-w','5','-C','INPUT','-j',static.CHAIN]
    if run(jump,False).returncode==0:run([binary,'-w','5','-D','INPUT','-j',static.CHAIN])
    for rule in reversed(observed):run([binary,'-w','5','-D',*rule[1:]])
    run([binary,'-w','5','-X',static.CHAIN])
  if unit.is_file() and sha(unit)==stage['static_unit_sha256']:unit.unlink()
  if (policy/'apply.py').is_file() and sha(policy/'apply.py')==stage['static_code_sha256']:(policy/'apply.py').unlink();policy.rmdir()
  run(['systemctl','daemon-reload']);raise
 before_root=backup/'source-directory.before';entry=Path('/usr/local/bin/crowdbastion');moved=False;pointer_changed=False
 assert not before_root.exists() and not entry.exists() and not entry.is_symlink()
 entry_bytes=('#!/bin/sh\n# CrowdBastion managed entry; execute the complete release.\nexec /bin/bash "'+str(release/'crowdbastion.sh')+'" "$@"\n').encode()
 try:
  root.rename(before_root);moved=True;next_root.rename(root)
  atomic_pointer(stage['maintenance']);pointer_changed=True
  with entry.open('xb') as f:f.write(entry_bytes)
  entry.chmod(0o755)
  for manager in [root/'crowdbastion.sh',current/'manager.sh',release/'crowdbastion.sh']:
   assert code_fingerprint(manager)==stage['fingerprint']
   p=run(['bash',str(manager),'--help']);assert '--status-json' in p.stdout
  assert snapshot(stage['protected_paths'])==json.loads((backup/'protected-before.json').read_text())
  save('manager-committed.json',{'time':time.time(),'entry':str(entry),'entry_sha256':sha(entry),'old_pointer':stage['old_pointer'],'new_pointer':os.readlink(current),'fingerprint':stage['fingerprint']})
 except BaseException:
  if entry.is_file() and entry.read_bytes()==entry_bytes:entry.unlink()
  if pointer_changed and os.readlink(current)==stage['maintenance']:atomic_pointer(stage['old_pointer'])
  if moved:
   if root.exists():
    assert code_fingerprint(root/'crowdbastion.sh')==stage['fingerprint'];root.rename(backup/'source-directory.failed')
   before_root.rename(root)
  save('manager-rolled-back.json',{'time':time.time(),'static_repair_retained':static_committed});raise
 result={'backup':str(backup),'release':str(release),'fingerprint':stage['fingerprint'],'static_unit':'active/enabled','restore_crons_disabled':2,'manager_copies_match':True,'protected_files_unchanged':len(snapshot(stage['protected_paths'])),'completed_at':time.time()}
 save('deployment.json',result)
print(json.dumps(result,ensure_ascii=False))

ROLLBACK="import fcntl,hashlib,json,os,subprocess\nfrom pathlib import Path\nbase=Path('/var/backups/crowdbastion/anytls-20261103')\nlock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)\nm=json.loads((base/'manifest.json').read_text())\nif (base/'committed').exists():\n print('committed; no rollback');raise SystemExit(0)\nerrors=[]\nfor f in reversed(m['files']):\n p=Path(f['path']);current=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None\n if current==f['before']:continue\n if current!=f['after']:\n  errors.append('file drift: '+str(p));continue\n if f['backup']:\n  data=Path(f['backup']).read_bytes();assert hashlib.sha256(data).hexdigest()==f['before']\n  temp=p.with_name(p.name+'.crowdbastion-restore');temp.write_bytes(data);temp.chmod(f['mode']);os.replace(temp,p)\n else:p.unlink()\nfor k,target in m['changes'].items():\n current=subprocess.run(['sysctl','-n',k],capture_output=True,text=True,check=True).stdout\n current=' '.join(current.split())\n if current==m['runtime_before'][k]:continue\n if current!=target:\n  errors.append('runtime drift: '+k);continue\n p=subprocess.run(['sysctl','-w',k+'='+m['runtime_before'][k]],capture_output=True,text=True)\n if p.returncode:errors.append('restore failed: '+k)\n(base/'rollback-result.json').write_text(json.dumps({'errors':errors}));(base/'rollback-result.json').chmod(0o600)\nprint(json.dumps({'rolled_back':not errors,'errors':errors}))\nraise SystemExit(bool(errors))\n"
import fcntl,hashlib,json,os,subprocess
from pathlib import Path
base=Path('/var/backups/crowdbastion/anytls-20261103')
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
m=json.loads((base/'manifest.json').read_text())
assert m['status']=='staged'
for f in m['files']:
 p=Path(f['path']);assert not p.is_symlink()
 actual=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
 assert actual==f['before'],'write precondition failed'
 assert hashlib.sha256(Path(f['candidate']).read_bytes()).hexdigest()==f['after']
for k,v in m['runtime_before'].items():
 p=subprocess.run(['sysctl','-n',k],capture_output=True,text=True,check=True,timeout=5)
 assert ' '.join(p.stdout.split())==v,'runtime changed since stage'
r=base/'rollback.py';r.write_text(ROLLBACK);r.chmod(0o700)
subprocess.run(['systemd-run','--unit=crowdbastion216-network-rollback','--on-active=10m','--timer-property=AccuracySec=1s','/usr/bin/python3','-B',str(r)],check=True,capture_output=True,timeout=15)
try:
 for f in m['files']:
  p=Path(f['path']);temp=p.with_name(p.name+'.crowdbastion-new')
  with temp.open('xb') as stream:stream.write(Path(f['candidate']).read_bytes());stream.flush();os.fsync(stream.fileno())
  temp.chmod(f['mode']);os.replace(temp,p)
 for k,v in m['changes'].items():
  subprocess.run(['sysctl','-w',k+'='+v],capture_output=True,check=True,timeout=5)
 for k,v in m['settings'].items():
  p=subprocess.run(['sysctl','-n',k],capture_output=True,text=True,check=True,timeout=5)
  assert ' '.join(p.stdout.split())==v,'postwrite mismatch'
 (base/'applied').write_text('awaiting independent verification');(base/'applied').chmod(0o600)
 print(json.dumps({'applied':True,'runtime_changes':m['changes'],'managed_keys':len(m['settings']),'rollback_timer':'10 minutes','backup':str(base)}))
except BaseException:
 lock.close()
 subprocess.run(['/usr/bin/python3','-B',str(r)],check=False,timeout=45)
 raise

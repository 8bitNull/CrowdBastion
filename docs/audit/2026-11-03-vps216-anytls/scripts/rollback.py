import fcntl,hashlib,json,os,subprocess
from pathlib import Path
base=Path('/var/backups/crowdbastion/anytls-20261103')
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
m=json.loads((base/'manifest.json').read_text())
if (base/'committed').exists():
 print('committed; no rollback');raise SystemExit(0)
errors=[]
for f in reversed(m['files']):
 p=Path(f['path']);current=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
 if current==f['before']:continue
 if current!=f['after']:
  errors.append('file drift: '+str(p));continue
 if f['backup']:
  data=Path(f['backup']).read_bytes();assert hashlib.sha256(data).hexdigest()==f['before']
  temp=p.with_name(p.name+'.crowdbastion-restore');temp.write_bytes(data);temp.chmod(f['mode']);os.replace(temp,p)
 else:p.unlink()
for k,target in m['changes'].items():
 current=subprocess.run(['sysctl','-n',k],capture_output=True,text=True,check=True).stdout
 current=' '.join(current.split())
 if current==m['runtime_before'][k]:continue
 if current!=target:
  errors.append('runtime drift: '+k);continue
 p=subprocess.run(['sysctl','-w',k+'='+m['runtime_before'][k]],capture_output=True,text=True)
 if p.returncode:errors.append('restore failed: '+k)
(base/'rollback-result.json').write_text(json.dumps({'errors':errors}));(base/'rollback-result.json').chmod(0o600)
print(json.dumps({'rolled_back':not errors,'errors':errors}))
raise SystemExit(bool(errors))

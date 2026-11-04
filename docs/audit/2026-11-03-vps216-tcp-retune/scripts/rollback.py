import fcntl,hashlib,json,os
from pathlib import Path
base=Path('/var/backups/crowdbastion/tcp-retune-20261103')
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
if (base/'committed').exists():
 print('committed; no rollback');raise SystemExit(0)
m=json.loads((base/'manifest.json').read_text())
errors=[]
for f in reversed(m['files']):
 try:
  p=Path(f['path']);current=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
  if current==f['before']:continue
  if current!=f['after']:
   errors.append('file drift: '+str(p));continue
  if f['backup']:
   data=Path(f['backup']).read_bytes()
   if hashlib.sha256(data).hexdigest()!=f['before']:raise ValueError('backup digest mismatch')
   temp=p.with_name(p.name+'.crowdbastion-restore')
   with temp.open('wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
   temp.chmod(f['mode']);os.replace(temp,p)
  else:p.unlink()
 except Exception as error:errors.append('file restore failed: '+f['path']+' '+type(error).__name__)
for k,target in m['changes'].items():
 try:
  p=Path('/proc/sys/'+k.replace('.','/'))
  current=' '.join(p.read_text().split())
  if current==m['runtime_before'][k]:continue
  if current!=target:
   errors.append('runtime drift: '+k);continue
  p.write_text(m['runtime_before'][k]+'\n')
  if ' '.join(p.read_text().split())!=m['runtime_before'][k]:raise ValueError('runtime restore mismatch')
 except Exception as error:errors.append('runtime restore failed: '+k+' '+type(error).__name__)
report={'rolled_back':not errors,'errors':errors}
temp=base/'rollback-result.json.new'
with temp.open('w') as stream:json.dump(report,stream);stream.flush();os.fsync(stream.fileno())
temp.chmod(0o600);os.replace(temp,base/'rollback-result.json')
print(json.dumps(report))
raise SystemExit(bool(errors))

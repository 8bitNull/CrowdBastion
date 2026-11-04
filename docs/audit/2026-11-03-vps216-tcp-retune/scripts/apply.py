ROLLBACK="import fcntl,hashlib,json,os\nfrom pathlib import Path\nbase=Path('/var/backups/crowdbastion/tcp-retune-20261103')\nlock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)\nif (base/'committed').exists():\n print('committed; no rollback');raise SystemExit(0)\nm=json.loads((base/'manifest.json').read_text())\nerrors=[]\nfor f in reversed(m['files']):\n try:\n  p=Path(f['path']);current=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None\n  if current==f['before']:continue\n  if current!=f['after']:\n   errors.append('file drift: '+str(p));continue\n  if f['backup']:\n   data=Path(f['backup']).read_bytes()\n   if hashlib.sha256(data).hexdigest()!=f['before']:raise ValueError('backup digest mismatch')\n   temp=p.with_name(p.name+'.crowdbastion-restore')\n   with temp.open('wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())\n   temp.chmod(f['mode']);os.replace(temp,p)\n  else:p.unlink()\n except Exception as error:errors.append('file restore failed: '+f['path']+' '+type(error).__name__)\nfor k,target in m['changes'].items():\n try:\n  p=Path('/proc/sys/'+k.replace('.','/'))\n  current=' '.join(p.read_text().split())\n  if current==m['runtime_before'][k]:continue\n  if current!=target:\n   errors.append('runtime drift: '+k);continue\n  p.write_text(m['runtime_before'][k]+'\\n')\n  if ' '.join(p.read_text().split())!=m['runtime_before'][k]:raise ValueError('runtime restore mismatch')\n except Exception as error:errors.append('runtime restore failed: '+k+' '+type(error).__name__)\nreport={'rolled_back':not errors,'errors':errors}\ntemp=base/'rollback-result.json.new'\nwith temp.open('w') as stream:json.dump(report,stream);stream.flush();os.fsync(stream.fileno())\ntemp.chmod(0o600);os.replace(temp,base/'rollback-result.json')\nprint(json.dumps(report))\nraise SystemExit(bool(errors))\n"
import fcntl,hashlib,json,os,subprocess,time,sys,socket
from pathlib import Path
base=Path('/var/backups/crowdbastion/tcp-retune-20261103')
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
m=json.loads((base/'manifest.json').read_text())
assert m['status']=='staged' and not (base/'applied').exists() and not (base/'committed').exists() and not (base/'rollback-result.json').exists()
def readkey(k):return ' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split())
for f in m['files']:
 p=Path(f['path']);assert not p.is_symlink()
 assert (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None)==f['before']
 assert hashlib.sha256(Path(f['candidate']).read_bytes()).hexdigest()==f['after']
for k,v in m['runtime_before'].items():assert readkey(k)==v
assert m['settings']['net.ipv4.tcp_mem']==m['runtime_before']['net.ipv4.tcp_mem']
for artifact in base.iterdir():
 if artifact.is_file():
  with artifact.open('rb') as fd:os.fsync(fd.fileno())
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_firewall_evidence as evidence
config=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
def api():
 start=time.monotonic();rows=evidence.live(config)
 return {'ok':True,'seconds':round(time.monotonic()-start,3),'records':len(rows)}
def services():
 return subprocess.run(['systemctl','show','V2bX','crowdsec','crowdsec-firewall-bouncer','docker','--property=Id,MainPID,ActiveState,NRestarts'],capture_output=True,text=True,check=True,timeout=15).stdout
before_api=api();before_services=services()
proof={'before_api':before_api,'before_services':before_services,'parameters':[]}
print(json.dumps({'baseline':before_api}),flush=True)
r=base/'rollback.py';r.write_text(ROLLBACK);r.chmod(0o700)
with r.open('rb') as fd:os.fsync(fd.fileno())
subprocess.run(['systemd-run','--unit=crowdbastion216-retune-rollback','--on-active=15m','--timer-property=AccuracySec=1s','/usr/bin/python3','-B',str(r)],check=True,capture_output=True,timeout=15)
try:
 for k,v in m['changes'].items():
  Path('/proc/sys/'+k.replace('.','/')).write_text(v+'\n')
  assert readkey(k)==v
  checked=api()
  s=socket.create_connection(('127.0.0.1',8443),timeout=3);s.close()
  item={'key':k,'before':m['runtime_before'][k],'after':v,'api':checked,'anytls_tcp_loopback':True}
  proof['parameters'].append(item);print(json.dumps(item),flush=True)
 assert services()==before_services,'service changed during parameter checks'
 for f in m['files']:
  p=Path(f['path']);assert (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None)==f['before']
  temp=p.with_name(p.name+'.crowdbastion-retune-new')
  with temp.open('xb') as stream:stream.write(Path(f['candidate']).read_bytes());stream.flush();os.fsync(stream.fileno())
  temp.chmod(f['mode']);os.replace(temp,p)
 for k,v in m['settings'].items():assert readkey(k)==v
 proof['after_services']=services();proof['persisted']=True
 (base/'apply-proof.json').write_text(json.dumps(proof,indent=2));(base/'apply-proof.json').chmod(0o600)
 with (base/'apply-proof.json').open('rb') as fd:os.fsync(fd.fileno())
 (base/'applied').write_text('awaiting independent verification');(base/'applied').chmod(0o600)
 print(json.dumps({'applied':True,'managed_keys':len(m['settings']),'runtime_changes':len(m['changes']),'tcp_mem_unchanged':True,'rollback_timer':'15 minutes'}),flush=True)
except BaseException:
 lock.close()
 try:
  result=subprocess.run(['/usr/bin/python3','-B',str(r)],capture_output=True,text=True,timeout=90)
  report=json.loads((base/'rollback-result.json').read_text())
  if result.returncode==0 and report.get('rolled_back') is True and report.get('errors')==[]:
   subprocess.run(['systemctl','stop','crowdbastion216-retune-rollback.timer'],capture_output=True,timeout=15)
  else:print(json.dumps({'rollback_incomplete':True,'timer_kept':True}),flush=True)
 except Exception:
  print(json.dumps({'rollback_incomplete':True,'timer_kept':True}),flush=True)
 raise

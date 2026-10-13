"""Real hy2 fork/client controls, native loopback and a real UDP forwarding socket."""
from pathlib import Path
import sys, os, json, shutil, subprocess, time, socket, threading
base=Path(__file__).resolve().parent; repo=Path('/data/project/script/crowdsec-1key'); old=Path('/tmp/v2bx-real-lab')
sys.path[:0]=[str(old),str(repo/'lib')]
from fixture import start,nodes,client_config
from crowdsec_v2bx_observe import Observer
from crowdsec_v2bx_logs import eligible
for name in ('cert.pem','key.pem','request.py'):shutil.copy2(old/name,base/name)
os.chmod(base/'key.pem',0o600)
(base/'closed-request.py').write_text((base/'request.py').read_text().replace('(28800).to_bytes','(28801).to_bytes'))
with socket.socket() as s:s.bind(('127.0.0.1',28801))
servers,calls=start();process=None;out=None;relay_stop=threading.Event()
# Each sequential probe has a distinct upstream socket. It changes the server-visible peer.
relay_in=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);relay_in.bind(('127.0.0.2',29113));relay_in.settimeout(.2)
relay_sockets=[]
def relay():
 peers={}
 while not relay_stop.is_set():
  try:data,peer=relay_in.recvfrom(65535)
  except socket.timeout:continue
  except OSError:return
  if peer not in peers:
   upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.bind(('127.0.0.2',0));upstream.connect(('127.0.0.1',29013));upstream.settimeout(.2);peers[peer]=upstream;relay_sockets.append(upstream)
   def back(sock=upstream,p=peer):
    while not relay_stop.is_set():
     try:reply=sock.recv(65535);relay_in.sendto(reply,p)
     except socket.timeout:continue
     except OSError:return
   threading.Thread(target=back,daemon=True).start()
  peers[peer].send(data)
threading.Thread(target=relay,daemon=True).start()
log=base/'server.log';log.touch();observer=Observer(log,base/'events.sqlite','hysteria2',relay_cidrs='127.0.0.2/32')
report={'scope':'experimental V2bX v0.4.0 hy2 fork; real sing-box1.12.0, native IPv4 loopback and UDP socket relay; not VPS/physical network','cases':[],'production_validation':'unverified'}
config={'Log':{'Level':'info'},'Cores':[{'Type':'hysteria2','Log':{'Level':'info'}}],'Nodes':[nodes(base)[12]]}
(base/'config.json').write_text(json.dumps(config))
def stop():
 global process,out
 if process:process.terminate();process.wait(timeout=15);process=None
 if out:out.close();out=None
 observer.poll()
def run(phase,via='direct',valid=True,tls_bad=False,target='request.py',expected=True):
 observer.poll();before=observer.db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]
 cfg=client_config(base,13,valid,host='127.0.0.2' if via=='relay' else '127.0.0.1',port=29113 if via=='relay' else 29013)
 if tls_bad:cfg['outbounds'][0]['tls']['server_name']='wrong.invalid'
 (base/'client.json').write_text(json.dumps(cfg))
 with (base/'client.log').open('w') as stream:
  client=subprocess.Popen([str(old/'sing-box-1.12.0'),'run','-c',str(base/'client.json')],stdout=stream,stderr=stream)
  try:
   deadline=time.monotonic()+15
   while 'sing-box started' not in (base/'client.log').read_text():
    if client.poll() is not None or time.monotonic()>deadline:raise RuntimeError('client startup')
    time.sleep(.05)
   probe=subprocess.run([sys.executable,str(base/target)],capture_output=True,text=True,timeout=25)
   if probe.returncode:raise RuntimeError('probe failed')
   response=json.loads(probe.stdout)
  finally:client.terminate();client.wait(timeout=10)
 time.sleep(.2);observer.poll()
 events=[json.loads(r[0]) for r in observer.db.execute('SELECT payload FROM events WHERE seq>? ORDER BY seq',(before,))]
 rejects=[e for e in events if e['event_type']=='auth_failure']
 passed=response['response_verified']==expected and response['socks_negotiated'] and response['outcome']!='probe_error' and process.poll() is None
 if not valid:
  # This client probe sends one actual auth request; repeated calls are separately observable.
  passed &= len(rejects)==1 and rejects[0]['source_ip']==('127.0.0.2' if via=='relay' else '127.0.0.1') and eligible(rejects[0])==(via=='direct')
 else:passed &= not rejects
 row=dict(phase=phase,ingress=via,passed=bool(passed),response=response,events=events)
 report['cases'].append(row);print(json.dumps(row),flush=True)
 (base/'partial-results.json').write_text(json.dumps(report,indent=2)+'\n')
try:
 out=log.open('a');process=subprocess.Popen([str(base/'V2bX-experimental'),'server','-c',str(base/'config.json'),'-w=false'],stdout=out,stderr=out)
 deadline=time.monotonic()+30
 while 'Nodes started' not in log.read_text(errors='replace'):
  if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('server startup')
  time.sleep(.1)
 for mode, expected_count in (('masquerade',0),('repeated_bad',2)):
  observer.poll();before=observer.db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]
  response=subprocess.run([str(base/'http3-probe'),str(base/'cert.pem'),mode],capture_output=True,text=True,timeout=20)
  if response.returncode:raise RuntimeError('HTTP3 control failed')
  statuses=json.loads(response.stdout)['http_statuses'];time.sleep(.2);observer.poll()
  events=[json.loads(r[0]) for r in observer.db.execute('SELECT payload FROM events WHERE seq>? ORDER BY seq',(before,))]
  rejects=[e for e in events if e['event_type']=='auth_failure']
  report['cases'].append(dict(phase=mode,ingress='direct',passed=statuses==[404]*(2 if mode=='repeated_bad' else 1) and len(rejects)==expected_count,response={'http_statuses':statuses},events=events))
 for via in ('direct','relay'):
  run('healthy',via);run('wrong_credentials',via,valid=False,expected=False);run('recovery',via)
  run('target_unreachable',via,target='closed-request.py',expected=False)
  run('tls_name_mismatch',via,tls_bad=True,expected=False)
 # New consumer resumes without replaying committed positions.
 observer.poll();count=observer.status()['events'];observer.close()
 observer=Observer(log,base/'events.sqlite','hysteria2',relay_cidrs='127.0.0.2/32');observer.poll()
 assert observer.status()['events']==count
 run('consumer_restart_bad',valid=False,expected=False)
 stop();observer.export(base/'events.ndjson');report['sampler']=observer.status()
 report['status']='passed' if all(c['passed'] for c in report['cases']) else 'failed'
except Exception as e:report.update(status='failed',error_class=type(e).__name__);raise
finally:
 stop();observer.close();relay_stop.set();relay_in.close()
 for s in relay_sockets:s.close()
 for s in servers:s.shutdown();s.server_close()
 (base/'results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(report['cases'])}),flush=True)
sys.exit(0 if report['status']=='passed' else 1)

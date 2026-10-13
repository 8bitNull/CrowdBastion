"""Actual patched sing QUIC, real clients and UDP forwarding; native loopback only."""
from pathlib import Path
import sys,os,json,shutil,subprocess,time,socket,threading
base=Path(__file__).resolve().parent;repo=Path('/data/project/script/crowdsec-1key');old=Path('/tmp/v2bx-real-lab')
sys.path.insert(0,str(repo/'lib'))
from fixture import start,nodes,client_config,BAD,UUID,COMBINATIONS
from crowdsec_v2bx_observe import Observer
from crowdsec_v2bx_logs import eligible
for name in ('cert.pem','key.pem','request.py'):shutil.copy2(old/name,base/name)
os.chmod(base/'key.pem',0o600)
(base/'closed-request.py').write_text((base/'request.py').read_text().replace('(28800).to_bytes','(28801).to_bytes'))
with socket.socket() as s:s.bind(('127.0.0.1',28801))
servers,calls=start();process=None;out=None;relay_stop=threading.Event();sockets=[]
def relay(index):
 listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);listener.bind(('127.0.0.2',29100+index));listener.settimeout(.2);sockets.append(listener);peers={}
 while not relay_stop.is_set():
  try:data,peer=listener.recvfrom(65535)
  except socket.timeout:continue
  except OSError:return
  if peer not in peers:
   upstream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);upstream.bind(('127.0.0.2',0));upstream.connect(('127.0.0.1',29000+index));upstream.settimeout(.2);peers[peer]=upstream;sockets.append(upstream)
   def back(sock=upstream,p=peer):
    while not relay_stop.is_set():
     try:reply=sock.recv(65535);listener.sendto(reply,p)
     except socket.timeout:continue
     except OSError:return
   threading.Thread(target=back,daemon=True).start()
  peers[peer].send(data)
for i in (9,11,12):threading.Thread(target=relay,args=(i,),daemon=True).start()
log=base/'sing.log';log.touch();observer=Observer(log,base/'events.sqlite','sing',relay_cidrs='127.0.0.2/32')
report={'scope':'cumulative experimental V2bX v0.4.0 hy2/sing-quic patch, real sing-box1.12.0, IPv4 native loopback plus actual UDP socket relay; not VPS or physical network','cases':[],'production_validation':'unverified'}
config={'Log':{'Level':'info'},'Cores':[{'Type':'sing','Log':{'Level':'info','Timestamp':True,'Output':str(log)},'NTP':{'Enable':False}}],'Nodes':[nodes(base)[i-1] for i in (9,11,12,14)]}
(base/'config.json').write_text(json.dumps(config))
def stop():
 global process,out
 if process:process.terminate();process.wait(timeout=15);process=None
 if out:out.close();out=None
 observer.poll()
def run(index,phase,via='direct',valid=True,tls_bad=False,target='request.py',expected=True,password_only=False):
 observer.poll();before=observer.db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]
 cfg=client_config(base,index,valid,host='127.0.0.2' if via=='relay' else '127.0.0.1',port=29100+index if via=='relay' else 29000+index)
 if tls_bad:cfg['outbounds'][0]['tls']['server_name']='wrong.invalid'
 if password_only:cfg['outbounds'][0]['password']=BAD
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
 rejects=[e for e in events if e['event_type']=='auth_failure'];protocol=COMBINATIONS[index-1][1]
 passed=response['response_verified']==expected and response['socks_negotiated'] and response['outcome']!='probe_error' and process.poll() is None
 if not valid or password_only:
  passed &= len(rejects)==1 and rejects[0]['source_ip']==('127.0.0.2' if via=='relay' else '127.0.0.1') and eligible(rejects[0])==(via=='direct') and rejects[0]['protocol']==protocol
 else:passed &= not rejects
 row=dict(protocol=protocol,node=index,phase=phase,ingress=via,passed=bool(passed),response=response,events=events)
 report['cases'].append(row);print(json.dumps(row),flush=True)
 (base/'partial-results.json').write_text(json.dumps(report,indent=2)+'\n')
try:
 out=(base/'server.log').open('a');process=subprocess.Popen(['/tmp/v2bx-sing-quic-20261013/V2bX-final','server','-c',str(base/'config.json'),'-w=false'],stdout=out,stderr=out)
 deadline=time.monotonic()+30
 while 'Nodes started' not in (base/'server.log').read_text(errors='replace'):
  if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('server startup')
  time.sleep(.1)
 for mode, port in (('masquerade',29012),('repeated_bad',29012),('policy',29014),('auth_timeout',29009),('flood',29012)):
  observer.poll();before=observer.db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0];raw_before=log.stat().st_size
  probe=subprocess.run(['/tmp/v2bx-sing-quic-20261013/quic-probe',str(base/'cert.pem'),mode,str(port)],capture_output=True,text=True,timeout=20)
  if probe.returncode:raise RuntimeError('QUIC control failed')
  response=json.loads(probe.stdout);time.sleep(.2);observer.poll()
  events=[json.loads(r[0]) for r in observer.db.execute('SELECT payload FROM events WHERE seq>? ORDER BY seq',(before,))]
  rejects=[e for e in events if e['event_type']=='auth_failure']
  payloads=[]
  with log.open('rb') as raw:
   raw.seek(raw_before)
   for line in raw.read().decode().splitlines():
    if ': v2bx-observation ' in line:payloads.append(json.loads(line.split(': v2bx-observation ',1)[1]))
  if mode=='auth_timeout':passed=response['closed_without_auth'] and not rejects
  else:
   expected_responses=2 if mode=='repeated_bad' else 46 if mode=='flood' else 1
   passed=response['http_statuses']==[404]*expected_responses
   if mode=='repeated_bad':passed &= len(rejects)==2 and len(payloads)==2 and payloads[0]['addr']==payloads[1]['addr']
   elif mode=='flood':passed &= len(rejects)+sum(p.get('dropped',0) for p in payloads)==46 and any(p.get('dropped',0)>0 for p in payloads)
   else:passed &= not rejects
  row=dict(phase=mode,ingress='direct',passed=bool(passed),response=response,events=events,fixed_payloads=payloads)
  report['cases'].append(row);print(json.dumps(row),flush=True)
 stop();observer.export(base/'events.ndjson');report['sampler']=observer.status()
 # Check actual emitted auth records for fixed-field privacy, not whole raw logs.
 payloads=[]
 for line in log.read_text().splitlines():
  if ': v2bx-observation ' in line:payloads.append(json.loads(line.split(': v2bx-observation ',1)[1]))
 assert all(set(p)=={'schema_version','core','protocol','event_type', 'dropped' if p['event_type']=='observations_dropped' else 'addr'} for p in payloads)
 report['fixed_auth_payloads_checked']=len(payloads)
 assert 'auth_str=' not in log.read_text(), 'legacy credential leak'
 report['legacy_hysteria_auth_str_absent']=True
 event_lines=[line for line in log.read_text().splitlines() if ': v2bx-observation ' in line]
 assert all('http://' not in line and 'https://' not in line and UUID not in line and BAD not in line for line in event_lines)
 report['full_observation_lines_without_panel_or_credentials']=True
 report['status']='passed' if all(c['passed'] for c in report['cases']) else 'failed'
except Exception as e:report.update(status='failed',error_class=type(e).__name__);raise
finally:
 stop();observer.close();relay_stop.set()
 for s in sockets:s.close()
 for s in servers:s.shutdown();s.server_close()
 (base/'results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(report['cases'])}),flush=True)
sys.exit(0 if report['status']=='passed' else 1)

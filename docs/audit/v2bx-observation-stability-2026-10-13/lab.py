"""Real official program controls; native loopback only, no host firewall changes."""
from pathlib import Path
import json,os,sys,subprocess,time,shutil,socketserver,threading
repo=Path('/data/project/script/crowdsec-1key');old=Path('/tmp/v2bx-real-lab');base=Path(__file__).resolve().parent
sys.path.insert(0,str(old));sys.path.insert(0,str(repo/'lib'))
from fixture import COMBINATIONS,nodes,start,client_config
from crowdsec_v2bx_observe import Observer
from crowdsec_v2bx_logs import eligible
for n in ('cert.pem','key.pem'):shutil.copy2(old/n,base/n)
os.chmod(base/'key.pem',0o600)
probe=(old/'request.py').read_text()
for n,port in [('request.py',28800),('closed-request.py',28801),('slow-request.py',28802)]:
 (base/n).write_text(probe.replace('(28800).to_bytes',f'({port}).to_bytes'))
# Prove closed target port is not occupied.
import socket
with socket.socket() as sock:sock.bind(('127.0.0.1',28801))
class Slow(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(15)
  self.request.recv(4096)
  threading.Event().wait(12)
class SlowServer(socketserver.ThreadingTCPServer):
 allow_reuse_address=True;daemon_threads=True
slow=SlowServer(('127.0.0.1',28802),Slow);threading.Thread(target=slow.serve_forever,daemon=True).start()
servers,calls=start();process=None;out=None
logs={'xray':base/'xray-access.log','sing':base/'sing.log','hysteria2':base/'server.log'}
for p in logs.values():p.touch()
observers={core:Observer(path,base/(core+'.sqlite'),core,'+00:00') for core,path in logs.items()}
report={'scope':'real official V2bX v0.4.0 and sing-box1.12.0; controlled UniProxy, IPv4 native loopback TCP target, no firewall/production changes','cases':[],'lifecycle':[],'production_validation':'unverified'}
cores=[{'Type':'xray','Log':{'Level':'info','AccessPath':str(logs['xray']),'ErrorPath':str(base/'xray-error.log')},'AssetPath':str(old/'v2bx')},{'Type':'sing','Log':{'Level':'info','Timestamp':True,'Output':str(logs['sing'])},'NTP':{'Enable':False}},{'Type':'hysteria2','Log':{'Level':'info'}}]
(base/'config.json').write_text(json.dumps({'Log':{'Level':'info'},'Cores':cores,'Nodes':nodes(base)}))
def server_start():
 global process,out
 before=logs['hysteria2'].stat().st_size;out=logs['hysteria2'].open('a')
 process=subprocess.Popen([str(old/'v2bx/V2bX'),'server','-c',str(base/'config.json'),'-w=false'],stdout=out,stderr=out)
 end=time.monotonic()+30
 while 'Nodes started' not in logs['hysteria2'].read_text(errors='replace')[before:]:
  if process.poll() is not None or time.monotonic()>end:raise RuntimeError('V2bX startup')
  time.sleep(.1)
def server_stop():
 global process,out
 if process:process.terminate();process.wait(timeout=15);process=None
 if out:out.close();out=None
 for o in observers.values():o.poll()
def run(index,phase,valid=True,tls_mismatch=False,request='request.py',expect_response=True):
 core,protocol=COMBINATIONS[index-1];o=observers[core]
 o.poll();before=o.db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]
 cfg=client_config(base,index,valid)
 if tls_mismatch:cfg['outbounds'][0]['tls']['server_name']='wrong.invalid'
 (base/'client.json').write_text(json.dumps(cfg))
 with (base/'client.log').open('w') as stream:
  client=subprocess.Popen([str(old/'sing-box-1.12.0'),'run','-c',str(base/'client.json')],stdout=stream,stderr=stream)
  try:
   end=time.monotonic()+15
   while 'sing-box started' not in (base/'client.log').read_text(errors='replace'):
    if client.poll() is not None or time.monotonic()>end:raise RuntimeError('Client startup')
    time.sleep(.05)
   response=subprocess.run([sys.executable,str(base/request)],text=True,capture_output=True,timeout=25)
   if response.returncode:raise RuntimeError('Probe process')
   result=json.loads(response.stdout);alive=client.poll() is None and process.poll() is None
  finally:client.terminate();client.wait(timeout=10)
 time.sleep(.15);o.poll()
 events=[json.loads(r[0]) for r in o.db.execute('SELECT payload FROM events WHERE seq>? ORDER BY seq',(before,))]
 failure=sum(eligible(e) for e in events)
 passed=result['response_verified']==expect_response and result['socks_negotiated'] and result['outcome']!='probe_error' and alive
 if phase not in ('wrong_credentials','post_restart_bad','post_truncate_bad'):passed=passed and failure==0
 expected={('xray','vmess'),('xray','vless'),('sing','vmess'),('sing','vless'),('sing','trojan'),('sing','anytls')}
 if phase in ('wrong_credentials','post_restart_bad','post_truncate_bad') and (core,protocol) in expected:passed=passed and failure>=1
 if phase=='wrong_credentials' and (core,protocol)==('sing','shadowsocks'):passed=passed and any(e['event_type']=='integrity_failure' for e in events) and failure==0
 row=dict(core=core,protocol=protocol,phase=phase,passed=passed,response=result,events=events,failure_observations=failure)
 report['cases'].append(row);print('CASE '+json.dumps(row),flush=True)
 (base/'partial-results.json').write_text(json.dumps(report,indent=2)+'\n')
 return row
try:
 server_start()
 for index in range(1,14):
  run(index,'healthy');run(index,'wrong_credentials',False,expect_response=False);run(index,'recovery')
  run(index,'target_unreachable',request='closed-request.py',expect_response=False)
  if COMBINATIONS[index-1][1] in ('trojan','tuic','anytls','hysteria','hysteria2'):
   run(index,'tls_name_mismatch',tls_mismatch=True,expect_response=False)
 run(6,'target_response_timeout',request='slow-request.py',expect_response=False)
 # V2bX keeps writing the old inode until it reopens: drain it before restart.
 logs['sing'].rename(base/'sing.log.1')
 run(10,'pre_restart_rotated_healthy')
 server_stop();logs['sing'].touch();server_start()
 run(10,'post_restart_healthy');run(10,'post_restart_bad',False,expect_response=False)
 report['lifecycle'].append(dict(name='writer_restart_and_rename',passed=True,policy='Old writer stopped/drained before handoff; arbitrary late writes not claimed lossless'))
 count=sum(o.status()['events'] for o in observers.values())
 for o in observers.values():o.close()
 observers={core:Observer(path,base/(core+'.sqlite'),core,'+00:00') for core,path in logs.items()}
 for o in observers.values():o.poll()
 assert sum(o.status()['events'] for o in observers.values())==count
 run(10,'post_consumer_restart_healthy');run(10,'post_restart_bad',False,expect_response=False)
 report['lifecycle'].append(dict(name='consumer_restart_committed_offsets',passed=True,unchanged_event_count_before_new_records=count))
 # Deliberate destructive truncate: detected and counted, not treated as lossless.
 logs['sing'].write_bytes(b'')
 run(10,'post_truncate_bad',False,expect_response=False)
 assert observers['sing'].status()['truncations']>=1
 report['lifecycle'].append(dict(name='copytruncate_detected',passed=True,unread_loss_possible=True))
 server_stop()
 report['samplers']={core:o.status() for core,o in observers.items()}
 for core,o in observers.items():o.export(base/(core+'.ndjson'))
 report['status']='passed' if all(r['passed'] for r in report['cases']) else 'failed'
except Exception as error:
 report.update(status='failed',error_class=type(error).__name__)
 raise
finally:
 server_stop()
 for o in observers.values():o.close()
 for s in servers:s.shutdown();s.server_close()
 slow.shutdown();slow.server_close()
 (base/'results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(report['cases']),'passed':sum(r['passed'] for r in report['cases'])}),flush=True)
sys.exit(0 if report['status']=='passed' else 1)

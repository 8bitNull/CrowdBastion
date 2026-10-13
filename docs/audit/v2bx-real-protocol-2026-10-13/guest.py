"""Temporary real-program lab. No production accounts/configuration used."""
import json,os,sys,subprocess,time,re,ipaddress
from pathlib import Path
sys.path.insert(0,'/workspace/tests');sys.path.insert(0,'/workspace/real/lib')
from relay_network_lab import Processes,guard,command
from verify_relay_network import setup,start_forwarder
from fixture import COMBINATIONS,nodes,client_config
from crowdsec_v2bx_logs import parse_line,eligible
from types import SimpleNamespace
base=Path('/workspace/real')

def logs(core):
 name={'xray':'xray-access.log','sing':'sing.log','hysteria2':'server.log'}[core]
 p=base/name
 return p.read_text(errors='replace') if p.exists() else ''

def project(raw,core,relay):
 items=[];ignored={}
 for line in raw.split('\n'):
  if not line:continue
  item,status=parse_line(line,core,'+00:00')
  if item:
   if item['source_ip']=='10.231.3.1':item['source_status']='relay_address'
   items.append(item)
  else:ignored[status]=ignored.get(status,0)+1
 sources={e['source_ip'] for e in items}
 if core=='sing':
  for line in raw.split('\n'):
   m=re.search(r' inbound/[a-z0-9]+\[.+\]: inbound connection from ([0-9.]+):[0-9]+$',line)
   if m:
    try:sources.add(str(ipaddress.ip_address(m[1])))
    except ValueError:pass
 return {'observed_source_ips':sorted(sources),'phase_attribution':'bounded window; delayed teardown cannot be excluded','events':items,'ignored':ignored,'failure_observations':sum(eligible(e) for e in items)}

def worker():
 guard(int(sys.argv[1]),int(sys.argv[2]));setup()
 report={'scope':'real official V2bX v0.4.0; three cores, 13 base core/protocol combinations; IPv4 direct and gost proxy; local TCP target over TCP/TLS/QUIC tunnels; not all transports or UDP application payload','cases':[],'production_validation':'unverified'}
 with Processes(grace=5) as owned:
  fixturelog=(base/'fixture.log').open('w')
  owned.start(['ip','netns','exec','backend',sys.executable,str(base/'fixture.py')],stdout=fixturelog,stderr=fixturelog)
  # Explicit HTTP API readiness, not a fixed sleep.
  end=time.monotonic()+30
  while time.monotonic()<end:
   ready=subprocess.run(['ip','netns','exec','backend',sys.executable,'-c','import socket; s=socket.create_connection(("127.0.0.1",28900),timeout=1); s.close()'],capture_output=True,timeout=20)
   if ready.returncode==0:break
   time.sleep(.1)
  else:raise RuntimeError('Panel fixture readiness timeout')
  cores=[{'Type':'xray','Log':{'Level':'info','AccessPath':str(base/'xray-access.log'),'ErrorPath':str(base/'xray-error.log')},'AssetPath':str(base/'v2bx')},{'Type':'sing','Log':{'Level':'info','Timestamp':True,'Output':str(base/'sing.log')},'NTP':{'Enable':False}},{'Type':'hysteria2','Log':{'Level':'info'}}]
  (base/'config.json').write_text(json.dumps({'Log':{'Level':'info'},'Cores':cores,'Nodes':nodes(base,'0.0.0.0')}))
  with (base/'server.log').open('w') as out:
   server=owned.start(['ip','netns','exec','backend',str(base/'v2bx/V2bX'),'server','-c',str(base/'config.json'),'-w=false'],stdout=out,stderr=out)
   end=time.monotonic()+60
   while time.monotonic()<end:
    if 'Nodes started' in logs('hysteria2'):break
    if server.poll() is not None:raise RuntimeError('V2bX startup failed')
    time.sleep(.2)
   else:raise RuntimeError('V2bX nodes readiness timeout')
   report['all_nodes_started']=True
   for path in ('direct','proxy-gost'):
    for index,(core,protocol) in enumerate(COMBINATIONS,1):
     row={'core':core,'protocol':protocol,'path':path,'phases':[]};report['cases'].append(row)
     if path=='proxy-gost':
      network='udp' if protocol in ('tuic','hysteria','hysteria2') else 'tcp'
      if network=='udp':
       owned.start(['/bin/gost','-L',f'udp://0.0.0.0:{31000+index}/10.231.3.2:{29000+index}?keepalive=true&ttl=30s'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
      else:
       start_forwarder(SimpleNamespace(gost='/bin/gost'),owned,base,'gost',network,'0.0.0.0','10.231.3.2',31000+index,29000+index)
      deadline=time.monotonic()+30
      while time.monotonic()<deadline:
       listening=subprocess.run(['ss','-H','-ln'+('u' if network=='udp' else 't'),'sport','=',str(31000+index)],capture_output=True,text=True,timeout=10)
       if listening.returncode==0 and listening.stdout.strip():break
       time.sleep(.1)
      else:raise RuntimeError('Relay listener readiness timeout')
     for phase,valid in [('healthy',True),('wrong_credentials',False),('recovery',True)]:
      before=logs(core)
      cfg=client_config(base,index,valid,'10.231.3.2' if path=='direct' else '10.231.1.1',29000+index if path=='direct' else 31000+index)
      config=base/'client.json';config.write_text(json.dumps(cfg))
      with (base/'client.log').open('w') as output:
       client=owned.start(['ip','netns','exec','bad',str(base/'sing-box'),'run','-c',str(config)],stdout=output,stderr=output)
       try:
        end=time.monotonic()+25
        while time.monotonic()<end:
         if 'sing-box started' in (base/'client.log').read_text(errors='replace'):break
         if client.poll() is not None:raise RuntimeError('Protocol client configuration/startup failed')
         time.sleep(.1)
        else:raise RuntimeError('Protocol client readiness timeout')
        result=subprocess.run(['ip','netns','exec','bad',sys.executable,str(base/'request.py')],capture_output=True,text=True,timeout=25)
        if result.returncode:raise RuntimeError('HTTP token probe failed to execute')
        response=json.loads(result.stdout)
        client_alive=client.poll() is None
        server_alive=server.poll() is None
       finally:
        client.terminate();client.wait(timeout=15)
      # Capture teardown and allow bounded quiet drain; no exact per-request attribution claim.
      end=time.monotonic()+5;last=logs(core);quiet=time.monotonic()
      while time.monotonic()<end:
       time.sleep(.2);current=logs(core)
       if current!=last:last=current;quiet=time.monotonic()
       if time.monotonic()-quiet>=1:break
      logprojection=project(logs(core)[len(before):],core,path=='proxy-gost')
      row['phases'].append({'phase':phase,**response,'client_alive':client_alive,'server_alive':server_alive,'log_projection':logprojection})
     expected_source='10.231.1.2' if path=='direct' else '10.231.3.1'
     row['source_verified']=all(expected_source in p['log_projection']['observed_source_ips'] for p in row['phases'] if p['phase']!='wrong_credentials')
     row['wrong_credentials_probe_valid']=row['phases'][1]['socks_negotiated'] and row['phases'][1]['outcome'] in ('socks_upstream_rejected','upstream_transport_closed','upstream_closed')
     row['passed']=row['source_verified'] and row['wrong_credentials_probe_valid'] and ([p['response_verified'] for p in row['phases']]==[True,False,True] and all(p['client_alive'] and p['server_alive'] for p in row['phases']))
     print('PROTOCOL_CASE '+json.dumps(row),flush=True)
     (base/'partial-results.json').write_text(json.dumps(report,indent=2)+'\n')
  fixturelog.close()
 report['status']='passed' if len(report['cases'])==26 and all(c['passed'] for c in report['cases']) else 'failed'
 return report

if __name__=='__main__':
 if len(sys.argv)==1:
  result=subprocess.run(['unshare','--net','--mount','--',sys.executable,__file__,str(os.stat('/proc/self/ns/net').st_ino),str(os.stat('/proc/self/ns/mnt').st_ino)],timeout=1200)
  sys.exit(result.returncode)
 try:report=worker()
 except Exception as error:
  report=json.loads((base/'partial-results.json').read_text()) if (base/'partial-results.json').exists() else {'cases':[]}
  report.update(status='failed',error_class=type(error).__name__,error=str(error) if isinstance(error,RuntimeError) else 'experiment execution failed')
 Path('/tmp/results.json').write_text(json.dumps(report,indent=2)+'\n')
 sys.exit(0 if report['status']=='passed' else 1)

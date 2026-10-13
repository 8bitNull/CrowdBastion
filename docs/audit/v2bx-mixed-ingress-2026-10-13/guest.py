import os,sys,json,time,subprocess,concurrent.futures,threading,re,ipaddress
from pathlib import Path
sys.path[:0]=['/workspace/tests','/workspace/real/lib']
from relay_network_lab import Processes,guard
from verify_relay_network import setup,endpoint
from fixture import COMBINATIONS,nodes,client_config,UUID,UUID2
from crowdsec_v2bx_logs import parse_line,eligible
base=Path('/workspace/real')
def execns(ns,*args):return ['ip','netns','exec',ns,*map(str,args)]
def logs(core):
 p=base/({'xray':'xray-access.log','sing':'sing.log','hysteria2':'server.log'}[core]);return p.read_text(errors='replace') if p.exists() else ''
def waitready(p,log,needle):
 end=time.monotonic()+70
 while time.monotonic()<end:
  if needle in log.read_text(errors='replace'):return
  if p.poll() is not None:raise RuntimeError('process startup failure')
  time.sleep(.1)
 raise RuntimeError('readiness timeout')
def worker():
 guard(int(sys.argv[1]),int(sys.argv[2]));setup()
 report={'status':'running','scope':'isolated QEMU namespaces; 13 base combinations; two valid accounts; concurrent direct/relay plus bad credentials; IPv4/IPv6 ingress and application echo target','cases':[],'production_validation':'unverified'}
 with Processes(grace=5) as owned:
  f=(base/'fixture.log').open('w');owned.start(execns('backend',sys.executable,base/'fixture.py'),stdout=f,stderr=f)
  end=time.monotonic()+30
  while time.monotonic()<end:
   r=subprocess.run(execns('backend',sys.executable,'-c','import socket;socket.create_connection(("127.0.0.1",28900),1).close()'),capture_output=True)
   if r.returncode==0:break
   time.sleep(.2)
  else:raise RuntimeError('panel unavailable')
  cores=[{'Type':'xray','Log':{'Level':'info','AccessPath':str(base/'xray-access.log'),'ErrorPath':str(base/'xray-error.log')},'AssetPath':str(base/'v2bx')},{'Type':'sing','Log':{'Level':'info','Timestamp':True,'Output':str(base/'sing.log')},'NTP':{'Enable':False}},{'Type':'hysteria2','Log':{'Level':'info'}}]
  cfg=base/'config.json';cfg.write_text(json.dumps({'Log':{'Level':'info'},'Cores':cores,'Nodes':nodes(base,'::')}))
  out=(base/'server.log').open('w');server=owned.start(execns('backend',base/'v2bx/V2bX','server','-c',cfg,'-w=false'),stdout=out,stderr=out);waitready(server,base/'server.log','Nodes started')
  for family in (4,6):
   backend='10.231.3.2' if family==4 else 'fd42:231:3::2';relay='10.231.2.1' if family==4 else 'fd42:231:2::1';relaypeer='10.231.3.1' if family==4 else 'fd42:231:3::1';badpeer='10.231.1.2' if family==4 else 'fd42:231:1::2';target='127.0.0.1' if family==4 else '::1'
   for index,(core,protocol) in enumerate(COMBINATIONS,1):
    row={'family':family,'core':core,'protocol':protocol,'phases':[]};report['cases'].append(row)
    network='udp' if protocol in ('tuic','hysteria','hysteria2') else 'tcp';port=31000+family*100+index
    forward=owned.start(['/bin/gost','-L',network+'://'+endpoint(relay,port)+'/'+endpoint(backend,29000+index)+('?keepalive=true&ttl=30s' if network=='udp' else '')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
     listening=subprocess.run(['ss','-H','-ln'+('u' if network=='udp' else 't'),'sport','=',str(port)],capture_output=True,text=True)
     if listening.returncode==0 and listening.stdout.strip():break
     if forward.poll() is not None:raise RuntimeError('relay startup failure')
     time.sleep(.1)
    else:raise RuntimeError('relay readiness timeout')
    udp_forward=None
    if protocol=='shadowsocks':
     udp_forward=owned.start(['/bin/gost','-L','udp://'+endpoint(relay,port)+'/'+endpoint(backend,29000+index)+'?keepalive=true&ttl=30s'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
     deadline=time.monotonic()+30
     while time.monotonic()<deadline:
      listening=subprocess.run(['ss','-H','-lnu','sport','=',str(port)],capture_output=True,text=True)
      if listening.returncode==0 and listening.stdout.strip():break
      if udp_forward.poll() is not None:raise RuntimeError('SS UDP relay startup failure')
      time.sleep(.1)
     else:raise RuntimeError('SS UDP relay readiness timeout')
    clients=[];handles=[]
    try:
     for role,ns,valid,via in [('direct','good',True,False),('relay','good',True,True),('bad_direct','bad',False,False),('bad_relay','bad',False,True)]:
      socks=21100+len(clients);c=client_config(base,index,valid,relay if via else backend,port if via else 29000+index)
      if role=='relay':c['outbounds'][0]={k:(UUID2 if v==UUID else v) for k,v in c['outbounds'][0].items()}
      c['inbounds'][0]['listen_port']=socks;path=base/(role+'.json');path.write_text(json.dumps(c));log=base/(role+'.log');h=log.open('w');handles.append(h);p=owned.start(execns(ns,base/'sing-box','run','-c',path),stdout=h,stderr=h);waitready(p,log,'sing-box started');clients.append((role,ns,socks,p))
     for phase in ('baseline','mixed','recovery'):
      before=logs(core);selected=clients if phase=='mixed' else clients[:2];scheduled={};barrier=threading.Barrier(len(selected),action=lambda:scheduled.update(start=time.monotonic()+3));phase_start=time.monotonic()
      def attempt(client):
       role,ns,socks,p=client;items=[]
       for mode in ('tcp','udp'):
        barrier.wait(timeout=30)
        r=subprocess.run(execns(ns,sys.executable,base/'probe.py',socks,mode,target,scheduled['start']),capture_output=True,text=True,timeout=25)
        if r.returncode:raise RuntimeError('probe failed')
        items.append({'mode':mode,**json.loads(r.stdout)})
       return {'role':role,'probes':items,'client_alive':p.poll() is None}
      with concurrent.futures.ThreadPoolExecutor(max_workers=len(selected)) as pool:results=list(pool.map(attempt,selected))
      time.sleep(1);events=[];sources=set()
      raw=logs(core)[len(before):]
      for line in raw.splitlines():
       event,status=parse_line(line,core,'+00:00')
       if event:
        if event['source_ip']==relaypeer:event['source_status']='relay_address'
        events.append(event);sources.add(event['source_ip'])
       m=re.search(r'inbound connection from (.+):[0-9]+$',line)
       if m:
        try:sources.add(str(ipaddress.ip_address(m[1].strip('[]'))))
        except ValueError:pass
      tcp=[r['probes'][0] for r in results];overlap=max(p['start'] for p in tcp)<min(p['end'] for p in tcp)
      udp=[r['probes'][1] for r in results];udp_overlap=max(p['start'] for p in udp)<min(p['end'] for p in udp)
      row['phases'].append({'phase':phase,'results':results,'events':events,'tcp_attempt_intervals_overlap':overlap,'udp_attempt_intervals_overlap':udp_overlap,'observed_sources':sorted(sources),'server_alive':server.poll() is None})
     row['tcp_passed']=all(p['server_alive'] and all(r['client_alive'] and all(probe['probe_valid'] for probe in r['probes']) and r['probes'][0]['negotiated'] and r['probes'][0]['verified']==(not r['role'].startswith('bad')) for r in p['results']) for p in row['phases'])
     row['udp_healthy_verified']=all(r['probes'][1]['verified'] for p in row['phases'] for r in p['results'] if not r['role'].startswith('bad'))
     row['bad_udp_rejected']=all(not r['probes'][1]['verified'] for p in row['phases'] for r in p['results'] if r['role'].startswith('bad'))
     events=[e for p in row['phases'] for e in p['events']];row['eligible_sources']=sorted({e['source_ip'] for e in events if eligible(e)});row['relay_excluded']=sum(e['source_status']=='relay_address' for e in events);row['source_safety']=set(row['eligible_sources'])<={badpeer}
     row['concurrency_verified']=all(p['tcp_attempt_intervals_overlap'] and p['udp_attempt_intervals_overlap'] for p in row['phases'])
     row['passed']=row['concurrency_verified'] and row['tcp_passed'] and row['bad_udp_rejected'] and row['source_safety']
     print('MIXED_CASE '+json.dumps(row),flush=True);(base/'partial-results.json').write_text(json.dumps(report,indent=2))
    finally:
     for _,_,_,p in clients:
      p.terminate();p.wait(timeout=20)
     for h in handles:h.close()
     forward.terminate();forward.wait(timeout=20)
     if udp_forward:udp_forward.terminate();udp_forward.wait(timeout=20)
  report['status']='passed' if len(report['cases'])==26 and all(c['passed'] for c in report['cases']) else 'failed'
 return report
if __name__=='__main__':
 if len(sys.argv)==1:sys.exit(subprocess.run(['unshare','--net','--mount','--',sys.executable,__file__,str(os.stat('/proc/self/ns/net').st_ino),str(os.stat('/proc/self/ns/mnt').st_ino)],timeout=1800).returncode)
 try:report=worker()
 except Exception as e:
  report=json.loads((base/'partial-results.json').read_text()) if (base/'partial-results.json').exists() else {'cases':[]}
  report.update(status='failed',error_class=type(e).__name__,error=str(e) if isinstance(e,RuntimeError) else 'execution failure')
 Path('/tmp/results.json').write_text(json.dumps(report,indent=2));sys.exit(0 if report['status']=='passed' else 1)

import subprocess as sp, pathlib, json, time, sys, socket, os, signal, urllib.request, yaml, ipaddress
BASE=pathlib.Path('/var/backups/crowdbastion/vps4-cycle-20261030')
TAG='cbv4-cycle-20261030'
SOURCES=['198.18.233.2','fd42:cb:1::2']
CONTROL=['198.18.233.3','fd42:cb:1::3']
RULES=[]; PROCS=[]
def run(args,check=True,**kw):
 r=sp.run(args,text=True,capture_output=True,timeout=30,**kw)
 if check and r.returncode:raise RuntimeError(str(args[:6])+': '+r.stderr[:500])
 return r

def decisions():
 c=yaml.safe_load(pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml').read_text())
 local=pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local')
 if local.exists():c.update(yaml.safe_load(local.read_text()) or {})
 q=urllib.request.Request(c['api_url'].rstrip('/')+'/v1/decisions',headers={'X-Api-Key':c['api_key']})
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(q,timeout=15) as r:return json.load(r) or []

def cleanup():
 if not (BASE/'flow-active').exists():return
 for d in decisions():
  if d.get('scenario','').startswith(TAG) and d['value'] in SOURCES:run(['cscli','decisions','delete','--id',str(d['id'])],False)
 for binary in ['iptables','ip6tables']:
  for chain in ['INPUT','DOCKER-USER']:
   rules=run([binary,'-S',chain],False).stdout.splitlines()
   import shlex
   for line in rules:
    if TAG in line:
     tokens=shlex.split(line);tokens[0]='-D';run([binary,'-w','5',*tokens],False)
 for p in PROCS:
  p.terminate()
  try:p.wait(timeout=2)
  except sp.TimeoutExpired:p.kill()
 for ns in ['cbv4-src','cbv4-dst']:
  pids=run(['ip','netns','pids',ns],False).stdout.split()
  for pid in pids:run(['kill',pid],False)
  run(['ip','netns','delete',ns],False)
 for dev in ['cbv4-in','cbv4-out']:run(['ip','link','del',dev],False)
 (BASE/'flow-active').unlink(missing_ok=True)

def setup():
 assert not (BASE/'flow-active').exists(), 'another flow check is active'
 for ns in ['cbv4-src','cbv4-dst']:
  assert not pathlib.Path('/run/netns',ns).exists(), 'test namespace already exists'
 assert not any(d['value'] in SOURCES+CONTROL for d in decisions()), 'test addresses have existing decisions'
 (BASE/'flow-active').touch(exist_ok=False)
 for ns,host,subnet in [('cbv4-src','cbv4-in',233),('cbv4-dst','cbv4-out',234)]:
  run(['ip','netns','add',ns]);run(['ip','link','add',host,'type','veth','peer','name','peer0','netns',ns])
  run(['ip','addr','add',f'198.18.{subnet}.1/24','dev',host]);v6='1' if subnet==233 else '2'
  run(['ip','-6','addr','add',f'fd42:cb:{v6}::1/64','dev',host,'nodad']);run(['ip','link','set',host,'up'])
  run(['ip','netns','exec',ns,'ip','link','set','lo','up']);run(['ip','netns','exec',ns,'ip','link','set','peer0','up'])
  for suffix in ([2,3] if subnet==233 else [2]):
   run(['ip','netns','exec',ns,'ip','addr','add',f'198.18.{subnet}.{suffix}/24','dev','peer0'])
   run(['ip','netns','exec',ns,'ip','-6','addr','add',f'fd42:cb:{v6}::{suffix}/64','dev','peer0','nodad'])
  other=234 if subnet==233 else 233;other6='2' if subnet==233 else '1'
  run(['ip','netns','exec',ns,'ip','route','add',f'198.18.{other}.0/24','via',f'198.18.{subnet}.1'])
  run(['ip','netns','exec',ns,'ip','-6','route','add',f'fd42:cb:{other6}::/64','via',f'fd42:cb:{v6}::1'])
 for binary,v4 in [('iptables',True),('ip6tables',False)]:
  source='198.18.233.0/24' if v4 else 'fd42:cb:1::/64'
  host='198.18.233.1' if v4 else 'fd42:cb:1::1'
  dest='198.18.234.2' if v4 else 'fd42:cb:2::2'
  for proto in ['tcp','udp']:
   run([binary,'-w','5','-A','INPUT','-i','cbv4-in','-s',source,'-d',host,'-p',proto,'--dport','18080','-m','comment','--comment',TAG,'-j','ACCEPT'])
   run([binary,'-w','5','-A','DOCKER-USER','-i','cbv4-in','-o','cbv4-out','-s',source,'-d',dest,'-p',proto,'--dport','18080','-m','comment','--comment',TAG,'-j','ACCEPT'])
   run([binary,'-w','5','-A','DOCKER-USER','-i','cbv4-out','-o','cbv4-in','-s',dest,'-d',source,'-p',proto,'--sport','18080','-m','comment','--comment',TAG,'-j','ACCEPT'])
 server='''import socket,threading,time,sys

def serve(addr,kind):
 s=socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET,kind)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if ':' in addr:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((addr,18080))
 if kind==socket.SOCK_STREAM:
  s.listen(32)
  while True:
   c,a=s.accept();c.sendall(b'ok');c.close()
 else:
  while True:
   b,a=s.recvfrom(64);s.sendto(b'ok',a)
for a in sys.argv[1:]:
 for k in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:threading.Thread(target=serve,args=(a,k),daemon=True).start()
while True:time.sleep(1)
'''
 for args in [['python3','-c',server,'198.18.233.1','fd42:cb:1::1'],['ip','netns','exec','cbv4-dst','python3','-c',server,'198.18.234.2','fd42:cb:2::2']]:PROCS.append(sp.Popen(args,stdout=sp.DEVNULL,stderr=(BASE/'flow-listeners.txt').open('a')))
 time.sleep(.5)

def probe():
 client='''import socket,json
rows=[]
for f,sources,targets in [(socket.AF_INET,['198.18.233.2','198.18.233.3'],['198.18.233.1','198.18.234.2']),(socket.AF_INET6,['fd42:cb:1::2','fd42:cb:1::3'],['fd42:cb:1::1','fd42:cb:2::2'])]:
 for src in sources:
  for dst in targets:
   for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
    s=socket.socket(f,kind);s.settimeout(.4);s.bind((src,0));ok=False
    try:
     s.connect((dst,18080))
     if kind==socket.SOCK_DGRAM:s.send(b'probe')
     ok=s.recv(16)==b'ok'
    except OSError:pass
    finally:s.close()
    rows.append(dict(source=src,destination=dst,protocol='tcp' if kind==socket.SOCK_STREAM else 'udp',reachable=ok))
print(json.dumps(rows))
'''
 return json.loads(run(['ip','netns','exec','cbv4-src','python3','-c',client]).stdout)

def expect(rows,blocked):
 return all(r['reachable']==(not blocked if r['source'] in SOURCES else True) for r in rows)

def poll(blocked,seconds=22):
 end=time.monotonic()+seconds
 while True:
  rows=probe()
  if expect(rows,blocked):return rows
  if time.monotonic()>end:raise AssertionError('flow mismatch: '+json.dumps(rows))
  time.sleep(1)

def add(duration,reason):
 for source in SOURCES:run(['cscli','decisions','add','--ip',source,'--duration',duration,'--reason',TAG+'-'+reason])

def main(mode):
 report={'mode':mode,'started':time.time()}
 try:
  setup();report['baseline']=poll(False)
  start=time.monotonic();add('40s','short');report['initial_ban']=poll(True)
  add('120s','renew')
  while time.monotonic()<start+46:time.sleep(min(1,start+46-time.monotonic()))
  report['after_original_expiry']=probe()
  live=[{k:d.get(k) for k in ['id','value','duration','scenario']} for d in decisions() if d['value'] in SOURCES]
  report['live_decisions']=live
  assert {d['value'] for d in live}==set(SOURCES)
  if mode=='before':assert expect(report['after_original_expiry'],False),'expected old backend renewal defect'
  else:assert expect(report['after_original_expiry'],True),'renewal still leaks traffic'
  for d in live:
   if d['scenario'].startswith(TAG):run(['cscli','decisions','delete','--id',str(d['id'])])
  report['after_delete']=poll(False)
  if mode!='before':
   start=time.monotonic();add('25s','natural-expiry');report['expiry_ban']=poll(True)
   while time.monotonic()<start+29:time.sleep(min(1,start+29-time.monotonic()))
   report['natural_expiry']=poll(False)
  report['passed']=True
 except BaseException as e:
  report['passed']=False;report['error']=str(e);raise
 finally:
  try:cleanup();report['cleanup']='done'
  except Exception as e:report['cleanup']=str(e)
  report['finished']=time.time();(BASE/('flow-'+mode+'.json')).write_text(json.dumps(report,indent=2))
if __name__=='__main__':
 os.umask(0o077)
 for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,lambda s,f:sys.exit(128+s))
 if sys.argv[1]=='cleanup':cleanup()
 else:main(sys.argv[1])

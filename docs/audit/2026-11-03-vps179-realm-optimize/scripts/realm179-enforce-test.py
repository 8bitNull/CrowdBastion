from pathlib import Path
import subprocess,json,datetime,os,time,ipaddress,re,signal,select,fcntl
base=Path('/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z')
lock=open('/run/lock/crowdsec-1key.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
token=os.urandom(3).hex();ns='cb179-'+token;vh='cb179h'+token;vn='cb179n'+token
subnet=ipaddress.ip_network('203.0.113.240/29');host='203.0.113.241';test='203.0.113.242';control='203.0.113.243';reason='crowdbastion-realm-acceptance-'+token
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'namespace':ns,'reason':reason,'test_source':test,'control_source':control,'coverage':'actual realm TCP listeners; controlled UDP echo behind production INPUT; IPv4 synthetic ingress, not public WAN/backend authentication','checks':{},'cleanup':{}}
created_ns=False;created_veth=False;decision_attempted=False;echo=None

def cmd(args,timeout=20,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if check and p.returncode:raise RuntimeError(str(args)+': '+p.stdout[-700:]+p.stderr[-700:])
 return p

def memberships(ip):
 names=cmd(['ipset','list','-name']).stdout.splitlines()
 return [name for name in names if name.startswith('crowdsec-blacklists') and cmd(['ipset','test',name,ip],check=False).returncode==0]

def wait_member(present):
 until=time.monotonic()+30
 while time.monotonic()<until:
  sets=memberships(test)
  if bool(sets)==present:return sets
  time.sleep(.5)
 raise RuntimeError('Bouncer membership timeout, wanted '+str(present))

client=r'''import socket,sys,json
proto,src,dst,port=sys.argv[1:];s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM);s.settimeout(.7);s.bind((src,0))
try:
 if proto=='udp':
  s.sendto(b'cb179-isolated-echo',(dst,int(port)));ok=s.recv(128)==b'cb179-isolated-echo'
 else:s.connect((dst,int(port)));ok=True
 print(json.dumps({'reachable':ok}))
except OSError as e:print(json.dumps({'reachable':False,'error':type(e).__name__}))
finally:s.close()
'''
def probe(proto,src,dst,port):return json.loads(cmd(['ip','netns','exec',ns,'python3','-c',client,proto,src,dst,str(port)],5).stdout)

def matrix(phase,banned):
 result={}
 for proto,dst,port in [('tcp','192.0.2.17',56017),('tcp','192.0.2.17',58372),('udp',host,17773)]:
  key=proto+':'+str(port);a=probe(proto,test,dst,port);b=probe(proto,control,dst,port)
  result[key]={'test':a,'control':b};assert a['reachable']==(not banned),(phase,key,a);assert b['reachable'],(phase,key,'control',b)
 r['checks'][phase]=result

def counters(names):
 text=cmd(['iptables-save','-c']).stdout;result={}
 for name in names:
  values=[]
  for line in text.splitlines():
   if '--match-set '+name+' src' in line:
    m=re.match(r'\[(\d+):(\d+)\]',line)
    if m:values.append(int(m.group(1)))
  result[name]=sum(values)
 return result

try:
 routes=json.loads(cmd(['ip','-j','route','show','table','all']).stdout)
 for route in routes:
  dst=route.get('dst')
  if dst and dst!='default':
   try:assert not ipaddress.ip_network(dst,strict=False).overlaps(subnet),('route overlap',dst)
   except ValueError:pass
 for src in (test,control):
  assert not memberships(src),('preexisting blacklist',src)
  old=json.loads(cmd(['cscli','decisions','list','-i',src,'-o','json']).stdout)
  assert not old,('preexisting decision',src)
 cmd(['ip','netns','add',ns]);created_ns=True
 cmd(['ip','link','add',vh,'type','veth','peer','name',vn]);created_veth=True
 cmd(['ip','link','set',vn,'netns',ns]);cmd(['ip','address','add',host+'/29','dev',vh]);cmd(['ip','link','set',vh,'up'])
 cmd(['ip','netns','exec',ns,'ip','link','set','lo','up'])
 for src in (test,control):cmd(['ip','netns','exec',ns,'ip','address','add',src+'/29','dev',vn])
 cmd(['ip','netns','exec',ns,'ip','link','set',vn,'up'])
 cmd(['ip','netns','exec',ns,'ip','route','add','192.0.2.17/32','via',host,'dev',vn])
 server="import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('"+host+"',17773)); print('ready',flush=True)\nwhile True:\n data,peer=s.recvfrom(2048);s.sendto(data,peer)"
 echo=subprocess.Popen(['python3','-u','-c',server],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 assert select.select([echo.stdout],[],[],5)[0] and echo.stdout.readline().strip()=='ready','UDP echo startup failed'
 matrix('before',False)
 decision_attempted=True
 add=cmd(['cscli','decisions','add','--ip',test,'--duration','2m','--reason',reason]);r['decision_add_exit']=add.returncode
 sets=wait_member(True);r['bouncer_sets']=sets;before=counters(sets)
 matrix('banned',True);after=counters(sets)
 r['drop_counters']={'before':before,'after':after};assert sum(after.values())>sum(before.values()),'no test set counter increase'
 cmd(['cscli','decisions','delete','--ip',test,'--scenario',reason]);wait_member(False)
 matrix('recovered',False)
 r['status']='passed'
except BaseException as e:
 r['status']='failed';r['error']=str(e)
finally:
 def cleanup_step(name,operation):
  try:return operation()
  except Exception as error:r['cleanup'][name+'_error']=type(error).__name__+': '+str(error);return None
 if decision_attempted:
  p=cleanup_step('decision_delete',lambda:cmd(['cscli','decisions','delete','--ip',test,'--scenario',reason],check=False))
  r['cleanup']['decision_delete_exit']=p.returncode if p else None
  try:wait_member(False);r['cleanup']['test_absent_from_sets']=True
  except Exception as e:r['cleanup']['test_absent_from_sets']=False;r['cleanup']['membership_error']=str(e)
 if echo:
  def stop_echo():
   echo.terminate()
   try:echo.wait(timeout=5)
   except subprocess.TimeoutExpired:echo.kill();echo.wait(timeout=5)
   return echo.poll() is not None
  r['cleanup']['udp_listener_stopped']=bool(cleanup_step('udp_listener',stop_echo))
 if created_veth:
  p=cleanup_step('veth_delete',lambda:cmd(['ip','link','delete',vh],check=False));r['cleanup']['veth_delete_exit']=p.returncode if p else None
 if created_ns:
  p=cleanup_step('namespace_delete',lambda:cmd(['ip','netns','delete',ns],check=False));r['cleanup']['namespace_delete_exit']=p.returncode if p else None
 p=cleanup_step('namespace_verify',lambda:cmd(['ip','netns','list']));r['cleanup']['namespace_absent']=bool(p is not None and ns not in p.stdout)
 p=cleanup_step('veth_verify',lambda:cmd(['ip','link','show',vh],check=False));r['cleanup']['veth_absent']=bool(p is not None and p.returncode!=0)
 if decision_attempted:
  p=cleanup_step('decision_verify',lambda:cmd(['cscli','decisions','list','-i',test,'-o','json']))
  remaining=cleanup_step('decision_parse',lambda:json.loads(p.stdout)) if p else None
  r['cleanup']['no_test_decision']=bool(p is not None and 'decision_parse_error' not in r['cleanup'] and not remaining)
 if r['status']=='passed' and not all(r['cleanup'].get(k) for k in ['namespace_absent','veth_absent','test_absent_from_sets','no_test_decision','udp_listener_stopped']):r['status']='cleanup_failed'
 (base/'enforcement-result.json').write_text(json.dumps(r,indent=2));print(json.dumps(r,indent=2))
assert r['status']=='passed',r.get('error')
assert all(r['cleanup'].get(k) for k in ['namespace_absent','veth_absent','test_absent_from_sets','no_test_decision','udp_listener_stopped']),r['cleanup']

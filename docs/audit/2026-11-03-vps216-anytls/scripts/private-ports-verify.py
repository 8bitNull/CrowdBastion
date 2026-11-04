import subprocess,json,socket,hashlib,sys
from pathlib import Path
def run(a):return subprocess.run(a,capture_output=True,text=True,check=True,timeout=20).stdout.strip()
r={}
r['policy']=run(['/usr/bin/python3','-B','/usr/local/lib/crowdbastion216-private-gost/policy.py','apply'])
r['rules']={b:{c:run([b,'-w','5','-S',c]) for c in ['INPUT','DOCKER-USER']} for b in ['iptables','ip6tables']}
for b,cs in r['rules'].items():
 for c,text in cs.items():
  entries=[s for s in text.splitlines() if s.startswith('-A '+c+' ')]
  assert entries[0]=='-A '+c+' -j CROWDSEC_CHAIN'
  for comment in ['crowdbastion216-private-gost','crowdbastion216-private-openlist']:
   assert sum(comment in entry for entry in entries)==1
   assert any(comment in entry for entry in entries[1:3])
r['loopback']={}
for port in [51080,5244]:
 for host in ['127.0.0.1','::1']:
  s=socket.create_connection((host,port),timeout=3);s.close();r['loopback'][host+':'+str(port)]='reachable'
r['service_enabled']=run(['systemctl','is-enabled','crowdbastion216-private-gost.service'])
r['service_active']=run(['systemctl','is-active','crowdbastion216-private-gost.service'])
r['services']=run(['systemctl','show','V2bX','crowdsec','crowdsec-firewall-bouncer','docker','--property=Id,ActiveState,MainPID,NRestarts'])
base=Path('/var/backups/crowdbastion/anytls-20261103');m=json.loads((base/'manifest.json').read_text())
for f in m['files']:
 p=Path(f['path']);actual=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
 assert actual==f['before']
for k in m['changes']:assert ' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split())==m['runtime_before'][k]
r['network_rollback_verified']=True
r['gost_container']=json.loads(run(['docker','inspect','gost']))[0]['State']['StartedAt']
r['openlist_container']=json.loads(run(['docker','inspect','openlist']))[0]['State']['StartedAt']
print(json.dumps(r,ensure_ascii=False,indent=2),flush=True)

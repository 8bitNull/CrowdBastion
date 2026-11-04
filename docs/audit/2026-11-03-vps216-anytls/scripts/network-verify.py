import sys,subprocess,json,hashlib,re,socket
from pathlib import Path
base=Path('/var/backups/crowdbastion/anytls-20261103')
m=json.loads((base/'manifest.json').read_text())
r={'file_hashes_match':True,'runtime_match':True,'duplicate_assignments':False}
for f in m['files']:
 assert hashlib.sha256(Path(f['path']).read_bytes()).hexdigest()==f['after']
for k,v in m['settings'].items():
 actual=' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split())
 assert actual==v,(k,actual,v)
active={}
for name in ['/etc/sysctl.conf','/etc/sysctl.d/99-bbr-ultimate.conf','/etc/sysctl.d/99-network-optimize.conf','/etc/sysctl.d/99-zz-crowdbastion-anytls.conf']:
 for line in Path(name).read_text().splitlines():
  match=re.match(r'^\s*(net\.[\w.]+)\s*=\s*(.*?)\s*$',line)
  if match:
   assert match[1] not in active,'duplicate key'
   active[match[1]]=' '.join(match[2].split())
assert active==m['settings']
p=subprocess.run(['systemd-analyze','cat-config','sysctl.d'],capture_output=True,text=True,timeout=20,check=True)
effective={}
for line in p.stdout.splitlines():
 match=re.match(r'^\s*-?(net\.[\w.]+)\s*=\s*(.*?)\s*$',line)
 if match:effective[match[1]]=' '.join(match[2].split())
assert all(effective.get(k)==v for k,v in m['settings'].items()),'boot assignment mismatch'
r['boot_config_matches']=True
r['managed_keys']=len(m['settings']);r['changed_runtime']=m['changes']
def run(a):return subprocess.run(a,capture_output=True,text=True,check=True,timeout=20).stdout.strip()
r['qdisc']=run(['tc','-s','qdisc','show','dev','eth0'])
r['services']=run(['systemctl','show','V2bX','crowdsec','crowdsec-firewall-bouncer','docker','--property=Id,ActiveState,MainPID,NRestarts'])
r['gost_policy']=run(['/usr/bin/python3','-B','/usr/local/lib/crowdbastion216-private-gost/policy.py','verify'])
for host in ['127.0.0.1','::1']:
 s=socket.create_connection((host,51080),timeout=3);s.close()
r['loopback_51080']='IPv4 and IPv6 reachable'
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_firewall_evidence
r['decisions']=crowdsec_firewall_evidence.inspect(Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml'))
assert r['decisions']['state']=='ok'
p=subprocess.run(['curl','--silent','--max-time','10','--noproxy','*','--output','/dev/null','--write-out','%{http_code}','https://site-05.example.com/'],capture_output=True,text=True,check=True,timeout=15)
r['public_https']=p.stdout;assert p.stdout=='200'
print(json.dumps(r,ensure_ascii=False,indent=2))

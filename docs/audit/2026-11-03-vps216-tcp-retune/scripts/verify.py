import subprocess,json,hashlib,re,socket,sys,time
from pathlib import Path
base=Path('/var/backups/crowdbastion/tcp-retune-20261103')
m=json.loads((base/'manifest.json').read_text());proof=json.loads((base/'apply-proof.json').read_text())
assert (base/'applied').exists() and not (base/'rollback-result.json').exists()
r={'file_hashes_match':True,'runtime_match':True,'managed_keys':len(m['settings']),'changes':m['changes'],'tcp_mem_unchanged':m['settings']['net.ipv4.tcp_mem']==m['runtime_before']['net.ipv4.tcp_mem']}
for f in m['files']:assert hashlib.sha256(Path(f['path']).read_bytes()).hexdigest()==f['after']
for k,v in m['settings'].items():assert ' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split())==v
active={}
for f in m['files']:
 for line in Path(f['path']).read_text().splitlines():
  match=re.match(r'^\s*(net\.[\w.]+)\s*=\s*(.*?)\s*$',line)
  if match:
   assert match[1] not in active
   active[match[1]]=' '.join(match[2].split())
assert active==m['settings'];r['unique_active_network_settings']=len(active)
def run(a):return subprocess.run(a,capture_output=True,text=True,check=True,timeout=20).stdout.strip()
effective={}
for line in run(['systemd-analyze','cat-config','sysctl.d']).splitlines():
 match=re.match(r'^\s*-?(net\.[\w.]+)\s*=\s*(.*?)\s*$',line)
 if match:effective[match[1]]=' '.join(match[2].split())
assert all(effective.get(k)==v for k,v in m['settings'].items());r['boot_config_matches']=True
r['services']=run(['systemctl','show','V2bX','crowdsec','crowdsec-firewall-bouncer','docker','--property=Id,MainPID,ActiveState,NRestarts'])
assert r['services']==proof['before_services'].strip();r['service_pids_unchanged']=True
r['private_policy']=run(['/usr/bin/python3','-B','/usr/local/lib/crowdbastion216-private-gost/policy.py','verify'])
for host in ['127.0.0.1','::1']:
 for port in [5244,51080]:
  s=socket.create_connection((host,port),timeout=3);s.close()
r['private_ports_dualstack_loopback']=True
for b in ['iptables','ip6tables']:
 for c in ['INPUT','FORWARD','DOCKER-USER']:
  lines=[line for line in run([b,'-w','5','-S',c]).splitlines() if line.startswith('-A '+c+' ')]
  assert lines[0]=='-A '+c+' -j CROWDSEC_CHAIN'
r['crowdsec_first_rules_preserved']=True
r['qdisc']=run(['tc','-s','qdisc','show','dev','eth0']);assert 'qdisc fq ' in r['qdisc']
def counters():
 values={}
 for name in ['snmp','netstat']:
  rows=Path('/proc/net/'+name).read_text().splitlines()
  for header,data in zip(rows[::2],rows[1::2]):
   hs,ds=header.split(),data.split()
   for k,v in zip(hs[1:],ds[1:]):
    if k in ['RetransSegs','OutSegs','RcvbufErrors','SndbufErrors','TCPMemoryPressures','TCPAbortOnMemory','ListenOverflows','ListenDrops']:values[hs[0]+k]=int(v)
 for line in Path('/proc/net/snmp6').read_text().splitlines():
  k,v=line.split()
  if k in ['Udp6RcvbufErrors','Udp6SndbufErrors','Udp6InErrors']:values[k]=int(v)
 return values
before=counters();r['api_samples']=[]
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_firewall_evidence as e
config=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
for i in range(3):
 started=time.monotonic();rows=e.live(config)
 r['api_samples'].append({'records':len(rows),'seconds':round(time.monotonic()-started,3)})
 if i<2:time.sleep(3)
r['decision_membership']=e.inspect(config)
assert r['decision_membership']['state']=='ok'
r['counter_delta']={k:v-before[k] for k,v in counters().items()}
r['sockstat']=Path('/proc/net/sockstat').read_text().strip()
r['v2bx_memory_bytes']=run(['systemctl','show','V2bX','--property=MemoryCurrent','--value'])
r['vmstat']=run(['vmstat','1','3'])
r['verification_scope']='configuration, low-load service stability and decision membership; no relay throughput benchmark'
print(json.dumps(r,ensure_ascii=False,indent=2),flush=True)

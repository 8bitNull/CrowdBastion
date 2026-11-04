REVIEW_PIDS={'forwardx-agent.service': '504', 'forwardx-realm-both-56017.service': '505', 'forwardx-realm-both-58372.service': '511', 'crowdsec.service': '524502', 'crowdsec-firewall-bouncer.service': '2109', 'systemd-journald.service': '524481'}
EXPECTED_ROLLBACK='077f61d3ec1c16c916d9779e58286df68bcaedff7918ed479703af55c487c475'
from pathlib import Path
import json,subprocess,hashlib,datetime,socket,time
base=Path('/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z');before=json.loads((base/'baseline.json').read_text());apply=json.loads((base/'apply-result.json').read_text());test=json.loads((base/'enforcement-review-result.json').read_text())
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backup':str(base),'status':'checking','file_integrity':{},'new_files':{},'commands':{}}
for name,digest in before['protected_sha256'].items():r['file_integrity'][name]=hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest
assert all(r['file_integrity'].values())
for name,digest in apply['new_files'].items():
 p=Path(name);r['new_files'][name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'matches':hashlib.sha256(p.read_bytes()).hexdigest()==digest,'uid':p.stat().st_uid,'mode':oct(p.stat().st_mode&0o777)}
assert all(x['matches'] and x['uid']==0 and x['mode']=='0o644' for x in r['new_files'].values())
for key,args in [('services',['systemctl','show','forwardx-realm-both-56017','forwardx-realm-both-58372','forwardx-agent','crowdsec','crowdsec-firewall-bouncer','systemd-journald','-p','Id','-p','MainPID','-p','NRestarts','-p','ActiveState']),('config_test',['crowdsec','-t']),('firewall_check',['crowdbastion','--firewall-check']),('relay_status',['crowdbastion','--relay-status-details']),('bouncers',['cscli','bouncers','list','-o','json']),('metrics',['cscli','metrics','show','-o','json']),('namespaces',['ip','netns','list']),('journal_check',['journalctl','-u','systemd-journald','--since','15 minutes ago','-n','30','--no-pager']),('journal_effective',['systemd-analyze','cat-config','systemd/journald.conf'])]:
 p=subprocess.run(args,capture_output=True,text=True,timeout=55)
 if key=='bouncers':
  r[key]=[{k:x.get(k) for k in ['name','type','last_pull','revoked']} for x in json.loads(p.stdout)]
 elif key=='metrics':
  m=json.loads(p.stdout);r[key]={'realm_acquisition':{k:v for k,v in m.get('acquisition',{}).items() if 'forwardx-realm' in k},'bouncers':m.get('bouncers',{}),'ssh_acquisition':{k:v for k,v in m.get('acquisition',{}).items() if 'ssh.service' in k}}
 else:r['commands'][key]={'exit':p.returncode,'stdout':p.stdout[-7000:],'stderr':p.stderr[-500:]}
 if key in ('config_test','firewall_check'):assert p.returncode==0,(key,p.stdout,p.stderr)
assert test['status']=='passed' and all(test['cleanup'][k] for k in ['namespace_absent','veth_absent','test_absent_from_sets','no_test_decision','udp_listener_stopped'])
# Compare process identity to baseline by unit, not by output ordering.
def states(text):
 return {d['Id']:d for block in text.strip().split('\n\n') if (d:=dict(x.split('=',1) for x in block.splitlines() if '=' in x)) and 'Id' in d}
b=states((base/'services-before.txt').read_text());a=states(r['commands']['services']['stdout'])
r['pid_continuity']={u:a[u]['MainPID']==b[u]['MainPID'] for u in b if u!='crowdsec.service'}
assert all(r['pid_continuity'].values());assert all(d['ActiveState']=='active' for d in a.values())
r['realm_follower']=[]
for p in Path('/proc').glob('[0-9]*'):
 try:
  if (p/'comm').read_text().strip()!='journalctl':continue
  argv=(p/'cmdline').read_bytes().decode().split('\0')
  if '_SYSTEMD_UNIT=forwardx-realm-both-56017.service' in argv and '_SYSTEMD_UNIT=forwardx-realm-both-58372.service' in argv:r['realm_follower'].append({'pid':p.name,'args':argv})
 except OSError:pass
assert r['realm_follower']
r['enforcement_result']={'status':test['status'],'drop_counters':test['drop_counters'],'cleanup':test['cleanup'],'coverage':test['coverage']}
r['backend_tcp']={}
for addr in [('192.0.2.13',2053),('192.0.2.19',8443)]:
 try:
  sock=socket.create_connection(addr,timeout=3);sock.close();r['backend_tcp'][str(addr)]=True
 except OSError:r['backend_tcp'][str(addr)]=False
assert all(r['backend_tcp'].values())
r['review_pid_continuity']={u:a[u]['MainPID']==pid for u,pid in REVIEW_PIDS.items()}
assert all(r['review_pid_continuity'].values())
r['rollback_sha256']=hashlib.sha256((base/'rollback.py').read_bytes()).hexdigest()
assert r['rollback_sha256']==EXPECTED_ROLLBACK
r['crowdsec_processes']=[]
for p in Path('/proc').glob('[0-9]*'):
 try:
  if (p/'comm').read_text().strip()=='crowdsec':r['crowdsec_processes'].append(p.name)
 except OSError:pass
assert r['crowdsec_processes']==[a['crowdsec.service']['MainPID']]
r['status']='verified'

(base/'review-20261103/final-result.json').write_text(json.dumps(r,ensure_ascii=False,indent=2))
print(json.dumps(r,ensure_ascii=False,indent=2))

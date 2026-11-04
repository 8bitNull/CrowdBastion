from pathlib import Path
import subprocess,json,hashlib,datetime,tarfile,os,re,socket,sys
b=Path('/var/backups/crowdbastion/vps144-20261103T103358Z');release=Path('/opt/crowdbastion/releases/20261103-vps144')
sys.path.insert(0,str(release/'lib'))
from crowdsec_config import merged_config
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'commands':{},'protected_hashes':{},'identity_preserved':{}}
def cmd(args,t=45):
 p=subprocess.run(args,capture_output=True,text=True,timeout=t);return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[-600:]}
def states(s):
 return {d['Id']:d for block in s.strip().split('\n\n') if (d:=dict(x.split('=',1) for x in block.splitlines() if '=' in x)) and 'Id' in d}
before=states((b/'services-before.txt').read_text())
current=cmd(['systemctl','show',*before,'-p','Id','-p','MainPID','-p','ActiveState','-p','NRestarts'])
r['commands']['services']=current;a=states(current['stdout'])
r['forwardx_pid_continuity']={name:a[name]['MainPID']==before[name]['MainPID'] for name in before if name.startswith('forwardx-')};assert all(value for name,value in r['forwardx_pid_continuity'].items() if name.startswith('forwardx-realm-'));assert all(x['ActiveState']=='active' for x in a.values())
for name,digest in json.loads((b/'baseline.json').read_text())['protected'].items():r['protected_hashes'][name]=hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest
assert all(r['protected_hashes'].values())
with tarfile.open(b/'configuration-before.tar.gz') as tar:
 for name in ['etc/crowdsec/local_api_credentials.yaml','etc/crowdsec/online_api_credentials.yaml','etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml']:
  r['identity_preserved'][name]=hashlib.sha256(tar.extractfile(name).read()).hexdigest()==hashlib.sha256(Path('/'+name).read_bytes()).hexdigest()
assert all(r['identity_preserved'].values())
for key,args in [('config_test',['crowdsec','-t']),('firewall',['crowdbastion','--firewall-check']),('runtime',['crowdbastion','--runtime-status']),('health',['crowdbastion','--status-json']),('sockets',['ss','-lntup']),('qdisc',['tc','-s','qdisc','show','dev','ens18']),('kernel',['sysctl','net.ipv4.tcp_syn_retries','net.ipv4.tcp_synack_retries','net.ipv4.tcp_orphan_retries','net.ipv4.tcp_fin_timeout','net.ipv4.tcp_autocorking','net.ipv4.tcp_no_metrics_save','net.ipv4.tcp_tw_reuse','net.core.default_qdisc','net.ipv4.tcp_congestion_control','net.core.rmem_max','net.core.wmem_max','net.ipv4.udp_rmem_min','net.ipv4.udp_wmem_min','net.ipv4.tcp_mem']),('namespaces',['ip','netns','list']),('links',['ip','-j','link','show']),('metrics',['cscli','metrics','show','-o','json']),('bouncers',['cscli','bouncers','list','-o','json']),('cron',['crontab','-l']),('journal',['journalctl','-u','systemd-journald','--since','45 minutes ago','-n','12','--no-pager']),('packages',['dpkg-query','-W','-f=${Package} ${Status} ${Version}\n','crowdsec','crowdsec-firewall-bouncer-iptables'])]:
 out=cmd(args,60)
 if key=='metrics':
  m=json.loads(out['stdout']);r['metrics']={'acquisition':m.get('acquisition'),'realm_parsers':{k:v for k,v in m.get('parsers',{}).items() if 'realm-forwardx' in k}};continue
 if key=='bouncers':r['bouncers']=[{k:x.get(k) for k in ['name','type','last_pull','revoked','version']} for x in json.loads(out['stdout'])];continue
 r['commands'][key]=out
 if key in ['config_test','firewall','runtime','packages']:assert out['exit']==0,(key,out)
 if key=='health':assert out['exit'] in (0,2),out
assert not r['commands']['namespaces']['stdout'].strip()
assert not any(x['ifname'].startswith(('cb144','cb179')) for x in json.loads(r['commands']['links']['stdout']))
r['bouncer_mode']=merged_config('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')['mode'];assert r['bouncer_mode']=='iptables'
r['migration']=json.loads((b/'host-migration.json').read_text());assert r['migration']['status']=='committed'
r['network_commit']=json.loads((b/'network-final-commit.json').read_text());assert r['network_commit']['state']=='committed'
r['enforcement']=json.loads((b/'enforcement-review-result.json').read_text());assert r['enforcement']['status']=='passed' and r['enforcement']['renewal_verified'] and r['enforcement']['expiry_verified']
raw=cmd(['nft','-j','list','tables']);tables=[x.get('table',{}) for x in json.loads(raw['stdout'])['nftables']]
assert not any(x.get('name')=='crowdbastion_vps144_guard' for x in tables);assert any(x.get('name')=='forwardx_traffic' for x in tables)
r['guard_removed']=True;r['forwardx_accounting_preserved']=True
r['network_values']={key.strip():value.strip() for line in r['commands']['kernel']['stdout'].splitlines() if '=' in line for key,value in [line.split('=',1)]}
expected={'net.ipv4.tcp_syn_retries':'6','net.ipv4.tcp_synack_retries':'5','net.ipv4.tcp_orphan_retries':'0','net.ipv4.tcp_fin_timeout':'60','net.ipv4.tcp_autocorking':'1','net.ipv4.tcp_no_metrics_save':'0','net.ipv4.tcp_tw_reuse':'2'}
assert all(r['network_values'][k]==v for k,v in expected.items());assert r['network_values']['net.ipv4.tcp_congestion_control']=='bbr' and r['network_values']['net.core.default_qdisc']=='fq'
stat=cmd(['nstat','-az']);r['socket_counters']={parts[0]:int(parts[1]) for line in stat['stdout'].splitlines() if len(parts:=line.split())>=2 and parts[0] in ['UdpRcvbufErrors','UdpSndbufErrors','UdpMemErrors','TcpExtListenOverflows','TcpExtListenDrops']}
r['backend_tcp']={}
for port in (2087,2096):
 sock=socket.create_connection(('192.0.2.13',port),3);sock.close();r['backend_tcp'][str(port)]=True
r['realm_follower']=[]
for p in Path('/proc').glob('[0-9]*'):
 try:
  if (p/'comm').read_text().strip()=='journalctl':
   argv=(p/'cmdline').read_bytes().decode().split('\0')
   if all('_SYSTEMD_UNIT=forwardx-realm-both-'+str(port)+'.service' in argv for port in [53534,53536,53537]):r['realm_follower'].append(p.name)
 except OSError:pass
assert r['realm_follower']
fixture='[2026-11-03][18:00:00][realm_core::tcp][ERROR][tcp][::ffff:203.0.113.242]:45012 => 192.0.2.13:2087, error: Connection timed out (os error 110)'
x=cmd(['cscli','explain','--log',fixture,'--type','realm-forwardx','--verbose']);(b/'observation-explain.txt').write_text(x['stdout'])
r['observation_parser_test']={'exit':x['exit'],'classified':'realm_forwardx_observation' in x['stdout'],'source_ip_extracted':'evt.Meta.source_ip' in x['stdout']};assert x['exit']==0 and r['observation_parser_test']['classified'] and not r['observation_parser_test']['source_ip_extracted']
r['status']='verified';(b/'final-result.json').write_text(json.dumps(r,ensure_ascii=False,indent=2));print(json.dumps(r,ensure_ascii=False,indent=2))

from pathlib import Path
import subprocess,json,hashlib,datetime,sqlite3
b=Path('/var/backups/crowdbastion/vps144-20261103T103358Z');r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':{},'commands':{}}
for name in ['/usr/local/lib/crowdbastion-static-policy/apply.py','/usr/local/lib/crowdbastion-static-policy/rules.json','/etc/systemd/system/crowdbastion-static-policy.service','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/sysctl.d/99-zz-crowdbastion-network.conf','/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml','/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml']:
 p=Path(name);r['files'][name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'uid':p.stat().st_uid,'mode':oct(p.stat().st_mode&0o777),'text':p.read_text()}
for k,a in [('services',['systemctl','show','forwardx-agent','forwardx-realm-both-53534','forwardx-realm-both-53536','forwardx-realm-both-53537','crowdsec','crowdsec-firewall-bouncer','systemd-journald','crowdbastion-static-policy','-p','Id','-p','MainPID','-p','ActiveState','-p','NRestarts','-p','ExecMainStartTimestamp','-p','UnitFileState']),('firewall',['crowdbastion','--firewall-check']),('health',['crowdbastion','--status-json']),('network',['crowdbastion','--network-status']),('metrics',['cscli','metrics','show','-o','json']),('rules4',['iptables-save','-c']),('rules6',['ip6tables-save','-c']),('namespaces',['ip','netns','list']),('timers',['systemctl','list-timers','--all','--no-pager']),('journal',['journalctl','-u','forwardx-agent','--since','3 hours ago','-n','12','--no-pager'])]:
 p=subprocess.run(a,capture_output=True,text=True,timeout=60)
 if k=='metrics':
  m=json.loads(p.stdout);p.stdout=json.dumps({'acquisition':m.get('acquisition',{}),'realm_parsers':{key:v for key,v in m.get('parsers',{}).items() if 'realm' in key}},indent=2)
 if k=='network':
  n=json.loads(p.stdout);p.stdout=json.dumps({key:n.get(key) for key in ['state','problems','running','owned_file','runtime','transactions']},indent=2)
 if k=='timers':p.stdout='\n'.join(line for line in p.stdout.splitlines() if 'crowdbastion' in line)
 r['commands'][k]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[-500:]}
manifest=json.loads((b/'manifest.json').read_text());r['backup_drift']={}
for name,digest in manifest['backup_files'].items():
 p=b/name
 if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:r['backup_drift'][name]='changed_or_missing'
c=sqlite3.connect('file:'+str(b/'crowdsec-consistent.sqlite3')+'?immutable=1',uri=True);r['backup_sqlite_check']=c.execute('PRAGMA quick_check').fetchone()[0];c.close()
print(json.dumps(r,ensure_ascii=False,indent=2))

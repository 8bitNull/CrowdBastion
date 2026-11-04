from pathlib import Path
import subprocess,json,hashlib,datetime,re,os
base=Path('/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z')
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':{},'services':{},'realm_messages':{}}
for name in ['/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml','/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml','/etc/systemd/journald.conf.d/60-crowdbastion-storage-cap.conf',str(base/'rollback.py')]:
 p=Path(name);r['files'][name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':oct(p.stat().st_mode&0o777),'uid':p.stat().st_uid,'text':p.read_text()}
for key,args in [('services',['systemctl','show','forwardx-agent','forwardx-realm-both-56017','forwardx-realm-both-58372','crowdsec','crowdsec-firewall-bouncer','systemd-journald','-p','Id','-p','MainPID','-p','NRestarts','-p','ActiveState','-p','ExecMainStartTimestamp']),('metrics',['cscli','metrics','show','-o','json']),('firewall',['crowdbastion','--firewall-check']),('netns',['ip','netns','list']),('sockets',['ss','-lntup']),('journald',['journalctl','-u','systemd-journald','--since','1 hour ago','-n','15','--no-pager']),('log_sources',['ps','-eo','pid,ppid,comm,args'])]:
 p=subprocess.run(args,capture_output=True,text=True,timeout=50)
 if key=='log_sources':p.stdout='\n'.join(line for line in p.stdout.splitlines() if 'journalctl --follow' in line)
 if key=='metrics':
  d=json.loads(p.stdout);p.stdout=json.dumps({'realm_acquisition':{k:v for k,v in d.get('acquisition',{}).items() if 'forwardx' in k},'realm_parser':{k:v for k,v in d.get('parsers',{}).items() if 'realm' in k},'ssh':{k:v for k,v in d.get('acquisition',{}).items() if 'ssh.service' in k}},indent=2)
 r[key]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[-500:]}
for unit in ['forwardx-realm-both-56017.service','forwardx-realm-both-58372.service']:
 p=subprocess.run(['journalctl','-u',unit,'-n','4','-o','json','--no-pager'],capture_output=True,text=True,timeout=15)
 messages=[]
 for line in p.stdout.splitlines():
  try:
   d=json.loads(line);m=d.get('MESSAGE','');m=re.sub(r'\[::ffff:[0-9.]+\]', '[::ffff:203.0.113.77]',m);messages.append({k:d.get(k) for k in ['_SYSTEMD_UNIT','SYSLOG_IDENTIFIER','__REALTIME_TIMESTAMP']}|{'MESSAGE':m})
  except ValueError:pass
 r['realm_messages'][unit]=messages
r['backup_manifest_check']={}
m=json.loads((base/'manifest.json').read_text())
for n,digest in m.items():
 p=base/n
 if not p.exists():r['backup_manifest_check'][n]='missing'
 elif hashlib.sha256(p.read_bytes()).hexdigest()!=digest:r['backup_manifest_check'][n]='changed'
print(json.dumps(r,ensure_ascii=False,indent=2))

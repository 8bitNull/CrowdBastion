from pathlib import Path
import hashlib,json,datetime,subprocess
b=Path('/var/backups/crowdbastion/vps144-20261103T103358Z')
sysctl=['/etc/sysctl.d/99-zz-crowdbastion-network.conf','/var/lib/crowdbastion/network.json','/var/lib/crowdbastion/node-roles.json','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml','/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml','/etc/systemd/journald.conf.d/60-crowdbastion-storage-cap.conf']
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backup':str(b),'live_hashes':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sysctl},'backup_files':{str(p.relative_to(b)):hashlib.sha256(p.read_bytes()).hexdigest() for p in b.rglob('*') if p.is_file() and p.name!='manifest.json'}}
(b/'manifest.json').write_text(json.dumps(r,indent=2)+'\n')
for p in b.rglob('*'):
 if p.is_file():p.chmod(0o600)
selected={}
for name in ['network-plan.json','network-apply.json','network-verify.json','network-final-commit.json','host-migration.json','host-migration.failed-1.json','switch-firewall-check.txt']:
 p=b/name
 if p.exists():selected[name]=p.read_text()
print(json.dumps({'backup':str(b),'files':len(r['backup_files']),'live_hashes':r['live_hashes'],'selected':selected},ensure_ascii=False))

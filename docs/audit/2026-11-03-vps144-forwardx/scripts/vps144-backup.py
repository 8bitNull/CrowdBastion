from pathlib import Path
import os,subprocess,json,hashlib,datetime,tarfile,sqlite3,shutil
base=Path('/var/backups/crowdbastion')/('vps144-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));base.mkdir(mode=0o700,parents=True);os.chmod(base,0o700)
release=Path('/opt/crowdbastion/releases/20261103-vps144');release.mkdir(mode=0o755,parents=True,exist_ok=False)
archive=Path('/root/vps144-release.tar.gz');assert hashlib.sha256(archive.read_bytes()).hexdigest()=='9f4228ad1b1e89b1dcb2a4cdf49fea3ee6bae43bc7dc4f66089f28eac65197ee'
with tarfile.open(archive) as tar:
 assert all(not m.issym() and not m.islnk() and not m.name.startswith('/') and '..' not in Path(m.name).parts for m in tar.getmembers());tar.extractall(release)
for p in release.rglob('*'):os.chown(p,0,0);p.chmod(0o755 if p.is_dir() or p.name=='crowdbastion.sh' else 0o644)
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backup':str(base),'release':str(release),'protected':{}}
with tarfile.open(base/'configuration-before.tar.gz','w:gz') as tar:
 for name in ['/etc/crowdsec','/etc/forwardx','/etc/systemd/system','/etc/sysctl.conf','/etc/sysctl.d','/etc/iptables','/etc/cron.d','/usr/local/bin/realm']:
  p=Path(name)
  if p.exists():tar.add(p,arcname=name.lstrip('/'))
src=sqlite3.connect('file:/var/lib/crowdsec/data/crowdsec.db?mode=ro',uri=True);dst=sqlite3.connect(base/'crowdsec-consistent.sqlite3');src.backup(dst);dst.close();src.close()
for args,name in [(['iptables-save','-c'],'iptables-before.txt'),(['ip6tables-save','-c'],'ip6tables-before.txt'),(['nft','-j','list','ruleset'],'nft-before.json'),(['crontab','-l'],'root.crontab.before'),(['systemctl','show','forwardx-agent','forwardx-realm-both-53534','forwardx-realm-both-53536','forwardx-realm-both-53537','crowdsec','crowdsec-firewall-bouncer','-p','Id','-p','MainPID','-p','ActiveState','-p','NRestarts'],'services-before.txt')]:
 p=subprocess.run(args,capture_output=True,text=True,timeout=20);assert p.returncode==0;(base/name).write_text(p.stdout)
for p in [Path('/usr/local/bin/realm'),*Path('/etc/forwardx/realm').glob('*.toml')]:r['protected'][str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
# Preserve root-owned static rules individually; do not restore a dynamic table.
static=[]
import shlex
for binary,name in [('iptables','iptables-before.txt'),('ip6tables','ip6tables-before.txt')]:
 table=None
 for line in (base/name).read_text().splitlines():
  if line.startswith('*'):table=line[1:]
  if '] -A ' in line:static.append({'binary':binary,'table':table,'rule':shlex.split(line.split('] ',1)[1])})
(base/'static-rules.json').write_text(json.dumps(static,indent=2))
(base/'baseline.json').write_text(json.dumps(r,indent=2));os.chmod(base/'baseline.json',0o600)
wrapper=Path('/usr/local/bin/crowdbastion');assert not wrapper.exists();wrapper.write_text('#!/bin/sh\nexec /bin/bash '+str(release/'crowdbastion.sh')+' "$@"\n');wrapper.chmod(0o755)
print(json.dumps(r,indent=2))

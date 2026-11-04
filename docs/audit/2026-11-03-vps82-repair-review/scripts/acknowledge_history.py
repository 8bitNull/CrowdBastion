DATA = {'backup': '/var/backups/crowdbastion/vps82-sysctl-review-iqdvz68q', 'after_hash': '8077d4e3c25a45e613ff52a81003adb01f870c0526a89109a1c5a8de1e212447', 'since_epoch': 1793707521}
from pathlib import Path
import subprocess,json,hashlib,datetime,stat
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def cmd(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=20)
 return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
backup=Path(DATA['backup']);info=backup.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_mode & 0o077==0
out=backup/'historical-failure-ack.json';assert not out.exists()
source=Path('/etc/sysctl.d/99-network-optimize.conf');assert not source.is_symlink()
assert hashlib.sha256(source.read_bytes()).hexdigest()==DATA['after_hash']
assert Path('/proc/sys/net/core/netdev_budget_usecs').read_text().strip()=='8000'
r['unit_before']=cmd(['systemctl','show','systemd-sysctl','-p','Result','-p','ExecMainStatus','-p','ActiveState','-p','MainPID'])
assert r['unit_before']['exit']==0 and 'ActiveState=failed' in r['unit_before']['stdout'] and 'MainPID=0' in r['unit_before']['stdout']
r['recent_unit_journal']=cmd(['journalctl','-u','systemd-sysctl','--since','@'+str(DATA['since_epoch']),'-o','json','--no-pager'])
assert r['recent_unit_journal']['exit']==0 and not r['recent_unit_journal']['stdout'].strip(),r['recent_unit_journal']
r['reset_failed']=cmd(['systemctl','reset-failed','systemd-sysctl.service']);assert r['reset_failed']['exit']==0
r['unit_after']=cmd(['systemctl','show','systemd-sysctl','-p','Result','-p','ExecMainStatus','-p','ActiveState','-p','MainPID'])
assert r['unit_after']['exit']==0 and 'ActiveState=inactive' in r['unit_after']['stdout'] and 'MainPID=0' in r['unit_after']['stdout']
r['scope']='Acknowledged recorded historical failure only; no unit restart and no full sysctl reload'
r['status']='historical_failure_acknowledged'
out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))

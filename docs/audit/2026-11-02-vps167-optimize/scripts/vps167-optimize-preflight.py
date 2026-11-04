import hashlib,json,os,re,stat,subprocess,time
from pathlib import Path

def run(argv):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=25);assert p.returncode==0,(argv[0],p.returncode);return p.stdout

def info(name):
 p=Path(name)
 if not p.exists() and not p.is_symlink():return {'exists':False}
 s=p.lstat();r={'exists':True,'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode),'symlink':p.is_symlink()}
 if p.is_symlink():r['target']=os.readlink(p)
 elif p.is_file():r['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 return r
p=Path('/etc/cron.d/crowdsec-autoupdate');text=p.read_text();entries=[]
for line in text.splitlines():
 m=re.search(r'(?<!\S)([0-9*/,-]+(?:\s+[0-9*/,-]+){4})\s+root\s+(/usr/bin/cscli hub update\s*&&\s*/usr/bin/cscli hub upgrade\s*&&\s*/bin/systemctl reload crowdsec)(?:\s*>\s*/dev/null\s+2>&1)?\s*$',line)
 if m:entries.append({'schedule':m[1],'disabled':line.lstrip().startswith('#'),'recognized_legacy_hub_command':True})
 # Export only ordinary comment text; never export arbitrary command arguments.
comments=[line for line in text.splitlines() if line.startswith('#') and not re.search(r'[/=]|(?:key|token|secret|password)',line,re.I)]
r={'checked_at':time.time(),'hub_cron':{'metadata':info(p),'recognized_entries':entries,'plain_comments':comments,'timezone_lines':[line for line in text.splitlines() if re.fullmatch(r'(?:CRON_TZ|TZ)=[A-Za-z_/+-]+',line)]},'rules':{b:run([b,'-w','5','-S']) for b in ['iptables','ip6tables']},'entries':{x:info(x) for x in ['/root/crowdsec-1key','/usr/local/bin/crowdbastion','/usr/local/lib/crowdsec-1key','/usr/local/lib/crowdsec-1key/current','/usr/local/lib/crowdsec-1key/.crowdsec-1key-managed','/etc/cron.d/crowdsec-autoupdate','/var/spool/cron/crontabs/root']},'units':{u:dict(x.split('=',1) for x in run(['systemctl','show',u,'--property=MainPID,ActiveState,UnitFileState,NRestarts,ExecMainStartTimestamp']).splitlines() if '=' in x) for u in ['crowdsec','crowdsec-firewall-bouncer','docker']},'timer_units':run(['systemctl','list-timers','--all','--no-pager','--no-legend']),'timezone':run(['timedatectl','show','--property=Timezone','--value']).strip()}
r['related_maintenance_files']=[]
for base in ['/etc/cron.d','/etc/systemd/system']:
 for q in Path(base).rglob('*'):
  if not q.is_file() or q.stat().st_size>131072:continue
  try:s=q.read_text()
  except (OSError,UnicodeError):continue
  if re.search(r'cscli\s+hub\s+(?:update|upgrade)|--update-hub|--cron',s):r['related_maintenance_files'].append({'path':str(q),'metadata':info(q),'has_active_hub_command':any(not line.lstrip().startswith('#') and re.search(r'cscli\s+hub\s+(?:update|upgrade)|--update-hub|--cron',line) is not None for line in s.splitlines())})
r['source_code_sha256']={str(q.relative_to('/root/crowdsec-1key')):hashlib.sha256(q.read_bytes()).hexdigest() for q in [Path('/root/crowdsec-1key/crowdbastion.sh'),*sorted(Path('/root/crowdsec-1key/lib').glob('*'))] if q.is_file() and q.suffix in ['.py','.sh','.lua']}
print(json.dumps(r,ensure_ascii=False,indent=2))

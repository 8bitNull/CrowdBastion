import hashlib,json,os,subprocess,stat
from pathlib import Path

def run(argv):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=30)
 assert p.returncode==0,(argv[0],p.returncode)
 return p.stdout

def info(p):
 p=Path(p)
 if not p.exists() and not p.is_symlink():return {'exists':False}
 s=p.lstat();r={'exists':True,'mode':oct(stat.S_IMODE(s.st_mode)),'uid':s.st_uid,'symlink':p.is_symlink()}
 if p.is_symlink():r['target']=os.readlink(p)
 if p.is_file():r['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 return r
r={'root_crontab':run(['crontab','-u','root','-l']),'rules':{b:run([b,'-w','5','-S']) for b in ['iptables','ip6tables']},'saved_rules':{v:Path('/etc/iptables/rules.'+v).read_text() for v in ['v4','v6']},'units':{u:run(['systemctl','show',u,'--property=MainPID,ActiveState,UnitFileState,NRestarts,After']) for u in ['crowdsec','crowdsec-firewall-bouncer','docker']},'entries':{p:info(p) for p in ['/root/crowdsec-1key','/usr/local/bin/crowdbastion','/usr/local/bin/crowdsec-1key','/usr/local/lib/crowdsec-1key/current','/etc/cron.d/crowdsec-autoupdate','/usr/local/lib/crowdbastion-static-policy','/etc/systemd/system/crowdbastion-static-policy.service']},'listeners':run(['ss','-lntup'])}
print(json.dumps(r,ensure_ascii=False))

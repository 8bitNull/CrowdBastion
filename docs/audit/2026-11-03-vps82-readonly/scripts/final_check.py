from pathlib import Path
import subprocess,json,datetime,hashlib,re
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'commands':{}}
for k,args in {
'fail2ban_port':['fail2ban-client','get','sshd','action','iptables-multiport','port'],
'fail2ban_journalmatch':['fail2ban-client','get','sshd','journalmatch'],
'netdev_usecs':['sysctl','net.core.netdev_budget_usecs'],
'services':['systemctl','show','forwardx-agent','fail2ban','ssh',*['forwardx-realm-both-'+str(x) for x in [53537,53541,53543,53544,53545,53546,53547,53548,53549,53551,53552,53553,53554]],'-p','Id','-p','MainPID','-p','ActiveState','-p','NRestarts'],
'iptables':['iptables-save'], 'ip6tables':['ip6tables-save'],
}.items():
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=15)
  r['commands'][k]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[-1000:]}
 except Exception as e:r['commands'][k]={'error':type(e).__name__}
r['protected_hashes']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path('/usr/local/bin/realm'),*Path('/etc/forwardx/realm').glob('*.toml')]}
r['sysctl_sources']=[]
for p in [Path('/etc/sysctl.conf'),*Path('/etc/sysctl.d').glob('*.conf'),*Path('/usr/lib/sysctl.d').glob('*.conf'),*Path('/run/sysctl.d').glob('*.conf')]:
 if p.is_file():
  for n,line in enumerate(p.read_text(errors='replace').splitlines(),1):
   if re.match(r'^\s*net[./]core[./]netdev_budget_usecs\s*=',line):r['sysctl_sources'].append({'path':str(p),'line':n,'assignment':line.strip()})
print(json.dumps(r,ensure_ascii=True,indent=2))

"""Host-only native-nftables -> iptables Bouncer switch; guarded rollback.
No Docker assumptions, no table flush/restore, no ForwardX configuration writes.
"""
from pathlib import Path
import sys,os,json,subprocess,hashlib,ipaddress,time,fcntl,signal,shlex,shutil,datetime
import yaml
BASE=Path('/var/backups/crowdbastion/vps144-20261103T103358Z')
RELEASE=Path('/opt/crowdbastion/releases/20261103-vps144')
sys.path.insert(0,str(RELEASE/'lib'))
from crowdsec_firewall_migrate import live,networks,Migration,native_references
from crowdsec_config import merged_config
CONFIG=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml');LOCAL=Path(str(CONFIG)+'.local')
GUARD='crowdbastion_vps144_guard';TIMER='crowdbastion-vps144-fw-rollback';UNIT='crowdsec-firewall-bouncer'
STATE=BASE/'host-migration.json'
CANDIDATE=yaml.safe_dump({'mode':'iptables','iptables_chains':[],'iptables_v4_chains':['INPUT','FORWARD'],'iptables_v6_chains':['INPUT','FORWARD']},sort_keys=False).encode()

def cmd(a,check=True,input=None,t=60):
 p=subprocess.run(a,capture_output=True,text=True,input=input,timeout=t)
 if check and p.returncode:raise RuntimeError(str(a[:4])+': '+p.stderr[-1000:])
 return p

def atomic(p,data):
 tmp=p.with_name('.'+p.name+'.vps144');fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(tmp,p)
 finally:tmp.unlink(missing_ok=True)

def save(s):atomic(STATE,json.dumps(s,indent=2).encode())
def source():return os.environ['SSH_CONNECTION'].split()
def guard_exists():return any(x.get('table',{}).get('name')==GUARD and x['table']['family']=='inet' for x in json.loads(cmd(['nft','-j','list','tables']).stdout)['nftables'])
def stop_timer():cmd(['systemctl','stop',TIMER+'.timer'],check=False)

def preserved_rules():
 def parse(text):
  table=None;rules=[];policies={}
  for line in text.splitlines():
   if line.startswith('*'):table=line[1:]
   line=__import__('re').sub(r'^\[\d+:\d+\] ','',line)
   if line.startswith(':') and not line.startswith(':CROWDSEC_CHAIN '):policies[(table,line.split()[0])]=line.split()[1]
   if line.startswith('-A ') and not (table=='filter' and (line.startswith('-A CROWDSEC_CHAIN ') or line in ('-A INPUT -j CROWDSEC_CHAIN','-A FORWARD -j CROWDSEC_CHAIN'))):rules.append((table,line))
  return rules,policies
 for binary,name in [('iptables','iptables-before.txt'),('ip6tables','ip6tables-before.txt')]:
  a,policies=parse((BASE/name).read_text());b,current=parse(cmd([binary+'-save']).stdout)
  if a!=b or any(current.get(k)!=v for k,v in policies.items()):raise RuntimeError('unrelated rule drift '+binary)

def rollback():
 if not STATE.exists():return
 s=json.loads(STATE.read_text())
 if s.get('status') in ('committed','rolled_back'):stop_timer();return
 if hashlib.sha256(CONFIG.read_bytes()).hexdigest()!=s['base_sha256']:raise RuntimeError('base credentials/config drift; guard retained')
 if LOCAL.exists() and LOCAL.read_bytes()!=CANDIDATE:raise RuntimeError('override drift; guard retained')
 cmd(['systemctl','stop',UNIT])
 old=BASE/'bouncer.local.before'
 if old.exists():atomic(LOCAL,old.read_bytes())
 else:LOCAL.unlink(missing_ok=True)
 cmd(['systemctl','start',UNIT]);cmd(['systemctl','is-active','--quiet',UNIT])
 Migration().wait_coverage(native=True)
 if guard_exists():cmd(['nft','delete','table','inet',GUARD])
 s['status']='rolled_back';save(s);stop_timer()

def start():
 if STATE.exists():raise RuntimeError('transaction already exists')
 if (BASE/'enforcement-review-result.json').exists():raise RuntimeError('prior enforcement evidence exists')
 for tool in ('nft','ipset','iptables','ip6tables','systemd-run','crowdsec-firewall-bouncer'):
  if not shutil.which(tool):raise RuntimeError('missing migration dependency '+tool)
 if merged_config(CONFIG)['mode']!='nftables' or LOCAL.exists():raise RuntimeError('unexpected original mode/override')
 if cmd(['systemctl','show','docker','-p','LoadState','--value']).stdout.strip()!='not-found':raise RuntimeError('host-only transaction refuses Docker')
 native_references(json.loads(cmd(['nft','-j','list','ruleset']).stdout),CONFIG)
 if guard_exists():raise RuntimeError('guard table exists')
 ssh=source();nets=networks(live(CONFIG));admin=ipaddress.ip_address(ssh[0])
 if any(admin.version==n.version and admin in n for n in nets):raise RuntimeError('SSH source banned')
 if any('@reboot iptables-restore' in line and not line.lstrip().startswith('#') for line in cmd(['crontab','-l'],check=False).stdout.splitlines()) or cmd(['systemctl','is-enabled','netfilter-persistent'],check=False).returncode==0:raise RuntimeError('boot restore must be resolved first')
 s={'status':'prepared','ssh':ssh,'created':time.time(),'base_sha256':hashlib.sha256(CONFIG.read_bytes()).hexdigest()};save(s)
 cmd(['systemd-run','--collect','--unit='+TIMER,'--on-active=12m','--timer-property=AccuracySec=1s','--property=Restart=on-failure','--property=RestartSec=30s','/usr/bin/python3',str(Path(__file__).resolve()),'rollback'])
 cmd(['systemctl','is-active','--quiet',TIMER+'.timer'])
 try:
  lines=['table inet '+GUARD+' {']
  for version,kind in [(4,'ipv4_addr'),(6,'ipv6_addr')]:
   values=', '.join(map(str,ipaddress.collapse_addresses(n for n in nets if n.version==version)))
   lines.append('set ban'+str(version)+' { type '+kind+'; flags interval; auto-merge; '+('elements = { '+values+' }; ' if values else '')+'}')
  for hook in ['input','forward']:lines+=['chain protect_'+hook+' { type filter hook '+hook+' priority -20; policy accept;','ip saddr @ban4 drop','ip6 saddr @ban6 drop','}']
  lines.append('}');nft='\n'.join(lines)+'\n';cmd(['nft','-c','-f','-'],input=nft);cmd(['nft','-f','-'],input=nft)
  cmd(['systemctl','stop',UNIT]);atomic(LOCAL,CANDIDATE);cmd(['systemctl','start',UNIT]);cmd(['systemctl','is-active','--quiet',UNIT])
  deadline=time.monotonic()+60
  while True:
   check=cmd(['/usr/local/bin/crowdbastion','--firewall-check'],check=False)
   (BASE/'switch-firewall-check.txt').write_text(check.stdout+check.stderr)
   if check.returncode==0:break
   if time.monotonic()>=deadline:raise RuntimeError('firewall initial synchronization timeout: '+check.stdout[-2000:])
   time.sleep(1)
  preserved_rules();s['status']='pending';save(s)
 except BaseException:
  for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
  rollback();raise
 print(json.dumps({'status':'pending','rollback_seconds':720,'guard':GUARD}))

def commit():
 s=json.loads(STATE.read_text());ssh=source()
 if s['status']!='pending' or ssh==s['ssh'] or ssh[0]!=s['ssh'][0] or ssh[2:]!=s['ssh'][2:]:raise RuntimeError('fresh independent SSH required')
 if time.time()>s['created']+660:raise RuntimeError('commit window expired')
 if LOCAL.read_bytes()!=CANDIDATE or hashlib.sha256(CONFIG.read_bytes()).hexdigest()!=s['base_sha256']:raise RuntimeError('config drift')
 evidence=BASE/'enforcement-review-result.json';r=json.loads(evidence.read_text())
 if evidence.stat().st_mtime<s['created'] or datetime.datetime.fromisoformat(r['at']).timestamp()<s['created'] or r.get('transaction_created')!=s['created'] or r.get('bouncer_override_sha256')!=hashlib.sha256(LOCAL.read_bytes()).hexdigest():raise RuntimeError('enforcement evidence not bound to transaction')
 if r['status']!='passed' or not r.get('renewal_verified') or not r.get('expiry_verified'):raise RuntimeError('full enforcement lifecycle required')
 cmd(['/usr/local/bin/crowdbastion','--firewall-check']);preserved_rules()
 if guard_exists():cmd(['nft','delete','table','inet',GUARD])
 s['status']='committed';save(s);stop_timer();print(json.dumps({'status':'committed'}))

if __name__=='__main__':
 os.umask(0o077)
 with open('/run/lock/crowdsec-1key.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,lambda n,f:(_ for _ in ()).throw(InterruptedError('cancelled')))
  {'start':start,'rollback':rollback,'commit':commit}[sys.argv[1]]()

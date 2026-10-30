import pathlib,subprocess as sp,sys,json,time,os,fcntl,hashlib,ipaddress,re,yaml,urllib.request
B=pathlib.Path('/var/backups/crowdbastion/vps4-cycle-20261030')
CONFIG=pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
LOCAL=pathlib.Path(str(CONFIG)+'.local')
DROPIN=pathlib.Path('/etc/systemd/system/crowdsec-firewall-bouncer.service.d/20-crowdbastion-docker-order.conf')
OVERRIDE=b'mode: iptables\niptables_chains: [INPUT, FORWARD, DOCKER-USER]\n'
ORDER=b'[Unit]\nAfter=docker.service\n'
UNIT='crowdsec-firewall-bouncer'
ADMINS=[(B/'ssh-source').read_text().strip()]
COMMENT='cbv4-migration-admin'
def run(args,check=True,input=None,timeout=45):
 r=sp.run(args,text=True,capture_output=True,input=input,timeout=timeout)
 if check and r.returncode:raise RuntimeError(str(args[:7])+': '+r.stderr[:800])
 return r

def write(path,data):
 p=path.with_name(path.name+'.cbv4-new');p.write_bytes(data);p.chmod(0o600);os.replace(p,path)

def live():
 c=yaml.safe_load(CONFIG.read_text())
 if LOCAL.exists():c.update(yaml.safe_load(LOCAL.read_text()) or {})
 q=urllib.request.Request(c['api_url'].rstrip('/')+'/v1/decisions',headers={'X-Api-Key':c['api_key']})
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(q,timeout=20) as r:return json.load(r) or []

def seconds(t):
 if t.startswith('-'):return -1
 factors={'h':3600,'m':60,'s':1,'ms':.001,'us':.000001,'µs':.000001,'ns':1e-9}
 return sum(float(n)*factors[u] for n,u in re.findall(r'([0-9.]+)(ns|us|µs|ms|h|m|s)',t))

def bans(rows,minleft=0):
 return [ipaddress.ip_network(d['value'],strict=False) for d in rows if d.get('type')=='ban' and d.get('scope','').lower() in ('ip','range') and seconds(d.get('duration','0s'))>minleft]

def hold():
 existing=run(['nft','list','table','inet','cbv4_migration'],False)
 if existing.returncode==0:return
 rows=live();(B/'decisions-at-switch.json').write_text(json.dumps(rows))
 nets=bans(rows)
 for admin in ADMINS:assert not any(ipaddress.ip_address(admin) in n for n in nets if n.version==4),'administrator is banned'
 lines=['table inet cbv4_migration {']
 for ver,typ in [(4,'ipv4_addr'),(6,'ipv6_addr')]:
  members=list(ipaddress.collapse_addresses(n for n in nets if n.version==ver))
  lines.append(f' set ban{ver} {{ type {typ}; flags interval; auto-merge; elements = {{ '+', '.join(str(n) for n in members)+' }; }')
 for hook in ['input','forward']:
  lines += [f' chain protect_{hook} {{ type filter hook {hook} priority -20; policy accept;', ' ip saddr @ban4 counter drop',' ip6 saddr @ban6 counter drop',' }']
 lines.append('}')
 script='\n'.join(lines)+'\n';(B/'hold.nft').write_text(script)
 run(['nft','-c','-f','-'],input=script);run(['nft','-f','-'],input=script)

def remove_hold():run(['nft','delete','table','inet','cbv4_migration'],False)
def admin_rules(add):
 for addr in ADMINS:
  rule=['-s',addr,'-p','tcp','--dport','53322','-m','comment','--comment',COMMENT,'-j','ACCEPT']
  exists=run(['iptables','-w','5','-C','INPUT',*rule],False).returncode==0
  if add and not exists:run(['iptables','-w','5','-I','INPUT','1',*rule])
  if not add and exists:run(['iptables','-w','5','-D','INPUT',*rule])

def membership():
 rows=live();expected=set(str(n) for n in bans(rows,15))
 saved=run(['ipset','save']).stdout;(B/'ipset-after.txt').write_text(saved)
 actual=set();names={4:set(),6:set()}
 for line in saved.splitlines():
  fields=line.split()
  if len(fields)>2 and fields[0]=='add' and re.fullmatch(r'crowdsec6?-blacklists-?[0-9]*',fields[1]):
   net=ipaddress.ip_network(fields[2],strict=False);actual.add(str(net));names[net.version].add(fields[1])
 missing=expected-actual
 # A broader network is sufficient; ask the kernel only for unmatched entries.
 unresolved=[]
 for value in missing:
  net=ipaddress.ip_network(value)
  if len(missing)>100 or net.prefixlen!=net.max_prefixlen or not any(run(['ipset','test',name,str(net.network_address)],False).returncode==0 for name in names[net.version]):unresolved.append(value)
 return {'active_decisions':len(rows),'expected_networks_over_15s':len(expected),'kernel_networks':len(actual),'missing':unresolved}

def check_rules():
 result={}
 for binary,file in [('iptables','iptables-before.txt'),('ip6tables','ip6tables-before.txt')]:
  before=(B/file).read_text().splitlines();after=run([binary+'-save']).stdout.splitlines()
  (B/('attempt-'+file)).write_text('\n'.join(after)+'\n')
  old=[l for l in before if l.startswith('-A 1PANEL_')];new=[l for l in after if l.startswith('-A 1PANEL_')]
  assert old==new,'1Panel rules changed'
  for chain in ['INPUT','FORWARD','DOCKER-USER']:
   lines=[l for l in after if l.startswith('-A '+chain+' ') and COMMENT not in l]
   assert lines and lines[0]=='-A '+chain+' -j CROWDSEC_CHAIN',(binary,chain,lines[:2])
  blocked=[l for l in after if l.startswith('-A CROWDSEC_CHAIN ')]
  assert blocked and all('--match-set crowdsec' in l and ' src ' in l and '-j DROP' in l for l in blocked),'unexpected CrowdSec chain rule'
  old_other=[l for l in before if l.startswith('-A ')]
  new_other=[l for l in after if l.startswith('-A ') and not l.startswith('-A CROWDSEC_CHAIN ') and '-j CROWDSEC_CHAIN' not in l and COMMENT not in l]
  assert old_other==new_other,'non-CrowdSec rules changed'
  (B/('post-'+file)).write_text('\n'.join(after)+'\n')
  result[binary]='all original rules unchanged; all three entry points protected first'
 return result



def restore_file(path, name):
 original=B/(name+'.before')
 if original.exists():write(path,original.read_bytes())
 else:path.unlink(missing_ok=True)

def snapshot_file(path,name):
 if path.exists():(B/(name+'.before')).write_bytes(path.read_bytes())

def rollback():
 if (B/'committed').exists() or (B/'rolled-back').exists():return
 # Refuse to overwrite a later administrator change.
 for path,name in [(LOCAL,'local'),(DROPIN,'dropin')]:
  expected=B/(name+'.applied')
  if expected.exists() and path.read_bytes()!=expected.read_bytes():raise RuntimeError('Configuration drift; manual recovery required')
 hold();run(['systemctl','stop',UNIT])
 restore_file(LOCAL,'local');restore_file(DROPIN,'dropin')
 run(['systemctl','daemon-reload']);run(['systemctl','start',UNIT]);run(['systemctl','is-active','--quiet',UNIT])
 remove_hold();admin_rules(False);(B/'rolled-back').touch()
 print('Rollback completed')

def migrate():
 assert not (B/'migration-started').exists()
 assert run(['ipset','--version']).returncode==0
 snapshot_file(LOCAL,'local');snapshot_file(DROPIN,'dropin')
 data=yaml.safe_load(LOCAL.read_text()) if LOCAL.exists() else {}
 assert data is None or isinstance(data,dict)
 data=data or {};data.update(mode='iptables',iptables_chains=['INPUT','FORWARD','DOCKER-USER'])
 desired=yaml.safe_dump(data,sort_keys=False).encode()
 (B/'local.applied').write_bytes(desired);(B/'dropin.applied').write_bytes(ORDER)
 (B/'migration-started').touch()
 run(['systemd-run','--unit=cb-vps4-firewall-rollback','--on-active=8m','/usr/bin/python3',str(B/'migrate.py'),'rollback'])
 try:
  hold();admin_rules(True)
  run(['systemctl','stop',UNIT]);write(LOCAL,desired);DROPIN.parent.mkdir(parents=True,exist_ok=True);write(DROPIN,ORDER)
  run(['systemctl','daemon-reload']);run(['systemctl','start',UNIT]);run(['systemctl','is-active','--quiet',UNIT])
  end=time.monotonic()+60
  while True:
   report=membership()
   if not report['missing']:break
   if time.monotonic()>end:raise RuntimeError('Kernel ban coverage incomplete')
   time.sleep(2)
  admin_rules(False);rules=check_rules()
  (B/'migration.json').write_text(json.dumps({'membership':report,'rules':rules,'awaiting_flow_and_fresh_ssh':True},indent=2))
  print(json.dumps({'membership':report,'rules':rules,'awaiting_flow_and_fresh_ssh':True}))
 except BaseException:
  rollback();raise

def commit():
 assert not (B/'rolled-back').exists()
 assert json.loads((B/'flow-after.json').read_text())['passed']
 report=membership();assert not report['missing'];check_rules()
 assert LOCAL.read_bytes()==(B/'local.applied').read_bytes() and DROPIN.read_bytes()==(B/'dropin.applied').read_bytes()
 run(['systemctl','stop','cb-vps4-firewall-rollback.timer']);remove_hold();admin_rules(False)
 (B/'committed').touch();print('Migration committed; rollback timer stopped; snapshot protection removed')

if __name__=='__main__':
 os.umask(0o077)
 with (B/'migration.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  {'migrate':migrate,'rollback':rollback,'commit':commit}[sys.argv[1]]()

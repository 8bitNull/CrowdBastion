import json,pathlib,hashlib,subprocess as sp,sys,os,tarfile,yaml
os.umask(0o077);B=pathlib.Path('/var/backups/crowdbastion/vps4-cycle-20261030');R=pathlib.Path('/root/crowdsec-1key');sys.path.insert(0,str(B));import migrate
report={}
def run(args,**kw):return sp.run(args,text=True,capture_output=True,timeout=150,**kw)
def out(args):
 r=run(args)
 if r.returncode:raise RuntimeError(str(args[:4])+': '+r.stderr[:200])
 return r.stdout
assert (B/'committed').exists() and not (B/'rolled-back').exists();report['migration_committed']=True
report['membership']=migrate.membership();assert not report['membership']['missing']
report['rules']=migrate.check_rules()
for name,args in [('core_config',['crowdsec','-t']),('nginx_config',['docker','exec','nginx','nginx','-t']),('service_active',['systemctl','is-active','crowdsec','crowdsec-firewall-bouncer','docker','V2bX','systemd-sysctl'])]:
 r=run(args);report[name]={'exit':r.returncode,'output':r.stdout+r.stderr};assert r.returncode==0
report['failed_units']=out(['systemctl','--failed','--no-legend','--no-pager']).strip();assert not report['failed_units']
old=(B/'services-before.txt').read_text();now=out(['systemctl','show','crowdsec','crowdsec-firewall-bouncer','docker','V2bX','-p','Id','-p','MainPID','-p','ExecMainStartTimestamp','-p','NRestarts'])
def units(text):
 return {next(l for l in block.splitlines() if l.startswith('Id=')):block.strip() for block in text.strip().split('\n\n')}
a,b=units(old),units(now)
report['core_docker_v2bx_not_restarted']=all(a[k]==b[k] for k in a if 'firewall-bouncer' not in k);assert report['core_docker_v2bx_not_restarted']
report['service_runtime']=now
containers=json.loads(out(['docker','inspect','nginx','gost','openlist','gost-http-proxy']));before={x['Name']:x for x in json.loads((B/'containers-before.json').read_text())}
report['containers']={}
for c in containers:
 report['containers'][c['Name']]={'state':c['State']['Status'],'restart_count':c['RestartCount']}
 if c['Name']!='/gost-http-proxy':
  assert c['State']['Running'] and not c['State']['Restarting']
  assert c['State']['Pid']==before[c['Name']]['State']['Pid'] and c['State']['StartedAt']==before[c['Name']]['State']['StartedAt']
 else:assert not c['State']['Running'] and c['HostConfig']['RestartPolicy']['Name']=='no'
report['existing_healthy_containers_not_restarted']=True
m=json.loads((B/'vps4-source-manifest.json').read_text());report['source_files']=len(m)
report['source_hashes_verified']=all(hashlib.sha256((root/p).read_bytes()).hexdigest()==h for root in [R,pathlib.Path('/opt/crowdbastion/releases/review-20261030-vps4')] for p,h in m.items());assert report['source_hashes_verified']
protected=json.loads((B/'protected-hashes.json').read_text());changed=[p for p,h in protected.items() if not pathlib.Path(p).exists() or hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()!=h]
report['protected_changed_paths']=changed;assert changed==['/etc/sysctl.d/99-network-optimize.conf'],changed
report['core_and_existing_bouncer_config_bytes_preserved']=True
cron=out(['crontab','-l']);assert not any(l.startswith('@reboot') and 'iptables-restore' in l for l in cron.splitlines())
assert [l for l in cron.splitlines() if not l.startswith('# crowdbastion-review')]==[l for l in (B/'crontab.before').read_text().splitlines() if not l.startswith('@reboot iptables-restore')]
report['obsolete_restore_disabled_and_other_jobs_preserved']=True
with tarfile.open(B/'before.tar.gz') as archive:
 report['saved_rules_unchanged']=all(archive.extractfile('etc/iptables/'+n).read()==(pathlib.Path('/etc/iptables')/n).read_bytes() for n in ['rules.v4','rules.v6']);assert report['saved_rules_unchanged']
report['sysctl_value']=out(['sysctl','-n','net.core.netdev_budget_usecs']).strip();assert report['sysctl_value']=='8000'
config=yaml.safe_load(pathlib.Path('/home/docker/gost/docker-compose.yml').read_text())
assert config['services']['gost-http']['profiles']==['disabled-port-conflict'] and config['services']['gost-http']['restart']=='no'
report['conflicting_proxy_persistently_disabled']=True
report['startup_after_docker']='docker.service' in out(['systemctl','show','crowdsec-firewall-bouncer','-p','After','--value']);assert report['startup_after_docker']
report['flow_before_reproduced']=json.loads((B/'flow-before.json').read_text())['passed'];report['flow_after_passed']=json.loads((B/'flow-after.json').read_text())['passed'];assert report['flow_before_reproduced'] and report['flow_after_passed']
report['cleanup']={
 'namespaces':'cbv4' not in out(['ip','netns','list']),
 'interfaces':'cbv4' not in out(['ip','-o','link']),
 'rules':all('cbv4' not in out([cmd]) for cmd in ['iptables-save','ip6tables-save','nft','list','ruleset'][:2]),
 'snapshot_table':'cbv4_migration' not in out(['nft','list','ruleset']),
 'listeners':':18080' not in out(['ss','-H','-lntup']),
 'timers':'cb-vps4' not in out(['systemctl','list-timers','--no-pager']),
 'decisions':not any(d.get('scenario','').startswith('cbv4-cycle-20261030') for d in migrate.live()),
}
assert all(report['cleanup'].values()),report['cleanup']
for label,flag in [('health','--status'),('node','--diagnose-v2bx')]:
 r=run(['bash',str(R/'crowdbastion.sh'),flag]);(B/(label+'-final.txt')).write_text(r.stdout+r.stderr);report[label+'_exit']=r.returncode;assert r.returncode==2
report['website']={}
for label,args in [('origin',['-k','--resolve','down-us1.354555.xyz:443:127.0.0.1']),('public',[])]:
 r=run(['curl','-sS','--max-time','20','-o','/dev/null','-w','%{http_code}',*args,'https://down-us1.354555.xyz/']);report['website'][label]={'exit':r.returncode,'status':r.stdout};assert r.returncode==0 and r.stdout=='200'
(B/'verification-final.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))

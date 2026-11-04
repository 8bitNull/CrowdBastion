ROLLBACK_HELPER='/var/backups/crowdbastion/vps167-optimize-review-20261102T044320Z/rollback-manager-v2.py'
import hashlib,json,os,re,runpy,stat,subprocess,time
from pathlib import Path
backup=Path('/var/backups/crowdbastion/vps167-optimize-20261102T034616Z')
rollback=runpy.run_path(str(backup/'rollback-manager.py'),run_name='vps167_rollback_module');stage=rollback['load_stage']();release=Path(stage['release'])
from crowdbastion_ux import code_fingerprint
from crowdbastion_health import parse_acquisition_metrics,acquisition_state
from crowdsec_maintenance import fingerprint
from crowdsec_config import merged_config
import crowdsec_web

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def run(argv,timeout=25):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
 return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}

def snapshot(paths):
 result={}
 for name in paths:
  p=Path(name);entries=[p,*sorted(p.rglob('*'))] if p.is_dir() and not p.is_symlink() else [p]
  for q in entries:
   if not q.exists() and not q.is_symlink():result[str(q)]={'exists':False};continue
   s=q.lstat();row={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
   if q.is_symlink():row['link']=os.readlink(q)
   elif q.is_file():row['sha256']=sha(q)
   else:assert q.is_dir(),str(q);row['directory']=True
   result[str(q)]=row
 return result
r={'checked_at':time.time(),'protected_items_unchanged':snapshot(stage['protected_paths'])==json.loads((backup/'protected-before.json').read_text()),'protected_items':stage['protected_items'],'original_source_preserved':fingerprint(backup/'source-directory.before')==stage['original_source_fingerprint'],'source_fingerprints':{str(p):code_fingerprint(p) for p in [Path(stage['root'])/'crowdbastion.sh',Path(stage['maintenance'])/'manager.sh',release/'crowdbastion.sh']},'complete_package_matches':{str(base):all(sha(base/name)==digest for name,digest in stage['package_hashes'].items()) for base in [Path(stage['root']),Path(stage['maintenance']),release]},'current_pointer':os.readlink(Path(stage['runtime'])/'current'),'entry_sha256_matches':sha(stage['entry'])==stage['entry_after_sha256'],'hub_cron_sha256_matches':sha(stage['cron'])==stage['cron_after_sha256'],'root_crontab_unchanged':sha('/var/spool/cron/crontabs/root')==stage['root_crontab_metadata']['sha256'],'services':{}}
for u in ['crowdsec','crowdsec-firewall-bouncer','docker','cron']:
 x=run(['systemctl','show',u,'--property=MainPID,ActiveState,UnitFileState,NRestarts,ExecMainStartTimestamp']);r['services'][u]=dict(line.split('=',1) for line in x['stdout'].splitlines() if '=' in line)
r['original_service_identities_unchanged']=all(r['services'][u]==v for u,v in stage['services_before'].items())
r['rules_unchanged']={b:run([b,'-w','5','-S'])['stdout']==s for b,s in stage['rules_before'].items()}
r['firewall_check']=run(['/usr/local/bin/crowdbastion','--firewall-check'])
m=re.search(r'适用网络 (\d+)，实际集合网络 (\d+)，遗漏 (\d+)',r['firewall_check']['stdout']);assert m
r['decision_membership']=dict(zip(['expected','kernel','missing'],map(int,m.groups())))
r['health']=run(['/usr/local/bin/crowdbastion','--status-json'],55)
r['health_document']=json.loads(r['health']['stdout'])
r['core_config_test']=run(['crowdsec','-t']);r['lapi_status']=run(['cscli','lapi','status']);r['failed_units']=run(['systemctl','--failed','--no-legend','--plain','--no-pager'])
cfg=merged_config(Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml'))
r['backend']={key:cfg.get(key) for key in ['mode','iptables_chains','disable_ipv6','update_frequency','supported_decisions_types','origins','scopes','scenarios_containing','scenarios_not_containing']}
ids=run(['docker','ps','-aq'])['stdout'].split();items=json.loads(run(['docker','inspect',*ids])['stdout'])
r['containers']={x['Id']:{'name':x['Name'],'image':x['Image'],'started':x['State']['StartedAt'],'pid':x['State']['Pid'],'health':x['State'].get('Health',{}).get('Status'),'network':x['HostConfig']['NetworkMode']} for x in items}
r['containers_unchanged']=r['containers']==stage['containers_before']
r['web_hooks']={};statepath=Path('/etc/crowdsec/crowdsec-1key-web-installs.json')
for name,entry in json.loads(statepath.read_text()).items():
 ng=run(['docker','exec',name,'nginx','-T']);mounts=json.loads(run(['docker','inspect',name])['stdout'])[0]['Mounts'];words=[tokens for _,tokens,_ in crowdsec_web.directives(Path(entry['host_target']).read_text())];phases={}
 for phase,directive in crowdsec_web.PHASES.items():
  actual=[v for v in words if v and v[0]==directive];content=(Path(entry['host_assets'])/(phase+'.lua')).read_text()
  phases[phase]={'directive_matches':actual==[[directive,entry['container_assets']+'/'+phase+'.lua']],'call_present':('crowdsec_1key.execution' if phase=='log' else 'crowdsec_1key.crowdsec') in content}
 crowdsec_web.check_install(statepath,name,mounts)
 r['web_hooks'][name]={'nginx_exit':ng['exit'],'target_loaded':'# configuration file '+entry['container_target']+':' in ng['stdout'],'resource_hashes_and_mounts':'ok','phases':phases}
r['origin_http_checks']={d:run(['curl','--silent','--show-error','--max-time','6','--noproxy','*','--insecure','--resolve',d+':443:127.0.0.1','--output','/dev/null','--write-out','%{http_code}','https://'+d+'/'],8) for d in ['origin-02.example.com','origin-04.example.com','site-18.example.com']}
metrics=run(['cscli','metrics','show','acquisition','-o','json']);assert metrics['exit']==0;sources=parse_acquisition_metrics(metrics['stdout'])
r['acquisition']={'state':acquisition_state(sources),'sources':sources}
probe=run(['python3','-B',ROLLBACK_HELPER,'--check']);assert probe['exit']==0
r['rollback_check']={'helper':ROLLBACK_HELPER,'result':json.loads(probe['stdout'])}
r['optional_components_absent']={p:not Path(p).exists() for p in ['/etc/crowdsec/crowdbastion-notify.json','/etc/crowdsec/crowdsec-1key-bot.json','/usr/local/lib/crowdsec-v2bx-observer/config.json']}
r['finished_at']=time.time()
assert r['protected_items_unchanged'] and r['original_source_preserved'] and r['containers_unchanged'] and r['original_service_identities_unchanged']
assert all(r['rules_unchanged'].values()) and all(r['complete_package_matches'].values()) and all(r['optional_components_absent'].values())
assert r['firewall_check']['exit']==0 and r['decision_membership']['missing']==0
assert r['health']['exit']==2 and r['health_document']['checks']['traffic']=='pending' and all(v=='ok' for k,v in r['health_document']['checks'].items() if k!='traffic')
assert r['core_config_test']['exit']==0 and r['lapi_status']['exit']==0 and not r['failed_units']['stdout'].strip()
assert all(v['exit']==0 and v['stdout']=='200' for v in r['origin_http_checks'].values()) and r['services']['cron']['ActiveState']=='active'
print(json.dumps(r,ensure_ascii=False,indent=2))

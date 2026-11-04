BACKUP='/var/backups/crowdbastion/vps45-repair-20261102T024205Z'
import hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
backup=Path(BACKUP);stage=json.loads((backup/'stage.json').read_text());release=Path(stage['release']);sys.path.insert(0,str(release/'lib'))
from crowdbastion_ux import code_fingerprint
from crowdsec_config import merged_config
import crowdsec_web

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(argv,timeout=30):
 p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
 return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
def snapshot(paths):
 result={}
 for name in paths:
  p=Path(name)
  for q in [p,*sorted(p.rglob('*'))] if p.is_dir() and not p.is_symlink() else [p]:
   if q.is_symlink():result[str(q)]={'link':os.readlink(q)}
   elif q.is_file():result[str(q)]={'sha256':sha(q),'mode':q.stat().st_mode&0o777,'uid':q.stat().st_uid}
 return result
r={'checked_at':time.time(),'protected_files_unchanged':snapshot(stage['protected_paths'])==json.loads((backup/'protected-before.json').read_text()),'protected_files':len(snapshot(stage['protected_paths'])),'source_fingerprints':{str(p):code_fingerprint(p) for p in [release/'crowdbastion.sh',Path(stage['root'])/'crowdbastion.sh',Path('/usr/local/lib/crowdsec-1key/current/manager.sh')]},'current_pointer':os.readlink('/usr/local/lib/crowdsec-1key/current'),'root_crontab':run(['crontab','-u','root','-l']),'services':{}}
for unit in ['crowdsec','crowdsec-firewall-bouncer','docker','crowdbastion-vps45-static','1panel-agent']:
 x=run(['systemctl','show',unit,'--property=MainPID,ActiveState,UnitFileState,NRestarts,ExecMainStartTimestamp']);r['services'][unit]=dict(s.split('=',1) for s in x['stdout'].splitlines() if '=' in s)
r['firewall_rules']={b:run([b,'-w','5','-S']) for b in ['iptables','ip6tables']}
r['firewall_check']=run(['/usr/local/bin/crowdbastion','--firewall-check'])
r['health']=run(['/usr/local/bin/crowdbastion','--status-json'],55)
config=merged_config(Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml'))
r['backend']={k:config.get(k) for k in ['mode','iptables_chains','iptables_v4_chains','iptables_v6_chains','disable_ipv4','disable_ipv6','update_frequency','supported_decisions_types','origins','scopes','scenarios_containing','scenarios_not_containing']}
r['containers']=[]
ids=subprocess.run(['docker','ps','-q'],capture_output=True,text=True,check=True).stdout.split()
for x in json.loads(subprocess.run(['docker','inspect',*ids],capture_output=True,text=True,check=True).stdout):
 r['containers'].append({'name':x['Name'],'id':x['Id'],'image':x['Image'],'started':x['State']['StartedAt'],'pid':x['State']['Pid'],'health':x['State'].get('Health',{}).get('Status'),'network':x['HostConfig']['NetworkMode']})
r['web_hooks']={}
statepath=Path('/etc/crowdsec/crowdsec-1key-web-installs.json');state=json.loads(statepath.read_text())
for name,entry in state.items():
 ng=run(['docker','exec',name,'nginx','-T']);mounts=json.loads(subprocess.run(['docker','inspect',name],capture_output=True,text=True,check=True).stdout)[0]['Mounts'];words=[tokens for _,tokens,_ in crowdsec_web.directives(Path(entry['host_target']).read_text())];phases={}
 for phase,directive in crowdsec_web.PHASES.items():
  actual=[v for v in words if v and v[0]==directive];content=(Path(entry['host_assets'])/(phase+'.lua')).read_text()
  phases[phase]={'parsed_directive_matches':actual==[[directive,entry['container_assets']+'/'+phase+'.lua']],'crowdsec_call_present':('crowdsec_1key.execution' if phase=='log' else 'crowdsec_1key.crowdsec') in content}
 crowdsec_web.check_install(statepath,name,mounts)
 r['web_hooks'][name]={'nginx_exit':ng['exit'],'target_loaded':'# configuration file '+entry['container_target']+':' in ng['stdout'],'resource_hashes_and_mounts':'ok','phases':phases}
r['origin_http_checks']={domain:run(['curl','--silent','--show-error','--max-time','6','--noproxy','*','--insecure','--resolve',domain+':443:127.0.0.1','--output','/dev/null','--write-out','%{http_code}','https://'+domain+'/'],8) for domain in ['site-04.example.com','site-14.example.com','site-17.example.com']}
r['core_config_test']=run(['crowdsec','-t'])
r['lapi_status']=run(['cscli','lapi','status'])
r['unit_order']=run(['systemctl','show','crowdbastion-vps45-static','--property=After,Before'])
r['optional_components_absent']={p:not Path(p).exists() for p in ['/etc/crowdsec/crowdbastion-notify.json','/etc/crowdsec/crowdsec-1key-bot.json','/usr/local/lib/crowdsec-v2bx-observer/config.json']}
r['finished_at']=time.time();print(json.dumps(r,ensure_ascii=False))

import hashlib,json,os,re,shlex,stat,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_web

def run(argv,timeout=20):
 try:
  p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'))
  return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
 except (OSError,subprocess.TimeoutExpired) as e:return {'error':type(e).__name__}
def meta(path):
 p=Path(path)
 if not p.is_file():return {'exists':False}
 s=p.stat();return {'exists':True,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'uid':s.st_uid,'mode':oct(stat.S_IMODE(s.st_mode)),'size':s.st_size}
def source(root):
 root=Path(root)
 if not root.is_dir():return {}
 files=[p for p in root.iterdir() if p.is_file() and p.name in ['crowdbastion.sh','manager.sh','install-crowdsec-1panel.sh']]
 if (root/'lib').is_dir():files += [p for p in (root/'lib').iterdir() if p.is_file() and p.suffix in ['.py','.sh','.lua']]
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
r={'checked_at':time.time(),'web_hooks':{}}
statepath=Path('/etc/crowdsec/crowdsec-1key-web-installs.json');state=json.loads(statepath.read_text())
for name,entry in state.items():
 result=run(['docker','exec',name,'nginx','-T']);mounts=json.loads(run(['docker','inspect',name])['stdout'])[0]['Mounts']
 words=[tokens for _,tokens,_ in crowdsec_web.directives(Path(entry['host_target']).read_text())];phases={}
 for phase,directive in crowdsec_web.PHASES.items():
  expected=[directive,entry['container_assets']+'/'+phase+'.lua'];actual=[v for v in words if v and v[0]==directive];content=(Path(entry['host_assets'])/(phase+'.lua')).read_text()
  phases[phase]={'parsed_directive_matches':actual==[expected],'crowdsec_call_present':('crowdsec_1key.execution' if phase=='log' else 'crowdsec_1key.crowdsec') in content}
 try:crowdsec_web.check_install(statepath,name,mounts);resources='ok'
 except Exception as e:resources=type(e).__name__
 errors=[tokens for _,tokens,_ in crowdsec_web.directives(result.get('stdout','')) if tokens and tokens[0]=='error_log']
 r['web_hooks'][name]={'nginx_T_exit':result.get('exit'),'target_in_effective_configuration':'# configuration file '+entry['container_target']+':' in result.get('stdout',''),'phases':phases,'resource_hashes_and_mounts':resources,'error_log_directives':errors,'standard_reload_log_notice':any(t[1:]==['/var/log/nginx/crowdbastion_reload_error.log','notice'] for t in errors)}
r['source_hashes']={root:source(root) for root in ['/root/crowdsec-1key','/opt/crowdbastion/releases/review-20261030','/usr/local/lib/crowdsec-1key/current']}
r['restore_crons']=[];r['cron_entries']=[]
for p in [Path('/etc/crontab'),Path('/etc/rc.local'),*Path('/etc/cron.d').glob('*'),*Path('/var/spool/cron').rglob('*')]:
 if not p.is_file():continue
 for number,line in enumerate(p.read_text(errors='replace').splitlines(),1):
  disabled=line.lstrip().startswith('#');text=line.lstrip('# ').strip();tokens=text.split()
  if re.search(r'crowdsec|crowdbastion|(?:ip6tables|iptables)-restore',line,re.I):
   row={'path':str(p),'line':number,'disabled':disabled,'sha256':hashlib.sha256(line.encode()).hexdigest(),'options':re.findall(r'--[a-z][a-z-]+',text),'schedule':tokens[:1] if tokens and tokens[0].startswith('@') else tokens[:5] if len(tokens)>=5 and all(re.fullmatch(r'[0-9*/,-]+',x) for x in tokens[:5]) else [],'commands':re.findall(r'\b(?:cscli|systemctl|iptables-restore|ip6tables-restore)\b',text),'script_paths':re.findall(r'/[A-Za-z0-9_./-]+\.sh',text)}
   r['cron_entries'].append(row)
   if not disabled and re.search(r'\b(?:ip6tables|iptables)-restore\b|\bnft\s+(?:-f|--file)\b',text):r['restore_crons'].append(row)
r['saved_rule_files']={}
for name in ['/etc/iptables/rules.v4','/etc/iptables/rules.v6']:
 p=Path(name)
 if not p.is_file():continue
 text=p.read_text();r['saved_rule_files'][name]={'metadata':meta(p),'lines':len(text.splitlines()),'crowdsec_lines':sum('crowdsec' in x.lower() for x in text.splitlines()),'docker_lines':sum('docker' in x.lower() for x in text.splitlines())}
core=run(['crowdsec','-t','-c','/etc/crowdsec/config.yaml'],30);r['core_config_check']={'exit':core.get('exit'),'error':core.get('error'),'vpatch_hub_warning_ids':sorted(set(re.findall(r'vpatch-CVE-[\d-]+',core.get('stderr','')+core.get('stdout',''))))}
r['nginx_config_check']={k:v for k,v in run(['docker','exec','openresty','nginx','-t']).items() if k in ['exit','error']}
r['origin_http_checks']={domain:run(['curl','--silent','--show-error','--max-time','6','--noproxy','*','--insecure','--resolve',domain+':443:127.0.0.1','--output','/dev/null','--write-out','%{http_code}','https://'+domain+'/'],8) for domain in ['origin-02.example.com','origin-04.example.com','site-18.example.com']}
r['bouncer_version']=run(['/usr/bin/crowdsec-firewall-bouncer','-version']);r['failed_units']=run(['systemctl','list-units','--failed','--no-legend','--plain','--no-pager']);r['timezone']=run(['timedatectl','show','--property=Timezone','--value'])
r['file_error_samples']={}
for name in ['/var/log/crowdsec.log','/var/log/crowdsec-firewall-bouncer.log']:
 p=Path(name)
 if not p.is_file():continue
 with p.open('rb') as f:f.seek(max(0,p.stat().st_size-524288));lines=f.read().decode(errors='replace').splitlines()
 r['file_error_samples'][name]={'scope':'last 512KiB, not full log or guaranteed 24h','sample_lines':len(lines),'error_or_fatal':sum(bool(re.search(r'level=(?:error|fatal)|\[(?:ERROR|FATAL)\]',x)) for x in lines),'warning_classes':{k:sum(bool(re.search(pattern,x,re.I)) for x in lines) for k,pattern in [('vpatch_hub_index',r'vpatch-CVE'),('authentication',r'unauthorized|authentication|permission denied'),('network',r'timeout|timed out'),('traceback',r'Traceback|ModuleNotFoundError')]}}
r['protected_files']={name:meta(name) for name in ['/etc/crowdsec/config.yaml','/etc/crowdsec/config.yaml.local','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/var/lib/crowdbastion/node-roles.json','/etc/crowdsec/crowdsec-1key-web-installs.json','/etc/cron.d/crowdsec-autoupdate','/var/spool/cron/crontabs/root']}
r['final_services']={}
for unit in ['crowdsec.service','crowdsec-firewall-bouncer.service','docker.service']:
 value=run(['systemctl','show',unit,'--no-pager','--property=MainPID,NRestarts,ActiveState,ExecMainStartTimestamp,UnitFileState']);r['final_services'][unit]=dict(x.split('=',1) for x in value['stdout'].splitlines() if '=' in x)
r['finished_at']=time.time();print(json.dumps(r,ensure_ascii=False,indent=2))

import contextlib,hashlib,importlib.util,io,json,os,re,shlex,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_config,crowdsec_web

def run(argv,timeout=15):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'))
        return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error':type(e).__name__}
def meta(path):
    p=Path(path)
    if not p.is_file():return {'exists':False}
    st=p.stat();return {'exists':True,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':st.st_size,'uid':st.st_uid,'mode':oct(st.st_mode&0o7777)}
def registry():
    result=run(['cscli','bouncers','list','-o','json'])
    return [{'name':v.get('name'),'last_pull':v.get('last_pull'),'type':v.get('type'),'version':v.get('version')} for v in json.loads(result['stdout'])]
report={'checked_at':time.time(),'registry_before':registry()}
report['restore_crons']=[]
for p in [Path('/etc/crontab'),Path('/etc/rc.local'),*Path('/etc/cron.d').glob('*'),*Path('/var/spool/cron').rglob('*')]:
    if not p.is_file():continue
    for number,line in enumerate(p.read_text(errors='replace').splitlines(),1):
        if not line.lstrip().startswith('#') and re.search(r'\b(?:ip6tables|iptables)-restore\b|\bnft\s+(?:-f|--file)\b',line):
            report['restore_crons'].append({'path':str(p),'line':number,'line_sha256':hashlib.sha256(line.encode()).hexdigest(),'schedule':line.split()[:1] if line.lstrip().startswith('@') else line.split()[:5],'delay_seconds':re.findall(r'\bsleep\s+(\d+)',line),'commands':re.findall(r'\b(?:ip6tables|iptables)-restore\b',line),'absolute_paths':re.findall(r'(?<!\w)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+',line)})
report['saved_rule_files']={}
for row in report['restore_crons']:
    for path in row['absolute_paths']:
        if Path(path).is_file() and path not in report['saved_rule_files']:
            text=Path(path).read_text(errors='replace')
            report['saved_rule_files'][path]={'metadata':meta(path),'lines':len(text.splitlines()),'crowdsec_lines':sum('crowdsec' in s.lower() for s in text.splitlines()),'docker_lines':sum('docker' in s.lower() for s in text.splitlines()),'tables':re.findall(r'^\*(\w+)$',text,re.M),'policies':re.findall(r'^:(INPUT|FORWARD|OUTPUT) (ACCEPT|DROP)',text,re.M)}
base=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml');config=crowdsec_config.merged_config(base)
report['filter_rules']={};references={};paths={}
for binary,family in [('iptables',4),('ip6tables',6)]:
    result=run([binary,'-w','5','-S']);lines=[shlex.split(s) for s in result['stdout'].splitlines()]
    report['filter_rules'][str(family)]=result
    chain=config.get('iptables_chain','CROWDSEC_CHAIN')
    first={entry:next((t for t in lines if t[:2]==['-A',entry]),None) for entry in ['INPUT','FORWARD','DOCKER-USER']}
    direct={entry:t==['-A',entry,'-j',chain] for entry,t in first.items()}
    indirect=first['FORWARD']==['-A','FORWARD','-j','DOCKER-USER'] and direct['DOCKER-USER']
    drop_rules=[]
    for tokens in lines:
        if tokens[:2]!=['-A',chain]:continue
        norm=[];i=0
        while i<len(tokens):
            if tokens[i:i+3]==['-m','comment','--comment']:i+=4
            else:norm.append(tokens[i]);i+=1
        drop_rules.append(norm)
    names=config.get('blacklists_ipv4' if family==4 else 'blacklists_ipv6','crowdsec-blacklists' if family==4 else 'crowdsec6-blacklists')
    names=[names] if isinstance(names,str) else names
    drops_valid=bool(drop_rules) and all(len(t)==9 and t[2:5]==['-m','set','--match-set'] and t[6:]==['src','-j','DROP'] and any(re.fullmatch(re.escape(n)+r'(?:-\d+)?',t[5]) for n in names) for t in drop_rules)
    references[family]={t[5] for t in drop_rules} if drops_valid else set()
    paths[str(family)]={'first_rules':first,'direct_first':direct,'forward_unconditional_via_docker_user':indirect,'all_crowdsec_rules_unconditional_source_drop':drops_valid,'sets':sorted(references[family]),'all_required_paths_reach_crowdsec_before_other_rules':direct['INPUT'] and direct['DOCKER-USER'] and (direct['FORWARD'] or indirect) and drops_valid}
report['static_path_analysis']=paths
# Load the reviewed read-only decision helper into memory, without installing it.
import types
m=types.ModuleType('vps45_readonly_membership');m.__file__='<stdin-readonly-membership>'
exec(compile(EVIDENCE_SOURCE,m.__file__,'exec'),m.__dict__)
if all(v['all_required_paths_reach_crowdsec_before_other_rules'] for v in paths.values()):
    rows=m.live(base);expected=m.networks(rows)
    report['decision_membership_independent']=m.membership(expected,references,run(['ipset','save'])['stdout'])
else:report['decision_membership_independent']={'state':'unconfirmed_paths'}
report['bouncer_binary_version']=run(['/usr/bin/crowdsec-firewall-bouncer','-version'])
report['core_configuration_check']={k:v for k,v in run(['crowdsec','-t','-c','/etc/crowdsec/config.yaml'],timeout=25).items() if k in ['exit','error']}
report['nginx_configuration_check']=run(['docker','exec','openresty','nginx','-t'])
report['acquisition_configs']={}
import yaml
for p in [Path('/etc/crowdsec/acquis.yaml'),*sorted(Path('/etc/crowdsec/acquis.d').glob('*.yaml'))]:
    if p.is_file():
        report['acquisition_configs'][str(p)]=[{'source':v.get('source'),'filenames':v.get('filenames'),'labels':{k:v.get('labels',{}).get(k) for k in ['type','service'] if k in v.get('labels',{})}} for v in yaml.safe_load_all(p.read_text()) if isinstance(v,dict)]
report['unparsed_log_classes']={}
for path in ['/var/log/kern.log','/var/log/syslog','/opt/1panel/apps/openresty/openresty/log/error.log']:
    p=Path(path)
    if not p.is_file():continue
    with p.open('rb') as f:
        f.seek(max(0,p.stat().st_size-65536));lines=f.read().decode(errors='replace').splitlines()[-100:]
    report['unparsed_log_classes'][path]={'sample_lines':len(lines),'levels':{k:sum(bool(re.search(r'\['+k+r'\]',s)) for s in lines) for k in ['emerg','alert','crit','error','warn','notice','info']},'classes':{k:sum(bool(re.search(pattern,s,re.I)) for s in lines) for k,pattern in [('ufw',r'\[UFW '),('kernel_routine',r'kernel:'),('systemd',r'systemd\['),('crowdsec_bouncer',r'crowdsec|bouncer'),('template',r'template.*(?:not found|missing|No such file)|No such file.*template'),('recaptcha',r'recaptcha'),('reload_evidence',r'CB_EXEC_V1'),('upstream',r'upstream.*(?:timed out|refused|no live)'),('traceback',r'Traceback')]} }
report['container_health']={}
for row in json.loads(run(['docker','inspect',*run(['docker','ps','-q'])['stdout'].split()])['stdout']):
    state=row['State'];health=state.get('Health',{})
    report['container_health'][row['Name'].lstrip('/') ]={'status':state.get('Status'),'health':health.get('Status'),'failing_streak':health.get('FailingStreak'),'started_at':state.get('StartedAt'),'restart_count':row.get('RestartCount')}
report['core_log_file_errors_24h']={}
for p in [Path('/var/log/crowdsec.log'),Path('/var/log/crowdsec-firewall-bouncer.log')]:
    if p.is_file():
        with p.open('rb') as f:
            f.seek(max(0,p.stat().st_size-256*1024));text=f.read().decode(errors='replace')
        lines=text.splitlines();report['core_log_file_errors_24h'][str(p)]={'scope':'last_256KiB_not_guaranteed_24h','sample_lines':len(lines),'error_or_fatal_lines':sum(bool(re.search(r'level=(?:error|fatal)|\[(?:ERROR|FATAL)\]',s)) for s in lines)}
report['final_services']={}
for unit in ['crowdsec','crowdsec-firewall-bouncer','docker']:
    r=run(['systemctl','show',unit,'--no-pager','--property=MainPID,NRestarts,ActiveState,ExecMainStartTimestamp,UnitFileState'])
    report['final_services'][unit]=dict(s.split('=',1) for s in r['stdout'].splitlines() if '=' in s)
# Listing registry records does not refresh the clients' last_pull timestamps.
start=time.monotonic()
while True:
    after=registry();before={r['name']:r.get('last_pull') for r in report['registry_before']}
    firewall=[r for r in after if r.get('type')=='crowdsec-firewall-bouncer']
    if firewall and any(r.get('last_pull')!=before.get(r['name']) for r in firewall):break
    if time.monotonic()-start>=15:break
    time.sleep(2)
report['registry_after']=after;report['registry_observation_seconds']=round(time.monotonic()-start,3)
report['finished_at']=time.time()
print(json.dumps(report,ensure_ascii=False,indent=2))

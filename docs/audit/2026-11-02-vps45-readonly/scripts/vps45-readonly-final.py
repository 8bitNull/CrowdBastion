import hashlib,json,os,re,subprocess,time
from pathlib import Path

def run(argv,timeout=15):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'))
        return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error':type(e).__name__}
def meta(p):
    p=Path(p)
    if not p.is_file():return {'exists':False}
    s=p.stat();return {'exists':True,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'uid':s.st_uid,'mode':oct(s.st_mode&0o7777),'size':s.st_size}
r={'checked_at':time.time(),'uid':os.geteuid(),'protected_files':{p:meta(p) for p in ['/etc/crowdsec/config.yaml','/etc/crowdsec/config.yaml.local','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/var/lib/crowdbastion/node-roles.json','/etc/crowdsec/crowdsec-1key-web-installs.json','/etc/cron.d/crowdsec-autoupdate','/var/spool/cron/crontabs/root']}}
ng=run(['docker','exec','openresty','nginx','-T'])
r['nginx_error_log_directives']=[line.strip() for line in ng.get('stdout','').splitlines() if re.match(r'\s*error_log\s+[^;]+;',line)]
r['web_hook_targets']={}
state=json.loads(Path('/etc/crowdsec/crowdsec-1key-web-installs.json').read_text())
for name,entry in state.items():
    phase={}
    target=Path(entry['host_target']).read_text()
    for key in ['init','access','log']:
        asset=Path(entry['host_assets'])/(key+'.lua')
        content=asset.read_text() if asset.is_file() else ''
        phase[key]={'hook_directive_present':key+'_by_lua_file '+entry['container_assets']+'/'+key+'.lua;' in target,'module_require_present':'crowdsec_1key.crowdsec' in content,'file':meta(asset)}
    r['web_hook_targets'][name]={'phases':phase,'bouncer_configuration':meta(Path(entry['host_assets'])/'bouncer.conf')}
r['origin_http_checks']={}
for domain in ['site-04.example.com','site-14.example.com','site-17.example.com']:
    r['origin_http_checks'][domain]=run(['curl','--silent','--show-error','--max-time','6','--noproxy','*','--insecure','--resolve',domain+':443:127.0.0.1','--output','/dev/null','--write-out','%{http_code}', 'https://'+domain+'/'],timeout=8)
r['timezone']=run(['timedatectl','show','--property=Timezone','--value'])
p=Path('/etc/cron.d/crowdsec-autoupdate')
r['scheduled_maintenance']=[{'schedule':s.split()[:5],'options':re.findall(r'--[a-z][a-z-]+',s),'file':str(p)} for s in p.read_text().splitlines() if s.strip() and not s.lstrip().startswith('#') and 'crowdsec-1key' in s]
r['rules_sources']={}
for root in ['/root/crowdsec-1key','/usr/local/lib/crowdsec-1key/current']:
    r['rules_sources'][root]={str(p.relative_to(root)):meta(p) for p in sorted((Path(root)/'rules').rglob('*')) if p.is_file()}
r['final_services']={}
for unit in ['crowdsec','crowdsec-firewall-bouncer','docker']:
    result=run(['systemctl','show',unit,'--no-pager','--property=MainPID,NRestarts,ActiveState,ExecMainStartTimestamp,UnitFileState'])
    r['final_services'][unit]=dict(s.split('=',1) for s in result['stdout'].splitlines() if '=' in s)
r['finished_at']=time.time()
print(json.dumps(r,ensure_ascii=False,indent=2))

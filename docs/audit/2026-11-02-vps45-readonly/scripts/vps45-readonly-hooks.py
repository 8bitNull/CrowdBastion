import hashlib,json,os,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_web
statepath=Path('/etc/crowdsec/crowdsec-1key-web-installs.json')
state=json.loads(statepath.read_text());report={'checked_at':time.time(),'web_hooks':{}}
for name,entry in state.items():
    result=subprocess.run(['docker','exec',name,'nginx','-T'],capture_output=True,text=True,timeout=15)
    mounts=json.loads(subprocess.run(['docker','inspect',name],capture_output=True,text=True,check=True).stdout)[0]['Mounts']
    target=Path(entry['host_target']).read_text();words=[tokens for _,tokens,_ in crowdsec_web.directives(target)]
    phases={}
    for phase,directive in crowdsec_web.PHASES.items():
        expected=[directive,entry['container_assets']+'/'+phase+'.lua']
        actual=[v for v in words if v and v[0]==directive]
        content=(Path(entry['host_assets'])/(phase+'.lua')).read_text()
        phases[phase]={'parsed_directive_matches':actual==[expected],'directives':actual,'crowdsec_call_present':('crowdsec_1key.execution' if phase=='log' else 'crowdsec_1key.crowdsec') in content}
    try:
        crowdsec_web.check_install(statepath,name,mounts);resources='ok'
    except Exception as error:resources=type(error).__name__
    report['web_hooks'][name]={'nginx_T_exit':result.returncode,'target_in_effective_configuration':'# configuration file '+entry['container_target']+':' in result.stdout,'phases':phases,'resource_hashes_and_mounts':resources}
root=Path('/root/crowdsec-1key');current=Path('/usr/local/lib/crowdsec-1key/current')
def manifest(folder):
    files=[p for p in folder.iterdir() if p.is_file() and p.name in ['crowdbastion.sh','manager.sh','install-crowdsec-1panel.sh']]
    files += [p for p in (folder/'lib').iterdir() if p.is_file() and p.suffix in ['.py','.sh','.lua']]
    return {str(p.relative_to(folder)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
report['source_hashes']={str(p):manifest(p) for p in [root,current]}
report['cron_hashes']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path('/var/spool/cron/crontabs/root'),Path('/etc/cron.d/crowdsec-autoupdate')]}
report['finished_at']=time.time();print(json.dumps(report,ensure_ascii=False,indent=2))

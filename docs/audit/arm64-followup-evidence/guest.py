import json,subprocess,pathlib,os,time,hashlib

def run(argv,inputs=None,timeout=300):
    p=subprocess.run(argv,input=inputs,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    return p.returncode,p.stdout

def emit(case,rc,command_exit_code=None,**assertions):
    print('VPS_RESULT '+json.dumps(dict(case=case,exit_code=rc,command_exit_code=rc if command_exit_code is None else command_exit_code,assertions=assertions)),flush=True)

def command(*argv): return run(list(argv))[0]==0

def digest(paths):
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for root in paths for p in pathlib.Path(root).rglob('*') if p.is_file()}

import re

def scrub(value):
    text=str(value)
    secrets=[]
    try:
        import yaml
        def visit(node):
            if isinstance(node,dict):
                for k,v in node.items():
                    if any(word in str(k).lower() for word in ('password','api_key','token','secret')) and isinstance(v,str) and len(v)>=4:secrets.append(v)
                    visit(v)
            elif isinstance(node,list):
                for v in node:visit(v)
        for p in pathlib.Path('/etc/crowdsec').rglob('*.yaml*'):
            if p.is_file() and p.stat().st_size<1000000:
                try:visit(yaml.safe_load(p.read_text()))
                except Exception:pass
    except ImportError:pass
    for secret in sorted(secrets,key=len,reverse=True):text=text.replace(secret,'<redacted>')
    text=re.sub(r'(?i)(api[_ -]?key|password|token|secret)([\s:=]+)([^\s,\"\']+)',r'\1\2<redacted>',text)
    text=re.sub(r'[A-Za-z0-9_+/=-]{32,}','<opaque-redacted>',text)
    return text

def note(name,data):print('CORE_DIAG '+json.dumps({'case':name,'data':scrub(data)}),flush=True)

def diagnose():
    for unit in ['crowdsec','crowdsec-firewall-bouncer']:
        rc,out=run(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','Result','-p','ExecMainCode','-p','ExecMainStatus','-p','FragmentPath'])
        note(unit+'_state',out)
        rc,out=run(['journalctl','-u',unit,'-n','60','--no-pager','-o','cat'],timeout=30)
        note(unit+'_journal',out)
    rc,out=run(['dpkg-query','-W','-f=${Package} ${Version} ${Status}\n','crowdsec','crowdsec-firewall-bouncer-nftables'])
    note('packages',out)
    for name in ['/var/log/crowdsec-firewall-bouncer.log','/var/log/crowdsec.log']:
        p=pathlib.Path(name)
        if p.is_file():note(name,'\n'.join(p.read_text(errors='replace').splitlines()[-60:]))
    p=pathlib.Path('/var/lib/dpkg/info/crowdsec-firewall-bouncer-nftables.postinst')
    if p.exists():note('official_bouncer_postinst',p.read_text())
    paths=['/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/systemd/system/crowdsec-firewall-bouncer.service']
    note('artifact_presence',{name:pathlib.Path(name).exists() for name in paths})


os.chdir('/opt/test/repo')
env=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
print('VPS_ENV '+json.dumps(dict(actual_distro=env.get('PRETTY_NAME','').strip('"'),os_id=env.get('ID','').strip('"'),version=env.get('VERSION_ID','').strip('"'),architecture=os.uname().machine,kernel=os.uname().release,pid1=pathlib.Path('/proc/1/comm').read_text().strip(),installer_sha256=hashlib.sha256(pathlib.Path('install-crowdsec-1panel.sh').read_bytes()).hexdigest(),ram_kib=int(pathlib.Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]))),flush=True)
rc,out=run(['apt-get','update'],timeout=600);emit('guest_dependencies_index',rc,ready=rc==0)
rc,out=run(['apt-get','install','-y','python3-yaml','curl','ca-certificates'],timeout=600);emit('guest_dependencies',rc,packages_ready=rc==0)
print('VPS_NOTE packages '+out[-2500:].replace('\n',' | '),flush=True)
if rc: diagnose(); print('ARM_FOLLOWUP_ABORT',flush=True); command('systemctl','poweroff'); raise SystemExit(1)
# ARM uses official native CrowdSec package, no foreign architecture binaries.
rc,out=run(['bash','-c','curl -fLsS --max-time 120 https://install.crowdsec.net -o /tmp/install-core.sh && bash /tmp/install-core.sh'],timeout=600)
emit('core_repository_setup',rc,ready=rc==0)
print('VPS_NOTE repository '+out[-2000:].replace('\n',' | '),flush=True)
if rc: diagnose(); print('ARM_FOLLOWUP_ABORT',flush=True); command('systemctl','poweroff'); raise SystemExit(1)
rc,out=run(['apt-get','install','-y','crowdsec'],timeout=900)
emit('core_package_install',rc,installed=rc==0)
print('VPS_NOTE core package '+out[-2000:].replace('\n',' | '),flush=True)
if rc: diagnose(); print('ARM_FOLLOWUP_ABORT',flush=True); command('systemctl','poweroff'); raise SystemExit(1)
import yaml
core_config=pathlib.Path('/etc/crowdsec/config.yaml');core_data=yaml.safe_load(core_config.read_text());core_data['api']['server']['listen_uri']='0.0.0.0:8080';core_config.write_text(yaml.safe_dump(core_data))
command('systemctl','enable','--now','crowdsec');command('systemctl','restart','crowdsec')
key=''
for attempt in range(60):
    rc,key=run(['/usr/bin/cscli','-c','/etc/crowdsec/config.yaml','bouncers','add','vps-lab-'+str(attempt),'-o','raw'])
    if rc==0: key=key.strip(); break
    time.sleep(1)
if rc: emit('official_lapi',rc,ready=False); raise SystemExit(1)
pathlib.Path('/etc/crowdsec').mkdir(exist_ok=True)
pathlib.Path('/etc/crowdsec/core-preserve.txt').write_text('existing core must remain unchanged\n')
before=digest(['/etc/crowdsec'])
cli=['bash','install-crowdsec-1panel.sh']
url='http://127.0.0.1:8080/'
local=pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local')
rc,out=run(cli+['--install-relay-bouncer'],url+'\n'+key+'\n',600)
# Installer output can include pre-existing config diagnostics; avoid secrets in serial.
print('VPS_NOTE fresh_output '+out.replace(key,'<redacted>')[-1500:].replace('\n',' | '),flush=True)
emit('fresh_remote_install',rc,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'),local_exists=local.exists())
if rc: diagnose(); print('ARM_FOLLOWUP_ABORT',flush=True); command('systemctl','poweroff'); raise SystemExit(1)
readonly_before=digest(['/opt/core/etc','/etc/crowdsec'])
help_rc,_=run(cli+['--help'])
status_rc,_=run(cli+['--relay-bouncer-status'])
emit('help_and_readonly_status',0,command_exit_code=status_rc,help_ok=help_rc==0,status_ok=status_rc==0,unchanged=readonly_before==digest(['/opt/core/etc','/etc/crowdsec']))
rc,out=run(cli+['--install-relay-bouncer'],url+'\n'+key+'\n',600)
emit('repeat_remote_install',rc,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
rc,key2=run(['/usr/bin/cscli','-c','/etc/crowdsec/config.yaml','bouncers','add','vps-change','-o','raw']); key2=key2.strip()
rc,out=run(cli+['--configure-relay-bouncer'],'http://127.0.0.2:8080/\n'+key2+'\n')
emit('change_url_and_key',rc,changed=key2 in local.read_text() and '127.0.0.2' in local.read_text(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
cs=['/usr/bin/cscli','-c','/etc/crowdsec/config.yaml']
rc,out=run(cs+['decisions','add','--ip','198.51.100.77','--duration','10m'])
for attempt in range(40):
    nr,no=run(['nft','list','ruleset'],timeout=20); present=nr==0 and '198.51.100.77' in no
    if present: break
    time.sleep(1)
emit('actual_nft_decision_add',rc,present=present)
rc,out=run(cs+['decisions','delete','--ip','198.51.100.77'])
for attempt in range(40):
    nr,no=run(['nft','list','ruleset'],timeout=20); absent=nr==0 and '198.51.100.77' not in no
    if absent: break
    time.sleep(1)
emit('actual_nft_decision_delete',rc,absent=absent)
old=local.read_bytes(); rc,out=run(cli+['--configure-relay-bouncer'],url+'\ndefinitely-invalid-lab-key\n')
emit('bad_key_preserves_state',0,command_exit_code=rc,rejected=rc!=0,local_unchanged=old==local.read_bytes(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
state=pathlib.Path(str(local).replace('.local','.remote.json')); stateold=state.read_bytes(); state.unlink()
rc,out=run(cli+['--configure-relay-bouncer'],url+'\n'+key+'\n')
emit('foreign_local_ownership',0,command_exit_code=rc,rejected=rc!=0,local_unchanged=old==local.read_bytes(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
state.write_bytes(stateold)
# Reboot persistence runs phase2 after boot before removal.
pathlib.Path('/opt/test/phase2.json').write_text(json.dumps(dict(before=before)))
pathlib.Path('/etc/systemd/system/vps-phase2.service').write_text('[Unit]\nAfter=network-online.target crowdsec-firewall-bouncer.service\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /opt/test/phase2.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload'); command('systemctl','enable','vps-phase2')
command('systemctl','reboot'); time.sleep(300)

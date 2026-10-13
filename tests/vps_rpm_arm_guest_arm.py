import json,subprocess,pathlib,os,time,hashlib

from vps_guest_runtime import run_bounded, wait_ready, service_healthy, service_removed, Scrubber
SECRET_PATHS=[pathlib.Path(p) for p in ['/etc/crowdsec/config.yaml','/etc/crowdsec/local_api_credentials.yaml','/etc/crowdsec/online_api_credentials.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/opt/core/etc/config.yaml','/opt/core/etc/local_api_credentials.yaml']]
scrubber=Scrubber()
scrub_ready=False

def refresh_secrets():
    global scrubber,scrub_ready
    try:import yaml
    except ImportError:
        scrub_ready=False
        return
    fresh=Scrubber.from_configs(SECRET_PATHS)
    scrubber=Scrubber(scrubber.secrets+fresh.secrets)
    scrub_ready=True

refresh_secrets()

def run(argv,inputs=None,timeout=30):
    rc,out,_=run_bounded(argv,timeout=timeout,input_text=inputs)
    return rc,out

def note(name,text):
    print('VPS_NOTE '+name+' '+(scrubber.summary(text.replace('\n',' | '),limit=3500) if scrub_ready else '<diagnostic withheld until secret collector ready>'),flush=True)

def emit(case,rc,command_exit_code=None,**assertions):
    print('VPS_RESULT '+json.dumps(dict(case=case,exit_code=rc,command_exit_code=rc if command_exit_code is None else command_exit_code,assertions=assertions)),flush=True)

def command(*argv): return run(list(argv))[0]==0

def digest(paths):
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for root in paths for p in pathlib.Path(root).rglob('*') if p.is_file()}

os.chdir('/opt/test/repo')
env=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
print('VPS_ENV '+json.dumps(dict(actual_distro=env.get('PRETTY_NAME','').strip('"'),os_id=env.get('ID','').strip('"'),version=env.get('VERSION_ID','').strip('"'),architecture=os.uname().machine,kernel=os.uname().release,pid1=pathlib.Path('/proc/1/comm').read_text().strip(),installer_sha256=hashlib.sha256(pathlib.Path('install-crowdsec-1panel.sh').read_bytes()).hexdigest(),ram_kib=int(pathlib.Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]))),flush=True)
rc,out=run(['apt-get','update'],timeout=600);emit('guest_dependencies_index',rc,ready=rc==0)
rc,out=run(['apt-get','install','-y','python3-yaml','curl','ca-certificates'],timeout=600);emit('guest_dependencies',rc,packages_ready=rc==0)
refresh_secrets();note('packages',out)
if rc: command('systemctl','poweroff'); raise SystemExit(1)
# ARM uses official native CrowdSec package, no foreign architecture binaries.
rc,out=run(['bash','-c','curl -fLsS --max-time 120 https://install.crowdsec.net -o /tmp/install-core.sh && bash /tmp/install-core.sh'],timeout=600)
emit('core_repository_setup',rc,ready=rc==0)
note('repository',out)
if rc: command('systemctl','poweroff'); raise SystemExit(1)
rc,out=run(['apt-get','install','-y','crowdsec'],timeout=600)
emit('core_package_install',rc,installed=rc==0)
refresh_secrets();note('core_package',out)
if rc: command('systemctl','poweroff'); raise SystemExit(1)
import yaml
core_config=pathlib.Path('/etc/crowdsec/config.yaml');core_data=yaml.safe_load(core_config.read_text());core_data['api']['server']['listen_uri']='0.0.0.0:8080';core_config.write_text(yaml.safe_dump(core_data))
command('systemctl','enable','--now','crowdsec');command('systemctl','restart','crowdsec')
key=''
for attempt in range(60):
    rc,key=run(['/usr/bin/cscli','-c','/etc/crowdsec/config.yaml','bouncers','add','vps-lab-'+str(attempt),'-o','raw'])
    if rc==0: key=key.strip(); scrubber.secrets.append(key); break
    time.sleep(1)
if rc: emit('official_lapi',rc,ready=False); command('systemctl','poweroff'); raise SystemExit(1)
pathlib.Path('/etc/crowdsec').mkdir(exist_ok=True)
pathlib.Path('/etc/crowdsec/core-preserve.txt').write_text('existing core must remain unchanged\n')
before=digest(['/etc/crowdsec'])
cli=['bash','install-crowdsec-1panel.sh']
url='http://127.0.0.1:8080/'
local=pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local')
rc,out=run(cli+['--install-relay-bouncer'],url+'\n'+key+'\n',600)
# Installer output can include pre-existing config diagnostics; avoid secrets in serial.
refresh_secrets();note('fresh_output',out)
emit('fresh_remote_install',rc,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'),local_exists=local.exists())
if rc: command('systemctl','poweroff'); raise SystemExit(1)
readonly_before=digest(['/opt/core/etc','/etc/crowdsec'])
help_rc,_=run(cli+['--help'])
status_rc,_=run(cli+['--relay-bouncer-status'])
emit('help_and_readonly_status',0,command_exit_code=status_rc,help_ok=help_rc==0,status_ok=status_rc==0,unchanged=readonly_before==digest(['/opt/core/etc','/etc/crowdsec']))
rc,out=run(cli+['--install-relay-bouncer'],url+'\n'+key+'\n',600)
emit('repeat_remote_install',rc,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
rc,key2=run(['/usr/bin/cscli','-c','/etc/crowdsec/config.yaml','bouncers','add','vps-change','-o','raw']); key2=key2.strip(); scrubber.secrets.append(key2)
rc,out=run(cli+['--configure-relay-bouncer'],'http://127.0.0.2:8080/\n'+key2+'\n')
emit('change_url_and_key',rc,changed=key2 in local.read_text() and '127.0.0.2' in local.read_text(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
cs=['/usr/bin/cscli','-c','/etc/crowdsec/config.yaml']
rc,out=run(cs+['decisions','add','--ip','198.51.100.77','--duration','10m'])
for attempt in range(40):
    nr,no=run(['nft','list','ruleset'],timeout=5); present=nr==0 and '198.51.100.77' in no
    if present: break
    time.sleep(1)
emit('actual_nft_decision_add',rc,present=present)
rc,out=run(cs+['decisions','delete','--ip','198.51.100.77'])
for attempt in range(40):
    nr,no=run(['nft','list','ruleset'],timeout=5); absent=nr==0 and '198.51.100.77' not in no
    if absent: break
    time.sleep(1)
emit('actual_nft_decision_delete',rc,absent=absent)
old=local.read_bytes(); rc,out=run(cli+['--configure-relay-bouncer'],url+'\ndefinitely-invalid-lab-key\n')
emit('bad_key_preserves_state',0,command_exit_code=rc,rejected=1<=rc<=123,local_unchanged=old==local.read_bytes(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
state=pathlib.Path(str(local).replace('.local','.remote.json')); stateold=state.read_bytes(); state.unlink()
rc,out=run(cli+['--configure-relay-bouncer'],url+'\n'+key+'\n')
emit('foreign_local_ownership',0,command_exit_code=rc,rejected=1<=rc<=123,local_unchanged=old==local.read_bytes(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
state.write_bytes(stateold)
# Reboot persistence runs phase2 after boot before removal.
pathlib.Path('/opt/test/phase2.json').write_text(json.dumps(dict(before=before)))
pathlib.Path('/etc/systemd/system/vps-phase2.service').write_text('[Unit]\nOnFailure=vps-failure.service\nAfter=network-online.target crowdsec-firewall-bouncer.service\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /opt/test/phase2.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload'); command('systemctl','enable','vps-phase2')
command('systemctl','reboot'); time.sleep(300)

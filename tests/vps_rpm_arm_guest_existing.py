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
if env.get('ID','').strip('"') in ('debian','ubuntu'):
    rc,out=run(['apt-get','update'],timeout=600);emit('guest_dependencies_index',rc,ready=rc==0)
    if rc:command('systemctl','poweroff');raise SystemExit(1)
    deps=['apt-get','install','-y','python3-yaml','curl','ca-certificates']
else:deps=['dnf','install','-y','python3-pyyaml','curl','ca-certificates']
rc,out=run(deps,timeout=600);emit('guest_dependencies',rc,packages_ready=rc==0);refresh_secrets();note('packages',out)
if rc:command('systemctl','poweroff');raise SystemExit(1)
# This scope deliberately installs the official native package before integration.
rc,out=run(['bash','-c','curl -fLsS --max-time 120 https://install.crowdsec.net -o /tmp/install-core.sh && bash /tmp/install-core.sh'],timeout=600)
emit('core_repository_setup',rc,ready=rc==0);refresh_secrets();note('repository',out)
if rc:command('systemctl','poweroff');raise SystemExit(1)
pm=['apt-get','install','-y','crowdsec'] if env.get('ID','').strip('"') in ('debian','ubuntu') else ['dnf','install','-y','crowdsec']
rc,out=run(pm,timeout=600);emit('core_package_install',rc,installed=rc==0);refresh_secrets();note('core_package',out)
if rc:command('systemctl','poweroff');raise SystemExit(1)
config=pathlib.Path('/etc/crowdsec/config.yaml')
config.write_bytes(config.read_bytes()+b'\n# existing-core integration sentinel\n')
existing_before=config.read_bytes()
print('VPS_PROGRESS existing_native_core_integration_start',flush=True)
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',timeout=900);refresh_secrets();note('core_relay',out)
emit('core_relay_install',rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
if rc:print('VPS_COMPLETE',flush=True);command('systemctl','poweroff');raise SystemExit(1)
emit('existing_core_config_preserved',0,preserved=existing_before==config.read_bytes())
before=pathlib.Path('/etc/crowdsec/config.yaml').read_bytes()
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',timeout=900);refresh_secrets();note('core_repeat',out)
emit('core_repeat_install',rc,preserved=before==pathlib.Path('/etc/crowdsec/config.yaml').read_bytes(),core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
pathlib.Path('/etc/systemd/system/vps-native.service').write_text('[Unit]\nOnFailure=vps-failure.service\nAfter=network-online.target crowdsec.service crowdsec-firewall-bouncer.service\nWants=network-online.target\n[Service]\nType=simple\nEnvironment=TERM=vt220\nExecStart=/usr/bin/python3 /opt/test/native-phase.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload');command('systemctl','enable','vps-native');command('systemctl','reboot')

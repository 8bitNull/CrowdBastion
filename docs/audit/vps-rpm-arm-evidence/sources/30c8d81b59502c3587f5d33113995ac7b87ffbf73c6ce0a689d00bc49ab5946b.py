import json,subprocess,pathlib,os,time,hashlib

def run(argv,inputs=None,timeout=300):
    p=subprocess.run(argv,input=inputs,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    return p.returncode,p.stdout

def emit(case,rc,command_exit_code=None,**assertions):
    print('VPS_RESULT '+json.dumps(dict(case=case,exit_code=rc,command_exit_code=rc if command_exit_code is None else command_exit_code,assertions=assertions)),flush=True)

def command(*argv): return run(list(argv))[0]==0

def digest(paths):
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for root in paths for p in pathlib.Path(root).rglob('*') if p.is_file()}

os.chdir('/opt/test/repo')
env=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
print('VPS_ENV '+json.dumps(dict(actual_distro=env.get('PRETTY_NAME','').strip('"'),os_id=env.get('ID','').strip('"'),version=env.get('VERSION_ID','').strip('"'),architecture=os.uname().machine,kernel=os.uname().release,pid1=pathlib.Path('/proc/1/comm').read_text().strip(),installer_sha256=hashlib.sha256(pathlib.Path('install-crowdsec-1panel.sh').read_bytes()).hexdigest(),ram_kib=int(pathlib.Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]))),flush=True)
rc,out=run(['dnf','install','-y','python3-pyyaml'],timeout=600); emit('guest_dependencies',rc,packages_ready=rc==0)
print('VPS_NOTE packages '+out[-2500:].replace('\n',' | '),flush=True)
if rc: raise SystemExit(1)
# Existing official core uses a private guest-only data snapshot and local LAPI.
import yaml
core_config=pathlib.Path('/opt/core/etc/config.yaml');core_data=yaml.safe_load(core_config.read_text());core_data['api']['server']['listen_uri']='0.0.0.0:8080';core_config.write_text(yaml.safe_dump(core_data))
pathlib.Path('/etc/systemd/system/vps-core.service').write_text('[Unit]\nAfter=network-online.target\n[Service]\nExecStart=/opt/test/bin/crowdsec -c /opt/core/etc/config.yaml -no-cs\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload'); command('systemctl','enable','--now','vps-core')
key=''
for attempt in range(60):
    rc,key=run(['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml','bouncers','add','vps-lab-'+str(attempt),'-o','raw'])
    if rc==0: key=key.strip(); break
    time.sleep(1)
if rc: emit('official_lapi',rc,ready=False); raise SystemExit(1)
pathlib.Path('/etc/crowdsec').mkdir(exist_ok=True)
pathlib.Path('/etc/crowdsec/core-preserve.txt').write_text('existing core must remain unchanged\n')
before=digest(['/opt/core/etc','/etc/crowdsec'])
cli=['bash','install-crowdsec-1panel.sh']
url='http://127.0.0.1:8080/'
local=pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local')
rc,out=run(cli+['--install-relay-bouncer'],url+'\n'+key+'\n',600)
# Installer output can include pre-existing config diagnostics; avoid secrets in serial.
print('VPS_NOTE fresh_output '+out.replace(key,'<redacted>')[-1500:].replace('\n',' | '),flush=True)
emit('fresh_remote_install',rc,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'),local_exists=local.exists())
if rc: raise SystemExit(1)
readonly_before=digest(['/opt/core/etc','/etc/crowdsec'])
help_rc,_=run(cli+['--help'])
status_rc,_=run(cli+['--relay-bouncer-status'])
emit('help_and_readonly_status',0,command_exit_code=status_rc,help_ok=help_rc==0,status_ok=status_rc==0,unchanged=readonly_before==digest(['/opt/core/etc','/etc/crowdsec']))
rc,out=run(cli+['--install-relay-bouncer'],url+'\n'+key+'\n',600)
emit('repeat_remote_install',rc,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
rc,key2=run(['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml','bouncers','add','vps-change','-o','raw']); key2=key2.strip()
rc,out=run(cli+['--configure-relay-bouncer'],'http://127.0.0.2:8080/\n'+key2+'\n')
emit('change_url_and_key',rc,changed=key2 in local.read_text() and '127.0.0.2' in local.read_text(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
cs=['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml']
rc,out=run(cs+['decisions','add','--ip','198.51.100.77','--duration','10m'])
for attempt in range(40):
    present='198.51.100.77' in run(['nft','list','ruleset'])[1]
    if present: break
    time.sleep(1)
emit('actual_nft_decision_add',rc,present=present)
rc,out=run(cs+['decisions','delete','--ip','198.51.100.77'])
for attempt in range(40):
    absent='198.51.100.77' not in run(['nft','list','ruleset'])[1]
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
pathlib.Path('/etc/systemd/system/vps-phase2.service').write_text('[Unit]\nAfter=network-online.target crowdsec-firewall-bouncer.service\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/bin/bash -c "exec /usr/bin/python3 /opt/test/phase2.py >/dev/ttyS0 2>&1"\nStandardOutput=null\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload'); command('systemctl','enable','vps-phase2')
command('systemctl','reboot'); time.sleep(300)

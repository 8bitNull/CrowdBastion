import json,subprocess,pathlib,os,time,hashlib,shutil

def run(argv,inputs=None,timeout=300):
    if argv[0]=='systemctl': print('VPS_NOTE systemctl_start '+str(argv[1:]),flush=True)
    try:
        p=subprocess.run(argv,input=inputs,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        print('VPS_NOTE command_timeout '+argv[0],flush=True)
        output=exc.stdout or ''
        return 124,output.decode(errors='replace') if isinstance(output,bytes) else output
    if argv[0]=='systemctl': print('VPS_NOTE systemctl_exit '+str(p.returncode),flush=True)
    return p.returncode,p.stdout

def emit(case,rc,command_exit_code=None,observations=None,**assertions):
    print('VPS_RESULT '+json.dumps(dict(case=case,exit_code=rc,command_exit_code=rc if command_exit_code is None else command_exit_code,observations=observations,assertions=assertions)),flush=True)

def command(*argv): return run(list(argv))[0]==0

def digest(paths):
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for root in paths for p in pathlib.Path(root).rglob('*') if p.is_file()}

os.chdir('/opt/test/repo')
env=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
print('VPS_ENV '+json.dumps(dict(payload_provenance=json.loads(pathlib.Path('/opt/test/provenance.json').read_text()),actual_distro=env.get('PRETTY_NAME','').strip('"'),disk_size_bytes=shutil.disk_usage('/').total,disk_free_bytes=shutil.disk_usage('/').free,ram_total_kib=int(pathlib.Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]),arch=os.uname().machine,kernel=os.uname().release,init=pathlib.Path('/proc/1/comm').read_text().strip(),installer_sha256=hashlib.sha256(pathlib.Path('install-crowdsec-1panel.sh').read_bytes()).hexdigest(),library_tree_sha256=hashlib.sha256(json.dumps(digest(['lib']),sort_keys=True).encode()).hexdigest())),flush=True)
help_before=digest(['/opt/core/etc'])
help_rc,help_out=run(['bash','install-crowdsec-1panel.sh','--help'])
emit('help_entry',help_rc,documented_option='--install-relay-bouncer' in help_out,core_unchanged=help_before==digest(['/opt/core/etc']))
rc,out=run(['apt-get','update']); emit('guest_dependencies_index',rc,index_ready=rc==0)
rc,out=run(['apt-get','install','-y','python3-yaml','curl','ca-certificates','nftables']); emit('guest_dependencies',rc,packages_ready=rc==0)
if rc: raise SystemExit(1)
# Existing official core uses a private guest-only data snapshot and local LAPI.
import yaml
core_config=pathlib.Path('/opt/core/etc/config.yaml')
config=yaml.safe_load(core_config.read_text()); config['api']['server']['listen_uri']='0.0.0.0:8080'
core_config.write_text(yaml.safe_dump(config))
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
rc,out=run(cli+['--install-relay-bouncer'],url+'\n'+key+'\n',600)
emit('repeat_remote_install',rc,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
readonly_before=digest(['/etc/crowdsec','/opt/core/etc'])
readonly_rc,_=run(cli+['--relay-bouncer-status'])
emit('remote_readonly_status',readonly_rc,config_unchanged=readonly_before==digest(['/etc/crowdsec','/opt/core/etc']))
rc,key2=run(['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml','bouncers','add','vps-change','-o','raw']); key2=key2.strip()
rc,out=run(cli+['--configure-relay-bouncer'],'http://127.0.0.2:8080/\n'+key2+'\n')
emit('change_url_and_key',rc,changed=key2 in local.read_text() and '127.0.0.2' in local.read_text(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
old=local.read_bytes(); rc,out=run(cli+['--configure-relay-bouncer'],url+'\ndefinitely-invalid-lab-key\n')
emit('bad_key_preserves_state',0,command_exit_code=rc,rejected=rc!=0,local_unchanged=old==local.read_bytes(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
state=pathlib.Path(str(local).replace('.local','.remote.json')); stateold=state.read_bytes(); state.unlink()
rc,out=run(cli+['--configure-relay-bouncer'],url+'\n'+key+'\n')
emit('foreign_local_ownership',0,command_exit_code=rc,rejected=rc!=0,local_unchanged=old==local.read_bytes(),active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
state.write_bytes(stateold)
# Real official decision API to actual kernel nftables set synchronization.
rc,out=run(['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml','decisions','add','--ip','198.51.100.2','--duration','2m'])
present=False
for _ in range(40):
    nft_rc,nft_out=run(['nft','-j','list','ruleset'])
    if '198.51.100.2' in nft_out: present=True; break
    time.sleep(1)
emit('official_decision_nft_ban_sync',rc,ban_present=present)
rc,out=run(['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml','decisions','delete','--ip','198.51.100.2'])
removed=False
for _ in range(40):
    nft_rc,nft_out=run(['nft','-j','list','ruleset'])
    if '198.51.100.2' not in nft_out: removed=True; break
    time.sleep(1)
emit('official_decision_nft_unban_sync',rc,ban_removed=removed)
# Reboot persistence runs phase2 after boot before removal.
pathlib.Path('/opt/test/phase2.json').write_text(json.dumps(dict(before=before)))
pathlib.Path('/etc/systemd/system/vps-phase2.service').write_text('[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /opt/test/phase2.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload'); command('systemctl','enable','vps-phase2')
command('systemctl','reboot'); time.sleep(300)

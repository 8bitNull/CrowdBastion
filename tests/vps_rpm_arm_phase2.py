"""Remote reboot, safe removal and separately scoped existing-core integration."""
exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo')
print('VPS_PROGRESS phase2_entered',flush=True)

p=pathlib.Path('/opt/test/remote-reboots.json')
state=json.loads(p.read_text()) if p.exists() else {'boots':0,'bouncer':True,'add':True,'delete':True,'commands':True}
state['boots']+=1
last_properties='Result=not-ready'
def probe_bouncer():
    global last_properties
    rc,out=run(['systemctl','show','crowdsec-firewall-bouncer','-p','ActiveState','-p','SubState','-p','Result'],timeout=5)
    last_properties=out if rc==0 else 'Result=probe-failed'
    return rc==0 and service_healthy(out)
ready=wait_ready(probe_bouncer,timeout=120)
state['bouncer']=state['bouncer'] and ready
observed={};codes={}
cs=['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml'] if pathlib.Path('/opt/test/bin/cscli').exists() else ['/usr/bin/cscli','-c','/etc/crowdsec/config.yaml']
for action in ['add','delete']:
    args=cs+['decisions',action,'--ip','198.51.100.78']
    if action=='add':args+=['--duration','10m']
    rc,out=run(args,timeout=60);codes[action]=rc;state['commands']=state['commands'] and rc==0
    def synced():
        nr,no=run(['nft','-j','list','ruleset'],timeout=5)
        return nr==0 and ('198.51.100.78' in no)==(action=='add')
    observed[action]=wait_ready(synced,timeout=60) and rc==0
    state[action]=state[action] and observed[action]
print('VPS_BOOT '+json.dumps({'phase':'remote_reboot','boot':state['boots'],'services':{'crowdsec-firewall-bouncer':ready},'add':observed['add'],'delete':observed['delete'],'add_command_exit_code':codes['add'],'delete_command_exit_code':codes['delete']}),flush=True)
p.write_text(json.dumps(state))
if state['boots']<3:
    command('systemctl','reboot');raise SystemExit(0)
emit('boot_auto_start',0,active=state['bouncer'],enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
hrc,hout=run(['systemctl','show','crowdsec-firewall-bouncer','-p','ActiveState','-p','SubState','-p','Result'],timeout=5)
print('VPS_HEALTH '+json.dumps({'phase':'remote_reboot','service':'crowdsec-firewall-bouncer','properties':hout if ready and hrc==0 else 'Result=readiness-failed'}),flush=True)
for action in ['add','delete']:
    emit('remote_reboot_decision_'+action,0 if state['commands'] else 1,synced=state[action])
# Finite diagnostics: no YAML tree scan or asynchronous stack output.
deadline=time.monotonic()+60
for unit in ['crowdsec','crowdsec-firewall-bouncer']:
    for what,args in [('state',['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','Result','-p','TimeoutStartUSec','-p','NRestarts']),('journal',['journalctl','-b','-u',unit,'-n','15','--no-pager','-o','short-monotonic'])]:
        remaining=deadline-time.monotonic()
        if remaining<=0:break
        rc,out=run(args,timeout=min(10,remaining));note(unit+'_'+what,out)
rc,out=run(['bash','install-crowdsec-1panel.sh','--remove-relay-bouncer'],timeout=120)
active_rc,active_out=run(['systemctl','show','crowdsec-firewall-bouncer','-p','ActiveState'],timeout=5)
enabled_rc,enabled_out=run(['systemctl','is-enabled','crowdsec-firewall-bouncer'],timeout=5)
removed=service_removed(active_rc,active_out,enabled_rc,enabled_out)
emit('remove_managed_remote',rc,inactive=removed,disabled=removed,local_removed=not pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local').exists())
before=json.loads(pathlib.Path('/opt/test/phase2.json').read_text())['before']
emit('existing_core_preserved',0,unchanged=all(pathlib.Path(path).is_file() and hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==value for path,value in before.items()))
print('VPS_REMOTE_COMPLETE',flush=True)
if pathlib.Path('/opt/test/test-scope.txt').is_file() and pathlib.Path('/opt/test/test-scope.txt').read_text().strip()=='remote_only':
    command('systemctl','disable','vps-phase2');print('VPS_COMPLETE',flush=True);command('systemctl','poweroff');raise SystemExit(0)
if pathlib.Path('/etc/systemd/system/vps-core.service').exists():
    command('systemctl','stop','vps-core');command('systemctl','disable','vps-core')
guard_before=digest(['/opt/core/etc','/etc/crowdsec'])
for profile in ['--install-relay','--install-core']:
    rc,out=run(['bash','install-crowdsec-1panel.sh',profile],'\n',timeout=60)
    emit('retained_remote_refused_'+profile.removeprefix('--install-'),0,command_exit_code=rc,refused=1<=rc<=123,unchanged=guard_before==digest(['/opt/core/etc','/etc/crowdsec']))
# Only test-created standalone artifacts are removed in this isolated guest.
for residue in ['/usr/local/bin/crowdsec-firewall-bouncer','/etc/systemd/system/crowdsec-firewall-bouncer.service','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml']:
    pathlib.Path(residue).unlink(missing_ok=True)
command('systemctl','daemon-reload')
print('VPS_PROGRESS existing_core_integration_start',flush=True)
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',timeout=900)
refresh_secrets();note('core_relay',out)
emit('core_relay_install',rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
command('systemctl','disable','vps-phase2')
pathlib.Path('/etc/systemd/system/vps-native.service').write_text('[Unit]\nOnFailure=vps-failure.service\nAfter=network-online.target crowdsec.service crowdsec-firewall-bouncer.service\nWants=network-online.target\n[Service]\nType=simple\nEnvironment=TERM=vt220\nExecStart=/usr/bin/python3 /opt/test/native-phase.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload');command('systemctl','enable','vps-native');command('systemctl','reboot')

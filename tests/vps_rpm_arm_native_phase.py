"""Three native-core reboot checks, including actual decision synchronization."""
exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo')
p=pathlib.Path('/opt/test/native-reboots.json')
state=json.loads(p.read_text()) if p.exists() else {'boots':0,'core':True,'bouncer':True,'add':True,'delete':True,'commands':True}
state['boots']+=1
print('VPS_PROGRESS native_reboot_'+str(state['boots']),flush=True)

properties={}
def healthy(unit):
    rc,out=run(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','Result'],timeout=5)
    properties[unit]=out if rc==0 else 'Result=probe-failed'
    return rc==0 and service_healthy(out)
deadline=time.monotonic()+120
observed={'core':False,'bouncer':False}
def probe():
    observed['core']=healthy('crowdsec') and time.monotonic()<=deadline
    observed['bouncer']=healthy('crowdsec-firewall-bouncer') and time.monotonic()<=deadline
    return observed['core'] and observed['bouncer']
wait_ready(probe,timeout=120)
state['core']=state['core'] and observed['core'];state['bouncer']=state['bouncer'] and observed['bouncer']
boot_services={'crowdsec':observed['core'],'crowdsec-firewall-bouncer':observed['bouncer']}
boot_sync={};codes={}
for action in ['add','delete']:
    args=['cscli','decisions',action,'--ip','198.51.100.79']
    if action=='add':args+=['--duration','10m']
    rc,out=run(args,timeout=60);codes[action]=rc;state['commands']=state['commands'] and rc==0
    def synced():
        nr,no=run(['nft','-j','list','ruleset'],timeout=5)
        return nr==0 and ('198.51.100.79' in no)==(action=='add')
    synced_ok=wait_ready(synced,timeout=60) and rc==0;boot_sync[action]=synced_ok;state[action]=state[action] and synced_ok
print('VPS_BOOT '+json.dumps({'phase':'native_core_reboot','boot':state['boots'],'services':boot_services,'add':boot_sync['add'],'delete':boot_sync['delete'],'add_command_exit_code':codes['add'],'delete_command_exit_code':codes['delete']}),flush=True)
p.write_text(json.dumps(state))
if state['boots']<3:
    command('systemctl','reboot')
else:
    emit('native_core_reboot',0,core_active=state['core'],bouncer_active=state['bouncer'])
    emit('native_core_decision_add',0 if state['commands'] else 1,synced=state['add'])
    emit('native_core_decision_delete',0 if state['commands'] else 1,synced=state['delete'])
    for unit in ['crowdsec','crowdsec-firewall-bouncer']:
        rc,out=run(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','Result'],timeout=5)
        if not all(boot_services.values()) or rc!=0:out='Result=readiness-failed'
        print('VPS_HEALTH '+json.dumps({'phase':'native_core_reboot','service':unit,'properties':out}),flush=True)
    if pathlib.Path('/opt/test/soak-manifest.json').exists():
        pathlib.Path('/run/crowdsec-vps-lab').write_text(json.loads(pathlib.Path('/opt/test/soak-manifest.json').read_text())['lab_id'])
        rc,out=run(['/usr/bin/python3','/opt/test/vps_soak_stage.py'],timeout=json.loads(pathlib.Path('/opt/test/soak-manifest.json').read_text())['duration_seconds']+300)
        event_file=pathlib.Path('/opt/test/soak-result.jsonl')
        if event_file.is_file():
            with event_file.open() as events:
                for event in events:
                    if len(event.encode())<=4000:print('VPS_SOAK_EVENT '+event.strip(),flush=True)
                    else:print('VPS_PROGRESS invalid_soak_event_size',flush=True)
        for line in out.splitlines():
            if line.startswith('VPS_SOAK_COMPLETE '):print(line,flush=True)
        if rc:note('soak_failure_category','Soak workload failed or timed out; inspect guest-local evidence.')
    print('VPS_COMPLETE',flush=True);command('systemctl','poweroff')

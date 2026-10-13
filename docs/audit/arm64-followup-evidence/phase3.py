exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo')
start=time.monotonic(); core_ready=False; bouncer_ready=False
while time.monotonic()-start<120:
    cr,_=run(['systemctl','is-active','--quiet','crowdsec'],timeout=5)
    br,_=run(['systemctl','is-active','--quiet','crowdsec-firewall-bouncer'],timeout=5)
    core_ready=cr==0 and time.monotonic()-start<=120; bouncer_ready=br==0 and time.monotonic()-start<=120
    if core_ready and bouncer_ready:break
    time.sleep(2)
print('VPS_NOTE native_readiness_elapsed '+str(round(time.monotonic()-start,2)),flush=True)
emit('native_core_reboot',0,core_active=core_ready,bouncer_active=bouncer_ready,core_enabled=command('systemctl','is-enabled','--quiet','crowdsec'),bouncer_enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
for action in ['add','delete']:
    argv=['cscli','decisions',action,'--ip','198.51.100.78']
    if action=='add':argv+=['--duration','10m']
    rc,out=run(argv,timeout=90)
    synced=False
    for _ in range(60):
        nr,no=run(['nft','-j','list','ruleset'],timeout=30)
        if nr==0 and ('198.51.100.78' in no)==(action=='add'):synced=True;break
        time.sleep(1)
    emit('native_core_decision_'+action,rc,synced=synced)
diagnose()
print('VPS_COMPLETE',flush=True)
print('ARM_FOLLOWUP_COMPLETE',flush=True)
command('systemctl','poweroff')

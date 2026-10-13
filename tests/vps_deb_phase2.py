exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
import faulthandler
faulthandler.enable(); faulthandler.dump_traceback_later(45,repeat=True)
print('VPS_NOTE phase2_entered',flush=True)
os.chdir('/opt/test/repo'); time.sleep(3)
print('VPS_NOTE phase2_after_sleep',flush=True)
initial_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer')
emit('boot_initial_active_observation',0,observations={'active':initial_active},sample_recorded=True)
start=time.monotonic(); active=initial_active; attempts=1
while not active and time.monotonic()-start<60:
    time.sleep(2); attempts+=1
    active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer')
core_active=command('systemctl','is-active','--quiet','vps-core')
lapi_rc,_=run(['/opt/test/bin/cscli','-c','/opt/core/etc/config.yaml','bouncers','list','-o','json'],timeout=15)
if not active:
    _,unit_state=run(['systemctl','show','crowdsec-firewall-bouncer','-p','ActiveState','-p','SubState','-p','Result','-p','ExecMainCode','-p','ExecMainStatus'],timeout=10)
    print('VPS_NOTE boot_unit_state '+json.dumps(unit_state.splitlines()),flush=True)
    _,journal=run(['journalctl','-u','crowdsec-firewall-bouncer','-n','25','--no-pager'],timeout=10)
    print('VPS_NOTE boot_safe_error_lines '+json.dumps([line for line in journal.splitlines() if any(word in line.lower() for word in ('error','failed','403','401')) and not any(word in line.lower() for word in ('key','token','password','credential'))]),flush=True)
emit('boot_auto_start',0,observations={'initial_active':initial_active,'attempts':attempts,'wait_seconds':round(time.monotonic()-start,2),'lapi_core_active':core_active,'lapi_authenticated_ready':lapi_rc==0},active=active,enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
rc,out=run(['bash','install-crowdsec-1panel.sh','--remove-relay-bouncer'])
emit('remove_managed_remote',rc,inactive=not command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),disabled=not command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'),local_removed=not pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local').exists())
before=json.loads(pathlib.Path('/opt/test/phase2.json').read_text())['before']
emit('existing_core_preserved',0,unchanged=all(pathlib.Path(path).is_file() and hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==value for path,value in before.items()))
print('VPS_REMOTE_COMPLETE',flush=True)
# Actual refusal of package-core transition while custom remote runtime remains.
artifacts=['/etc/systemd/system/crowdsec-firewall-bouncer.service','/usr/local/bin/crowdsec-firewall-bouncer']
def guard_snapshot():
    return digest(['/etc/crowdsec','/opt/core/etc']) | {name:hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() for name in artifacts}
guard_before=guard_snapshot()
for case,flag in [('local_relay_transition_guard','--install-relay'),('local_web_transition_guard','--install-core')]:
    guard_rc,guard_out=run(['bash','install-crowdsec-1panel.sh',flag],'\n',60)
    emit(case,0,command_exit_code=guard_rc,rejected=guard_rc!=0,files_preserved=guard_before==guard_snapshot())
# Separate fresh relay scenario after remote/core-preservation acceptance.
command('systemctl','disable','--now','vps-core')
for name in ['/etc/systemd/system/crowdsec-firewall-bouncer.service','/usr/local/bin/crowdsec-firewall-bouncer','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml']:
    pathlib.Path(name).unlink(missing_ok=True)
command('systemctl','daemon-reload')
import threading
progress_stop=threading.Event()
def report_core_processes():
    while not progress_stop.wait(30):
        try:
            snapshot=subprocess.run(['ps','-eo','pid=,ppid=,comm='],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout
            processes=[line.split() for line in snapshot.splitlines() if len(line.split())==3]
            print('VPS_NOTE core_process_tree '+json.dumps(processes),flush=True)
        except subprocess.TimeoutExpired:
            print('VPS_NOTE core_process_snapshot_timeout',flush=True)
threading.Thread(target=report_core_processes,daemon=True).start()
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
progress_stop.set()
print('VPS_NOTE core_relay_failure_markers '+json.dumps([line for line in out.splitlines() if any(word in line.lower() for word in ('error','failed','错误','失败','unable to locate')) and not any(word in line.lower() for word in ('key','password','token','credential'))][-12:]),flush=True)
emit('fresh_core_relay_install',rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
if rc==0:
    for case,flag in [('core_status','--status'),('core_log_check','--check-logs'),('core_relay_status','--relay-status'),('core_update_hub','--update-hub')]:
        check_rc,check_out=run(['bash','install-crowdsec-1panel.sh',flag],timeout=600)
        emit(case,check_rc,operation_completed=check_rc==0)
    config=pathlib.Path('/etc/crowdsec/config.yaml').read_bytes()
    repeat_rc,repeat_out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
    emit('core_relay_repeat',repeat_rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),main_config_preserved=config==pathlib.Path('/etc/crowdsec/config.yaml').read_bytes())
print('VPS_COMPLETE',flush=True)
command('systemctl','poweroff')

exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo');print('VPS_PROGRESS phase2_entered',flush=True)
import faulthandler;faulthandler.enable();faulthandler.dump_traceback_later(120,repeat=True)
for _ in range(60):
    if command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'):break
    time.sleep(1)
print('VPS_NOTE reboot_unit_state '+run(['systemctl','show','crowdsec-firewall-bouncer','-p','ActiveState','-p','SubState','-p','Result'])[1].replace('\n',' | '),flush=True)
emit('boot_auto_start',0,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
rc,out=run(['bash','install-crowdsec-1panel.sh','--remove-relay-bouncer'])
emit('remove_managed_remote',rc,inactive=not command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),disabled=not command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'),local_removed=not pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local').exists())
before=json.loads(pathlib.Path('/opt/test/phase2.json').read_text())['before']
emit('existing_core_preserved',0,unchanged=all(pathlib.Path(path).is_file() and hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==value for path,value in before.items()))
print('VPS_REMOTE_COMPLETE',flush=True)
if pathlib.Path('/etc/systemd/system/vps-core.service').exists():
    command('systemctl','stop','vps-core');command('systemctl','disable','vps-core')
guard_before=digest(['/opt/core/etc','/etc/crowdsec'])
for profile in ['--install-relay','--install-core']:
    rc,out=run(['bash','install-crowdsec-1panel.sh',profile],'\n',timeout=60)
    emit('retained_remote_refused_'+profile.removeprefix('--install-'),0,command_exit_code=rc,refused=rc!=0,unchanged=guard_before==digest(['/opt/core/etc','/etc/crowdsec']))
# Separate fresh native core install from the retained standalone remote unit.
for residue in ['/usr/local/bin/crowdsec-firewall-bouncer','/etc/systemd/system/crowdsec-firewall-bouncer.service','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml']:
    pathlib.Path(residue).unlink(missing_ok=True)
command('systemctl','daemon-reload')
import threading
progress_stop=threading.Event()
def progress_probe():
    while not progress_stop.wait(120):
        try:
            print('VPS_PROGRESS guest_process_comm_wchan '+run(['ps','-eo','pid,comm,wchan'],timeout=20)[1].replace('\n',' | '),flush=True)
        except subprocess.TimeoutExpired:
            print('VPS_PROGRESS bounded_process_probe_timeout',flush=True)
threading.Thread(target=progress_probe,daemon=True).start()
try:
    rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',timeout=900)
except subprocess.TimeoutExpired as exc:
    partial=exc.stdout or ""
    if isinstance(partial,bytes):partial=partial.decode(errors="replace")
    rc,out=124,partial+'Core relay installer exceeded bounded 900 second runtime.'
import re
safe_out=re.sub(r'(?i)((?:api[_ -]?key|token|password|secret)\s*[:=]\s*)\S+',r'\1<redacted>',out)
safe_out=re.sub(r'\b[A-Za-z0-9_-]{32,}\b','<opaque-redacted>',safe_out)
print('VPS_NOTE core relay '+safe_out[-3000:].replace('\n',' | '),flush=True)
emit('core_relay_install',rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
print('VPS_NOTE native_core_version '+run(['crowdsec','-version'])[1].replace('\n',' | '),flush=True)
progress_stop.set()
faulthandler.cancel_dump_traceback_later()
print('VPS_COMPLETE',flush=True)
command('systemctl','poweroff')

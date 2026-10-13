exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo'); time.sleep(15)
emit('boot_auto_start',0,active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
rc,out=run(['bash','install-crowdsec-1panel.sh','--remove-relay-bouncer'])
emit('remove_managed_remote',rc,inactive=not command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'),disabled=not command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'),local_removed=not pathlib.Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local').exists())
before=json.loads(pathlib.Path('/opt/test/phase2.json').read_text())['before']
emit('existing_core_preserved',0,unchanged=all(pathlib.Path(path).is_file() and hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==value for path,value in before.items()))
print('VPS_REMOTE_COMPLETE',flush=True)
if pathlib.Path('/etc/systemd/system/vps-core.service').exists():
    command('systemctl','stop','vps-core');command('systemctl','disable','vps-core')
# Separate fresh native core install from the retained standalone remote unit.
for residue in ['/usr/local/bin/crowdsec-firewall-bouncer','/etc/systemd/system/crowdsec-firewall-bouncer.service','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml']:
    pathlib.Path(residue).unlink(missing_ok=True)
command('systemctl','daemon-reload')
try:
    rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',timeout=900)
except subprocess.TimeoutExpired:
    rc,out=124,'Core relay installer exceeded bounded 900 second runtime.'
import re
safe_out=re.sub(r'(?i)((?:api[_ -]?key|token|password|secret)\s*[:=]\s*)\S+',r'\1<redacted>',out)
safe_out=re.sub(r'\b[A-Za-z0-9_-]{32,}\b','<opaque-redacted>',safe_out)
print('VPS_NOTE core relay '+safe_out[-3000:].replace('\n',' | '),flush=True)
emit('core_relay_install',rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
print('VPS_COMPLETE',flush=True)
command('systemctl','poweroff')

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

import re

def scrub(value):
    text=str(value)
    secrets=[]
    try:
        import yaml
        def visit(node):
            if isinstance(node,dict):
                for k,v in node.items():
                    if any(word in str(k).lower() for word in ('password','api_key','token','secret')) and isinstance(v,str) and len(v)>=4:secrets.append(v)
                    visit(v)
            elif isinstance(node,list):
                for v in node:visit(v)
        for p in pathlib.Path('/etc/crowdsec').rglob('*.yaml*'):
            if p.is_file() and p.stat().st_size<1000000:
                try:visit(yaml.safe_load(p.read_text()))
                except Exception:pass
    except ImportError:pass
    for secret in sorted(secrets,key=len,reverse=True):text=text.replace(secret,'<redacted>')
    text=re.sub(r'(?i)(api[_ -]?key|password|token|secret)([\s:=]+)([^\s,\"\']+)',r'\1\2<redacted>',text)
    text=re.sub(r'[A-Za-z0-9_+/=-]{32,}','<opaque-redacted>',text)
    return text

def note(name,data):print('CORE_DIAG '+json.dumps({'case':name,'data':scrub(data)}),flush=True)

def diagnose():
    for unit in ['crowdsec','crowdsec-firewall-bouncer']:
        rc,out=run(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','Result','-p','ExecMainCode','-p','ExecMainStatus','-p','FragmentPath'])
        note(unit+'_state',out)
        rc,out=run(['journalctl','-u',unit,'-n','60','--no-pager','-o','cat'],timeout=30)
        note(unit+'_journal',out)
    rc,out=run(['dpkg-query','-W','-f=${Package} ${Version} ${Status}\n','crowdsec','crowdsec-firewall-bouncer-nftables'])
    note('packages',out)
    for name in ['/var/log/crowdsec-firewall-bouncer.log','/var/log/crowdsec.log']:
        p=pathlib.Path(name)
        if p.is_file():note(name,'\n'.join(p.read_text(errors='replace').splitlines()[-60:]))
    p=pathlib.Path('/var/lib/dpkg/info/crowdsec-firewall-bouncer-nftables.postinst')
    if p.exists():note('official_bouncer_postinst',p.read_text())
    paths=['/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/systemd/system/crowdsec-firewall-bouncer.service']
    note('artifact_presence',{name:pathlib.Path(name).exists() for name in paths})

os.chdir('/opt/test/repo')
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('installer_exit',rc);note('installer_output',out)
diagnose()
print('CORE_DIAG_COMPLETE',flush=True)
command('systemctl','poweroff')

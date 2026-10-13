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
print('CORE_FIXED_ENV '+json.dumps({'distro':pathlib.Path('/etc/os-release').read_text(),'kernel':os.uname().release,'arch':os.uname().machine,'init':pathlib.Path('/proc/1/comm').read_text().strip(),'mem_total_kib':int(pathlib.Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]),'TERM':os.environ.get('TERM'),'NO_COLOR':os.environ.get('NO_COLOR'),'installer_sha256':hashlib.sha256(pathlib.Path('install-crowdsec-1panel.sh').read_bytes()).hexdigest()}),flush=True)
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('installer_output',out)
emit('fixed_fresh_core_relay_install',rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
diagnose()
if rc:
    print('CORE_FIXED_COMPLETE',flush=True);command('systemctl','poweroff');raise SystemExit(1)
before=pathlib.Path('/etc/crowdsec/config.yaml').read_bytes()
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',600)
note('repeat_output',out)
emit('fixed_core_repeat',rc,main_config_preserved=before==pathlib.Path('/etc/crowdsec/config.yaml').read_bytes(),core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
phase=r"""
exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo')
start=time.monotonic();active=False
while time.monotonic()-start<60:
    active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer')
    if active:break
    time.sleep(2)
emit('fixed_core_reboot',0,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=active,bouncer_enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
rc,out=run(['cscli','decisions','add','--ip','198.51.100.3','--duration','2m'],timeout=60)
present=False
for _ in range(30):
    nr,no=run(['nft','-j','list','ruleset'],timeout=15)
    if nr==0 and '198.51.100.3' in no:present=True;break
    time.sleep(1)
emit('fixed_core_decision_add',rc,ban_present=present)
rc,out=run(['cscli','decisions','delete','--ip','198.51.100.3'],timeout=60)
removed=False
for _ in range(30):
    nr,no=run(['nft','-j','list','ruleset'],timeout=15)
    if nr==0 and '198.51.100.3' not in no:removed=True;break
    time.sleep(1)
emit('fixed_core_decision_delete',rc,ban_removed=removed)
diagnose()
print('CORE_FIXED_COMPLETE',flush=True)
command('systemctl','poweroff')
"""
pathlib.Path('/opt/test/fixed-phase2.py').write_text(phase)
pathlib.Path('/etc/systemd/system/core-fixed-phase2.service').write_text('[Unit]\nAfter=network-online.target crowdsec.service\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /opt/test/fixed-phase2.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload');command('systemctl','enable','core-fixed-phase2')
command('systemctl','reboot');time.sleep(300)

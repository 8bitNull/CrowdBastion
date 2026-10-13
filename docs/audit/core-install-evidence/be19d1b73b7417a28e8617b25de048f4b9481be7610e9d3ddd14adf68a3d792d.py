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
print('CORE_DIAG_ENV '+json.dumps({'distro':pathlib.Path('/etc/os-release').read_text(),'kernel':os.uname().release,'arch':os.uname().machine,'mem_total':pathlib.Path('/proc/meminfo').read_text().splitlines()[0]}),flush=True)

os.chdir('/opt/test/repo')

note('terminal_environment',{'TERM':os.environ.get('TERM'),'NO_COLOR':os.environ.get('NO_COLOR')})
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('baseline_installer_exit',rc);note('baseline_installer_output',out)
diagnose()
import pty
master,slave=pty.openpty()
p=subprocess.Popen(['/bin/sh','-xc','. /usr/lib/crowdsec-firewall-bouncer-nftables/_bouncer.sh; printf "HELPER_LOADED\\n"'],stdout=slave,stderr=slave)
os.close(slave);buf=b''
while True:
    try:chunk=os.read(master,65536)
    except OSError:break
    if not chunk:break
    buf+=chunk
p.wait();os.close(master)
note('actual_helper_pty_probe_exit',p.returncode);note('actual_helper_pty_probe_trace',buf.decode(errors='replace'))
# Change only the upstream-documented color control for the retry.
os.environ['NO_COLOR']='1'
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('no_color_retry_installer_exit',rc);note('no_color_retry_installer_output',out)
diagnose()
print('CORE_DIAG_COMPLETE',flush=True)
command('systemctl','poweroff')

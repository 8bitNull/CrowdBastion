import json,subprocess,pathlib,os,time,hashlib

def run(argv,inputs=None,timeout=300):
    p=subprocess.run(argv,input=inputs,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    return p.returncode,p.stdout

def emit(case,rc,command_exit_code=None,**assertions):
    print('VPS_RESULT '+json.dumps(dict(case=case,exit_code=rc,command_exit_code=rc if command_exit_code is None else command_exit_code,assertions=assertions)),flush=True)

def command(*argv): return run(list(argv))[0]==0

def digest(paths):
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for root in paths for p in pathlib.Path(root).rglob('*') if p.is_file()}

os.chdir('/opt/test/repo')
env=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
print('VPS_ENV '+json.dumps(dict(actual_distro=env.get('PRETTY_NAME','').strip('"'),os_id=env.get('ID','').strip('"'),version=env.get('VERSION_ID','').strip('"'),architecture=os.uname().machine,kernel=os.uname().release,pid1=pathlib.Path('/proc/1/comm').read_text().strip(),installer_sha256=hashlib.sha256(pathlib.Path('install-crowdsec-1panel.sh').read_bytes()).hexdigest(),ram_kib=int(pathlib.Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]))),flush=True)
rc,out=run(['dnf','install','-y','python3-pyyaml'],timeout=600); emit('guest_dependencies',rc,packages_ready=rc==0)
print('VPS_NOTE packages '+out[-2500:].replace('\n',' | '),flush=True)
if rc: raise SystemExit(1)
import threading
print('VPS_NOTE scope fresh_native_core_only',flush=True)
print('VPS_NOTE meminfo '+pathlib.Path('/proc/meminfo').read_text().replace('\n',' | '),flush=True)
progress_stop=threading.Event()
def progress_probe():
    while not progress_stop.wait(120):
        try:
            print('VPS_PROGRESS guest_process_comm_wchan '+run(['ps','-eo','pid,comm,rss,wchan'],timeout=20)[1].replace('\n',' | '),flush=True)
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

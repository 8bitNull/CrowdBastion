RELEASE='/opt/crowdbastion/releases/vps45-repair-20261102-1f5c867f601e'
import json,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,RELEASE+'/lib')
from crowdsec_bot_runtime import maintenance_guard
r={'checked_at':time.time()}
def rules():return {b:subprocess.check_output([b,'-w','5','-S'],text=True) for b in ['iptables','ip6tables']}
def units():
 return {u:dict(s.split('=',1) for s in subprocess.check_output(['systemctl','show',u,'--property=MainPID,ActiveState,NRestarts,ExecMainStartTimestamp'],text=True).splitlines() if '=' in s) for u in ['crowdsec','crowdsec-firewall-bouncer','docker','1panel-agent']}
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 before=rules();pids=units();p=subprocess.run(['systemctl','restart','crowdbastion-vps45-static'],capture_output=True,text=True,timeout=20)
 r.update(restart_exit=p.returncode,restart_stderr=p.stderr,rules_unchanged=before==rules(),existing_units_unchanged=pids==units(),units=units())
 assert p.returncode==0 and r['rules_unchanged'] and r['existing_units_unchanged']
print(json.dumps(r,ensure_ascii=False))

import pathlib,subprocess,time,json,os,re,shlex,hashlib
start=time.monotonic()
def run(args,timeout=30):
 t=time.monotonic()
 try:
  p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout);return p.returncode,p.stdout,round(time.monotonic()-t,2)
 except subprocess.TimeoutExpired as e:
  out=e.stdout or '';return 124,out.decode(errors='replace') if isinstance(out,bytes) else out,round(time.monotonic()-t,2)
def safe(s):
 return '\n'.join(re.sub(r'[A-Za-z0-9_+/=-]{32,}','<opaque-redacted>',line) for line in str(s).splitlines() if not re.search(r'(?i)api.?key|password|token|secret',line))
def note(name,data):print('ARM_RECOVERY '+json.dumps({'case':name,'data':safe(data)}),flush=True)
def result(name,rc,**a):print('ARM_RECOVERY_RESULT '+json.dumps({'case':name,'exit_code':rc,'assertions':a}),flush=True)
def active(unit):return run(['systemctl','is-active','--quiet',unit],5)[0]==0
print('ARM_RECOVERY_ENV '+json.dumps({'architecture':os.uname().machine,'pid1':pathlib.Path('/proc/1/comm').read_text().strip(),'installer_sha256':hashlib.sha256(pathlib.Path('/opt/test/repo/install-crowdsec-1panel.sh').read_bytes()).hexdigest()}),flush=True)
props=['ActiveState','SubState','Result','ExecMainStatus','ExecStartPre','TimeoutStartUSec','NRestarts','FragmentPath']
for unit in ['crowdsec','crowdsec-firewall-bouncer']:
 note('baseline_'+unit+'_properties',run(['systemctl','show',unit]+[x for p in props for x in ['-p',p]])[1])
 note('baseline_'+unit+'_journal',run(['journalctl','-b','-u',unit,'-n','20','--no-pager','-o','short-monotonic'])[1][-3500:])
rc,unit,_=run(['systemctl','cat','crowdsec']);note('actual_native_core_unit',unit)
for name in ['crowdsec','crowdsec-firewall-bouncer']:note('stop_'+name,run(['systemctl','stop',name],60)[0])
commands=[shlex.split(line.split('=',1)[1]) for line in unit.splitlines() if line.startswith('ExecStartPre=')]
if len(commands)==1 and commands[0][0]=='/usr/bin/crowdsec' and '-t' in commands[0]:
 rc,out,elapsed=run(commands[0],360);note('isolated_official_precheck_elapsed_seconds',elapsed);note('isolated_official_precheck_output',out[-1500:]);result('isolated_official_precheck',rc,successful=rc==0)
else:result('isolated_official_precheck',1,successful=False)
# Diagnostic-only controlled change in this cloned guest, not the installer.
d=pathlib.Path('/etc/systemd/system/crowdsec.service.d');d.mkdir(exist_ok=True);(d/'arm-diagnostic-timeout.conf').write_text('[Service]\nTimeoutStartSec=300\n')
run(['systemctl','daemon-reload']);run(['systemctl','reset-failed','crowdsec'])
rc,out,elapsed=run(['systemctl','start','crowdsec'],360);note('controlled_core_start_elapsed_seconds',elapsed);note('controlled_core_start_output',out)
result('controlled_core_start',rc,core_active=active('crowdsec'))
rc,out,elapsed=run(['systemctl','start','crowdsec-firewall-bouncer'],120);note('controlled_bouncer_start_output',out)
result('controlled_bouncer_start',rc,bouncer_active=active('crowdsec-firewall-bouncer'))
for action in ['add','delete']:
 args=['cscli','decisions',action,'--ip','198.51.100.79']
 if action=='add':args+=['--duration','10m']
 rc,out,elapsed=run(args,90);synced=False
 for _ in range(60):
  nr,no,_=run(['nft','-j','list','ruleset'],10)
  if nr==0 and ('198.51.100.79' in no)==(action=='add'):synced=True;break
  time.sleep(1)
 result('controlled_decision_'+action,rc,synced=synced)
for unit in ['crowdsec','crowdsec-firewall-bouncer']:
 note('controlled_'+unit+'_properties',run(['systemctl','show',unit]+[x for p in props for x in ['-p',p]])[1])
 note('controlled_'+unit+'_journal',run(['journalctl','-b','-u',unit,'-n','15','--no-pager','-o','short-monotonic'])[1][-3000:])
print('ARM_RECOVERY_COMPLETE',flush=True)
run(['systemctl','poweroff'])

"""Isolated real-journal acquisition proof; no production engine/restart or API."""
from pathlib import Path
import subprocess,os,json,yaml,socket,time,datetime,signal,shutil
base=Path('/var/backups/crowdbastion')/('vps179-realm-review-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
base.mkdir(mode=0o700);os.chmod(base,0o700)
config=base/'etc';shutil.copytree('/etc/crowdsec',config,symlinks=False)
# The production .local overrides metrics port; never carry it into an isolated clone.
(config/'config.yaml.local').unlink(missing_ok=True)
for name in ('logs','db','plugins'): (base/name).mkdir(mode=0o700)
# Empty profile file prevents notifications or remediation even if another scenario misbehaves.
(config/'profiles.yaml').write_text(yaml.safe_dump({'name':'isolated-never-remediate','filters':['false'],'decisions':[{'type':'ban','duration':'1m'}],'on_success':'break'},sort_keys=False))
(config/'acquis.yaml').write_text('');shutil.rmtree(config/'acquis.d');(config/'acquis.d').mkdir()
token=os.urandom(4).hex();units=['crowdbastion-realm-probe-a-'+token,'crowdbastion-realm-probe-b-'+token]
(config/'acquis.d/probe.yaml').write_text(yaml.safe_dump({'source':'journalctl','journalctl_filter':['_SYSTEMD_UNIT='+u+'.service' for u in units],'labels':{'type':'realm-forwardx'}},sort_keys=False))
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
api_port=port();metrics_port=port()
while metrics_port==api_port:metrics_port=port()
c=yaml.safe_load((config/'config.yaml').read_text())
c['common'].update(daemonize=False,log_media='stdout',log_dir=str(base/'logs'))
c['config_paths'].update(config_dir=str(config),simulation_path=str(config/'simulation.yaml'),notification_dir=str(config/'notifications'),plugin_dir=str(base/'plugins'))
c['crowdsec_service'].update(acquisition_path=str(config/'acquis.yaml'),acquisition_dir=str(config/'acquis.d'))
c['db_config']['db_path']=str(base/'db/crowdsec.db')
c['api']['client']['credentials_path']=str(config/'local_api_credentials.yaml')
c['api']['server'].update(listen_uri='127.0.0.1:'+str(api_port),profiles_path=str(config/'profiles.yaml'),console_path=str(config/'console.yaml'),online_client=None)
c['prometheus'].update(enabled=True,level='full',listen_addr='127.0.0.1',listen_port=metrics_port)
(config/'config.yaml').write_text(yaml.safe_dump(c,sort_keys=False))
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backup':str(base),'test_units':units,'isolated_api_port':api_port,'isolated_metrics_port':metrics_port,'production_api_untouched':True,'production_services_restarted':False}
proc=None;output=None

def call(args,t=40):
 p=subprocess.run(args,capture_output=True,text=True,timeout=t)
 if p.returncode:raise RuntimeError(str(args[:4])+': '+p.stdout[-1000:]+p.stderr[-1200:])
 return p.stdout

def cancel(signum,frame):raise InterruptedError('cancelled '+str(signum))
for s in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(s,cancel)
try:
 call(['cscli','-c',str(config/'config.yaml'),'machines','add','realm-isolated-probe','--auto','-f',str(config/'local_api_credentials.yaml'),'--url','http://127.0.0.1:'+str(api_port)])
 call(['crowdsec','-c',str(config/'config.yaml'),'-t','-no-capi'])
 output=(base/'engine.log').open('w');proc=subprocess.Popen(['crowdsec','-c',str(config/'config.yaml'),'-no-capi'],stdout=output,stderr=subprocess.STDOUT)
 until=time.monotonic()+35
 while time.monotonic()<until:
  if proc.poll() is not None:raise RuntimeError('isolated core exited: '+(base/'engine.log').read_text()[-2000:])
  followed=False
  for p in Path('/proc').glob('[0-9]*'):
   try:
    if (p/'comm').read_text().strip()!='journalctl':continue
    if 'PPid:\t'+str(proc.pid)+'\n' not in (p/'status').read_text():continue
    argv=(p/'cmdline').read_bytes().decode().split('\0')
    followed=all('_SYSTEMD_UNIT='+u+'.service' in argv for u in units)
    if followed:break
   except OSError:pass
  if followed:break
  time.sleep(.2)
 else:raise RuntimeError('isolated journal follower not ready')
 stamp=datetime.datetime.now().strftime('[%Y-%m-%d][%H:%M:%S]')
 msgs=[stamp+'[realm_core::tcp::socket][WARN][tcp]isolated journal acquisition probe',stamp+'[realm_core::tcp][ERROR][tcp]isolated journal acquisition probe']
 r['unit_progress']={}
 def current_metrics():return json.loads(call(['cscli','-c',str(config/'config.yaml'),'metrics','show','-o','json']))
 def parsed_count(m):return sum(v.get('parsed',0) for k,v in m.get('acquisition',{}).items() if token in k)
 for unit,msg in zip(units,msgs):
  initial=parsed_count(current_metrics());observed=initial
  # The ephemeral emitter stays alive briefly for journald attribution. A bounded
  # retry handles follower startup before journalctl has attached its cursor.
  for attempt in range(3):
   call(['systemd-run','--quiet','--collect','--wait','--unit',unit,'/usr/bin/python3','-c','import time; print('+repr(msg)+',flush=True); time.sleep(.2)'])
   until=time.monotonic()+2
   while time.monotonic()<until:
    m=current_metrics();observed=parsed_count(m)
    if observed>initial:break
    time.sleep(.2)
   if observed>initial:break
  if observed<=initial:raise RuntimeError('no parsed event from controlled journal source '+unit)
  r['unit_progress'][unit]={'parsed_before':initial,'parsed_after':observed,'attempts':attempt+1}
 m=current_metrics();acq={k:v for k,v in m.get('acquisition',{}).items() if token in k};parser={k:v for k,v in m.get('parsers',{}).items() if 'realm-forwardx' in k}
 r['effective_db_is_private']=c['db_config']['db_path'].startswith(str(base)+'/');r['local_override_removed']=not (config/'config.yaml.local').exists();r['acquisition']=acq;r['parsers']=parser;r['alerts']=m.get('alerts',{});r['decisions']=m.get('decisions',{})
 assert not r['alerts'] and not r['decisions'],'unexpected isolated scenario activity'
 r['status']='passed'
except BaseException as error:r['status']='failed';r['error']=str(error)
finally:
 for s in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(s,signal.SIG_IGN)
 if proc:
  proc.terminate()
  try:proc.wait(timeout=10)
  except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
  r['isolated_core_stopped']=proc.poll() is not None
 if output:output.close()
 r['test_units_inactive']={}
 for u in units:
  p=subprocess.run(['systemctl','is-active',u],capture_output=True,text=True,timeout=5)
  if p.stdout.strip()=='active':subprocess.run(['systemctl','stop',u],capture_output=True,timeout=10)
  r['test_units_inactive'][u]=p.stdout.strip()!='active'
 (base/'journal-proof.json').write_text(json.dumps(r,ensure_ascii=False,indent=2));print(json.dumps(r,ensure_ascii=False,indent=2))
assert r['status']=='passed',r.get('error')

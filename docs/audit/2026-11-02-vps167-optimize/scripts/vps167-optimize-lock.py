import json,os,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/opt/crowdbastion/releases/vps167-optimize-20261102-f592721e5d3e/lib')
from crowdsec_bot_runtime import maintenance_guard
release='/opt/crowdbastion/releases/vps167-optimize-20261102-f592721e5d3e/crowdbastion.sh'
env=dict(os.environ);env.pop('MAINTENANCE_LOCK_HELD',None)
r={'checked_at':time.time(),'method':'Real parent maintenance_guard held; child must independently refuse.'}
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 for name,argv in [('daily_cli',['/usr/local/bin/crowdbastion','--vps167-lock-probe']),('source_operation',['bash','-c','source "$1"; probe() { printf "%s\\n" SHOULD_NOT_RUN; }; locked_operation probe','vps167-lock-probe',release])]:
  p=subprocess.run(argv,capture_output=True,text=True,env=env,timeout=10);r[name]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
  assert p.returncode==75 and 'SHOULD_NOT_RUN' not in p.stdout+p.stderr
print(json.dumps(r,ensure_ascii=False,indent=2))

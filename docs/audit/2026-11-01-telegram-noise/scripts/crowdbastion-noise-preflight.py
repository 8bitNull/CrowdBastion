from pathlib import Path
import hashlib,json,subprocess,sys,time
base=Path('/opt/crowdbastion/releases/tg-responsive-20261101-73c519efafda')
sys.path.insert(0,str(base/'lib'))
from crowdbastion_ux import code_fingerprint
from crowdsec_bot_runtime import validate_runtime_pointer
from crowdsec_notify import load_config
from crowdsec_notify_client import request
expected='73c519efafda0ac96a6614621ff7b163c285363f124cb12dfaa6ea412afe48cc'
root=Path('/root/crowdsec-1key')
runtime=Path('/usr/local/lib/crowdsec-1key-bot/runtime')
validate_runtime_pointer(runtime)
assert all(code_fingerprint(p)==expected for p in [base/'crowdbastion.sh',root/'crowdbastion.sh',runtime/'current/manager.sh'])
assert Path('/usr/local/bin/crowdbastion').read_text()=='#!/bin/sh\n# CrowdBastion managed entry; execute the complete release.\nexec /bin/bash "'+str(base/'crowdbastion.sh')+'" "$@"\n'
config=load_config('/etc/crowdsec/crowdbastion-notify.json')
status=request(config,'status')
assert status['state']=='ready' and status['retrying']==0
units=['crowdsec','crowdsec-firewall-bouncer','crowdbastion-notify','crowdsec-1key-bot','docker']
services={}
for unit in units:
    services[unit]=dict(line.split('=',1) for line in subprocess.check_output(['systemctl','show',unit,'--property=ActiveState,UnitFileState,MainPID,NRestarts'],text=True).splitlines() if '=' in line)
    assert services[unit]['ActiveState']=='active'
helpers=['crowdsec_notify.py','crowdsec_notify_client.py','crowdsec_bot_api.py','crowdsec_bot_health.py','crowdbastion_health.py','crowdbastion_node.py','crowdsec_bot_runtime.py','crowdbastion_ux.py']
assert all((Path('/usr/local/lib/crowdbastion-notify')/name).read_bytes()==(base/'lib'/name).read_bytes() for name in helpers)
print(json.dumps({'checked_at':time.time(),'base':str(base),'fingerprint':expected,'bot_runtime_current':str((runtime/'current').readlink()),'services':services,'status':status,'policy':{key:config['policy'][key] for key in ['attention_interval_seconds','digest_seconds','cooldown_seconds']},'notify_helpers':{name:hashlib.sha256((base/'lib'/name).read_bytes()).hexdigest() for name in helpers}},indent=2))

from pathlib import Path
import hashlib,json,os,subprocess,sys,time
os.umask(0o077)
old=Path('/opt/crowdbastion/releases/review-20261101-vps179-29689b60aa54')
sys.path.insert(0,str(old/'lib'))
from crowdbastion_ux import code_fingerprint
cfg=Path('/etc/crowdsec/crowdsec-1key-bot.json')
settings=json.loads(cfg.read_bytes())
state=Path(settings.get('state_dir','/var/lib/crowdsec-1key-bot'))
installed=Path('/usr/local/lib/crowdsec-1key-bot')
services={}
for unit in ['crowdsec','crowdsec-firewall-bouncer','crowdsec-1key-bot','crowdbastion-notify','docker']:
    p=subprocess.run(['systemctl','show',unit,'--property=ActiveState,UnitFileState,MainPID,NRestarts,ExecMainStartTimestamp'],capture_output=True,text=True,check=True)
    services[unit]=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
report={'checked_at':time.time(),'source_fingerprint':code_fingerprint(old/'crowdbastion.sh'),
        'root_fingerprint':code_fingerprint('/root/crowdsec-1key/crowdbastion.sh'),
        'bot_manager_fingerprint':code_fingerprint(installed/'runtime/current/manager.sh'),
        'bot_code_sha256':hashlib.sha256((installed/'crowdsec_bot.py').read_bytes()).hexdigest(),
        'config_sha256':hashlib.sha256(cfg.read_bytes()).hexdigest(),
        'offsets':{p.name:int(p.read_text()) for p in state.glob('offset-*')},
        'audits':{p.name:{'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in state.glob('bot-actions-*.jsonl*')},
        'services':services,'entry_sha256':hashlib.sha256(Path('/usr/local/bin/crowdbastion').read_bytes()).hexdigest()}
print(json.dumps(report,indent=2))

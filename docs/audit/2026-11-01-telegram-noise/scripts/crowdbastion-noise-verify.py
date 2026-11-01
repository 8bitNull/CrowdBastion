from pathlib import Path
import hashlib,json,os,subprocess,sys,time
meta=json.loads(Path('/tmp/crowdbastion-noise-deployment.json').read_text())
release,backup,bundled=[Path(meta[k]) for k in ['release','backup','bundled']]
sys.path.insert(0,str(release/'lib'))
from crowdsec_notify import load_config
from crowdsec_notify_client import request
from crowdbastion_ux import code_fingerprint
config=load_config('/etc/crowdsec/crowdbastion-notify.json')
deployment=json.loads((backup/'deployment.json').read_text())
before=json.loads((backup/'before.json').read_text())
assert config['policy']['attention_interval_seconds']==3600 and config['policy']['digest_seconds']==21600
code=release/'lib/crowdsec_notify.py'
assert hashlib.sha256(code.read_bytes()).hexdigest()==meta['notify_sha256']
assert code.read_bytes()==Path('/usr/local/lib/crowdbastion-notify/crowdsec_notify.py').read_bytes()
assert all(code_fingerprint(p)==meta['fingerprint'] for p in [release/'crowdbastion.sh',Path('/root/crowdsec-1key/crowdbastion.sh'),Path('/usr/local/lib/crowdsec-1key-bot/runtime/current/manager.sh')])
# Only the notification file differs from the previous complete manager release.
base=Path(meta['base'])
changed=[]
for path in base.rglob('*'):
    relative=path.relative_to(base);candidate=release/relative
    if path.is_symlink():assert candidate.is_symlink() and os.readlink(candidate)==os.readlink(path)
    elif path.is_file() and path.read_bytes()!=candidate.read_bytes():changed.append(str(relative))
assert changed==['lib/crowdsec_notify.py']
status=request(config,'status');assert status['state']=='ready'
assert time.time()-status['health_age']>=deployment['started_at']
services={}
for unit,old in deployment['services_after'].items():
    services[unit]=dict(line.split('=',1) for line in subprocess.check_output(['systemctl','show',unit,'--property=ActiveState,UnitFileState,MainPID,NRestarts'],text=True).splitlines() if '=' in line)
    assert services[unit]==old
assert all(hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest for name,digest in before['protected'].items())
assert all(int(Path(name).read_text())>=value for name,value in before['offset'].items())
# Bot live diagnostics, without getUpdates or sending a Telegram test message.
sys.path.insert(0,'/usr/local/lib/crowdsec-1key-bot')
import crowdsec_bot as bot
bot.load_settings('/etc/crowdsec/crowdsec-1key-bot.json')
assert code_fingerprint(bot.MANAGER_SCRIPT)==meta['fingerprint']
poll=bot.sibling('crowdsec_bot_api').read_runtime(bot.STATE_DIR,bot.BOT_TOKEN)
assert poll['status']=='healthy' and poll['last_poll_at']>=deployment['started_at']
start=time.monotonic()
terminal=subprocess.run(['/usr/local/bin/crowdbastion','--status-json'],capture_output=True,text=True,timeout=25)
health=json.loads(terminal.stdout)
assert terminal.returncode in (0,2)
assert health['summary']['verdict']=='运行检查通过，实际拦截待验证'
report={'checked_at':time.time(),'fingerprint':meta['fingerprint'],'notify_sha256':meta['notify_sha256'],'manager_changed_files':changed,'policy':deployment['policy'],'status':status,'services':services,'protected_files_preserved':len(before['protected']),'bot_poller':{key:poll.get(key) for key in ['status','last_poll_at','checked_at']},'health':{'seconds':round(time.monotonic()-start,3),'exit':terminal.returncode,'summary':health['summary'],'traffic':health['checks'].get('traffic')},'telegram_test_sent':False,'elapsed_six_hours_observed':False}
path=backup/'verification.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');path.chmod(0o600)
print(json.dumps(report,ensure_ascii=False,indent=2))

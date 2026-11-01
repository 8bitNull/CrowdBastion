from pathlib import Path
import hashlib,json,os,subprocess,sys,threading,time
os.umask(0o077)
meta=json.loads(Path('/tmp/crowdbastion-responsive-deployment.json').read_text())
release,backup=Path(meta['release']),Path(meta['backup'])
installed=Path('/usr/local/lib/crowdsec-1key-bot')
sys.path.insert(0,str(installed))
import crowdsec_bot as bot
from crowdbastion_ux import code_fingerprint
bot.load_settings('/etc/crowdsec/crowdsec-1key-bot.json')
report={'checked_at':time.time(),'release_fingerprint':code_fingerprint(release/'crowdbastion.sh'),
        'root_fingerprint':code_fingerprint('/root/crowdsec-1key/crowdbastion.sh'),
        'bot_manager_fingerprint':code_fingerprint(bot.MANAGER_SCRIPT)}
assert all(report[k]==meta['fingerprint'] for k in ['release_fingerprint','root_fingerprint','bot_manager_fingerprint'])
for name,digest in meta['file_hashes'].items():
    assert hashlib.sha256((release/name).read_bytes()).hexdigest()==digest
assert (installed/'crowdsec_bot.py').read_bytes()==(release/'lib/crowdsec_bot.py').read_bytes()
start=time.monotonic()
terminal=subprocess.run(['/usr/local/bin/crowdbastion','--status-json'],capture_output=True,text=True,timeout=25)
report['terminal_seconds']=round(time.monotonic()-start,3)
report['terminal_exit']=terminal.returncode
report['terminal']=json.loads(terminal.stdout)
assert terminal.returncode==2
sent=[]
def telegram(endpoint,data=None):
    sent.append((endpoint,data))
    return {'ok':True,'result':{'message_id':90}}
bot.tg_request=telegram
original_health=bot.module_health_status
entered,finished=threading.Event(),threading.Event()
probe_times=[]
def health(**kwargs):
    entered.set();start=time.monotonic()
    try:return original_health(**kwargs)
    finally:probe_times.append(time.monotonic()-start)
bot.module_health_status=health
bot._HEALTH_WORKER=bot.HealthViewWorker()
def callback(data):
    return {'callback_query':{'id':'local-verification','from':{'id':bot.ADMIN_USER_ID},'data':data,
            'message':{'message_id':90,'chat':{'id':bot.ADMIN_CHAT_ID}}}}
try:
    started=time.monotonic();bot.handle_update(callback('nav:status'))
    report['enqueue_seconds']=round(time.monotonic()-started,6)
    assert entered.wait(1)
    started=time.monotonic();bot.handle_update(callback('nav:home'))
    report['home_during_probe_seconds']=round(time.monotonic()-started,6)
    assert bot._HEALTH_WORKER.submit('barrier',lambda:'done',lambda result:finished.set())
    assert finished.wait(25)
    report['complete_probe_seconds']=round(probe_times[0],3)
    edits=[payload for method,payload in sent if method=='editMessageText']
    assert len(edits)==1 and '主菜单' in edits[0]['text']
    report['stale_result_suppressed']=True
    report['health_brief']=original_health(details=False)
    report['health_details']=original_health(details=True)
    assert '检查结论：运行检查通过，实际拦截待验证' in report['health_brief']
    assert '实际拦截验证：待验证' in report['health_brief']
    assert '实际拦截验证通过' not in report['health_details']
    assert '采样：复用 30 秒内缓存' in report['health_brief']
    report['bot_report']=bot._HEALTH_COLLECTOR[1]._cached
    for key in ['checks','summary','scope']:assert report['bot_report'][key]==report['terminal'][key]
    before=bot._HEALTH_COLLECTOR[1]._cached_at
    started=time.monotonic();text,_=bot.render_view('status',force_refresh=True)
    report['fresh_seconds']=round(time.monotonic()-started,3)
    report['fresh_sample_completed_later']=bot._HEALTH_COLLECTOR[1]._cached_at>before
    assert report['fresh_sample_completed_later'] and '采样：本次采样' in text
finally:bot._HEALTH_WORKER.close()
report['verification_transport']='local stub; no Telegram message or getUpdates request was sent'
runtime=bot.sibling('crowdsec_bot_api').read_runtime(bot.STATE_DIR,bot.BOT_TOKEN)
report['poller']={k:runtime.get(k) for k in ['status','checked_at','last_poll_at','last_poll_attempt_at','last_send_at']}
assert runtime['status']=='healthy'
assert runtime['last_poll_at']>json.loads((backup/'deployment-result.json').read_text())['started_at']
instances=[]
for process in Path('/proc').glob('[0-9]*'):
    try:
        if str(installed/'crowdsec_bot.py').encode() in (process/'cmdline').read_bytes().split(b'\0'):instances.append(int(process.name))
    except OSError:pass
report['instances']=instances
assert len(instances)==1
protected=json.loads((backup/'protected.before.json').read_text())
assert all(hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest for name,digest in protected.items())
report['protected_configs_preserved']=len(protected)
report['services']={}
for unit in ['crowdsec','crowdsec-firewall-bouncer','crowdsec-1key-bot','crowdbastion-notify','docker']:
    out=subprocess.check_output(['systemctl','show',unit,'--property=ActiveState,UnitFileState,MainPID,NRestarts'],text=True)
    report['services'][unit]=dict(line.split('=',1) for line in out.splitlines() if '=' in line)
    assert report['services'][unit]['ActiveState']=='active' and report['services'][unit]['NRestarts']=='0'
(backup/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(report,ensure_ascii=False,indent=2))

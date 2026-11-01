from pathlib import Path
import hashlib,json,os,signal,sqlite3,subprocess,sys,tempfile,time
os.umask(0o077)
meta=json.loads(Path('/tmp/crowdbastion-noise-review-deployment.json').read_text())
base,release,backup,bundled=[Path(meta[k]) for k in ['base','release','backup','bundled']]
sys.path.insert(0,str(base/'lib'))
from crowdbastion_ux import code_fingerprint,validate_private_destination
from crowdsec_bot_runtime import maintenance_guard,validate_runtime_pointer
from crowdsec_notify import load_config,validate_config
from crowdsec_notify_client import request
unit='crowdbastion-notify.service'
config_path=Path('/etc/crowdsec/crowdbastion-notify.json')
installed=Path('/usr/local/lib/crowdbastion-notify/crowdsec_notify.py')
root_source=Path('/root/crowdsec-1key/lib/crowdsec_notify.py')
entry=Path('/usr/local/bin/crowdbastion')
current=Path('/usr/local/lib/crowdsec-1key-bot/runtime/current')
units=['crowdsec','crowdsec-firewall-bouncer','crowdsec-1key-bot','docker','crowdbastion-notify']

def services():
    return {unit:dict(line.split('=',1) for line in subprocess.check_output(['systemctl','show',unit,'--property=ActiveState,UnitFileState,MainPID,NRestarts'],text=True).splitlines() if '=' in line) for unit in units}
def private_json(path,data):
    path.write_text(json.dumps(data,indent=2)+'\n');path.chmod(0o600)
def atomic(path,data,mode):
    validate_private_destination(path)
    fd,temp=tempfile.mkstemp(prefix='.noise-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.lexists(temp):os.unlink(temp)
def pointer(target):
    temporary=current.parent/('.noise-pointer-'+str(os.getpid()))
    assert not os.path.lexists(temporary)
    try:
        os.symlink(target,temporary);os.replace(temporary,current)
    finally:
        if os.path.lexists(temporary):temporary.unlink()
def queue_state(config,make_backup=False):
    result={}
    for path in Path(config['state_dir']).glob('*.sqlite3'):
        assert not path.is_symlink()
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=5) as db:
            assert db.execute('PRAGMA quick_check').fetchone()==('ok',)
            result[path.name]={'inode':path.stat().st_ino,'incidents':[r[0] for r in db.execute('SELECT id FROM incidents')],'events':[r[0] for r in db.execute('SELECT fingerprint FROM events')],'meta':dict(db.execute('SELECT key,value FROM meta WHERE key IN (\'attention\',\'digest\',\'api_retry\',\'last_delivery\')'))}
            if make_backup:
                destination=backup/('consistent-'+path.name)
                assert not destination.exists()
                with sqlite3.connect(destination) as snapshot:
                    db.backup(snapshot);assert snapshot.execute('PRAGMA quick_check').fetchone()==('ok',)
                destination.chmod(0o600)
    return result

def interrupt(signum,frame):raise InterruptedError('deployment interrupted')
for sig in [signal.SIGINT,signal.SIGTERM]:signal.signal(sig,interrupt)
started=time.time()
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
    old_fingerprint='54a673a20f56acfc7b84e21b3bc1121429a34859e07405afdcd212b9edee619d'
    validate_runtime_pointer(current.parent)
    assert os.readlink(current)==meta['old_pointer']
    assert code_fingerprint(release/'crowdbastion.sh')==meta['fingerprint']==code_fingerprint(bundled/'manager.sh')
    assert all(code_fingerprint(p)==old_fingerprint for p in [base/'crowdbastion.sh',root_source.parent.parent/'crowdbastion.sh',current/'manager.sh'])
    original_config=config_path.read_bytes()
    parsed=load_config(config_path)
    assert parsed['enabled']
    assert parsed['policy']['attention_interval_seconds']==3600 and parsed['policy']['digest_seconds']==21600
    proposed=parsed
    candidate_code=(release/'lib/crowdsec_notify.py').read_bytes()
    assert hashlib.sha256(candidate_code).hexdigest()==meta['notify_sha256']
    assert installed.read_bytes()==root_source.read_bytes()==(base/'lib/crowdsec_notify.py').read_bytes()
    assert entry.read_text()=='#!/bin/sh\n# CrowdBastion managed entry; execute the complete release.\nexec /bin/bash "'+str(base/'crowdbastion.sh')+'" "$@"\n'
    before_services=services()
    assert all(v['ActiveState']=='active' and v['UnitFileState']=='enabled' for v in before_services.values())
    protected_files=[Path(p) for p in ['/etc/crowdsec/crowdbastion-notify.json','/etc/crowdsec/config.yaml','/etc/crowdsec/config.yaml.local','/etc/crowdsec/crowdsec-1key-bot.json','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/var/lib/crowdbastion/node-roles.json'] if Path(p).is_file()]
    protected_files+=list(Path('/etc/crowdsec').glob('profiles*.yaml'))+list(Path('/etc/crowdsec/notifications').glob('*.yaml'))
    protected={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in protected_files}
    offset_before={str(p):int(p.read_text()) for p in Path('/var/lib/crowdsec-1key-bot').glob('offset-*')}
    audit_before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/var/lib/crowdsec-1key-bot').glob('bot-actions-*.jsonl*')}
    replacements=[(installed,candidate_code,0o600),(root_source,candidate_code,0o644),(entry,('#!/bin/sh\n# CrowdBastion managed entry; execute the complete release.\nexec /bin/bash "'+str(release/'crowdbastion.sh')+'" "$@"\n').encode(),0o755)]
    originals={str(path):path.read_bytes() for path,data,mode in replacements}
    modes={str(path):path.stat().st_mode & 0o777 for path,data,mode in replacements}
    config_backup=backup/'notify-config.before.json';config_backup.write_bytes(original_config);config_backup.chmod(0o600)
    for number,(path,data,mode) in enumerate(replacements):
        validate_private_destination(path)
        dest=backup/(str(number)+'-'+path.name+'.before');dest.write_bytes(originals[str(path)]);dest.chmod(0o600)
    private_json(backup/'before.json',{'started_at':started,'services':before_services,'protected':protected,'offset':offset_before,'audit':audit_before,'old_pointer':meta['old_pointer'],'original_modes':modes})
    private_json(backup/'queue-before-stop.json',queue_state(parsed,True))
    stop_attempted=False;pointer_changed=False;published=[]
    try:
        stop_attempted=True
        subprocess.run(['systemctl','stop',unit],check=True,timeout=15)
        stopped=subprocess.check_output(['systemctl','show',unit,'--property=ActiveState','--value'],text=True).strip()
        assert stopped=='inactive'
        queue_before=queue_state(parsed)
        private_json(backup/'queue-stopped.json',queue_before)
        for path,data,mode in replacements:
            # Record before writing so rollback includes a publish followed by fsync failure.
            published.append(path)
            atomic(path,data,mode)
        pointer_changed=True;pointer(str(bundled))
        assert code_fingerprint(root_source.parent.parent/'crowdbastion.sh')==meta['fingerprint']
        runner='import runpy,sys;from pathlib import Path;sys.path.insert(0,str(Path(sys.argv[1]).parent));sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name="__main__")'
        check=subprocess.run(['python3','-I','-B','-c',runner,str(installed),'check',str(config_path)],capture_output=True,timeout=8)
        assert check.returncode==0,'installed configuration check failed'
        subprocess.run(['systemctl','start',unit],check=True,timeout=15)
        ready_deadline=time.monotonic()+20
        while time.monotonic()<ready_deadline:
            try:
                status=request(proposed,'status')
                if status['state']=='ready' and status['health_age'] is not None:break
            except (OSError,ValueError):pass
            time.sleep(0.5)
        else:raise RuntimeError('notification readiness check failed')
        after_services=services()
        for name in units:
            assert after_services[name]['ActiveState']=='active' and after_services[name]['UnitFileState']==before_services[name]['UnitFileState']
            if name!='crowdbastion-notify':assert after_services[name]==before_services[name]
        assert after_services['crowdbastion-notify']['MainPID']!=before_services['crowdbastion-notify']['MainPID']
        assert {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in protected_files}==protected
        assert all(int(Path(p).read_text())>=v for p,v in offset_before.items())
        assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==v for p,v in audit_before.items())
        queue_after=queue_state(proposed)
        for name,record in queue_before.items():
            assert record['inode']==queue_after[name]['inode']
            assert set(record['incidents'])<=set(queue_after[name]['incidents']) and set(record['events'])<=set(queue_after[name]['events'])
        report={'started_at':started,'completed_at':time.time(),'release':str(release),'backup':str(backup),'fingerprint':meta['fingerprint'],'notify_sha256':meta['notify_sha256'],'policy':{key:proposed['policy'][key] for key in ['attention_interval_seconds','digest_seconds','cooldown_seconds']},'only_policy_fields_changed':[],'services_before':before_services,'services_after':after_services,'status':status,'protected_files_preserved':len(protected),'offset_files_retained':len(offset_before),'audit_files_retained':len(audit_before),'queues':[{'name':name,'inode_preserved':True,'retained_incidents':len(row['incidents']),'retained_events':len(row['events'])} for name,row in queue_before.items()],'isolated_check_exit':check.returncode,'explicit_telegram_test_sent':False}
        private_json(backup/'deployment.json',report)
    except BaseException:
        for sig in [signal.SIGINT,signal.SIGTERM]:signal.signal(sig,signal.SIG_IGN)
        rollback=[]
        if stop_attempted:
            stopped=subprocess.run(['systemctl','stop',unit],timeout=15).returncode==0
            if stopped:
                try:
                    if pointer_changed:pointer(meta['old_pointer'])
                    for path in reversed(published):atomic(path,originals[str(path)],modes[str(path)])
                    subprocess.run(['systemctl','start',unit],check=True,timeout=15)
                    rollback.append('program/pointer restored; configuration unchanged; live queues retained')
                except BaseException:rollback.append('rollback incomplete; inspect private backups')
            else:rollback.append('could not stop notifier; files retained for manual recovery')
        private_json(backup/'rollback.json',{'at':time.time(),'actions':rollback})
        raise
print(json.dumps(report,indent=2))

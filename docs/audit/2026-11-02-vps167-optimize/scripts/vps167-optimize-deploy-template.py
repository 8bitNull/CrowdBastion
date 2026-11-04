# BACKUP, STAGE_SHA256 and ROLLBACK_SHA256 are injected after local verification.
import hashlib,json,os,runpy,signal,stat,subprocess,time
from pathlib import Path
os.umask(0o077)

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def run(argv):
    p=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    assert p.returncode==0,(argv[0],p.returncode)
    return p.stdout

def snapshot(paths):
    result={}
    for name in paths:
        p=Path(name)
        entries=[p,*sorted(p.rglob('*'))] if p.is_dir() and not p.is_symlink() else [p]
        for q in entries:
            if not q.exists() and not q.is_symlink():result[str(q)]={'exists':False};continue
            s=q.lstat();row={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
            if q.is_symlink():row['link']=os.readlink(q)
            elif q.is_file():row['sha256']=sha(q)
            else:assert q.is_dir(),str(q);row['directory']=True
            result[str(q)]=row
    return result

def services():
    return {u:dict(x.split('=',1) for x in run(['systemctl','show',u,'--property=MainPID,ActiveState,UnitFileState,NRestarts,ExecMainStartTimestamp']).splitlines() if '=' in x) for u in ['crowdsec','crowdsec-firewall-bouncer','docker']}

def containers():
    ids=run(['docker','ps','-aq']).split();items=json.loads(run(['docker','inspect',*ids]))
    return {x['Id']:{'name':x['Name'],'image':x['Image'],'started':x['State']['StartedAt'],'pid':x['State']['Pid'],'health':x['State'].get('Health',{}).get('Status'),'network':x['HostConfig']['NetworkMode']} for x in items}

def save(name,data):
    p=backup/name
    with p.open('x') as stream:json.dump(data,stream,indent=2);stream.write('\n')
    p.chmod(0o600)

def interrupted(signum,frame):raise InterruptedError('Deployment interrupted')
signal.signal(signal.SIGINT,interrupted);signal.signal(signal.SIGTERM,interrupted)
assert os.geteuid()==0
backup=Path(BACKUP)
assert sha(backup/'stage.json')==STAGE_SHA256 and sha(backup/'rollback-manager.py')==ROLLBACK_SHA256
rollback=runpy.run_path(str(backup/'rollback-manager.py'),run_name='vps167_rollback_module');stage=rollback['load_stage']()
from crowdsec_bot_runtime import maintenance_guard
from crowdsec_maintenance import fingerprint
from crowdbastion_ux import code_fingerprint
root=Path(stage['root']);next_root=Path(stage['next_root']);release=Path(stage['release']);maintenance=Path(stage['maintenance']);entry=Path(stage['entry']);cron=Path(stage['cron']);current=Path(stage['runtime'])/'current';saved=backup/'source-directory.before'
expected_protected=json.loads((backup/'protected-before.json').read_text())
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
    assert fingerprint(root)==stage['original_source_fingerprint'],'original source changed'
    assert fingerprint(next_root)==stage['prepared_source_fingerprint'],'prepared source changed'
    assert not current.exists() and not current.is_symlink() and not entry.exists() and not entry.is_symlink() and not saved.exists()
    for path in [root,entry.parent,cron.parent,current.parent]:
        for ancestor in [path,*path.parents]:
            s=ancestor.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,str(ancestor)
    assert sha(cron)==stage['cron_before_sha256']
    assert sha(backup/'entry.prepared')==stage['entry_after_sha256'] and sha(backup/'hub.cron.prepared')==stage['cron_after_sha256']
    assert snapshot(stage['protected_paths'])==expected_protected,'protected files changed'
    assert services()==stage['services_before'] and containers()==stage['containers_before'],'service/container identity changed'
    for binary,rules in stage['rules_before'].items():assert run([binary,'-w','5','-S'])==rules,'rules changed'
    for manager in [release/'crowdbastion.sh',maintenance/'manager.sh',next_root/'crowdbastion.sh']:
        assert code_fingerprint(manager)==stage['fingerprint']
    for name,digest in stage['package_hashes'].items():
        for base in [release,maintenance,next_root]:assert sha(base/name)==digest,'complete package mismatch'
    save('deployment-intent.json',{'started_at':time.time(),'stage_sha256':STAGE_SHA256,'scope':['source','daily entry','maintenance pointer','Hub cron']})
    temporary_entry=entry.with_name('.'+entry.name+'.vps167-'+stage['stamp']);temporary_cron=cron.with_name('.'+cron.name+'.vps167-'+stage['stamp'])
    try:
        os.rename(root,saved);os.rename(next_root,root)
        current.symlink_to(maintenance.name)
        with temporary_entry.open('xb') as stream:stream.write((backup/'entry.prepared').read_bytes())
        temporary_entry.chmod(0o755);os.link(temporary_entry,entry);temporary_entry.unlink()
        with temporary_cron.open('xb') as stream:stream.write((backup/'hub.cron.prepared').read_bytes())
        temporary_cron.chmod(stage['cron_mode']);assert sha(cron)==stage['cron_before_sha256'];os.replace(temporary_cron,cron)
        for manager in [root/'crowdbastion.sh',current/'manager.sh',release/'crowdbastion.sh']:
            assert code_fingerprint(manager)==stage['fingerprint']
            assert '--status-json' in run(['bash',str(manager),'--help'])
        assert sha(entry)==stage['entry_after_sha256'] and sha(cron)==stage['cron_after_sha256']
        assert snapshot(stage['protected_paths'])==expected_protected and services()==stage['services_before'] and containers()==stage['containers_before']
        for binary,rules in stage['rules_before'].items():assert run([binary,'-w','5','-S'])==rules
        assert fingerprint(saved)==stage['original_source_fingerprint']
        result={'completed_at':time.time(),'backup':str(backup),'release':str(release),'fingerprint':stage['fingerprint'],'manager_copies_match':True,'complete_resources_match':True,'protected_items_unchanged':len(expected_protected),'services_unchanged':True,'containers_unchanged':len(stage['containers_before']),'iptables_rules_unchanged':True,'root_crontab_unchanged':True,'hub_cron_restored':'30 3 * * *; existing Asia/Shanghai timezone','hub_update_executed':False,'original_source_preserved':True}
        save('deployment.json',result)
    except BaseException:
        try:save('rollback-automatic.json',rollback['restore'](stage))
        except BaseException as error:
            save('rollback-automatic-failed.json',{'error_type':type(error).__name__,'manual_review_required':True})
            raise
        raise
    finally:
        for p,digest in [(temporary_entry,stage['entry_after_sha256']),(temporary_cron,stage['cron_after_sha256'])]:
            if p.is_file() and not p.is_symlink() and sha(p)==digest:p.unlink()
print(json.dumps(result,ensure_ascii=False))

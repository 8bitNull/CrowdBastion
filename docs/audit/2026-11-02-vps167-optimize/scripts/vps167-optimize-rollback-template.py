# BACKUP and STAGE_SHA256 are injected as plain JSON literals.
import hashlib,json,os,stat,sys
from pathlib import Path


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_stage():
    backup=Path(BACKUP)
    assert sha(backup/'stage.json')==STAGE_SHA256,'stage changed'
    stage=json.loads((backup/'stage.json').read_text())
    release=Path(stage['release'])
    for name,digest in stage['package_hashes'].items():
        p=release/name;s=p.lstat()
        assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and sha(p)==digest,'release changed'
    sys.path.insert(0,str(release/'lib'))
    return stage


def replace_cron(path,content,mode):
    temporary=path.with_name('.'+path.name+'.vps167-rollback')
    with temporary.open('xb') as stream:stream.write(content)
    temporary.chmod(mode)
    os.replace(temporary,path)


def restore(stage,check_only=False):
    from crowdsec_maintenance import fingerprint
    backup=Path(stage['backup']);root=Path(stage['root']);saved=backup/'source-directory.before'
    current=Path(stage['runtime'])/'current';entry=Path(stage['entry']);cron=Path(stage['cron'])
    assert sha(cron) in (stage['cron_before_sha256'],stage['cron_after_sha256']),'cron changed; manual review required'
    if current.exists() or current.is_symlink():
        assert current.is_symlink() and os.readlink(current)==Path(stage['maintenance']).name,'current changed'
    if entry.exists() or entry.is_symlink():
        s=entry.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o755 and sha(entry)==stage['entry_after_sha256'],'entry changed'
    if saved.exists():
        assert fingerprint(saved)==stage['original_source_fingerprint'],'original source changed'
        if root.exists() or root.is_symlink():
            assert not root.is_symlink() and fingerprint(root)==stage['prepared_source_fingerprint'],'deployed source changed'
        assert not (backup/'source-directory.deployed').exists(),'rollback destination occupied'
    else:
        assert not root.is_symlink() and fingerprint(root)==stage['original_source_fingerprint'],'source state unknown'
    result={'check_only':check_only,'restores':['original source directory','original disabled Hub cron','daily entry absence','current pointer absence'],'preserves':['configuration','live databases','firewall','services','immutable release and staged maintenance artifacts']}
    if check_only:return result
    if sha(cron)==stage['cron_after_sha256']:
        content=(backup/'hub.cron.before').read_bytes();assert hashlib.sha256(content).hexdigest()==stage['cron_before_sha256']
        replace_cron(cron,content,stage['cron_mode'])
    if current.is_symlink():current.unlink()
    if entry.exists():entry.unlink()
    if saved.exists():
        if root.exists():os.rename(root,backup/'source-directory.deployed')
        os.rename(saved,root)
    assert fingerprint(root)==stage['original_source_fingerprint']
    assert sha(cron)==stage['cron_before_sha256'] and not current.is_symlink() and not entry.exists()
    (backup/'rollback-result.json').write_text(json.dumps(result,indent=2)+'\n');(backup/'rollback-result.json').chmod(0o600)
    return result


if __name__=='__main__':
    os.umask(0o077)
    assert os.geteuid()==0
    assert sys.argv[1:] in ([],['--check']),'usage: rollback-manager.py [--check]'
    stage=load_stage()
    from crowdsec_bot_runtime import maintenance_guard
    with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
        print(json.dumps(restore(stage,check_only=(sys.argv[1:]==['--check'])),ensure_ascii=False))

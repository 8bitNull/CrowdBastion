# PACKAGE, METADATA, PREFLIGHT, and ROLLBACK_CODE are injected locally.
import ast,base64,datetime,hashlib,io,json,os,re,shutil,stat,subprocess,sys,tarfile
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
release=Path('/opt/crowdbastion/releases/vps167-optimize-20261102-'+METADATA['fingerprint'][:12])
backup=Path('/var/backups/crowdbastion/vps167-optimize-'+stamp)
runtime=Path('/usr/local/lib/crowdsec-1key');maintenance=runtime/('release-vps167-optimize-20261102-'+METADATA['fingerprint'][:12])
root=Path('/root/crowdsec-1key');next_root=Path('/root/.crowdsec-1key.vps167-next-'+stamp)
cron=Path('/etc/cron.d/crowdsec-autoupdate');entry=Path('/usr/local/bin/crowdbastion')

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def run(argv):
    p=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    assert p.returncode==0,(argv[0],p.returncode)
    return p.stdout

def trusted_parent(p):
    for path in [p,*p.parents]:
        if path.exists() or path.is_symlink():
            s=path.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,str(path)

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

def check_preflight():
    for binary,rules in PREFLIGHT['rules'].items():assert run([binary,'-w','5','-S'])==rules,'rules changed'
    for path in [str(cron),'/var/spool/cron/crontabs/root']:
        assert sha(path)==PREFLIGHT['entries'][path]['sha256'],'cron changed'
    for path in [entry,runtime]:assert not path.exists() and not path.is_symlink(),str(path)
    for name,digest in PREFLIGHT['source_code_sha256'].items():assert sha(root/name)==digest,'source changed'

for p in [release,backup,maintenance,next_root]:
    trusted_parent(p.parent);assert not p.exists() and not p.is_symlink(),str(p)
check_preflight()
raw=base64.b64decode(PACKAGE);assert hashlib.sha256(raw).hexdigest()==METADATA['tar_sha256']
release.mkdir(mode=0o700,parents=True);release.chmod(0o700)
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
    members=archive.getmembers();assert len(members)==len(METADATA['file_hashes'])
    for member in members:
        assert member.name in METADATA['file_hashes'] and member.isfile()
        content=archive.extractfile(member).read();assert hashlib.sha256(content).hexdigest()==METADATA['file_hashes'][member.name]
        p=release/member.name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with p.open('xb') as stream:stream.write(content)
        p.chmod(0o700 if p.name=='crowdbastion.sh' else 0o600)
        if p.suffix=='.py':ast.parse(content,filename=str(p))
        if p.suffix=='.sh':run(['bash','-n',str(p)])
(release/'manager.sh').write_bytes((release/'crowdbastion.sh').read_bytes());(release/'manager.sh').chmod(0o700)
(release/'install-crowdsec-1panel.sh').symlink_to('crowdbastion.sh')
sys.path.insert(0,str(release/'lib'))
from crowdsec_bot_runtime import maintenance_guard
from crowdsec_maintenance import runtime_preflight,fingerprint
from crowdbastion_ux import code_fingerprint
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
    check_preflight();runtime_preflight(runtime)
    assert code_fingerprint(release/'crowdbastion.sh')==METADATA['fingerprint']
    backup.mkdir(mode=0o700,parents=True);backup.chmod(0o700)
    assert backup.stat().st_dev==root.stat().st_dev,'source backup must remain on same filesystem'
    shutil.copytree(root,next_root,symlinks=True)
    assert not (next_root/'lib').is_symlink();shutil.rmtree(next_root/'lib');shutil.copytree(release/'lib',next_root/'lib')
    for name in ['crowdbastion.sh','manager.sh','readme.md',*[n for n in METADATA['file_hashes'] if n.startswith('rules/')]]:
        q=next_root/name
        # Do not follow an old alias or an untrusted resource link when copying.
        for ancestor in q.parents:
            if ancestor==next_root:break
            assert not ancestor.is_symlink(),str(ancestor)
        q.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if q.is_symlink() or q.is_file():q.unlink()
        assert not q.exists(),str(q)
        shutil.copy2(release/name,q)
    q=next_root/'install-crowdsec-1panel.sh'
    if q.is_symlink() or q.is_file():q.unlink()
    assert not q.exists();q.symlink_to('crowdbastion.sh');next_root.chmod(0o700)
    runtime.mkdir(mode=0o700);runtime.chmod(0o700)
    (runtime/'.crowdsec-1key-managed').write_text('Managed VPS167 maintenance runtime\n');(runtime/'.crowdsec-1key-managed').chmod(0o600)
    shutil.copytree(release,maintenance,symlinks=True)
    assert code_fingerprint(next_root/'crowdbastion.sh')==METADATA['fingerprint']
    web=json.loads(Path('/etc/crowdsec/crowdsec-1key-web-installs.json').read_text())
    paths=['/etc/crowdsec','/var/lib/crowdbastion/node-roles.json','/var/spool/cron/crontabs/root','/etc/systemd/system/crowdsec-firewall-bouncer.service.d','/etc/iptables/rules.v4','/etc/iptables/rules.v6','/etc/crowdsec/crowdsec-1key-bot.json','/etc/crowdsec/crowdbastion-notify.json']
    paths += [v[k] for v in web.values() for k in ['host_assets','host_target']]
    protected=snapshot(paths)
    (backup/'protected-before.json').write_text(json.dumps(protected,indent=2)+'\n')
    with tarfile.open(backup/'config-and-web.before.tar.gz','w:gz') as archive:
        for name in [*paths,str(cron)]:
            if Path(name).exists():archive.add(name,arcname=str(Path(name)).lstrip('/'))
    original=cron.read_bytes();text=original.decode()
    lines=text.splitlines();matches=[i for i,line in enumerate(lines) if line.startswith('# crowdbastion: disabled duplicate updater: ') and re.search(r'30 3 \* \* \* root /usr/bin/cscli hub update',line)]
    assert len(matches)==1,'unrecognized Hub cron; refusing to guess'
    expected='# crowdbastion: disabled duplicate updater: 30 3 * * * root /usr/bin/cscli hub update >/dev/null 2>&1 && /usr/bin/cscli hub upgrade >/dev/null 2>&1 && /bin/systemctl reload crowdsec >/dev/null 2>&1'
    assert lines[matches[0]]==expected,'legacy command changed'
    lines[matches[0]]='30 3 * * * root /bin/bash /usr/local/lib/crowdsec-1key/current/manager.sh --update-hub >/dev/null 2>&1'
    if lines[0]=='# CrowdSec 每日规则库与黑名单自动同步':lines[0]='# CrowdSec Hub 检测规则更新；封禁决策由 Bouncer 持续同步。'
    prepared_cron=('\n'.join(lines)+'\n').encode()
    (backup/'hub.cron.before').write_bytes(original);(backup/'hub.cron.prepared').write_bytes(prepared_cron)
    wrapper=('#!/bin/sh\n# CrowdBastion managed entry; execute the complete release.\nexec /bin/bash '+json.dumps(str(release/'crowdbastion.sh'))+' "$@"\n').encode()
    (backup/'entry.prepared').write_bytes(wrapper)
    (backup/'root.crontab.before').write_text(run(['crontab','-u','root','-l']))
    for binary in ['iptables','ip6tables']:(backup/(binary+'-save.before.txt')).write_text(run([binary+'-save']))
    ids=run(['docker','ps','-aq']).split();inspected=json.loads(run(['docker','inspect',*ids]))
    containers={x['Id']:{'name':x['Name'],'image':x['Image'],'started':x['State']['StartedAt'],'pid':x['State']['Pid'],'health':x['State'].get('Health',{}).get('Status'),'network':x['HostConfig']['NetworkMode']} for x in inspected}
    stage={'stamp':stamp,'release':str(release),'backup':str(backup),'runtime':str(runtime),'root':str(root),'next_root':str(next_root),'maintenance':str(maintenance),'entry':str(entry),'cron':str(cron),'fingerprint':METADATA['fingerprint'],'package_hashes':METADATA['file_hashes'],'original_source_fingerprint':fingerprint(root),'prepared_source_fingerprint':fingerprint(next_root),'protected_paths':paths,'protected_items':len(protected),'cron_before_sha256':sha(backup/'hub.cron.before'),'cron_after_sha256':sha(backup/'hub.cron.prepared'),'cron_mode':stat.S_IMODE(cron.stat().st_mode),'entry_after_sha256':sha(backup/'entry.prepared'),'rules_before':PREFLIGHT['rules'],'root_crontab_metadata':PREFLIGHT['entries']['/var/spool/cron/crontabs/root'],'services_before':PREFLIGHT['units'],'containers_before':containers}
    (backup/'stage.json').write_text(json.dumps(stage,indent=2)+'\n')
    rollback='BACKUP='+json.dumps(str(backup))+'\nSTAGE_SHA256='+json.dumps(sha(backup/'stage.json'))+'\n'+ROLLBACK_CODE
    (backup/'rollback-manager.py').write_text(rollback);ast.parse(rollback)
    for p in backup.iterdir():p.chmod(0o600)
    assert run(['bash',str(release/'crowdbastion.sh'),'--help'])
print(json.dumps({'prepared':True,'backup':str(backup),'release':str(release),'maintenance':str(maintenance),'next_root':str(next_root),'fingerprint':METADATA['fingerprint'],'package_files':len(METADATA['file_hashes']),'rules_resources':[n for n in METADATA['file_hashes'] if n.startswith('rules/')],'protected_items':len(protected),'stage_sha256':sha(backup/'stage.json'),'rollback_sha256':sha(backup/'rollback-manager.py'),'hub_schedule':'30 3 * * *','hub_timezone':'Asia/Shanghai','hub_update_executed':False},ensure_ascii=False))

from pathlib import Path
import ast,hashlib,json,os,shutil,subprocess,sys,time
os.umask(0o077)
base=Path('/opt/crowdbastion/releases/tg-responsive-20261101-73c519efafda')
sys.path.insert(0,str(base/'lib'))
from crowdbastion_ux import code_fingerprint,validate_private_destination
from crowdsec_bot_runtime import validate_runtime_pointer
code=bytes.fromhex('__CANDIDATE_HEX__')
ast.parse(code)
sha=hashlib.sha256(code).hexdigest()
assert code_fingerprint(base/'crowdbastion.sh')=='73c519efafda0ac96a6614621ff7b163c285363f124cb12dfaa6ea412afe48cc'
release=base.parent/('tg-noise-20261101-'+sha[:12]+'-r2')
backup=Path('/var/backups/crowdbastion')/time.strftime('tg-noise-%Y%m%dT%H%M%SZ',time.gmtime())
runtime=Path('/usr/local/lib/crowdsec-1key-bot/runtime')
validate_runtime_pointer(runtime)
bundled=runtime/('release-'+str(int(time.time()))+'-noise')
for path in [release,backup,bundled]:
    validate_private_destination(path/'.guard',missing_parents=True)
    assert not path.exists()
shutil.copytree(base,release,symlinks=True)
(release/'lib/crowdsec_notify.py').write_bytes(code)
(release/'lib/crowdsec_notify.py').chmod(0o644)
release.chmod(0o700)
shutil.copytree(release/'lib',bundled/'lib',symlinks=True)
shutil.copy2(release/'crowdbastion.sh',bundled/'manager.sh')
bundled.chmod(0o700)
backup.mkdir(mode=0o700)
for path in release.rglob('*'):
    if not path.is_symlink():
        validate_private_destination(path/'.guard' if path.is_dir() else path)
fingerprint=code_fingerprint(release/'crowdbastion.sh')
assert fingerprint==code_fingerprint(bundled/'manager.sh')
runner='import sys;sys.path.insert(0,sys.argv[1]);import crowdsec_notify;crowdsec_notify.load_config("/etc/crowdsec/crowdbastion-notify.json")'
subprocess.run(['python3','-I','-B','-c',runner,str(release/'lib')],check=True,timeout=10)
report={'created_at':time.time(),'base':str(base),'release':str(release),'backup':str(backup),'bundled':str(bundled),'fingerprint':fingerprint,'notify_sha256':sha,'old_pointer':str((runtime/'current').readlink())}
path=backup/'stage.json';path.write_text(json.dumps(report,indent=2)+'\n');path.chmod(0o600)
path=Path('/tmp/crowdbastion-noise-deployment.json');path.write_text(json.dumps(report,indent=2)+'\n');path.chmod(0o600)
print(json.dumps(report,indent=2))

from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,sys,tarfile
os.umask(0o077)
root=Path('/projects/script/CrowdBastion')
sys.path.insert(0,str(root/'lib'))
from crowdbastion_ux import code_fingerprint
folder=root/'docs/audit/2026-11-01-telegram-responsive'
fingerprint=code_fingerprint(root/'crowdbastion.sh')
stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
files=[root/'crowdbastion.sh',root/'readme.md',*sorted(p for p in (root/'lib').rglob('*') if p.is_file() and '__pycache__' not in p.parts)]
archive=Path('/tmp/crowdbastion-responsive-release.tar.gz')
def normalize(info):
    info.uid=info.gid=0
    info.uname=info.gname='root'
    info.mode=0o755 if info.name.endswith('.sh') else 0o644
    return info
with tarfile.open(archive,'w:gz') as out:
    for p in files:
        assert not p.is_symlink()
        out.add(p,arcname=str(p.relative_to(root)),recursive=False,filter=normalize)
    out.add(root/'install-crowdsec-1panel.sh',arcname='install-crowdsec-1panel.sh',recursive=False,filter=normalize)
record={'fingerprint':fingerprint,'release':'/opt/crowdbastion/releases/tg-responsive-20261101-'+fingerprint[:12],
        'backup':'/var/backups/crowdbastion/tg-responsive-'+stamp,'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
        'file_hashes':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
(folder/'deployment.json').write_text(json.dumps(record,indent=2)+'\n')
print({k:v for k,v in record.items() if k!='file_hashes'})

from pathlib import Path
import base64,hashlib,io,json,sys,tarfile
root=Path('/projects/script/CrowdBastion-vps45-repair');folder=root/'docs/audit/2026-11-02-vps45-repair';sys.path.insert(0,str(root/'lib'))
from crowdbastion_ux import code_fingerprint
files=[root/'crowdbastion.sh',root/'readme.md',*sorted(p for p in (root/'lib').iterdir() if p.is_file() and p.suffix in ('.py','.sh','.lua'))]
payload=io.BytesIO()
with tarfile.open(fileobj=payload,mode='w:gz') as tar:
 for p in files:
  content=p.read_bytes();member=tarfile.TarInfo(str(p.relative_to(root)));member.size=len(content);member.uid=member.gid=0;member.mode=0o700 if p.name=='crowdbastion.sh' else 0o600;tar.addfile(member,io.BytesIO(content))
metadata={'fingerprint':code_fingerprint(root/'crowdbastion.sh'),'file_hashes':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},'tar_sha256':hashlib.sha256(payload.getvalue()).hexdigest()}
(folder/'package.json').write_text(json.dumps(metadata,indent=2)+'\n')
prefix='PACKAGE='+repr(base64.b64encode(payload.getvalue()).decode())+'\nMETADATA='+repr(metadata)+'\nSTATIC_CODE='+repr((folder/'scripts/static-policy.py').read_text())+'\nSTATIC_UNIT='+repr((folder/'scripts/crowdbastion-vps45-static.service').read_text())+'\nPREFLIGHT='+repr(json.loads((folder/'preflight.json').read_text()))+'\n'
Path('/tmp/vps45-repair-package-prefix.py').write_text(prefix)
print(json.dumps({k:v for k,v in metadata.items() if k!='file_hashes'},indent=2))

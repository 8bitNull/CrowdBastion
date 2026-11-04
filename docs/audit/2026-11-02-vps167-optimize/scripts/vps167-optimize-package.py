from pathlib import Path
import ast,base64,hashlib,io,json,os,subprocess,sys,tarfile
sys.dont_write_bytecode=True
root=Path('/projects/script/CrowdBastion-vps167-optimize');folder=root/'docs/audit/2026-11-02-vps167-optimize'
sys.path.insert(0,str(root/'lib'))
from crowdbastion_ux import code_fingerprint
names=['crowdbastion.sh','readme.md']+[str(p.relative_to(root)) for p in sorted((root/'lib').iterdir()) if p.is_file() and p.suffix in ('.py','.sh','.lua')]+[str(p.relative_to(root)) for p in sorted((root/'rules/v2bx').rglob('*')) if p.is_file()]
assert len([x for x in names if x.startswith('rules/')])==3
hashes={}
buffer=io.BytesIO()
with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
 for name in names:
  p=root/name;assert not p.is_symlink();content=p.read_bytes();hashes[name]=hashlib.sha256(content).hexdigest()
  if p.suffix=='.py':ast.parse(content,filename=name)
  if p.suffix=='.sh':subprocess.run(['bash','-n',str(p)],check=True,capture_output=True)
  info=tarfile.TarInfo(name);info.size=len(content);info.mode=0o700 if name=='crowdbastion.sh' else 0o600;archive.addfile(info,io.BytesIO(content))
raw=buffer.getvalue();metadata={'fingerprint':code_fingerprint(root/'crowdbastion.sh'),'tar_sha256':hashlib.sha256(raw).hexdigest(),'file_hashes':hashes}
(folder/'package.json').write_text(json.dumps(metadata,indent=2)+'\n');(folder/'package.json').chmod(0o600)
preflight=json.loads((folder/'preflight.json').read_text());rollback=Path('/tmp/vps167-optimize-rollback-template.py').read_text()
prefix='\n'.join(name+'='+repr(value) for name,value in [('PACKAGE',base64.b64encode(raw).decode()),('METADATA',metadata),('PREFLIGHT',preflight),('ROLLBACK_CODE',rollback)])+'\n'
content=prefix+Path('/tmp/vps167-optimize-stage-template.py').read_text();ast.parse(content)
p=Path('/tmp/vps167-optimize-stage.py');p.write_text(content);p.chmod(0o600)
print(json.dumps({'files':len(names),'fingerprint':metadata['fingerprint'],'tar_sha256':metadata['tar_sha256']}))

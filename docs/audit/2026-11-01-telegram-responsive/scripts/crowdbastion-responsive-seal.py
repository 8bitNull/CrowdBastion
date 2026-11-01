from pathlib import Path
import base64,hashlib,importlib.util,io,json,os,subprocess,tarfile,time
os.umask(0o077)
root=Path('/projects/script/CrowdBastion');folder=root/'docs/audit/2026-11-01-telegram-responsive'
meta=json.loads((folder/'deployment.json').read_text())
support=['docs/2026-10-13-custom-telegram-bot.md','docs/audit/README.md','docs/audit/2026-11-01-telegram-responsive.md','docs/superpowers/plans/2026-11-01-telegram-responsive.md','docs/superpowers/specs/2026-11-01-telegram-responsive-design.md']
paths=[root/name for name in support]+[p for p in sorted(folder.rglob('*')) if p.is_file() and p.name not in ['manifest.json','bundle-manifest.json','remote-seal.json']]
manifest={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
(folder/'bundle-manifest.json').write_text(json.dumps({'created_at':time.time(),'files':manifest},indent=2)+'\n')
paths.append(folder/'bundle-manifest.json')
buffer=io.BytesIO()
with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
    for path in paths:archive.add(path,arcname=str(path.relative_to(root)),recursive=False)
payload=buffer.getvalue()
remote=r'''
from pathlib import Path
import base64,hashlib,io,json,os,tarfile,time
import yaml
os.umask(0o077)
backup=Path(__BACKUP__)
payload=base64.b64decode(__PAYLOAD__)
assert hashlib.sha256(payload).hexdigest()==__DIGEST__
secrets=set()
def walk(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if str(key).lower() in ('bot_token','api_key','password','token','secret','api_secret') and isinstance(item,str) and len(item)>=12:secrets.add(item.encode())
            walk(item)
    elif isinstance(value,list):
        for item in value:walk(item)
for name in ('crowdsec-1key-bot.json','crowdbastion-notify.json','bouncers/crowdsec-firewall-bouncer.yaml','bouncers/crowdsec-firewall-bouncer.yaml.local','local_api_credentials.yaml','online_api_credentials.yaml'):
    path=Path('/etc/crowdsec')/name
    if path.is_file():walk(yaml.safe_load(path.read_text()))
leaks=[]
with tarfile.open(fileobj=io.BytesIO(payload),mode='r:gz') as archive:
    for member in archive:
        assert member.isfile() and not member.name.startswith('/') and '..' not in Path(member.name).parts
        data=archive.extractfile(member).read()
        if any(secret in data for secret in secrets):leaks.append(member.name)
assert not leaks,'credential value appears in audit artifact'
path=backup/'tg-responsive-audit.tar.gz'
with path.open('xb') as stream:stream.write(payload)
receipt={'completed_at':time.time(),'bundle_path':str(path),'bundle_sha256':hashlib.sha256(payload).hexdigest(),'bundle_files':__COUNT__,
         'credential_values_checked':len(secrets),'credential_value_leaks':leaks}
(backup/'audit-delivery.json').write_text(json.dumps(receipt,indent=2)+'\n')
files={}
for path in sorted(backup.rglob('*')):
    name=str(path.relative_to(backup))
    if name=='final-manifest.json':continue
    if path.is_symlink():files[name]={'type':'symlink','target':os.readlink(path)}
    elif path.is_file():files[name]={'type':'regular','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size}
manifest=backup/'final-manifest.json'
manifest.write_text(json.dumps({'sealed_at':time.time(),'files':files},indent=2)+'\n')
for name,item in files.items():
    path=backup/name
    if item['type']=='regular':assert hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256']
    else:assert os.readlink(path)==item['target']
print(json.dumps({**receipt,'backup_manifest_path':str(manifest),'backup_manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'backup_manifest_files':len(files)},indent=2))
'''
remote=remote.replace('__BACKUP__',repr(meta['backup'])).replace('__PAYLOAD__',repr(base64.b64encode(payload).decode())).replace('__DIGEST__',repr(hashlib.sha256(payload).hexdigest())).replace('__COUNT__',str(len(paths)))
spec=importlib.util.spec_from_file_location('repair','/tmp/vps179-repair-client.py');client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
result=subprocess.run(client.SSH+['env PYTHONDONTWRITEBYTECODE=1 python3 -B -'],input=remote.encode(),capture_output=True,timeout=55)
assert result.returncode==0,result.stderr.decode(errors='replace')[-1500:]
receipt=folder/'remote-seal.json';receipt.write_bytes(result.stdout)
print(result.stdout.decode())
files={str(p.relative_to(folder)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.rglob('*')) if p.is_file() and p.name!='manifest.json'}
(folder/'manifest.json').write_text(json.dumps({'sealed_at':time.time(),'files':files,'supporting_documents':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in support}},indent=2)+'\n')
print('Local final manifest files:',len(files))

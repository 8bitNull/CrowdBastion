from pathlib import Path
import hashlib,json,os,subprocess,time
root=Path('/projects/script/CrowdBastion')
folder=root/'docs/audit/2026-11-01-telegram-noise-review'
paths=sorted([root/'crowdbastion.sh',*root.glob('lib/*.py'),*root.glob('lib/*.sh'),*root.glob('tests/*.py'),*root.glob('lib/*.lua')])
def source():return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
before=source()
p=folder/'source-validated.json';p.write_text(json.dumps(before,indent=2)+'\n');p.chmod(0o600)
started=time.time()
p=folder/'full-suite.txt'
with p.open('w') as output:
    p.chmod(0o600)
    result=subprocess.run(['python3','-m','unittest','discover','-s','tests'],cwd=root,stdout=output,stderr=subprocess.STDOUT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':'tests:lib'})
after=source()
report={'exit':result.returncode,'seconds':time.time()-started,'source_files':len(before),'stable':before==after,'changed':[k for k in before if before[k]!=after.get(k)]}
p=folder/'full-suite-result.json';p.write_text(json.dumps(report,indent=2)+'\n');p.chmod(0o600)

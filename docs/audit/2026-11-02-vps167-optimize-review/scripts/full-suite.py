from pathlib import Path
import ast,datetime,hashlib,json,os,subprocess,time
root=Path('/projects/script/CrowdBastion-vps167-optimize');folder=root/'docs/audit/2026-11-02-vps167-optimize-review'
def sources():
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file() and p.suffix in ('.py','.sh','.lua') and not any(s.startswith('.') or s=='docs' for s in p.relative_to(root).parts)}
original_sources=sources
def sources():
 result=original_sources()
 helper=root/'docs/audit/2026-11-02-vps167-optimize-review/scripts/rollback-manager-v2.py'
 result[str(helper.relative_to(root))]=hashlib.sha256(helper.read_bytes()).hexdigest()
 return result
before=sources(); (folder/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
started=time.monotonic()
with (folder/'full-suite.txt').open('wb') as log:
 p=subprocess.run(['python3','-B','-m','unittest','discover','-s','tests','-q'],cwd=root,env={**os.environ,'PYTHONPATH':str(root/'lib'),'PYTHONDONTWRITEBYTECODE':'1'},stdout=log,stderr=subprocess.STDOUT)
after=sources();(folder/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
r={'exit':p.returncode,'seconds':time.monotonic()-started,'source_unchanged':before==after,'source_files':len(before),'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat()};(folder/'full-suite-result.json').write_text(json.dumps(r,indent=2)+'\n')
for p in folder.rglob('*'):p.chmod(0o700 if p.is_dir() else 0o600)
raise SystemExit(0 if r['exit']==0 and r['source_unchanged'] else 1)

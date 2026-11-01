from pathlib import Path
import ast, hashlib, json, os, subprocess, time
os.umask(0o077)
root=Path('/projects/script/CrowdBastion')
folder=root/'docs/audit/2026-11-01-telegram-responsive'
files=sorted(set(json.loads((root/'docs/audit/2026-11-01-vps179-review/source-after.json').read_text()))|{'tests/test_telegram_responsive.py'})
hashes={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}
(folder/'source-validated.json').write_text(json.dumps(hashes,indent=2)+'\n')
started=time.time()
with (folder/'full-suite.txt').open('w') as output:
    result=subprocess.run(['python3','-m','unittest','discover','-s','tests'],cwd=root,stdout=output,stderr=subprocess.STDOUT,
        env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':'tests:lib'})
assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==value for name,value in hashes.items())
(folder/'full-suite-result.json').write_text(json.dumps({'exit':result.returncode,'seconds':time.time()-started,'source_files':len(files)},indent=2)+'\n')

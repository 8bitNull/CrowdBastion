from pathlib import Path
import json,runpy,subprocess,time
folder=Path('/projects/script/CrowdBastion/docs/audit/2026-11-01-telegram-noise')
verification=json.loads((folder/'full-suite-result.json').read_text())
assert verification['exit']==0 and verification['stable']
ssh=runpy.run_path('/tmp/vps179-repair-client.py')['SSH']
started=time.time()
result=subprocess.run(ssh+['env PYTHONDONTWRITEBYTECODE=1 python3 -B -'],input=Path('/tmp/crowdbastion-noise-deploy.py').read_bytes(),capture_output=True,timeout=150)
for name,data in [('vps-deployment.json',result.stdout),('vps-deployment-stderr.txt',result.stderr),('vps-deployment-client.json',(json.dumps({'exit':result.returncode,'seconds':time.time()-started},indent=2)+'\n').encode())]:
    path=folder/name;path.write_bytes(data);path.chmod(0o600)

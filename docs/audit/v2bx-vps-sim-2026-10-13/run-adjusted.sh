#!/bin/bash
cd /workspace
python3 - <<'INNER'
import subprocess,time,json
args=['/bin/python3','/workspace/tests/verify_relay_network.py','--probe','127.0.0.1','1','tcp']
start=time.monotonic();children=[subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL) for _ in range(5)]
rows=[]
for process in children:
 process.wait(timeout=30);rows.append({'returncode':process.returncode,'elapsed_seconds':round(time.monotonic()-start,3)})
print('PROBE_STARTUP_LOADED '+json.dumps(rows),flush=True)
INNER
python3 tests/verify_remote_bouncer.py --output /tmp/remote-results.json
remote_result=$?
python3 landing.py
landing_result=$?
python3 - <<'PY'
import json
from pathlib import Path
results={'scope':'isolated no-NIC QEMU network simulation; real CrowdSec LAPI/Bouncer; no V2bX protocol handshake or bandwidth benchmark', 'remote':json.loads(Path('/tmp/remote-results.json').read_text()), 'landing':json.loads(Path('/tmp/landing-results.json').read_text())}
results['status']='passed' if all(results[k]['status']=='passed' for k in ('remote','landing')) else 'failed'
Path('/tmp/results.json').write_text(json.dumps(results,indent=2)+'\n')
PY
[[ $remote_result -eq 0 && $landing_result -eq 0 ]]

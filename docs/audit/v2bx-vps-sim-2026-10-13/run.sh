#!/bin/bash
cd /workspace
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

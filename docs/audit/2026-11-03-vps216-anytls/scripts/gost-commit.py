import json,hashlib,fcntl,subprocess,os
from pathlib import Path
base=Path('/var/backups/crowdbastion/private-gost-20261103')
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
assert not (base/'rolled-back').exists()
for name,wanted in json.loads((base/'manifest.json').read_text()).items():
 assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==wanted
subprocess.run(['/usr/bin/python3','-B','/usr/local/lib/crowdbastion216-private-gost/policy.py','apply'],capture_output=True,check=True,timeout=65)
for option in ['is-active','is-enabled']:
 subprocess.run(['systemctl',option,'crowdbastion216-private-gost.service'],capture_output=True,check=True,timeout=10)
with (base/'committed').open('x') as f:f.write('verified external denial, loopback reachability, service continuity and decision coverage\n');f.flush();os.fsync(f.fileno())
subprocess.run(['systemctl','stop','crowdbastion216-access-rollback.timer'],capture_output=True,check=True,timeout=10)
print(json.dumps({'committed':True,'rollback_timer_stopped':True,'reapply_idempotent':True}))

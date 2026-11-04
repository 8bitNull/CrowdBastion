import fcntl,subprocess,json,hashlib,os
from pathlib import Path
base=Path('/var/backups/crowdbastion/private-openlist-20261103')
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
assert not (base/'rolled-back').exists()
m=json.loads((base/'manifest.json').read_text());p=Path(m['path'])
assert hashlib.sha256(p.read_bytes()).hexdigest()==m['after']
subprocess.run(['/usr/bin/python3','-B',str(p),'verify'],capture_output=True,check=True,timeout=65)
for option in ['is-active','is-enabled']:subprocess.run(['systemctl',option,'crowdbastion216-private-gost.service'],capture_output=True,check=True,timeout=15)
with (base/'committed').open('x') as f:f.write('external denial, dual-stack rule and loopback checks passed\n');f.flush();os.fsync(f.fileno())
subprocess.run(['systemctl','stop','crowdbastion216-openlist-rollback.timer'],capture_output=True,check=True,timeout=15)
print(json.dumps({'committed':True,'private_ports':[5244,51080],'rollback_timer_stopped':True}))

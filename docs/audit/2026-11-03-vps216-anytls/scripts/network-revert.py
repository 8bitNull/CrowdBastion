import subprocess,json
from pathlib import Path
base=Path('/var/backups/crowdbastion/anytls-20261103')
assert not (base/'committed').exists()
p=subprocess.run(['/usr/bin/python3','-B',str(base/'rollback.py')],capture_output=True,text=True,timeout=90,check=True)
subprocess.run(['systemctl','stop','crowdbastion216-network-rollback.timer'],capture_output=True,timeout=15,check=True)
print(p.stdout)

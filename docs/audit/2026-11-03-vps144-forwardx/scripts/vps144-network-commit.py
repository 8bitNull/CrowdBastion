from pathlib import Path
import json,subprocess,hashlib,socket
b=Path('/var/backups/crowdbastion/vps144-20261103T103358Z');before=json.loads((b/'baseline.json').read_text())
for name,digest in before['protected'].items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest
for unit,pid in [('forwardx-agent',439),('forwardx-realm-both-53534',444),('forwardx-realm-both-53536',445),('forwardx-realm-both-53537',446)]:
 if unit=='forwardx-agent':continue
 current=subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'],text=True).strip();assert current==str(pid),(unit,current)
for port in (2087,2096):
 s=socket.create_connection(('192.0.2.13',port),timeout=3);s.close()
script='/opt/crowdbastion/releases/20261103-vps144/lib/crowdbastion_network.py'
r={}
for action in ('verify','commit'):
 p=subprocess.run(['python3',script,action],capture_output=True,text=True,timeout=90);(b/('network-final-'+action+'.json')).write_text(p.stdout);r[action]={'exit':p.returncode,'result':json.loads(p.stdout)};assert p.returncode==0
print(json.dumps(r,indent=2))

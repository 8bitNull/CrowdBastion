from pathlib import Path
import subprocess,json,os
base=Path('/var/backups/crowdbastion/vps144-20261103T103358Z')
if (base/'install-relay.log').exists() and not (base/'install-relay.first.log').exists():(base/'install-relay.first.log').write_bytes((base/'install-relay.log').read_bytes())
p=subprocess.run(['/bin/bash','/opt/crowdbastion/releases/20261103-vps144/crowdbastion.sh','--install-relay'],input='y\n',capture_output=True,text=True,timeout=240,env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NO_COLOR='1',UCF_FORCE_CONFFOLD='1'))
(base/'install-relay.log').write_text(p.stdout+p.stderr)
print(json.dumps({'exit':p.returncode,'output_tail':(p.stdout+p.stderr)[-5500:]},ensure_ascii=False,indent=2))
raise SystemExit(p.returncode)

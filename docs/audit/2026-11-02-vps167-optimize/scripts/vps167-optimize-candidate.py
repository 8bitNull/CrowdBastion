import json,subprocess
from pathlib import Path
release=Path('/opt/crowdbastion/releases/vps167-optimize-20261102-f592721e5d3e')
r={}
for flag in ['--firewall-check','--status-json']:
 p=subprocess.run(['bash',str(release/'crowdbastion.sh'),flag],capture_output=True,text=True,timeout=55)
 r[flag]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
print(json.dumps(r,ensure_ascii=False))

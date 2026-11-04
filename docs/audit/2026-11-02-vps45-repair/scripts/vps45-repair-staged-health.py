import json,subprocess
from pathlib import Path
release='/opt/crowdbastion/releases/vps45-repair-20261102-1f5c867f601e'
r={}
for flag in ["--firewall-check","--status-json"]:
 p=subprocess.run(["bash",release+"/crowdbastion.sh",flag],capture_output=True,text=True,timeout=55);r[flag]={"exit":p.returncode,"stdout":p.stdout,"stderr":p.stderr}
print(json.dumps(r,ensure_ascii=False))

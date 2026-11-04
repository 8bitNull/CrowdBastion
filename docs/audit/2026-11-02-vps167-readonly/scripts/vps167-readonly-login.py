import json,os,time
from pathlib import Path
print(json.dumps({"uid":os.geteuid(),"checked_at":time.time(),"os":Path("/etc/os-release").read_text(),"manager_exists":Path("/root/crowdsec-1key/crowdbastion.sh").is_file()}))

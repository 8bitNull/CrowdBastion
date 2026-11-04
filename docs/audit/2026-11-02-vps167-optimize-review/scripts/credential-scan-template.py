# Prefix AUDIT_TEXTS with the exact artifact-to-text mapping before SSH execution.
import hashlib,json,re,time
from pathlib import Path
import yaml
secrets=set();sources=[]
def collect(value):
 if isinstance(value,dict):
  for key,item in value.items():
   if re.search('password|secret|token|api[_-]?key',str(key),re.I) and isinstance(item,str) and len(item)>=8:secrets.add(item)
   else:collect(item)
 elif isinstance(value,list):
  for item in value:collect(item)
for name in ['/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/local_api_credentials.yaml','/etc/crowdsec/online_api_credentials.yaml']:
 p=Path(name)
 if p.is_file():collect(yaml.safe_load(p.read_text()));sources.append(name)
state=json.loads(Path('/etc/crowdsec/crowdsec-1key-web-installs.json').read_text())
for entry in state.values():
 p=Path(entry['host_assets'])/'bouncer.conf'
 if p.is_file():
  sources.append(str(p))
  for line in p.read_text().splitlines():
   if '=' in line:
    key,value=line.split('=',1);value=value.strip().strip(chr(34)+chr(39))
    if re.search('KEY|TOKEN|SECRET|PASSWORD',key) and len(value)>=8:secrets.add(value)
matches={name:sum(value in text or json.dumps(value,ensure_ascii=False)[1:-1] in text for value in secrets) for name,text in AUDIT_TEXTS.items()}
print(json.dumps({'checked_at':time.time(),'method':'Exact known remote credentials and JSON-escaped forms; values are never exported.','source_paths':sources,'distinct_credentials_checked':len(secrets),'artifacts_checked':len(AUDIT_TEXTS),'scanned_artifacts':{name:hashlib.sha256(text.encode()).hexdigest() for name,text in AUDIT_TEXTS.items()},'matched_artifacts':{name:count for name,count in matches.items() if count},'values_disclosed':False},ensure_ascii=False,indent=2))

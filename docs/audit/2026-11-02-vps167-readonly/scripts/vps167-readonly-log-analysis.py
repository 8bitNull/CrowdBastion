import collections,datetime,hashlib,json,os,re,subprocess,time
from pathlib import Path
import yaml
secrets=set()
def collect(value):
 if isinstance(value,dict):
  for k,v in value.items():
   if re.search('password|secret|token|api[_-]?key',str(k),re.I) and isinstance(v,str) and len(v)>=8:secrets.add(v)
   else:collect(v)
 elif isinstance(value,list):
  for v in value:collect(v)
for name in ['/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/local_api_credentials.yaml','/etc/crowdsec/online_api_credentials.yaml']:
 p=Path(name)
 if p.is_file():collect(yaml.safe_load(p.read_text()))
def mask(text):
 for value in secrets:text=text.replace(value,'<redacted>')
 return re.sub(r'https?://\S+|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?','<endpoint>',text)[:240]
def field(line,name):
 m=re.search(r'\b'+name+r'="((?:\\.|[^"\\])*)"',line)
 if not m:return ''
 try:return json.loads('"'+m[1]+'"')
 except ValueError:return ''
def epoch(line):
 value=field(line,'time')
 try:return datetime.datetime.fromisoformat(value).timestamp()
 except ValueError:return None
r={'checked_at':time.time(),'error_breakdown':{}}
for name in ['/var/log/crowdsec.log','/var/log/crowdsec-firewall-bouncer.log']:
 p=Path(name)
 if not p.is_file():continue
 with p.open('rb') as f:f.seek(max(0,p.stat().st_size-524288));lines=f.read().decode(errors='replace').splitlines()
 errors=[s for s in lines if re.search(r'level=(?:error|fatal)\b|\[(?:ERROR|FATAL)\]',s)];recent=[s for s in errors if (epoch(s) or 0)>=time.time()-86400]
 groups=collections.Counter();messages=collections.Counter();recent_classes=collections.Counter();unknown=sum(epoch(s) is None for s in errors)
 for s in errors:
  msg=field(s,'msg');tag='other'
  if msg=='Failed to process request body':tag='appsec_xml_body' if 'XML syntax error' in s else 'appsec_other_body'
  elif re.search(r'while (?:removing rule|flushing chain|deleting chain)',msg):tag='chain_cleanup'
  elif re.search(r'connection refused|dial tcp|network is unreachable',s,re.I):tag='api_connection'
  elif re.search(r'ipset.*(?:does not exist|Set cannot be destroyed)|Unknown set',s,re.I):tag='ipset_lifecycle'
  elif re.search(r'(?<!\w)(?:unauthorized|authentication failed)(?!\w)|status(?: code)?[ =:]+(?:401|403)\b',s,re.I):tag='authentication'
  groups[tag]+=1;messages[mask(msg)]+=1
  if s in recent:recent_classes[tag]+=1
 warns=[s for s in lines if 'vpatch-CVE-' in s and re.search(r'level=warn(?:ing)?\b|\[WARN(?:ING)?\]',s)]
 r['error_breakdown'][name]={'scope':'last 512KiB only','errors':len(errors),'errors_last_24h':len(recent),'unknown_timestamps':unknown,'classes':dict(groups),'recent_classes':dict(recent_classes),'message_counts':dict(messages),'latest_error_utc':datetime.datetime.fromtimestamp(max((epoch(s) or 0) for s in errors),datetime.timezone.utc).isoformat() if errors else None,'vpatch_warning_ids':sorted(set(re.findall(r'vpatch-CVE-[0-9-]+','\n'.join(warns)))),'latest_vpatch_warning_utc':datetime.datetime.fromtimestamp(max((epoch(s) or 0) for s in warns),datetime.timezone.utc).isoformat() if warns else None}
p=subprocess.run(['cscli','metrics','show','appsec','-o','json'],capture_output=True,text=True,timeout=20);r['appsec_metrics']={'exit':p.returncode}
try:r['appsec_metrics']['data']=json.loads(p.stdout)
except ValueError:r['appsec_metrics']['json_parse_error']=True
state=json.loads(Path('/etc/crowdsec/crowdsec-1key-web-installs.json').read_text());r['failure_policy']={}
for name,entry in state.items():
 values={}
 for line in (Path(entry['host_assets'])/'bouncer.conf').read_text().splitlines():
  if '=' in line:
   key,value=line.split('=',1)
   if re.fullmatch(r'(?:APPSEC|LAPI)_(?:FAILURE_ACTION|TIMEOUT|CONNECT_TIMEOUT|BODY_LIMIT)',key):values[key]=value.strip().strip('"')
 r['failure_policy'][name]=values
r['finished_at']=time.time();print(json.dumps(r,ensure_ascii=False,indent=2))

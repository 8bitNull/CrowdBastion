import hashlib,json,re,time,urllib.parse
from pathlib import Path
import yaml


def collect(value,key=''):
    if isinstance(value,dict):
        for k,v in value.items():collect(v,str(k))
    elif isinstance(value,list):
        for item in value:collect(item,key)
    elif isinstance(value,str):
        if re.search(r'password|secret|token|api[_-]?key|^(?:username|login)$',key,re.I) and len(value)>=8:credentials.add(value)
        for match in re.finditer(r'[A-Za-z][A-Za-z0-9+.-]*://[^\s\"\'<>]+',value):
            try:
                url=urllib.parse.urlsplit(match[0])
                for field in [url.username,url.password]:
                    if field and len(urllib.parse.unquote(field))>=8:credentials.add(urllib.parse.unquote(field))
            except ValueError:pass


credentials=set();sources={}
for name in ['/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/crowdsec/local_api_credentials.yaml','/etc/crowdsec/online_api_credentials.yaml','/etc/V2bX/config.json','/home/docker/gost/docker-compose.yml','/home/docker/openlist/config.json']:
    p=Path(name)
    if not p.is_file():sources[name]={'exists':False};continue
    text=p.read_text();before=len(credentials)
    try:
        if name.endswith('/V2bX/config.json'):
            import sys
            sys.path.insert(0,'/root/crowdsec-1key/lib')
            from crowdsec_v2bx import jsonc
            data=jsonc(text)
        else:data=yaml.safe_load(text)
        collect(data);sources[name]={'exists':True,'parsed':True,'additional_distinct_values':len(credentials)-before}
    except Exception as exc:sources[name]={'exists':True,'parsed':False,'error_type':type(exc).__name__}
variants=set(credentials)
for value in credentials:variants.add(json.dumps(value,ensure_ascii=True)[1:-1]);variants.add(json.dumps(value,ensure_ascii=False)[1:-1])
matched=[name for name,text in TEXT.items() if any(value in text for value in variants)]
r={'checked_at':time.time(),'method':'Read known credentials and login identities with length >= 8; compare original and JSON-escaped variants entirely in remote memory. URL userinfo is also inspected. Values are never returned.','source_summary':sources,'distinct_credentials_checked':len(credentials),'variants_checked':len(variants),'artifacts_checked':len(TEXT),'scanned_artifacts':{name:hashlib.sha256(text.encode()).hexdigest() for name,text in TEXT.items()},'scanned_artifacts_raw_sha256':RAW_SHA256,'text_input_format':'Python UTF-8 read_text with universal newline normalization; text digests and original byte digests are recorded separately','matched_artifacts':matched,'values_disclosed':False,'payload_written_to_server':False}
print(json.dumps(r,ensure_ascii=False,indent=2))

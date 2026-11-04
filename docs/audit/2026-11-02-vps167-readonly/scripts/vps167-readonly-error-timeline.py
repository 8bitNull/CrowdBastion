import collections,datetime,hashlib,json,re,time
from pathlib import Path
import yaml
report={'checked_at':time.time(),'files':{}}
secrets=set()
for path in ['/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/local_api_credentials.yaml','/etc/crowdsec/online_api_credentials.yaml']:
    p=Path(path)
    if p.is_file():
        for key,value in (yaml.safe_load(p.read_text()) or {}).items():
            if re.search('key|password|token|secret',str(key),re.I) and isinstance(value,str) and len(value)>=8:secrets.add(value)
def mask(s):
    for v in secrets:s=s.replace(v,'<redacted>')
    s=re.sub(r'https?://\S+','<url>',s)
    s=re.sub(r'(?i)(api[_-]?key|password|token|secret)(\s*[:=]\s*)[^\s,;]+',r'\1\2<redacted>',s)
    s=re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?','<ip>',s)
    return s[:300]
for path in ['/var/log/crowdsec-firewall-bouncer.log','/var/log/crowdsec.log']:
    p=Path(path)
    if not p.is_file():continue
    with p.open('rb') as f:
        f.seek(max(0,p.stat().st_size-512*1024));lines=f.read().decode(errors='replace').splitlines()
    errors=[s for s in lines if re.search(r'level=(?:error|fatal)|\[(?:ERROR|FATAL)\]',s)]
    times=[];recent=0;unknown=0;classes=collections.Counter()
    for s in errors:
        match=re.search(r'time=["\']?([0-9T:+.Z-]+)',s)
        if match:
            try:
                dt=datetime.datetime.fromisoformat(match[1]);times.append(dt.timestamp());recent+=dt.timestamp()>=time.time()-86400
            except ValueError:unknown+=1
        else:unknown+=1
        matched=False
        for label,pattern in [('api_connection',r'connection refused|dial tcp|connect:|network is unreachable'),('ipset_in_use',r'in use by|Set cannot be destroyed'),('ipset_missing',r'does not exist|Unknown set'),('api_unauthorized',r'unauthorized|403|401'),('timeout',r'timeout|deadline|timed out'),('nftables',r'nftables|nft:|nft '),('process_exit',r'exit status|signal:|terminated')]:
            if re.search(pattern,s,re.I):classes[label]+=1;matched=True
        if not matched:classes['other']+=1
    report['files'][path]={'scope':'last_512KiB','sample_lines':len(lines),'error_count':len(errors),'errors_last_24h':recent,'unknown_timestamps':unknown,'earliest_error_utc':datetime.datetime.fromtimestamp(min(times),datetime.timezone.utc).isoformat() if times else None,'latest_error_utc':datetime.datetime.fromtimestamp(max(times),datetime.timezone.utc).isoformat() if times else None,'classes':dict(classes),'last_three_error_excerpts':[mask(s) for s in errors[-3:]]}
print(json.dumps(report,ensure_ascii=False,indent=2))

import json,subprocess,time

def registry():
    p=subprocess.run(['cscli','bouncers','list','-o','json'],capture_output=True,text=True,timeout=10,check=True)
    return [{'name':r.get('name'),'last_pull':r.get('last_pull'),'type':r.get('type'),'version':r.get('version')} for r in json.loads(p.stdout)]
r={'checked_at':time.time(),'method':'Only cscli bouncers list; no decision fetch, lapi status, or requests using a bouncer credential during this observation.','before':registry()};before={v['name']:v['last_pull'] for v in r['before']};start=time.monotonic()
while True:
    after=registry()
    changed=[v for v in after if v['type']=='crowdsec-firewall-bouncer' and v['last_pull']!=before.get(v['name'])]
    if changed or time.monotonic()-start>=16:break
    time.sleep(2)
r.update(after=after,firewall_pull_advanced=bool(changed),seconds=round(time.monotonic()-start,3),finished_at=time.time())
print(json.dumps(r,ensure_ascii=False,indent=2))

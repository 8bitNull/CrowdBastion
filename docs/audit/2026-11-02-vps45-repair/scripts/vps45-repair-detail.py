import hashlib,json,os,subprocess
from pathlib import Path
r={}
for path in ['/root/crowdsec-1key','/usr/local/lib/crowdsec-1key','/etc/systemd/system/crowdsec-firewall-bouncer.service.d']:
 p=Path(path);r[path]=[{'name':c.name,'directory':c.is_dir(),'link':os.readlink(c) if c.is_symlink() else None,'mode':oct(c.lstat().st_mode&0o777)} for c in sorted(p.iterdir())] if p.is_dir() else None
r['panel_units']={}
for unit in ['1panel','1panel-core','1panel-agent']:
 p=subprocess.run(['systemctl','cat',unit],capture_output=True,text=True,timeout=10);r['panel_units'][unit]={'exit':p.returncode,'unit':p.stdout}
r['containers']=json.loads(subprocess.run(['docker','inspect',*subprocess.run(['docker','ps','-q'],capture_output=True,text=True,check=True).stdout.split()],capture_output=True,text=True,check=True).stdout)
r['containers']=[{'name':x['Name'],'id':x['Id'],'image':x['Image'],'started':x['State']['StartedAt'],'pid':x['State']['Pid'],'health':x['State'].get('Health',{}).get('Status'),'network':x['HostConfig']['NetworkMode']} for x in r['containers']]
print(json.dumps(r,ensure_ascii=False))

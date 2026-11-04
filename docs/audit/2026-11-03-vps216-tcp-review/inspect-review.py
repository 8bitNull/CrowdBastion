import subprocess,json,hashlib,time
from pathlib import Path
base=Path('/var/backups/crowdbastion/tcp-retune-20261103');m=json.loads((base/'manifest.json').read_text())
r={'committed':(base/'committed').exists(),'manifest':m,'final_config':Path('/etc/sysctl.d/99-zz-crowdbastion-anytls.conf').read_text()}
assert r['committed']
for f in m['files']:assert hashlib.sha256(Path(f['path']).read_bytes()).hexdigest()==f['after']
for k,v in m['settings'].items():assert ' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split())==v
keys=list(m['changes'])
p=subprocess.run(['unshare','-n','/usr/sbin/sysctl',*keys],capture_output=True,text=True,check=True,timeout=15)
r['unshare_defaults']=p.stdout.strip()
# Only per-network-namespace forwarding/interface settings are written in a new netns.
selected={k:v for k,v in m['settings'].items() if k=='net.ipv4.ip_forward' or k.startswith(('net.ipv4.conf.','net.ipv6.conf.'))}
code='SETTINGS='+repr(selected)+'\n'
code+='''from pathlib import Path
import json
Path('/proc/sys/net/ipv4/ip_forward').write_text('0\\n')
before={k:' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split()) for k in SETTINGS}
for k,v in sorted(SETTINGS.items()):Path('/proc/sys/'+k.replace('.','/')).write_text(v+'\\n')
after={k:' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split()) for k in SETTINGS}
mismatches={k:{'expected':v,'actual':after[k]} for k,v in SETTINGS.items() if after[k]!=v}
print(json.dumps({'before':before,'after':after,'mismatches':mismatches,'checked_keys':len(SETTINGS),'host_runtime_modified':False}))
raise SystemExit(bool(mismatches))
'''
p=subprocess.run(['unshare','-n','/usr/bin/python3','-B','-c',code],capture_output=True,text=True,timeout=20)
r['isolated_boot_order_check']={'exit':p.returncode,'output':json.loads(p.stdout) if p.stdout else None,'error_type':None if p.returncode==0 else 'isolated probe failed'}
r['checked_at']=subprocess.run(['date','-u','--iso-8601=seconds'],capture_output=True,text=True,check=True,timeout=5).stdout.strip()
print(json.dumps(r,ensure_ascii=False,indent=2))

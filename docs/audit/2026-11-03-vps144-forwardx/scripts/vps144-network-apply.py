from pathlib import Path
import subprocess,json,os
b=Path('/var/backups/crowdbastion/vps144-20261103T103358Z');release=Path('/opt/crowdbastion/releases/20261103-vps144')
cron=Path('/etc/cron.d/crowdsec-autoupdate');before=cron.read_bytes();(b/'maintenance.cron.before').write_bytes(before)
current=Path('/usr/local/lib/crowdsec-1key/current');(b/'maintenance.current.before.txt').write_text(os.readlink(current))
x=subprocess.run(['crowdbastion','--sync-runtime'],input='y\n',capture_output=True,text=True,timeout=60);(b/'sync-runtime.log').write_text(x.stdout+x.stderr);assert x.returncode==0,(x.stdout+x.stderr)[-2000:];assert cron.read_bytes()==before
args=['python3',str(release/'lib/crowdbastion_network.py')]
common=['--config','/var/lib/crowdbastion/network.json','--manager',str(release/'crowdbastion.sh'),'--runtime','/usr/local/lib/crowdsec-1key','--cron',str(cron)]
r={'runtime_sync_exit':x.returncode,'cron_bytes_preserved':True}
for action in ['plan','apply','verify']:
 p=subprocess.run(args+[action]+common,capture_output=True,text=True,timeout=120)
 (b/('network-'+action+'.json')).write_text(p.stdout);(b/('network-'+action+'.stderr')).write_text(p.stderr)
 data=json.loads(p.stdout);r[action]={'exit':p.returncode,'state':data.get('state'),'id':data.get('id'),'blockers':data.get('blockers'),'error_code':data.get('error_code')}
 assert p.returncode==0,(action,data,p.stderr[-1000:])
print(json.dumps(r,indent=2))

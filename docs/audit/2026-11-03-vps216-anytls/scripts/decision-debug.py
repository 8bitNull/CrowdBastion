import sys,json,time
from pathlib import Path
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_firewall_evidence as e
import crowdsec_firewall_runtime as r
config=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
report={};refs=rows=payload=None
for name,action in [('references',lambda:r.iptables_references(config,True)),('live',lambda:e.live(config)),('ipset',lambda:r.run(['ipset','save']).stdout)]:
 start=time.monotonic()
 try:
  value=action()
  if name=='references':refs=value
  elif name=='live':rows=value
  else:payload=value
  report[name]={'ok':True,'seconds':round(time.monotonic()-start,2),'size':len(value)}
 except Exception as error:report[name]={'ok':False,'error':type(error).__name__,'seconds':round(time.monotonic()-start,2)}
 print(json.dumps({name:report[name]}),flush=True)
if all(v['ok'] for v in report.values()):
 try:report['membership']=e.membership(e.networks(rows),refs,payload)
 except Exception as error:report['membership']={'error':type(error).__name__}
print(json.dumps(report))

from pathlib import Path
import importlib.util,json,subprocess,sys,tempfile
from unittest.mock import patch
root=Path('/projects/script/CrowdBastion-vps45-repair');sys.path.insert(0,str(root/'lib'))
import crowdsec_firewall_runtime as runtime
with tempfile.TemporaryDirectory() as tmp:
 config=Path(tmp)/'bouncer.yaml';config.write_text('mode: iptables\n')
 def coverage(lines):
  def run(argv):
   rules=lines.replace('crowdsec-blacklists','crowdsec6-blacklists') if argv[0]=='ip6tables' else lines
   return subprocess.CompletedProcess(argv,0,rules)
  with patch.object(runtime,'run',side_effect=run):return runtime.chain_coverage(config,True)
 prefix='-N X\n-N Y\n-N DOCKER-USER\n-A INPUT -j CROWDSEC_CHAIN\n-A FORWARD -j X\n-A DOCKER-USER -j CROWDSEC_CHAIN\n'
 drop='-A CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists src -j DROP\n'
 cycle=prefix+'-A X -j Y\n-A Y -j X\n'+drop
 assert coverage(cycle)=='fault'
 large='-N DOCKER-USER\n-A INPUT -j CROWDSEC_CHAIN\n-A DOCKER-USER -j CROWDSEC_CHAIN\n-A FORWARD -j T0\n'+drop
 for i in range(2000):large+='-N T'+str(i)+'\n-A T'+str(i)+' -j '+('T'+str(i+1) if i<1999 else 'CROWDSEC_CHAIN')+'\n'
 assert coverage(large)=='ok'
 assert coverage(prefix+'-A X -p tcp -j Y\n-A Y -j CROWDSEC_CHAIN\n'+drop)=='fault'
 assert coverage(prefix+'-A X -j Y\n-A Y -j CROWDSEC_CHAIN\n-A CROWDSEC_CHAIN -j ACCEPT\n'+drop)=='fault'
script=root/'docs/audit/2026-11-02-vps45-repair/scripts/static-policy.py';spec=importlib.util.spec_from_file_location('policy',script);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
calls=[]
def foreign(argv):calls.append(argv);return subprocess.CompletedProcess(argv,0,'-A CB45_STATIC -j ACCEPT\n')
try:m.apply(foreign)
except RuntimeError:pass
else:raise AssertionError('Foreign chain accepted')
assert len(calls)==1
print(json.dumps({'declared_user_chain_cycle':'rejected','2000_hop_unconditional_path':'ok','conditional_transit':'rejected','bouncer_accept_before_drop':'rejected','foreign_static_chain':'rejected without mutation','checks':5}))

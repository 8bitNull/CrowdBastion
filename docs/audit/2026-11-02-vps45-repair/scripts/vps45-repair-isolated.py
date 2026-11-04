BACKUP='/var/backups/crowdbastion/vps45-repair-20261102T024205Z'
from pathlib import Path
import json,subprocess,time
backup=Path(BACKUP)
p=backup/'crowdbastion-vps45-static.service';assert not p.exists();p.write_bytes((backup/'static.service.prepared').read_bytes());p.chmod(0o600)
r={}
a=subprocess.run(['systemd-analyze','verify',str(p)],capture_output=True,text=True,timeout=20);r['unit_verify']={'exit':a.returncode,'stderr':a.stderr,'stdout':a.stdout}
child='''from pathlib import Path
import importlib.util,json,subprocess
from importlib.machinery import SourceFileLoader
loader=SourceFileLoader('static',SOURCE);spec=importlib.util.spec_from_loader('static',loader);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.apply()
before={b:subprocess.check_output([b,'-S'],text=True) for b in ['iptables','ip6tables']}
module.apply()
after={b:subprocess.check_output([b,'-S'],text=True) for b in ['iptables','ip6tables']}
assert before==after
for binary,content in after.items():
 assert content.count('-A INPUT -j CB45_STATIC')==1
 assert len([s for s in content.splitlines() if s.startswith('-A CB45_STATIC ')])==len(module.RULES)
print(json.dumps({'both_families':True,'rules_per_family':len(module.RULES),'second_apply_unchanged':True,'scope':'isolated network namespace only'}))
'''
child='SOURCE='+repr(str(backup/'apply.py.prepared'))+'\n'+child
p=subprocess.run(['unshare','--net','python3','-B','-c',child],capture_output=True,text=True,timeout=40);r['isolated_network_namespace']={'exit':p.returncode,'stderr':p.stderr,'stdout':p.stdout};r['checked_at']=time.time()
print(json.dumps(r,ensure_ascii=False))

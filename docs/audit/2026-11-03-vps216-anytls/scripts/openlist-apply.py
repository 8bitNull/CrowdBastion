NEW_POLICY='"""Restrict the existing Docker-published gost port on eth0; never flush tables."""\nimport subprocess,sys\nCOMMENT=\'crowdbastion216-private-gost\'\ndef call(args,check=True):\n return subprocess.run(args,capture_output=True,text=True,check=check,timeout=10)\ndef rules():\n for binary in (\'iptables\',\'ip6tables\'):\n  for port,comment in [(\'51080\',COMMENT),(\'5244\',\'crowdbastion216-private-openlist\')]:\n   yield binary,\'INPUT\',[\'-i\',\'eth0\',\'-p\',\'tcp\',\'--dport\',port,\'-m\',\'comment\',\'--comment\',comment,\'-j\',\'DROP\']\n   yield binary,\'DOCKER-USER\',[\'-i\',\'eth0\',\'-p\',\'tcp\',\'-m\',\'conntrack\',\'--ctdir\',\'ORIGINAL\',\'--ctorigdstport\',port,\'-m\',\'comment\',\'--comment\',comment,\'-j\',\'DROP\']\ndef apply():\n call([\'ip\',\'link\',\'show\',\'eth0\'])\n for binary,chain,rule in rules():\n  before=call([binary,\'-w\',\'5\',\'-S\',chain]).stdout.splitlines()\n  present=call([binary,\'-w\',\'5\',\'-C\',chain,*rule],check=False)\n  if present.returncode==0:continue\n  if present.returncode!=1:raise RuntimeError(\'rule inspection failed\')\n  entries=[s for s in before if s.startswith(\'-A \'+chain+\' \')]\n  position=\'2\' if entries and entries[0]==\'-A \'+chain+\' -j CROWDSEC_CHAIN\' else \'1\'\n  call([binary,\'-w\',\'5\',\'-I\',chain,position,*rule])\n verify()\ndef verify():\n for binary,chain,rule in rules():call([binary,\'-w\',\'5\',\'-C\',chain,*rule])\ndef remove():\n for binary,chain,rule in reversed(list(rules())):\n  for _ in range(8):\n   present=call([binary,\'-w\',\'5\',\'-C\',chain,*rule],check=False)\n   if present.returncode==1:break\n   if present.returncode!=0:raise RuntimeError(\'cannot inspect rollback rule\')\n   call([binary,\'-w\',\'5\',\'-D\',chain,*rule])\n  else:raise RuntimeError(\'too many rule copies\')\nif __name__==\'__main__\':\n {\'apply\':apply,\'verify\':verify,\'remove\':remove}[sys.argv[1]]()\n print(\'gost public-access policy \'+sys.argv[1]+\' complete\')\n'
import subprocess,json,hashlib,fcntl,os
from pathlib import Path
base=Path('/var/backups/crowdbastion/private-openlist-20261103')
assert not base.exists()
base.mkdir(parents=True,mode=0o700)
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
p=Path('/usr/local/lib/crowdbastion216-private-gost/policy.py')
old=p.read_bytes();oldhash=hashlib.sha256(old).hexdigest()
previous=Path('/var/backups/crowdbastion/private-gost-20261103')
assert (previous/'committed').exists()
assert oldhash==json.loads((previous/'manifest.json').read_text())[str(p)]
backup=base/'policy.before';backup.write_bytes(old);backup.chmod(0o600)
(base/'policy.after').write_text(NEW_POLICY);(base/'policy.after').chmod(0o600)
manifest={'path':str(p),'before':oldhash,'after':hashlib.sha256(NEW_POLICY.encode()).hexdigest()}
(base/'manifest.json').write_text(json.dumps(manifest));(base/'manifest.json').chmod(0o600)
rollback="import subprocess,json,hashlib,fcntl,os\nfrom pathlib import Path\nbase=Path('/var/backups/crowdbastion/private-openlist-20261103')\nlock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)\nif (base/'committed').exists():raise SystemExit(0)\nm=json.loads((base/'manifest.json').read_text());p=Path(m['path'])\nassert hashlib.sha256(p.read_bytes()).hexdigest() in [m['before'],m['after']]\nfor binary in ['iptables','ip6tables']:\n for chain,match in [('INPUT',['--dport','5244']),('DOCKER-USER',['-m','conntrack','--ctdir','ORIGINAL','--ctorigdstport','5244'])]:\n  rule=['-i','eth0','-p','tcp',*match,'-m','comment','--comment','crowdbastion216-private-openlist','-j','DROP']\n  check=subprocess.run([binary,'-w','5','-C',chain,*rule],capture_output=True,timeout=10)\n  if check.returncode==0:subprocess.run([binary,'-w','5','-D',chain,*rule],capture_output=True,check=True,timeout=10)\n  elif check.returncode!=1:raise RuntimeError('rule inspection failed')\nold=(base/'policy.before').read_bytes();assert hashlib.sha256(old).hexdigest()==m['before']\ntemp=p.with_name('policy.py.restore');temp.write_bytes(old);temp.chmod(0o600);os.replace(temp,p)\n(base/'rolled-back').write_text('yes')\n"
r=base/'rollback.py';r.write_text(rollback);r.chmod(0o700)
subprocess.run(['systemd-run','--unit=crowdbastion216-openlist-rollback','--on-active=5m','--timer-property=AccuracySec=1s','/usr/bin/python3','-B',str(r)],capture_output=True,check=True,timeout=15)
try:
 temp=p.with_name('policy.py.next');temp.write_text(NEW_POLICY);temp.chmod(0o600);os.replace(temp,p)
 subprocess.run(['/usr/bin/python3','-B',str(p),'apply'],capture_output=True,check=True,timeout=100)
 print(json.dumps({'applied':True,'new_private_port':5244,'existing_private_port':51080,'rollback_timer':'5 minutes','backup':str(base)}))
except BaseException:
 lock.close();subprocess.run(['/usr/bin/python3','-B',str(r)],timeout=100);raise

POLICY='"""Restrict the existing Docker-published gost port on eth0; never flush tables."""\nimport subprocess,sys\nCOMMENT=\'crowdbastion216-private-gost\'\ndef call(args,check=True):\n return subprocess.run(args,capture_output=True,text=True,check=check,timeout=10)\ndef rules():\n for binary in (\'iptables\',\'ip6tables\'):\n  yield binary,\'INPUT\',[\'-i\',\'eth0\',\'-p\',\'tcp\',\'--dport\',\'51080\',\'-m\',\'comment\',\'--comment\',COMMENT,\'-j\',\'DROP\']\n  yield binary,\'DOCKER-USER\',[\'-i\',\'eth0\',\'-p\',\'tcp\',\'-m\',\'conntrack\',\'--ctdir\',\'ORIGINAL\',\'--ctorigdstport\',\'51080\',\'-m\',\'comment\',\'--comment\',COMMENT,\'-j\',\'DROP\']\ndef apply():\n call([\'ip\',\'link\',\'show\',\'eth0\'])\n for binary,chain,rule in rules():\n  before=call([binary,\'-w\',\'5\',\'-S\',chain]).stdout.splitlines()\n  present=call([binary,\'-w\',\'5\',\'-C\',chain,*rule],check=False)\n  if present.returncode==0:continue\n  if present.returncode!=1:raise RuntimeError(\'rule inspection failed\')\n  entries=[s for s in before if s.startswith(\'-A \'+chain+\' \')]\n  position=\'2\' if entries and entries[0]==\'-A \'+chain+\' -j CROWDSEC_CHAIN\' else \'1\'\n  call([binary,\'-w\',\'5\',\'-I\',chain,position,*rule])\n verify()\ndef verify():\n for binary,chain,rule in rules():call([binary,\'-w\',\'5\',\'-C\',chain,*rule])\ndef remove():\n for binary,chain,rule in reversed(list(rules())):\n  for _ in range(8):\n   present=call([binary,\'-w\',\'5\',\'-C\',chain,*rule],check=False)\n   if present.returncode==1:break\n   if present.returncode!=0:raise RuntimeError(\'cannot inspect rollback rule\')\n   call([binary,\'-w\',\'5\',\'-D\',chain,*rule])\n  else:raise RuntimeError(\'too many rule copies\')\nif __name__==\'__main__\':\n {\'apply\':apply,\'verify\':verify,\'remove\':remove}[sys.argv[1]]()\n print(\'gost public-access policy \'+sys.argv[1]+\' complete\')\n'
import subprocess,json,hashlib,fcntl,os
from pathlib import Path
base=Path('/var/backups/crowdbastion/private-gost-20261103')
assert not base.exists(),'transaction exists'
base.mkdir(mode=0o700,parents=True)
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
code=Path('/usr/local/lib/crowdbastion216-private-gost')
unit=Path('/etc/systemd/system/crowdbastion216-private-gost.service')
assert not code.exists() and not unit.exists()
def run(a,timeout=15):return subprocess.run(a,capture_output=True,text=True,check=True,timeout=timeout)
for b in ['iptables','ip6tables']:
 for c in ['INPUT','DOCKER-USER']:
  text=run([b,'-w','5','-S',c]).stdout
  entries=[s for s in text.splitlines() if s.startswith('-A '+c+' ')]
  assert entries[0]=='-A '+c+' -j CROWDSEC_CHAIN'
  (base/(b+'-'+c+'.before')).write_text(text)
container=json.loads(run(['docker','inspect','gost']).stdout)[0]
assert container['HostConfig']['PortBindings']['1080/tcp'][0]['HostPort']=='51080'
(base/'container-baseline.json').write_text(json.dumps({'id':container['Id'],'pid':container['State']['Pid'],'started':container['State']['StartedAt']}));(base/'container-baseline.json').chmod(0o600)
code.mkdir(mode=0o700)
p=code/'policy.py';p.write_text(POLICY);p.chmod(0o600)
unit_text='[Unit]\nDescription=Keep gost port 51080 private on VPS216\nWants=docker.service\nAfter=docker.service crowdsec-firewall-bouncer.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 -B /usr/local/lib/crowdbastion216-private-gost/policy.py apply\nExecStop=/usr/bin/python3 -B /usr/local/lib/crowdbastion216-private-gost/policy.py remove\nTimeoutStartSec=60\nTimeoutStopSec=60\n\n[Install]\nWantedBy=multi-user.target\n'
unit.write_text(unit_text);unit.chmod(0o644)
rollback="import subprocess,fcntl,hashlib,json\nfrom pathlib import Path\nbase=Path('/var/backups/crowdbastion/private-gost-20261103')\nlock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)\nif (base/'committed').exists():raise SystemExit(0)\nmanifest=json.loads((base/'manifest.json').read_text())\nfor name,wanted in manifest.items():\n p=Path(name)\n if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=wanted:raise RuntimeError('managed file drift')\nsubprocess.run(['systemctl','disable','--now','crowdbastion216-private-gost.service'],check=True,timeout=70)\nsubprocess.run(['/usr/bin/python3','-B','/usr/local/lib/crowdbastion216-private-gost/policy.py','remove'],check=True,timeout=70)\nPath('/etc/systemd/system/crowdbastion216-private-gost.service').unlink()\nPath('/usr/local/lib/crowdbastion216-private-gost/policy.py').unlink()\nPath('/usr/local/lib/crowdbastion216-private-gost').rmdir()\nsubprocess.run(['systemctl','daemon-reload'],check=True,timeout=20)\n(base/'rolled-back').write_text('yes')\n"
r=base/'rollback.py';r.write_text(rollback);r.chmod(0o700)
m={str(t):hashlib.sha256(t.read_bytes()).hexdigest() for t in [p,unit]}
(base/'manifest.json').write_text(json.dumps(m));(base/'manifest.json').chmod(0o600)
run(['systemd-run','--unit=crowdbastion216-access-rollback','--on-active=5m','--timer-property=AccuracySec=1s','/usr/bin/python3','-B',str(r)])
try:
 run(['systemctl','daemon-reload'])
 run(['systemctl','enable','--now',unit.name],timeout=70)
 run(['/usr/bin/python3','-B',str(p),'verify'])
 print(json.dumps({'applied':True,'service':unit.name,'timer':'5 minutes','backup':str(base),'port':51080,'protected_ingress':'eth0','protocol':'tcp'}))
except BaseException:
 lock.close()
 subprocess.run(['/usr/bin/python3','-B',str(r)],timeout=150)
 raise

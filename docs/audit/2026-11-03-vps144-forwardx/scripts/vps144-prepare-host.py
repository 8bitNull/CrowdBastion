from pathlib import Path
import os,json,subprocess,shutil
base=Path('/var/backups/crowdbastion/vps144-20261103T103358Z')
current=subprocess.run(['crontab','-l'],capture_output=True,text=True,check=True).stdout
assert current==(base/'root.crontab.before').read_text()
expected='@reboot iptables-restore < /etc/iptables/rules.v4'
assert current.splitlines().count(expected)==1
new='\n'.join('# CrowdBastion disabled full-table restore: '+s if s==expected else s for s in current.splitlines())+'\n'
subprocess.run(['crontab','-'],input=new,text=True,check=True)
subprocess.run(['systemctl','disable','netfilter-persistent'],capture_output=True,check=True)
policy=Path('/usr/local/lib/crowdbastion-static-policy');policy.mkdir(mode=0o700,exist_ok=False)
shutil.copy2(base/'static-rules.json',policy/'rules.json');(policy/'rules.json').chmod(0o600)
program='''from pathlib import Path
import json,subprocess
rules=json.loads(Path('/usr/local/lib/crowdbastion-static-policy/rules.json').read_text())
for item in rules:
 if item['binary'] not in ('iptables','ip6tables') or item['table'] not in ('raw','mangle','filter','nat','security') or item['rule'][0]!='-A':raise RuntimeError('invalid static rule')
 prefix=[item['binary'],'-w','5','-t',item['table']]
 p=subprocess.run(prefix+['-C']+item['rule'][1:],capture_output=True)
 if p.returncode==1:subprocess.run(prefix+item['rule'],check=True)
 elif p.returncode:raise RuntimeError('static rule lookup failed')
'''
(policy/'apply.py').write_text(program);(policy/'apply.py').chmod(0o600)
unit=Path('/etc/systemd/system/crowdbastion-static-policy.service');assert not unit.exists()
unit.write_text('[Unit]\nDescription=CrowdBastion static non-dynamic firewall rules\nAfter=local-fs.target\nBefore=crowdsec-firewall-bouncer.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B /usr/local/lib/crowdbastion-static-policy/apply.py\nRemainAfterExit=yes\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n');unit.chmod(0o644)
for args in [['systemd-analyze','verify',str(unit)],['systemctl','daemon-reload'],['systemctl','enable','--now','crowdbastion-static-policy']]:subprocess.run(args,capture_output=True,check=True)
# Add only the missing ipset dependency; the one-key installer handles package flavor later.
p=subprocess.run(['apt-get','install','-y','--no-upgrade','ipset'],capture_output=True,text=True,timeout=180,env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NO_COLOR='1'))
(base/'ipset-install.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr[-1500:]
print(json.dumps({'boot_restore_disabled':True,'netfilter_persistent_disabled':True,'static_rules':len(json.loads((policy/'rules.json').read_text())),'static_policy_active':True,'ipset_install_exit':p.returncode}))

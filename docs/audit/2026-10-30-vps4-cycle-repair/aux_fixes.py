import pathlib,json,subprocess as s,os,re,yaml
os.umask(0o077);B=pathlib.Path('/var/backups/crowdbastion/vps4-cycle-20261030')
def run(args,**kw):
 r=s.run(args,text=True,capture_output=True,timeout=45,**kw)
 if r.returncode:raise RuntimeError(str(args[:3])+': command failed; inspect private backup')
 return r.stdout
cron=run(['crontab','-l']);assert cron==(B/'crontab.before').read_text()
line='@reboot iptables-restore < /etc/iptables/rules.v4';assert cron.splitlines().count(line)==1
# Preserve renewal/logrotate jobs and old snapshots; only disable the identified obsolete restore.
new='\n'.join('# crowdbastion-review-20261030 disabled obsolete table restore: '+l if l==line else l for l in cron.splitlines())+'\n'
run(['crontab','-'],input=new);assert run(['crontab','-l'])==new
report={'old_firewall_restore_disabled':True,'other_cron_entries_preserved':True}
p=pathlib.Path('/home/docker/gost/docker-compose.yml');original=p.read_text();(B/'gost-compose.before').write_text(original)
d=yaml.safe_load(original);assert set(d['services'])=={'gost-http'};service=d['services']['gost-http'];assert service['restart']=='always' and not service.get('profiles')
healthy=json.loads(run(['docker','inspect','gost']))[0];assert healthy['State']['Running'] and not healthy['State']['Restarting']
# Preserve original text/credentials and only change restart/profile settings.
pattern=r'(?m)^(\s*)restart:\s*always\s*$';matches=list(re.finditer(pattern,original));assert len(matches)==1
indent=matches[0][1];updated=re.sub(pattern,lambda m:indent+'restart: "no"\n'+indent+'profiles: ["disabled-port-conflict"]',original)
expected=yaml.safe_load(original);expected['services']['gost-http']['restart']='no';expected['services']['gost-http']['profiles']=['disabled-port-conflict'];assert yaml.safe_load(updated)==expected
p.write_text(updated)
try:
 run(['docker','compose','-f',str(p),'config','--quiet'])
 run(['docker','update','--restart=no','gost-http-proxy']);run(['docker','stop','-t','10','gost-http-proxy'])
 state=json.loads(run(['docker','inspect','gost-http-proxy']))[0]
 assert not state['State']['Running'] and state['HostConfig']['RestartPolicy']['Name']=='no'
 now=json.loads(run(['docker','inspect','gost']))[0]
 assert now['State']['Pid']==healthy['State']['Pid'] and now['State']['StartedAt']==healthy['State']['StartedAt']
 report.update(conflicting_proxy_stopped=True,conflicting_proxy_restart_disabled=True,compose_requires_explicit_disabled_profile=True,healthy_proxy_not_restarted=True,proxy_port_51080_preserved=True,credentials_and_command_preserved=True)
except BaseException:
 p.write_text(original);raise
(B/'aux-fixes.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))

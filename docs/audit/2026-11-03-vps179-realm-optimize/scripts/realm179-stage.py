import pathlib,subprocess,json,datetime,hashlib,os,shutil,yaml
base=pathlib.Path('/var/backups/crowdbastion')/('vps179-realm-opt-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
base.mkdir(mode=0o700,parents=True);os.chmod(base,0o700)
fixture='[2026-11-03][01:00:00][realm_core::tcp][ERROR][tcp][::ffff:203.0.113.77]:45012 => 192.0.2.13:2053, error: Connection timed out (os error 110)'
result={'backup':str(base),'baseline_explain':{}}
p=subprocess.run(['cscli','explain','--log',fixture,'--type','realm-forwardx','-o','json'],capture_output=True,text=True,timeout=55)
(base/'parser-red.json').write_text(p.stdout);(base/'parser-red.stderr').write_text(p.stderr)
result['baseline_explain']={'exit':p.returncode,'bytes':len(p.stdout),'observation_marker_present':'realm_forwardx_observation' in p.stdout}
assert 'realm_forwardx_observation' not in p.stdout
# Capture protected configurations including sensitive data only inside the root-private backup.
protected=['/etc/crowdsec/config.yaml','/etc/crowdsec/acquis.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/forwardx/realm/forwardx-realm-both-56017.toml','/etc/forwardx/realm/forwardx-realm-both-58372.toml','/etc/systemd/system/forwardx-realm-both-56017.service','/etc/systemd/system/forwardx-realm-both-58372.service','/usr/local/bin/realm']
result['protected_sha256']={}
for name in protected:
 p=pathlib.Path(name);result['protected_sha256'][name]=hashlib.sha256(p.read_bytes()).hexdigest()
 if name!='/usr/local/bin/realm':
  dest=base/'before'/name.lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
for command,name in [(['iptables-save','-c'],'iptables-before.txt'),(['ip6tables-save','-c'],'ip6tables-before.txt'),(['systemctl','show','forwardx-realm-both-56017','forwardx-realm-both-58372','forwardx-agent','crowdsec','crowdsec-firewall-bouncer','-p','Id','-p','MainPID','-p','NRestarts','-p','ActiveState'],'services-before.txt')]:
 p=subprocess.run(command,capture_output=True,text=True,timeout=20);assert p.returncode==0;(base/name).write_text(p.stdout)
(base/'baseline.json').write_text(json.dumps(result,indent=2))
# Copy config with dereferenced hub links; offline explain never needs to modify production config.
stage=base/'stage';shutil.copytree('/etc/crowdsec',stage,symlinks=False)
c=yaml.safe_load((stage/'config.yaml').read_text());c['config_paths']['config_dir']=str(stage);c['crowdsec_service']['acquisition_path']=str(stage/'acquis.yaml');c['crowdsec_service']['acquisition_dir']=str(stage/'acquis.d')
(stage/'config.yaml').write_text(yaml.safe_dump(c,sort_keys=False))
print(json.dumps(result,indent=2))

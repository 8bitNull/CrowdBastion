from pathlib import Path
import subprocess,json,hashlib
b=Path('/var/backups/crowdbastion/vps144-20261103T103358Z');source=Path('/etc/crowdsec/acquis.d/setup.linux.yaml');disabled=source.with_suffix('.yaml.disabled')
assert source.is_file() and not source.is_symlink() and not disabled.exists()
# This source is the package's generic system messages only; authentication stays enabled.
import yaml
cfg=yaml.safe_load(source.read_text());assert set(cfg['filenames'])=={'/var/log/messages','/var/log/syslog','/var/log/kern.log'} and cfg['labels']['type']=='syslog'
(b/'setup.linux.yaml.before').write_bytes(source.read_bytes());digest=hashlib.sha256(source.read_bytes()).hexdigest();source.rename(disabled)
p=subprocess.run(['crowdsec','-t'],capture_output=True,text=True,timeout=60)
if p.returncode:
 disabled.rename(source);raise RuntimeError('scoped acquisition config check failed')
p=subprocess.run(['systemctl','restart','crowdsec'],capture_output=True,text=True,timeout=60)
if p.returncode:
 disabled.rename(source);subprocess.run(['systemctl','restart','crowdsec'],capture_output=True,timeout=60);raise RuntimeError('source change rolled back')
print(json.dumps({'disabled_generic_source':str(disabled),'original_sha256':digest,'ssh_source_retained':'/etc/crowdsec/acquis.d/setup.sshd.yaml','realm_source_retained':True}))

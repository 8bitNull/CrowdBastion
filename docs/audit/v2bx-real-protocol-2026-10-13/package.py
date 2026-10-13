from pathlib import Path
import subprocess,shutil,os,json,hashlib
lab=Path('/tmp/v2bx-real-lab');repo=Path('/data/project/script/crowdsec-1key')
subprocess.run(['cp','--reflink=auto','--sparse=always','/tmp/crowdsec-remote-lapi-lab/disk.raw',str(lab/'disk.raw')],check=True)
files={}
for name in ('fixture.py','guest.py','request.py','cert.pem','key.pem'):files['/workspace/real/'+name]=lab/name
files['/workspace/real/sing-box']=lab/'sing-box-1.12.0'
files['/workspace/real/v2bx/V2bX']=lab/'v2bx/V2bX'
for name in ('geoip.dat','geosite.dat'):files['/workspace/real/v2bx/'+name]=lab/'v2bx'/name
for source in (repo/'lib').glob('*.py'):files['/workspace/real/lib/'+source.name]=source
for name in ('relay_network_lab.py','verify_relay_network.py'):files['/workspace/tests/'+name]=repo/'tests'/name
run=lab/'run.sh';run.write_text('#!/bin/bash\ncd /workspace/real\nexport TZ=UTC\npython3 guest.py\n')
files['/workspace/run.sh']=run
for name in ('/workspace/real','/workspace/real/lib','/workspace/real/v2bx'):
 subprocess.run(['debugfs','-w','-R','mkdir '+name,str(lab/'disk.raw')],capture_output=True,check=True)
for target,source in files.items():
 subprocess.run(['debugfs','-w','-R','rm '+target,str(lab/'disk.raw')],capture_output=True)
 subprocess.run(['debugfs','-w','-R',f'write {source} {target}',str(lab/'disk.raw')],capture_output=True,check=True)
 if target.endswith(('V2bX','sing-box')):
  subprocess.run(['debugfs','-w','-R',f'set_inode_field {target} mode 0100755',str(lab/'disk.raw')],capture_output=True,check=True)
 if target.endswith('key.pem'):
  subprocess.run(['debugfs','-w','-R',f'set_inode_field {target} mode 0100600',str(lab/'disk.raw')],capture_output=True,check=True)
records=[{'guest_path':target,'sha256':hashlib.sha256(source.read_bytes()).hexdigest()} for target,source in files.items() if not target.endswith('key.pem')]
(lab/'package-hashes.json').write_text(json.dumps(records,indent=2)+'\n')
runner=Path('/tmp/v2bx-vps-sim-20261013/runner.py').read_text().replace('/tmp/v2bx-vps-sim-20261013','/tmp/v2bx-real-lab').replace("'-m','1024','-smp','1'", "'-m','1536','-smp','2'").replace('timeout=600','timeout=1200').replace("'ram_mib':1024", "'ram_mib':1536")
(lab/'runner.py').write_text(runner)
shutil.copy2('/tmp/crowdsec-remote-lapi-lab/boot.gz',lab/'boot.gz')
print('Guest payload packaged')

from pathlib import Path
import shutil,subprocess
lab=Path('/tmp/v2bx-vps-sim-20261013')
source=Path('/tmp/crowdsec-remote-lapi-lab')
subprocess.run(['cp','--reflink=auto','--sparse=always',str(source/'disk.raw'),str(lab/'disk.raw')],check=True)
repo=Path('/data/project/script/crowdsec-1key')
files={}
for name in ('verify_remote_bouncer.py','verify_relay_network.py','relay_network_lab.py'):
 files['/workspace/tests/'+name]=repo/'tests'/name
files['/workspace/lib/crowdsec_remote_bouncer.py']=repo/'lib/crowdsec_remote_bouncer.py'
files['/workspace/run.sh']=lab/'run.sh'
files['/workspace/landing.py']=lab/'landing.py'
for target,local in files.items():
 subprocess.run(['debugfs','-w','-R','rm '+target,str(lab/'disk.raw')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 subprocess.run(['debugfs','-w','-R','write '+str(local)+' '+target,str(lab/'disk.raw')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
shutil.copy2(source/'boot.gz',lab/'boot.gz')

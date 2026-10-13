"""Build an isolated NoCloud seed. Requires pycdlib in the selected Python environment."""
import argparse, tarfile, pathlib, io, json, hashlib
import pycdlib
p=argparse.ArgumentParser(description='Prepare offline NoCloud ISO carrying actual installer and official core guest payload')
p.add_argument('--lab',default='/tmp/crowdsec-vps-deb-lab'); p.add_argument('--core-root',default='/tmp/crowdsec-remote-lapi-lab/root'); p.add_argument('--output')
a=p.parse_args(); lab=pathlib.Path(a.lab); lab.mkdir(parents=True,exist_ok=True)
repo=pathlib.Path(__file__).resolve().parent.parent
with tarfile.open(lab/'payload.tgz','w:gz') as tar:
    tar.add(repo/'install-crowdsec-1panel.sh',arcname='opt/test/repo/install-crowdsec-1panel.sh')
    tar.add(repo/'lib',arcname='opt/test/repo/lib')
    for source,name in [('vps_deb_guest.py','guest.py'),('vps_deb_phase2.py','phase2.py')]: tar.add(repo/'tests'/source,arcname='opt/test/'+name)
    base=pathlib.Path(a.core_root)
    tar.add(base/'opt/core',arcname='opt/core')
    for name in ['crowdsec','cscli']: tar.add(base/'bin'/name,arcname='opt/test/bin/'+name)
    provenance={name:hashlib.sha256((repo/'tests'/name).read_bytes()).hexdigest() for name in ['vps_deb_guest.py','vps_deb_phase2.py','prepare_vps_deb.py']}
    provenance['core_binary_sha256']=hashlib.sha256((base/'bin/crowdsec').read_bytes()).hexdigest()
    provenance['cscli_binary_sha256']=hashlib.sha256((base/'bin/cscli').read_bytes()).hexdigest()
    metadata=json.dumps(provenance,sort_keys=True).encode(); member=tarfile.TarInfo('opt/test/provenance.json'); member.size=len(metadata)
    tar.addfile(member,io.BytesIO(metadata))
user='''#cloud-config
runcmd:
  - [ bash, -c, 'mkdir -p /mnt/lab; mount LABEL=cidata /mnt/lab; tar -xzf /mnt/lab/payload.tgz -C /; python3 /opt/test/guest.py >/dev/ttyS0 2>&1; systemctl poweroff' ]
'''
iso=pycdlib.PyCdlib(); iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
for name,data in [('user-data',user.encode()),('meta-data',b'instance-id: vps-lab\nlocal-hostname: vps-lab\n')]:
    iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
iso.add_file(str(lab/'payload.tgz'),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz')
output=pathlib.Path(a.output) if a.output else lab/'seed.iso'
iso.write(str(output)); iso.close(); output.chmod(0o600); (lab/'payload.tgz').chmod(0o600)

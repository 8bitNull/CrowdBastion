import pathlib,sys,io,tarfile,json,hashlib
sys.path.insert(0,'/tmp/crowdsec-vps-deb-lab/pylib');import pycdlib
l=pathlib.Path('/tmp/crowdsec-arm-recovery')
with tarfile.open(l/'payload.tgz','w:gz') as t:t.add(l/'guest.py',arcname='opt/arm-recovery/guest.py')
unit='[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /opt/arm-recovery/guest.py\nStandardOutput=journal+console\nStandardError=journal+console\n'
user='#cloud-config\nbootcmd:\n  - [ bash, -c, "for u in vps-phase2 arm-followup arm-final; do rm -f /etc/systemd/system/$u.service; ln -s /dev/null /etc/systemd/system/$u.service; done; systemctl daemon-reload; systemctl stop vps-phase2 arm-followup arm-final || true" ]\nwrite_files:\n  - path: /etc/systemd/system/arm-recovery.service\n    content: |\n'+''.join('      '+v+'\n' for v in unit.splitlines())+"runcmd:\n  - [ bash, -c, 'mkdir -p /mnt/recovery; mount LABEL=cidata /mnt/recovery; tar -xzf /mnt/recovery/payload.tgz -C /; systemctl daemon-reload; systemctl start --no-block arm-recovery' ]\n"
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
for name,data in [('user-data',user.encode()),('meta-data',b'instance-id: arm-minimal-recovery-20261012\nlocal-hostname: arm-minimal-recovery\n')]:iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
iso.add_file(str(l/'payload.tgz'),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz');iso.write(str(l/'seed.iso'));iso.close()
(l/'provenance.json').write_text(json.dumps({'files':{n:hashlib.sha256((l/n).read_bytes()).hexdigest() for n in ['guest.py','build.py','payload.tgz','seed.iso']},'backing_file':'/tmp/crowdsec-arm-followup/guest-v2.qcow2','scope':'diagnostic_cloned_guest_timeout_control_not_unmodified_installer_acceptance'},indent=2)+'\n')

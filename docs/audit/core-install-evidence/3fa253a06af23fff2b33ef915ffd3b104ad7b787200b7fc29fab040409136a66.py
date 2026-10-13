import pathlib,sys,io
sys.path.insert(0,'/tmp/crowdsec-vps-deb-lab/pylib')
import pycdlib
lab=pathlib.Path('/tmp/crowdsec-core-diagnostic')
# Same fixed guest/source payload; only switch initial evidence transport.
user=b'''#cloud-config
write_files:
  - path: /etc/systemd/system/core-fixed-first.service
    content: |
      [Unit]
      After=network-online.target
      Wants=network-online.target
      [Service]
      Type=simple
      Environment=TERM=vt220
      ExecStart=/usr/bin/python3 /opt/test/guest.py
      StandardOutput=journal+console
      StandardError=journal+console
runcmd:
  - [ bash, -c, 'mkdir -p /mnt/lab; mount LABEL=cidata /mnt/lab; tar -xzf /mnt/lab/payload.tgz -C /; systemctl daemon-reload; systemctl start core-fixed-first.service' ]
'''
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
for name,data in [('user-data',user),('meta-data',b'instance-id: core-fixed-observer\nlocal-hostname: core-fixed\n')]:
 iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
iso.add_file(str(lab/'fixed.tgz'),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz');iso.write(str(lab/'fixed-observer.iso'));iso.close();(lab/'fixed-observer.iso').chmod(0o600)

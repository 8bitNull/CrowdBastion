import pathlib,tarfile,io,sys
sys.path.insert(0,'/tmp/crowdsec-vps-deb-lab/pylib')
import pycdlib
lab=pathlib.Path('/tmp/crowdsec-core-diagnostic')
s=(lab/'cold-guest.py').read_text();s=s[:s.index("rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay']")]+r'''
note('terminal_environment',{'TERM':os.environ.get('TERM'),'NO_COLOR':os.environ.get('NO_COLOR')})
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('baseline_installer_exit',rc);note('baseline_installer_output',out)
diagnose()
import pty
master,slave=pty.openpty()
p=subprocess.Popen(['/bin/sh','-xc','. /usr/lib/crowdsec-firewall-bouncer-nftables/_bouncer.sh; printf "HELPER_LOADED\\n"'],stdout=slave,stderr=slave)
os.close(slave);buf=b''
while True:
    try:chunk=os.read(master,65536)
    except OSError:break
    if not chunk:break
    buf+=chunk
p.wait();os.close(master)
note('actual_helper_pty_probe_exit',p.returncode);note('actual_helper_pty_probe_trace',buf.decode(errors='replace'))
# Change only the upstream-documented color control for the retry.
os.environ['NO_COLOR']='1'
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('no_color_retry_installer_exit',rc);note('no_color_retry_installer_output',out)
diagnose()
print('CORE_DIAG_COMPLETE',flush=True)
command('systemctl','poweroff')
'''
(lab/'verify-color-guest.py').write_text(s)
with tarfile.open(lab/'cold.tgz','r:gz') as old,tarfile.open(lab/'verify-color.tgz','w:gz') as new:
 for m in old.getmembers():
  if m.name=='opt/test/guest.py':
   data=s.encode();m.size=len(data);new.addfile(m,io.BytesIO(data))
  else:new.addfile(m,old.extractfile(m) if m.isfile() else None)
user=b'''#cloud-config
runcmd:
  - [ bash, -c, 'mkdir -p /mnt/lab; mount LABEL=cidata /mnt/lab; tar -xzf /mnt/lab/payload.tgz -C /; python3 /opt/test/guest.py >/dev/ttyS0 2>&1; systemctl poweroff' ]
'''
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
for name,data in [('user-data',user),('meta-data',b'instance-id: core-diag-color\nlocal-hostname: core-diag-color\n')]:
 iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
iso.add_file(str(lab/'verify-color.tgz'),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz');iso.write(str(lab/'verify-color.iso'));iso.close()
for name in ['verify-color.tgz','verify-color.iso']:(lab/name).chmod(0o600)

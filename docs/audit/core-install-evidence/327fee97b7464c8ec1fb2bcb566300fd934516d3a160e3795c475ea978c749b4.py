import pathlib,tarfile,io,sys,json,hashlib
sys.path.insert(0,'/tmp/crowdsec-vps-deb-lab/pylib')
import pycdlib
repo=pathlib.Path('/data/project/script/crowdsec-1key');lab=pathlib.Path('/tmp/crowdsec-core-diagnostic')
base=(lab/'cold-guest.py').read_text();base=base[:base.index("os.chdir('/opt/test/repo')")]
guest=base+r'''
os.chdir('/opt/test/repo')
print('CORE_FIXED_ENV '+json.dumps({'distro':pathlib.Path('/etc/os-release').read_text(),'kernel':os.uname().release,'arch':os.uname().machine,'init':pathlib.Path('/proc/1/comm').read_text().strip(),'mem_total_kib':int(pathlib.Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]),'TERM':os.environ.get('TERM'),'NO_COLOR':os.environ.get('NO_COLOR'),'installer_sha256':hashlib.sha256(pathlib.Path('install-crowdsec-1panel.sh').read_bytes()).hexdigest()}),flush=True)
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('installer_output',out)
emit('fixed_fresh_core_relay_install',rc,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
diagnose()
if rc:
    print('CORE_FIXED_COMPLETE',flush=True);command('systemctl','poweroff');raise SystemExit(1)
before=pathlib.Path('/etc/crowdsec/config.yaml').read_bytes()
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',600)
note('repeat_output',out)
emit('fixed_core_repeat',rc,main_config_preserved=before==pathlib.Path('/etc/crowdsec/config.yaml').read_bytes(),core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer'))
phase=r"""
exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo')
start=time.monotonic();active=False
while time.monotonic()-start<60:
    active=command('systemctl','is-active','--quiet','crowdsec-firewall-bouncer')
    if active:break
    time.sleep(2)
emit('fixed_core_reboot',0,core_active=command('systemctl','is-active','--quiet','crowdsec'),bouncer_active=active,bouncer_enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
rc,out=run(['cscli','decisions','add','--ip','198.51.100.3','--duration','2m'],timeout=60)
present=False
for _ in range(30):
    nr,no=run(['nft','-j','list','ruleset'],timeout=15)
    if nr==0 and '198.51.100.3' in no:present=True;break
    time.sleep(1)
emit('fixed_core_decision_add',rc,ban_present=present)
rc,out=run(['cscli','decisions','delete','--ip','198.51.100.3'],timeout=60)
removed=False
for _ in range(30):
    nr,no=run(['nft','-j','list','ruleset'],timeout=15)
    if nr==0 and '198.51.100.3' not in no:removed=True;break
    time.sleep(1)
emit('fixed_core_decision_delete',rc,ban_removed=removed)
diagnose()
print('CORE_FIXED_COMPLETE',flush=True)
command('systemctl','poweroff')
"""
pathlib.Path('/opt/test/fixed-phase2.py').write_text(phase)
pathlib.Path('/etc/systemd/system/core-fixed-phase2.service').write_text('[Unit]\nAfter=network-online.target crowdsec.service\nWants=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /opt/test/fixed-phase2.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n')
command('systemctl','daemon-reload');command('systemctl','enable','core-fixed-phase2')
command('systemctl','reboot');time.sleep(300)
'''
(lab/'fixed-guest.py').write_text(guest)
with tarfile.open(lab/'fixed.tgz','w:gz') as tar:
 tar.add(repo/'install-crowdsec-1panel.sh',arcname='opt/test/repo/install-crowdsec-1panel.sh');tar.add(repo/'lib',arcname='opt/test/repo/lib')
 data=guest.encode();m=tarfile.TarInfo('opt/test/guest.py');m.size=len(data);tar.addfile(m,io.BytesIO(data))
user=b'''#cloud-config
runcmd:
  - [ bash, -c, 'mkdir -p /mnt/lab; mount LABEL=cidata /mnt/lab; tar -xzf /mnt/lab/payload.tgz -C /; python3 /opt/test/guest.py >/dev/ttyS0 2>&1; systemctl poweroff' ]
'''
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
for name,data in [('user-data',user),('meta-data',b'instance-id: core-fixed\nlocal-hostname: core-fixed\n')]:
 iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
iso.add_file(str(lab/'fixed.tgz'),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz');iso.write(str(lab/'fixed.iso'));iso.close()
for name in ['fixed.tgz','fixed.iso']:(lab/name).chmod(0o600)
print('fixed seed ready')

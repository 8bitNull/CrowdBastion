import pathlib,tarfile,io,json,hashlib,sys
sys.path.insert(0,'/tmp/crowdsec-vps-deb-lab/pylib')
import pycdlib
r=pathlib.Path('/data/project/script/crowdsec-1key'); l=pathlib.Path('/tmp/crowdsec-arm-followup')
fixed=pathlib.Path('/tmp/crowdsec-core-diagnostic/fixed-guest.py').read_text()
diag=fixed[fixed.index('import re\n'):fixed.index("os.chdir('/opt/test/repo')")]
guest=(r/'tests/vps_rpm_arm_guest_arm.py').read_text().replace("os.chdir('/opt/test/repo')",diag+"os.chdir('/opt/test/repo')",1)
guest=guest.replace("if rc: raise SystemExit(1)","if rc: diagnose(); print('ARM_FOLLOWUP_ABORT',flush=True); command('systemctl','poweroff'); raise SystemExit(1)")
guest=guest.replace("'crowdsec'],timeout=600)","'crowdsec'],timeout=900)")
guest=guest.replace("present='198.51.100.77' in run(['nft','list','ruleset'])[1]", "nr,no=run(['nft','list','ruleset'],timeout=20); present=nr==0 and '198.51.100.77' in no")
guest=guest.replace("absent='198.51.100.77' not in run(['nft','list','ruleset'])[1]", "nr,no=run(['nft','list','ruleset'],timeout=20); absent=nr==0 and '198.51.100.77' not in no")
phase=(r/'tests/vps_rpm_arm_phase2.py').read_text().replace('range(60)','range(120)',1)
a=phase.index('for _ in range(120):');b=phase.index("rc,out=run(['bash','install-crowdsec-1panel.sh','--remove-relay-bouncer'])")
phase=phase[:a]+"""start=time.monotonic(); ready=False
while time.monotonic()-start<120:
    br,_=run(['systemctl','is-active','--quiet','crowdsec-firewall-bouncer'],timeout=5)
    if br==0 and time.monotonic()-start<=120:ready=True;break
    time.sleep(1)
print('VPS_NOTE remote_readiness_elapsed '+str(round(time.monotonic()-start,2)),flush=True)
emit('boot_auto_start',0,active=ready,enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
diagnose()
"""+phase[b:]
phase=phase.replace("print('VPS_COMPLETE',flush=True)\ncommand('systemctl','poweroff')",'''diagnose()
command('systemctl','disable','vps-phase2')
pathlib.Path('/etc/systemd/system/arm-final.service').write_text('[Unit]\\nAfter=network-online.target crowdsec.service\\nWants=network-online.target\\n[Service]\\nType=simple\\nEnvironment=TERM=vt220\\nExecStart=/usr/bin/python3 /opt/test/phase3.py\\nStandardOutput=journal+console\\nStandardError=journal+console\\n[Install]\\nWantedBy=multi-user.target\\n')
command('systemctl','daemon-reload');command('systemctl','enable','arm-final');command('systemctl','reboot');time.sleep(300)''')
phase3='''exec(open('/opt/test/guest.py').read().split("os.chdir('/opt/test/repo')")[0])
os.chdir('/opt/test/repo')
start=time.monotonic(); core_ready=False; bouncer_ready=False
while time.monotonic()-start<120:
    cr,_=run(['systemctl','is-active','--quiet','crowdsec'],timeout=5)
    br,_=run(['systemctl','is-active','--quiet','crowdsec-firewall-bouncer'],timeout=5)
    core_ready=cr==0 and time.monotonic()-start<=120; bouncer_ready=br==0 and time.monotonic()-start<=120
    if core_ready and bouncer_ready:break
    time.sleep(2)
print('VPS_NOTE native_readiness_elapsed '+str(round(time.monotonic()-start,2)),flush=True)
emit('native_core_reboot',0,core_active=core_ready,bouncer_active=bouncer_ready,core_enabled=command('systemctl','is-enabled','--quiet','crowdsec'),bouncer_enabled=command('systemctl','is-enabled','--quiet','crowdsec-firewall-bouncer'))
for action in ['add','delete']:
    argv=['cscli','decisions',action,'--ip','198.51.100.78']
    if action=='add':argv+=['--duration','10m']
    rc,out=run(argv,timeout=90)
    synced=False
    for _ in range(60):
        nr,no=run(['nft','-j','list','ruleset'],timeout=30)
        if nr==0 and ('198.51.100.78' in no)==(action=='add'):synced=True;break
        time.sleep(1)
    emit('native_core_decision_'+action,rc,synced=synced)
diagnose()
print('VPS_COMPLETE',flush=True)
print('ARM_FOLLOWUP_COMPLETE',flush=True)
command('systemctl','poweroff')
'''
for name,body in [('guest.py',guest),('phase2.py',phase),('phase3.py',phase3)]:
    compile(body,name,'exec');(l/name).write_text(body)
with tarfile.open(l/'payload.tgz','w:gz') as t:
    t.add(r/'install-crowdsec-1panel.sh',arcname='opt/test/repo/install-crowdsec-1panel.sh');t.add(r/'lib',arcname='opt/test/repo/lib')
    for name in ['guest.py','phase2.py','phase3.py']:t.add(l/name,arcname='opt/test/'+name)
unit='[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nEnvironment=TERM=vt220\nExecStart=/usr/bin/python3 /opt/test/guest.py\nStandardOutput=journal+console\nStandardError=journal+console\n[Install]\nWantedBy=multi-user.target\n'
user='#cloud-config\nwrite_files:\n  - path: /etc/systemd/system/arm-followup.service\n    content: |\n'+''.join('      '+v+'\n' for v in unit.splitlines())+"runcmd:\n  - [ bash, -c, 'mkdir -p /mnt/lab; mount LABEL=cidata /mnt/lab; tar -xzf /mnt/lab/payload.tgz -C /; systemctl daemon-reload; systemctl start --no-block arm-followup' ]\n"
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
for name,data in [('user-data',user.encode()),('meta-data',b'instance-id: arm-followup-20261012\nlocal-hostname: arm-followup\n')]:iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
iso.add_file(str(l/'payload.tgz'),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz');iso.write(str(l/'seed.iso'));iso.close()
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p={'installer_sha256':h(r/'install-crowdsec-1panel.sh'),'files':{n:h(l/n) for n in ['guest.py','phase2.py','phase3.py','payload.tgz','seed.iso']},'helpers':{str(p.relative_to(r)):h(p) for p in (r/'lib').rglob('*') if p.is_file()},'image_sha512':hashlib.sha512(pathlib.Path('/tmp/crowdsec-vps-rpm-arm-lab/images/debian13-arm64.qcow2').read_bytes()).hexdigest()}
(l/'provenance.json').write_text(json.dumps(p,indent=2)+'\n');print(p['installer_sha256'],p['image_sha512'])

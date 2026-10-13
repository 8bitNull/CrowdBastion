import pathlib, tarfile, io, json, hashlib, sys
sys.path.insert(0,'/tmp/crowdsec-vps-deb-lab/pylib')
import pycdlib
repo=pathlib.Path('/data/project/script/crowdsec-1key')
lab=pathlib.Path('/tmp/crowdsec-core-diagnostic');lab.mkdir(exist_ok=True);lab.chmod(0o700)
helper=r'''
import re

def scrub(value):
    text=str(value)
    secrets=[]
    try:
        import yaml
        def visit(node):
            if isinstance(node,dict):
                for k,v in node.items():
                    if any(word in str(k).lower() for word in ('password','api_key','token','secret')) and isinstance(v,str) and len(v)>=4:secrets.append(v)
                    visit(v)
            elif isinstance(node,list):
                for v in node:visit(v)
        for p in pathlib.Path('/etc/crowdsec').rglob('*.yaml*'):
            if p.is_file() and p.stat().st_size<1000000:
                try:visit(yaml.safe_load(p.read_text()))
                except Exception:pass
    except ImportError:pass
    for secret in sorted(secrets,key=len,reverse=True):text=text.replace(secret,'<redacted>')
    text=re.sub(r'(?i)(api[_ -]?key|password|token|secret)([\s:=]+)([^\s,\"\']+)',r'\1\2<redacted>',text)
    text=re.sub(r'[A-Za-z0-9_+/=-]{32,}','<opaque-redacted>',text)
    return text

def note(name,data):print('CORE_DIAG '+json.dumps({'case':name,'data':scrub(data)}),flush=True)

def diagnose():
    for unit in ['crowdsec','crowdsec-firewall-bouncer']:
        rc,out=run(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','Result','-p','ExecMainCode','-p','ExecMainStatus','-p','FragmentPath'])
        note(unit+'_state',out)
        rc,out=run(['journalctl','-u',unit,'-n','60','--no-pager','-o','cat'],timeout=30)
        note(unit+'_journal',out)
    rc,out=run(['dpkg-query','-W','-f=${Package} ${Version} ${Status}\n','crowdsec','crowdsec-firewall-bouncer-nftables'])
    note('packages',out)
    for name in ['/var/log/crowdsec-firewall-bouncer.log','/var/log/crowdsec.log']:
        p=pathlib.Path(name)
        if p.is_file():note(name,'\n'.join(p.read_text(errors='replace').splitlines()[-60:]))
    p=pathlib.Path('/var/lib/dpkg/info/crowdsec-firewall-bouncer-nftables.postinst')
    if p.exists():note('official_bouncer_postinst',p.read_text())
    paths=['/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/systemd/system/crowdsec-firewall-bouncer.service']
    note('artifact_presence',{name:pathlib.Path(name).exists() for name in paths})
'''
base=(repo/'tests/vps_deb_guest.py').read_text().split("os.chdir('/opt/test/repo')")[0]
install=r'''
os.chdir('/opt/test/repo')
rc,out=run(['bash','install-crowdsec-1panel.sh','--install-relay'],'\n',900)
note('installer_exit',rc);note('installer_output',out)
diagnose()
print('CORE_DIAG_COMPLETE',flush=True)
command('systemctl','poweroff')
'''
cold=base+helper+r'''
os.chdir('/opt/test/repo')
print('CORE_DIAG_ENV '+json.dumps({'distro':pathlib.Path('/etc/os-release').read_text(),'kernel':os.uname().release,'arch':os.uname().machine,'mem_total':pathlib.Path('/proc/meminfo').read_text().splitlines()[0]}),flush=True)
'''+install
phase=(repo/'tests/vps_deb_phase2.py').read_text();phase=phase[:phase.index('import threading')]+helper+install
for mode in ['cold','after-remote']:
    output=lab/(mode+'.iso');payload=lab/(mode+'.tgz')
    guest=cold if mode=='cold' else (repo/'tests/vps_deb_guest.py').read_text()
    with tarfile.open(payload,'w:gz') as tar:
        tar.add(repo/'install-crowdsec-1panel.sh',arcname='opt/test/repo/install-crowdsec-1panel.sh');tar.add(repo/'lib',arcname='opt/test/repo/lib')
        basecore=pathlib.Path('/tmp/crowdsec-remote-lapi-lab/root')
        tar.add(basecore/'opt/core',arcname='opt/core')
        for name in ['crowdsec','cscli']:tar.add(basecore/'bin'/name,arcname='opt/test/bin/'+name)
        prov={name:hashlib.sha256((repo/'tests'/name).read_bytes()).hexdigest() for name in ['vps_deb_guest.py','vps_deb_phase2.py','prepare_vps_deb.py']}
        for path,text in [('opt/test/guest.py',guest),('opt/test/phase2.py',phase),('opt/test/provenance.json',json.dumps(prov))]:
            data=text.encode();member=tarfile.TarInfo(path);member.size=len(data);tar.addfile(member,io.BytesIO(data))
    user='''#cloud-config
runcmd:
  - [ bash, -c, 'mkdir -p /mnt/lab; mount LABEL=cidata /mnt/lab; tar -xzf /mnt/lab/payload.tgz -C /; python3 /opt/test/guest.py >/dev/ttyS0 2>&1; systemctl poweroff' ]
'''
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
    for name,data in [('user-data',user.encode()),('meta-data',('instance-id: core-diag-'+mode+'\nlocal-hostname: core-diag\n').encode())]:
        iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
    iso.add_file(str(payload),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz');iso.write(str(output));iso.close();output.chmod(0o600);payload.chmod(0o600)
    (lab/(mode+'-guest.py')).write_text(guest);(lab/(mode+'-phase2.py')).write_text(phase)
print(lab)

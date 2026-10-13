#!/usr/bin/env python3
"""Build immutable cloud-init payload media; requires pycdlib in the caller's Python environment."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import secrets


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab',type=Path,required=True)
    parser.add_argument('--core-root',type=Path,help='Existing private snapshot built from official CrowdSec source, required for RPM')
    parser.add_argument('--output',type=Path,required=True)
    scopes=parser.add_mutually_exclusive_group()
    scopes.add_argument('--core-only',action='store_true',help='Run only fresh native core relay installation')
    scopes.add_argument('--remote-only',action='store_true',help='Only remote lifecycle; no later local core integration')
    scopes.add_argument('--integration-only',action='store_true',help='Bootstrap official native core before independently testing integration')
    parser.add_argument('--arm',action='store_true',help='Use native official Debian ARM64 packages for the real LAPI')
    parser.add_argument('--soak-duration',type=int,choices=[120,3600,86400])
    parser.add_argument('--gost',type=Path);parser.add_argument('--realm',type=Path)
    args=parser.parse_args()
    if args.soak_duration and (not args.core_only or args.arm or not args.gost or not args.realm or not args.gost.is_file() or not args.realm.is_file()):parser.error('Soak seed currently requires amd64 cold local core and two verified binaries')
    if args.output.exists() or args.output.with_suffix('.provenance.json').exists():parser.error('Refusing to overwrite immutable seed/provenance')
    repo=Path(__file__).resolve().parents[1]
    if not args.arm and not args.core_only and not args.integration_only:
        if args.core_root is None:parser.error('--core-root is required for RPM guests')
        for name in ['opt/core/etc/config.yaml','bin/crowdsec','bin/cscli']:
            if not (args.core_root/name).is_file():parser.error('Missing official core snapshot artifact: '+name)
    import pycdlib
    args.lab.mkdir(parents=True,exist_ok=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    payload=args.output.with_suffix('.payload.tgz')
    if payload.exists():parser.error('Refusing to overwrite existing payload')
    guest=repo/'tests'/('vps_rpm_arm_guest_arm.py' if args.arm else 'vps_rpm_arm_guest.py')
    if args.core_only:guest=repo/'tests/vps_rpm_arm_guest_core.py'
    if args.integration_only:guest=repo/'tests/vps_rpm_arm_guest_existing.py'
    scope='fresh_native_core_only' if args.core_only else 'existing_core_integration' if args.integration_only else 'remote_only' if args.remote_only else 'full_lifecycle'
    phase2=repo/'tests/vps_rpm_arm_phase2.py'
    source_sha256={'opt/test/repo/'+str(path.relative_to(repo)):hashlib.sha256(path.read_bytes()).hexdigest() for path in [repo/'crowdbastion.sh',repo/'install-crowdsec-1panel.sh',*sorted((repo/'lib').glob('*.py')),*sorted((repo/'lib').glob('*.sh'))]}
    def source_filter(info):
        return None if '__pycache__' in Path(info.name).parts or info.name.endswith('.pyc') else info
    soak_sources={}
    lab_id=secrets.token_hex(16)
    with tarfile.open(payload,'w:gz',compresslevel=1) as tar:
        tar.add(repo/'crowdbastion.sh',arcname='opt/test/repo/crowdbastion.sh')
        tar.add(repo/'install-crowdsec-1panel.sh',arcname='opt/test/repo/install-crowdsec-1panel.sh')
        tar.add(repo/'lib',arcname='opt/test/repo/lib',filter=source_filter)
        tar.add(guest,arcname='opt/test/guest.py');tar.add(phase2,arcname='opt/test/phase2.py')
        data=(scope+'\n').encode();info=tarfile.TarInfo('opt/test/test-scope.txt');info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
        tar.add(repo/'tests/vps_guest_runtime.py',arcname='opt/test/vps_guest_runtime.py')
        tar.add(repo/'tests/vps_rpm_arm_native_phase.py',arcname='opt/test/native-phase.py')
        if args.soak_duration:
            sources=['relay_soak_guest.py','vps_soak_stage.py','benchmark_relay.py','relay_network_lab.py','verify_relay_network.py']
            for name in sources:
                path=repo/'tests'/name;tar.add(path,arcname='opt/test/'+name);soak_sources['opt/test/'+name]=hashlib.sha256(path.read_bytes()).hexdigest()
            for name,path in [('gost',args.gost),('realm',args.realm)]:
                tar.add(path,arcname='opt/test/'+name);soak_sources['opt/test/'+name]=hashlib.sha256(path.read_bytes()).hexdigest()
            config={'mode':'local','duration_seconds':args.soak_duration,'endpoints':{name:['127.0.0.1',30001+i] for i,name in enumerate(['gost_tcp','gost_udp','realm_tcp','realm_udp'])},'cscli':['/usr/bin/cscli'],'lab_id':lab_id}
            data=json.dumps(config).encode();info=tarfile.TarInfo('opt/test/soak-manifest.json');info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data));soak_sources[info.name]=hashlib.sha256(data).hexdigest()
        if not args.arm and not args.core_only and not args.integration_only:
            tar.add(args.core_root/'opt/core',arcname='opt/core')
            for name in ['crowdsec','cscli']:tar.add(args.core_root/'bin'/name,arcname='opt/test/bin/'+name)
    user="""#cloud-config
write_files:
  - path: /etc/systemd/system/vps-initial.service
    content: |
      [Unit]
      After=network-online.target
      Wants=network-online.target
      OnFailure=vps-failure.service
      [Service]
      Type=simple
      Environment=TERM=vt220
      ExecStart=/usr/bin/python3 /opt/test/guest.py
      StandardOutput=journal+console
      StandardError=journal+console
  - path: /etc/systemd/system/vps-failure.service
    content: |
      [Unit]
      Description=Terminate failed isolated VPS test
      [Service]
      Type=oneshot
      ExecStart=/usr/bin/python3 -c "print('VPS_HARNESS_FAILED', flush=True)"
      ExecStartPost=/usr/bin/systemctl --no-block poweroff
      StandardOutput=journal+console
      StandardError=journal+console
runcmd:
  - [ bash, -c, 'mkdir -p /mnt/lab; mount LABEL=cidata /mnt/lab; tar -xzf /mnt/lab/payload.tgz -C /; systemctl daemon-reload; systemctl start --no-block vps-initial' ]
"""
    if args.soak_duration:
        user=user.replace('runcmd:', '  - path: /run/crowdsec-vps-lab\n    permissions: \'0600\'\n    content: '+lab_id+'\nruncmd:')
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
    for name,data in [('user-data',user.encode()),('meta-data',b'instance-id: vps-lab\nlocal-hostname: vps-lab\n')]:
        iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name.upper().replace('-','_')+';1',rr_name=name,joliet_path='/'+name)
    iso.add_file(str(payload),iso_path='/PAYLOAD.TGZ;1',rr_name='payload.tgz',joliet_path='/payload.tgz')
    iso.write(str(args.output));iso.close()
    def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    provenance={'installer_sha256':digest(repo/'install-crowdsec-1panel.sh'),'hub_helper_sha256':digest(repo/'lib/crowdsec_hub_snapshot.py'),'test_scope':scope,'remote_helper_sha256':digest(repo/'lib/remote_bouncer.sh'),'guest_sha256':digest(guest),'phase2_sha256':digest(phase2),'seed_sha256':digest(args.output),'payload_sha256':digest(payload),'architecture':'arm64' if args.arm else 'amd64','core_source':'official_native_repository' if args.arm or args.core_only or args.integration_only else str(args.core_root),'runtime_sha256':digest(repo/'tests/vps_guest_runtime.py'),'native_phase_sha256':digest(repo/'tests/vps_rpm_arm_native_phase.py')}
    provenance['scope_control_sha256']=hashlib.sha256((scope+'\n').encode()).hexdigest()
    provenance.update(source_sha256=source_sha256,soak_duration_seconds=args.soak_duration,soak_sources=soak_sources)
    args.output.with_suffix('.provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    return 0

if __name__=='__main__':raise SystemExit(main())

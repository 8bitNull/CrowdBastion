#!/usr/bin/env python3
"""Actual RPM/ARM systemd guest runner; no forwarded ports or host shares."""
import argparse
import hashlib
import tarfile
import time
import json
import os
import re
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from vps_guest_runtime import service_healthy
from relay_soak_guest import assess as assess_soak
HOST_ASSESSMENT_SOURCES={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ('verify_vps_rpm_arm.py','vps_guest_runtime.py','relay_soak_guest.py')}

REQUIRED_ASSERTIONS={
 'fresh_remote_install':('active','enabled','local_exists'),
 'repeat_remote_install':('active',),
 'change_url_and_key':('changed','active'),
 'bad_key_preserves_state':('rejected','local_unchanged','active'),
 'foreign_local_ownership':('rejected','local_unchanged','active'),
 'actual_nft_decision_add':('present',),
 'actual_nft_decision_delete':('absent',),
 'boot_auto_start':('active','enabled'),
 'remove_managed_remote':('inactive','disabled','local_removed'),
 'existing_core_preserved':('unchanged',),
 'remote_reboot_decision_add':('synced',),
 'remote_reboot_decision_delete':('synced',),
}
REQUIRED=tuple(REQUIRED_ASSERTIONS)
CASE_ASSERTIONS={**REQUIRED_ASSERTIONS,
 'core_relay_install':('core_active','bouncer_active'),
 'help_and_readonly_status':('help_ok','status_ok','unchanged'),
 'retained_remote_refused_relay':('refused','unchanged'),
 'retained_remote_refused_core':('refused','unchanged'),
 'guest_dependencies':('packages_ready',),
 'guest_dependencies_index':('ready',),
 'core_repository_setup':('ready',),
 'core_package_install':('installed',),
 'official_lapi':('ready',),
 'existing_core_config_preserved':('preserved',),
 'core_repeat_install':('preserved','core_active','bouncer_active'),
 'native_core_reboot':('core_active','bouncer_active'),
 'native_core_decision_add':('synced',),
 'native_core_decision_delete':('synced',),
}

REFUSAL_CASES={'bad_key_preserves_state','foreign_local_ownership','retained_remote_refused_relay','retained_remote_refused_core'}
TARGETS={'debian12':('debian','12'),'debian13':('debian','13'),'debian13-arm64':('debian','13'),
         'ubuntu22':('ubuntu','22.04'),'ubuntu24':('ubuntu','24.04'),'jammy':('ubuntu','22.04'),'noble':('ubuntu','24.04'),
         'centos9':('centos','9'),'alma9':('almalinux','9'),'rocky9':('rocky','9'),'fedora44':('fedora','44')}

def identity_matches(identity,distro):
    target=TARGETS.get(distro)
    version=identity.get('version')
    return bool(target and identity.get('os_id')==target[0] and isinstance(version,str)
                and (version==target[1] or (target[1]=='9' and version.startswith('9.')))
                and identity.get('architecture')==('aarch64' if 'arm64' in distro else 'x86_64')
                and identity.get('pid1')=='systemd' and isinstance(identity.get('kernel'),str) and identity['kernel']
                and isinstance(identity.get('installer_sha256'),str) and re.fullmatch('[0-9a-f]{64}',identity['installer_sha256'])
                and type(identity.get('ram_kib')) is int and identity['ram_kib']>0)


def accepted(identity,cases):
    return identity.get('pid1')=='systemd' and all(identity.get(k) for k in ('os_id','version','architecture','kernel','ram_kib')) and all(cases.get(name) is True for name in REQUIRED)

def parse_report(serial):
    start='RPM_ARM_RESULT_BEGIN\n'; end='\nRPM_ARM_RESULT_END'
    if start not in serial or end not in serial.split(start,1)[1]: return None
    return json.loads(serial.split(start,1)[1].split(end,1)[0])

def qemu_command(distro,lab,image,seed,ram=1024):
    base=Path('/tmp/crowdsec-qemu-lab/host')
    arm='arm64' in distro
    binary=lab/'host/usr/bin/qemu-system-aarch64' if arm else base/'usr/bin/qemu-system-x86_64'
    args=[str(binary),'-accel','tcg','-machine','virt' if arm else 'q35','-cpu','max','-m',str(ram),'-smp','1','-nographic','-monitor','none','-drive',f'file={image},format=qcow2,if=virtio,snapshot=on','-netdev','user,id=n1','-device','virtio-net-pci,netdev=n1,romfile=','-L',str(base/'usr/share/qemu')]
    if arm:
        args+=['-bios',str(lab/'host/usr/share/qemu-efi-aarch64/QEMU_EFI.fd'),'-drive',f'file={seed},format=raw,if=none,id=seed,readonly=on','-device','virtio-blk-pci,drive=seed']
    else: args+=['-bios',str(base/'usr/share/seabios/bios.bin'),'-drive',f'file={seed},format=raw,if=virtio,readonly=on']
    return args

def normalize_line(line):
    line=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',line).replace('\x1b]104\x07','').strip()
    return re.sub(r'^(?:\[\s*\d+(?:\.\d+)?\]\s+)?python3\[\d+\]:\s*','',line)

def parse_serial(serial,distro,*,scope='full_lifecycle'):
    if scope not in ('full_lifecycle','remote_only','fresh_native_core_only','existing_core_integration'):raise ValueError('Unknown validation scope')
    identity={}; cases=[]; health=[]; boots=[]; identity_seen=False
    marker_lines=[normalize_line(line) for line in serial.splitlines()]
    kernel_oom=any(re.match(r'^\[\s*\d+(?:\.\d+)?\]\s+(?:Out of memory: Killed process \d+|Memory cgroup out of memory: Killed process \d+|oom-kill:constraint=)',line) for line in (re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw).strip() for raw in serial.splitlines()))
    remote_complete=marker_lines.count('VPS_REMOTE_COMPLETE')==1
    complete=marker_lines.count('VPS_COMPLETE')==1
    for line in marker_lines:
        if line.startswith('VPS_ENV '):
            if identity_seen:raise ValueError('Duplicate guest identity')
            identity_seen=True
            identity=json.loads(line.removeprefix('VPS_ENV '))
            if set(identity)-{'actual_distro','os_id','version','architecture','kernel','pid1','ram_kib','installer_sha256'}:raise ValueError('Unexpected guest identity fields')
        if line.startswith('VPS_BOOT '):
            item=json.loads(line.removeprefix('VPS_BOOT '))
            if set(item)!={'phase','boot','services','add','delete','add_command_exit_code','delete_command_exit_code'} or item['phase'] not in ('remote_reboot','native_core_reboot') or type(item['boot']) is not int or item['boot'] not in (1,2,3) or not isinstance(item['services'],dict):raise ValueError('Invalid reboot event')
            boots.append(item)
        if line.startswith('VPS_HEALTH '):
            item=json.loads(line.removeprefix('VPS_HEALTH '))
            if set(item)!={'phase','service','properties'} or item['phase'] not in ('remote_reboot','native_core_reboot') or item['service'] not in ('crowdsec','crowdsec-firewall-bouncer') or not isinstance(item['properties'],str):raise ValueError('Invalid health event')
            health.append(item)
        if not line.startswith('VPS_RESULT '): continue
        item=json.loads(line.split('VPS_RESULT ',1)[1]); assertions=item.get('assertions',{})
        if set(item)-{'case','exit_code','command_exit_code','assertions'}:raise ValueError('Unexpected guest result fields')
        if any(type(v) is not bool for v in assertions.values()):raise ValueError('Guest assertions must be booleans')
        if item.get('case') not in CASE_ASSERTIONS:raise ValueError('Unexpected guest case')
        required=CASE_ASSERTIONS[item['case']]
        cmd=item.get('command_exit_code')
        command_ok=type(cmd) is int and (1<=cmd<=123 if item['case'] in REFUSAL_CASES else cmd==0)
        item['status']='passed' if command_ok and set(assertions)==set(required) and type(item.get('exit_code')) is int and item.get('exit_code')==0 and required and all(assertions.get(name) is True for name in required) and all(v is True for v in assertions.values()) else 'failed'
        item['validation_level']='actual_systemd'; cases.append(item)
    states={name:sum(c['case']==name for c in cases)==1 and all(c['status']=='passed' for c in cases if c['case']==name) for name in REQUIRED}
    core_cases=[c for c in cases if c['case']=='core_relay_install']
    core_status=core_cases[0]['status'] if len(core_cases)==1 else 'not_tested' if not core_cases else 'failed'
    def phase_healthy(phase,services):
        return all(len(events:=[h for h in health if h['phase']==phase and h['service']==service])==1 and service_healthy(events[0]['properties']) for service in services)
    def boots_healthy(phase,services):
        events=[b for b in boots if b['phase']==phase]
        return len(events)==3 and {b['boot'] for b in events}=={1,2,3} and all(set(b['services'])==set(services) and all(v is True for v in b['services'].values()) and b['add'] is True and b['delete'] is True and all(type(b[k]) is int and b[k]==0 for k in ('add_command_exit_code','delete_command_exit_code')) for b in events)
    remote_health=phase_healthy('remote_reboot',('crowdsec-firewall-bouncer',)) and boots_healthy('remote_reboot',('crowdsec-firewall-bouncer',))
    core_health=phase_healthy('native_core_reboot',('crowdsec','crowdsec-firewall-bouncer')) and boots_healthy('native_core_reboot',('crowdsec','crowdsec-firewall-bouncer'))
    remote_status='not_tested' if scope in ('fresh_native_core_only','existing_core_integration') else 'passed' if identity_matches(identity,distro) and accepted(identity,states) and remote_complete and remote_health else 'failed' if cases else 'not_tested'
    core_required=('core_relay_install','native_core_reboot','native_core_decision_add','native_core_decision_delete')
    if scope in ('fresh_native_core_only','existing_core_integration'):core_required=core_required+('core_repeat_install',)
    if scope=='existing_core_integration':core_required=core_required+('core_repository_setup','core_package_install','existing_core_config_preserved')
    required=REQUIRED if scope=='remote_only' else core_required if scope in ('fresh_native_core_only','existing_core_integration') else REQUIRED+core_required+('help_and_readonly_status','retained_remote_refused_relay','retained_remote_refused_core')
    unique_pass=lambda name:sum(c['case']==name for c in cases)==1 and all(c['status']=='passed' for c in cases if c['case']==name)
    has_identity=identity_matches(identity,distro)
    status='passed' if not kernel_oom and 'VPS_HARNESS_FAILED' not in marker_lines and has_identity and complete and all(unique_pass(n) for n in required) and len({c['case'] for c in cases})==len(cases) and all(c['status']=='passed' for c in cases) and (scope in ('fresh_native_core_only','existing_core_integration') or remote_status=='passed') and (scope=='remote_only' or core_health) else 'failed' if cases or kernel_oom or 'VPS_HARNESS_FAILED' in marker_lines else 'not_tested'
    return {'distro':distro,**identity,'scope':scope,'validation_level':'actual_systemd' if identity.get('pid1')=='systemd' else 'not_tested','status':status,'remote_status':remote_status,'core_status':core_status,'cases':cases,'health':health,'boots':boots,'remote_complete':remote_complete,'complete':complete,'missing_cases':[name for name in required if not any(c['case']==name for c in cases)],'kernel_oom_observed':kernel_oom,'failure_cause':None if status=='passed' else 'Kernel OOM observed during guest lifecycle.' if kernel_oom else 'Required identity, cases, completion or reboot health incomplete/failed.'}

def final_status(status,timed_out,returncode,*,stopped_by_agent=False):
    return status if timed_out is False and type(returncode) is int and returncode==0 and stopped_by_agent is False else 'failed'

def file_digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
    return h.hexdigest()


def validate_seed(seed,artifacts,distro,scope):
    if distro not in TARGETS:raise ValueError('Unknown target system')
    selected=artifacts.get('test_scope')
    if selected not in ('full_lifecycle','remote_only','fresh_native_core_only','existing_core_integration') or (scope and scope!=selected):raise ValueError('Seed scope mismatch')
    if artifacts.get('architecture')!=('arm64' if 'arm64' in distro else 'amd64'):raise ValueError('Seed architecture mismatch')
    for path,key in [(seed,'seed_sha256'),(seed.with_suffix('.payload.tgz'),'payload_sha256')]:
        if not artifacts.get(key) or file_digest(path)!=artifacts[key]:raise ValueError('Seed artifact hash mismatch')
    mapping={'installer_sha256':'opt/test/repo/install-crowdsec-1panel.sh','hub_helper_sha256':'opt/test/repo/lib/crowdsec_hub_snapshot.py','remote_helper_sha256':'opt/test/repo/lib/remote_bouncer.sh','guest_sha256':'opt/test/guest.py','phase2_sha256':'opt/test/phase2.py','runtime_sha256':'opt/test/vps_guest_runtime.py','native_phase_sha256':'opt/test/native-phase.py'}
    with tarfile.open(seed.with_suffix('.payload.tgz')) as tar:
        if artifacts.get('scope_control_sha256'):
            with tar.extractfile('opt/test/test-scope.txt') as f:control=f.read(1024)
            if hashlib.sha256(control).hexdigest()!=artifacts['scope_control_sha256'] or control.decode().strip()!=selected:raise ValueError('Guest scope control mismatch')
        for name,expected in {**artifacts.get('source_sha256',{}),**artifacts.get('soak_sources',{})}.items():
            member=tar.getmember(name)
            if not member.isfile() or member.size>67108864:raise ValueError('Invalid soak source')
            with tar.extractfile(member) as f:
                if hashlib.sha256(f.read()).hexdigest()!=expected:raise ValueError('Soak source hash mismatch')
        for key,name in mapping.items():
            member=tar.getmember(name)
            if not member.isfile() or member.size>1048576:raise ValueError('Invalid payload source')
            with tar.extractfile(member) as f:digest=hashlib.sha256(f.read()).hexdigest()
            if digest!=artifacts.get(key):raise ValueError('Payload source hash mismatch')
    return selected


def run_qemu(argv,serial,env,timeout):
    timed_out=False;stopped=False
    with serial.open('x') as stream:
        process=subprocess.Popen(argv,stdout=stream,stderr=subprocess.STDOUT,env=env)
        try:process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired,KeyboardInterrupt) as error:
            timed_out=isinstance(error,subprocess.TimeoutExpired);stopped=not timed_out
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
    return timed_out,stopped,process.returncode


def finish_report(serial,distro,scope,artifacts,timed_out,returncode,stopped):
    try:result=parse_serial(serial.read_text(errors='replace'),distro,scope=scope)
    except (ValueError,TypeError,AttributeError,KeyError):
        result={'distro':distro,'scope':scope,'status':'failed','failure_cause':'Malformed guest evidence.','cases':[]}
    if result.get('installer_sha256')!=artifacts.get('installer_sha256') or not artifacts.get('installer_sha256'):
        result['status']='failed'
        if result.get('failure_cause')!='Malformed guest evidence.':result['failure_cause']='Guest source provenance missing or mismatched.'
    if artifacts.get('soak_duration_seconds'):
        try:
            lines=[normalize_line(line) for line in serial.read_text(errors='replace').splitlines()]
            ends=[json.loads(line.removeprefix('VPS_SOAK_COMPLETE ')) for line in lines if line.startswith('VPS_SOAK_COMPLETE ')]
            events=[json.loads(line.removeprefix('VPS_SOAK_EVENT ')) for line in lines if line.startswith('VPS_SOAK_EVENT ')]
            if len(ends)!=1:raise ValueError('Missing unique completion')
            soak=ends[0]
            soak.update(samples=[{k:v for k,v in e.items() if k!='kind'} for e in events if e.get('kind')=='sample'],sync=[{k:v for k,v in e.items() if k!='kind'} for e in events if e.get('kind')=='sync'],recoveries=[])
            finals=[{k:v for k,v in e.items() if k!='kind'} for e in events if e.get('kind')=='final_observation']
            if len(finals)!=1:raise ValueError('Missing unique final observation')
            soak['final_observation']=finals[0]
            setups=[{k:v for k,v in e.items() if k!='kind'} for e in events if e.get('kind')=='setup']
            if len(setups)!=1:raise ValueError('Missing unique endpoint setup')
            soak['setup']=setups[0]
            provenance=artifacts.get('soak_sources',{})
            if soak.get('duration_seconds')!=artifacts['soak_duration_seconds'] or soak.get('mode')!='local' or soak.get('observer_sha256')!=provenance.get('opt/test/relay_soak_guest.py') or soak.get('manifest_sha256')!=provenance.get('opt/test/soak-manifest.json'):raise ValueError('Soak provenance mismatch')
            result['soak']=assess_soak(soak)
            if result['soak']['status']!='passed':result['status']='failed';result['failure_cause']='Soak incomplete or failed.'
        except (ValueError,TypeError,AttributeError,KeyError):result['status']='failed';result['failure_cause']='Malformed or incomplete soak evidence.'
    result.update(host_assessment_sources=HOST_ASSESSMENT_SOURCES,artifacts=artifacts,evidence=str(serial),timed_out=timed_out,qemu_exit_code=returncode,stopped_by_agent=stopped,serial_sha256=file_digest(serial))
    result['status']=final_status(result['status'],timed_out,returncode,stopped_by_agent=stopped)
    result['stage_status_interpretation']='Raw case observations; only overall status includes guest process termination.'
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--distro',required=True);p.add_argument('--lab',default='/tmp/crowdsec-vps-rpm-arm-lab');p.add_argument('--timeout',type=int,default=3600);p.add_argument('--ram',type=int,default=1024);p.add_argument('--seed',type=Path);p.add_argument('--scope',choices=['full_lifecycle','remote_only','fresh_native_core_only','existing_core_integration'])
    a=p.parse_args();lab=Path(a.lab);serial=lab/(a.distro+'.serial.log');report=lab/(a.distro+'.json')
    if serial.exists() or report.exists():p.error('Refusing to overwrite historical evidence')
    if a.timeout<=0 or a.ram<=0:p.error('Positive timeout/RAM required')
    seed=a.seed or lab/('seed-arm.iso' if 'arm64' in a.distro else 'seed-rpm.iso')
    artifacts=json.loads(seed.with_suffix('.provenance.json').read_text())
    scope=validate_seed(seed,artifacts,a.distro,a.scope)
    image=lab/'images'/(a.distro+'.qcow2');image_hash=file_digest(image)
    env=os.environ.copy();env['LD_LIBRARY_PATH']='/tmp/crowdsec-qemu-lab/host/usr/lib/x86_64-linux-gnu:/tmp/crowdsec-qemu-lab/host/lib/x86_64-linux-gnu'
    started=time.monotonic()
    timed_out,stopped,returncode=run_qemu(qemu_command(a.distro,lab,image,seed,a.ram),serial,env,a.timeout)
    result=finish_report(serial,a.distro,scope,artifacts,timed_out,returncode,stopped)
    result.update(ram_mib=a.ram,image_sha256=image_hash,elapsed_seconds=round(time.monotonic()-started,3))
    with report.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
    return 0 if result['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
"""Bounded real-systemd QEMU runner; only explicit guest assertions count as passes."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess


REQUIRED_CASES={
    'help_entry':('documented_option','core_unchanged'),
    'remote_readonly_status':('config_unchanged',),
    'fresh_remote_install':('active','enabled','local_exists'),
    'repeat_remote_install':('active',),
    'change_url_and_key':('changed','active'),
    'bad_key_preserves_state':('rejected','local_unchanged','active'),
    'foreign_local_ownership':('rejected','local_unchanged','active'),
    'boot_auto_start':('active','enabled'),
    'remove_managed_remote':('inactive','disabled','local_removed'),
    'existing_core_preserved':('unchanged',),
    'official_decision_nft_ban_sync':('ban_present',),
    'official_decision_nft_unban_sync':('ban_removed',),
}

CORE_REQUIRED_CASES={
    'fresh_core_relay_install':('core_active','bouncer_active')}

def parse_serial(serial, distro):
    cases=[]; environment={}
    for line in serial.splitlines():
        for marker in ('VPS_ENV ', 'VPS_RESULT '):
            if marker in line:
                line=line[line.index(marker):]
                break
        if line.startswith('VPS_ENV '):
            environment=json.loads(line[8:])
        if not line.startswith('VPS_RESULT '):
            continue
        item=json.loads(line[11:])
        if set(item)-{'case','exit_code','command_exit_code','assertions','failure_cause','observations'}:
            raise ValueError('unstructured guest fields forbidden in evidence')
        observations=item.get('observations') or {}
        if not isinstance(observations,dict) or any(not isinstance(value,(bool,int,float)) for value in observations.values()):
            raise ValueError('observations must contain only scalar numerical/boolean evidence')
        encoded=json.dumps(item).lower()
        if any('\"'+key+'\"' in encoded for key in ('api_key','password','credentials','token')):
            raise ValueError('credential fields forbidden in evidence')
        assertions=item.get('assertions',{})
        required=REQUIRED_CASES.get(item.get('case'),CORE_REQUIRED_CASES.get(item.get('case'),()))
        item['status']='passed' if item.get('exit_code')==0 and assertions and all(assertions.get(name) is True for name in required) and all(value is True for value in assertions.values()) else 'failed'
        item['validation_level']='actual_systemd'
        if item['status']=='failed':
            failed=[name for name in set(required)|set(assertions) if assertions.get(name) is not True]
            item['failure_cause']='Command exit %s; missing/false assertions: %s' % (item.get('exit_code'), ', '.join(sorted(failed)) or 'no assertions')
        if item.get('case') in ('core_status','core_log_check','core_relay_status') and item.get('exit_code')==2:
            item['status']='unverified'
            item['failure_cause']='Read-only diagnostic exit 2 denotes pending/unverified evidence, not installation incompatibility.'
        cases.append(item)
    missing=sorted(set(REQUIRED_CASES)-{item['case'] for item in cases})
    journal_prefix=r'(?:\[\s*\d+(?:\.\d+)?\]\s*)?python3\[\d+\]: '
    complete=any(line=='VPS_COMPLETE' or re.fullmatch(journal_prefix+'VPS_COMPLETE',line) for line in serial.splitlines())
    by_name={item['case']:item for item in cases}
    remote_complete=any(line=='VPS_REMOTE_COMPLETE' or re.fullmatch(journal_prefix+'VPS_REMOTE_COMPLETE',line) for line in serial.splitlines())
    remote_passed=not missing and remote_complete and environment.get('init')=='systemd' and all(item['status']=='passed' for item in cases if item['case'] in REQUIRED_CASES)
    core_cases=[item for item in cases if item['case'].startswith('core_') or item['case']=='fresh_core_relay_install']
    core_status=('failed' if any(item['status']=='failed' for item in core_cases) else ('passed' if complete else 'incomplete')) if core_cases else 'not_tested'
    missing_core=sorted(set(CORE_REQUIRED_CASES)-set(by_name))
    if missing_core and core_cases and core_status!='failed': core_status='incomplete'
    accepted=cases and not missing and not missing_core and remote_complete and complete and environment.get('init')=='systemd' and all(c['status'] in ('passed','unverified') for c in cases)
    return {'distro':distro, **environment, 'validation_level':'actual_systemd' if cases else 'not_tested', 'status':'passed' if accepted else ('failed' if cases else 'not_tested'),'cases':cases,'remote_status':'passed' if remote_passed else ('failed' if any(item['status']=='failed' for item in cases if item['case'] in REQUIRED_CASES) else 'incomplete'),'core_status':core_status,'missing_required_cases':missing,'complete':complete,'remote_complete':remote_complete,'missing_core_cases':missing_core,'scope':'remote lifecycle plus separate package core relay installation; other script workflows not covered','failure_cause':None if accepted else 'Incomplete or failed guest acceptance; requires systemd, complete marker, and every required case.'}


def qemu_command(qemu,image,seed,ram):
    return [qemu,'-accel','tcg','-machine','q35','-cpu','max','-m',str(ram),'-smp','1','-nographic','-monitor','none','-drive',f'file={image},format=qcow2,if=virtio,snapshot=on','-drive',f'file={seed},format=raw,if=virtio,readonly=on','-netdev','user,id=n1','-device','virtio-net-pci,netdev=n1,romfile=']


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qemu',required=True); p.add_argument('--image',required=True); p.add_argument('--seed',required=True); p.add_argument('--distro',required=True)
    p.add_argument('--ram',type=int,default=1024); p.add_argument('--timeout',type=int,default=1500); p.add_argument('--output',required=True); p.add_argument('--serial',required=True)
    args=p.parse_args()
    env=os.environ.copy(); qroot=Path(args.qemu).parents[2]
    env['LD_LIBRARY_PATH']=str(qroot/'usr/lib/x86_64-linux-gnu')+':'+str(qroot/'lib/x86_64-linux-gnu')
    argv=qemu_command(args.qemu,args.image,args.seed,args.ram)+['-L',str(qroot/'usr/share/qemu'),'-bios',str(qroot/'usr/share/seabios/bios.bin')]
    timed_out=False
    fd=os.open(args.serial,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    os.chmod(args.serial,0o600)
    with os.fdopen(fd,'w') as stream:
        process=subprocess.Popen(argv,stdout=stream,stderr=subprocess.STDOUT,env=env)
        try: process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out=True; process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    record=parse_serial(Path(args.serial).read_text(errors='replace'),args.distro)
    if timed_out or process.returncode != 0:
        record['status']='failed' if record['cases'] else 'not_tested'
        record['failure_cause']='QEMU timed out or exited unsuccessfully.'
    record.update(ram_mib=args.ram,qemu_exit_code=process.returncode,timed_out=timed_out,evidence=args.serial)
    Path(args.output).write_text(json.dumps(record,indent=2)+'\n')
    return 0 if record['status']=='passed' else 1

if __name__=='__main__': raise SystemExit(main())

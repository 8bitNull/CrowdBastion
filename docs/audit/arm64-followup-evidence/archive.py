import pathlib,json,re,hashlib,sys,datetime
sys.path.insert(0,'/data/project/script/crowdsec-1key/tests')
from verify_vps_rpm_arm import CASE_ASSERTIONS,REQUIRED
lab=pathlib.Path('/tmp/crowdsec-arm-followup'); repo=pathlib.Path('/data/project/script/crowdsec-1key')
required={**CASE_ASSERTIONS};required.pop('official_lapi')
required.update(native_core_reboot=('core_active','bouncer_active','core_enabled','bouncer_enabled'),native_core_decision_add=('synced',),native_core_decision_delete=('synced',))
# Recognize only actual known console prefixes, never markers embedded within notes.
def clean(line):
    line=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',line).replace('\x1b]104\x07','').strip()
    return re.sub(r'^(?:\[\s*\d+(?:\.\d+)?\]\s+)?python3\[\d+\]:\s*','',line)
def property_health(data):
    if not isinstance(data,str):return False
    fields={}
    for line in data.splitlines():
        if '=' not in line:continue
        key,value=line.split('=',1)
        if key in fields:return False
        fields[key]=value
    return fields.get('ActiveState')=='active' and fields.get('SubState')=='running' and fields.get('Result')=='success'
raw=(lab/'serial.log').read_text(errors='replace'); lines=[clean(v) for v in raw.splitlines()]
identities=[];cases=[];diagnostics=[];safe=[]
for line in lines:
    if line.startswith('VPS_ENV '):
        e=json.loads(line.removeprefix('VPS_ENV '))
        assert set(e)=={'actual_distro','os_id','version','architecture','kernel','pid1','ram_kib','installer_sha256'}
        identities.append(e);safe.append(line)
    elif line.startswith('VPS_RESULT '):
        c=json.loads(line.removeprefix('VPS_RESULT '));assert set(c)=={'case','exit_code','command_exit_code','assertions'}
        assert c['case'] in required and type(c['exit_code']) is int and type(c['command_exit_code']) is int
        assert set(c['assertions'])==set(required[c['case']]) and all(type(v) is bool for v in c['assertions'].values())
        refusal=c['case'] in ('bad_key_preserves_state','foreign_local_ownership','retained_remote_refused_relay','retained_remote_refused_core')
        command_ok=(c['command_exit_code']!=0) if refusal else (c['command_exit_code']==0)
        c['status']='passed' if c['exit_code']==0 and command_ok and all(c['assertions'].values()) else 'failed'
        cases.append(c);safe.append(line)
    elif line.startswith('CORE_DIAG '):
        d=json.loads(line.removeprefix('CORE_DIAG '));assert set(d)=={'case','data'};diagnostics.append(d);safe.append(line)
    elif line.startswith(('VPS_NOTE remote_readiness_elapsed ','VPS_NOTE native_readiness_elapsed ')):
        float(line.rsplit(' ',1)[1]);safe.append(line)
    elif line in ('VPS_REMOTE_COMPLETE','VPS_COMPLETE','ARM_FOLLOWUP_COMPLETE','ARM_FOLLOWUP_ABORT'):safe.append(line)
first_states={name:next((d['data'] for d in diagnostics if d['case']==name+'_state'),None) for name in ('crowdsec','crowdsec-firewall-bouncer')}
health_ok=all(property_health(data) for data in first_states.values())
health={'status':'passed' if health_ok else 'failed','phase':'remote_post_reboot_diagnostics_before_removal','states':first_states,'reason':None if health_ok else 'Service snapshots do not confirm both core and remote Bouncer healthy; raw instantaneous active predicate is insufficient.'}
runner=json.loads((lab/'runner.json').read_text());provenance=json.loads((lab/'provenance.json').read_text())
assert len(identities)==1
identity=identities[0];assert identity['installer_sha256']==provenance['installer_sha256']
assert identity['pid1']=='systemd' and identity['os_id']=='debian' and identity['version']=='13' and identity['architecture']=='aarch64' and type(identity['ram_kib']) is int
states={name:len([c for c in cases if c['case']==name])==1 and all(c['status']=='passed' for c in cases if c['case']==name) for name in required}
completion=all(lines.count(v)==1 for v in ('VPS_REMOTE_COMPLETE','VPS_COMPLETE','ARM_FOLLOWUP_COMPLETE'))
process_ok=type(runner['qemu_exit_code']) is int and runner['qemu_exit_code']==0 and runner['timed_out'] is False and runner.get('stopped_by_agent',False) is False
result={'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'execution_state':'completed','status':'passed' if all(states.values()) and health_ok and completion and process_ok else 'failed','scope':'official_native_arm64_bootstrap_remote_lifecycle_existing_core_integration_attempt','identity':identity,'runner':runner,'remote_status':'passed' if all(states[n] for n in REQUIRED) and health_ok and lines.count('VPS_REMOTE_COMPLETE')==1 and process_ok else 'failed','existing_core_integration_status':'not_tested' if not any(c['case']=='core_relay_install' for c in cases) else 'passed' if all(states[n] for n in ('core_relay_install','native_core_reboot','native_core_decision_add','native_core_decision_delete')) and completion and process_ok else 'failed','post_reboot_health':health,'raw_case_assertion_status':'passed' if all(states.values()) else 'failed','required_assertions':required,'missing_or_failed_cases':[n for n,v in states.items() if not v],'completion_markers_valid':completion,'cases':cases,'diagnostics':diagnostics,'artifacts':provenance,'raw_serial_sha256':hashlib.sha256((lab/'serial.log').read_bytes()).hexdigest(),'limits':['QEMU TCG functional evidence; not VPS throughput or CPU capacity.','Core was already installed as the native LAPI before relay integration; not a cold core install.','No real公网 forwarding, long-duration, or vendor-specific VPS tests.']}
evidence=repo/'docs/audit/arm64-followup-evidence';evidence.mkdir(exist_ok=True)
archive=evidence/'debian13-arm64.serial.log';archive.write_text('\n'.join(safe)+'\n');result['evidence']=str(archive.relative_to(repo));result['evidence_sha256']=hashlib.sha256(archive.read_bytes()).hexdigest()
for name in ['build.py','guest.py','phase2.py','phase3.py','run.py','archive.py','provenance.json','check_harness.py','harness-regression.json','observer-stop.json']:
    (evidence/name).write_bytes((lab/name).read_bytes())
(evidence/'attempt1-runner.json').write_bytes((lab/'attempt1/runner.json').read_bytes())
(repo/'docs/audit/2026-10-12-arm64-followup-results.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({k:result[k] for k in ('status','remote_status','existing_core_integration_status','missing_or_failed_cases','runner')},indent=2))

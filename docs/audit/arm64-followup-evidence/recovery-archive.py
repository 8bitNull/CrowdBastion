import pathlib,json,re,hashlib,datetime
lab=pathlib.Path('/tmp/crowdsec-arm-recovery');repo=pathlib.Path('/data/project/script/crowdsec-1key')
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
raw=(lab/'serial.log').read_text(errors='replace');lines=[clean(l) for l in raw.splitlines()];env=[];cases=[];notes=[];safe=[]
required={'isolated_official_precheck':{'successful'},'controlled_core_start':{'core_active'},'controlled_bouncer_start':{'bouncer_active'},'controlled_decision_add':{'synced'},'controlled_decision_delete':{'synced'}}
for l in lines:
 if l.startswith('ARM_RECOVERY_ENV '):
  e=json.loads(l.removeprefix('ARM_RECOVERY_ENV '));assert set(e)=={'architecture','pid1','installer_sha256'};env.append(e);safe.append(l)
 elif l.startswith('ARM_RECOVERY_RESULT '):
  c=json.loads(l.removeprefix('ARM_RECOVERY_RESULT '));assert set(c)=={'case','exit_code','assertions'} and c['case'] in required
  assert type(c['exit_code']) is int and set(c['assertions'])==required[c['case']] and all(type(v) is bool for v in c['assertions'].values())
  c['status']='passed' if c['exit_code']==0 and all(c['assertions'].values()) else 'failed';cases.append(c);safe.append(l)
 elif l.startswith('ARM_RECOVERY '):
  n=json.loads(l.removeprefix('ARM_RECOVERY '));assert set(n)=={'case','data'} and type(n['data']) is str;notes.append(n);safe.append(l)
 elif l=='ARM_RECOVERY_COMPLETE':safe.append(l)
provenance=json.loads((lab/'provenance.json').read_text());runner=json.loads((lab/'runner.json').read_text())
assert len(env)==1 and env[0]['architecture']=='aarch64' and env[0]['pid1']=='systemd' and env[0]['installer_sha256']==provenance['original_installer_sha256']
states={k:len([c for c in cases if c['case']==k])==1 and all(c['status']=='passed' for c in cases if c['case']==k) for k in required}
contamination=any(l.startswith(('VPS_ENV ','VPS_RESULT ','VPS_PROGRESS ')) for l in lines)
complete=lines.count('ARM_RECOVERY_COMPLETE')==1
health_events={name:[n['data'] for n in notes if n['case']=='controlled_'+name+'_properties'] for name in ('crowdsec','crowdsec-firewall-bouncer')}
health={name:values[0] if len(values)==1 else None for name,values in health_events.items()}
healthy=all(property_health(data) for data in health.values())
passed=all(states.values()) and healthy and complete and not contamination and type(runner['qemu_exit_code']) is int and runner['qemu_exit_code']==0 and runner['timed_out'] is False and runner.get('stopped_by_agent',False) is False
out=repo/'docs/audit/arm64-followup-evidence';out.mkdir(exist_ok=True);a=out/'recovery.serial.log';a.write_text('\n'.join(safe)+'\n')
r={'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'passed' if passed else 'failed','scope':'cloned_guest_diagnostic_timeout_control_only','identity':env[0],'cases':cases,'diagnostics':notes,'controlled_final_health':health,'harness_progress_seen':contamination,'complete':complete,'runner':runner,'artifacts':provenance,'evidence':str(a.relative_to(repo)),'evidence_sha256':hashlib.sha256(a.read_bytes()).hexdigest(),'raw_serial_sha256':hashlib.sha256((lab/'serial.log').read_bytes()).hexdigest(),'production_installer_changed':False,'limits':['This is a cloned post-failure guest with diagnostic TimeoutStartSec=300; not acceptance of the original default boot or installer.','Boot conditions, stopped services and caches differ; does not uniquely establish CPU contention as the root cause.','Harness units masked by bootcmd; no harness progress observed in this boot.','No subsequent reboot under diagnostic timeout was tested.']}
for n in ['guest.py','build.py','run.py','archive.py','provenance.json','check_archive.py','archive-regression.json']:(out/('recovery-'+n)).write_bytes((lab/n).read_bytes())
(repo/'docs/audit/2026-10-12-arm64-recovery-results.json').write_text(json.dumps(r,indent=2,ensure_ascii=False)+'\n');print(json.dumps({'status':r['status'],'cases':len(cases),'harness_progress_seen':contamination,'runner':runner}))

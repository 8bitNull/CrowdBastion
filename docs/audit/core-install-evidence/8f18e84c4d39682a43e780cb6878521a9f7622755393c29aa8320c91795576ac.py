import pathlib,json,hashlib,re,datetime,shutil,sys,io,tarfile
sys.path.insert(0,"/tmp/crowdsec-vps-deb-lab/pylib")
import pycdlib
lab=pathlib.Path('/tmp/crowdsec-core-diagnostic');repo=pathlib.Path('/data/project/script/crowdsec-1key');archive=repo/'docs/audit/core-install-evidence';archive.mkdir(exist_ok=True)
required={
'fixed_fresh_core_relay_install':('core_active','bouncer_active'),
'fixed_core_repeat':('main_config_preserved','core_active','bouncer_active'),
'fixed_core_reboot':('core_active','bouncer_active','bouncer_enabled'),
'fixed_core_decision_add':('ban_present',),
'fixed_core_decision_delete':('ban_removed',)}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def lines(raw):
 for line in raw.splitlines():
  line=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',line).strip()
  for marker in ['CORE_DIAG ','CORE_DIAG_ENV ','CORE_FIXED_ENV ','CORE_DIAG_COMPLETE','CORE_FIXED_COMPLETE','VPS_RESULT ','VPS_ENV ']:
   if marker in line:
    # Accept standalone, known systemd console or known getty prompt only.
    prefix=line[:line.index(marker)]
    if prefix and not re.fullmatch(r'(?:\[\s*\d+(?:\.\d+)?\]\s*)?python3\[\d+\]: ',prefix) and prefix not in ['core-diag login: ','core-diag-color login: ','core-fixed login: ']:continue
    yield line[line.index(marker):];break
records=[]
for name in ['cold','after-remote','verify-color','fixed-debian13','fixed-jammy','fixed-noble','fixed-debian13-observer','fixed-debian13-observer-v2']:
 raw=lab/(name+'.serial.log')
 if not raw.exists():continue
 selected=list(lines(raw.read_text(errors='replace')))
 p=archive/(name+'.log');p.write_text('\n'.join(selected)+'\n')
 r={'attempt':name,'evidence':str(p.relative_to(repo)),'evidence_sha256':sha(p),'archive_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'fresh native core, repeat, reboot and decision synchronization' if name.startswith('fixed-') else 'diagnostic root-cause investigation','validation_level':'actual_systemd','requested_ram_mib':1024,'vcpus':1}
 runner=lab/(name+'-runner.json' if name.startswith('fixed-') else name+'-result.json')
 if runner.exists():
  q=json.loads(runner.read_text());r.update(qemu_exit_code=q['qemu_exit_code'],timed_out=q['timed_out'])
 else:r.update(qemu_exit_code=None,timed_out=None)
 if name.startswith('fixed-'):
  envs=[json.loads(line[len('CORE_FIXED_ENV '):]) for line in selected if line.startswith('CORE_FIXED_ENV ')];r['environment']=envs[-1] if len(envs)==1 else None
  r['cases']=[json.loads(line[len('VPS_RESULT '):]) for line in selected if line.startswith('VPS_RESULT ')]
  checks=[]
  for case,keys in required.items():
   rows=[row for row in r['cases'] if row.get('case')==case]
   checks.append(len(rows)==1 and type(rows[0].get('exit_code')) is int and rows[0]['exit_code']==0 and set(rows[0].get('assertions',{}))==set(keys) and all(rows[0]['assertions'][key] is True for key in keys))
  r['complete']='CORE_FIXED_COMPLETE' in selected
  r['expected_installer_sha256']=sha(repo/'install-crowdsec-1panel.sh')
  r['source_matches']=bool(r['environment'] and r['environment'].get('installer_sha256')==r['expected_installer_sha256'])
  passed=r['source_matches'] and all(checks) and len(r['cases'])==len(required) and r['complete'] and r['environment'] and r['environment']['init']=='systemd' and r['qemu_exit_code']==0 and r['timed_out'] is False
  r['status']='passed' if passed else 'incomplete_or_failed'
  if not r['environment']:r['validation_level']='not_tested'
  if name=='fixed-debian13':r['failure_cause']='Guest powered off but case output was not captured; no core acceptance claim.'
  if name=='fixed-debian13-observer':r['failure_cause']='QEMU could not open the task disk after disk creation failed from a missing portable library; no guest test executed.'
 else:
  r['diagnostics']=[json.loads(line[len('CORE_DIAG '):]) for line in selected if line.startswith('CORE_DIAG ')];r['complete']='CORE_DIAG_COMPLETE' in selected
  r['status']='diagnostic_completed' if r['complete'] and r['qemu_exit_code']==0 and r['timed_out'] is False else 'incomplete'
 records.append(r)
source_artifacts={}
for source in [lab/'fixed-guest.py',lab/'verify-color-guest.py',lab/'cold-guest.py',lab/'after-remote-phase2.py',pathlib.Path('/tmp/crowdsec-core-diag-build.py'),pathlib.Path('/tmp/crowdsec-core-diag-verify-build.py'),pathlib.Path('/tmp/crowdsec-core-fixed-build.py'),pathlib.Path('/tmp/crowdsec-core-fixed-observer-build.py'),pathlib.Path('/tmp/crowdsec-core-preserved-run.py'),pathlib.Path(__file__),repo/'install-crowdsec-1panel.sh',lab/'official-bouncer-extracted/usr/lib/crowdsec-firewall-bouncer-nftables/_bouncer.sh',lab/'official-bouncer-control/postinst']:
 target=archive/(sha(source)+source.suffix);shutil.copyfile(source,target);source_artifacts[str(source)]={'evidence':str(target.relative_to(repo)),'sha256':sha(target)}
seed_sources={}
for seed in ['cold','after-remote','verify-color','fixed','fixed-observer']:
 iso=pycdlib.PyCdlib();iso.open(str(lab/(seed+'.iso')))
 payload=io.BytesIO();iso.get_file_from_iso_fp(payload,rr_path='/payload.tgz');payload.seek(0)
 mapping={}
 with tarfile.open(fileobj=payload,mode='r:gz') as tar:
  for name in ['opt/test/guest.py','opt/test/phase2.py','opt/test/repo/install-crowdsec-1panel.sh','opt/test/repo/lib/remote_bouncer.sh','opt/test/repo/lib/crowdsec_hub_snapshot.py']:
   try:member=tar.getmember(name)
   except KeyError:continue
   data=tar.extractfile(member).read();digest=hashlib.sha256(data).hexdigest();target=archive/(digest+pathlib.Path(name).suffix);target.write_bytes(data)
   mapping[name]={'evidence':str(target.relative_to(repo)),'sha256':digest}
 userdata=io.BytesIO();iso.get_file_from_iso_fp(userdata,rr_path='/user-data');data=userdata.getvalue();digest=hashlib.sha256(data).hexdigest();target=archive/(digest+'.yaml');target.write_bytes(data)
 mapping['user-data']={'evidence':str(target.relative_to(repo)),'sha256':digest};seed_sources[seed]=mapping;iso.close()
result={'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'required_fixed_cases':required,'results':records,'source_artifacts':source_artifacts,'seed_sources':seed_sources,'seed_sha256':{name:sha(lab/(name+'.iso')) for name in ['cold','after-remote','verify-color','fixed','fixed-observer']},'official_package':json.loads((lab/'official-bouncer.metadata.json').read_text()),'initial_provenance':json.loads((lab/'provenance.json').read_text()),'limitations':['QEMU TCG validates functionality, not performance','Historical compatibility matrix and original failures remain untouched','ARM64 original failures are not retested by this amd64 followup','Diagnostics redact configuration secrets and some long identifiers; no raw configuration dumps','Generic remote-suite runner acceptance is not reused for this independently scoped core test']}
(repo/'docs/audit/2026-10-12-core-install-results.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
print([(r['attempt'],r['status']) for r in records])

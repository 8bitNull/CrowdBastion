import pathlib,json,tempfile,shutil,subprocess,sys
lab=pathlib.Path('/tmp/crowdsec-arm-recovery');raw=(lab/'serial.log').read_text(errors='replace');runner=json.loads((lab/'runner.json').read_text());source=(lab/'archive.py').read_text();results=[]
healthline=next(l for l in raw.splitlines() if 'ARM_RECOVERY ' in l and 'controlled_crowdsec_properties' in l)
def conflict(text):
 prefix,payload=healthline.split('ARM_RECOVERY ',1);d=json.loads(payload);d['data']+='\nResult=timeout\n';return text.replace(healthline,prefix+'ARM_RECOVERY '+json.dumps(d))
variants=[('actual_complete_control',raw,runner,True),('duplicate_final_health',raw+'\n'+healthline+'\n',runner,False),('conflicting_result_field',conflict(raw),runner,False),('manually_stopped_runner',raw,{**runner,'stopped_by_agent':True},False),('boolean_qemu_exit',raw,{**runner,'qemu_exit_code':False},False),('missing_completion',raw.replace('ARM_RECOVERY_COMPLETE','ARM_RECOVERY_INCOMPLETE'),runner,False)]
for name,serial,runstate,expected in variants:
 with tempfile.TemporaryDirectory() as td:
  base=pathlib.Path(td);case_lab=base/'lab';case_repo=base/'repo';case_lab.mkdir();(case_repo/'docs/audit').mkdir(parents=True)
  for n in ['guest.py','build.py','run.py','archive.py','provenance.json','check_archive.py','archive-regression.json']:shutil.copy2(lab/n,case_lab/n)
  (case_lab/'serial.log').write_text(serial);(case_lab/'runner.json').write_text(json.dumps(runstate))
  code=source.replace("'/tmp/crowdsec-arm-recovery'",repr(str(case_lab))).replace("'/data/project/script/crowdsec-1key'",repr(str(case_repo)))
  p=subprocess.run([sys.executable,'-'],input=code,text=True,capture_output=True)
  result=json.loads((case_repo/'docs/audit/2026-10-12-arm64-recovery-results.json').read_text()) if p.returncode==0 else {}
  passed=result.get('status')=='passed';assert passed==expected,(name,p.returncode,p.stderr,result)
  results.append({'case':name,'accepted':passed,'expected_accepted':expected,'passed':True})
(lab/'archive-regression.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))

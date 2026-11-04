from pathlib import Path
import sys,types,unittest
sys.path[:0]=[str(Path.cwd()/'tests'),str(Path.cwd()/'lib')]
cases=[]
checks=[
 ('test_optimize_empty_selection_final_cancel_and_eof_do_not_mutate','cancel-write'),
 ('test_optimize_validation_failure_restores_selected_config','skip-rollback'),
 ('test_optimize_repeated_metrics_selection_skips_service_load','force-load')]
for method,mode in checks:
 case=unittest.TestLoader().loadTestsFromName('test_workflows.Workflows.'+method)._tests[0]
 original=case.setUp
 def prepare(self,setup=original,mutation=mode):
  setup()
  if mutation=='force-load':
   path=self.base/'lib/maintenance.sh';needle='config_change_needed() {\n';insert='    return 0 # injected unnecessary service load\n'
  else:
   path=self.source
   if mutation=='skip-rollback':needle='restore_config_change() {\n';insert='    return 0 # injected rollback omission\n'
   else:
    needle="        log_info '未选择修复项目，保持诊断结果。'"
    source=path.read_text();assert source.count(needle)==1
    path.write_text(source.replace(needle,'        printf injected-write >> "$CS_DIR/config.yaml"\n'+needle,1));return
  source=path.read_text();assert source.count(needle)==1
  path.write_text(source.replace(needle,needle+insert,1))
 case.setUp=types.MethodType(prepare,case);cases.append(case)
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(cases))
failed_ids={getattr(test, "test_case", test).id() for test,_ in result.failures}
assert result.testsRun==3 and len(failed_ids)==3 and not result.errors and not result.skipped,(failed_ids,result.errors)
print('EXPECTED MUTATIONS DETECTED: canceled write, missing rollback and repeated service load all failed original assertions')

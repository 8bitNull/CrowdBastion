from pathlib import Path
import sys,unittest,types
sys.path[:0]=[str(Path.cwd()/'tests'),str(Path.cwd()/'lib')]
from run_tests import flatten
names=[
 'test_real_ip_reload_review.RealIPReloadReview.test_silent_reload_rejection_restores_real_ip_configuration_and_registry',
 'test_script_review_fixes.AdditionalTransactionReview.test_silent_host_rollback_rejection_keeps_package_account',
 'test_nginx_reload.ReloadProcessEvidence.test_worker_that_dies_before_second_sample_is_not_accepted']
cases=list(flatten(unittest.TestLoader().loadTestsFromNames(names)))
for case in cases:
 original=case.setUp
 def prepare(self,setup=original):
  setup()
  path=self.base/'lib/nginx_reload.sh';source=path.read_text()
  needle='nginx_reload_verified() (\n'
  assert source.count(needle)==1
  path.write_text(source.replace(needle,needle+'    return 0  # Deliberately unsafe acceptance inside this disposable fixture.\n',1))
 case.setUp=types.MethodType(prepare,case)
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(cases))
assert result.testsRun==3 and len(result.failures)==3 and not result.errors and not result.skipped
print('EXPECTED MUTATIONS DETECTED: all 3 original business assertions rejected unsafe unconditional acceptance')

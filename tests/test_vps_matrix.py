"""Compatibility fixture result integrity; never booted-OS evidence."""
import importlib.util
import unittest
from pathlib import Path

FILE=Path(__file__).with_name('verify_vps_matrix.py')

def load():
    if not FILE.exists(): return None
    spec=importlib.util.spec_from_file_location('vps_matrix',FILE)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

class MatrixAcceptance(unittest.TestCase):
    def setUp(self):
        self.matrix=load()
        self.assertIsNotNone(self.matrix,'fixture matrix implementation missing')
    def test_manifest_has_all_distro_branches_and_backend_install_states(self):
        manifest=self.matrix.manifest()
        package=[c for c in manifest if c['scenario']=='package_backend']
        self.assertEqual({c['os_id'] for c in package},{'debian','ubuntu','centos','rhel','almalinux','rocky','fedora'})
        for os_id in ('debian','ubuntu','centos','rhel','almalinux','rocky','fedora'):
            combinations={(c['backend'],c['install_state']) for c in package if c['os_id']==os_id}
            self.assertEqual(combinations,{('nftables','fresh'),('iptables','fresh'),('nftables','existing'),('iptables','existing')})
        self.assertEqual(len({c['id'] for c in manifest}),len(manifest))
        self.assertTrue(all(c['validation_level']=='fixture' for c in manifest))
    def test_acceptance_requires_real_assertions_and_expected_exit(self):
        self.assertEqual(self.matrix.accept(0,0,{'preserved':True})['status'],'pass')
        self.assertEqual(self.matrix.accept(0,0,{})['status'],'fail')
        self.assertEqual(self.matrix.accept(0,0,{'preserved':False})['status'],'fail')
        self.assertEqual(self.matrix.accept(1,0,{'preserved':True})['status'],'fail')
        self.assertEqual(self.matrix.accept(2,2,{'read_only':True})['status'],'pass')
    def test_failure_cause_names_assertion_without_raw_credentials(self):
        result=self.matrix.accept(0,0,{'configuration_preserved':False})
        self.assertIn('configuration_preserved',result['failure_cause'])
        self.assertNotIn('stdout',result)
    def test_result_manifest_rejects_missing_duplicate_or_unexpected_rows(self):
        wanted=[{'id':'one'},{'id':'two'}]
        with self.assertRaises(ValueError): self.matrix.validate_results(wanted,[{'id':'one'}])
        with self.assertRaises(ValueError): self.matrix.validate_results(wanted,[{'id':'one'},{'id':'one'}])
        with self.assertRaises(ValueError): self.matrix.validate_results(wanted,[{'id':'one'},{'id':'other'}])
    def test_report_rejects_fixture_relabeling_or_forged_pass(self):
        case={'id':'one','validation_level':'fixture'}
        valid={'id':'one','validation_level':'fixture',**self.matrix.accept(0,0,{'preserved':True})}
        self.matrix.validate_results([case],[valid])
        with self.assertRaises(ValueError): self.matrix.validate_results([case],[{**valid,'validation_level':'real_systemd'}])
        with self.assertRaises(ValueError): self.matrix.validate_results([case],[{**valid,'assertions':{'preserved':False}}])
    def test_imported_archive_is_hashed_and_not_promoted_or_copied(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'old.json'
            file.write_text(json.dumps({'status':'pass','credential':'must-not-copy'}))
            imported=self.matrix.archive_import(file)
        self.assertEqual(imported['validation_level'],'archive_reference_only')
        self.assertFalse(imported['rerun'])
        self.assertEqual(imported['status'],'not_evaluated_by_fixture_runner')
        self.assertNotIn('must-not-copy',json.dumps(imported))
    def test_selected_package_and_preservation_cases_execute_with_fixture_evidence(self):
        wanted=self.matrix.manifest()
        scenarios=['package_backend','package_skip','remote_cancel','override_refusal','readonly_help','readonly_status','readonly_unverified','remote_restart_rollback']
        for scenario in scenarios:
            case=next(c for c in wanted if c['scenario']==scenario)
            result=self.matrix.run_case(case)
            self.assertEqual(result['status'],'pass',result)
            self.assertEqual(result['validation_level'],'fixture')
            self.assertIsNone(result['kernel'])
            self.assertIsNone(result['ram_mib'])
            self.assertTrue(result['assertions'])
    def test_cli_inventory_marks_every_option_covered_or_unexercised(self):
        inventory=self.matrix.cli_inventory(self.matrix.manifest())
        self.assertIn('--install-relay-bouncer',{x['option'] for x in inventory})
        self.assertIn('--telegram-test',{x['option'] for x in inventory})
        self.assertTrue(all(x['coverage'] in ('fixture','not_exercised_by_this_matrix') for x in inventory))
        telegram=next(x for x in inventory if x['option']=='--telegram-test')
        self.assertEqual(telegram['coverage'],'not_exercised_by_this_matrix')

if __name__=='__main__': unittest.main()

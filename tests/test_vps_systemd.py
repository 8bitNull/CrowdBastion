import unittest
import verify_vps_systemd as runner

class SystemdEvidenceTests(unittest.TestCase):
    def test_missing_serial_result_is_not_pass(self):
        self.assertEqual(runner.parse_serial('systemd booted', 'debian12')['status'], 'not_tested')
    def test_only_all_true_assertions_pass(self):
        record=runner.parse_serial('VPS_RESULT {"case":"repeat","exit_code":0,"assertions":{"active":false}}', 'debian12')
        self.assertEqual(record['cases'][0]['status'], 'failed')
        self.assertIn('active',record['cases'][0]['failure_cause'])
    def test_secret_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            runner.parse_serial('VPS_RESULT {"case":"repeat","api_key":"secret","assertions":{"active":true}}', 'debian12')
    def test_no_inbound_or_shares_in_qemu(self):
        argv=runner.qemu_command('/tmp/qemu','/tmp/image','/tmp/seed',512)
        self.assertIn('user', ' '.join(argv))
        self.assertNotIn('hostfwd', ' '.join(argv))
        self.assertNotIn('virtfs', ' '.join(argv))

class CompleteAcceptanceTests(unittest.TestCase):
    def test_successful_prefix_does_not_pass(self):
        record=runner.parse_serial('VPS_RESULT {"case":"guest_dependencies","exit_code":0,"assertions":{"ready":true}}','debian12')
        self.assertNotEqual(record['status'],'passed')
    def test_non_systemd_environment_does_not_pass(self):
        serial='VPS_ENV {"init":"init"}\n'+'\n'.join('VPS_RESULT '+__import__('json').dumps({'case':case,'exit_code':0,'assertions':{'ok':True}}) for case in runner.REQUIRED_CASES)+'\nVPS_COMPLETE'
        self.assertNotEqual(runner.parse_serial(serial,'debian12')['status'],'passed')
    def test_required_cases_with_missing_assertions_do_not_pass(self):
        serial='VPS_ENV {"init":"systemd"}\n'+'\n'.join('VPS_RESULT '+__import__('json').dumps({'case':case,'exit_code':0,'assertions':{'irrelevant':True}}) for case in runner.REQUIRED_CASES)+'\nVPS_COMPLETE'
        self.assertNotEqual(runner.parse_serial(serial,'debian12')['status'],'passed')
    def test_relay_status_two_is_unverified_not_incompatibility(self):
        record=runner.parse_serial('VPS_RESULT {"case":"core_relay_status","exit_code":2,"assertions":{"operation_completed":false}}','debian12')
        self.assertEqual(record['cases'][0]['status'],'unverified')
    def test_complete_required_systemd_evidence_passes(self):
        import json
        serial='VPS_ENV {"init":"systemd"}\n'+'\n'.join('VPS_RESULT '+json.dumps({'case':case,'exit_code':0,'assertions':dict.fromkeys(assertions,True)}) for case,assertions in runner.REQUIRED_CASES.items())+'\nVPS_REMOTE_COMPLETE\nVPS_RESULT '+json.dumps({'case':'fresh_core_relay_install','exit_code':0,'assertions':{'core_active':True,'bouncer_active':True}})+'\nVPS_COMPLETE'
        self.assertEqual(runner.parse_serial(serial,'debian12')['status'],'passed')
        prefixed='\n'.join('[ 12.345678] python3[123]: '+line for line in serial.splitlines())
        self.assertEqual(runner.parse_serial(prefixed,'debian12')['status'],'passed')
        bogus=serial.replace('VPS_COMPLETE','diagnostic: VPS_COMPLETE')
        self.assertFalse(runner.parse_serial(bogus,'debian12')['complete'])
        bogus=serial.replace('VPS_REMOTE_COMPLETE','configuration: VPS_REMOTE_COMPLETE')
        self.assertFalse(runner.parse_serial(bogus,'debian12')['remote_complete'])
    def test_nested_secret_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            runner.parse_serial('VPS_RESULT {"case":"repeat","assertions":{"api_key":"secret"}}','debian12')
    def test_serial_login_prefix_does_not_hide_environment(self):
        record=runner.parse_serial('vps-lab login: VPS_ENV {"init":"systemd","arch":"x86_64"}','debian13')
        self.assertEqual(record['init'],'systemd')
    def test_unstructured_guest_fields_cannot_enter_report(self):
        with self.assertRaises(ValueError):
            runner.parse_serial('VPS_RESULT {"case":"repeat","debug_dump":"unfiltered config","assertions":{"active":true}}','debian12')
    def test_remote_rows_without_phase_marker_are_incomplete(self):
        import json
        serial='VPS_ENV {"init":"systemd"}\n'+'\n'.join('VPS_RESULT '+json.dumps({'case':case,'exit_code':0,'assertions':dict.fromkeys(assertions,True)}) for case,assertions in runner.REQUIRED_CASES.items())
        self.assertNotEqual(runner.parse_serial(serial,'debian12')['remote_status'],'passed')
    def test_remote_only_cannot_certify_core(self):
        import json
        serial='VPS_ENV {"init":"systemd"}\n'+'\n'.join('VPS_RESULT '+json.dumps({'case':case,'exit_code':0,'assertions':dict.fromkeys(assertions,True)}) for case,assertions in runner.REQUIRED_CASES.items())+'\nVPS_REMOTE_COMPLETE\nVPS_COMPLETE'
        self.assertNotEqual(runner.parse_serial(serial,'debian12')['status'],'passed')
    def test_later_success_does_not_hide_failed_remote_case(self):
        import json
        rows=[{'case':'fresh_remote_install','exit_code':1,'assertions':{'active':False}}]
        rows += [{'case':case,'exit_code':0,'assertions':dict.fromkeys(assertions,True)} for case,assertions in runner.REQUIRED_CASES.items()]
        serial='VPS_ENV {"init":"systemd"}\n'+'\n'.join('VPS_RESULT '+json.dumps(row) for row in rows)+'\nVPS_REMOTE_COMPLETE'
        self.assertEqual(runner.parse_serial(serial,'debian12')['remote_status'],'failed')
    def test_diagnostic_only_cannot_mark_core_passed(self):
        record=runner.parse_serial('VPS_RESULT {"case":"core_status","exit_code":0,"assertions":{"operation_completed":true}}\nVPS_COMPLETE','debian12')
        self.assertEqual(record['core_status'],'incomplete')
        self.assertEqual(record['missing_core_cases'],['fresh_core_relay_install'])

class GuestCommandBoundsTests(unittest.TestCase):
    def test_real_timed_out_child_returns_recordable_exit_124(self):
        from pathlib import Path
        import sys,io,contextlib
        source=Path(__file__).with_name('vps_deb_guest.py').read_text()
        namespace={}
        exec(compile(source.split("os.chdir('/opt/test/repo')")[0],'guest-helpers','exec'),namespace)
        with contextlib.redirect_stdout(io.StringIO()):
            rc,_=namespace['run']([sys.executable,'-c','import time; time.sleep(5)'],timeout=0.05)
        self.assertEqual(rc,124)

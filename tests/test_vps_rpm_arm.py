import importlib.util
from pathlib import Path
import unittest

class GuestEvidenceTests(unittest.TestCase):
    def load(self):
        path=Path(__file__).with_name('verify_vps_rpm_arm.py')
        self.assertTrue(path.exists(), 'RPM/ARM guest runner is missing')
        spec=importlib.util.spec_from_file_location('rpm_arm_runner',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module
    def test_pass_requires_real_systemd_identity_and_complete_assertions(self):
        m=self.load()
        self.assertFalse(m.accepted({'pid1':'systemd'}, {'install':True}))
        identity={'pid1':'systemd','os_id':'almalinux','version':'9.8','architecture':'x86_64','kernel':'5.14','ram_kib':1000000}
        cases={name:True for name in m.REQUIRED}
        self.assertTrue(m.accepted(identity,cases))
        cases['bad_key_preserves_state']=False
        self.assertFalse(m.accepted(identity,cases))
    def test_parse_rejects_truncated_guest_report(self):
        m=self.load()
        self.assertIsNone(m.parse_report('RPM_ARM_RESULT_BEGIN\n{}\n'))
        self.assertEqual(m.parse_report('noise\nRPM_ARM_RESULT_BEGIN\n{"pid1":"systemd"}\nRPM_ARM_RESULT_END\n'),{'pid1':'systemd'})
    def test_partial_actual_guest_is_not_accepted(self):
        m=self.load()
        serial='VPS_ENV {"pid1":"systemd","os_id":"fedora","version":"44","architecture":"x86_64","kernel":"6","ram_kib":999999}\nVPS_RESULT {"case":"fresh_remote_install","exit_code":0,"assertions":{"active":true}}\n'
        result=m.parse_serial(serial,'fedora44')
        self.assertEqual(result['status'],'failed')
        self.assertIn('remove_managed_remote',result['missing_cases'])

    def test_core_failure_is_separate_from_complete_remote_acceptance(self):
        import json
        m=self.load()
        env={'pid1':'systemd','os_id':'rocky','version':'9','architecture':'x86_64','kernel':'5','ram_kib':99999,'installer_sha256':'a'*64}
        lines=['VPS_ENV '+json.dumps(env)]
        lines+=['VPS_RESULT '+json.dumps({'case':name,'exit_code':0,'command_exit_code':1 if name in m.REFUSAL_CASES else 0,'assertions':{key:True for key in m.REQUIRED_ASSERTIONS[name]}}) for name in m.REQUIRED]
        lines+=['VPS_HEALTH '+json.dumps({'phase':'remote_reboot','service':'crowdsec-firewall-bouncer','properties':'ActiveState=active\nSubState=running\nResult=success\n'})]
        for boot in range(1,4):
            lines.append('VPS_BOOT '+json.dumps({'phase':'remote_reboot','boot':boot,'services':{'crowdsec-firewall-bouncer':True},'add':True,'delete':True,'add_command_exit_code':0,'delete_command_exit_code':0}))
        lines+=['VPS_REMOTE_COMPLETE','VPS_COMPLETE']
        lines+=['VPS_RESULT '+json.dumps({'case':'core_relay_install','exit_code':1,'assertions':{'core_active':False}})]
        result=m.parse_serial('\n'.join(lines),'rocky9')
        self.assertEqual(result['remote_status'],'passed')
        self.assertEqual(result['status'],'failed')

    def test_arbitrary_true_assertion_cannot_certify_required_case(self):
        import json
        m=self.load()
        env={'pid1':'systemd','os_id':'fedora','version':'44','architecture':'x86_64','kernel':'6','ram_kib':99999,'installer_sha256':'a'*64}
        lines=['VPS_ENV '+json.dumps(env),'VPS_REMOTE_COMPLETE','VPS_COMPLETE']
        lines+=['VPS_RESULT '+json.dumps({'case':name,'exit_code':0,'assertions':{'dummy':True}}) for name in m.REQUIRED]
        self.assertEqual(m.parse_serial('\n'.join(lines),'fedora44')['remote_status'],'failed')

    def test_completion_text_inside_note_is_not_completion_marker(self):
        import json
        m=self.load()
        env={'pid1':'systemd','os_id':'fedora','version':'44','architecture':'x86_64','kernel':'6','ram_kib':99999,'installer_sha256':'a'*64}
        lines=['VPS_ENV '+json.dumps(env),'VPS_NOTE expected VPS_REMOTE_COMPLETE and VPS_COMPLETE']
        lines+=['VPS_RESULT '+json.dumps({'case':name,'exit_code':0,'command_exit_code':1 if name in m.REFUSAL_CASES else 0,'assertions':{key:True for key in m.REQUIRED_ASSERTIONS[name]}}) for name in m.REQUIRED]
        self.assertEqual(m.parse_serial('\n'.join(lines),'fedora44')['remote_status'],'failed')

    def test_guest_credential_fields_are_rejected(self):
        m=self.load()
        with self.assertRaises(ValueError):
            m.parse_serial('VPS_RESULT {"case":"fresh_remote_install","exit_code":0,"api_key":"forbidden-example","assertions":{"active":true}}','fedora44')

    def test_final_marker_without_planned_core_attempt_is_not_full_acceptance(self):
        import json
        m=self.load()
        env={'pid1':'systemd','os_id':'fedora','version':'44','architecture':'x86_64','kernel':'6','ram_kib':99999,'installer_sha256':'a'*64}
        lines=['VPS_ENV '+json.dumps(env),'VPS_REMOTE_COMPLETE','VPS_COMPLETE']
        lines+=['VPS_RESULT '+json.dumps({'case':name,'exit_code':0,'command_exit_code':1 if name in m.REFUSAL_CASES else 0,'assertions':{key:True for key in m.REQUIRED_ASSERTIONS[name]}}) for name in m.REQUIRED]
        result=m.parse_serial('\n'.join(lines),'fedora44')
        self.assertNotEqual(result['status'],'passed')
        self.assertEqual(result['core_status'],'not_tested')
        lines.insert(1,'VPS_RESULT '+json.dumps({'case':'fresh_remote_install','exit_code':1,'assertions':{key:False for key in m.REQUIRED_ASSERTIONS['fresh_remote_install']}}))
        self.assertEqual(m.parse_serial('\n'.join(lines),'fedora44')['remote_status'],'failed')

    def test_arbitrary_true_assertion_cannot_certify_native_core(self):
        import json
        m=self.load()
        env={'pid1':'systemd','os_id':'fedora','version':'44','architecture':'x86_64','kernel':'6','ram_kib':99999,'installer_sha256':'a'*64}
        lines=['VPS_ENV '+json.dumps(env),'VPS_REMOTE_COMPLETE','VPS_COMPLETE']
        lines+=['VPS_RESULT '+json.dumps({'case':name,'exit_code':0,'command_exit_code':1 if name in m.REFUSAL_CASES else 0,'assertions':{key:True for key in m.REQUIRED_ASSERTIONS[name]}}) for name in m.REQUIRED]
        lines+=['VPS_RESULT '+json.dumps({'case':'core_relay_install','exit_code':0,'assertions':{'dummy':True}})]
        self.assertEqual(m.parse_serial('\n'.join(lines),'fedora44')['core_status'],'failed')

    def test_journal_console_completion_marker_is_recognized(self):
        m=self.load()
        serial='[  288.123] python3[710]: VPS_REMOTE_COMPLETE\npython3[710]: VPS_COMPLETE\n'
        result=m.parse_serial(serial,'fedora44')
        self.assertTrue(result['remote_complete'])
        self.assertTrue(result['complete'])
        self.assertFalse(m.parse_serial('python3[710]: VPS_NOTE expects VPS_COMPLETE','fedora44')['complete'])

    def core_fixture(self):
        import json
        env={'pid1':'systemd','os_id':'debian','version':'13','architecture':'aarch64','kernel':'6','ram_kib':980512,'installer_sha256':'a'*64}
        rows=[{'case':'core_relay_install','exit_code':0,'command_exit_code':0,'assertions':{'core_active':True,'bouncer_active':True}},
              {'case':'native_core_reboot','exit_code':0,'command_exit_code':0,'assertions':{'core_active':True,'bouncer_active':True}},
              {'case':'native_core_decision_add','exit_code':0,'command_exit_code':0,'assertions':{'synced':True}},
              {'case':'native_core_decision_delete','exit_code':0,'command_exit_code':0,'assertions':{'synced':True}}]
        rows.append({'case':'core_repeat_install','exit_code':0,'command_exit_code':0,'assertions':{'preserved':True,'core_active':True,'bouncer_active':True}})
        lines=['VPS_ENV '+json.dumps(env)]+['VPS_RESULT '+json.dumps(row) for row in rows]
        for service in ('crowdsec','crowdsec-firewall-bouncer'):
            lines.append('VPS_HEALTH '+json.dumps({'phase':'native_core_reboot','service':service,'properties':'ActiveState=active\nSubState=running\nResult=success\n'}))
        for boot in range(1,4):
            lines.append('VPS_BOOT '+json.dumps({'phase':'native_core_reboot','boot':boot,'services':{'crowdsec':True,'crowdsec-firewall-bouncer':True},'add':True,'delete':True,'add_command_exit_code':0,'delete_command_exit_code':0}))
        return '\n'.join(lines+['VPS_COMPLETE'])

    def test_kernel_oom_during_install_cannot_be_hidden_by_later_healthy_boots(self):
        m=self.load();fixture=self.core_fixture()
        events=('[ 485.953669] Out of memory: Killed process 1987 (python3) total-vm:289936kB',
                '[ 12.5] Memory cgroup out of memory: Killed process 42 (python3)',
                '[ 12.5] oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null)')
        for event in events:
            with self.subTest(event=event):
                self.assertEqual(m.parse_serial(fixture+'\n'+event,'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')
                for diagnostic in ('VPS_NOTE diagnostic '+event,'[ 10.0] python3[55]: '+event):
                    self.assertEqual(m.parse_serial(fixture+'\n'+diagnostic,'debian13-arm64',scope='fresh_native_core_only')['status'],'passed')

    def test_guest_harness_failure_cannot_be_hidden_by_complete_cases(self):
        m=self.load()
        fixture=self.core_fixture()
        self.assertEqual(m.parse_serial('VPS_HARNESS_FAILED','debian13-arm64',scope='fresh_native_core_only')['status'],'failed')
        for event in ('VPS_HARNESS_FAILED','[ 12.000] python3[42]: VPS_HARNESS_FAILED'):
            self.assertEqual(m.parse_serial(fixture+'\n'+event,'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')
        self.assertEqual(m.parse_serial(fixture+'\nVPS_NOTE diagnostic VPS_HARNESS_FAILED','debian13-arm64',scope='fresh_native_core_only')['status'],'passed')

    def test_health_events_are_unique_and_conflict_free(self):
        m=self.load();serial=self.core_fixture()
        self.assertEqual(m.parse_serial(serial,'debian13-arm64',scope='fresh_native_core_only')['status'],'passed')
        event=next(line for line in serial.splitlines() if line.startswith('VPS_HEALTH '))
        for bad in (serial+'\n'+event, serial.replace('Result=success','Result=timeout'),serial+'\nVPS_COMPLETE'):
            self.assertEqual(m.parse_serial(bad,'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')

    def test_any_duplicate_case_cannot_pass(self):
        serial=self.core_fixture()
        extra='VPS_RESULT {"case":"help_and_readonly_status","exit_code":0,"command_exit_code":0,"assertions":{"help_ok":true,"status_ok":true,"unchanged":true}}'
        self.assertEqual(self.load().parse_serial(serial+'\n'+extra+'\n'+extra,'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')

    def test_wrong_architecture_cannot_pass_arm_scope(self):
        self.assertEqual(self.load().parse_serial(self.core_fixture().replace('aarch64','x86_64'),'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')

    def test_actual_command_failure_cannot_certify_case(self):
        import json
        for code in (124,False,None,-15):
            lines=[]
            for line in self.core_fixture().splitlines():
                if line.startswith('VPS_RESULT '):
                    row=json.loads(line[11:])
                    if code is None:row.pop('command_exit_code')
                    else:row['command_exit_code']=code
                    line='VPS_RESULT '+json.dumps(row)
                lines.append(line)
            self.assertEqual(self.load().parse_serial('\n'.join(lines),'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')

    def test_extra_assertion_cannot_certify_case(self):
        self.assertEqual(self.load().parse_serial(self.core_fixture().replace('"synced": true','"synced": true, "invented": true'),'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')

    def test_wrong_distribution_cannot_pass(self):
        self.assertEqual(self.load().parse_serial(self.core_fixture().replace('"debian"','"ubuntu"').replace('"13"','"24.04"'),'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')

    def test_three_independent_boots_are_required(self):
        lines=self.core_fixture().splitlines()
        for bad in ('\n'.join(line for line in lines if not (line.startswith('VPS_BOOT ') and '"boot": 2' in line)),self.core_fixture()+'\n'+next(line for line in lines if line.startswith('VPS_BOOT '))):
            self.assertEqual(self.load().parse_serial(bad,'debian13-arm64',scope='fresh_native_core_only')['status'],'failed')

    def test_existing_core_scope_requires_bootstrap_and_configuration_preservation(self):
        import json
        serial=self.core_fixture()
        m=self.load()
        events={
            'core_repository_setup': {'ready':True},
            'core_package_install': {'installed':True},
            'existing_core_config_preserved': {'preserved':True},
        }
        lines={name:'VPS_RESULT '+json.dumps({'case':name,'exit_code':0,'command_exit_code':0,'assertions':assertions}) for name,assertions in events.items()}
        valid=serial+'\n'+'\n'.join(lines.values())
        self.assertEqual(m.parse_serial(valid,'debian13-arm64',scope='existing_core_integration')['status'],'passed')
        for omitted in events:
            incomplete=serial+'\n'+'\n'.join(line for name,line in lines.items() if name!=omitted)
            with self.subTest(omitted=omitted):
                result=m.parse_serial(incomplete,'debian13-arm64',scope='existing_core_integration')
                self.assertEqual(result['status'],'failed')
                self.assertIn(omitted,result['missing_cases'])
        self.assertEqual(m.parse_serial(valid.replace('"preserved": true','"preserved": false'),'debian13-arm64',scope='existing_core_integration')['status'],'failed')

    def test_remote_only_can_complete_without_later_core_install(self):
        import json
        m=self.load();env={'pid1':'systemd','os_id':'debian','version':'13','architecture':'aarch64','kernel':'6','ram_kib':980512,'installer_sha256':'a'*64}
        lines=['VPS_ENV '+json.dumps(env)]
        lines+=['VPS_RESULT '+json.dumps({'case':name,'exit_code':0,'command_exit_code':1 if name in m.REFUSAL_CASES else 0,'assertions':{key:True for key in m.REQUIRED_ASSERTIONS[name]}}) for name in m.REQUIRED]
        lines.append('VPS_HEALTH '+json.dumps({'phase':'remote_reboot','service':'crowdsec-firewall-bouncer','properties':'ActiveState=active\nSubState=running\nResult=success\n'}))
        for boot in range(1,4):lines.append('VPS_BOOT '+json.dumps({'phase':'remote_reboot','boot':boot,'services':{'crowdsec-firewall-bouncer':True},'add':True,'delete':True,'add_command_exit_code':0,'delete_command_exit_code':0}))
        lines+=['VPS_REMOTE_COMPLETE','VPS_COMPLETE'];serial='\n'.join(lines)
        self.assertEqual(m.parse_serial(serial,'debian13-arm64',scope='remote_only')['status'],'passed')
        self.assertEqual(m.parse_serial(serial,'debian13-arm64')['status'],'failed')

    def test_scope_core_only_does_not_require_remote_cases(self):
        import inspect,json
        m=self.load()
        self.assertIn('scope',inspect.signature(m.parse_serial).parameters)
        env={'pid1':'systemd','os_id':'debian','version':'13','architecture':'aarch64','kernel':'6','ram_kib':980512,'installer_sha256':'a'*64}
        case={'case':'core_relay_install','exit_code':0,'command_exit_code':0,'assertions':{'core_active':True,'bouncer_active':True}}
        result=m.parse_serial('VPS_ENV '+json.dumps(env)+'\nVPS_RESULT '+json.dumps(case)+'\nVPS_COMPLETE\n','debian13-arm64',scope='fresh_native_core_only')
        self.assertEqual(result['remote_status'],'not_tested')
        self.assertNotIn('fresh_remote_install',result['missing_cases'])
        self.assertNotEqual(result['status'],'passed') # missing health/reboot evidence

    def test_boolean_guest_case_exit_cannot_pass(self):
        m=self.load()
        serial='VPS_RESULT {"case":"core_relay_install","exit_code":false,"assertions":{"core_active":true,"bouncer_active":true}}'
        self.assertEqual(m.parse_serial(serial,'fedora44')['core_status'],'failed')

    def test_nft_read_failure_cannot_certify_delete(self):
        import ast
        m=self.load()
        path=Path(__file__).with_name('vps_rpm_arm_guest_arm.py')
        tree=ast.parse(path.read_text())
        start=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='run' and "decisions', 'delete'" in ast.unparse(n.value))
        end=next(i for i in range(start,len(tree.body)) if isinstance(tree.body[i],ast.Expr) and isinstance(tree.body[i].value,ast.Call) and isinstance(tree.body[i].value.func,ast.Name) and tree.body[i].value.func.id=='emit')
        events=[]
        def run(args,**kw):return (1,'operation not permitted') if args[0]=='nft' else (0,'')
        import types
        exec(compile(ast.Module(body=tree.body[start:end+1],type_ignores=[]),str(path),'exec'),{'run':run,'emit':lambda name,rc,**a:events.append(a),'cs':['cscli'],'time':types.SimpleNamespace(sleep=lambda _:None)})
        self.assertFalse(events[0]['absent'])

    def test_boolean_qemu_exit_is_not_success(self):
        self.assertEqual(self.load().final_status('passed', False, False), 'failed')

    def test_environment_embedded_in_note_is_not_identity(self):
        result = self.load().parse_serial('VPS_NOTE expected VPS_ENV {"pid1":"systemd","architecture":"aarch64"}\n', 'debian13-arm64')
        self.assertNotIn('pid1', result)

    def test_manually_stopped_cannot_pass(self):
        import inspect
        m=self.load()
        self.assertIn('stopped_by_agent',inspect.signature(m.final_status).parameters)
        self.assertEqual(m.final_status('passed', False, 0, stopped_by_agent=True), 'failed')

    def test_duplicate_environment_is_rejected(self):
        with self.assertRaises(ValueError):
            self.load().parse_serial('VPS_ENV {}\nVPS_ENV {}\n', 'fedora44')

    def test_timeout_never_accepts_even_complete_cases(self):
        m=self.load()
        self.assertEqual(m.final_status('passed',True,0),'failed')
        self.assertEqual(m.final_status('passed',False,1),'failed')
        self.assertEqual(m.final_status('passed',False,0),'passed')

    def test_seed_uses_virtio_for_cloud_kernel_compatibility(self):
        m=self.load();seed=Path('/tmp/seed.iso')
        args=m.qemu_command('debian12',Path('/tmp/lab'),Path('/tmp/disk'),seed)
        self.assertTrue(any('file=/tmp/seed.iso' in value and 'if=virtio' in value and 'readonly=on' in value for value in args))

    def test_qemu_has_no_forwarded_ports_or_host_shares(self):
        m=self.load()
        args=m.qemu_command('alma9',Path('/tmp/lab'),Path('/tmp/disk'),Path('/tmp/seed'))
        self.assertTrue(any('user' in value for value in args))
        self.assertFalse(any('hostfwd' in value or 'virtfs' in value or '9p' in value for value in args))

if __name__=='__main__': unittest.main()

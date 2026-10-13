import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class RunnerTests(unittest.TestCase):
    def load(self):
        spec=importlib.util.spec_from_file_location('runner',Path(__file__).with_name('verify_vps_rpm_arm.py'))
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

    def test_changed_seed_is_refused_before_launch(self):
        m=self.load()
        with tempfile.TemporaryDirectory() as td:
            seed=Path(td)/'seed.iso';seed.write_bytes(b'wrong')
            with self.assertRaises(ValueError):m.validate_seed(seed,{'seed_sha256':'a'*64},'debian13-arm64',None)

    def test_malformed_evidence_preserves_exit_and_failure(self):
        m=self.load()
        with tempfile.TemporaryDirectory() as td:
            log=Path(td)/'serial';log.write_text('VPS_ENV {broken secret-value\n')
            result=m.finish_report(log,'debian13-arm64','fresh_native_core_only',{},False,0,False)
            self.assertEqual(result['status'],'failed');self.assertEqual(result['qemu_exit_code'],0)
            self.assertEqual(result['failure_cause'],'Malformed guest evidence.')
            self.assertNotIn('secret-value',json.dumps(result))

    def test_interrupt_is_recorded_and_process_reaped(self):
        m=self.load()
        class Process:
            returncode=None
            def wait(self,timeout=None):
                if self.returncode is None:raise KeyboardInterrupt
                return self.returncode
            def terminate(self):self.returncode=-15
            def kill(self):self.returncode=-9
        process=Process()
        with tempfile.TemporaryDirectory() as td,patch.object(m.subprocess,'Popen',return_value=process):
            timed,stopped,rc=m.run_qemu(['harmless-boundary'],Path(td)/'serial',{},30)
            self.assertFalse(timed);self.assertTrue(stopped);self.assertEqual(rc,-15)

    def test_existing_serial_is_never_overwritten(self):
        m=self.load()
        with tempfile.TemporaryDirectory() as td:
            log=Path(td)/'serial';log.write_text('history')
            with self.assertRaises(FileExistsError):m.run_qemu(['unused'],log,{},30)
            self.assertEqual(log.read_text(),'history')

    def test_soak_host_rechecks_unique_final_observation(self):
        import copy,sys
        sys.path.insert(0,str(Path(__file__).parent))
        from test_vps_rpm_arm import GuestEvidenceTests
        from test_relay_soak import SoakTests
        m=self.load();soak=SoakTests().fixture();soak['mode']='local'
        for row in soak['samples']+[soak['final_observation']]:
            row['services']['crowdsec']=copy.deepcopy(row['services']['crowdsec-firewall-bouncer']);row['services']['crowdsec']['pid']=43
        meta={k:soak[k] for k in ('mode','duration_seconds','elapsed_seconds','complete','exit_code')}
        meta.update(observer_sha256='b'*64,manifest_sha256='c'*64)
        artifacts={'installer_sha256':'a'*64,'soak_duration_seconds':120,'soak_sources':{'opt/test/relay_soak_guest.py':'b'*64,'opt/test/soak-manifest.json':'c'*64}}
        with tempfile.TemporaryDirectory() as td:
            for kind in ('valid','missing','duplicate','failed','setup_missing','setup_duplicate','setup_failed'):
                lines=[GuestEvidenceTests().core_fixture()]
                setup=copy.deepcopy(soak['setup'])
                if kind=='setup_failed':setup['ready']=False
                setup_event='VPS_SOAK_EVENT '+json.dumps({'kind':'setup',**setup})
                if kind!='setup_missing':lines.append(setup_event)
                if kind=='setup_duplicate':lines.append(setup_event)
                lines+=['VPS_SOAK_EVENT '+json.dumps({'kind':'sample',**row}) for row in soak['samples']]
                final=copy.deepcopy(soak['final_observation'])
                if kind=='failed':final['services']['crowdsec']['healthy']=False
                event='VPS_SOAK_EVENT '+json.dumps({'kind':'final_observation',**final})
                if kind!='missing':lines.append(event)
                if kind=='duplicate':lines.append(event)
                lines.append('VPS_SOAK_COMPLETE '+json.dumps(meta))
                log=Path(td)/kind;log.write_text('\n'.join(lines))
                result=m.finish_report(log,'debian13-arm64','fresh_native_core_only',artifacts,False,0,False)
                self.assertEqual(result['status'],'passed' if kind=='valid' else 'failed',kind)

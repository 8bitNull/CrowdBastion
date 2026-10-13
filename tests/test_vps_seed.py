import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

class SeedTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec('pycdlib'),'pycdlib required for media validation')
    def test_seed_payloads_keep_both_entry_points_runnable(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            core=root/'core-snapshot'
            (core/'opt/core/etc').mkdir(parents=True)
            (core/'opt/core/etc/config.yaml').write_text('{}\n')
            (core/'bin').mkdir()
            for name in ('crowdsec','cscli'):
                (core/'bin'/name).write_text('#!/bin/sh\nexit 0\n')
            for builder in ('prepare_vps_deb.py','prepare_vps_rpm_arm.py'):
                with self.subTest(builder=builder):
                    lab=root/builder
                    seed=lab/'seed.iso'
                    command=[sys.executable,str(Path(__file__).with_name(builder)),
                             '--lab',str(lab),'--output',str(seed)]
                    if builder=='prepare_vps_deb.py':
                        command+=['--core-root',str(core)]
                        archive=lab/'payload.tgz'
                    else:
                        command+=['--arm','--core-only']
                        archive=seed.with_suffix('.payload.tgz')
                    result=subprocess.run(command,text=True,capture_output=True,timeout=20)
                    self.assertEqual(result.returncode,0,result.stderr)
                    unpacked=lab/'unpacked'
                    unpacked.mkdir()
                    subprocess.run(['tar','-xzf',str(archive),'-C',str(unpacked)],check=True)
                    outputs=[]
                    for entry in ('crowdbastion.sh','install-crowdsec-1panel.sh'):
                        script=unpacked/'opt/test/repo'/entry
                        result=subprocess.run(['bash',str(script),'--help'],cwd=root,
                                              text=True,capture_output=True,timeout=5)
                        self.assertEqual(result.returncode,0,result.stderr)
                        outputs.append(result.stdout)
                    self.assertEqual(outputs[0],outputs[1])

    @unittest.skipUnless(importlib.util.find_spec('pycdlib'),'pycdlib required for media validation')
    def test_arm_cold_core_seed_is_self_contained_and_immutable(self):
        script=Path(__file__).with_name('prepare_vps_rpm_arm.py')
        with tempfile.TemporaryDirectory() as td:
            seed=Path(td)/'arm-core.iso'
            cmd=[sys.executable,str(script),'--arm','--core-only','--lab',td,'--output',str(seed)]
            first=subprocess.run(cmd,text=True,capture_output=True,env=os.environ.copy())
            self.assertEqual(first.returncode,0,first.stderr)
            with tarfile.open(seed.with_suffix('.payload.tgz')) as tar:
                names=set(tar.getnames())
                self.assertIn('opt/test/vps_guest_runtime.py',names)
                self.assertIn('opt/test/native-phase.py',names)
                self.assertNotIn('opt/core/etc/config.yaml',names)
            import io, pycdlib, yaml
            iso=pycdlib.PyCdlib();iso.open(str(seed))
            data=io.BytesIO();iso.get_file_from_iso_fp(data,rr_path='/user-data');iso.close()
            userdata=yaml.safe_load(data.getvalue())
            units={entry['path']:entry['content'] for entry in userdata['write_files']}
            initial=units['/etc/systemd/system/vps-initial.service']
            failure_name=next((line.split('=',1)[1] for line in initial.splitlines() if line.startswith('OnFailure=')),None)
            self.assertIsNotNone(failure_name,'Killed harness must trigger explicit guest termination')
            failure=units['/etc/systemd/system/'+failure_name]
            self.assertIn('VPS_HARNESS_FAILED',failure)
            self.assertIn('poweroff',failure)
            before=seed.read_bytes()
            second=subprocess.run(cmd,text=True,capture_output=True,env=os.environ.copy())
            self.assertNotEqual(second.returncode,0)
            self.assertEqual(seed.read_bytes(),before)

    @unittest.skipUnless(importlib.util.find_spec('pycdlib'),'pycdlib required for media validation')
    def test_soak_seed_packs_manifest_and_sources(self):
        import json
        script=Path(__file__).with_name('prepare_vps_rpm_arm.py')
        with tempfile.TemporaryDirectory() as td:
            seed=Path(td)/'soak.iso';gost=Path(td)/'gost';realm=Path(td)/'realm'
            gost.write_bytes(b'fixture-gost');realm.write_bytes(b'fixture-realm')
            cmd=[sys.executable,str(script),'--core-only','--lab',td,'--output',str(seed),'--soak-duration','120','--gost',str(gost),'--realm',str(realm)]
            result=subprocess.run(cmd,text=True,capture_output=True,env=os.environ.copy())
            self.assertEqual(result.returncode,0,result.stderr)
            with tarfile.open(seed.with_suffix('.payload.tgz')) as tar:
                cfg=json.load(tar.extractfile('opt/test/soak-manifest.json'))
                self.assertEqual(cfg['mode'],'local');self.assertEqual(cfg['duration_seconds'],120)
                for name in ['relay_soak_guest.py','vps_soak_stage.py','benchmark_relay.py','gost','realm']:
                    self.assertIn('opt/test/'+name,tar.getnames())
            provenance=json.loads(seed.with_suffix('.provenance.json').read_text())
            self.assertEqual(provenance['soak_duration_seconds'],120)

    @unittest.skipUnless(importlib.util.find_spec('pycdlib'),'pycdlib required for media validation')
    def test_remote_and_existing_core_scopes_have_distinct_seed_control(self):
        import json
        script=Path(__file__).with_name('prepare_vps_rpm_arm.py')
        for option,scope in [('--remote-only','remote_only'),('--integration-only','existing_core_integration')]:
            with tempfile.TemporaryDirectory() as td:
                seed=Path(td)/'seed.iso'
                result=subprocess.run([sys.executable,str(script),'--arm',option,'--lab',td,'--output',str(seed)],text=True,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                manifest=json.loads(seed.with_suffix('.provenance.json').read_text())
                self.assertEqual(manifest['test_scope'],scope)
                with tarfile.open(seed.with_suffix('.payload.tgz')) as tar:
                    self.assertEqual(tar.extractfile('opt/test/test-scope.txt').read().decode().strip(),scope)
                    self.assertNotIn('opt/core/etc/config.yaml',tar.getnames())
                    if scope=='existing_core_integration':self.assertIn('core_repository_setup',tar.extractfile('opt/test/guest.py').read().decode())

if __name__=='__main__':unittest.main()

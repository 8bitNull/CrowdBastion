import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).parent))

class Benchmark(unittest.TestCase):
    def test_schedule_pairs_and_reproducibility(self):
        from benchmark_relay import schedule
        runs = schedule(['gost','realm'], ['tcp','udp'], [0,1000], 3, 17)
        self.assertEqual(runs, schedule(['gost','realm'], ['tcp','udp'], [0,1000], 3, 17))
        self.assertEqual(len(runs), 36)
        for block in range(3):
            selected = [r for r in runs if r['block']==block]
            self.assertEqual(len({(r['tool'],r['protocol'],r['ban_count']) for r in selected}),12)

    def test_failed_samples_not_success(self):
        from benchmark_relay import summarize
        result = summarize([dict(ok=2, errors=1, bytes=200, elapsed=2, latency_ms=[10,20])])
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['goodput_mbps'], .0008)
        self.assertEqual(result['error_rate'], 1/3)

    def test_resource_snapshot_actual_process(self):
        from benchmark_relay import snapshot
        sample = snapshot(os.getpid())
        self.assertGreater(sample['rss_bytes'],0)
        self.assertGreaterEqual(sample['cpu_seconds'],0)

    def test_actual_workload_roundtrip(self):
        from benchmark_relay import load, free_port
        for protocol in ('tcp','udp'):
            port = free_port('127.0.0.1',protocol)
            script = str(Path(__file__).with_name('benchmark_relay.py'))
            child = subprocess.Popen([sys.executable,script,'--echo',protocol,str(port),'128'],stderr=subprocess.DEVNULL)
            try:
                import time
                time.sleep(.1)
                result = load('127.0.0.1',port,protocol,.2,2,128)
                self.assertGreater(result['ok'],0)
                self.assertEqual(result['errors'],0)
                self.assertEqual(result['bytes'],result['ok']*128)
            finally:
                child.terminate(); child.wait(timeout=5)

    def test_runner_drains_large_workload_output(self):
        from benchmark_relay import measured_load
        from relay_network_lab import Processes
        with tempfile.TemporaryDirectory() as temp, Processes() as owned:
            data, resources = measured_load([sys.executable,'-c','import json;print(json.dumps({"ok":1,"errors":0,"bytes":1,"elapsed":1,"latency_ms":[1]*100000}))'],owned,{},Path(temp))
            self.assertEqual(len(data['latency_ms']),100000)
            self.assertEqual(resources,{})

    def test_weighted_latency_quantile(self):
        from benchmark_relay import summarize
        result=summarize([dict(ok=105000,errors=0,bytes=105000,elapsed=1,latency_ms=[1,100],latency_weights=[100000,5000])])
        self.assertEqual(result['p95_ms'],1)

    def test_pair_comparison_preserves_block(self):
        from benchmark_relay import comparisons
        runs=[dict(tool='gost',protocol='tcp',block=b,ban_count=n,status='passed',goodput_mbps=s)
              for b,n,s in [(0,None,100),(0,1000,90),(1,None,200),(1,1000,180)]]
        result=comparisons(runs)[0]
        self.assertEqual(result['paired_goodput_change_percent'],[-10,-10])
        self.assertEqual(result['pairs'],2)
        runs[-1]['status']='failed'
        self.assertEqual(comparisons(runs)[0]['pairs'],1)

    @unittest.skipUnless(os.environ.get('GOST_TEST_BINARY'),'optional official gost binary')
    def test_persistent_gost_udp_concurrency(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'report.json'
            result=subprocess.run([sys.executable,str(Path(__file__).with_name('benchmark_relay.py')),'--forward-only','--tools','gost','--protocols','udp','--gost',os.environ['GOST_TEST_BINARY'],'--duration','.3','--repeats','1','--concurrency','4','--output',str(output)],stdout=subprocess.DEVNULL,timeout=15)
            self.assertEqual(result.returncode,0)
            self.assertEqual(json.loads(output.read_text())['runs'][0]['raw']['errors'],0)

    def test_missing_yaml_reports_unverified(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'report.json'
            environment=dict(os.environ)
            environment.pop('PYTHONPATH',None)
            result=subprocess.run([sys.executable,'-S',str(Path(__file__).with_name('benchmark_relay.py')),'--output',str(output)],stdout=subprocess.DEVNULL,env=environment)
            data=json.loads(output.read_text())
            self.assertEqual(result.returncode,2)
            self.assertIn('yaml',data['error'])

    def test_missing_dependency_structured(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'out.json'
            result=subprocess.run([sys.executable,str(Path(__file__).with_name('benchmark_relay.py')),'--gost','/missing/gost','--output',str(output)],capture_output=True)
            self.assertEqual(result.returncode,2)
            self.assertEqual(json.loads(output.read_text())['status'],'unverified')

if __name__=='__main__':
    unittest.main()

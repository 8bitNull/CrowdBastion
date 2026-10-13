import os
import sys
import unittest
import urllib.request
import urllib.error
sys.path.insert(0, os.path.dirname(__file__))

class NetworkAcceptance(unittest.TestCase):
    def test_isolation_guard(self):
        from relay_network_lab import guard
        with self.assertRaises(RuntimeError):
            guard(os.stat('/proc/self/ns/net').st_ino)

    def test_mount_isolation_guard(self):
        from relay_network_lab import guard
        with self.assertRaises(RuntimeError):
            guard(-1, os.stat("/proc/self/ns/mnt").st_ino)

    def test_missing_dependency_report(self):
        import json, subprocess, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("verify_relay_network.py")), "--gost", "/missing/relay-tool", "--output", str(output)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(output.read_text())["status"], "unverified")

    def test_sigterm_cleans_detached_children(self):
        import signal, subprocess, time
        from pathlib import Path
        script = "import sys;sys.path.insert(0,sys.argv[1]);from relay_network_lab import Processes;import time\nwith Processes() as p:\n c=p.start([sys.executable,'-c','import time;time.sleep(60)']);print(c.pid,flush=True);time.sleep(60)"
        manager = subprocess.Popen([sys.executable, '-c', script, str(Path(__file__).parent)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        child_pid = int(manager.stdout.readline())
        try:
            manager.terminate()
            manager.wait(timeout=8)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            manager.stdout.close()
            if manager.poll() is None:
                manager.kill()
                manager.wait()
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_echo_cannot_steal_udp_port(self):
        import socket, subprocess
        from pathlib import Path
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as existing:
            existing.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            existing.bind(('127.0.0.1', 0))
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('verify_relay_network.py')), '--echo', '127.0.0.1', str(existing.getsockname()[1]), 'udp'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                self.assertNotEqual(process.wait(timeout=2), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_named_drop_counters_exclude_processed(self):
        from relay_network_lab import drop_packets
        data = {'nftables': [
            {'counter': {'table': 'crowdsec', 'name': 'processed', 'packets': 100}},
            {'counter': {'table': 'crowdsec', 'name': 'cscli', 'packets': 3}},
            {'rule': {'table': 'crowdsec', 'expr': [{'counter': 'processed'}]}},
            {'rule': {'table': 'crowdsec', 'expr': [{'counter': 'cscli'}, {'drop': None}]}},
        ]}
        self.assertEqual(drop_packets(data), 3)

    def test_nested_cleanup_reaps_ignoring_children(self):
        import subprocess, tempfile, signal
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / 'worker.py'
            script.write_text("import sys,time;sys.path.insert(0,sys.argv[1]);from relay_network_lab import Processes\nwith Processes(grace=3) as p:\n for _ in range(2):\n  c=p.start([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)']);print(c.pid,flush=True)\n time.sleep(60)\n")
            manager = subprocess.Popen([sys.executable, str(script), str(Path(__file__).parent)], start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            children = [int(manager.stdout.readline()) for _ in range(2)]
            import time
            time.sleep(.1)
            from relay_network_lab import Processes
            try:
                with Processes() as owned:
                    owned.children.append(manager)
                for pid in children:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
            finally:
                manager.stdout.close()
                for pid in children:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_evidence_requires_all_checks(self):
        from relay_network_lab import accepted
        evidence = dict(normal_bad=True, normal_good=True, blocked_bad=False,
                        healthy_good=True, counter_increased=True, recovered_bad=True,
                        recovered_good=True)
        self.assertTrue(accepted(evidence))
        for key in evidence:
            altered = dict(evidence)
            altered[key] = not altered[key]
            self.assertFalse(accepted(altered), key)

    def test_fixture_authenticated_stream(self):
        from relay_network_lab import DecisionAPI
        with DecisionAPI() as api:
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(api.url + 'v1/decisions/stream')
            api.set_ban('10.231.1.2', True)
            def get():
                import json
                request = urllib.request.Request(api.url + 'v1/decisions/stream', headers={'X-Api-Key': api.key})
                return json.load(urllib.request.urlopen(request))
            self.assertEqual(get()['new'][0]['value'], '10.231.1.2')
            self.assertEqual(get(), {'new': [], 'deleted': []})
            api.set_ban('10.231.1.2', False)
            self.assertEqual(get()['deleted'][0]['value'], '10.231.1.2')

    def test_owned_process_cleanup(self):
        from relay_network_lab import Processes
        with Processes() as processes:
            child = processes.start([sys.executable, '-c', 'import time; time.sleep(60)'])
            self.assertIsNone(child.poll())
        self.assertIsNotNone(child.poll())

if __name__ == '__main__':
    unittest.main()

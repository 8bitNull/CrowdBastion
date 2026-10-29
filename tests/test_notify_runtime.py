"""Real worker process with local TLS Telegram and synthetic health commands."""
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

import test_notify as fixtures
from crowdsec_notify_client import request


@unittest.skipUnless(shutil.which('openssl'), 'openssl is required for loopback TLS')
class NotificationRuntime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='notify-runtime-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = fixtures.configuration(self.root)
        self.config['policy'].update(health_interval_seconds=1, fault_seconds=1, recovery_seconds=1,
                                     critical_scenarios=['test/critical'])
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.config['port'] = probe.getsockname()[1]
        cert, key = self.root/'cert.pem', self.root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True, timeout=15)
        self.api_calls = []
        self.api_lock = threading.Lock()
        owner = self

        class API(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                with owner.api_lock:
                    owner.api_calls.append((time.monotonic(), payload))
                    first = len(owner.api_calls) == 1
                body = {'ok': False, 'error_code': 429, 'parameters': {'retry_after': 4}} if first else {
                    'ok': True, 'result': {'message_id': len(owner.api_calls)}}
                self.send_response(429 if first else 200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *args):
                pass

        self.api = http.server.ThreadingHTTPServer(('127.0.0.1', 0), API)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.api.socket = context.wrap_socket(self.api.socket, server_side=True)
        self.api_thread = threading.Thread(target=self.api.serve_forever, daemon=True)
        self.api_thread.start()
        self.addCleanup(self.stop_api)
        self.config['api_endpoint'] = f'https://127.0.0.1:{self.api.server_port}'
        Path(self.config['crowdsec_config']).write_text('api: {}\n')
        self.config_path = self.root/'notify.json'
        self.config_path.write_text(json.dumps(self.config))
        commands = self.root/'bin'
        commands.mkdir()
        self.health_file = self.root/'health'
        self.health_file.write_text('ok')
        (commands/'systemctl').write_text('''#!/bin/sh
if [ "$(cat "$NOTIFY_TEST_HEALTH")" = ok ]; then echo active; exit 0; fi
echo inactive
exit 3
''')
        (commands/'cscli').write_text('#!/bin/sh\necho "[]"\n')
        for command in commands.iterdir():
            command.chmod(0o700)
        self.env = {**os.environ, 'PATH': str(commands)+os.pathsep+os.environ['PATH'],
                    'SSL_CERT_FILE': str(cert), 'NO_PROXY': '127.0.0.1,localhost',
                    'no_proxy': '127.0.0.1,localhost', 'NOTIFY_TEST_HEALTH': str(self.health_file)}
        self.log = self.root/'worker.log'
        self.stream = self.log.open('ab')
        self.addCleanup(self.stream.close)
        self.process = None
        self.addCleanup(self.stop_worker)

    def stop_api(self):
        self.api.shutdown()
        self.api.server_close()
        self.api_thread.join(2)

    def stop_worker(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)

    def wait_for(self, predicate, timeout=10):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            if self.process and self.process.poll() is not None:
                self.fail('Worker stopped: '+self.log.read_text())
            try:
                if predicate():
                    return
            except OSError:
                pass
            time.sleep(0.05)
        self.fail('Timed out waiting for worker: '+self.log.read_text())

    def start_worker(self):
        # Isolate the real health collector's roles file as well as its subprocesses.
        runner = '''import functools, runpy, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import crowdsec_bot_health
crowdsec_bot_health.HealthCollector = functools.partial(
    crowdsec_bot_health.HealthCollector, roles_path=sys.argv.pop())
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
'''
        self.process = subprocess.Popen([sys.executable, '-c', runner,
            str(fixtures.ROOT/'lib/crowdsec_notify.py'), 'run', str(self.config_path), str(self.root/'roles.json')],
            env=self.env, stdin=subprocess.DEVNULL,
            stdout=self.stream, stderr=self.stream)
        self.wait_for(lambda: request(self.config, 'status')['state'] == 'ready')

    def messages(self):
        with self.api_lock:
            return list(self.api_calls)

    def post(self, alerts):
        message = urllib.request.Request(f'http://127.0.0.1:{self.config["port"]}/alerts',
            data=json.dumps(alerts).encode(), headers={'Authorization': 'Bearer '+self.config['secret']})
        with urllib.request.urlopen(message, timeout=5) as response:
            return json.load(response)

    def test_restart_respects_real_https_429_then_ack_and_recovery_work(self):
        self.start_worker()
        ordinary = fixtures.alert(1)
        critical = fixtures.alert(2, 'test/critical')
        self.assertEqual(self.post([ordinary, critical]), {'accepted': 2})
        self.wait_for(lambda: request(self.config, 'status')['last_failure'] > 0)
        self.assertEqual(len(self.messages()), 1)
        self.stop_worker()
        self.start_worker()
        self.wait_for(lambda: len(self.messages()) >= 2)
        calls = self.messages()
        self.assertGreaterEqual(calls[1][0]-calls[0][0], 4)
        self.assertIn('紧急告警', calls[1][1]['text'])
        self.assertFalse(calls[1][1]['disable_notification'])
        identifier = re.search(r'事件：([a-f0-9]{24})', calls[1][1]['text'])[1]
        self.assertTrue(request(self.config, 'ack', {'id': identifier})['acknowledged'])
        self.assertEqual(self.post([critical]), {'accepted': 0})
        self.health_file.write_text('fault')
        self.wait_for(lambda: any('紧急告警' in payload['text'] and 'CrowdSec 服务' in payload['text']
                                  for _, payload in self.messages()))
        self.health_file.write_text('ok')
        self.wait_for(lambda: any('故障恢复' in payload['text'] for _, payload in self.messages()))
        self.assertFalse(any('普通告警汇总' in payload['text'] for _, payload in self.messages()))
        self.assertEqual(sum('故障恢复' in payload['text'] for _, payload in self.messages()), 1)


if __name__ == '__main__':
    unittest.main()

"""Run staged Bouncer Lua through real Nginx HTTP requests.

Set CROWDBASTION_TEST_NGINX to a Lua-enabled Nginx binary. For extracted
Debian packages, also set CROWDBASTION_TEST_LUA_PREFIX to their root directory.
The pinned archives use the same paths as test_web_install.py.
"""
import contextlib
import hashlib
import http.server
import importlib.util
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import tarfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NGINX = os.environ.get('CROWDBASTION_TEST_NGINX', '')


@contextlib.contextmanager
def endpoint(role, mode='healthy'):
    state = {'upstream_requests': 0, 'requests': 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state['requests'] += 1
            if role == 'upstream':
                state['upstream_requests'] += 1
                body, status = b'business-upstream', 403 if mode == 'business_403' else 200
            elif self.path.startswith('/v1/decisions'):
                if mode == 'timeout':
                    time.sleep(0.2)
                body, status = (json.dumps([{'id': 17, 'type': 'ban', 'origin': 'cscli', 'scope': 'Ip', 'value': '127.0.0.1', 'duration': '5m'}]).encode() if mode == 'lapi_ban' else b'null'), 503 if mode == 'http_error' else 200
            else:
                if mode == 'timeout':
                    time.sleep(0.2)
                body, status = (b'{"action":"ban","http_status":403}', 403) if mode == 'rule_block' else (b'{}', 503 if mode == 'http_error' else 200)
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_POST = do_GET

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def unused_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


@unittest.skipUnless(NGINX and Path(NGINX).is_file(), 'Lua-enabled Nginx required')
class WebBouncerRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bouncer_archive = Path('/tmp/crowdsec-official-openresty.tgz')
        cls.http_archive = Path('/tmp/crowdsec-http')
        if not cls.bouncer_archive.is_file() or not cls.http_archive.is_file():
            raise unittest.SkipTest('pinned official archives required')
        spec = importlib.util.spec_from_file_location('runtime_web', ROOT/'lib/crowdsec_web.py')
        cls.web = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.web)

    def request_case(self, policy, fault, lapi_policy=None, lapi_fault='healthy',
                     always_send=False, include_appsec_count=False, evidence=False,
                     installed_defaults=False, legacy_upgrade=None):
        with contextlib.ExitStack() as stack:
            base = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='cb-lua-runtime-')))
            upstream_port, upstream = stack.enter_context(endpoint('upstream', fault))
            if lapi_fault == 'refused':
                api_port = unused_port()
            else:
                api_port, _ = stack.enter_context(endpoint('lapi', 'lapi_ban' if fault == 'lapi_ban' else lapi_fault))
            if fault == 'refused':
                appsec_port = unused_port()
                appsec = {'requests': 0}
            else:
                appsec_port, appsec = stack.enter_context(endpoint('appsec', fault))
            assets = base/'assets'
            plan = {'mode': 'npm', 'original': None, 'container_assets': str(assets)}
            self.web.stage_assets(plan, self.bouncer_archive, self.http_archive, assets,
                                  '0123456789abcdef0123456789abcdef',
                                  f'http://127.0.0.1:{api_port}/')
            if legacy_upgrade is not None:
                # Recreate official v1.2.3 modules, with either old hooks or the
                # previously released execution recorder, then run our upgrade.
                with tarfile.open(self.bouncer_archive) as archive:
                    for rel in ['crowdsec.lua', 'plugins/crowdsec/config.lua']:
                        name = next(n for n in archive.getnames() if n.endswith('/lua/lib/'+rel))
                        text = archive.extractfile(name).read().decode()
                        text = re.sub(r'(["\'])(plugins\.crowdsec(?:\.[a-zA-Z_]+)*|resty\.http(?:_[a-zA-Z_]+)?)(["\'])',
                                      lambda m: m[1]+'crowdsec_1key.'+m[2]+m[3], text)
                        if rel == 'crowdsec.lua' and legacy_upgrade:
                            text = self.web.instrument_execution(text)
                        (assets/'lib/crowdsec_1key'/rel).write_text(text)
                target = base/'http_top.conf'
                plan.update(host_assets=str(assets), host_target=str(target),
                            container_target=str(target), original_mode=0o644)
                hooks = self.web.render_hooks(plan, execution=legacy_upgrade)
                target.write_text(hooks['target'])
                (assets/'target.conf').write_text(hooks['target'])
                if not legacy_upgrade:
                    (assets/'log.lua').unlink()
                    (assets/'lib/crowdsec_1key/execution.lua').unlink()
                state = base/'installs.json'
                self.web.save_state(state, {'web': dict(plan, status='installed', account='keep',
                    installed_sha=hashlib.sha256(target.read_bytes()).hexdigest(),
                    resource_hashes=self.web.resource_hashes(assets))})
                before = (assets/'bouncer.conf').read_bytes()
                self.web.upgrade_execution(state, 'web', [dict(Type='bind', RW=True, Source=str(base), Destination=str(base))])
                self.assertEqual((assets/'bouncer.conf').read_bytes(), before)
            config = assets/'bouncer.conf'
            overrides = {'MODE': 'live', 'APPSEC_URL': f'http://127.0.0.1:{appsec_port}',
                         'APPSEC_PROCESS_TIMEOUT': '50',
                         'REQUEST_TIMEOUT': '50'}
            if not installed_defaults:
                overrides['APPSEC_FAILURE_ACTION'] = policy
            if lapi_policy is not None:
                overrides['LAPI_FAILURE_ACTION'] = lapi_policy
            if always_send:
                overrides['ALWAYS_SEND_TO_APPSEC'] = 'true'
            removed = set(overrides) | (set() if installed_defaults else {'LAPI_FAILURE_ACTION'})
            lines = [line for line in config.read_text().splitlines()
                     if line.split('=', 1)[0].strip() not in removed]
            config.write_text('\n'.join(lines)+'\n'+''.join(k+'='+v+'\n' for k,v in overrides.items()))
            port = unused_port()
            env = os.environ.copy()
            package_path = str(assets)+'/lib/?.lua;'
            directives = ''
            prefix = env.get('CROWDBASTION_TEST_LUA_PREFIX')
            if prefix:
                prefix = Path(prefix)
                modules = prefix/'usr/lib/nginx/modules'
                directives += ''.join('load_module '+json.dumps(str(modules/name))+';\n'
                                      for name in ['ndk_http_module.so', 'ngx_http_lua_module.so'])
                package_path += str(prefix)+'/usr/share/lua/5.1/?.lua;'+str(prefix)+'/usr/share/lua/5.1/?/init.lua;'
                library_dirs = [prefix/'usr/lib/x86_64-linux-gnu', prefix/'lib/x86_64-linux-gnu']
                env['LD_LIBRARY_PATH'] = ':'.join(map(str, library_dirs))+':'+env.get('LD_LIBRARY_PATH', '')
                directives += 'env LD_LIBRARY_PATH;\n'
                cpath = str(prefix)+'/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;;'
            else:
                cpath = ';;'
            error_log = base/'error.log'
            nginx_config = directives+f'''
daemon off;
master_process off;
pid "{base}/nginx.pid";
error_log "{error_log}" notice;
events {{ worker_connections 128; }}
http {{
  access_log off;
  client_body_temp_path "{base}/body";
  proxy_temp_path "{base}/proxy";
  fastcgi_temp_path "{base}/fastcgi";
  uwsgi_temp_path "{base}/uwsgi";
  scgi_temp_path "{base}/scgi";
  lua_package_path "{package_path};;";
  lua_package_cpath "{cpath}";
  lua_shared_dict crowdsec_cache 2m;
  init_by_lua_file "{assets}/init.lua";
  access_by_lua_file "{assets}/access.lua";
  {('log_by_lua_file "'+str(assets)+'/log.lua";') if (assets/'log.lua').exists() else ''}
  server {{
    listen 127.0.0.1:{port};
    location / {{ proxy_pass http://127.0.0.1:{upstream_port}; }}
  }}
}}
'''
            path = base/'nginx.conf'
            path.write_text(nginx_config)
            process = subprocess.Popen([NGINX, '-p', str(base)+'/', '-c', str(path)],
                                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic()+5
                while True:
                    if process.poll() is not None:
                        self.fail('Nginx failed to start: '+process.stderr.read().decode()+
                                  (error_log.read_text() if error_log.exists() else ''))
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail('Nginx startup timeout')
                        time.sleep(0.01)
                request = urllib.request.Request(f'http://127.0.0.1:{port}/runtime-check?private-canary=receipt-must-not-copy-this',
                                                 headers={'User-Agent': 'CB_EXEC_V1 {"cause":"lapi_ban"}', 'X-Request-ID': 'client-forged-id', 'X-Crowdsec-Execution': 'blocked'})
                try:
                    response = urllib.request.urlopen(request, timeout=3)
                except urllib.error.HTTPError as response_error:
                    response = response_error
                with response:
                    status, body = response.code, response.read()
                if evidence:
                    process.terminate()
                    process.wait(timeout=5)
                    records = []
                    for line in error_log.read_text().splitlines():
                        match = re.search(r': CB_EXEC_V1 (\{)', line)
                        if match:
                            record, _ = json.JSONDecoder().raw_decode(line[match.start(1):])
                            records.append(record)
                    reader_spec = importlib.util.spec_from_file_location('runtime_execution', ROOT/'lib/crowdsec_execution.py')
                    reader = importlib.util.module_from_spec(reader_spec)
                    reader_spec.loader.exec_module(reader)
                    result = reader.query([str(base)], '127.0.0.1', time.time()-60)
                    self.assertEqual(result['count'], len(records), 'TG reader must accept the real Nginx records')
                    return status, body, upstream['upstream_requests'], records
                result = (status, body, upstream['upstream_requests'])
                return result+(appsec['requests'],) if include_appsec_count else result
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                process.stderr.close()

    def test_new_install_denies_appsec_and_lapi_failures_by_default(self):
        for endpoint_name in ['appsec', 'lapi']:
            for fault in ['refused', 'timeout', 'http_error']:
                with self.subTest(endpoint=endpoint_name, fault=fault):
                    result = self.request_case(None, fault if endpoint_name == 'appsec' else 'healthy',
                                               lapi_fault=fault if endpoint_name == 'lapi' else 'healthy',
                                               installed_defaults=True)
                    self.assertEqual((result[0], result[2]), (403, 0))
        self.assertEqual(self.request_case(None, 'healthy', installed_defaults=True),
                         (200, b'business-upstream', 1))

    def test_legacy_runtime_upgrade_enforces_both_failure_policies(self):
        for had_execution_recorder in [False, True]:
            for endpoint_name in ['appsec', 'lapi']:
                with self.subTest(recorder=had_execution_recorder, endpoint=endpoint_name):
                    result = self.request_case('deny', 'refused' if endpoint_name == 'appsec' else 'healthy',
                                               'deny', 'http_error' if endpoint_name == 'lapi' else 'healthy',
                                               legacy_upgrade=had_execution_recorder)
                    self.assertEqual((result[0], result[2]), (403, 0))

    def test_real_denials_emit_server_receipts_after_final_response(self):
        cases = [('lapi_ban', 'passthrough', 'lapi_ban'),
                 ('rule_block', 'passthrough', 'appsec_rule'),
                 ('refused', 'deny', 'appsec_failure'),
                 ('timeout', 'deny', 'appsec_failure'),
                 ('http_error', 'deny', 'appsec_failure')]
        for fault, policy, cause in cases:
            with self.subTest(fault=fault):
                status, body, requests, records = self.request_case(policy, fault, evidence=True)
                self.assertEqual((status, requests), (403, 0))
                self.assertEqual(len(records), 1, 'a real ban must produce a final-response receipt')
                record = records[0]
                self.assertEqual(record['cause'], cause)
                self.assertEqual(record['status'], status)
                self.assertEqual(record['upstream'], '')
                self.assertEqual(record['ip'], '127.0.0.1')
                self.assertRegex(record['request_id'], r'^[a-f0-9]{32}$')
                self.assertNotIn('client-forged', json.dumps(record))
                self.assertNotIn('private-canary', json.dumps(record))
                self.assertNotIn('receipt-must-not-copy-this', json.dumps(record))

    def test_lapi_failure_policy_denial_has_distinct_execution_cause(self):
        status, _, requests, records = self.request_case('deny', 'healthy', 'deny', 'http_error', evidence=True)
        self.assertEqual((status, requests), (403, 0))
        self.assertEqual(len(records), 1, 'LAPI failure denial needs its own execution receipt')
        self.assertEqual(records[0]['cause'], 'lapi_failure')

    def test_allowed_requests_and_business_403_never_emit_bouncer_receipts(self):
        for fault in ['healthy', 'refused', 'timeout', 'http_error', 'business_403']:
            with self.subTest(fault=fault):
                status, body, requests, records = self.request_case('passthrough', fault, evidence=True)
                self.assertEqual(requests, 1)
                self.assertEqual(status, 403 if fault == 'business_403' else 200)
                self.assertEqual(records, [])

    def test_deny_on_appsec_failure_returns_403_without_contacting_upstream(self):
        for fault in ['refused', 'timeout', 'http_error']:
            with self.subTest(fault=fault):
                status, body, requests = self.request_case('deny', fault)
                self.assertEqual(requests, 0, 'failure denial must stop before the business upstream')
                self.assertEqual(status, 403, 'failure denial must carry an HTTP denial status')
                self.assertNotEqual(body, b'business-upstream')

    def test_passthrough_preserves_access_on_appsec_failure(self):
        for fault in ['refused', 'timeout', 'http_error']:
            with self.subTest(fault=fault):
                status, body, requests = self.request_case('passthrough', fault)
                self.assertEqual((status, body, requests), (200, b'business-upstream', 1))

    def test_healthy_appsec_allows_upstream_with_deny_failure_policy(self):
        self.assertEqual(self.request_case('deny', 'healthy'), (200, b'business-upstream', 1))

    def test_lapi_failure_denial_stops_upstream_even_with_healthy_appsec(self):
        for fault in ['refused', 'timeout', 'http_error']:
            with self.subTest(fault=fault):
                status, body, requests = self.request_case('deny', 'healthy', 'deny', fault)
                self.assertEqual(requests, 0, 'decision lookup failure must stop business access')
                self.assertEqual(status, 403)
                self.assertNotEqual(body, b'business-upstream')

    def test_lapi_passthrough_and_unspecified_policy_preserve_existing_access(self):
        for policy in [None, 'passthrough']:
            for fault in ['refused', 'timeout', 'http_error']:
                with self.subTest(policy=policy, fault=fault):
                    self.assertEqual(self.request_case('deny', 'healthy', policy, fault),
                                     (200, b'business-upstream', 1))

    def test_both_healthy_allow_upstream_with_both_failure_policies_deny(self):
        self.assertEqual(self.request_case('deny', 'healthy', 'deny'),
                         (200, b'business-upstream', 1))

    def test_invalid_lapi_failure_policy_rejects_startup(self):
        with self.assertRaisesRegex(AssertionError, 'LAPI_FAILURE_ACTION'):
            self.request_case('deny', 'healthy', 'denny')

    def test_lapi_denial_short_circuits_appsec_even_when_always_send_enabled(self):
        status, _, requests, appsec = self.request_case(
            'deny', 'healthy', 'deny', 'http_error',
            always_send=True, include_appsec_count=True)
        self.assertEqual((status, requests, appsec), (403, 0, 0))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Optional real OpenResty + CrowdSec AppSec integration, without service installs.

Usage: python3 tests/verify_web.py /path/to/crowdsec-v1.8.1 \
    /path/to/crowdsec-openresty-bouncer-v1.2.3.tgz /path/to/lua-resty-http-v0.17.1.tgz

Requires Python's PyYAML, dpkg-deb, Linux amd64 and network access to the official
OpenResty repository and CrowdSec Hub. Packages are verified and extracted, never
installed. Processes, configuration, sockets and dummy WAF scripts are isolated
in temporary directories; downloads remain in the configurable cache directory.
The dummy WAF proves hook composition, not proprietary 1Panel WAF compatibility.
"""
import argparse
from contextlib import contextmanager
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PACKAGES_URL = 'https://openresty.org/package/debian/dists/bookworm/openresty/binary-amd64/Packages'
DEB_BASE = 'https://openresty.org/package/debian/'
PACKAGES = {
    'openresty': ('1.25.3.2-2~bookworm1', '6a3a21b249f5f942ccdcb62e800aa9f64b5d63e56c5b89c1415b61b68fdfc37a'),
    'openresty-openssl111': ('1.1.1w-1~bookworm1', 'a755b32fe0fc2d227faa8dbee9c3aa76860595a5efab49b9a7fdfebe20a3120a'),
    'openresty-pcre': ('8.45-2~bookworm1', '9ea616345beabf3d0da8894fe1f1f7f24f57131e487ae04d2da59e621ce46bd0'),
    'openresty-zlib': ('1.3.1-1~bookworm1', '6235392758978451187c7d137fb03a19731ccd3ceaed87d4deb9e087fe002a02'),
}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed:\n{result.stdout[-5000:]}{result.stderr[-5000:]}')
    return result.stdout


def download(url, path):
    with urllib.request.urlopen(url, timeout=60) as response:
        path.write_bytes(response.read())


def unpack_openresty(cache, dest, metadata):
    cache.mkdir(parents=True, exist_ok=True)
    if metadata is None:
        metadata = cache/'Packages'
        if not metadata.exists():
            download(PACKAGES_URL, metadata)
    records = []
    for paragraph in metadata.read_text().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in paragraph.splitlines()
                      if ': ' in line and not line.startswith(' '))
        records.append(fields)
    for name, (version, digest) in PACKAGES.items():
        match = [r for r in records if r.get('Package') == name and
                 r.get('Version') == version and r.get('Architecture') == 'amd64']
        assert len(match) == 1, f'Official metadata lacks pinned {name} {version}'
        record = match[0]
        assert record['SHA256'] == digest, f'Metadata SHA256 mismatch: {name}'
        archive = cache/Path(record['Filename']).name
        if not archive.exists():
            download(DEB_BASE+record['Filename'], archive)
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest, f'Archive SHA256 mismatch: {archive}'
        run(['dpkg-deb', '-x', str(archive), str(dest)])
    install = dest/'usr/local/openresty'
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = ':'.join(str(install/p/'lib') for p in ['openssl111', 'pcre', 'zlib', 'luajit'])
    nginx = install/'nginx/sbin/nginx'
    version = subprocess.run([str(nginx), '-v'], capture_output=True, text=True, env=env, check=True).stderr
    assert 'openresty/1.25.3.2' in version, version
    print('Official OpenResty 1.25.3.2 packages: SHA256 verified, extracted without install.', flush=True)
    return nginx, install, env, version


def wait_port(process, number, logfile):
    for _ in range(150):
        if process.poll() is not None:
            raise RuntimeError('Process exited:\n'+logfile.read_text()[-8000:])
        try:
            with socket.create_connection(('127.0.0.1', number), timeout=.2):
                return
        except OSError:
            time.sleep(.2)
    raise RuntimeError('Startup timeout:\n'+logfile.read_text()[-8000:])


def stop(process):
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@contextmanager
def real_engine(release, base):
    helper = module('web_qa_config', ROOT/'lib/crowdsec_config.py')
    cfg = base/'etc'
    shutil.copytree(release/'config', cfg)
    for name in ['data', 'hub', 'plugins', 'logs']:
        (base/name).mkdir()
    for name in ['notifications', 'acquis.d']:
        (cfg/name).mkdir(exist_ok=True)
    config_path = cfg/'config.yaml'
    conf = helper.read(config_path)
    conf['common'].update(daemonize=False, log_media='stdout', log_dir=str(base/'logs'))
    conf['config_paths'].update(config_dir=str(cfg), data_dir=str(base/'data'),
        simulation_path=str(cfg/'simulation.yaml'), hub_dir=str(base/'hub'),
        index_path=str(base/'hub/.index.json'), notification_dir=str(cfg/'notifications'), plugin_dir=str(base/'plugins'))
    conf['crowdsec_service'].update(acquisition_path=str(cfg/'acquis.yaml'), acquisition_dir=str(cfg/'acquis.d'))
    conf['db_config']['db_path'] = str(base/'data/crowdsec.db')
    conf['plugin_config'] = {'user': 'root', 'group': 'root'}
    api_port, appsec_port, metrics_port = free_port(), free_port(), free_port()
    conf['api']['client']['credentials_path'] = str(cfg/'local_api_credentials.yaml')
    conf['api']['server'].update(listen_uri=f'127.0.0.1:{api_port}', profiles_path=str(cfg/'profiles.yaml'),
        console_path=str(cfg/'console.yaml'), online_client=None)
    conf['prometheus'].update(listen_port=metrics_port, listen_addr='127.0.0.1')
    helper.write(config_path, conf)
    helper.main(['wal', str(config_path)])
    (cfg/'acquis.yaml').write_text('')
    cscli = release/'cmd/crowdsec-cli/cscli'
    engine = release/'cmd/crowdsec/crowdsec'

    def cli(*args):
        return run([str(cscli), '-c', str(config_path), *args])

    cli('machines', 'add', 'qa-web', '--auto', '-f', str(cfg/'local_api_credentials.yaml'), '--url', f'http://127.0.0.1:{api_port}')
    print('Installing official AppSec virtual-patching and generic rules in temporary engine...', flush=True)
    cli('hub', 'update')
    cli('collections', 'install', 'crowdsecurity/appsec-virtual-patching', 'crowdsecurity/appsec-generic-rules')
    appsec = cfg/'acquis.d/crowdsec-1key-appsec.yaml'
    helper.main(['appsec', str(appsec)])
    acquisition = helper.read(appsec)
    acquisition['listen_addr'] = f'127.0.0.1:{appsec_port}'
    helper.write(appsec, acquisition)
    key = cli('bouncers', 'add', 'qa-web', '-o', 'raw').strip()
    run([str(engine), '-c', str(config_path), '-t'])
    log = base/'engine.log'
    with log.open('w') as stream:
        process = subprocess.Popen([str(engine), '-c', str(config_path)], stdout=stream, stderr=subprocess.STDOUT)
        try:
            wait_port(process, appsec_port, log)
            yield {'api_url': f'http://127.0.0.1:{api_port}', 'appsec_url': f'http://127.0.0.1:{appsec_port}',
                   'key': key, 'cli': cli, 'metrics_url': f'http://127.0.0.1:{metrics_port}/metrics'}
        finally:
            stop(process)


def request(url, ip='203.0.113.10'):
    req = urllib.request.Request(url, headers={'X-Test-Ip': ip, 'User-Agent': 'CrowdSec OpenResty integration'})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as response:
        return response.code, response.read()


def processed(metrics_url):
    with urllib.request.urlopen(metrics_url, timeout=10) as response:
        metrics = response.read().decode()
    values = [float(line.rsplit(' ', 1)[1]) for line in metrics.splitlines()
              if line.startswith('cs_appsec_reqs_total{')]
    # Prometheus CounterVec labels appear after the first request; no series is
    # therefore the valid zero baseline, while the final assertion needs growth.
    return sum(values)


def verify(args):
    web = module('web_qa_installer', ROOT/'lib/crowdsec_web.py')
    engine_release = args.engine.resolve()
    with tempfile.TemporaryDirectory(prefix='crowdsec-real-openresty-') as tmp:
        base = Path(tmp)
        nginx, install, env, version = unpack_openresty(args.cache, base/'packages', args.metadata)
        with real_engine(engine_release, base/'engine') as engine:
            verify_hooks(base, web, nginx, install, env, version, engine, args)


def verify_hooks(base, web, nginx, install, env, version, engine, args):
    waf = base/'1pwaf'
    (waf/'data/conf').mkdir(parents=True)
    (waf/'lib/resty').mkdir(parents=True)
    dependency = waf/'lib/resty/http.lua'
    dependency.write_text('return {marker="existing-waf-dependency"}\n')
    original_dependency = dependency.read_bytes()
    marker = 'assert(require("resty.http").marker == "existing-waf-dependency")\n'
    (waf/'init.lua').write_text(marker+'original_waf_initialized = true\n')
    (waf/'worker.lua').write_text(marker+'assert(original_waf_initialized)\nngx.shared.waf_req_count:set("original_worker", true)\n')
    (waf/'waf.lua').write_text(marker+'assert(original_waf_initialized)\nassert(ngx.shared.waf_req_count:get("original_worker"))\n'
        'ngx.ctx.original_waf = true\nngx.req.set_header("X-Original-Waf", "retained")\n'
        'if ngx.var.uri == "/waf-block" then ngx.status = 403; ngx.say("original-waf-block"); return ngx.exit(403) end\n')
    waf_log = base/'waf.log'
    (waf/'log_and_traffic.lua').write_text('assert(ngx.ctx.original_waf)\n'
        'local f = assert(io.open('+json.dumps(str(waf_log))+', "a"))\nf:write(ngx.var.uri .. "\\n"); f:close()\n')
    target = waf/'data/conf/waf.conf'
    original_root = '/usr/local/openresty/1pwaf'
    original = '''lua_shared_dict waf_req_count 10m;
lua_shared_dict waf 1m;
lua_shared_dict waf_block_ip 1m;
lua_shared_dict waf_limit 1m;
lua_shared_dict waf_sql 1m;
lua_shared_dict waf_locks 1m;
lua_code_cache on;
lua_package_path "/usr/local/openresty/1pwaf/?.lua;/usr/local/openresty/1pwaf/lib/?.lua;;";
init_by_lua_file /usr/local/openresty/1pwaf/init.lua;
access_by_lua_file /usr/local/openresty/1pwaf/waf.lua;
log_by_lua_file /usr/local/openresty/1pwaf/log_and_traffic.lua;
init_worker_by_lua_file /usr/local/openresty/1pwaf/worker.lua;
'''
    original = original.replace(';;";', f';{install}/lualib/?.lua;{install}/lualib/?/init.lua;;";')
    target.write_text(original)
    plan = web.plan_install(effective='# configuration file '+original_root+'/data/conf/waf.conf:\n'+original,
        mounts=[{'Type': 'bind', 'RW': True, 'Source': str(waf/'data'), 'Destination': original_root+'/data'}],
        image='1panel/openresty:qa', network='host', version=version)
    assets = base/'assets'
    plan['host_assets'] = plan['container_assets'] = str(assets)
    web.stage_assets(plan, args.bouncer, args.http, assets, engine['key'], engine['api_url'])
    hooks = web.render_hooks(plan)
    # Container absolute paths are mapped to this isolated fixture's filesystem.
    # The CrowdSec hook code and namespaced official modules remain unchanged.
    for name in ['init.lua', 'access.lua', 'worker.lua']:
        (assets/name).write_text(hooks[name].replace(original_root, str(waf)))
    target.write_text(hooks['target'].replace(original_root, str(waf)))
    config_files = [p for p in assets.rglob('*') if p.is_file() and b'APPSEC_URL=' in p.read_bytes() and b'API_KEY=' in p.read_bytes()]
    assert len(config_files) == 1, config_files
    config = config_files[0]
    config.write_text(re.sub(r'^APPSEC_URL=.*$', 'APPSEC_URL='+engine['appsec_url'], config.read_text(), flags=re.M))
    seen = []

    class Backend(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.do_GET()

        def do_GET(self):
            seen.append((self.path, self.headers.get('X-Original-Waf')))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'backend-reached')

        def log_message(self, *args):
            pass

    backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    prefix = base/'nginx'
    prefix.mkdir()
    (prefix/'logs').mkdir()
    port = free_port()
    h2_port = free_port()
    config_path = prefix/'nginx.conf'
    user_directive = f'user {pwd.getpwuid(os.getuid()).pw_name};\n' if os.getuid() == 0 else ''
    config_path.write_text(user_directive+f'''worker_processes 1;
daemon off;
error_log {prefix}/error.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 128; }}
http {{
    lua_package_cpath "{install}/lualib/?.so;;";
    include {target};
    server {{
        listen 127.0.0.1:{port};
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Test-Ip;
        location / {{ proxy_pass http://127.0.0.1:{backend.server_port}; }}
    }}
    server {{
        listen 127.0.0.1:{h2_port};
        http2 on;
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Test-Ip;
        location / {{ proxy_pass http://127.0.0.1:{backend.server_port}; }}
    }}
}}
''')
    process = None
    log = prefix/'stdout.log'
    try:
        run([str(nginx), '-p', str(prefix)+'/', '-c', str(config_path), '-t'], env=env)
        print('Real OpenResty nginx -t: PASS with generated hooks and namespaced official Lua modules.', flush=True)
        with log.open('w') as stream:
            process = subprocess.Popen([str(nginx), '-p', str(prefix)+'/', '-c', str(config_path)], env=env, stdout=stream, stderr=subprocess.STDOUT)
            wait_port(process, port, log)
            url = f'http://127.0.0.1:{port}'
            before = processed(engine['metrics_url'])
            assert request(url+'/') == (200, b'backend-reached')
            assert seen == [('/', 'retained')], seen
            for _ in range(30):
                allowed_counter = processed(engine['metrics_url'])
                if allowed_counter >= before+1:
                    break
                time.sleep(.2)
            assert allowed_counter == before+1, (before, allowed_counter)
            assert request(url+'/waf-block') == (403, b'original-waf-block\n')
            assert seen == [('/', 'retained')], seen
            assert processed(engine['metrics_url']) == allowed_counter, 'CrowdSec ran before the original WAF block'
            status, body = request(url+'/.env', '203.0.113.20')
            assert status == 403 and body != b'original-waf-block\n', (status, body)
            assert seen == [('/', 'retained')], seen
            for _ in range(30):
                after = processed(engine['metrics_url'])
                if after >= before+2:
                    break
                time.sleep(.2)
            assert after == before+2, (before, after)
            metrics = engine['cli']('metrics', 'show', 'appsec')
            assert 'vpatch-env-access' in metrics, metrics
            for _ in range(30):
                if waf_log.exists() and waf_log.read_text().splitlines() == ['/', '/waf-block', '/.env']:
                    break
                time.sleep(.1)
            assert waf_log.read_text().splitlines() == ['/', '/waf-block', '/.env']
            assert dependency.read_bytes() == original_dependency
            errors = (prefix/'error.log').read_text()
            assert 'failed to run' not in errors and 'module ' not in errors, errors[-6000:]
            print('Live HTTP: allowed / reached backend; original WAF /waf-block retained 403; AppSec /.env blocked before backend.', flush=True)
            print(f'Real AppSec processed counter: {before:g} -> {after:g}; vpatch-env-access rule matched.', flush=True)
            print('Original WAF init/access/worker/log executed; original resty.http module retained and unchanged.', flush=True)
            # Exercise the explicit policies with real official Lua/OpenResty.
            # Restart this isolated runtime to load policy changes deterministically.
            audit = module('appsec_policy', ROOT/'lib/crowdsec_appsec.py')
            before_raw = urllib.request.urlopen(engine['metrics_url'], timeout=5).read().decode()
            measured = audit.counters(before_raw)
            assert measured['processed'] >= 2 and measured['blocked'] >= 1 and measured['rules'] >= 1, measured
            for body_policy in ('false', 'true'):
                stop(process)
                text = config.read_text()
                key = 'APPSEC_DROP_UNREADABLE_BODY'
                text = re.sub(r'^'+key+r'=.*$', key+'='+body_policy, text, flags=re.M)
                config.write_text(text)
                process = subprocess.Popen([str(nginx), '-p', str(prefix)+'/', '-c', str(config_path)], env=env, stdout=stream, stderr=subprocess.STDOUT)
                wait_port(process, port, log)
                marker = '/body-policy-'+body_policy
                size = len(seen)
                result = run(['curl', '--noproxy', '*', '--http2-prior-knowledge', '--max-time', '10', '-sS',
                              '-X', 'POST', '--data-binary', 'normal-body', '-H', 'Content-Length:',
                              '-H', 'X-Test-Ip: 203.0.113.21', '-o', '/dev/null', '-w', '%{http_code}',
                              f'http://127.0.0.1:{h2_port}'+marker])
                assert result == ('200' if body_policy == 'false' else '403'), result
                assert len(seen) == size+(body_policy == 'false'), seen
            for failure_policy in ('passthrough', 'deny'):
                stop(process)
                text = config.read_text()
                text = re.sub(r'^APPSEC_URL=.*$', 'APPSEC_URL=http://127.0.0.1:'+str(free_port()), text, flags=re.M)
                text = re.sub(r'^APPSEC_FAILURE_ACTION=.*$', 'APPSEC_FAILURE_ACTION='+failure_policy, text, flags=re.M)
                config.write_text(text)
                process = subprocess.Popen([str(nginx), '-p', str(prefix)+'/', '-c', str(config_path)], env=env, stdout=stream, stderr=subprocess.STDOUT)
                wait_port(process, port, log)
                size = len(seen)
                status, response_body = request(url+'/failure-policy-'+failure_policy, '203.0.113.22')
                if failure_policy == 'passthrough':
                    assert (status, response_body) == (200, b'backend-reached'), (status, response_body)
                else:
                    # Official 1.2.3 returns its ban template with HTTP 200 on
                    # connection failure. Backend isolation is the deny proof.
                    assert b'backend-reached' not in response_body and b'CrowdSec' in response_body, (status, response_body)
                assert len(seen) == size+(failure_policy == 'passthrough'), seen
                print(f'Unavailable AppSec {failure_policy}: HTTP {status}, backend reached={len(seen) > size}.', flush=True)
            print('Real HTTP2 POST without Content-Length: false allowed, true blocked; unavailable AppSec: passthrough allowed, deny blocked.', flush=True)
    except Exception as error:
        details = '\n'.join(p.read_text()[-8000:] for p in [prefix/'error.log', log] if p.exists())
        raise RuntimeError(str(error)+'\nOpenResty diagnostics:\n'+details) from error
    finally:
        stop(process)
        backend.shutdown()
        backend.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine', type=Path)
    parser.add_argument('bouncer', type=Path)
    parser.add_argument('http', type=Path)
    parser.add_argument('--metadata', type=Path, help='Existing official OpenResty Packages file')
    parser.add_argument('--cache', type=Path, default=Path('/tmp/crowdsec-openresty-qa-downloads'))
    verify(parser.parse_args())

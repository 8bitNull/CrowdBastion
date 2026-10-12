"""Real HTTP checks of adapter layouts; optional Docker bridge uses a cached image.

This validates NPM/LDNMP configuration contracts, not their entire vendor stacks.
The host nginx layout runs on extracted OpenResty with Lua, without apt installs.
"""
import argparse
from contextlib import contextmanager, redirect_stdout
import http.server
import io
import ipaddress
import json
from pathlib import Path
import re
import secrets
import signal
import shutil
import socket
import socketserver
import select
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import urllib.request

import verify_web as runtime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
import crowdsec_host as host
import crowdsec_request_audit as audit
import crowdsec_transport as transport
import crowdsec_web as web


@contextmanager
def bridge(image):
    image_id = runtime.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image]).strip()
    name = 'crowdsec-1key-qa-'+secrets.token_hex(6)
    network_id = runtime.run(['docker', 'network', 'create', '--internal', '--label', 'crowdsec-1key-qa=true', name]).strip()
    try:
        network = json.loads(runtime.run(['docker', 'network', 'inspect', network_id]))[0]
        gateway = network['IPAM']['Config'][0]['Gateway']
        yield {'id': network_id, 'name': name, 'gateway': gateway, 'image': image_id, 'network': network}
    finally:
        runtime.run(['docker', 'network', 'rm', network_id])


@contextmanager
def relay(address, destination):
    class Proxy(socketserver.BaseRequestHandler):
        def handle(self):
            with socket.create_connection(destination, timeout=10) as upstream:
                upstream.settimeout(None)
                streams = [self.request, upstream]
                while True:
                    readable, _, _ = select.select(streams, [], [], 15)
                    if not readable:
                        return
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        target = upstream if source is self.request else self.request
                        target.sendall(data)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    server = Server((address, 0), Proxy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield 'http://'+address+':'+str(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def verify_bridge_diagnostics(base, container, private, network):
    name = runtime.run(['docker', 'inspect', '--format', '{{.Name}}', container]).strip().lstrip('/')
    state = base/'docker-endpoints.json'
    with relay(private['gateway'], ('127.0.0.1', 1)) as stopped_url:
        pass
    cases = (
        ('registered', {name: private}, 0, '网络与宿主机精确监听匹配'),
        ('unregistered', {}, 0, '未登记私有端点'),
        ('network drift', {name: {**private, 'network_id': '0'*64}}, 1, 'Docker 网络已变化'),
        ('listener stopped', {name: {**private, 'appsec_url': stopped_url}}, 1, '精确监听'),
    )
    command = ['bash', '-c', 'source "$1"; DOCKER_ENDPOINTS="$2"; diagnose_docker_transport "$3" "$4" "$5"',
               'bridge-diagnostics', str(ROOT/'install-crowdsec-1panel.sh'), str(state), container, name, network]
    for label, data, expected_status, message in cases:
        web.save_state(state, data)
        before = (state.read_bytes(), state.stat().st_ino, state.stat().st_mtime_ns)
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        output = result.stdout+result.stderr
        if result.returncode != expected_status or message not in output:
            raise RuntimeError(f'Bridge diagnostic {label}: status={result.returncode}, output={output}')
        if before != (state.read_bytes(), state.stat().st_ino, state.stat().st_mtime_ns):
            raise RuntimeError('Bridge diagnostics modified registered endpoints')
        if expected_status != 0 and '精确监听匹配' in output:
            raise RuntimeError('Bridge diagnostics reported invalid endpoints as valid')
    print('Real Docker bridge diagnostics: registered / unregistered / network drift / stopped listener, read-only: PASS', flush=True)


def profile(base, kind, binary, install, environment, engine, args, private=None):
    base.mkdir()
    base.chmod(0o755)
    staged = base/'staged'
    data = base/'data'
    custom = data/'nginx/custom'
    custom.mkdir(parents=True)
    assets = base/'assets'
    target = custom/'http_top.conf' if kind == 'npm' else base/('crowdsec_'+kind+'.conf')
    native = kind in ('npm', 'ldnmp')
    original = 'add_header X-Persist retained;\n'
    target.write_text(original)
    mounts = [{'Type': 'bind', 'RW': True, 'Source': str(base), 'Destination': str(base)}]
    if native:
        virtual = '/data' if kind == 'npm' else '/etc/nginx/conf.d'
        effective = 'http { include '+('/data/nginx/custom/http_top[.]conf' if kind == 'npm' else virtual+'/*.conf')+'; }'
        planned = web.plan_install(effective, [{'Type': 'bind', 'RW': True, 'Source': str(data), 'Destination': virtual}],
                                   'lua-compatible-layout', 'bridge' if private else 'host', 'openresty/qa', private)
        planned.update(host_target=str(target), container_target=str(target), host_assets=str(assets), container_assets=str(assets), original=original)
    else:
        planned = dict(mode='nginx', original='', host_target=str(target), container_target=str(target),
                       host_assets=str(assets), container_assets=str(assets), original_mode=0o644)
    api_url = private['api_url'] if private else engine['api_url']
    appsec_url = private['appsec_url'] if private else engine['appsec_url']
    web.stage_assets(planned, args.bouncer, args.http, staged, engine['key'], api_url)
    if not private:
        shutil.copytree(install/'lualib', staged/'lib', dirs_exist_ok=True)
    settings = staged/'bouncer.conf'
    settings.write_text(re.sub(r'^APPSEC_URL=.*$', 'APPSEC_URL='+appsec_url, settings.read_text(), flags=re.M))
    state = base/'installs'
    if native:
        web.apply_install(planned, staged, state, 'fixture', 'qa-web')
    else:
        shutil.copytree(staged, assets)
        target.write_text(f'''lua_package_path "{assets}/lib/?.lua;;";
lua_shared_dict crowdsec_cache 50m;
init_by_lua_block {{ local cs = require "crowdsec_1key.crowdsec"; local ok, err = cs.init("{assets}/bouncer.conf", "qa"); if ok == nil then error(err) end }}
init_worker_by_lua_block {{ local cs = require "crowdsec_1key.crowdsec"; if string.lower(cs.get_mode()) == "stream" then cs.SetupStream() end; if ngx.worker.id() == 0 then cs.SetupMetrics() end }}
access_by_lua_block {{ local cs = require "crowdsec_1key.crowdsec"; cs.Allow(ngx.var.remote_addr) }}
''')
    seen = []

    class Backend(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'backend-reached')

        def log_message(self, *arguments):
            pass

    gateway = private['gateway'] if private else '127.0.0.1'
    backend = http.server.ThreadingHTTPServer((gateway, 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    port = runtime.free_port()
    config = base/'nginx.conf'
    (base/'logs').mkdir()
    library = '/usr/local/openresty/lualib' if private else str(install/'lualib')
    config.write_text(f'''worker_processes 1;
daemon off;
error_log {base}/error.log info;
pid {base}/nginx.pid;
events {{ worker_connections 128; }}
http {{
    lua_package_cpath "{library}/?.so;;";
    include {target};
    access_log {base}/access.log combined buffer=32k flush=1s;
    server {{
        listen 127.0.0.1:{port};
        server_name example.test;
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Test-Ip;
        location / {{ proxy_pass http://{gateway}:{backend.server_port}; }}
    }}
}}
''')
    process = None
    container = None
    firewall_rule = None
    firewall_before = None
    output = base/'stdout.log'
    prefix = [str(binary), '-p', str(base)+'/', '-c', str(config)]

    def command(*arguments):
        if container:
            return runtime.run(['docker', 'exec', container, 'nginx', '-p', str(base)+'/', '-c', str(config), *arguments])
        return runtime.run([*prefix, *arguments], env=environment)

    def request(path):
        url = f'http://127.0.0.1:{port}'+path
        if container:
            result = runtime.run(['docker', 'exec', container, 'curl', '-sS', '--noproxy', '*', '--max-time', '10',
                                  '-H', 'Host: example.test', '-H', 'X-Test-Ip: 8.8.8.8', '-w', '\n%{http_code}', url])
            body, status = result.rsplit('\n', 1)
            return int(status), body.encode()
        req = urllib.request.Request(url, headers={'Host': 'example.test', 'X-Test-Ip': '8.8.8.8'})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as response:
            return response.code, response.read()

    try:
        if private:
            container = runtime.run(['docker', 'run', '-d', '--network', args.bridge_context['name'], '--label', 'crowdsec-1key-qa=true',
                                     '-v', str(base)+':'+str(base), '--entrypoint', 'nginx', args.bridge_context['image'],
                                     '-p', str(base)+'/', '-c', str(config)]).strip()
            if args.allow_test_bridge:
                inspection = json.loads(runtime.run(['docker', 'inspect', container]))[0]
                connection = inspection['NetworkSettings']['Networks'][args.bridge_context['name']]
                assert connection['NetworkID'] == private['network_id']
                address = str(ipaddress.IPv4Address(connection['IPAddress']))
                interface = args.bridge_context['network'].get('Options', {}).get('com.docker.network.bridge.name', 'br-'+private['network_id'][:12])
                assert re.fullmatch(r'[a-zA-Z0-9_.-]+', interface)
                ports = [api_url.rsplit(':', 1)[1], appsec_url.rsplit(':', 1)[1], str(backend.server_port)]
                firewall_rule = ['-i', interface, '-s', address+'/32', '-d', gateway+'/32', '-p', 'tcp',
                                 '-m', 'multiport', '--dports', ','.join(ports), '-m', 'comment', '--comment',
                                 args.bridge_context['name'], '-j', 'ACCEPT']
                firewall_before = runtime.run(['iptables', '-S', 'INPUT'])
                runtime.run(['iptables', '-I', 'INPUT', '1', *firewall_rule])
            for attempt in range(40):
                try:
                    command('-t')
                    break
                except RuntimeError:
                    if attempt == 39:
                        raise
                    time.sleep(.2)
            verify_bridge_diagnostics(base, container, private, args.bridge_context['name'])
        else:
            command('-t')
            with output.open('w') as stream:
                process = subprocess.Popen(prefix, env=environment, stdout=stream, stderr=subprocess.STDOUT)
            runtime.wait_port(process, port, output)
        before = runtime.processed(engine['metrics_url'])
        effective = base/'effective'
        effective.write_text(command('-T'))
        mapping = base/'mounts'
        web.save_state(mapping, mounts)
        links = base/'links.yaml'
        settings = assets/'bouncer.conf'
        links.write_text(json.dumps({str(settings): ''}))
        token = 'a'*24
        plan_file = base/'request-plan'
        with patch.object(audit, 'HOST_APPSEC_URL', appsec_url):
            audit.plan(effective, mapping, state if native else links, 'fixture' if native else kind,
                       f'http://example.test:{port}', '8.8.8.8', token, plan_file, None if native else str(settings))
        original_hook = Path(web.read_state(plan_file)['target']).read_bytes()
        try:
            audit.stage(plan_file)
            command('-t')
            command('-s', 'reload')
            time.sleep(.5)
            status, body = request('/?crowdsec_ip_check='+token)
            assert (status, body) == (200, b'backend-reached'), (status, body)
            for attempt in range(30):
                try:
                    with redirect_stdout(io.StringIO()):
                        audit.verify(plan_file, base/'proof')
                    break
                except ValueError:
                    if attempt == 29:
                        raise
                    time.sleep(.2)
        finally:
            Path(web.read_state(plan_file)['target']).write_bytes(original_hook)
            command('-t')
            command('-s', 'reload')
        time.sleep(.5)
        status, body = request('/.env')
        assert status == 403, (status, body)
        assert seen == ['/?crowdsec_ip_check='+token], seen
        for attempt in range(40):
            count = runtime.processed(engine['metrics_url'])
            if count >= before+2:
                break
            time.sleep(.2)
        assert count == before+2, (before, count)
        if kind == 'npm':
            rebuilt = base/'rebuilt-site.conf'
            rebuilt.write_text(f'server {{ listen 127.0.0.1:{runtime.free_port()}; server_name added.example.test; location / {{ proxy_pass http://127.0.0.1:{backend.server_port}; }} }}\n')
            original_config = config.read_text()
            config.write_text(original_config.replace('http {', f'http {{\n include {rebuilt};', 1))
            command('-t')
            command('-s', 'reload')
            effective.write_text(command('-T'))
            web.main(['active-hooks', str(state), 'fixture', str(mapping), str(effective)])
            assert target.read_text().startswith(original)
        print(f'{kind}'+(' / real Docker private bridge' if private else ' / isolated Lua runtime')+': normal=200, AppSec=403, backend protected, buffered log and actual Bouncer IP=8.8.8.8: PASS', flush=True)
    except Exception as error:
        diagnostics = (base/'error.log').read_text()[-6000:] if (base/'error.log').exists() else ''
        raise RuntimeError(str(error)+'\nAdapter runtime diagnostics:\n'+diagnostics) from error
    finally:
        try:
            if firewall_rule:
                runtime.run(['iptables', '-D', 'INPUT', *firewall_rule])
                assert runtime.run(['iptables', '-S', 'INPUT']) == firewall_before, 'INPUT changed during QA; existing rules were not overwritten'
        finally:
            try:
                if container:
                    runtime.run(['docker', 'rm', '-f', container])
            finally:
                runtime.stop(process)
                backend.shutdown()
                backend.server_close()


def main():
    def terminate(signum, frame):
        raise KeyboardInterrupt('QA terminated')
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser()
    parser.add_argument('engine', type=Path)
    parser.add_argument('bouncer', type=Path)
    parser.add_argument('http', type=Path)
    parser.add_argument('--cache', type=Path, default=Path('/tmp/crowdsec-openresty-qa-downloads'))
    parser.add_argument('--metadata', type=Path)
    parser.add_argument('--bridge-image')
    parser.add_argument('--bridge-only', action='store_true')
    parser.add_argument('--allow-test-bridge', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='crowdsec-adapter-qa-') as temporary:
        base = Path(temporary)
        base.chmod(0o755)
        binary, install, environment, _ = runtime.unpack_openresty(args.cache, base/'packages', args.metadata)
        with runtime.real_engine(args.engine.resolve(), base/'engine') as engine:
            for kind in (() if args.bridge_only else ('npm', 'nginx', 'openresty')):
                profile(base/kind, kind, binary, install, environment, engine, args)
            if args.bridge_image:
                with bridge(args.bridge_image) as network:
                    args.bridge_context = network
                    api_port = int(engine['api_url'].rsplit(':', 1)[1])
                    appsec_port = int(engine['appsec_url'].rsplit(':', 1)[1])
                    with relay(network['gateway'], ('127.0.0.1', api_port)) as api_url, relay(network['gateway'], ('127.0.0.1', appsec_port)) as appsec_url:
                        inspection = {'HostConfig': {'NetworkMode': network['name']}, 'NetworkSettings': {'Networks': {
                            network['name']: {'NetworkID': network['id'], 'Gateway': network['gateway']}}}}
                        private = transport.plan(inspection, [network['network']], api_url, appsec_url)
                        profile(base/'ldnmp', 'ldnmp', binary, install, environment, engine, args, private)
            else:
                print('Docker bridge: SKIP (pass an already cached Lua-compatible --bridge-image).', flush=True)


if __name__ == '__main__':
    main()

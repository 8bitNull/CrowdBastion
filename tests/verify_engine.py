#!/usr/bin/env python3
"""Optional integration check using an unpacked official CrowdSec release.

Usage: python3 tests/verify_engine.py /path/to/crowdsec-v1.8.1
Downloads official Hub rules. Only a temporary tree and loopback ports are used.
"""
import http.server
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('config_helper', ROOT/'lib/crowdsec_config.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def verify(release):
    release = Path(release).resolve()
    cscli = release/'cmd/crowdsec-cli/cscli'
    engine = release/'cmd/crowdsec/crowdsec'
    with tempfile.TemporaryDirectory(prefix='crowdsec-real-engine-') as tmp:
        base = Path(tmp)
        cfg = base/'etc'
        shutil.copytree(release/'config', cfg)
        for d in ['data', 'hub', 'plugins', 'logs']:
            (base/d).mkdir()
        (cfg/'notifications').mkdir(exist_ok=True)
        (cfg/'acquis.d').mkdir(exist_ok=True)
        shutil.copy2(release/'cmd/notification-http/notification-http', base/'plugins/notification-http')
        config_path = cfg/'config.yaml'
        conf = helper.read(config_path)
        conf['common'].update(daemonize=False, log_media='stdout', log_dir=str(base/'logs'))
        conf['config_paths'].update(config_dir=str(cfg), data_dir=str(base/'data'), simulation_path=str(cfg/'simulation.yaml'), hub_dir=str(base/'hub'), index_path=str(base/'hub/.index.json'), notification_dir=str(cfg/'notifications'), plugin_dir=str(base/'plugins'))
        conf['crowdsec_service'].update(acquisition_path=str(cfg/'acquis.yaml'), acquisition_dir=str(cfg/'acquis.d'))
        conf['db_config']['db_path'] = str(base/'data/crowdsec.db')
        conf['plugin_config'] = {'user': 'root', 'group': 'root'}
        api_port, appsec_port, metrics_port = port(), port(), port()
        conf['api']['client']['credentials_path'] = str(cfg/'local_api_credentials.yaml')
        conf['api']['server'].update(listen_uri=f'127.0.0.1:{api_port}', profiles_path=str(cfg/'profiles.yaml'), console_path=str(cfg/'console.yaml'), online_client=None)
        conf['prometheus'].update(listen_port=metrics_port, listen_addr='127.0.0.1')
        helper.write(config_path, conf)
        helper.main(['wal', str(config_path)])
        (cfg/'acquis.yaml').write_text('')

        def cli(*args):
            p = subprocess.run([str(cscli), '-c', str(config_path), *args], text=True, capture_output=True, timeout=180)
            if p.returncode:
                raise RuntimeError('cscli '+str(args)+':\n'+p.stdout[-4000:]+p.stderr[-4000:])
            return p.stdout

        cli('machines', 'add', 'qa-engine', '--auto', '-f', str(cfg/'local_api_credentials.yaml'), '--url', f'http://127.0.0.1:{api_port}')
        print('Updating official Hub and installing collections...', flush=True)
        cli('hub', 'update')
        cli('collections', 'install', 'crowdsecurity/linux', 'crowdsecurity/sshd', 'crowdsecurity/nginx', 'crowdsecurity/nginx-proxy-manager', 'crowdsecurity/http-cve', 'crowdsecurity/base-http-scenarios', 'crowdsecurity/whitelist-good-actors', 'crowdsecurity/wordpress', 'crowdsecurity/iptables', 'crowdsecurity/appsec-virtual-patching', 'crowdsecurity/appsec-generic-rules')
        print('All manager collection names accepted by official Hub.', flush=True)
        # Use actual bind-source files, including characters special to Go globs.
        web = base/r'host web[qa]\logs'
        log_file = web/'sites/bob.example.com/log/access.log'
        log_file.parent.mkdir(parents=True)
        log_file.touch()
        presets, mounts = base/'presets.yaml', base/'mounts.tsv'
        presets.write_text('')
        mounts.write_text('nginx\t'+json.dumps([{'Type': 'bind', 'Source': str(web), 'Destination': '/www'}])+'\n')
        repair = cfg/'acquis.d/crowdsec-1key-log-repair.yaml'
        helper.stage_log_repair(cfg, presets, mounts, repair)
        assert helper.read(repair)['labels']['type'] == 'nginx'
        appsec = cfg/'acquis.d/crowdsec-1key-appsec.yaml'
        helper.main(['appsec', str(appsec)])
        data = helper.read(appsec)
        data['listen_addr'] = f'127.0.0.1:{appsec_port}'
        helper.write(appsec, data)
        helper.main(['whitelist', str(cfg/'parsers/s02-enrich/99-admin-whitelist.yaml'), '203.0.113.9'])
        received = []

        class Receiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        notification = cfg/'notifications/crowdsec-1key-telegram.yaml'
        helper.main(['telegram', str(notification), '123456:TEST', '-123', 'https://telegram.example/proxy'])
        notif = helper.read(notification)
        notif['url'] = f'http://127.0.0.1:{server.server_port}/test'
        helper.write(notification, notif)
        helper.main(['profiles', str(cfg/'profiles.yaml'), 'enable'])
        try:
            cli('notifications', 'test', 'crowdsec_1key_telegram')
            assert received and received[-1]['chat_id'] == '-123' and 'CrowdSec' in received[-1]['text']
            hostile = 'test "quoted"\n<script>&\\escape'
            cli('notifications', 'test', 'crowdsec_1key_telegram', '--alert', json.dumps({'scenario': hostile, 'decisions': [], 'source': None}))
            assert hostile in received[-1]['text'], received[-1]
            print('Official HTTP notification plugin rendered template and delivered valid JSON.', flush=True)
            checked = subprocess.run([str(engine), '-c', str(config_path), '-t'], text=True, capture_output=True, timeout=60)
            if checked.returncode:
                raise RuntimeError(checked.stdout[-4000:]+checked.stderr[-4000:])
            print('crowdsec -t: PASS (log repair, AppSec, profiles, notification, administrator whitelist).', flush=True)
            key = cli('bouncers', 'add', 'qa-appsec', '-o', 'raw').strip()
            log = base/'engine.log'
            with log.open('w') as f:
                process = subprocess.Popen([str(engine), '-c', str(config_path)], stdout=f, stderr=subprocess.STDOUT)
                try:
                    for _ in range(100):
                        if process.poll() is not None:
                            raise RuntimeError('Engine exited:\n'+log.read_text()[-6000:])
                        try:
                            with socket.create_connection(('127.0.0.1', appsec_port), timeout=.2):
                                break
                        except OSError:
                            time.sleep(.2)
                    else:
                        raise RuntimeError('Engine startup timeout:\n'+log.read_text()[-6000:])

                    with log_file.open('a') as access:
                        access.write('203.0.113.10 - - ['+time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime())+'] "GET / HTTP/1.1" 200 42 "-" "CrowdSec integration test"\n')
                    for _ in range(30):
                        acquired = cli('metrics', 'show', 'acquisition', '-o', 'json')
                        if str(log_file) in acquired.replace('\\\\', '\\'):
                            break
                        time.sleep(.2)
                    else:
                        raise RuntimeError('Repaired log source absent from acquisition metrics:\n'+acquired)
                    print('Live repaired HTTP file with spaces, brackets and backslash: acquisition metrics present.', flush=True)

                    headers = {'X-Crowdsec-Appsec-Ip': '203.0.113.10', 'X-Crowdsec-Appsec-Uri': '/.env', 'X-Crowdsec-Appsec-Host': 'test.example', 'X-Crowdsec-Appsec-Verb': 'GET', 'X-Crowdsec-Appsec-Api-Key': key, 'X-Crowdsec-Appsec-User-Agent': 'CrowdSec integration test', 'X-Crowdsec-Appsec-Http-Version': '11'}
                    request = urllib.request.Request(f'http://127.0.0.1:{appsec_port}/', headers=headers)
                    try:
                        with urllib.request.urlopen(request, timeout=10) as response:
                            status, body = response.status, response.read()
                    except urllib.error.HTTPError as e:
                        status, body = e.code, e.read()
                    assert status == 403 and json.loads(body)['action'] == 'ban', (status, body)
                    print('Live AppSec /.env request: HTTP 403, action=ban.', flush=True)
                    headers['X-Crowdsec-Appsec-Uri'] = '/'
                    with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{appsec_port}/', headers=headers), timeout=10) as response:
                        assert response.status == 200 and json.load(response)['action'] == 'allow'
                    print('Live AppSec ordinary / request: HTTP 200, action=allow.', flush=True)
                    cli('lapi', 'status')
                    webcreds = cfg/'webui_api_credentials.yaml'
                    cli('machines', 'add', 'qa-webui', '--auto', '-f', str(webcreds), '--url', f'http://127.0.0.1:{api_port}')
                    webconfig = cfg/'webui-test-config.yaml'
                    helper.main(['credentials-config', str(config_path), str(webcreds), str(webconfig)])
                    checked = subprocess.run([str(cscli), '-c', str(webconfig), 'lapi', 'status'], capture_output=True, timeout=30)
                    assert checked.returncode == 0
                    cli('machines', 'delete', 'qa-webui')
                    checked = subprocess.run([str(cscli), '-c', str(webconfig), 'lapi', 'status'], capture_output=True, timeout=30)
                    assert checked.returncode != 0
                    print('Independent WebUI credentials: valid account accepted; deleted account rejected.', flush=True)
                    cli('decisions', 'add', '--ip', '203.0.113.11', '--duration', '168h', '--reason', 'integration check')
                    assert '203.0.113.11' in cli('decisions', 'list', '-o', 'json')
                    cli('decisions', 'delete', '--ip', '203.0.113.11')
                    metrics = cli('metrics', 'show', 'appsec')
                    assert 'vpatch-env-access' in metrics, metrics
                    print('LAPI login, manual ban/unban and AppSec rule metrics: PASS.', flush=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        finally:
            server.shutdown()
            server.server_close()


def verify_bouncer(release):
    release = Path(release).resolve()
    for mode in ['nftables', 'iptables']:
        with tempfile.TemporaryDirectory(prefix='crowdsec-bouncer-config-') as tmp:
            path = Path(tmp)/'bouncer.yaml'
            original = (release/'config/crowdsec-firewall-bouncer.yaml').read_text().replace('${BACKEND}', mode).replace('${API_KEY}', 'fake-original-api-key')
            path.write_text(original)
            helper.main(['bouncer', str(path), 'http://127.0.0.1:8080/', 'fake-new-api-key-longer-than-16', 'true'])
            result = subprocess.run([str(release/'crowdsec-firewall-bouncer'), '-c', str(path), '-T'], text=True, capture_output=True, timeout=10)
            assert result.returncode == 0, result.stderr
            effective = yaml.safe_load(result.stdout)
            assert effective['api_key'] == 'fake-new-api-key-longer-than-16'
            assert effective['nftables']['ipv6']['table'] == 'crowdsec6'
            if mode == 'iptables':
                assert 'DOCKER-USER' in effective['iptables_v4_chains']
                assert 'DOCKER-USER' not in effective['iptables_chains']
            assert path.read_text() == original
    print('Official Firewall Bouncer -T: nftables/iptables local overrides accepted; defaults preserved.', flush=True)


if __name__ == '__main__':
    verify(sys.argv[1])
    if len(sys.argv) > 2:
        verify_bouncer(sys.argv[2])

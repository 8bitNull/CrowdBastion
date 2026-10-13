#!/usr/bin/env python3
"""Verify relay acquisition with an unpacked official CrowdSec release.

Usage: python3 tests/verify_relay.py /path/to/crowdsec-v1.8.1
Only a temporary configuration, synthetic SSH log and loopback LAPI are used.
"""
import contextlib
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))
from crowdsec_config import read, write
from crowdsec_relay import stage_system_logs


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def verify(release):
    release = Path(release).resolve()
    engine = release/'cmd/crowdsec/crowdsec'
    cscli = release/'cmd/crowdsec-cli/cscli'
    with tempfile.TemporaryDirectory(prefix='crowdsec-relay-engine-') as tmp:
        base = Path(tmp)
        config_dir = base/'etc'
        shutil.copytree(release/'config', config_dir)
        for name in ('data', 'hub', 'plugins', 'logs'):
            (base/name).mkdir()
        for name in ('acquis.d', 'notifications'):
            (config_dir/name).mkdir(exist_ok=True)
        config_path = config_dir/'config.yaml'
        config = read(config_path)
        config['common'].update(daemonize=False, log_media='stdout', log_dir=str(base/'logs'))
        config['config_paths'].update(config_dir=str(config_dir), data_dir=str(base/'data'),
                                     simulation_path=str(config_dir/'simulation.yaml'),
                                     hub_dir=str(base/'hub'), index_path=str(base/'hub/.index.json'),
                                     notification_dir=str(config_dir/'notifications'), plugin_dir=str(base/'plugins'))
        config['crowdsec_service'].update(acquisition_path=str(config_dir/'acquis.yaml'),
                                         acquisition_dir=str(config_dir/'acquis.d'))
        config['db_config']['db_path'] = str(base/'data/crowdsec.db')
        config['plugin_config'] = {'user': 'root', 'group': 'root'}
        config['api']['client']['credentials_path'] = str(config_dir/'local_api_credentials.yaml')
        api_port = free_port()
        config['api']['server'].update(listen_uri=f'127.0.0.1:{api_port}',
                                      profiles_path=str(config_dir/'profiles.yaml'),
                                      console_path=str(config_dir/'console.yaml'), online_client=None)
        config['prometheus'].update(listen_port=free_port(), listen_addr='127.0.0.1')
        write(config_path, config)
        (config_dir/'acquis.yaml').write_text('')

        def cli(*args):
            result = subprocess.run([str(cscli), '-c', str(config_path), *args], capture_output=True,
                                    text=True, timeout=180)
            if result.returncode:
                raise RuntimeError('Official cscli failed: '+str(args)+'\n'+result.stderr[-3000:])
            return result.stdout

        cli('machines', 'add', 'relay-qa', '--auto', '-f', str(config_dir/'local_api_credentials.yaml'),
            '--url', f'http://127.0.0.1:{api_port}')
        cli('hub', 'update')
        cli('collections', 'install', 'crowdsecurity/linux', 'crowdsecurity/sshd', 'crowdsecurity/whitelist-good-actors')
        source = config_dir/'acquis.d/crowdsec-1key-relay.yaml'
        stage = base/'stage.yaml'
        auth, secure = base/'auth.log', base/'secure'

        def stage_logs():
            with contextlib.redirect_stdout(io.StringIO()):
                stage_system_logs(config_dir, stage, [str(auth), str(secure)])
            shutil.copy2(stage, source)

        def validate():
            result = subprocess.run([str(engine), '-c', str(config_path), '-t'], capture_output=True,
                                    text=True, timeout=60)
            if result.returncode:
                raise RuntimeError('Official crowdsec -t failed:\n'+result.stdout[-3000:]+result.stderr[-3000:])

        stage_logs()
        assert read(source)['source'] == 'journalctl'
        validate()
        print('Official crowdsec -t: SSH journalctl source PASS.', flush=True)
        source.unlink()
        auth.touch()
        stage_logs()
        validate()
        print('Official crowdsec -t: SSH file source PASS.', flush=True)
        log = base/'engine.log'
        with log.open('w') as output:
            process = subprocess.Popen([str(engine), '-c', str(config_path)], stdout=output, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Isolated engine exited:\n'+log.read_text()[-3000:])
                try:
                    with socket.create_connection(('127.0.0.1', api_port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Isolated engine startup timeout.')
            # A file source starts asynchronously after LAPI; wait for registration.
            for _ in range(50):
                metrics = json.loads(cli('metrics', 'show', 'acquisition', '-o', 'json'))
                if any(str(auth) in name for name in metrics.get('acquisition', {})):
                    break
                time.sleep(.1)
            with auth.open('a') as output:
                output.write(time.strftime('%b %e %H:%M:%S')+' relay-qa sshd[1234]: Failed password for invalid user relay-test from 203.0.113.77 port 2222 ssh2\n')
            for _ in range(100):
                metrics = json.loads(cli('metrics', 'show', 'acquisition', '-o', 'json'))
                sources = [data for name, data in metrics.get('acquisition', {}).items() if str(auth) in name]
                if any(data.get('reads', 0) > 0 and data.get('parsed', 0) > 0 for data in sources):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('Synthetic SSH line was not acquired and parsed:\n'+json.dumps(metrics))
            print('Live official engine: synthetic SSH line acquired and parsed PASS.', flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    verify(sys.argv[1])

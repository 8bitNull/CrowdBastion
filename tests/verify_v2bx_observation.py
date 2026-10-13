#!/usr/bin/env python3
"""Official CrowdSec integration using source-backed synthetic V2bX events.

No production config, service, firewall or upstream API is touched. Loopback
LAPI and all engine files live inside a temporary directory.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
from crowdsec_config import read, write
from crowdsec_v2bx_logs import eligible, parse_line


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def samples():
    now = datetime.now(timezone.utc)
    xclock, sclock = now.strftime('%Y/%m/%d %H:%M:%S.%f'), now.strftime('+0000 %Y-%m-%d %H:%M:%S')
    raw = [
        ('xray', xclock+' from 198.51.100.71:1234 rejected  proxy/vless/encoding: invalid request user id'),
        ('xray', xclock+' from [2001:db8::72]:1234 rejected  proxy/vmess/encoding: invalid user > synthetic reason'),
        ('xray', xclock+' from 198.51.100.73:1234 rejected  proxy/trojan: not a valid user'),
        ('xray', xclock+' from 198.51.100.74:1234 rejected  proxy/trojan: not trojan protocol'),
        ('sing', sclock+' ERROR inbound/vless[synthetic]: process connection from 198.51.100.75:1234: unknown UUID: 11111111-2222-3333-4444-555555555555'),
        ('sing', sclock+' ERROR inbound/vmess[synthetic]: process connection from [2001:db8::76]:1234: bad request'),
        ('sing', sclock+' ERROR inbound/trojan[synthetic]: process connection from 198.51.100.77:1234: bad request: fallback disabled'),
        ('sing', sclock+' ERROR inbound/anytls[synthetic]: process connection from 198.51.100.83:1234: unknown user password: fallback disabled'),
        ('sing', sclock+' ERROR inbound/shadowsocks[synthetic]: process connection from 198.51.100.84:1234: shadowsocks: serve TCP from 198.51.100.84:1234: chacha20poly1305: message authentication failed'),
        ('xray', xclock+' from 198.51.100.78:1234 accepted tcp:synthetic.invalid:443'),
        ('sing', sclock+' ERROR inbound/vless[synthetic]: process connection from 198.51.100.79:1234: TLS handshake: timeout'),
        ('hysteria2', json.dumps({'time': int(now.timestamp()*1000), 'msg': 'client connected', 'addr': '198.51.100.80:1234', 'uuid': 'synthetic-secret'})),
        ('hysteria2', json.dumps({'time': int(now.timestamp()*1000), 'level': 'error', 'msg': 'v2bx authentication rejected',
            'schema_version': 1, 'core': 'hysteria2', 'protocol': 'hysteria2', 'event_type': 'auth_rejected', 'addr': '198.51.100.86:1234'})),
    ]
    for index, protocol in enumerate(('tuic', 'hysteria', 'hysteria2'), 88):
        fields = {'schema_version': 1, 'core': 'sing', 'protocol': protocol,
                  'event_type': 'auth_rejected', 'addr': f'198.51.100.{index}:1234'}
        raw.append(('sing', sclock+' ERROR v2bx-auth/'+protocol+': v2bx-observation '+json.dumps(fields)))
    events = []
    for core, line in raw:
        item, status = parse_line(line, core, '+00:00')
        if status != 'parsed':
            raise RuntimeError('Source-backed synthetic fixture was not parsed')
        events.append(item)
    expected = {item['source_ip'] for item in events if eligible(item)}
    relay = dict(events[0], source_ip='198.51.100.81', source_status='relay_address')
    not_observation = dict(events[0], source_ip='198.51.100.82', observation_only=False)
    invalid_source = dict(events[0], source_ip='not-an-ip')
    unsupported_anytls = dict(events[0], source_ip='198.51.100.85', core='sing', protocol='anytls', event_type='protocol_rejection')
    unsupported_hy2 = dict(events[0], source_ip='198.51.100.87', core='hysteria2', protocol='hysteria2', event_type='protocol_rejection')
    events.extend([relay, not_observation, invalid_source, unsupported_anytls, unsupported_hy2])
    for index, protocol in enumerate(('tuic', 'hysteria', 'hysteria2'), 91):
        events.append(dict(events[0], source_ip=f'198.51.100.{index}', core='sing', protocol=protocol, event_type='protocol_rejection'))
    return events, expected


def verify(release, sample_factory=samples, expected_groups=None, live_producer=None, profile_documents=None, control_scenario=False):
    release = Path(release).resolve()
    engine = release/'cmd/crowdsec/crowdsec'
    cscli = release/'cmd/crowdsec-cli/cscli'
    parser = ROOT/'rules/v2bx/parsers/s01-parse/10-v2bx-observation.yaml'
    scenario = ROOT/'rules/v2bx/scenarios/v2bx-failure-observation.yaml'
    if not all(path.is_file() for path in (engine, cscli, parser, scenario)):
        raise RuntimeError('Official binaries or observation rule artifacts missing')
    if read(scenario).get('labels', {}).get('remediation') is not False:
        raise RuntimeError('Observation scenario must explicitly disable remediation')
    with tempfile.TemporaryDirectory(prefix='crowdsec-v2bx-observation-') as tmp:
        base = Path(tmp)
        config_dir = base/'etc'
        shutil.copytree(release/'config', config_dir)
        for name in ('data', 'hub', 'plugins', 'logs'):
            (base/name).mkdir()
        # No Hub download or CAPI contact: these are local unmanaged test rules.
        (base/'hub/.index.json').write_text('{}\n')
        for name in ('acquis.d', 'notifications', 'parsers/s01-parse', 'scenarios'):
            (config_dir/name).mkdir(parents=True, exist_ok=True)
        shutil.copy2(parser, config_dir/'parsers/s01-parse'/parser.name)
        shutil.copy2(scenario, config_dir/'scenarios'/scenario.name)
        if profile_documents is not None:
            write(config_dir/'profiles.yaml', profile_documents, True)
        if control_scenario:
            write(config_dir/'scenarios/control.yaml', {
                'type': 'trigger', 'name': 'crowdsec-1key/qa-control',
                'description': 'Isolated remediation control',
                'filter': "evt.Meta.log_type == 'v2bx_failure_observation' && evt.Meta.source_ip == '198.51.100.250'",
                'groupby': 'evt.Meta.source_ip', 'blackhole': '1s',
                'labels': {'service': 'qa', 'remediation': True}})
        config_path = config_dir/'config.yaml'
        config = read(config_path)
        config['common'].update(daemonize=False, log_media='stdout', log_dir=str(base/'logs'))
        config['config_paths'].update(config_dir=str(config_dir), data_dir=str(base/'data'),
            simulation_path=str(config_dir/'simulation.yaml'), hub_dir=str(base/'hub'),
            index_path=str(base/'hub/.index.json'), notification_dir=str(config_dir/'notifications'),
            plugin_dir=str(base/'plugins'))
        config['crowdsec_service'].update(acquisition_path=str(config_dir/'acquis.yaml'),
                                          acquisition_dir=str(config_dir/'acquis.d'))
        config['db_config']['db_path'] = str(base/'data/crowdsec.db')
        config['plugin_config'] = {'user': 'root', 'group': 'root'}
        config['api']['client']['credentials_path'] = str(config_dir/'local_api_credentials.yaml')
        api_port = free_port()
        config['api']['server'].update(listen_uri=f'127.0.0.1:{api_port}',
            profiles_path=str(config_dir/'profiles.yaml'), console_path=str(config_dir/'console.yaml'), online_client=None)
        config['prometheus'].update(listen_port=free_port(), listen_addr='127.0.0.1')
        write(config_path, config)
        logfile = base/'normalized.ndjson'
        logfile.touch()
        write(config_dir/'acquis.yaml', {'filenames': [str(logfile)], 'labels': {'type': 'v2bx-observation'}})

        def cli(*args):
            result = subprocess.run([str(cscli), '-c', str(config_path), *args],
                                    capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise RuntimeError('Private cscli query failed')
            return result.stdout

        cli('machines', 'add', 'v2bx-observation-qa', '--auto', '-f', str(config_dir/'local_api_credentials.yaml'),
            '--url', f'http://127.0.0.1:{api_port}')
        validated = subprocess.run([str(engine), '-c', str(config_path), '-t'], capture_output=True, timeout=30)
        if validated.returncode:
            raise RuntimeError('Official crowdsec -t rejected observation rules')
        print('Official crowdsec -t: PASS', flush=True)
        with (base/'engine.log').open('w') as output:
            process = subprocess.Popen([str(engine), '-c', str(config_path)], stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError('Private observation engine exited')
                try:
                    metrics = json.loads(cli('metrics', 'show', 'acquisition', '-o', 'json'))
                    # An empty file has no metric series until its first record.
                    # Wait for the actual tailer plus reachable metrics instead.
                    if 'Starting tail (offset: 0, whence: 2)' in (base/'engine.log').read_text():
                        break
                except RuntimeError:
                    pass
                time.sleep(.2)
            else:
                raise RuntimeError('Private engine acquisition startup timed out')
            if live_producer is not None:
                logfile.chmod(0o600)
                events, expected = live_producer(logfile)
            else:
                events, expected = sample_factory()
            expected_count = len(expected_groups) if expected_groups is not None else len(expected)
            if live_producer is None:
                with logfile.open('a') as stream:
                    for item in events:
                        stream.write(json.dumps(item)+'\n')
            deadline = time.monotonic()+20
            alerts = []
            while time.monotonic() < deadline:
                alerts = json.loads(cli('alerts', 'list', '-o', 'json')) or []
                alerts = [a for a in alerts if a.get('scenario') == 'crowdsec-1key/v2bx-failure-observation']
                if len(alerts) >= expected_count:
                    break
                time.sleep(.2)
            observed = {str(item.get('source', {}).get('value')) for item in alerts}
            if observed != expected or len(alerts) != expected_count:
                raise RuntimeError('Failure/normal/relay observation alert assertions failed')
            if expected_groups is not None:
                observed_groups = set()
                for alert in alerts:
                    for event in alert.get('events', []):
                        metadata = event.get('meta', [])
                        meta = metadata if isinstance(metadata, dict) else {m['key']: m['value'] for m in metadata}
                        observed_groups.add((str(alert.get('source', {}).get('value')), meta.get('v2bx_core'), meta.get('v2bx_protocol')))
                if observed_groups != expected_groups:
                    raise RuntimeError('Actual alert source/core/protocol group assertions failed')
            # cscli alert JSON omits the transient Alert.Remediation field.
            # Verify loaded YAML above and actual per-alert/global decisions here.
            if any(item.get('decisions') for item in alerts):
                raise RuntimeError('An observation alert unexpectedly contains decisions')
            decision_rows = json.loads(cli('decisions', 'list', '-o', 'json')) or []
            decisions = [decision for row in decision_rows for decision in row.get('decisions', [])]
            control_decisions = [d for d in decisions if d.get('scenario') == 'crowdsec-1key/qa-control']
            if any(d.get('scenario') != 'crowdsec-1key/qa-control' for d in decisions):
                raise RuntimeError('Observation generated a decision')
            if control_scenario and (len(control_decisions) != 1 or control_decisions[0].get('value') != '198.51.100.250'):
                raise RuntimeError('Independent control remediation was not preserved')
            metrics = json.loads(cli('metrics', 'show', 'acquisition', '-o', 'json'))
            rows = [item for name, item in metrics.get('acquisition', {}).items() if str(logfile) in name]
            if not rows or sum(item.get('reads', 0) for item in rows) != len(events):
                raise RuntimeError('Engine did not read all normalized synthetic events')
            result = {'scope': 'isolated official CrowdSec 1.8.1; no production traffic',
                    'configuration_validation': 'pass', 'normalized_events': len(events),
                    'failure_alerts': len(alerts), 'noneligible_records_excluded': True,
                    'scenario_remediation': False, 'per_alert_decisions_empty': True, 'decisions': 0,
                    'production_validation': 'unverified', 'control_decisions': len(control_decisions)}
            if live_producer is not None:
                result.update(normal_and_relay_excluded=True)
            elif sample_factory is samples:
                result.update(scope='isolated official CrowdSec 1.8.1, synthetic/source-backed events; no production traffic',
                              normal_and_relay_excluded=True, invalid_normalized_records_excluded=True)
            else:
                result.update(scope='isolated official CrowdSec 1.8.1; externally produced event exports; provenance supplied by caller',
                              actual_alert_groups_verified=expected_groups is not None)
            return result
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        raise SystemExit('Usage: verify_v2bx_observation.py OFFICIAL_RELEASE [RESULT_JSON]')
    result = verify(sys.argv[1])
    text = json.dumps(result, ensure_ascii=False, indent=2)+'\n'
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(text)
    print(text, end='')

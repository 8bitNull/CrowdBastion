#!/usr/bin/env python3
"""Real collector/SQLite/publisher/official engine using synthetic raw logs."""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
from crowdsec_v2bx_alerts import GUARD
from crowdsec_v2bx_logs import eligible
from crowdsec_v2bx_stream import Publisher
from verify_v2bx_observation import verify
import yaml


def pipeline(logfile):
    base = logfile.parent/'live';base.mkdir(mode=0o700)
    raw = base/'raw';raw.mkdir(mode=0o700)
    collector = base/'collector';collector.mkdir(mode=0o700)
    stream = base/'stream';stream.mkdir(mode=0o700)
    config = base/'observer.json'
    sources = [{'name': core, 'core': core, 'file': str(raw/(core+'.log')), 'timezone': '+00:00', 'relay_cidrs': '198.51.100.200/32'} for core in ('xray', 'sing', 'hysteria2')]
    for s in sources:Path(s['file']).touch()
    config.write_text(json.dumps({'poll_interval': .5, 'sources': sources}));config.chmod(0o600)
    processes = []
    publisher = None
    expected_events = 0
    def start():
        process = subprocess.Popen([sys.executable, str(ROOT/'lib/crowdsec_v2bx_service.py'), 'run', '--config', str(config), '--state', str(collector)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(process)
        return process
    def stop(process):
        process.terminate();out, err = process.communicate(timeout=5)
        if process.returncode:raise RuntimeError('collector failed during controlled stop')
    def line(core, ip, healthy=False):
        now = datetime.now(timezone.utc)
        if core == 'xray':
            clock = now.strftime('%Y/%m/%d %H:%M:%S.%f')
            return clock+f' from {ip}:1234 '+('accepted tcp:synthetic.invalid:443' if healthy else 'rejected  proxy/vless/encoding: invalid request user id')+'\n'
        if core == 'sing':
            clock = now.strftime('+0000 %Y-%m-%d %H:%M:%S')
            return clock+f' ERROR inbound/anytls[synthetic]: process connection from {ip}:1234: '+('TLS handshake: timeout' if healthy else 'unknown user password: fallback disabled')+'\n'
        item = {'time': int(now.timestamp()*1000), 'msg': 'client connected', 'addr': ip+':1234'}
        if not healthy:item.update(level='error', msg='v2bx authentication rejected', schema_version=1, core='hysteria2', protocol='hysteria2', event_type='auth_rejected')
        return json.dumps(item)+'\n'
    def append_phase(phase):
        nonlocal expected_events
        for index, source in enumerate(sources):
            with Path(source['file']).open('a') as target:
                target.write(line(source['core'], f'198.51.100.{100+phase*10+index}'))
                target.write(line(source['core'], '198.51.100.200'))
                if source['core'] != 'sing':target.write(line(source['core'], f'198.51.100.{150+index}', True));expected_events += 1
            expected_events += 2
    def wait_collector():
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            try:
                data = json.loads((collector/'status.json').read_text())
                if sum(s['events'] for s in data.get('sources', {}).values()) == expected_events:return data
            except (FileNotFoundError, json.JSONDecodeError):pass
            time.sleep(.05)
        raise RuntimeError('collector did not reach expected event count')
    def connect():
        result = Publisher(stream, {s['name']: collector/(s['name']+'.sqlite') for s in sources}, output=logfile)
        result.bind_consumer('isolated-engine-generation')
        return result
    try:
        # Historical backlog is committed before publication starts.
        append_phase(0);process = start();wait_collector()
        publisher = connect()
        if publisher.publish() != expected_events:raise RuntimeError('backlog incomplete')
        if publisher.publish() != 0:raise RuntimeError('duplicate publication')
        publisher.close();stop(process)
        append_phase(1);process = start();wait_collector()
        publisher = connect();publisher.publish()
        for source in sources:
            path = Path(source['file']);path.rename(path.with_suffix('.log.1'));path.touch()
        append_phase(2);metrics = wait_collector();publisher.publish()
        if any(s['rotations'] != 1 for s in metrics['sources'].values()):raise RuntimeError('rotation not observed')
        if publisher.publish() != 0:raise RuntimeError('rotation duplicate')
        # Independent remediation control, while the same event is an observation too.
        with Path(sources[1]['file']).open('a') as target:target.write(line('sing', '198.51.100.250'))
        expected_events += 1;wait_collector();publisher.publish()
        saved = logfile.read_bytes()
        try:publisher.bind_consumer('changed-engine-generation')
        except ValueError:pass
        else:raise RuntimeError('consumer generation change not blocked')
        if logfile.read_bytes() != saved:raise RuntimeError('generation change wrote output')
        events = [json.loads(s) for s in logfile.read_text().splitlines()]
        if len(events) != expected_events or len({e['observation_id'] for e in events}) != len(events):
            raise RuntimeError('event count or stable IDs mismatch')
        groups = {(e['source_ip'], e['core'], e['protocol']) for e in events if eligible(e)}
        if len(groups) != 10:raise RuntimeError('eligible groups mismatch')
        return events, {g[0] for g in groups}
    finally:
        if publisher:publisher.close()
        for process in processes:
            if process.poll() is None:process.terminate()
            process.communicate(timeout=5)


def main(release, target):
    profiles = [doc for doc in yaml.safe_load_all(GUARD) if doc]
    profiles.append({'name': 'deliberately_broad_qa_ban', 'filters': ['true'], 'decisions': [{'type': 'ban', 'duration': '1m'}], 'on_success': 'break'})
    result = verify(release, live_producer=pipeline, profile_documents=profiles, control_scenario=True)
    result.update(scope='isolated real collector/SQLite/incremental publisher/official CrowdSec 1.8.1; synthetic raw logs, no protocol clients',
                  observation_decisions=0, control_decisions=1, publisher_restart_no_reexport=True,
                  collector_restart_no_duplicate=True, renamed_log_rotation=True, backlog_drained=True,
                  consumer_generation_change_blocked=True, exactly_once_consumer_delivery=False)
    Path(target).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 3:raise SystemExit('Usage: verify_v2bx_alert_pipeline.py RELEASE RESULT_JSON')
    main(*sys.argv[1:])

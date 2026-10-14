#!/usr/bin/env python3
"""Local-only V2bX observer lifecycle. No CrowdSec or firewall mutations."""
import hashlib
import fcntl
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sqlite3
import subprocess
import sys
import time

from crowdsec_v2bx_observe import Observer, regular_open
from crowdsec_v2bx_logs import InputError, offset_zone, relay_networks

UNIT = 'crowdsec-v2bx-observer.service'
HELPERS = ('crowdsec_v2bx_service.py', 'crowdsec_v2bx_observe.py',
           'crowdsec_v2bx_logs.py', 'crowdsec_v2bx.py',
           'crowdsec_config.py', 'crowdsec_relay_paths.py', 'crowdbastion_health.py')


def safe_regular(path, private=False):
    path = Path(path)
    if path.resolve() != path.absolute():
        raise ValueError('symlink_path')
    fd = regular_open(path)
    info = os.fstat(fd)
    if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        os.close(fd)
        raise ValueError('file_not_private')
    return fd


def read_json(path):
    fd = safe_regular(path, private=True)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('configuration_too_large')
    return json.loads(raw)


def load_config(path):
    config = read_json(path)
    if not isinstance(config, dict) or set(config)-{'poll_interval', 'sources'}:
        raise ValueError('invalid_config')
    interval = config.get('poll_interval', 1)
    if type(interval) not in (int, float) or not math.isfinite(interval) or not .5 <= interval <= 60:
        raise ValueError('invalid_interval')
    sources = config.get('sources')
    if not isinstance(sources, list) or not 1 <= len(sources) <= 16:
        raise ValueError('invalid_sources')
    names, identities, result = set(), set(), []
    for source in sources:
        if not isinstance(source, dict) or set(source)-{'name', 'core', 'file', 'timezone', 'relay_cidrs', 'unit', 'max_events'}:
            raise ValueError('invalid_source')
        name, core, filename = source.get('name'), source.get('core'), source.get('file')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', name) or name in names:
            raise ValueError('invalid_name')
        if core not in ('xray', 'sing', 'hysteria2') or not isinstance(filename, str) or not Path(filename).is_absolute():
            raise ValueError('invalid_source')
        fd = safe_regular(filename)
        try:
            info = os.fstat(fd);identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
        if identity in identities:
            raise ValueError('duplicate_source')
        zone = source.get('timezone')
        if zone is not None:
            offset_zone(zone)
        if core == 'xray' and zone is None:
            raise ValueError('xray_timezone_required')
        networks = source.get('relay_cidrs', '')
        if not isinstance(networks, str):
            raise ValueError('invalid_relay_cidrs')
        relay_networks(networks)
        unit = source.get('unit', 'V2bX.service')
        if not isinstance(unit, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service', unit):
            raise ValueError('invalid_unit')
        maximum = source.get('max_events', 100000)
        if type(maximum) is not int or not 1 <= maximum <= 1000000:
            raise ValueError('invalid_capacity')
        names.add(name);identities.add(identity)
        result.append(dict(name=name, core=core, file=filename, timezone=zone,
                           relay_cidrs=networks, unit=unit, max_events=maximum))
    return dict(poll_interval=interval, sources=result)


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if path.resolve() != path.absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('directory_not_private')


def write_status(state, report):
    # Private directory, replace rather than follow an existing target.
    temp = state/'status.json.new'
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temp, state/'status.json')
    finally:
        if temp.exists():temp.unlink()


def run(config_path, state):
    state = Path(state)
    private_directory(state)
    lock = os.open(state/'daemon.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('unsafe_lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, ValueError):
        os.close(lock)
        print(json.dumps({'status': 'observer_busy_or_unsafe', 'observation_only': True}))
        return 1
    # Only the lock holder may recover an interrupted metrics write.
    stale = state/'status.json.new'
    if stale.exists() or stale.is_symlink():
        try:
            fd = safe_regular(stale, private=True);os.close(fd);stale.unlink()
        except Exception:
            os.close(lock)
            raise
    observers = []
    report = dict(observation_only=True, production_validation='unverified', sources={})
    stopped = False
    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    previous = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        config = load_config(config_path)
        for source in config['sources']:
            name = source['name']
            observer = Observer(source['file'], state/(name+'.sqlite'), source['core'],
                                source['timezone'], source['relay_cidrs'], source['unit'], source['max_events'])
            observers.append((source, observer))
        while not stopped:
            for source, observer in observers:
                name = source['name']
                metrics = observer.poll()
                metrics['source_present'] = Path(source['file']).is_file()
                report['sources'][name] = metrics
            report.update(status='running', heartbeat=time.time())
            write_status(state, report)
            end = time.monotonic()+config['poll_interval']
            while not stopped and time.monotonic() < end:
                time.sleep(min(.1, max(0, end-time.monotonic())))
        report.update(status='stopped', heartbeat=time.time())
        write_status(state, report)
        return 0
    except (InputError, ValueError, OSError, sqlite3.Error) as error:
        reason = 'observation_capacity_reached' if error.args == ('observation_capacity_reached',) else 'observer_failed'
        report.update(status='failed', reason=reason, heartbeat=time.time())
        write_status(state, report)
        print(json.dumps({'status': 'failed', 'reason': reason, 'observation_only': True}))
        return 1
    finally:
        for _, observer in observers:observer.close()
        for signum, handler in previous.items():signal.signal(signum, handler)
        os.close(lock)


def systemctl(*args):
    result = subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=30)
    if result.returncode and args[0] not in ('is-active',):
        raise RuntimeError('service_operation_failed')
    return result.stdout.strip()


def runtime_ready():
    # Check the actual systemd interpreter without an interactive PYTHONPATH.
    result = subprocess.run(['/usr/bin/python3', '-I', '-c', 'import yaml'],
                            capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError('system_python_yaml_missing')


class Manager:
    def __init__(self, root=Path('/'), control=systemctl, runtime_check=runtime_ready, startup_timeout=10):
        self.root = Path(root)
        self.code = self.root/'usr/local/lib/crowdsec-v2bx-observer'
        self.config = self.code/'config.json'
        self.state = self.root/'var/lib/crowdsec-v2bx-observer'
        self.unit = self.root/'etc/systemd/system'/UNIT
        self.control = control
        self.runtime_check = runtime_check
        self.startup_timeout = startup_timeout

    def guard(self, path):
        # Check every existing ancestor within the installation root.
        for item in (path, *path.parents):
            if item == self.root.parent and self.root != self.root.parent:break
            if item.exists() or item.is_symlink():
                info = item.lstat()
                if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise ValueError('unsafe_install_path')
            if item == self.root:break

    def managed(self):
        self.guard(self.code);self.guard(self.unit);self.guard(self.state)
        manifest = read_json(self.code/'manifest.json')
        expected = set(HELPERS) | {'config.json', 'unit'}
        # Previous managed bundles predate the optional diagnostic reporter.
        # Keep checking every recorded file hash, including the service unit.
        if not isinstance(manifest, dict) or set(manifest) not in (expected, expected - {'crowdbastion_health.py'}):
            raise ValueError('foreign_installation')
        reporter = self.code/'crowdbastion_health.py'
        if 'crowdbastion_health.py' not in manifest and (reporter.exists() or reporter.is_symlink()):
            raise ValueError('installation_changed')
        for name, expected_hash in manifest.items():
            target = self.unit if name == 'unit' else self.code/name
            fd = safe_regular(target, private=True)
            with os.fdopen(fd, 'rb') as stream:actual = hashlib.sha256(stream.read()).hexdigest()
            if actual != expected_hash:raise ValueError('installation_changed')

    def install(self, config_path):
        config = load_config(config_path)
        self.runtime_check()
        if self.root == Path('/'):
            for source in config['sources']:
                if any(Path(source['file']).is_relative_to(p) for p in ('/tmp', '/var/tmp')):
                    raise ValueError('private_tmp_source_unsupported')
        for target in (self.code, self.state, self.unit):
            self.guard(target)
            if target.exists() or target.is_symlink():raise ValueError('installation_exists')
        if self.control('show', '--property=LoadState', '--value', UNIT) not in ('', 'not-found'):
            raise ValueError('external_unit_exists')
        created = []
        start_attempted = False
        try:
            for target in (self.code, self.state):
                target.mkdir(parents=True, mode=0o700);created.append(target)
            manifest = {}
            for name in HELPERS:
                data = (Path(__file__).parent/name).read_bytes()
                target = self.code/name
                target.write_bytes(data);target.chmod(0o600)
                manifest[name] = hashlib.sha256(data).hexdigest()
            data = (json.dumps(config, sort_keys=True)+'\n').encode()
            self.config.write_bytes(data);self.config.chmod(0o600)
            manifest['config.json'] = hashlib.sha256(data).hexdigest()
            unit = f'''[Unit]
Description=V2bX local observation collector (no remediation)
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -B /usr/local/lib/crowdsec-v2bx-observer/crowdsec_v2bx_service.py run --config /usr/local/lib/crowdsec-v2bx-observer/config.json --state /var/lib/crowdsec-v2bx-observer
UMask=0077
Restart=no
TimeoutStopSec=15
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/lib/crowdsec-v2bx-observer
MemoryMax=256M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
'''.encode()
            self.unit.parent.mkdir(parents=True, exist_ok=True)
            with self.unit.open('xb') as stream:
                created.append(self.unit)
                stream.write(unit)
            self.unit.chmod(0o600)
            manifest['unit'] = hashlib.sha256(unit).hexdigest()
            (self.code/'manifest.json').write_text(json.dumps(manifest))
            (self.code/'manifest.json').chmod(0o600)
            self.control('daemon-reload')
            start_attempted = True
            started = time.time()
            self.control('enable', '--now', UNIT)
            deadline = time.monotonic()+self.startup_timeout
            ready = False
            names = {s['name'] for s in config['sources']}
            while time.monotonic() < deadline:
                if self.control('is-active', UNIT) != 'active':break
                try:
                    heartbeat = read_json(self.state/'status.json')
                except FileNotFoundError:
                    heartbeat = {}
                sources = heartbeat.get('sources', {})
                ready = (heartbeat.get('status') == 'running' and
                         started <= heartbeat.get('heartbeat', 0) <= time.time() and
                         set(sources) == names and
                         all(s.get('source_present') for s in sources.values()))
                if ready:break
                if heartbeat.get('status') == 'failed':break
                time.sleep(.05)
            if not ready:raise RuntimeError('collector_not_ready')
        except Exception:
            if start_attempted:
                # If stop fails, keep installation/state for diagnosis instead of deleting live code.
                self.control('disable', '--now', UNIT)
            for target in reversed(created):
                if target.is_dir():shutil.rmtree(target)
                else:target.unlink()
            self.control('daemon-reload')
            raise
        return dict(status='installed', observation_only=True, production_validation='unverified')

    def disable(self):
        self.managed()
        self.control('disable', '--now', UNIT)
        return dict(status='disabled', data_preserved=True, observation_only=True)

    def status(self):
        if not self.code.exists() and not self.code.is_symlink():
            return dict(status='not_installed', observation_only=True, production_validation='unverified')
        self.managed()
        active = self.control('is-active', UNIT) == 'active'
        report = read_json(self.state/'status.json') if (self.state/'status.json').exists() else {}
        age = time.time()-report.get('heartbeat', 0)
        missing = any(not s.get('source_present') for s in report.get('sources', {}).values())
        config = read_json(self.config)
        complete = set(report.get('sources', {})) == {s['name'] for s in config['sources']}
        healthy = complete and active and report.get('status') == 'running' and 0 <= age <= max(10, config['poll_interval']*3) and not missing
        return dict(status='observing' if healthy else 'needs_attention', service_active=active,
                    heartbeat_age_seconds=round(age, 1) if report else None,
                    collector=report, observation_only=True, production_validation='unverified')


def main(argv):
    from crowdsec_v2bx import Parser
    parser = Parser(description='V2bX 落地常驻仅观察服务')
    parser.add_argument('action', choices=('install', 'status', 'disable', 'run'))
    parser.add_argument('--config')
    parser.add_argument('--state')
    try:
        options = parser.parse_args(argv)
        if options.action in ('install', 'disable') and os.geteuid() != 0:
            raise ValueError('root_required')
        if options.action == 'run':
            if not options.config or not options.state:raise ValueError('arguments_required')
            return run(options.config, options.state)
        manager = Manager()
        if options.action == 'install':
            if not options.config:raise ValueError('configuration_required')
            result = manager.install(options.config)
        elif options.action == 'disable':result = manager.disable()
        else:result = manager.status()
        print(json.dumps(result))
        # Observation status never attests production protection.
        return 2 if options.action == 'status' else 0
    except (InputError, ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({'status': 'operation_failed', 'observation_only': True}))
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

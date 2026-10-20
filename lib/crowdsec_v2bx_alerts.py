#!/usr/bin/env python3
"""Managed V2bX observation rules and fail-closed incremental publication."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time

import yaml

from crowdsec_v2bx_service import (HELPERS, Manager, private_directory, read_json,
                                   safe_regular, systemctl, write_status)
from crowdsec_v2bx_stream import Publisher
from crowdsec_config import merged_config

UNIT = 'crowdsec-v2bx-alerts.service'
GUARD = b'''name: crowdsec_1key_v2bx_observation_guard
filters:
  - "Alert.GetScenario() == 'crowdsec-1key/v2bx-failure-observation'"
decisions: []
on_success: break
---
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bytes_of(path):
    fd = safe_regular(path)
    with os.fdopen(fd, 'rb') as stream:
        data = stream.read(1024*1024+1)
    if len(data) > 1024*1024:raise ValueError('configuration_too_large')
    return data


def replace(path, data):
    target = path.with_name(path.name+'.v2bx-new')
    mode = path.stat().st_mode & 0o777
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(target, path)
    finally:
        if target.exists():target.unlink()


def command(*args):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=30)
    if result.returncode:raise RuntimeError('crowdsec_operation_failed')
    return result.stdout


class AlertManager:
    def __init__(self, root=Path('/'), control=systemctl, runner=command, collector=None):
        self.root = Path(root)
        self.collector = collector or Manager(self.root, control)
        self.control, self.command = control, runner
        self.code = self.root/'usr/local/lib/crowdsec-v2bx-alerts'
        self.state = self.root/'var/lib/crowdsec-v2bx-alerts'
        self.unit = self.root/'etc/systemd/system'/UNIT
        self.cs = self.root/'etc/crowdsec'
        self.config = self.cs/'config.yaml'
        self.acquisition = self.cs/'acquis.d/crowdsec-1key-v2bx-observation.yaml'
        self.parser = self.cs/'parsers/s01-parse/10-crowdsec-1key-v2bx-observation.yaml'
        self.scenario = self.cs/'scenarios/crowdsec-1key-v2bx-observation.yaml'
        self.guard_paths = Manager(self.root, control).guard

    def layout(self):
        self.guard_paths(self.config)
        bytes_of(self.config)
        self.local_config_digest()
        cfg = merged_config(self.config)
        core = cfg['crowdsec_service']
        # Initial rollout only supports the standard local layout; no guessing alternate roots.
        if cfg['config_paths']['config_dir'].rstrip('/') != str(self.cs) or core['acquisition_dir'].rstrip('/') != str(self.cs/'acquis.d'):
            raise ValueError('unsupported_core_layout')
        profile = Path(cfg['api']['server']['profiles_path'])
        if not profile.is_absolute():raise ValueError('relative_profiles_path')
        self.guard_paths(profile)
        # CrowdSec evaluates profiles_path.local before profiles_path.
        local_profile = Path(str(profile)+'.local')
        self.guard_paths(local_profile)
        if local_profile.exists():profile = local_profile
        return cfg, profile

    def local_config_digest(self):
        path = Path(str(self.config)+'.local')
        self.guard_paths(path)
        return digest(bytes_of(path)) if path.exists() else None

    def assert_unique_acquisition(self, cfg):
        import fnmatch
        paths = list((self.cs/'acquis.d').glob('*.yaml')) + list((self.cs/'acquis.d').glob('*.yml'))
        legacy = cfg['crowdsec_service'].get('acquisition_path')
        if legacy and Path(legacy).exists():paths.append(Path(legacy))
        for path in paths:
            self.guard_paths(path)
            for doc in yaml.safe_load_all(bytes_of(path)):
                if doc is None:continue
                if not isinstance(doc, dict):raise ValueError('invalid_acquisition')
                patterns = doc.get('filenames', [])
                if not isinstance(patterns, list) or any(not isinstance(p, str) for p in patterns):
                    raise ValueError('invalid_acquisition_patterns')
                if any(fnmatch.fnmatchcase(str(self.state/'events.ndjson'), p) for p in patterns):
                    raise ValueError('duplicate_acquisition')

    def manifest(self):
        return read_json(self.code/'manifest.json')

    def save_manifest(self, manifest):
        target = self.code/'manifest.json'
        if not target.exists():target.touch(mode=0o600)
        replace(target, (json.dumps(manifest, sort_keys=True)+'\n').encode())

    def check_managed(self):
        self.guard_paths(self.code);self.guard_paths(self.state);self.guard_paths(self.unit)
        manifest = self.manifest()
        if manifest.get('phase') != 'enabled':raise ValueError('installation_not_enabled')
        if manifest['core_config'] != digest(bytes_of(self.config)):raise ValueError('core_config_changed')
        if manifest.get('core_config_local') != self.local_config_digest():raise ValueError('core_config_changed')
        _, profile = self.layout()
        if str(profile) != manifest['profile'] or not bytes_of(profile).startswith(GUARD):
            raise ValueError('observation_guard_changed')
        expected_paths = {str(p) for p in (self.acquisition, self.parser, self.scenario, self.unit)}
        expected_paths.update(str(self.code/name) for name in (*HELPERS, 'crowdsec_v2bx_stream.py', 'crowdsec_v2bx_alerts.py'))
        if set(manifest['assets']) != expected_paths:raise ValueError('invalid_installation_manifest')
        for filename, expected in manifest['assets'].items():
            path = Path(filename);self.guard_paths(path)
            if digest(bytes_of(path)) != expected:raise ValueError('observation_asset_changed')
        return manifest, profile

    def enable(self):
        self.collector.managed()
        if self.collector.status()['status'] != 'observing':raise ValueError('collector_not_ready')
        cfg, profile = self.layout()
        original = bytes_of(profile)
        if b'crowdsec_1key_v2bx_observation_guard' in original:raise ValueError('guard_already_exists')
        self.assert_unique_acquisition(cfg)
        for path in (self.code, self.state, self.unit, self.acquisition, self.parser, self.scenario):
            self.guard_paths(path)
            if path.exists() or path.is_symlink():raise ValueError('observation_installation_exists')
        if self.control('show', '--property=LoadState', '--value', UNIT) not in ('', 'not-found'):
            raise ValueError('external_observation_unit')
        if self.control('is-active', 'crowdsec') != 'active':raise ValueError('core_not_active')
        assets = {}
        for name in (*HELPERS, 'crowdsec_v2bx_stream.py', 'crowdsec_v2bx_alerts.py'):
            assets[self.code/name] = (Path(__file__).parent/name).read_bytes()
        root = Path(__file__).resolve().parents[1]
        assets[self.parser] = (root/'rules/v2bx/parsers/s01-parse/10-v2bx-observation.yaml').read_bytes()
        assets[self.scenario] = (root/'rules/v2bx/scenarios/v2bx-failure-observation.yaml').read_bytes()
        assets[self.acquisition] = yaml.safe_dump({'filenames': [str(self.state/'events.ndjson')], 'labels': {'type': 'v2bx-observation'}}).encode()
        assets[self.unit] = b'''[Unit]
Description=V2bX observation-only alert publication
After=crowdsec.service crowdsec-v2bx-observer.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -B /usr/local/lib/crowdsec-v2bx-alerts/crowdsec_v2bx_alerts.py run
UMask=0077
Restart=no
TimeoutStopSec=15
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/lib/crowdsec-v2bx-alerts
MemoryMax=128M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
'''
        created = []
        changed = attempted = False
        try:
            for path in (self.code, self.state):path.mkdir(parents=True, mode=0o700);created.append(path)
            (self.code/'profiles.before').write_bytes(original);(self.code/'profiles.before').chmod(0o600)
            manifest = dict(phase='prepared', profile=str(profile), core_config=digest(bytes_of(self.config)),
                            core_config_local=self.local_config_digest(),
                            assets={str(p): digest(data) for p, data in assets.items()})
            self.save_manifest(manifest)
            for path, data in assets.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as stream:
                    created.append(path);stream.write(data)
                path.chmod(0o600)
            output = self.state/'events.ndjson';output.touch(mode=0o600)
            replace(profile, GUARD+original);changed = True
            self.command('crowdsec', '-c', str(self.config), '-t')
            self.control('daemon-reload')
            self.control('restart', 'crowdsec')
            manifest['phase'] = 'enabled';self.save_manifest(manifest)
            attempted = True
            self.control('enable', '--now', UNIT)
            self.wait_ready()
        except Exception:
            if attempted:self.control('disable', '--now', UNIT)
            if changed:
                current = bytes_of(profile)
                if not current.startswith(GUARD):raise RuntimeError('guard_restore_requires_review')
                replace(profile, current[len(GUARD):])
            # Restore core assets first; retain backups/ledger until rollback restart succeeds.
            for path in reversed(created):
                if path not in (self.code, self.state) and not path.is_relative_to(self.code) and path.exists():
                    path.unlink()
            self.control('daemon-reload')
            if changed:self.control('restart', 'crowdsec')
            if attempted:
                manifest['phase'] = 'rollback_complete_requires_review'
                self.save_manifest(manifest)
            else:
                for path in (self.code, self.state):
                    if path in created and path.exists():shutil.rmtree(path)
            raise
        return dict(status='enabled', observation_only=True, production_validation='unverified')

    def wait_ready(self):
        end = time.monotonic()+20
        while time.monotonic() < end:
            if self.control('is-active', UNIT) != 'active':break
            try:status = read_json(self.state/'status.json')
            except FileNotFoundError:status = {}
            if status.get('status') == 'publishing' and time.time()-status.get('heartbeat', 0) <= 5:return
            if status.get('status') == 'failed':break
            time.sleep(.1)
        raise RuntimeError('publication_not_ready')

    def disable(self):
        manifest, profile = self.check_managed()
        # Stop first, retain the rules+guard if stop or subsequent validation fails.
        self.control('disable', '--now', UNIT)
        originals = {p: bytes_of(p) for p in (self.acquisition, self.parser, self.scenario)}
        profile_data = bytes_of(profile)
        try:
            for path in originals:path.unlink()
            replace(profile, profile_data[len(GUARD):])
            self.command('crowdsec', '-c', str(self.config), '-t')
            self.control('restart', 'crowdsec')
        except Exception:
            for path, data in originals.items():
                if not path.exists():path.write_bytes(data);path.chmod(0o600)
            replace(profile, profile_data)
            self.control('restart', 'crowdsec')
            raise
        self.unit.unlink();self.control('daemon-reload')
        manifest['phase'] = 'disabled';self.save_manifest(manifest)
        return dict(status='disabled', evidence_preserved=True, observation_only=True)

    def status(self):
        if not self.code.exists() and not self.code.is_symlink():return dict(status='not_installed', observation_only=True)
        manifest = self.manifest()
        if manifest.get('phase') == 'disabled':return dict(status='disabled', evidence_preserved=True, observation_only=True)
        self.check_managed()
        collector = read_json(self.state/'status.json') if (self.state/'status.json').exists() else {}
        active = self.control('is-active', UNIT) == 'active'
        source_status = self.collector.status()['status']
        core_active = self.control('is-active', 'crowdsec') == 'active'
        healthy = active and core_active and source_status == 'observing' and collector.get('status') == 'publishing' and 0 <= time.time()-collector.get('heartbeat', 0) <= 10
        return dict(status='publishing' if healthy else 'needs_attention', service_active=active,
                    publisher=collector, collector_status=source_status, core_active=core_active,
                    observation_only=True, production_validation='unverified')


def run(manager):
    private_directory(manager.state)
    lock = os.open(manager.state/'daemon.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('unsafe_daemon_lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, ValueError):
        os.close(lock)
        return 1
    stale = manager.state/'status.json.new'
    if stale.exists() or stale.is_symlink():
        try:
            fd = safe_regular(stale, private=True);os.close(fd);stale.unlink()
        except Exception:
            os.close(lock);raise
    publisher = None
    stopped = False
    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    previous = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        manager.check_managed();manager.collector.managed()
        cfg = read_json(manager.collector.config)
        databases = {s['name']: manager.collector.state/(s['name']+'.sqlite') for s in cfg['sources']}
        publisher = Publisher(manager.state, databases)
        def generation():
            if manager.control('is-active', 'crowdsec') != 'active':raise ValueError('consumer_inactive')
            value = manager.control('show', '--property=InvocationID', '--value', 'crowdsec')
            if not value or len(value) != 32:raise ValueError('consumer_generation_unavailable')
            return value
        current = generation();publisher.bind_consumer(current)
        # Prove acquisition reads probes before draining potentially large backlog.
        def reads():
            data = json.loads(manager.command('cscli', '-c', str(manager.config), 'metrics', 'show', 'acquisition', '-o', 'json'))
            rows = [row for name, row in data.get('acquisition', {}).items() if str(publisher.output) in name]
            return sum(r.get('reads', 0) for r in rows)
        baseline = reads()
        ready = False
        for _ in range(40):
            if stopped:break
            if generation() != current:raise ValueError('consumer_changed_requires_review')
            publisher.probe()
            time.sleep(.2)
            if reads() > baseline:ready = True;break
        if not ready and not stopped:raise ValueError('acquisition_not_ready')
        while not stopped:
            manager.check_managed()
            if generation() != current:raise ValueError('consumer_changed_requires_review')
            count = publisher.publish()
            write_status(manager.state, dict(status='publishing', heartbeat=time.time(), published_this_poll=count,
                                            cursors=publisher.saved['cursors'], output_bytes=publisher.saved['size'], observation_only=True))
            time.sleep(.5)
        write_status(manager.state, dict(status='stopped', heartbeat=time.time(), observation_only=True))
        return 0
    except (ValueError, OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError):
        write_status(manager.state, dict(status='failed', reason='publication_requires_review', heartbeat=time.time(), observation_only=True))
        return 1
    finally:
        if publisher:publisher.close()
        for signum, handler in previous.items():signal.signal(signum, handler)
        os.close(lock)


def main(argv):
    from crowdsec_v2bx import Parser
    parser = Parser(description='V2bX 常驻仅观察告警接入')
    parser.add_argument('action', choices=('enable', 'status', 'disable', 'run'))
    try:
        action = parser.parse_args(argv).action
        if action != 'status' and os.geteuid() != 0:raise ValueError('root_required')
        manager = AlertManager()
        if action == 'run':return run(manager)
        result = getattr(manager, action)()
        print(json.dumps(result))
        return 2 if action == 'status' else 0
    except (ValueError, OSError, RuntimeError, sqlite3.Error, KeyError, subprocess.SubprocessError):
        print(json.dumps({'status': 'observation_alert_operation_failed', 'observation_only': True}))
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

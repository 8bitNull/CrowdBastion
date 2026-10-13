#!/usr/bin/env python3
"""Durable observation sampling. No service, firewall or CrowdSec mutations.

SQLite atomically commits projected events and source offsets. Export is a
one-time snapshot, not a production NDJSON tailer or exactly-once delivery API.
"""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

from crowdsec_v2bx_logs import InputError, Parser, offset_zone, parse_line, relay_networks, eligible

BATCH = 65536
LIMIT = 8192


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_open(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise InputError('source_not_regular')
    return fd


def claim_source(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise InputError('source_observed_elsewhere') from None


class Observer:
    def __init__(self, source, database, core, timezone_offset=None, relay_cidrs='',
                 journal_unit='V2bX.service', max_events=100000):
        self.fd = self.lock = self.db = None
        self.source = Path(os.path.abspath(source))
        database = Path(os.path.abspath(database))
        if core not in ('xray', 'sing', 'hysteria2') or not 1 <= max_events <= 1000000:
            raise InputError('invalid_observer_options')
        if timezone_offset:
            offset_zone(timezone_offset)
        # Validate unit via same restricted grammar as the sample inspector.
        import re
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service', journal_unit):
            raise InputError('invalid_unit')
        self.core, self.zone, self.unit = core, timezone_offset, journal_unit
        self.networks = relay_networks(relay_cidrs)
        self.max_events = max_events
        if self.source.parent.resolve()/self.source.name == database.parent.resolve()/database.name:
            raise InputError('source_database_conflict')
        parent = database.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise InputError('state_directory_not_private')
        config = digest(json.dumps([str(self.source), core, timezone_offset,
                                   sorted(str(n) for n in self.networks), journal_unit]).encode())
        try:
            self.lock = os.open(database, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            info = os.fstat(self.lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise InputError('database_not_private_regular')
            if self.source.exists() and os.path.samestat(info, self.source.stat()):
                raise InputError('source_database_conflict')
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InputError('observer_already_running') from None
            self.db = sqlite3.connect(database, timeout=1)
            self.db.execute('PRAGMA synchronous=FULL')
            tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and not {'state', 'events'} <= tables:
                raise InputError('foreign_database')
            self.db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, config TEXT, payload TEXT)')
            self.db.execute('CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL)')
            previous = self.db.execute('SELECT config FROM state WHERE id=1').fetchone()
            if previous and previous[0] != config:
                raise InputError('observer_config_mismatch')
            if not previous:
                initial = dict(dev=None, ino=None, offset=0, anchor='', dropping=False,
                               lines=0, events=0, failure_observations=0, integrity_failures=0,
                               ignored={}, oversized_lines=0, rotations=0, truncations=0,
                               continuity_risks=0, missing_polls=0)
                self.db.execute('INSERT INTO state VALUES (1,?,?)', (config, json.dumps(initial)))
            self.db.commit()
        except Exception:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd);self.fd = None
        if self.db is not None:
            self.db.close();self.db = None
        if self.lock is not None:
            os.close(self.lock);self.lock = None

    def status(self):
        data = json.loads(self.db.execute('SELECT payload FROM state WHERE id=1').fetchone()[0])
        return {k: v for k, v in data.items() if k not in ('dev', 'ino', 'offset', 'anchor', 'dropping')}

    def _saved(self):
        return json.loads(self.db.execute('SELECT payload FROM state WHERE id=1').fetchone()[0])

    def _save(self, data, items):
        if data['events'] > self.max_events:
            raise InputError('observation_capacity_reached')
        try:
            with self.db:
                self.db.executemany('INSERT INTO events (payload) VALUES (?)',
                                    [(json.dumps(e),) for e in items])
                self.db.execute('UPDATE state SET payload=? WHERE id=1', (json.dumps(data),))
        except sqlite3.Error:
            raise InputError('observation_commit_failed') from None

    def _recover(self, data, current):
        """Bounded lookup of conventional uncompressed renamed siblings."""
        if data['ino'] is None:
            return current
        if current is not None and (os.fstat(current).st_dev, os.fstat(current).st_ino) == (data['dev'], data['ino']):
            return current
        with os.scandir(self.source.parent) as entries:
            for index, entry in enumerate(entries):
                if index >= 128:
                    break
                if not entry.name.startswith(self.source.name+'.'):
                    continue
                try:
                    fd = regular_open(entry.path)
                except (OSError, InputError):
                    continue
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == (data['dev'], data['ino']):
                    if current is not None:
                        os.close(current)
                    return fd
                os.close(fd)
        return current

    def poll(self, _switched=False):
        data = self._saved()
        try:
            current = regular_open(self.source)
        except FileNotFoundError:
            current = None
        except OSError:
            raise InputError('source_open_failed') from None
        try:
            if self.fd is None:
                current = self._recover(data, current)
                if current is not None:
                    claim_source(current)
                self.fd, current = current, None
            if self.fd is None:
                data['missing_polls'] += 1
                self._save(data, [])
                return self.status()
            info = os.fstat(self.fd)
            identity = (info.st_dev, info.st_ino)
            if identity != (data['dev'], data['ino']):
                if data['ino'] is not None:
                    data['rotations'] += 1
                    # No old descriptor to drain after restart: content may be lost.
                    data['continuity_risks'] += 1
                data.update(dev=identity[0], ino=identity[1], offset=0, anchor='', dropping=False)
            offset = data['offset']
            anchor = digest(os.pread(self.fd, min(256, offset), max(0, offset-256))) if offset else ''
            if info.st_size < offset or anchor != data['anchor']:
                data['truncations'] += 1;data['continuity_risks'] += 1
                data.update(offset=0, anchor='', dropping=False)
                offset = 0
            raw = os.pread(self.fd, BATCH, offset)
            items, consumed = [], 0
            while consumed < len(raw):
                end = raw.find(b'\n', consumed)
                if end < 0:
                    if data['dropping'] or len(raw)-consumed > LIMIT:
                        if not data['dropping']:
                            data['oversized_lines'] += 1
                        data['dropping'] = True
                        consumed = len(raw)
                    break
                line = raw[consumed:end]
                consumed = end+1
                if data['dropping']:
                    data['dropping'] = False
                    data['lines'] += 1
                    continue
                data['lines'] += 1
                if len(line) > LIMIT:
                    data['oversized_lines'] += 1
                    continue
                try:
                    item, status = parse_line(line.decode('utf-8'), self.core, self.zone, self.unit)
                except UnicodeDecodeError:
                    item, status = None, 'invalid_encoding'
                if item is None:
                    data['ignored'][status] = data['ignored'].get(status, 0)+1
                    continue
                if any(ipaddress.ip_address(item['source_ip']) in net for net in self.networks):
                    item['source_status'] = 'relay_address'
                items.append(item)
                data['events'] += 1
                data['failure_observations'] += int(eligible(item))
                data['integrity_failures'] += int(item['event_type'] == 'integrity_failure')
            data['offset'] += consumed
            offset = data['offset']
            data['anchor'] = digest(os.pread(self.fd, min(256, offset), max(0, offset-256))) if offset else ''
            if current is not None:
                next_info = os.fstat(current)
                changed = (next_info.st_dev, next_info.st_ino) != identity
                if changed and len(raw) < BATCH and consumed < len(raw):
                    # Never concatenate an incomplete old-inode line with a new file.
                    data['offset'] = os.fstat(self.fd).st_size
                    data['anchor'] = digest(os.pread(self.fd, min(256, data['offset']), max(0, data['offset']-256)))
                    data['ignored']['incomplete_rotated_line'] = data['ignored'].get('incomplete_rotated_line', 0)+1
                    data['continuity_risks'] += 1
            self._save(data, items)
            # Only switch after draining the old descriptor to its observed EOF.
            if current is not None:
                next_info = os.fstat(current)
                changed = (next_info.st_dev, next_info.st_ino) != identity
                if changed and data['offset'] >= os.fstat(self.fd).st_size:
                    claim_source(current)
                    os.close(self.fd);self.fd, current = current, None
                    data.update(dev=next_info.st_dev, ino=next_info.st_ino, offset=0, anchor='', dropping=False)
                    data['rotations'] += 1
                    # EOF is only observed, not proof that every writer reopened.
                    data['continuity_risks'] += 1
                    self._save(data, [])
                    if not _switched:
                        return self.poll(_switched=True)
            return self.status()
        finally:
            if current is not None:
                os.close(current)

    def export(self, target):
        """Create private snapshot; callers must not reacquire overlapping snapshots."""
        target = Path(target)
        if target.parent.resolve()/target.name == self.source.parent.resolve()/self.source.name:
            raise InputError('snapshot_source_conflict')
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError:
            raise InputError('snapshot_create_failed') from None
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                for row in self.db.execute('SELECT payload FROM events ORDER BY seq'):
                    stream.write(row[0]+'\n')
                stream.flush();os.fsync(stream.fileno())
        except OSError:
            raise InputError('snapshot_write_failed') from None


def main(args):
    parser = Parser(description='持久保存 V2bX 脱敏观察样本；不安装服务或防护规则。')
    parser.add_argument('--file', required=True)
    parser.add_argument('--database', required=True)
    parser.add_argument('--core', required=True)
    parser.add_argument('--timezone')
    parser.add_argument('--relay-cidrs', default='')
    parser.add_argument('--unit', default='V2bX.service')
    parser.add_argument('--duration', type=float, default=60)
    parser.add_argument('--poll-interval', type=float, default=.5)
    parser.add_argument('--max-events', type=int, default=100000)
    parser.add_argument('--export')
    observer = None
    try:
        options = parser.parse_args(args)
        if not 0 < options.duration <= 86400 or not .05 <= options.poll_interval <= 60:
            raise InputError('invalid_observation_duration')
        observer = Observer(options.file, options.database, options.core, options.timezone,
                            options.relay_cidrs, options.unit, options.max_events)
        end = time.monotonic()+options.duration
        while True:
            observer.poll()
            remaining = end-time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(options.poll_interval, remaining))
        if options.export:
            observer.export(options.export)
        print(json.dumps(dict(observer.status(), observation_only=True, production_validation='unverified')))
        return 2
    except (InputError, OSError, ValueError, sqlite3.Error):
        print(json.dumps({'status': 'observation_failed', 'observation_only': True}))
        return 1
    except KeyboardInterrupt:
        print(json.dumps({'status': 'interrupted', 'observation_only': True}))
        return 130
    finally:
        if observer is not None:
            observer.close()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

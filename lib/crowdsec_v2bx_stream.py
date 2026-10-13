#!/usr/bin/env python3
"""Incremental publication ledger. Consumer crashes are not exactly-once delivery."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from crowdsec_v2bx_service import private_directory, safe_regular

FIELDS = ('schema_version', 'timestamp', 'time_basis', 'core', 'protocol',
          'event_type', 'source_ip', 'source_status', 'observation_only')


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Publisher:
    def __init__(self, state, databases, output=None, max_bytes=128*1024*1024):
        self.db = self.lock = None
        self.sources = {}
        self.state = Path(state)
        private_directory(self.state)
        self.output = Path(output) if output else self.state/'events.ndjson'
        if not 1 <= len(databases) <= 16 or type(max_bytes) is not int or not 1 <= max_bytes <= 1024*1024*1024:
            raise ValueError('invalid_publisher_options')
        self.max_bytes = max_bytes
        self.before_commit = lambda: None
        try:
            path = self.state/'publisher.sqlite'
            self.lock = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            info = os.fstat(self.lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('unsafe_ledger')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path, timeout=1)
            self.db.execute('PRAGMA synchronous=FULL')
            tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables != {'publication'}:raise ValueError('foreign_ledger')
            self.db.execute('CREATE TABLE IF NOT EXISTS publication (id INTEGER PRIMARY KEY, payload TEXT)')
            identities = {}
            for name, source in databases.items():
                if not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', name):raise ValueError('invalid_source_name')
                source = Path(source).absolute()
                fd = safe_regular(source, private=True)
                info = os.fstat(fd);os.close(fd)
                connection = sqlite3.connect(source.as_uri()+'?mode=ro', uri=True, timeout=1)
                self.sources[name] = (source, connection)
                configuration = connection.execute('SELECT config FROM state WHERE id=1').fetchone()
                if not configuration:raise ValueError('missing_source_contract')
                identities[name] = [str(source), info.st_dev, info.st_ino, configuration[0]]
            previous = self.db.execute('SELECT payload FROM publication WHERE id=1').fetchone()
            if previous:
                self.saved = json.loads(previous[0])
                if self.saved['identities'] != identities or self.saved['output_path'] != str(self.output.absolute()):
                    raise ValueError('source_contract_changed')
                self.recover()
            else:
                # Never take over existing nonempty output or follow a symlink.
                fd = os.open(self.output, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_size or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                        raise ValueError('foreign_output')
                finally:os.close(fd)
                self.saved = dict(identities=identities, cursors={name: 0 for name in identities},
                                  output_path=str(self.output.absolute()), dev=info.st_dev, ino=info.st_ino,
                                  size=0, anchor=digest(b''), pending=None, consumer=None)
                self.save()
        except Exception:
            self.close();raise

    def close(self):
        for _, conn in self.sources.values():conn.close()
        self.sources = {}
        if self.db is not None:self.db.close();self.db = None
        if self.lock is not None:os.close(self.lock);self.lock = None

    def save(self):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO publication VALUES (1,?)', (json.dumps(self.saved),))

    def checked_output(self, pending=False):
        fd = safe_regular(self.output, private=True)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != (self.saved['dev'], self.saved['ino']):
                raise ValueError('output_replaced')
            size = self.saved['size']
            if info.st_size < size or (not pending and info.st_size != size):raise ValueError('output_size_changed')
            anchor = os.pread(fd, min(256, size), max(0, size-256))
            if digest(anchor) != self.saved['anchor']:raise ValueError('output_anchor_changed')
            return info.st_size
        finally:os.close(fd)

    def recover(self, allow_append=False):
        pending = self.saved['pending']
        actual = self.checked_output(pending=bool(pending))
        if not pending:return
        size = self.saved['size']
        data = pending['data'].encode()
        if actual == size:
            if not allow_append:return
            # No bytes reached the consumer; retry the already persisted intent.
            self.append(data)
        elif actual == size+len(data):
            fd = safe_regular(self.output, private=True)
            try:
                written = os.pread(fd, len(data), size)
                if written != data:raise ValueError('pending_output_mismatch')
                os.fsync(fd)
            finally:os.close(fd)
        else:
            raise ValueError('partial_publication_requires_review')
        self.finish(data)

    def finish(self, data):
        pending = self.saved['pending']
        self.saved['size'] += len(data)
        fd = safe_regular(self.output, private=True)
        try:self.saved['anchor'] = digest(os.pread(fd, min(256, self.saved['size']), max(0, self.saved['size']-256)))
        finally:os.close(fd)
        if pending['source'] is not None:self.saved['cursors'][pending['source']] = pending['seq']
        self.saved['pending'] = None
        self.save()

    def append(self, data):
        fd = os.open(self.output, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino, info.st_size) != (self.saved['dev'], self.saved['ino'], self.saved['size']):
                raise ValueError('output_changed_before_append')
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if not count:raise OSError('publication_write_failed')
                view = view[count:]
            os.fsync(fd)
        finally:os.close(fd)

    def write(self, data, source=None, seq=0):
        self.checked_output()
        if self.saved['size']+len(data) > self.max_bytes:raise ValueError('publication_capacity_reached')
        self.saved['pending'] = dict(data=data.decode(), source=source, seq=seq)
        self.save()
        self.append(data)
        self.before_commit()
        self.finish(data)

    def bind_consumer(self, generation):
        if not isinstance(generation, str) or not 1 <= len(generation) <= 128:raise ValueError('invalid_consumer_generation')
        previous = self.saved['consumer']
        if previous is not None and previous != generation:raise ValueError('consumer_changed_requires_review')
        self.saved['consumer'] = generation;self.save()
        self.recover(allow_append=True)

    def probe(self):
        self.write(b'{}\n')

    def publish(self):
        if self.saved['consumer'] is None:raise ValueError('consumer_not_bound')
        if self.saved['pending']:raise ValueError('pending_publication_requires_reopen')
        self.checked_output()
        count = 0
        for name, (path, conn) in self.sources.items():
            fd = safe_regular(path, private=True)
            info = os.fstat(fd);os.close(fd)
            config = conn.execute('SELECT config FROM state WHERE id=1').fetchone()[0]
            if [str(path), info.st_dev, info.st_ino, config] != self.saved['identities'][name]:
                raise ValueError('source_replaced')
            cursor = self.saved['cursors'][name]
            maximum = conn.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]
            if maximum < cursor:raise ValueError('source_history_truncated')
            rows = conn.execute('SELECT seq,payload FROM events WHERE seq>? ORDER BY seq LIMIT 256', (cursor,)).fetchall()
            records = []
            for seq, payload in rows:
                item = json.loads(payload)
                if set(item) != set(FIELDS) or item['observation_only'] is not True or item['schema_version'] != 1:
                    raise ValueError('invalid_projection')
                item['observation_id'] = digest(json.dumps([self.saved['identities'][name], seq], sort_keys=True).encode())
                records.append(json.dumps(item, separators=(',', ':'))+'\n')
            if rows:
                self.write(''.join(records).encode(), name, rows[-1][0]);count += len(rows)
        return count

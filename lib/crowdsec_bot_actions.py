"""Process-local confirmations and private durable audit for bot mutations.

Call ``begin`` successfully before performing an operation. A failed ``begin``
must prevent execution; a failed ``finish`` means the audit is incomplete.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone


class ActionStore:
    """Bind one-use confirmations to an actor, chat and validated operation."""

    def __init__(self, state_dir, token):
        if not isinstance(token, str) or not token:
            raise ValueError('A bot token is required')
        self._state_dir = Path(os.path.abspath(os.fspath(state_dir)))
        self._token = token
        self._namespace = hashlib.sha256(token.encode('utf-8')).hexdigest()[:24]
        self._audit_name = 'bot-actions-' + self._namespace + '.jsonl'
        self._pending_name = 'bot-actions-' + self._namespace + '.pending.json'
        self._offers = {}
        self._lock = threading.RLock()

    @staticmethod
    def _operation(action, params, user, chat):
        if action not in ('ban', 'unban', 'white', 'reload', 'drop_caches'):
            raise ValueError('Unsupported bot action')
        if (type(user) is not int or user <= 0 or type(chat) is not int or chat == 0
                or abs(user) >= 2 ** 63 or abs(chat) >= 2 ** 63):
            raise ValueError('Invalid bot actor or chat')
        if type(params) is not list or any(type(item) is not str for item in params):
            raise ValueError('Invalid bot action parameters')
        if action in ('reload', 'drop_caches'):
            valid_count = len(params) == 0
        else:
            valid_count = len(params) in ((1, 2) if action == 'ban' else (1,))
        if not valid_count:
            raise ValueError('Invalid bot action parameters')
        if params:
            if len(params[0]) > 45 or '%' in params[0]:
                raise ValueError('Invalid bot action address')
            try:
                ipaddress.ip_address(params[0])
            except ValueError:
                raise ValueError('Invalid bot action address') from None
        if len(params) == 2 and (len(params[1]) > 64 or not re.fullmatch(r'(?:[1-9][0-9]*[smh])+', params[1])):
            raise ValueError('Invalid bot action duration')
        return {'action': action, 'params': list(params), 'user': user, 'chat': chat}

    def offer(self, action, params, user, chat, now=None):
        ticket = self._operation(action, params, user, chat)
        current = time.monotonic() if now is None else now
        nonce = secrets.token_urlsafe(16)
        ticket['id'] = secrets.token_hex(16)
        with self._lock:
            self._offers = {key: entry for key, entry in self._offers.items() if entry[0] > current}
            self._offers[nonce] = (current + 60, ticket)
        return nonce

    def take(self, nonce, user, chat, now=None):
        current = time.monotonic() if now is None else now
        with self._lock:
            if type(nonce) is not str:
                return None
            entry = self._offers.get(nonce)
            if entry is None:
                return None
            expires, ticket = entry
            if current >= expires:
                del self._offers[nonce]
                return None
            if type(user) is not int or type(chat) is not int or (user, chat) != (ticket['user'], ticket['chat']):
                return None
            del self._offers[nonce]
            return dict(ticket, params=list(ticket['params']))

    def cancel(self, nonce, user, chat, now=None):
        return self.take(nonce, user, chat, now=now) is not None

    @classmethod
    def _ticket(cls, ticket):
        if (type(ticket) is not dict or set(ticket) != {'id', 'action', 'params', 'user', 'chat'}
                or type(ticket['id']) is not str or not re.fullmatch(r'[0-9a-f]{32}', ticket['id'])):
            raise ValueError('Invalid bot action ticket')
        return dict(cls._operation(ticket['action'], ticket['params'], ticket['user'], ticket['chat']),
                    id=ticket['id'])

    @staticmethod
    def _timestamp():
        return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

    @contextmanager
    def _directory(self, create=False):
        """Walk using directory descriptors so no path component follows a link."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open('/', flags)
        try:
            for component in self._state_dir.parts[1:]:
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        yield None
                        return
                    try:
                        os.mkdir(component, 0o700, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or (not create and stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError('Bot audit directory must be private and owned by the current user')
            if create:
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
            yield descriptor
        finally:
            os.close(descriptor)

    @staticmethod
    def _check_file(directory, name):
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError('Bot audit paths must be regular private files')
        return info

    def _open_file(self, directory, name, flags):
        descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
                raise ValueError('Bot audit paths must be regular private files')
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _validate_files(self, directory):
        names = [self._audit_name, self._pending_name]
        names.extend(self._audit_name + '.' + str(number) for number in range(1, 4))
        for name in names:
            self._check_file(directory, name)

    def _load_pending(self, directory):
        if self._check_file(directory, self._pending_name) is None:
            return []
        descriptor = self._open_file(directory, self._pending_name, os.O_RDONLY)
        with os.fdopen(descriptor, 'rb') as source:
            content = source.read(16 * 1024 * 1024 + 1)
        if len(content) > 16 * 1024 * 1024:
            raise ValueError('Bot audit state exceeds its size limit')
        try:
            state = json.loads(content)
            if (type(state) is not dict or set(state) != {'version', 'started'}
                    or type(state['version']) is not int or state['version'] != 1
                    or type(state['started']) is not list):
                raise ValueError
            entries = []
            seen = set()
            for entry in state['started']:
                if type(entry) is not dict or 'timestamp' not in entry:
                    raise ValueError
                ticket = self._ticket({key: value for key, value in entry.items() if key != 'timestamp'})
                timestamp = entry['timestamp']
                if type(timestamp) is not str or len(timestamp) > 40:
                    raise ValueError
                parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0 or ticket['id'] in seen:
                    raise ValueError
                seen.add(ticket['id'])
                entries.append(dict(ticket, timestamp=timestamp))
            return entries
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise ValueError('Invalid bot audit state') from None

    @staticmethod
    def _write_all(descriptor, content):
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError('Unable to write bot audit')
            remaining = remaining[written:]

    def _save_pending(self, directory, entries):
        content = (json.dumps({'version': 1, 'started': entries}, ensure_ascii=True,
                              separators=(',', ':')) + '\n').encode('utf-8')
        if len(content) > 16 * 1024 * 1024:
            raise ValueError('Bot audit state exceeds its size limit')
        self._check_file(directory, self._pending_name)
        temporary = '.bot-actions-' + self._namespace + '-' + secrets.token_hex(8) + '.tmp'
        descriptor = self._open_file(directory, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.fchmod(descriptor, 0o600)
            self._write_all(descriptor, content)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            self._check_file(directory, self._pending_name)
            os.replace(temporary, self._pending_name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    def _append(self, directory, record):
        content = (json.dumps(record, ensure_ascii=True, separators=(',', ':')) + '\n').encode('utf-8')
        self._validate_files(directory)
        current = self._check_file(directory, self._audit_name)
        if current is not None and current.st_size + len(content) > 1024 * 1024:
            last = self._audit_name + '.3'
            if self._check_file(directory, last) is not None:
                os.unlink(last, dir_fd=directory)
            for number in (2, 1, 0):
                source = self._audit_name + ('.' + str(number) if number else '')
                if self._check_file(directory, source) is not None:
                    os.replace(source, self._audit_name + '.' + str(number + 1),
                               src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        descriptor = self._open_file(directory, self._audit_name, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        try:
            os.fchmod(descriptor, 0o600)
            self._write_all(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)

    def begin(self, ticket):
        """Persist the start before execution; any failure must stop the caller."""
        ticket = self._ticket(ticket)
        with self._lock, self._directory(create=True) as directory:
            self._validate_files(directory)
            pending = self._load_pending(directory)
            if any(entry['id'] == ticket['id'] for entry in pending):
                raise ValueError('Bot action has already started')
            entry = dict(ticket, timestamp=self._timestamp())
            # Save first so an interrupted append can never hide an uncertain action.
            self._save_pending(directory, pending + [entry])
            self._append(directory, dict(entry, event='started'))

    def finish(self, ticket, outcome, message):
        """Record a safe caller-provided summary, retaining pending on failure."""
        ticket = self._ticket(ticket)
        if outcome not in ('success', 'failed', 'unknown') or type(message) is not str:
            raise ValueError('Invalid bot audit result')
        message = message.replace(self._token, '[redacted]')
        message = ' '.join(''.join(character if character.isprintable() else ' '
                                   for character in message).split())[:256]
        with self._lock, self._directory() as directory:
            if directory is None:
                raise ValueError('Bot action has not started')
            pending = self._load_pending(directory)
            matches = [entry for entry in pending if entry['id'] == ticket['id']]
            if not matches or {key: matches[0][key] for key in ticket} != ticket:
                raise ValueError('Bot action has not started or ticket changed')
            self._append(directory, dict(ticket, event='finished', timestamp=self._timestamp(),
                                         outcome=outcome, message=message))
            if outcome == 'unknown':
                return
            remaining = [entry for entry in pending if entry['id'] != ticket['id']]
            try:
                self._save_pending(directory, remaining)
            except (OSError, ValueError):
                # A failed final-state sync remains uncertain, even if its rename ran.
                try:
                    self._save_pending(directory, pending)
                except (OSError, ValueError):
                    pass
                raise

    def unfinished(self):
        """Read recent uncertain starts without creating or modifying any paths."""
        with self._lock, self._directory() as directory:
            if directory is None:
                return []
            return list(reversed(self._load_pending(directory)[-5:]))

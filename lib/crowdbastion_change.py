#!/usr/bin/env python3
"""Guarded, journaled compare-and-swap changes; adapters never execute JSON code.

Lock order: maintenance (including inherited shell fd 9), then state .lock.
Recovery deliberately does not sample environment pressure.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from crowdbastion_environment import require_stable
from crowdbastion_ux import read_regular, validate_private_destination

ROOT = Path('/var/lib/crowdbastion/changes')
LOCK = Path('/run/lock/crowdsec-1key.lock')
HELPERS = ('crowdbastion_change.py', 'crowdbastion_port_policy.py', 'crowdbastion_environment.py',
           'crowdbastion_node.py', 'crowdbastion_ux.py')
TERMINAL = ('committed', 'rolled_back')


class ChangeRefused(ValueError):
    """Finite, credential-free integration detail; remains ValueError-compatible."""
    def __init__(self, code, kind=None):
        self.report = {'version': 1, 'state': 'refused', 'error_code': code}
        if kind in ('network', 'port-policy'): self.report['pending_kind'] = kind
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def atomic(path, data, mode=0o600):
    """Durable publication under an already trusted directory; never follow links."""
    path = Path(path); validate_private_destination(path)
    fd, temporary = tempfile.mkstemp(prefix='.change-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode); stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def json_read(path):
    validate_private_destination(Path(path))
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    return json.loads(read_regular(Path(path)), object_pairs_hook=unique)


def private_profile_read(path):
    """Operator profiles require privacy on the descriptor actually consumed.

    Keep json_read permissive for intentional public state/configuration files.
    """
    path = Path(path)
    validate_private_destination(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        maximum = 8 * 1024 * 1024
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > maximum):
            raise ValueError('unsafe private profile')
        data = stream.read(maximum + 1)
        if len(data) > maximum: raise ValueError('private profile grew too large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def initialize(root):
    root = Path(root)
    validate_private_destination(root/'.probe', missing_parents=True)
    if root.exists():
        if not (root/'.crowdbastion-managed').exists(): raise ValueError('unowned state')
        if json_read(root/'.crowdbastion-managed') != {'version': 1}: raise ValueError('unowned state')
        if root.stat().st_mode & 0o077: raise ValueError('state is not private')
    else:
        root.mkdir(mode=0o700, parents=True)
        atomic(root/'.crowdbastion-managed', canonical({'version': 1}))


def _lock_info(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
            info.st_mode & 0o022 or info.st_nlink != 1):
        raise ValueError('unsafe lock')


def open_lock(path):
    """Create/open an owned single-link lock without truncation or following links."""
    path = Path(path)
    validate_private_destination(path, missing_parents=True, allow_sticky_parent=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_private_destination(path, allow_sticky_parent=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd); _lock_info(info)
        target = path.lstat(); _lock_info(target)
        if (info.st_dev, info.st_ino) != (target.st_dev, target.st_ino): raise ValueError('lock replaced')
        return fd
    except BaseException:
        os.close(fd); raise


def check_lock_fd(path, fd):
    """Validate a shell-owned fd and acquire flock on that same description."""
    if type(fd) is not int or fd < 3: raise ValueError('invalid lock descriptor')
    probe = open_lock(path)
    try:
        info = os.fstat(fd); _lock_info(info)
        target = os.fstat(probe)
        if (info.st_dev, info.st_ino) != (target.st_dev, target.st_ino): raise ValueError('wrong lock descriptor')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally: os.close(probe)


@contextmanager
def maintenance_lock(path=LOCK):
    path = Path(path)
    validate_private_destination(path, missing_parents=True, allow_sticky_parent=True)
    inherited = False
    if os.environ.get('MAINTENANCE_LOCK_HELD') == 'true':
        try:
            info = os.fstat(9); target = path.lstat()
            inherited = (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino)
        except OSError: pass
    if inherited:
        # Shared open-file description; never unlock the parent's ownership.
        check_lock_fd(path, 9)
        yield
    else:
        fd = open_lock(path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally: os.close(fd)


@contextmanager
def state_lock(root):
    with maintenance_lock(Path(root)/'.lock'):
        yield


def file_state(path):
    path = Path(path); validate_private_destination(path, missing_parents=True)
    if not path.exists(): return None
    info = path.lstat()
    return {'content': base64.b64encode(read_regular(path)).decode(), 'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid}


def file_value(text, mode=0o600):
    return {'content': base64.b64encode(text.encode()).decode(), 'mode': mode,
            'uid': os.geteuid(), 'gid': os.getegid()}


def write_file(path, before, after):
    path = Path(path)
    if file_state(path) != before: raise ValueError('file drift')
    if after is None:
        if before is not None:
            path.unlink()
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
    else:
        validate_private_destination(path, missing_parents=True)
        path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        atomic(path, base64.b64decode(after['content'], validate=True), after['mode'])
        os.chown(path, after['uid'], after['gid'])


class SystemdScheduler:
    """Persistent wall-clock deadline plus retries; no shell or transient session."""
    def __init__(self, unit_dir=Path('/etc/systemd/system'), run=None):
        self.unit_dir = Path(unit_dir); self.run = run or command
    def paths(self, ident):
        if not re.fullmatch(r'[0-9a-f]{32}', ident): raise ValueError('invalid transaction id')
        return [self.unit_dir/f'crowdbastion-change-{ident}.{suffix}' for suffix in ('service', 'timer')]
    def arm(self, root, ident, runtime, deadline):
        service, timer = self.paths(ident)
        for path in (root, runtime):
            if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)): raise ValueError('unsafe runtime path')
        calendar = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(deadline))
        values = [f'[Unit]\nDescription=CrowdBastion guarded rollback\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {runtime}/crowdbastion_change.py rollback --root {root} --id {ident}\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n',
                  f'[Unit]\nDescription=CrowdBastion guarded rollback deadline\n[Timer]\nOnCalendar={calendar}\nOnUnitInactiveSec=60s\nPersistent=true\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n']
        for path in (service, timer):
            validate_private_destination(path)
            if path.exists(): raise ValueError('timer ownership conflict')
        for path, text in zip((service, timer), values): atomic(path, text.encode(), 0o644)
        self.run(['systemctl', 'daemon-reload'])
        self.run(['systemctl', 'enable', '--now', timer.name])
        self.run(['systemctl', 'is-active', '--quiet', timer.name])
    def disarm(self, ident):
        service, timer = self.paths(ident)
        self.run(['systemctl', 'disable', '--now', timer.name])
        # Keep owned units as an audit trail. Terminal journal state makes late
        # queued activation harmless, including a timer already executing.


def command(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, timeout=15, check=False)
    if result.returncode: raise ValueError('host command failed')
    if len(result.stdout) > 8 * 1024 * 1024: raise ValueError('host output too large')
    return result.stdout


class Engine:
    """Adapter contract: read(resource), write(resource,before,after), verify(metadata).

    Every effect is {resource: fixed typed identity, before: JSON value, after:
    JSON value}. Writes must perform one reversible operation and compare first.
    `verify` must independently observe the adapter's resulting effective state.
    """
    def __init__(self, root, adapter, *, scheduler=None, guard=require_stable, lock_path=LOCK):
        self.root = Path(root); self.adapter = adapter
        self.scheduler = scheduler or SystemdScheduler(); self.guard = guard; self.lock_path = Path(lock_path)
    def _tx(self, ident):
        if not isinstance(ident, str) or not re.fullmatch(r'[0-9a-f]{32}', ident): raise ValueError('invalid transaction')
        return self.root/ident
    def _load(self, ident):
        tx = self._tx(ident)
        manifest = json_read(tx/'manifest.json'); journal = json_read(tx/'journal.json')
        if hashlib.sha256(canonical(manifest)).hexdigest() != journal['manifest_sha256']:
            raise ValueError('manifest changed')
        for name, digest in manifest['runtime'].items():
            validate_private_destination(tx/'runtime'/name)
            if name != Path(name).name or hashlib.sha256(read_regular(tx/'runtime'/name)).hexdigest() != digest:
                raise ValueError('runtime changed')
        return manifest, journal
    def _save(self, ident, journal): atomic(self._tx(ident)/'journal.json', canonical(journal))
    def _report(self, ident, journal, state=None):
        return {'version': 1, 'id': ident, 'kind': json_read(self._tx(ident)/'manifest.json')['kind'], 'state': state or journal['state'],
                'errors': list(journal.get('errors', [])), 'deadline': journal['deadline'],
                'error_code': journal.get('failure_code')}
    def status(self, ident=None):
        if ident is None:
            if not self.root.exists(): return {'version': 1, 'state': 'absent', 'transactions': []}
            validate_private_destination(self.root/'.crowdbastion-managed')
            if json_read(self.root/'.crowdbastion-managed') != {'version': 1} or self.root.stat().st_mode & 0o077:
                raise ValueError('unowned state')
            ids = sorted(p.name for p in self.root.iterdir() if re.fullmatch(r'[0-9a-f]{32}', p.name))
            return {'version': 1, 'transactions': [self.status(i) for i in ids]}
        tx = self._tx(ident)
        if not (tx/'journal.json').exists():
            validate_private_destination(tx/'journal.json')
            return {'version': 1, 'id': ident, 'state': 'preparation_incomplete'}
        _, journal = self._load(ident); return self._report(ident, journal)
    def select(self, kind, ident=None):
        """Select only this command's kind, including explicit terminal IDs."""
        if kind not in ('network', 'port-policy'): raise ValueError('invalid change kind')
        if ident is not None:
            row = self.status(ident)
            if row.get('kind') != kind: raise ChangeRefused('transaction_kind_mismatch')
            return ident
        candidates = [row for row in self.status().get('transactions', [])
                      if row['state'] not in (*TERMINAL, 'preparation_incomplete')]
        if len(candidates) != 1 or candidates[0].get('kind') != kind:
            if len(candidates) == 1: raise ChangeRefused('pending_change', candidates[0].get('kind'))
            raise ChangeRefused('transaction_selection_ambiguous')
        return candidates[0]['id']

    def apply(self, kind, effects, *, metadata=None, runtime_files=(), timeout=900, prepare=None):
        if kind not in ('port-policy', 'network') or type(timeout) is not int or not 60 <= timeout <= 3600:
            raise ValueError('invalid change')
        with maintenance_lock(self.lock_path):
            self.guard()  # Must precede backups, runtime publication and writes.
            initialize(self.root)
            with state_lock(self.root):
                for row in self.status().get('transactions', []):
                    if row['state'] not in (*TERMINAL, 'preparation_incomplete'): raise ChangeRefused('pending_change', row.get('kind'))
                ident = uuid.uuid4().hex; tx = self._tx(ident); runtime = tx/'runtime'
                if prepare is not None: effects, metadata = prepare(runtime)
                if hasattr(self.adapter, 'preflight'): self.adapter.preflight(metadata or {})
                # Validate the entire observed preimage, accounting for effects
                # that intentionally touch the same resource more than once.
                expected = {}
                for effect in effects:
                    if set(effect) != {'resource', 'before', 'after'}: raise ValueError('invalid effect')
                    key = canonical(effect['resource'])
                    live = expected[key] if key in expected else self.adapter.read(effect['resource'])
                    if live != effect['before']: raise ValueError('preimage drift')
                    expected[key] = effect['after']
                tx.mkdir(mode=0o700)
                runtime.mkdir(mode=0o700)
                sources = [Path(__file__).parent/name for name in HELPERS] + [Path(p) for p in runtime_files]
                hashes = {}
                for source in sources:
                    if source.name in hashes: continue
                    data = read_regular(source); atomic(runtime/source.name, data)
                    hashes[source.name] = hashlib.sha256(data).hexdigest()
                deadline = int(time.time()) + timeout
                manifest = {'version': 1, 'id': ident, 'kind': kind, 'effects': effects,
                            'metadata': metadata or {}, 'runtime': hashes}
                manifest_data = canonical(manifest)
                if len(manifest_data) > 8 * 1024 * 1024: raise ValueError('manifest too large')
                atomic(tx/'manifest.json', manifest_data, 0o400)
                journal = {'version': 1, 'state': 'arming', 'deadline': deadline,
                           'manifest_sha256': hashlib.sha256(canonical(manifest)).hexdigest(),
                           'items': ['planned'] * len(effects), 'errors': []}
                self._save(ident, journal)
                directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(directory)
                finally: os.close(directory)
                try:
                    self.scheduler.arm(self.root, ident, runtime, deadline)
                    journal['state'] = 'applying'; self._save(ident, journal)
                    for index, effect in enumerate(effects):
                        journal['items'][index] = 'started'; self._save(ident, journal)
                        self.adapter.write(effect['resource'], effect['before'], effect['after'])
                        if self.adapter.read(effect['resource']) != effect['after']: raise ValueError('postimage mismatch')
                        journal['items'][index] = 'done'; self._save(ident, journal)
                    journal['state'] = 'staged'; self._save(ident, journal)
                    return self._report(ident, journal)
                except (ValueError, OSError, subprocess.SubprocessError):
                    journal['failure_code'] = 'apply_failed'; journal['errors'] = ['apply_failed']; self._save(ident, journal)
                    return self._rollback(ident, manifest, journal)
    def _verify(self, manifest):
        final = {}
        for effect in manifest['effects']: final[canonical(effect['resource'])] = effect
        try:
            return (all(self.adapter.read(e['resource']) == e['after'] for e in final.values()) and
                    self.adapter.verify(manifest['metadata']) is True)
        except (ValueError, OSError, subprocess.SubprocessError): return False
    def verify(self, ident):
        with maintenance_lock(self.lock_path), state_lock(self.root):
            manifest, journal = self._load(ident)
            if journal['state'] in TERMINAL: return self._report(ident, journal)
            if journal['state'] not in ('staged', 'verified'): return self._report(ident, journal, 'verification_failed')
            if not self._verify(manifest): return self._report(ident, journal, 'verification_failed')
            journal['state'] = 'verified'; self._save(ident, journal)
            return self._report(ident, journal)
    def commit(self, ident):
        with maintenance_lock(self.lock_path), state_lock(self.root):
            manifest, journal = self._load(ident)
            if journal['state'] in TERMINAL: return self._report(ident, journal)
            if journal['state'] not in ('staged', 'verified'):
                return self._report(ident, journal, 'verification_failed')
            if time.time() >= journal['deadline']:
                return dict(self._report(ident, journal, 'verification_failed'), refusal_code='transaction_expired')
            if not self._verify(manifest):
                return self._report(ident, journal, 'verification_failed')
            # Independent external reads can cross expiry while holding the
            # lock. Keep recovery eligible if verification consumed the budget.
            if time.time() >= journal['deadline']:
                return dict(self._report(ident, journal, 'verification_failed'), refusal_code='transaction_expired')
            # Persist terminal state before touching the timer: a queued rollback
            # must see committed after obtaining these same locks.
            journal['state'] = 'committed'; journal['errors'] = []; self._save(ident, journal)
            self._disarm(ident, journal)
            return self._report(ident, journal)
    def _disarm(self, ident, journal):
        try: self.scheduler.disarm(ident)
        except (ValueError, OSError, subprocess.SubprocessError):
            journal['errors'].append('timer_cleanup_failed'); self._save(ident, journal)
    def _rollback(self, ident, manifest, journal):
        if journal['state'] in TERMINAL: return self._report(ident, journal)
        journal['state'] = 'rolling_back'; journal['errors'] = []; self._save(ident, journal)
        unresolved_resources = set()
        for index in reversed(range(len(manifest['effects']))):
            if journal['items'][index] in ('planned', 'reverted'): continue
            effect = manifest['effects'][index]
            resource_key = canonical(effect['resource'])
            if resource_key in unresolved_resources: continue
            try:
                live = self.adapter.read(effect['resource'])
                if live == effect['after']:
                    self.adapter.write(effect['resource'], effect['after'], effect['before'])
                    if self.adapter.read(effect['resource']) != effect['before']: raise ValueError('rollback mismatch')
                elif live != effect['before']: raise ValueError('rollback drift')
                journal['items'][index] = 'reverted'; self._save(ident, journal)
            except (ValueError, OSError, subprocess.SubprocessError):
                # A later inverse may have succeeded before its post-read or
                # journal failed. Do not move this resource further backwards
                # until retry can settle that uncertain effect. Independent
                # resources must still recover in this pass.
                unresolved_resources.add(resource_key)
                journal['errors'].append({'index': index, 'error_code': 'rollback_item_refused'})
        journal['state'] = 'rollback_incomplete' if journal['errors'] else 'rolled_back'
        self._save(ident, journal)
        if journal['state'] == 'rolled_back': self._disarm(ident, journal)
        return self._report(ident, journal)
    def rollback(self, ident):
        with maintenance_lock(self.lock_path), state_lock(self.root):
            manifest, journal = self._load(ident)
            return self._rollback(ident, manifest, journal)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'verify', 'commit', 'rollback', 'lock-prepare', 'lock-check'))
    parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--id')
    parser.add_argument('--lock-path', type=Path); parser.add_argument('--fd', type=int)
    args = parser.parse_args(argv)
    if os.geteuid() != 0: raise ValueError('root required')
    if args.action in ('lock-prepare', 'lock-check'):
        if args.lock_path is None: raise ValueError('lock path required')
        if args.action == 'lock-prepare': os.close(open_lock(args.lock_path))
        else: check_lock_fd(args.lock_path, args.fd)
        return 0
    # Fixed adapter selection only. Manifests never contain command strings.
    if args.id and not re.fullmatch(r'[0-9a-f]{32}', args.id): raise ValueError('invalid transaction')
    manifest = json_read(args.root/args.id/'manifest.json') if args.id else None
    if manifest and manifest['kind'] == 'network':
        from crowdbastion_network import transaction_adapter
    else:
        from crowdbastion_port_policy import transaction_adapter
    engine = Engine(args.root, transaction_adapter(args.root))
    if args.action != 'status' and not args.id: raise ValueError('transaction required')
    result = getattr(engine, args.action)(args.id)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('state') not in ('verification_failed', 'rollback_incomplete') else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except BlockingIOError:
        print(json.dumps({'version': 1, 'state': 'refused', 'error_code': 'change_busy', 'retryable': True})); sys.exit(75)
    except (ValueError, OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError):
        print(json.dumps({'version': 1, 'state': 'refused', 'error_code': 'change_refused'})); sys.exit(1)

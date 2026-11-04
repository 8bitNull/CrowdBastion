"""Remove only VPS179's three unchanged observation/journal-cap files.

Usage: python3 rollback.py /var/backups/crowdbastion/vps179-realm-opt-TIMESTAMP
The backup is a root-private trust boundary. Run as root under the maintenance
lock; concurrent root operators must respect that lock. No firewall, decision,
ForwardX, realm or Bouncer configuration is restored or changed.
SIGTERM/SIGHUP/SIGINT request recovery; further requests are ignored while it
finishes. SIGKILL and power loss cannot be recovered by a running script.
"""
from pathlib import Path
import fcntl
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time


OWNED = (
    '/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml',
    '/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml',
    '/etc/systemd/journald.conf.d/60-crowdbastion-storage-cap.conf',
)
UNITS = ('systemd-journald', 'crowdsec')
CANCEL_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


class Cancelled(BaseException):
    """Cancellation must escape command retries and enter file recovery."""


def protect_recovery():
    for signum in CANCEL_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def cancel(signum, frame):
    protect_recovery()
    raise Cancelled('cancelled by signal ' + str(signum))


def directory_chain(path, allow_sticky=False):
    """Reject symlink/writable ancestors and remember their identities."""
    result = []
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        sticky_lock_dir = allow_sticky and parent == path and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                (info.st_mode & 0o022 and not sticky_lock_dir)):
            raise RuntimeError('unsafe directory: ' + str(parent))
        result.append((str(parent), info.st_dev, info.st_ino, info.st_mode, info.st_gid))
    return result


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, parent_fd=None, deployment=False):
    fd = os.open(path.name if parent_fd is not None else path,
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or info.st_mode & 0o022 or
                (deployment and stat.S_IMODE(info.st_mode) != 0o644)):
            raise RuntimeError('unsafe file ownership/type/mode: ' + str(path))
        data = source.read()
        if fingerprint(os.fstat(source.fileno())) != fingerprint(info):
            raise RuntimeError('file changed while reading: ' + str(path))
    return data, info


def check_parent(item):
    if directory_chain(item['path'].parent) != item['parents']:
        raise RuntimeError('parent changed: ' + str(item['path']))
    info = os.fstat(item['parent_fd'])
    if (info.st_dev, info.st_ino) != item['parents'][-1][1:3]:
        raise RuntimeError('parent changed while opening: ' + str(item['path']))


def run(args):
    process = subprocess.run(args, capture_output=True, text=True, timeout=55)
    if process.returncode:
        raise RuntimeError(str(args) + ': ' + process.stderr[-1000:])


def detection_ready():
    # LAPI may need a short interval after restart. No events/metrics required.
    deadline = time.monotonic() + 20
    while True:
        try:
            run(['cscli', 'lapi', 'status'])
            return
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def restore(item):
    check_parent(item)
    path, parent_fd = item['path'], item['parent_fd']
    # O_EXCL also refuses dangling symlinks or externally recreated files.
    fd = os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(item['data'])
            out.flush()
            os.fchown(out.fileno(), item['info'].st_uid, item['info'].st_gid)
            os.fchmod(out.fileno(), stat.S_IMODE(item['info'].st_mode))
            os.fsync(out.fileno())
        check_parent(item)
    except BaseException:
        # Remove only our partial restore, never a replacement made by others.
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
            os.unlink(path.name, dir_fd=parent_fd)
        raise


def rollback(base):
    if base.parent != Path('/var/backups/crowdbastion') or not base.name.startswith('vps179-realm-opt-'):
        raise RuntimeError('unexpected backup path')
    directory_chain(base)
    if base.lstat().st_mode & 0o077:
        raise RuntimeError('backup must be root-private')
    manifest_data, _ = read_file(base / 'apply-result.json')
    manifest = json.loads(manifest_data)
    expected = manifest.get('new_files')
    if manifest.get('status') != 'applied' or not isinstance(expected, dict) or set(expected) != set(OWNED):
        raise RuntimeError('manifest must describe exactly the three applied deployment files')
    for digest in expected.values():
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise RuntimeError('invalid deployment digest')

    items, removed = [], []
    try:
        for name in OWNED:
            path = Path(name)
            parents = directory_chain(path.parent)
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            item = {'path': path, 'parents': parents, 'parent_fd': parent_fd}
            items.append(item)
            check_parent(item)
            data, info = read_file(path, parent_fd, deployment=True)
            if hashlib.sha256(data).hexdigest() != expected[name]:
                raise RuntimeError('refuse modified file: ' + name)
            item.update(data=data, info=info)

        try:
            for item in items:
                check_parent(item)
                data, info = read_file(item['path'], item['parent_fd'], deployment=True)
                if data != item['data'] or fingerprint(info) != fingerprint(item['info']):
                    raise RuntimeError('file changed after validation: ' + str(item['path']))
                # Deliver cancellation only after recording a successful unlink.
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL_SIGNALS)
                try:
                    os.unlink(item['path'].name, dir_fd=item['parent_fd'])
                    removed.append(item)
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            run(['crowdsec', '-t'])
            for unit in UNITS:
                run(['systemctl', 'restart', unit])
                run(['systemctl', 'is-active', unit])
            detection_ready()
        except BaseException as error:
            protect_recovery()
            errors = []
            for item in removed:
                try:
                    restore(item)
                except Exception as restore_error:
                    errors.append(str(item['path']) + ': ' + str(restore_error))
            # Each operation is independent: one failure must not skip the rest.
            for args in ([['crowdsec', '-t']] +
                         [['systemctl', verb, unit] for unit in UNITS
                          for verb in ('restart', 'is-active')]):
                try:
                    run(args)
                except Exception as recovery_error:
                    errors.append(str(recovery_error))
            try:
                detection_ready()
            except Exception as readiness_error:
                errors.append(str(readiness_error))
            print(json.dumps({'status': 'rollback_failed', 'error': str(error),
                              'restore_errors': errors}), file=sys.stderr)
            return 1
        print(json.dumps({'status': 'rolled_back', 'removed': list(OWNED),
                          'services_active': list(UNITS), 'lapi_ready': True}))
        return 0
    finally:
        for item in items:
            os.close(item['parent_fd'])


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise RuntimeError('run as root with exactly one backup path')
    # Root-owned sticky /run/lock (1777) is standard on some distributions.
    directory_chain(Path('/run/lock'), allow_sticky=True)
    fd = os.open('/run/lock/crowdsec-1key.lock', os.O_CREAT | os.O_RDWR |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise RuntimeError('unsafe maintenance lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for signum in CANCEL_SIGNALS:
            signal.signal(signum, cancel)
        return rollback(Path(sys.argv[1]))
    finally:
        os.close(fd)


if __name__ == '__main__':
    # Do not inherit an executable search path from the caller.
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    try:
        sys.exit(main())
    except (Exception, Cancelled) as error:
        print(json.dumps({'status': 'refused', 'error': str(error)}), file=sys.stderr)
        sys.exit(1)

"""One-time guarded sysctl persistence repair; baseline is injected by client."""
from pathlib import Path
import datetime
import fcntl
import hashlib
import json
import os
import signal
import stat
import subprocess
import tempfile


TARGET = Path('/etc/sysctl.d/99-network-optimize.conf')
LOCK = Path('/run/lock/crowdsec-1key.lock')
SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=20)
    return {'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}


def values():
    return {key: (Path('/proc/sys') / key.replace('.', '/')).read_text().strip()
            for key in EXPECTED['sysctl_values']}


def protected():
    return {name: digest(Path(name).read_bytes()) for name in EXPECTED['protected_hashes']}


def safe_file(path, expected_mode=None):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o022 or expected_mode is not None and stat.S_IMODE(info.st_mode) != expected_mode):
        raise RuntimeError('unsafe owned file: ' + str(path))
    return info


def replace_owned(data, expected_hash, mode):
    target_info = safe_file(TARGET, mode)
    if digest(TARGET.read_bytes()) != expected_hash:
        raise RuntimeError('source changed; refusing replacement')
    fd, temporary = tempfile.mkstemp(prefix='.crowdbastion-sysctl-', dir=TARGET.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.fchown(stream.fileno(), target_info.st_uid, target_info.st_gid)
            os.fchmod(stream.fileno(), mode)
        safe_file(TARGET, mode)
        if digest(TARGET.read_bytes()) != expected_hash:
            raise RuntimeError('source changed before atomic replacement')
        os.replace(temporary, TARGET)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    os.umask(0o077)
    for directory in [Path('/'), Path('/etc'), TARGET.parent, Path('/run')]:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('unsafe parent: ' + str(directory))
    info = LOCK.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
        raise RuntimeError('unsafe lock parent')
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        opened = os.fstat(fd)
        safe_file(LOCK)
        current = LOCK.lstat()
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError('lock replaced')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if digest(TARGET.read_bytes()) != EXPECTED['source_hash']:
            raise RuntimeError('baseline source changed')
        info = safe_file(TARGET, 0o644)
        before = TARGET.read_bytes()
        old = b'net.core.netdev_budget_usecs = 6000\n'
        new = b'net.core.netdev_budget_usecs = 8000\n'
        if before.count(old) != 1:
            raise RuntimeError('expected one exact assignment')
        after = before.replace(old, new, 1)
        if values() != EXPECTED['sysctl_values'] or protected() != EXPECTED['protected_hashes']:
            raise RuntimeError('runtime or protected configuration drift')
        if EXPECTED['sysctl_values']['net.core.netdev_budget_usecs'] != '8000':
            raise RuntimeError('runtime target no longer 8000')
        stack = command(['/lib/systemd/systemd-sysctl', '--cat-config', '--no-pager'])
        if stack['exit'] != 0 or digest(stack['stdout'].encode()) != EXPECTED['effective_config_before']['sha256']:
            raise RuntimeError('effective sysctl configuration changed')
        root = Path('/var/backups/crowdbastion')
        root.mkdir(mode=0o700, exist_ok=True)
        for parent in [root, *root.parents]:
            info_parent = parent.lstat()
            if not stat.S_ISDIR(info_parent.st_mode) or info_parent.st_uid != 0 or info_parent.st_mode & 0o022:
                raise RuntimeError('unsafe backup parent')
        backup = Path(tempfile.mkdtemp(prefix='vps82-sysctl-review-', dir=root))
        (backup / 'source-before.conf').write_bytes(before)
        (backup / 'baseline.json').write_text(json.dumps(EXPECTED, indent=2) + '\n')
        result = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'backup': str(backup),
                  'target': str(TARGET), 'before_sha256': digest(before), 'after_sha256': digest(after),
                  'original_mode': oct(stat.S_IMODE(info.st_mode)), 'original_uid': info.st_uid,
                  'original_gid': info.st_gid, 'runtime_before': values(), 'service_restarts': [],
                  'known_failure_before': EXPECTED['known_failure_before']}
        intended = False
        cancelled = False
        recovering = False

        def interrupted(number, frame):
            nonlocal cancelled
            if not cancelled and not recovering:
                cancelled = True
                raise InterruptedError('cancelled: ' + str(number))

        handlers = {s: signal.getsignal(s) for s in SIGNALS}
        try:
            for number in SIGNALS:
                signal.signal(number, interrupted)
            intended = True
            replace_owned(after, digest(before), stat.S_IMODE(info.st_mode))
            invocation = ['/lib/systemd/systemd-sysctl', '--prefix=/net/core/netdev_budget_usecs']
            result['targeted_command'] = invocation
            result['targeted_apply'] = command(invocation)
            if result['targeted_apply']['exit'] != 0:
                raise RuntimeError('targeted application failed')
            result['runtime_after'] = values()
            if result['runtime_after'] != result['runtime_before']:
                raise RuntimeError('observed sysctl drift')
            if protected() != EXPECTED['protected_hashes']:
                raise RuntimeError('protected files changed')
            if TARGET.read_bytes() != after:
                raise RuntimeError('candidate file changed')
            stack = command(['/lib/systemd/systemd-sysctl', '--cat-config', '--no-pager'])
            normalized = stack['stdout'].replace(new.decode(), old.decode(), 1)
            if stack['exit'] != 0 or digest(normalized.encode()) != EXPECTED['effective_config_before']['sha256']:
                raise RuntimeError('unrelated effective sysctl configuration changed')
            result['effective_config_after_sha256'] = digest(stack['stdout'].encode())
            result['status'] = 'applied_and_verified'
        except BaseException as error:
            recovering = True
            for number in SIGNALS:
                signal.signal(number, signal.SIG_IGN)
            result['status'] = 'failed'
            result['error'] = type(error).__name__ + ': ' + str(error)
            if intended:
                live_hash = digest(TARGET.read_bytes())
                if live_hash == digest(after):
                    replace_owned(before, live_hash, stat.S_IMODE(info.st_mode))
                    result['rollback'] = 'original_file_restored'
                elif live_hash == digest(before):
                    result['rollback'] = 'original_file_already_present'
                else:
                    result['rollback'] = 'refused_concurrent_file_change'
            raise
        finally:
            (backup / 'repair-result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))
            for number, handler in handlers.items():
                signal.signal(number, handler)
    finally:
        os.close(fd)


main()

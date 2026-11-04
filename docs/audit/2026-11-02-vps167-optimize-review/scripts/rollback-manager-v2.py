"""VPS167 rollback revision: validate first and resume our own parked source.

BACKUP, STAGE_SHA256 and RESULT_DIRECTORY are injected by the installer.
No active configuration, database, firewall or service state is restored.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exists(path):
    return os.path.lexists(path)


def trusted_parent(path):
    for parent in Path(path).parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0,
                'unsafe rollback ancestor')
        require(not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX,
                'writable rollback ancestor')


def regular(path, mode=None):
    trusted_parent(path)
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unsafe rollback file')
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode, 'rollback file mode changed')


def directory(path):
    trusted_parent(path)
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unsafe rollback directory')


def source_matches(path, expected):
    from crowdsec_maintenance import fingerprint
    directory(path)
    # fingerprint preserves link text and file modes; inspect ownership as well.
    for item in Path(path).rglob('*'):
        info = item.lstat()
        require(info.st_uid == 0, 'source ownership changed')
        if not stat.S_ISLNK(info.st_mode):
            require(not info.st_mode & 0o022, 'source became writable')
    require(fingerprint(path) == expected, 'source content or file modes changed')


def load_stage():
    backup = Path(BACKUP)
    directory(backup)
    regular(backup/'stage.json', 0o600)
    require(sha(backup/'stage.json') == STAGE_SHA256, 'stage changed')
    stage = json.loads((backup/'stage.json').read_text())
    require(Path(stage['backup']) == backup, 'stage backup mismatch')
    release = Path(stage['release'])
    directory(release)
    directory(release/'lib')
    for name, digest in stage['package_hashes'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe package path')
        path = release/relative
        regular(path)
        require(sha(path) == digest, 'release changed')
    sys.path.insert(0, str(release/'lib'))
    return stage


def replace_file(path, content, mode):
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'.rollback-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if exists(temporary):
            temporary.unlink()


def restore(stage, check_only=False):
    backup = Path(stage['backup'])
    root = Path(stage['root'])
    saved = backup/'source-directory.before'
    parked = backup/'source-directory.deployed'
    current = Path(stage['runtime'])/'current'
    entry = Path(stage['entry'])
    cron = Path(stage['cron'])
    original_cron = backup/'hub.cron.before'
    result_directory = Path(RESULT_DIRECTORY)
    directory(backup)
    directory(result_directory)
    for path in [root, saved, parked, current, entry, cron]:
        trusted_parent(path)
    regular(cron, stage['cron_mode'])
    cron_hash = sha(cron)
    require(cron_hash in (stage['cron_before_sha256'], stage['cron_after_sha256']),
            'cron changed; manual review required')
    regular(original_cron, 0o600)
    original_bytes = original_cron.read_bytes()
    require(hashlib.sha256(original_bytes).hexdigest() == stage['cron_before_sha256'],
            'original cron backup changed')
    if exists(current):
        info = current.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and
                os.readlink(current) == Path(stage['maintenance']).name, 'current changed')
    if exists(entry):
        regular(entry, 0o755)
        require(sha(entry) == stage['entry_after_sha256'], 'entry changed')
    has_saved, has_root, has_parked = exists(saved), exists(root), exists(parked)
    if has_saved:
        source_matches(saved, stage['original_source_fingerprint'])
        if has_root:
            source_matches(root, stage['prepared_source_fingerprint'])
            require(not has_parked, 'rollback destination occupied')
        elif has_parked:
            source_matches(parked, stage['prepared_source_fingerprint'])
    else:
        source_matches(root, stage['original_source_fingerprint'])
        if has_parked:
            source_matches(parked, stage['prepared_source_fingerprint'])
    result = {'check_only': check_only, 'resuming_parked_source': has_saved and not has_root and has_parked,
              'restores': ['original source directory', 'original disabled Hub cron',
                           'daily entry absence', 'current pointer absence'],
              'preserves': ['configuration', 'live databases', 'firewall', 'services',
                            'immutable release and sealed evidence files']}
    if check_only:
        return result
    if cron_hash == stage['cron_after_sha256']:
        replace_file(cron, original_bytes, stage['cron_mode'])
    if exists(current):
        current.unlink()
    if exists(entry):
        entry.unlink()
    if has_saved:
        if has_root:
            os.rename(root, parked)
        os.rename(saved, root)
    source_matches(root, stage['original_source_fingerprint'])
    require(sha(cron) == stage['cron_before_sha256'] and not exists(current) and not exists(entry),
            'rollback verification failed')
    replace_file(result_directory/'rollback-result.json', (json.dumps(result, indent=2)+'\n').encode(), 0o600)
    return result


if __name__ == '__main__':
    os.umask(0o077)
    require(os.geteuid() == 0, 'root required')
    require(sys.argv[1:] in ([], ['--check']), 'usage: rollback-manager-v2.py [--check]')
    stage = load_stage()
    from crowdsec_bot_runtime import maintenance_guard
    with maintenance_guard('/run/lock/crowdsec-1key.lock', '/var/lib/crowdbastion/firewall-migration'):
        print(json.dumps(restore(stage, check_only=sys.argv[1:] == ['--check']), ensure_ascii=False))

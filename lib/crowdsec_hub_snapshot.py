#!/usr/bin/env python3
"""Snapshot Hub-owned directories, restoring only files changed by this transaction."""
import base64
import hashlib
import json
import os
import stat
import sys
import re
import tempfile
from pathlib import Path
from crowdsec_safety import load


class BlobDocument(dict):
    """JSON metadata plus a local, unencoded content store for format 3."""
    def __init__(self, content, blob_directory):
        super().__init__(content)
        self.blob_directory = Path(blob_directory)


def blob_directory(path, *, create=False):
    path = Path(path)
    if not path.is_absolute() or any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('snapshot content directory must be an absolute plain path')
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('snapshot content directory must be privately owned')
    return path


def stream_file(path, output=None):
    checksum, size = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('snapshot content must be a regular file')
        for chunk in iter(lambda: source.read(1024*1024), b''):
            checksum.update(chunk)
            size += len(chunk)
            if output is not None:
                output.write(chunk)
    return {'sha256': checksum.hexdigest(), 'size': size}


def checked_blob(directory, record):
    if (not isinstance(record, dict) or set(record) != {'sha256', 'size'} or
            not isinstance(record['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', record['sha256']) or
            type(record['size']) is not int or record['size'] < 0):
        raise ValueError('invalid snapshot content reference')
    path = blob_directory(directory)/record['sha256']
    if stream_file(path) != record:
        raise ValueError('Hub snapshot content changed; restoration refused')
    return path


def store_blob(directory, source):
    directory = blob_directory(directory, create=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
        temporary = Path(output.name)
        try:
            record = stream_file(source, output)
            output.flush()
            target = directory/record['sha256']
            if target.exists() or target.is_symlink():
                checked_blob(directory, record)
            else:
                os.replace(temporary, target)
            return record
        finally:
            temporary.unlink(missing_ok=True)


def validate_blobs(document):
    if document.get('format') != 3:
        return
    if not isinstance(document, BlobDocument):
        raise ValueError('snapshot content store is not bound to this metadata file')
    blob_directory(document.blob_directory)
    checked = set()
    for stage in ('before', 'after'):
        for record in document.get(stage, {}).values():
            if record.get('kind') == 'file':
                data = record['data']
                # Validate every reference, including repeated hashes with different sizes.
                key = json.dumps(data, sort_keys=True)
                if key not in checked:
                    checked_blob(document.blob_directory, data)
                    checked.add(key)


def roots(config):
    directory = Path(config).parent
    paths = load(config).get('config_paths', {})
    directory = Path(paths.get('config_dir') or directory)
    hub = Path(paths.get('hub_dir') or directory/'hub')
    result = [directory/'hub', hub, *(directory/name for name in ('collections', 'parsers', 'scenarios', 'postoverflows', 'contexts', 'appsec-configs', 'appsec-rules'))]
    if paths.get('index_path'):
        result.append(Path(paths['index_path']))
    if any(not item.is_absolute() or item == Path('/') for item in result):
        raise ValueError('Hub paths must be absolute and must not be /')
    for item in result:
        for component in (item, *item.parents):
            if component.is_symlink():
                raise ValueError(f'symlinked snapshot root or ancestor unsupported: {component}')
    # No overlapping roots: prevents duplicate or conflicting restoration.
    managed = [str(directory/'hub'), str(hub)]
    if paths.get('index_path'):
        managed.append(str(paths['index_path']))
    return sorted(set(str(x) for x in result)), managed


def scan(paths, managed, data_dir=None, database=None, content_directory=None):
    records = {}
    def visit(path):
        if database and path == Path(database):
            return
        if path.suffix in ('.db', '.sqlite', '.sqlite3') or path.name.endswith(('-wal', '-shm', '-journal')):
            return
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        mode = stat.S_IMODE(info.st_mode)
        owned = any(path == Path(root) or Path(root) in path.parents for root in managed) or (data_dir and path.parent == Path(data_dir))
        if not owned and (path.is_symlink() or not path.is_dir()):
            if not path.is_symlink() or not any(path.resolve() == Path(root) or Path(root) in path.resolve().parents for root in managed):
                return
        if owned and path.is_symlink():
            raise ValueError(f'symlinked Hub entry unsupported: {path}')
        metadata = {'mode': mode, 'uid': info.st_uid, 'gid': info.st_gid}
        if path.is_symlink():
            records[str(path)] = {'kind': 'link', 'data': os.readlink(path), **metadata}
        elif path.is_dir():
            records[str(path)] = {'kind': 'directory', **metadata}
            for child in sorted(path.iterdir()):
                visit(child)
        elif path.is_file():
            data = store_blob(content_directory, path) if content_directory else base64.b64encode(path.read_bytes()).decode()
            records[str(path)] = {'kind': 'file', 'data': data, **metadata}
        else:
            raise ValueError(f'unsupported Hub entry: {path}')
    for root in paths:
        visit(Path(root))
    if data_dir:
        data = Path(data_dir)
        for component in (data, *data.parents):
            if component.is_symlink():
                raise ValueError(f'symlinked data directory unsupported: {component}')
        if data.exists():
            for path in sorted(data.iterdir()):
                if path.is_file():
                    # Downloads are regular files immediately under data_dir.
                    visit(path)
    return records


def capture(document):
    for root in document['roots']:
        for component in (Path(root), *Path(root).parents):
            if component.is_symlink():
                raise ValueError(f'symlinked snapshot root or ancestor unsupported: {component}')
    if document.get('format') == 3 and not isinstance(document, BlobDocument):
        raise ValueError('missing snapshot content store')
    return scan(document['roots'], document['managed'], document.get('data_dir'), document.get('database'),
                document.blob_directory if isinstance(document, BlobDocument) else None)


def digest(document):
    # Keep format-2 checksum bytes identical without allocating a second full
    # JSON snapshot and its UTF-8 copy alongside large downloaded data files.
    checksum = hashlib.sha256()
    content = {k: v for k, v in document.items() if k != 'checksum'}
    for chunk in json.JSONEncoder(sort_keys=True).iterencode(content):
        checksum.update(chunk.encode())
    return checksum.hexdigest()


def save(path, document):
    path = Path(path)
    if document.get('format') == 3 and (not isinstance(document, BlobDocument) or document.blob_directory != path.parent/'files'):
        raise ValueError('snapshot content store must be beside its metadata file')
    document['checksum'] = digest(document)
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('w') as stream:
        os.chmod(temporary, 0o600)
        json.dump(document, stream)
    os.replace(temporary, path)


def read_document(path):
    document = json.loads(Path(path).read_text())
    if (document.get('format') in (2, 3) or 'checksum' in document) and document.get('checksum') != digest(document):
        raise ValueError('Hub snapshot content changed; restoration refused')
    if document.get('format') == 3:
        document = BlobDocument(document, Path(path).parent/'files')
        validate_blobs(document)
    return document


def before(config, content_directory=None):
    paths, managed = roots(config)
    effective = load(config)
    data = effective.get('config_paths', {}).get('data_dir')
    if data and (not Path(data).is_absolute() or Path(data) == Path('/')):
        raise ValueError('data_dir must be an absolute directory other than /')
    document = {'format': 2, 'roots': paths, 'managed': managed, 'data_dir': data,
                'database': effective.get('db_config', {}).get('db_path')}
    if content_directory is not None:
        document['format'] = 3
        document = BlobDocument(document, blob_directory(content_directory, create=True))
    document['before'] = capture(document)
    return document


def restore(document):
    validate_blobs(document)
    before, after = document['before'], document['after']
    current = capture(document)
    changed = [p for p in set(before)|set(after) if before.get(p) != after.get(p)]
    conflicts = [p for p in changed if current.get(p) != after.get(p)]
    removals = {p for p in changed if after.get(p) and
                (not before.get(p) or before[p]['kind'] != after[p]['kind'])}
    # Inspect the filesystem itself: the ownership scanner omits custom files
    # and databases, but those entries still prevent safe directory removal.
    for name in removals:
        if after[name]['kind'] != 'directory' or name in conflicts:
            continue
        for directory, directories, files in os.walk(name, followlinks=False):
            for child in directories + files:
                path = str(Path(directory)/child)
                if path not in removals:
                    conflicts.append(path)
    if conflicts:
        raise ValueError('concurrent modifications; preserved: '+', '.join(sorted(set(conflicts))))
    # Remove transaction additions and changed entry types, children first.
    for name in sorted(changed, key=lambda x: (x.count('/'), x), reverse=True):
        path, old, new = Path(name), before.get(name), after.get(name)
        if new and (not old or old['kind'] != new['kind']):
            if new['kind'] == 'directory':
                path.rmdir()
            else:
                path.unlink()
    for name in sorted(changed, key=lambda x: (x.count('/'), x)):
        old = before.get(name)
        if not old:
            continue
        path = Path(name)
        if old['kind'] == 'directory':
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                path.unlink()
            if old['kind'] == 'link':
                os.symlink(old['data'], path)
            else:
                if document.get('format') == 3:
                    source = checked_blob(document.blob_directory, old['data'])
                    with path.open('wb') as output:
                        stream_file(source, output)
                else:
                    path.write_bytes(base64.b64decode(old['data']))
        os.chown(path, old['uid'], old['gid'], follow_symlinks=False)
        if old['kind'] != 'link':
            path.chmod(old['mode'])


def main():
    action, config, snapshot = sys.argv[1:]
    file = Path(snapshot)
    if action == 'before':
        document = before(config)
    else:
        document = read_document(file)
        if action == 'after':
            document['after'] = capture(document)
        elif action == 'restore':
            restore(document)
            return
        else:
            raise ValueError('unknown snapshot action')
    save(file, document)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Hub snapshot: {exc}', file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Snapshot Hub-owned directories, restoring only files changed by this transaction."""
import base64
import json
import os
import stat
import sys
from pathlib import Path
from crowdsec_safety import load


def roots(config):
    directory = Path(config).parent
    paths = load(config).get('config_paths', {})
    directory = Path(paths.get('config_dir') or directory)
    hub = Path(paths.get('hub_dir') or directory/'hub')
    result = [hub, *(directory/name for name in ('collections', 'parsers', 'scenarios', 'postoverflows', 'contexts', 'appsec-configs', 'appsec-rules'))]
    if paths.get('index_path'):
        result.append(Path(paths['index_path']))
    if any(not item.is_absolute() or item == Path('/') for item in result):
        raise ValueError('Hub paths must be absolute and must not be /')
    for item in result:
        for component in (item, *item.parents):
            if component.is_symlink():
                raise ValueError(f'symlinked snapshot root or ancestor unsupported: {component}')
    # No overlapping roots: prevents duplicate or conflicting restoration.
    return sorted(set(str(x) for x in result)), [str(hub), str(paths['index_path'])] if paths.get('index_path') else [str(hub)]


def scan(paths, managed):
    records = {}
    def visit(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        mode = stat.S_IMODE(info.st_mode)
        owned = any(path == Path(root) or Path(root) in path.parents for root in managed)
        if not owned and not path.is_dir():
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
            records[str(path)] = {'kind': 'file', 'data': base64.b64encode(path.read_bytes()).decode(), **metadata}
        else:
            raise ValueError(f'unsupported Hub entry: {path}')
    for root in paths:
        visit(Path(root))
    return records


def restore(document):
    before, after = document['before'], document['after']
    current = scan(document['roots'], document['managed'])
    changed = [p for p in set(before)|set(after) if before.get(p) != after.get(p)]
    conflicts = [p for p in changed if current.get(p) != after.get(p)]
    if conflicts:
        raise ValueError('concurrent modifications; preserved: '+', '.join(conflicts))
    # Remove transaction additions and changed entry types, children first.
    for name in sorted(changed, key=lambda x: (x.count('/'), x), reverse=True):
        path, old, new = Path(name), before.get(name), after.get(name)
        if new and (not old or old['kind'] != new['kind']):
            if new['kind'] == 'directory':
                path.rmdir()  # preserve unrelated new children by failing safely
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
                path.write_bytes(base64.b64decode(old['data']))
        os.chown(path, old['uid'], old['gid'], follow_symlinks=False)
        if old['kind'] != 'link':
            path.chmod(old['mode'])


def main():
    action, config, snapshot = sys.argv[1:]
    file = Path(snapshot)
    if action == 'before':
        paths, managed = roots(config)
        document = {'roots': paths, 'managed': managed, 'before': scan(paths, managed)}
    else:
        document = json.loads(file.read_text())
        if action == 'after':
            document['after'] = scan(document['roots'], document['managed'])
        elif action == 'restore':
            restore(document)
            return
        else:
            raise ValueError('unknown snapshot action')
    file.write_text(json.dumps(document))
    file.chmod(0o600)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Hub snapshot: {exc}', file=sys.stderr)
        sys.exit(1)

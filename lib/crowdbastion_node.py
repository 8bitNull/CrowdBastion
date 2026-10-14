#!/usr/bin/env python3
"""Strict, non-executable node preferences; Python standard library only."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

ROLES = ('web', 'relay', 'remote', 'node')


def normalize(roles):
    if (not isinstance(roles, list) or not roles or
            any(not isinstance(role, str) or role not in ROLES for role in roles) or
            len(set(roles)) != len(roles)):
        raise ValueError('invalid roles')
    if 'remote' in roles and ({'web', 'relay'} & set(roles)):
        raise ValueError('conflicting roles')
    return [role for role in ROLES if role in roles]


def safe_path(path):
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError('symlink directory')
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_uid != os.geteuid():
        raise ValueError('unsafe preferences')


def load(path):
    safe_path(path)
    # NOFOLLOW + NONBLOCK also protect against a replaced symlink or FIFO.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 4096 or
                info.st_mode & 0o022 or info.st_uid != os.geteuid()):
            raise ValueError('unsafe preferences')
        data = json.load(stream)
    if (not isinstance(data, dict) or set(data) != {'version', 'roles'} or
            type(data['version']) is not int or data['version'] != 1):
        raise ValueError('invalid preferences')
    return normalize(data['roles'])


def save(path, roles):
    roles = normalize(roles)
    safe_path(path)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    safe_path(path)
    fd, temporary = tempfile.mkstemp(prefix='.node-roles-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump({'version': 1, 'roles': roles}, stream, ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return roles


def main(args):
    if len(args) < 2:
        raise ValueError('missing arguments')
    action, filename, *roles = args
    path = Path(os.path.abspath(filename))
    if action == 'load' and not roles:
        try:
            result = load(path)
        except FileNotFoundError:
            return 3
    elif action == 'save':
        result = save(path, roles)
    else:
        raise ValueError('unknown operation')
    print(' '.join(result))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, UnicodeError):
        print('[ERROR] 节点用途配置无效或不安全；内容损坏可从菜单 [7] 重设，权限、归属或链接问题须先人工修正。未执行安装或修复。', file=sys.stderr)
        sys.exit(1)

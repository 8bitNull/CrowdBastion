#!/usr/bin/env python3
"""Shared standard-library credential validation and private approval transport."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

class RemoteError(ValueError):
    pass

def validate(url, key):
    if not isinstance(url,str) or not isinstance(key,str) or not key or len(key)>4096 or re.search(r'[\s\x00-\x1f\x7f]',key):
        raise RemoteError('URL 或密钥格式无效。')
    if re.search(r'[\s\x00-\x1f\x7f]',url):
        raise RemoteError('URL 格式无效。')
    parts=urlsplit(url)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise RemoteError('URL 必须为无用户信息、查询或片段的 HTTP(S) 地址。')
    try:
        parts.port
    except ValueError:
        raise RemoteError('URL 端口无效。') from None
    try:
        address=ipaddress.ip_address(parts.hostname)
    except ValueError:
        address=None
    if parts.scheme=='http':
        # Names (including .local) do not prove transport is private; use a
        # literal RFC1918/ULA/loopback address, or verified TLS instead.
        networks=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','::1/128','fc00::/7']
        if address is None or not any(address in ipaddress.ip_network(n) for n in networks):
            raise RemoteError('明文 HTTP 仅允许环回、RFC1918 或 ULA 地址；其他地址必须使用 HTTPS。')
    return url.rstrip('/')+'/'


MAX_PLAN_BYTES = 32768


def private_parent(path):
    """Walk directory descriptors without following links, including parents."""
    absolute = Path(os.path.abspath(path))
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, absolute.name
    except Exception:
        os.close(descriptor)
        raise


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RemoteError('计划含重复字段。')
        result[key] = value
    return result


def read_private(path):
    parent, name = private_parent(path)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_size > MAX_PLAN_BYTES):
            raise RemoteError('计划必须是当前用户所有的 0600 单链接普通文件。')
        payload = stream.read(MAX_PLAN_BYTES + 1)
        if len(payload) > MAX_PLAN_BYTES:
            raise RemoteError('计划过大。')
        data = json.loads(payload, object_pairs_hook=unique_object)
    if not isinstance(data, dict):
        raise RemoteError('计划格式无效。')
    return data


def credentials(data):
    if set(data) != {'url', 'key'}:
        raise RemoteError('凭据字段无效。')
    return {'url': validate(data['url'], data['key']), 'key': data['key']}


def publish(input_path, output_path):
    data = {'version': 1, 'action': 'install', **credentials(read_private(input_path))}
    parent, name = private_parent(output_path)
    temporary = None
    try:
        # Create in the held directory, so a renamed parent cannot redirect it.
        for _ in range(20):
            temporary = '.remote-plan-' + os.urandom(16).hex()
            try:
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=parent)
                break
            except FileExistsError:
                temporary = None
        if temporary is None:
            raise RemoteError('无法创建私有计划。')
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        # No replacement: an existing output, including a link, is never approved.
        os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
                follow_symlinks=False)
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def main():
    action = sys.argv[1]
    if action == 'validate':
        credentials(read_private(sys.argv[2]))
    elif action == 'publish':
        publish(sys.argv[2], sys.argv[3])
    elif action == 'read':
        data = read_private(sys.argv[2])
        if (set(data) != {'version', 'action', 'url', 'key'}
                or type(data['version']) is not int or data['version'] != 1
                or data['action'] != 'install'):
            raise RemoteError('未找到有效的安装批准计划。')
        json.dump(credentials({'url': data['url'], 'key': data['key']}), sys.stdout)
    else:
        raise RemoteError('未知计划操作。')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Parsing, path, and credential exceptions must never quote input values.
        print('远端批准计划无效或不安全，未应用任何更改。', file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Cloudflare real-IP plans for a dedicated persistent HTTP include."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

from crowdsec_web import directives, mount_path, read_state, save_state

FILE = 'crowdsec-1key-cloudflare-real-ip.conf'
INCLUDES = ['/usr/local/openresty/nginx/conf/http.d/*.conf',
            '/usr/local/openresty/nginx/conf/conf.d/*.conf',
            '/etc/nginx/conf.d/*.conf']


def validate_ranges(ranges):
    networks = []
    for value in ranges:
        network = ipaddress.ip_network(value, strict=True)
        minimum = 8 if network.version == 4 else 16
        if not network.network_address.is_global or network.prefixlen < minimum:
            raise ValueError('Cloudflare 网段无效或信任范围过宽，未应用')
        if network not in networks:
            networks.append(network)
    if {network.version for network in networks} != {4, 6}:
        raise ValueError('必须提供完整 IPv4 和 IPv6 来源')
    return [str(network) for network in networks]


def plan_real_ip(effective, mounts, ranges, owned=None):
    ranges = validate_ranges(ranges)
    candidates = [words[1] for context, words, block in directives(effective)
                  if context == ('http',) and not block and len(words) == 2 and words[0] == 'include']
    target = host = None
    for include in INCLUDES:
        if include in candidates:
            possible = include.rsplit('/', 1)[0]+'/'+FILE
            try:
                local, mount = mount_path(possible, mounts)
                if mount['Destination'].rstrip('/') == possible or not Path(mount['Source']).is_dir():
                    raise ValueError('需要目录挂载，单文件 bind 不支持原子更新')
            except ValueError:
                continue
            target, host = possible, local
            break
    if not target:
        raise ValueError('未找到已启用且可写的持久化 HTTP include；请先核对 nginx -T 与 Mounts')
    if owned:
        if owned.get('host_target') != host or owned.get('container_target') != target:
            raise ValueError('原真实 IP 配置挂载已变化，未覆盖')
        if not Path(host).is_file() or hashlib.sha256(Path(host).read_bytes()).hexdigest() != owned['sha']:
            raise ValueError('本工具真实 IP 配置已被手工修改或移除，未覆盖')
    elif Path(host).exists():
        raise ValueError('已有同名配置且无管理记录，未覆盖')
    parts = re.split(r'(?m)^# configuration file ([^\n]+):\n', effective)
    unrelated = parts[0]
    for index in range(1, len(parts), 2):
        if not owned or parts[index] != target:
            unrelated += parts[index+1]
    if any(words and words[0] in ('set_real_ip_from', 'real_ip_header', 'real_ip_recursive')
           for _, words, _ in directives(unrelated)):
        raise ValueError('已有其他真实 IP 配置，请先人工核对信任范围，未覆盖')
    text = '# Managed by crowdsec-1key; Cloudflare official IP ranges only.\n'
    text += '# Sources: https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6\n'
    text += ''.join('set_real_ip_from '+network+';\n' for network in ranges)
    text += 'real_ip_header CF-Connecting-IP;\nreal_ip_recursive on;\n'
    return dict(host_target=host, container_target=target, text=text,
                sha=hashlib.sha256(text.encode()).hexdigest())


def main(args):
    action, *args = args
    if action == 'list':
        for name in read_state(args[0]):
            print(name)
    elif action == 'plan':
        effective, mounts, ipv4, ipv6, state, name, destination = args
        v4 = Path(ipv4).read_text().split()
        v6 = Path(ipv6).read_text().split()
        if not 10 <= len(v4) <= 128 or not 3 <= len(v6) <= 64:
            raise ValueError('官方网段响应数量异常，未应用')
        if any(ipaddress.ip_network(value, strict=True).version != version
               for values, version in [(v4, 4), (v6, 6)] for value in values):
            raise ValueError('官方 IPv4/IPv6 来源类型不符')
        plan = plan_real_ip(Path(effective).read_text(), json.loads(Path(mounts).read_text()),
                            v4+v6, read_state(state).get(name))
        save_state(destination, plan)
    elif action == 'apply':
        plan_file, state_file, name = args
        plan = read_state(plan_file)
        target = Path(plan['host_target'])
        state = read_state(state_file)
        if name in state:
            if state[name].get('host_target') != str(target) or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != state[name]['sha']:
                raise ValueError('配置在预检后变化，未覆盖')
        elif target.exists():
            raise ValueError('配置在预检后出现，未覆盖')
        target.parent.mkdir(parents=True, exist_ok=True)
        # Same-directory replacement preserves bind-mounted directory persistence.
        import os
        import tempfile
        fd, temporary = tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(plan['text'])
            os.chmod(temporary, 0o644)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        state[name] = {key: plan[key] for key in ['host_target', 'container_target', 'sha']}
        save_state(state_file, state)
    elif action == 'restore-plan':
        state_file, name, mounts, destination = args
        entry = read_state(state_file)[name]
        resolved, mount = mount_path(entry['container_target'], json.loads(Path(mounts).read_text()))
        if mount['Destination'].rstrip('/') == entry['container_target'] or not Path(mount['Source']).is_dir():
            raise ValueError('需要持久化目录挂载，不能移除单文件 bind 配置')
        if resolved != entry['host_target'] or not Path(resolved).is_file() or hashlib.sha256(Path(resolved).read_bytes()).hexdigest() != entry['sha']:
            raise ValueError('真实 IP 配置或挂载已变化，未移除')
        save_state(destination, entry)
    elif action == 'remove':
        state_file, name = args
        state = read_state(state_file)
        entry = state[name]
        if hashlib.sha256(Path(entry['host_target']).read_bytes()).hexdigest() != entry['sha']:
            raise ValueError('配置已变化，未移除')
        Path(entry['host_target']).unlink()
        del state[name]
        save_state(state_file, state)
    else:
        raise ValueError('未知真实 IP 操作')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, KeyError) as error:
        print('[ERROR] '+str(error), file=sys.stderr)
        sys.exit(1)

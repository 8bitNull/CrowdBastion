#!/usr/bin/env python3
"""Cloudflare real-IP plans for a dedicated persistent HTTP include."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from crowdsec_web import directives, mount_path, read_state, save_state

FILE = 'crowdsec-1key-cloudflare-real-ip.conf'
INCLUDES = ['/usr/local/openresty/nginx/conf/http.d/*.conf',
            '/usr/local/openresty/nginx/conf/conf.d/*.conf',
            '/etc/nginx/conf.d/*.conf']
HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'X-Forwarded', 'Forwarded-For',
           'True-Client-IP', 'Client-IP', 'Ali-CDN-Real-IP', 'CDN-Src-IP',
           'CDN-Real-IP', 'CF-Connecting-IP', 'X-Cluster-Client-IP',
           'WL-Proxy-Client-IP', 'Proxy-Client-IP']
REALIP = ('set_real_ip_from', 'real_ip_header', 'real_ip_recursive')
NPM_TARGET = '/data/nginx/custom/server_proxy.conf'


def validate_ranges(ranges, provider='cloudflare'):
    if provider not in ('cloudflare', 'custom'):
        raise ValueError('未知可信代理类型')
    networks = []
    for value in ranges:
        network = ipaddress.ip_network(value, strict=True)
        address = network.network_address
        minimum = (8 if network.version == 4 else 16) if address.is_global else (24 if network.version == 4 else 64)
        if address.is_loopback:
            minimum = network.max_prefixlen
        if address.is_unspecified or address.is_multicast or address.is_link_local or network.prefixlen < minimum:
            raise ValueError('代理网段无效或信任范围过宽，未应用')
        if provider == 'cloudflare' and not address.is_global:
            raise ValueError('Cloudflare 来源必须为公网网段')
        if network not in networks:
            networks.append(network)
    if not networks:
        raise ValueError('必须明确提供可信代理网段')
    if provider == 'cloudflare' and {network.version for network in networks} != {4, 6}:
        raise ValueError('必须提供完整 IPv4 和 IPv6 来源')
    return [str(network) for network in networks]


def sections(effective):
    parts = re.split(r'(?m)^# configuration file ([^\n]+):\n', effective)
    yield '', parts[0]
    for index in range(1, len(parts), 2):
        yield parts[index], parts[index+1]


def atomic_text(target, text, mode):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def plan_real_ip(effective, mounts, ranges, owned=None, provider='cloudflare', header='CF-Connecting-IP'):
    ranges = validate_ranges(ranges, provider)
    header = next((value for value in HEADERS if value.lower() == header.lower()), None)
    if not header:
        raise ValueError('Header 不支持；Forwarded 是 RFC 格式，请由可信上游规范化为 IP Header')
    if provider == 'cloudflare' and header != 'CF-Connecting-IP':
        raise ValueError('Cloudflare 固定使用 CF-Connecting-IP，不尝试其他 Header')
    candidates = [words[1] for context, words, block in directives(effective)
                  if context == ('http',) and not block and len(words) == 2 and words[0] == 'include']
    npm = any(value in candidates for value in ['/data/nginx/custom/http_top[.]conf', '/data/nginx/custom/http_top.conf'])
    if npm and not any(context in [('server',), ('http', 'server')] and words in
                       [['include', '/data/nginx/custom/server_proxy[.]conf'], ['include', NPM_TARGET]]
                       for context, words, _ in directives(effective)):
        raise ValueError('NPM 未加载 server_proxy.conf 站点入口，未修改')
    target = host = None
    for include in ([NPM_TARGET] if npm else INCLUDES):
        if npm or include in candidates:
            possible = NPM_TARGET if npm else include.rsplit('/', 1)[0]+'/'+FILE
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
    elif Path(host).exists() and not npm:
        raise ValueError('已有同名配置且无管理记录，未覆盖')
    original = owned.get('original') if owned else (Path(host).read_bytes().decode('utf-8') if npm and Path(host).exists() else None)
    original_mode = owned.get('original_mode', 0o644) if owned else (Path(host).stat().st_mode & 0o777 if Path(host).exists() else 0o644)
    for path, content in sections(effective):
        if owned and path == target:
            content = original or ''
        for context, words, _ in directives(content):
            if not words or words[0] not in REALIP:
                continue
            if npm and ((path == '/etc/nginx/nginx.conf' and context == ('http',)) or
                        (path == '/etc/nginx/conf.d/include/ip_ranges.conf' and words[0] == 'set_real_ip_from')):
                continue
            raise ValueError('已有其他真实 IP 配置，请先人工核对信任范围，未覆盖')
    if original and any(words and words[0] in REALIP for _, words, _ in directives(original)):
        raise ValueError('NPM 自定义入口已有真实 IP 指令，未覆盖')
    text = (original or '')+'\n# crowdsec-1key managed trusted proxy real IP\n'
    if provider == 'cloudflare':
        text += '# Sources: https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6\n'
    text += ''.join('set_real_ip_from '+network+';\n' for network in ranges)
    text += 'real_ip_header '+header+';\nreal_ip_recursive on;\n'
    return dict(host_target=host, container_target=target, text=text,
                sha=hashlib.sha256(text.encode()).hexdigest(), provider=provider, header=header, ranges=ranges,
                scope='npm-proxy-hosts' if npm else 'http', original=original, original_mode=original_mode,
                before_sha=hashlib.sha256(Path(host).read_bytes()).hexdigest() if Path(host).exists() else None)


def main(args):
    action, *args = args
    if action == 'list':
        for name in read_state(args[0]):
            print(name)
    elif action == 'discover':
        effective = Path(args[0]).read_text()
        headers = sorted({words[1] for _, words, _ in directives(effective)
                          if len(words) == 2 and words[0] == 'real_ip_header'})
        print('现有 real_ip_header：'+(', '.join(headers) or '未配置'))
        print('候选 IP Header：'+', '.join(HEADERS))
        print('Forwarded：可作为诊断线索，但 RFC 语法不能直接用于 real_ip_header。')
        trusts = [words[1] for _, words, _ in directives(effective)
                  if len(words) == 2 and words[0] == 'set_real_ip_from']
        print('已有可信来源条目数：'+str(len(trusts)))
        if 'CF-Connecting-IP' in headers or any(value in trusts for value in ['104.16.0.0/13', '172.64.0.0/13', '2606:4700::/32']):
            print('发现 Cloudflare 配置线索；仍需确认请求是官方公网节点直接接入。')
        print('配置证据不等于实际接入识别；不按 Header 存在顺序选择，也不自动信任代理。')
    elif action == 'plan-custom':
        effective, mounts, header, ranges, state, name, destination = args
        plan = plan_real_ip(Path(effective).read_text(), json.loads(Path(mounts).read_text()),
                            ranges.split(), read_state(state).get(name), provider='custom', header=header)
        save_state(destination, plan)
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
        elif (hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None) != plan.get('before_sha'):
            raise ValueError('配置在预检后出现，未覆盖')
        atomic_text(target, plan['text'], plan.get('original_mode', 0o644))
        state[name] = {key: plan[key] for key in ['host_target', 'container_target', 'sha', 'provider', 'header', 'ranges', 'scope', 'original', 'original_mode']}
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
        if entry.get('original') is None:
            Path(entry['host_target']).unlink()
        else:
            atomic_text(entry['host_target'], entry['original'], entry.get('original_mode', 0o644))
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

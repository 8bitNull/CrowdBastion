#!/usr/bin/env python3
"""Structured configuration edits for the CrowdSec manager (Python 3 + PyYAML)."""
import glob
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit

import yaml


def read(path, multiple=False):
    text = Path(path).read_text()
    return list(yaml.safe_load_all(text)) if multiple else yaml.safe_load(text)


def write(path, value, multiple=False):
    """Atomically replace a file; shell workflow owns backups/rollback."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (yaml.safe_dump_all(value, allow_unicode=True, sort_keys=False)
            if multiple else yaml.safe_dump(value, allow_unicode=True, sort_keys=False))
    fd, tmp = tempfile.mkstemp(prefix='.'+path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def get(path, key):
    value = read(path)
    for part in key.split('.'):
        value = value[part]
    if value is None:
        raise ValueError('配置项为空: '+key)
    print(value if isinstance(value, str) else json.dumps(value))


def merged_config(path):
    data = read(path)
    def merge(left, right):
        for key, value in right.items():
            if isinstance(value, dict) and isinstance(left.get(key), dict):
                merge(left[key], value)
            else:
                left[key] = value
    local = Path(str(path)+'.local')
    if local.exists():
        merge(data, read(local))
    return data


def acquisition_locations(root):
    service = merged_config(str(Path(root)/'config.yaml')).get('crowdsec_service', {})
    if not isinstance(service, dict) or service.get('enable') is False:
        raise ValueError('未启用日志处理服务 crowdsec_service')
    directory = service.get('acquisition_dir')
    single = service.get('acquisition_path')
    if not directory or not Path(directory).is_absolute():
        raise ValueError('请先在 crowdsec_service.acquisition_dir 设置有效的绝对目录')
    if single and not Path(single).is_absolute():
        raise ValueError('acquisition_path 必须为绝对路径')
    repair = Path(directory)/'crowdsec-1key-log-repair.yaml'
    if repair.is_symlink():
        raise ValueError('修复采集文件是符号链接，请先确认并改为普通文件：'+str(repair))
    return directory, single, repair


def go_glob(pattern):
    """Match Unix Go filepath.Glob semantics used by CrowdSec's file source."""
    paths = ['/'] if pattern.startswith('/') else ['.']
    for component in pattern.split('/'):
        if not component:
            continue
        i, literal, regex, wildcard = 0, '', '', False

        def character():
            nonlocal i
            if i >= len(component):
                raise ValueError('日志通配符格式无效：'+pattern)
            char = component[i]
            i += 1
            if char == '\\':
                if i >= len(component):
                    raise ValueError('日志通配符格式无效：'+pattern)
                char = component[i]
                i += 1
            return char

        while i < len(component):
            token = component[i]
            if token in '*?':
                wildcard = True
                regex += '.*' if token == '*' else '.'
                i += 1
            elif token == '[':
                wildcard = True
                i += 1
                negate = i < len(component) and component[i] == '^'
                if negate:
                    i += 1
                members, consumed = [], 0
                while i < len(component) and component[i] != ']':
                    first = character()
                    consumed += 1
                    if i < len(component) and component[i] == '-':
                        i += 1
                        last = character()
                        if first <= last:
                            members.append(re.escape(first)+'-'+re.escape(last))
                    else:
                        members.append(re.escape(first))
                if not consumed or i >= len(component):
                    raise ValueError('日志通配符格式无效：'+pattern)
                i += 1
                regex += ('['+('^' if negate else '')+''.join(members)+']'
                          if members else ('.' if negate else '(?!)'))
            else:
                char = character()
                literal += char
                regex += re.escape(char)
        if not wildcard:
            paths = [os.path.join(path, literal) for path in paths
                     if os.path.lexists(os.path.join(path, literal))]
        else:
            try:
                matcher = re.compile(regex, re.S)
            except re.error as error:
                raise ValueError('日志通配符格式无效：'+pattern) from error
            matches = []
            for path in paths:
                try:
                    with os.scandir(path) as entries:
                        matches.extend(entry.path for entry in entries if matcher.fullmatch(entry.name))
                except (FileNotFoundError, NotADirectoryError, PermissionError):
                    continue
            paths = matches
    return paths


def go_escape(path):
    return ''.join('\\'+char if char in '\\*?[]' else char for char in path)


def stage_log_repair(root, presets, mounts, destination):
    """Add existing, unacquired HTTP files to a dedicated acquisition file."""
    npm_names = ['*host*_access.log', '*host*_error.log',
                 'fallback_http_access.log', 'fallback_http_error.log',
                 'letsencrypt-requests_access.log', 'letsencrypt-requests_error.log']
    directory, single, original = acquisition_locations(root)
    candidates, hidden, visible = [], set(), set()
    for line in Path(mounts).read_text().splitlines():
        kind, encoded = line.split('\t', 1)
        if kind not in ['nginx', 'nginx-proxy-manager']:
            raise ValueError('未知日志类型')
        records = json.loads(encoded)
        if not isinstance(records, list):
            raise ValueError('Docker 挂载数据不是列表')
        for record in records:
            target = record['Destination'].rstrip('/')
            patterns = []
            if record.get('Type', 'bind') not in ['bind', 'volume']:
                continue
            supported = target in (['/data', '/data/logs'] if kind == 'nginx-proxy-manager'
                                   else ['/www', '/www/sites', '/var/log/nginx'])
            if not supported:
                continue
            source = record['Source']
            if not Path(source).is_absolute():
                raise ValueError('Docker 挂载 Source 必须为绝对路径')
            prefix = glob.escape(source.rstrip('/'))
            if kind == 'nginx-proxy-manager':
                log_directory = prefix + ('/logs' if target == '/data' else '')
                patterns = [log_directory+'/'+name for name in npm_names]
            elif target == '/www':
                patterns = [prefix+'/sites/*/log/'+name for name in ['access.log', 'error.log']]
            elif target == '/www/sites':
                patterns = [prefix+'/*/log/'+name for name in ['access.log', 'error.log']]
            elif target == '/var/log/nginx':
                patterns = [prefix+'/'+name for name in ['access.log', 'error.log']]
            for pattern in patterns:
                for filename in glob.glob(pattern):
                    virtual = target+'/'+os.path.relpath(filename, source)
                    canonical = os.path.realpath(filename)
                    shadowed = any(other['Destination'].rstrip('/') != target
                                   and other['Destination'].rstrip('/').startswith(target+'/')
                                   and (virtual == other['Destination'].rstrip('/')
                                        or virtual.startswith(other['Destination'].rstrip('/')+'/'))
                                   for other in records)
                    if shadowed:
                        hidden.add(canonical)
                    else:
                        visible.add(canonical)
                        candidates.append((glob.escape(filename), kind))

    for doc in read(presets, multiple=True):
        kind = doc.get('labels', {}).get('type')
        if kind in ['nginx', 'nginx-proxy-manager']:
            candidates.extend((pattern, kind) for pattern in doc.get('filenames', []))

    acquired = {}
    paths = ([single] if single else []) + [*glob.glob(glob.escape(directory)+'/*.yaml'),
                                          *glob.glob(glob.escape(directory)+'/*.yml')]
    for path in paths:
        if not Path(path).exists():
            continue
        for doc in read(path, multiple=True):
            if not doc or doc.get('source', 'file') != 'file':
                continue
            filenames = doc.get('filenames', [])
            if isinstance(filenames, str):
                filenames = [filenames]
            if doc.get('filename'):
                filenames = [*filenames, doc['filename']]
            for pattern in filenames:
                for filename in go_glob(pattern):
                    acquired[os.path.realpath(filename)] = doc.get('labels', {}).get('type')

    additions = {}
    for pattern, kind in candidates:
        for filename in sorted(glob.glob(pattern)):
            path = Path(filename)
            if not path.is_file() or path.name.startswith(('stream-', 'stream_', 'fallback_stream_')):
                continue
            canonical = os.path.realpath(filename)
            if canonical in hidden and canonical not in visible:
                continue
            if canonical in acquired:
                if acquired[canonical] != kind:
                    print(f'[WARN] 日志已被其他类型采集，请核对标签：{filename}', file=sys.stderr)
                continue
            if not os.access(filename, os.R_OK):
                print(f'[WARN] 无法读取日志，跳过：{filename}', file=sys.stderr)
                continue
            additions.setdefault(kind, []).append(go_escape(canonical))
            acquired[canonical] = kind
            print(f'[INFO] 待补齐日志采集（{kind}）：{canonical}', file=sys.stderr)

    count = sum(len(names) for names in additions.values())
    if count:
        docs = [doc for doc in read(original, multiple=True) if doc] if original.exists() else []
        for kind, names in additions.items():
            for doc in docs:
                if set(doc) <= {'filenames', 'labels'} and doc.get('labels') == {'type': kind} and isinstance(doc.get('filenames'), list):
                    doc['filenames'].extend(names)
                    break
            else:
                docs.append({'filenames': names, 'labels': {'type': kind}})
        write(destination, docs, multiple=True)
    print(count)


def main(args):
    action, *args = args
    if action == 'get':
        get(*args)
    elif action == 'repair-log-acquis':
        stage_log_repair(*args)
    elif action == 'log-repair-file':
        print(acquisition_locations(args[0])[2])
    elif action == 'credentials-config':
        source, credentials, destination = args
        data = merged_config(source)
        data['api']['client']['credentials_path'] = credentials
        write(destination, data)
    elif action == 'bouncer-key':
        print(merged_config(args[0]).get('api_key') or '')
    elif action == 'firewall-tables':
        data = merged_config(args[0])
        for family, group in [('ip', 'ipv4'), ('ip6', 'ipv6')]:
            block = data.get('nftables', {}).get(group, {})
            table = block.get('table')
            if table:
                print(family, table)
    elif action == 'compose-image':
        path, image = args
        write(path, {'services': {'crowdsec-web-ui': {'image': image}}})
    elif action == 'ip':
        ipaddress.ip_address(args[0])
    elif action == 'normalize-ip':
        print(ipaddress.ip_address(args[0]))
    elif action == 'url':
        u = urlsplit(args[0])
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or any(c.isspace() for c in args[0]):
            raise ValueError('请输入不含凭据、查询参数的 HTTPS 端点')
    elif action == 'metrics':
        path, = args
        if Path(path+'.local').exists():
            path += '.local'
        data = read(path)
        data.setdefault('prometheus', {}).update(enabled=True, level='full', listen_addr='127.0.0.1', listen_port=6060)
        write(path, data)
    elif action == 'wal':
        path, = args
        effective = merged_config(path)
        if effective.get('db_config', {}).get('type') != 'sqlite':
            raise ValueError('仅适用于 SQLite 数据库')
        if Path(path+'.local').exists():
            path += '.local'
        data = read(path)
        data.setdefault('db_config', {})['use_wal'] = True
        write(path, data)
    elif action == 'whitelist':
        path, ip = args
        ips = ['127.0.0.1', '::1']
        if ip:
            ips.append(str(ipaddress.ip_address(ip)))
        write(path, {'name': 'custom/admin-whitelist', 'description': 'Admin and internal networks', 'whitelist': {'reason': 'Administrator protection', 'ip': ips, 'cidr': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10']}})
    elif action == 'appsec-existing':
        root, own = args
        paths = [str(Path(root)/'acquis.yaml'), *glob.glob(str(Path(root)/'acquis.d/*.yaml')), *glob.glob(str(Path(root)/'acquis.d/*.yml'))]
        for path in paths:
            if path == own or not Path(path).exists():
                continue
            if any(isinstance(d, dict) and d.get('source') == 'appsec' for d in read(path, True)):
                print(path)
    elif action == 'appsec':
        write(args[0], {'source': 'appsec', 'listen_addr': '127.0.0.1:7422', 'appsec_configs': ['crowdsecurity/appsec-default'], 'labels': {'type': 'appsec'}})
    elif action == 'bouncer':
        path, url, key, docker_chain = args
        data = merged_config(path)
        if not isinstance(data, dict) or data.get('mode') not in ('nftables', 'iptables', 'ipset'):
            raise ValueError('请先安装具有有效默认配置的官方 Firewall Bouncer')
        data.update(api_url=url, api_key=key)
        if docker_chain == 'true' and data['mode'] == 'iptables':
            chains = list(data.get('iptables_v4_chains') or data.get('iptables_chains') or ['INPUT'])
            if 'DOCKER-USER' not in chains:
                chains.append('DOCKER-USER')
            data['iptables_v4_chains'] = chains
        # Package defaults remain untouched; local values override them.
        local = Path(path+'.local')
        overrides = read(local) if local.exists() else {}
        overrides.update(api_url=url, api_key=key)
        if docker_chain == 'true' and data['mode'] == 'iptables':
            overrides['iptables_v4_chains'] = data['iptables_v4_chains']
        write(local, overrides)
    elif action == 'compose':
        path, directory, url, machine, password, port = args
        write(path, {'services': {'crowdsec-web-ui': {'image': 'ghcr.io/theduffman85/crowdsec-web-ui:latest', 'container_name': 'crowdsec-web-ui', 'restart': 'unless-stopped', 'network_mode': 'host', 'labels': {'io.crowdsec-1key.managed': 'true'}, 'environment': {'CONFIG_INSTANCE_LAPI_URL': url.rstrip('/'), 'CONFIG_INSTANCE_LAPI_AUTH_USERNAME': machine, 'CONFIG_INSTANCE_LAPI_AUTH_PASSWORD': password, 'CONFIG_INSTANCE_METRICS_URL': 'http://127.0.0.1:6060/metrics', 'CONFIG_SERVER_PORT': port, 'CONFIG_UI_TIME_ZONE': 'Asia/Shanghai', 'CONFIG_UPDATES_ENABLED': 'true'}, 'volumes': [directory+'/data:/app/data']}}})
    elif action == 'telegram':
        path, token, chat, endpoint = args
        if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', token) or not re.fullmatch(r'-?\d+', chat):
            raise ValueError('Bot Token 或 Chat ID 格式错误')
        main(['url', endpoint])
        # Build text first and let toJson escape quotes, newlines and attacker data.
        template = '{{ $text := "CrowdSec 告警" }}\n{{ range . }}\n{{ $text = printf "%s\\n场景: %s" $text (.Scenario | toJson | fromJson) }}\n{{ if .Source }}{{ $text = printf "%s\\n来源: %s" $text (.Source.Value | toJson | fromJson) }}{{ end }}\n{{ range .Decisions }}{{ $text = printf "%s\\n决策: %s / %s" $text (.Type | toJson | fromJson) (.Duration | toJson | fromJson) }}{{ end }}\n{{ end }}\n{{ dict "chat_id" '+json.dumps(chat)+' "text" $text | toJson }}\n'
        write(path, {'type': 'http', 'name': 'crowdsec_1key_telegram', 'log_level': 'info', 'format': template, 'url': endpoint.rstrip('/')+'/bot'+token+'/sendMessage', 'method': 'POST', 'headers': {'Content-Type': 'application/json'}, 'timeout': '10s', 'max_retry': 3})
    elif action == 'profiles':
        path, operation = args
        docs = read(path, True)
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            routes = doc.get('notifications') or []
            if not isinstance(routes, list):
                raise ValueError('notifications 必须为列表')
            if operation == 'enable' and 'crowdsec_1key_telegram' not in routes:
                routes.append('crowdsec_1key_telegram')
            if operation == 'disable':
                routes = [x for x in routes if x != 'crowdsec_1key_telegram']
            if routes:
                doc['notifications'] = routes
            else:
                doc.pop('notifications', None)
        write(path, docs, True)
    elif action == 'web-bouncer':
        path, url = args
        text = Path(path).read_text()
        line = 'APPSEC_URL='+url
        text = re.sub(r'^APPSEC_URL=.*$', line, text, flags=re.M) if re.search(r'^APPSEC_URL=', text, re.M) else text.rstrip()+'\n'+line+'\n'
        fd, tmp = tempfile.mkstemp(dir=Path(path).parent)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        os.replace(tmp, path)
    elif action == 'link-web-bouncer':
        path, state = args
        links = read(state) if Path(state).exists() else {}
        text = Path(path).read_text()
        match = re.search(r'^APPSEC_URL=(.*)$', text, re.M)
        links.setdefault(path, match.group(1) if match else '')
        write(state, links)
        main(['web-bouncer', path, 'http://127.0.0.1:7422'])
    elif action == 'unlink-web-bouncer':
        path, state = args
        links = read(state)
        if path in links:
            main(['web-bouncer', path, links.pop(path)])
            write(state, links)
    elif action == 'link-owned':
        path, state = args
        if path not in read(state):
            raise ValueError('该接入不由本工具管理')
    else:
        raise ValueError('未知配置操作: '+action)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, yaml.YAMLError) as e:
        print('配置处理失败: '+str(e), file=sys.stderr)
        sys.exit(1)

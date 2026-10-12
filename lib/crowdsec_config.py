#!/usr/bin/env python3
"""Structured configuration edits for the CrowdSec manager (Python 3 + PyYAML)."""
import glob
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit

import yaml


def read(path, multiple=False):
    text = Path(path).read_text()
    return list(yaml.safe_load_all(text)) if multiple else yaml.safe_load(text)


def write(path, value, multiple=False, private=False):
    """Atomically replace a file; shell workflow owns backups/rollback."""
    path = Path(path)
    if path.is_file() and read(path, multiple) == value:
        if private:
            path.chmod(0o600)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (yaml.safe_dump_all(value, allow_unicode=True, sort_keys=False)
            if multiple else yaml.safe_dump(value, allow_unicode=True, sort_keys=False))
    fd, tmp = tempfile.mkstemp(prefix='.'+path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            if path.exists():
                metadata = path.stat()
                os.fchown(f.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(f.fileno(), 0o600 if private else stat.S_IMODE(metadata.st_mode))
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


def read_mapping(path):
    data = read(path)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError('配置必须为 mapping: '+str(path))
    return data


def notification_locations(root):
    config = merged_config(str(Path(root)/'config.yaml'))
    profiles = config.get('api', {}).get('server', {}).get('profiles_path', str(Path(root)/'profiles.yaml'))
    directory = config.get('config_paths', {}).get('notification_dir', str(Path(root)/'notifications'))
    for path in [profiles, directory]:
        if not isinstance(path, str) or not Path(path).is_absolute() or any(c in path for c in '\r\n\t'):
            raise ValueError('profiles_path / notification_dir 必须为绝对路径')
    return Path(profiles), Path(directory)/'crowdsec-1key-telegram.yaml'


def merged_config(path):
    data = read_mapping(path)
    def merge(left, right):
        for key, value in right.items():
            if isinstance(value, dict) and isinstance(left.get(key), dict):
                merge(left[key], value)
            else:
                left[key] = value
    local = Path(str(path)+'.local')
    if local.exists():
        merge(data, read_mapping(local))
    return data


def acquisition_locations(root, filename='crowdsec-1key-log-repair.yaml'):
    service = merged_config(str(Path(root)/'config.yaml')).get('crowdsec_service', {})
    if not isinstance(service, dict) or service.get('enable') is False:
        raise ValueError('未启用日志处理服务 crowdsec_service')
    directory = service.get('acquisition_dir')
    single = service.get('acquisition_path')
    if not directory or not Path(directory).is_absolute():
        raise ValueError('请先在 crowdsec_service.acquisition_dir 设置有效的绝对目录')
    if single and not Path(single).is_absolute():
        raise ValueError('acquisition_path 必须为绝对路径')
    repair = Path(directory)/filename
    if repair.is_symlink():
        raise ValueError('修复采集文件是符号链接，请先确认并改为普通文件：'+str(repair))
    return directory, single, repair


def appsec_sources(root):
    directory, single, _ = acquisition_locations(root, 'crowdsec-1key-appsec.yaml')
    paths = ([single] if single else []) + [*glob.glob(glob.escape(directory)+'/*.yaml'),
                                          *glob.glob(glob.escape(directory)+'/*.yml')]
    return [(path, doc) for path in dict.fromkeys(paths) if Path(path).exists()
            for doc in read(path, True) if isinstance(doc, dict) and doc.get('source') == 'appsec']


def docker_bouncer_path(target):
    records = json.load(sys.stdin)
    if not isinstance(records, list):
        raise ValueError('Docker 挂载数据不是列表')
    matches = [record for record in records
               if target == record['Destination'].rstrip('/')
               or target.startswith(record['Destination'].rstrip('/')+'/')]
    if not matches:
        raise ValueError('Web Bouncer 配置没有持久化挂载，请先按官方文档持久化安装')
    record = max(matches, key=lambda r: len(r['Destination'].rstrip('/')))
    if record.get('Type') not in ['bind', 'volume']:
        raise ValueError('Web Bouncer 配置被非持久化挂载遮住，请先配置 bind 或 volume 挂载')
    if not record.get('RW', True):
        raise ValueError('Web Bouncer 配置挂载只读，未修改接入')
    source = Path(record['Source'])
    if not source.is_absolute():
        raise ValueError('Docker 挂载 Source 必须为绝对路径')
    suffix = target[len(record['Destination'].rstrip('/')):].lstrip('/')
    result = source/suffix if suffix else source
    if (any(char in str(result) for char in '\t\r\n') or not result.is_file()
            or any(path.is_symlink() for path in [result, *result.parents])):
        raise ValueError('Web Bouncer 挂载配置必须是可读取的普通文件，且路径不能含制表符或换行')
    local_target = target+'.local'
    overrides = [entry for entry in records if local_target == entry['Destination'].rstrip('/')
                 or local_target.startswith(entry['Destination'].rstrip('/')+'/')]
    if overrides:
        override = max(overrides, key=lambda entry: len(entry['Destination'].rstrip('/')))
        if override.get('Type') not in ('bind', 'volume'):
            raise ValueError('Web Bouncer 覆盖文件被非持久化挂载遮住，未修改接入')
        local = Path(override['Source'])/local_target[len(override['Destination'].rstrip('/')):].lstrip('/')
        if local.exists() and re.search(r'^\s*(?:API_KEY|API_URL|APPSEC_URL)\s*=', local.read_text(), re.M):
            raise ValueError('Web Bouncer .local 覆盖接入地址或凭据，请先手动核对，未修改主配置')
    print(result)


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


def stage_log_repair(root, presets, mounts, destination, discovered=None):
    """Add existing, unacquired HTTP files to a dedicated acquisition file."""
    npm_names = ['*host*_access.log', '*host*_error.log',
                 'fallback_http_access.log', 'fallback_http_error.log',
                 'letsencrypt-requests_access.log', 'letsencrypt-requests_error.log']
    directory, single, original = acquisition_locations(root)
    legacy = Path(directory)/'web-sites.yaml'
    migrate = (legacy.is_file() and not legacy.is_symlink()
               and read(legacy, True) == read(presets, True))
    candidates, hidden, visible = [], set(), set()
    if discovered:
        for line in Path(discovered).read_text().splitlines():
            entry = json.loads(line)
            if entry['kind'] not in ('nginx', 'nginx-proxy-manager'):
                raise ValueError('未知日志类型')
            candidates.append((glob.escape(entry['path']), entry['kind']))
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
        if kind in ['nginx', 'nginx-proxy-manager', 'syslog']:
            candidates.extend((pattern, kind) for pattern in doc.get('filenames', []))

    acquired = {}
    paths = ([single] if single else []) + [*glob.glob(glob.escape(directory)+'/*.yaml'),
                                          *glob.glob(glob.escape(directory)+'/*.yml')]
    for path in paths:
        if migrate and Path(path) == legacy:
            continue
        if not Path(path).exists():
            continue
        for doc in read(path, multiple=True):
            if not doc or doc.get('source', 'file') != 'file':
                continue
            if Path(path) == original and set(doc) <= {'filenames', 'labels'} and isinstance(doc.get('filenames'), list):
                continue
            filenames = doc.get('filenames', [])
            if isinstance(filenames, str):
                filenames = [filenames]
            if doc.get('filename'):
                filenames = [*filenames, doc['filename']]
            for pattern in filenames:
                for filename in go_glob(pattern):
                    acquired[os.path.realpath(filename)] = doc.get('labels', {}).get('type')

    docs = [doc for doc in read(original, multiple=True) if doc] if original.exists() else []
    removed = 0
    for doc in docs:
        if set(doc) <= {'filenames', 'labels'} and isinstance(doc.get('filenames'), list):
            retained = []
            for pattern in doc['filenames']:
                matches = go_glob(pattern)
                if matches and all(os.path.realpath(filename) in acquired for filename in matches):
                    removed += len(matches)
                    continue
                retained.append(pattern)
                for filename in matches:
                    acquired[os.path.realpath(filename)] = doc.get('labels', {}).get('type')
            doc['filenames'] = retained
    docs = [doc for doc in docs if not (set(doc) <= {'filenames', 'labels'} and doc.get('filenames') == [])]
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

    count = sum(len(names) for names in additions.values()) + removed
    if count or migrate:
        for kind, names in additions.items():
            for doc in docs:
                if set(doc) <= {'filenames', 'labels'} and doc.get('labels') == {'type': kind} and isinstance(doc.get('filenames'), list):
                    doc['filenames'].extend(names)
                    break
            else:
                docs.append({'filenames': names, 'labels': {'type': kind}})
        write(destination, docs, multiple=True)
        if migrate:
            Path(str(destination)+'.migrate-presets').write_text(str(legacy))
            count = max(1, count)
        if removed:
            print(f'[INFO] 移除本工具修复文件中的重复采集：{removed} 项', file=sys.stderr)
    print(count)


def main(args):
    action, *args = args
    if action == 'get':
        get(*args)
    elif action == 'notification-paths':
        profiles, notification = notification_locations(args[0])
        print(notification)
        print(profiles)
    elif action == 'repair-log-acquis':
        stage_log_repair(*args)
    elif action == 'log-acquis-file':
        print(acquisition_locations(args[0], 'web-sites.yaml')[2])
    elif action == 'log-repair-file':
        print(acquisition_locations(args[0])[2])
    elif action == 'web-log-file':
        print(acquisition_locations(args[0], 'web-sites.yaml')[2])
    elif action == 'bouncer-mode':
        print(merged_config(args[0]).get('mode') or '')
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
        port = merged_config(path).get('prometheus', {}).get('listen_port', 6060)
        if Path(path+'.local').exists():
            path += '.local'
        data = read_mapping(path)
        data.setdefault('prometheus', {}).update(enabled=True, level='full', listen_addr='127.0.0.1', listen_port=port)
        write(path, data)
    elif action == 'wal':
        path, = args
        effective = merged_config(path)
        if effective.get('db_config', {}).get('type') != 'sqlite':
            raise ValueError('仅适用于 SQLite 数据库')
        if Path(path+'.local').exists():
            path += '.local'
        data = read_mapping(path)
        data.setdefault('db_config', {})['use_wal'] = True
        write(path, data)
    elif action == 'whitelist':
        path, ip = args
        ips = ['127.0.0.1', '::1']
        if ip:
            ips.append(str(ipaddress.ip_address(ip)))
        data = read(path) if Path(path).exists() else {'name': 'custom/admin-whitelist', 'description': 'Admin and internal networks'}
        rules = data.setdefault('whitelist', {})
        rules.setdefault('reason', 'Administrator protection')
        rules['ip'] = list(dict.fromkeys([*rules.get('ip', []), *ips]))
        rules['cidr'] = list(dict.fromkeys([*rules.get('cidr', []), '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10']))
        write(path, data)
    elif action == 'appsec-existing':
        root, own = args
        for path, _ in appsec_sources(root):
            if path != own:
                print(path)
    elif action == 'appsec-file':
        print(acquisition_locations(args[0], 'crowdsec-1key-appsec.yaml')[2])
    elif action == 'appsec-listeners':
        for path, doc in appsec_sources(args[0]):
            address = doc.get('listen_addr')
            if not address or not isinstance(address, str) or any(c in address for c in '\r\n\t'):
                raise ValueError('AppSec listen_addr 无效：'+path)
            print(address)
    elif action == 'docker-bouncer-path':
        docker_bouncer_path(args[0])
    elif action == 'appsec-web-hooks':
        text = sys.stdin.read()
        if re.search(r'\b(?:cs|crowdsec)\.Allow\s*\(', text):
            print('crowdsec')
        if re.search(r'access_by_lua_file\s+[^;]*1pwaf/', text):
            print('1pwaf')
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
        overrides = read_mapping(local) if local.exists() else {}
        overrides.update(api_url=url, api_key=key)
        if docker_chain == 'true' and data['mode'] == 'iptables':
            overrides['iptables_v4_chains'] = data['iptables_v4_chains']
        write(local, overrides, private=True)
    elif action == 'compose':
        path, directory, url, machine, password, port, *images = args
        image = images[0] if images else 'ghcr.io/theduffman85/crowdsec-web-ui:latest'
        health_script = ("require('http').get('http://127.0.0.1:"+port+
                         "/api/health',r=>process.exit(r.statusCode===200?0:1))"
                         ".on('error',()=>process.exit(1))")
        write(path, {'services': {'crowdsec-web-ui': {
            'image': image,
            'container_name': 'crowdsec-web-ui',
            'restart': 'unless-stopped',
            'network_mode': 'host',
            'labels': {'io.crowdsec-1key.managed': 'true'},
            'environment': {
                'CONFIG_INSTANCE_LAPI_URL': url.rstrip('/'),
                'CONFIG_INSTANCE_LAPI_AUTH_USERNAME': machine,
                'CONFIG_INSTANCE_LAPI_AUTH_PASSWORD': password,
                'CONFIG_INSTANCE_METRICS_URL': images[1] if len(images) > 1 else 'http://127.0.0.1:6060/metrics',
                'CONFIG_SERVER_PORT': port,
                'CONFIG_AUTH_ENABLED': 'true',
                'CONFIG_UI_TIME_ZONE': 'Asia/Shanghai',
                'CONFIG_UPDATES_ENABLED': 'true',
            },
            'healthcheck': {
                'test': ['CMD', 'node', '-e', health_script],
                'interval': '10s', 'timeout': '5s', 'retries': 6,
                'start_period': '30s',
            },
            'volumes': [directory+'/data:/app/data'],
        }}}, private=True)
    elif action == 'telegram':
        path, token, chat, endpoint = args
        if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', token) or not re.fullmatch(r'-?\d+', chat):
            raise ValueError('Bot Token 或 Chat ID 格式错误')
        main(['url', endpoint])
        # Build text first and let toJson escape quotes, newlines and attacker data.
        template = '{{ $text := "CrowdSec 告警" }}\n{{ range . }}\n{{ $text = printf "%s\\n场景: %s" $text (.Scenario | toJson | fromJson) }}\n{{ if .Source }}{{ $text = printf "%s\\n来源: %s" $text (.Source.Value | toJson | fromJson) }}{{ end }}\n{{ range .Decisions }}{{ $text = printf "%s\\n决策: %s / %s" $text (.Type | toJson | fromJson) (.Duration | toJson | fromJson) }}{{ end }}\n{{ end }}\n{{ dict "chat_id" '+json.dumps(chat)+' "text" $text | toJson }}\n'
        write(path, {'type': 'http', 'name': 'crowdsec_1key_telegram', 'log_level': 'info', 'format': template, 'url': endpoint.rstrip('/')+'/bot'+token+'/sendMessage', 'method': 'POST', 'headers': {'Content-Type': 'application/json'}, 'timeout': '10s', 'max_retry': 3}, private=True)
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
    elif action in ['web-bouncer', 'stage-web-bouncer']:
        path, url, *destination = args
        text = Path(path).read_text()
        line = 'APPSEC_URL='+url
        text = re.sub(r'^APPSEC_URL=.*$', line, text, flags=re.M) if re.search(r'^APPSEC_URL=', text, re.M) else text.rstrip()+'\n'+line+'\n'
        target = Path(destination[0]) if destination else Path(path)
        if target.is_file() and target.read_text() == text:
            return
        fd, tmp = tempfile.mkstemp(dir=target.parent)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        if target.exists():
            metadata = target.stat()
            os.chmod(tmp, metadata.st_mode & 0o777)
            os.chown(tmp, metadata.st_uid, metadata.st_gid)
        os.replace(tmp, target)
    elif action == 'link-docker-bouncer':
        path, state, container, target, name, *managed = args
        managed_url = managed[0] if managed else 'http://127.0.0.1:7422'
        links = read(state) if Path(state).exists() else {}
        if path in links:
            if links[path].get('name', links[path]['container']) != name:
                raise ValueError('该配置已有其他容器的接入记录，请先停用原接入')
            main(['docker-link-current', path, state])
        match = re.search(r'^APPSEC_URL=(.*)$', Path(path).read_text(), re.M)
        links.setdefault(path, {'container': container, 'target': target, 'name': name,
                                'previous_url': match.group(1) if match else ''})
        links[path].update(container=container, name=name, target=target, managed_url=managed_url)
        if len(managed) > 1:
            links[path]['transport'] = json.loads(Path(managed[1]).read_text())
        elif links[path].get('transport'):
            raise ValueError('原私有接入记录仍存在，不能直接切换为 host 接入')
        write(state, links)
    elif action == 'docker-link-current':
        expected = read(args[1])[args[0]].get('managed_url', 'http://127.0.0.1:7422') if len(args) > 1 else 'http://127.0.0.1:7422'
        if re.findall(r'^APPSEC_URL=(.*)$', Path(args[0]).read_text(), re.M) != [expected]:
            raise ValueError('Web Bouncer 的 APPSEC_URL 已被手工修改，请先核对接入；未覆盖配置')
    elif action == 'docker-link-private':
        if not read(args[1])[args[0]].get('transport'):
            raise ValueError('此接入未记录私有网络')
    elif action == 'docker-link-owned':
        if args[0] not in read(args[1]):
            raise ValueError('该容器接入不由本工具管理')
    elif action == 'docker-appsec-links':
        for path, link in read(args[0]).items():
            if any(c in path+link['container']+link['target'] for c in '\t\r\n'):
                raise ValueError('容器接入记录无效')
            name = link.get('name', link['container'])
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', name):
                raise ValueError('容器接入记录中的名称无效')
            print(name+'\t'+path+'\t'+link['target'])
    elif action == 'restore-docker-bouncer':
        path, state, destination = args
        link = read(state)[path]
        main(['stage-web-bouncer', path, link['previous_url'], destination])
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

#!/usr/bin/env python3
"""Bounded read-only inventory. Raw configuration and credentials never leave it."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from crowdbastion_health import acquisition_state, parse_acquisition_metrics

LIMIT = 1024 * 1024


def read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ValueError('unreadable configuration')
        return stream.read(LIMIT + 1)


def run_command(args, timeout):
    # Files bound in-memory output even for a large nginx -T or broken daemon.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        output.seek(0)
        data = output.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError('probe output too large')
        return subprocess.CompletedProcess(args, result.returncode, data.decode('utf-8', errors='replace'), '')


class Probes:
    def __init__(self, budget, runner):
        self.deadline = time.monotonic() + max(0, budget)
        self.runner = runner or run_command
        self.limitations = []

    def command(self, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            if '快速检查时间已用完；未检查项目保持未知' not in self.limitations:
                self.limitations.append('快速检查时间已用完；未检查项目保持未知')
            return None
        try:
            result = self.runner(list(args), min(2.0, remaining))
            if len(result.stdout or '') > LIMIT:
                raise ValueError('large output')
            return result
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.limitations.append(f'{args[0]} 检查未完成')
            return None

    def service(self, unit):
        result = self.command('systemctl', 'show', unit, '--property=LoadState,ActiveState')
        if result is None or result.returncode:
            return 'unknown'
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if values.get('LoadState') == 'not-found':
            return 'missing'
        if values.get('LoadState') != 'loaded':
            return 'unknown'
        return {'active': 'ok', 'inactive': 'fault', 'failed': 'fault'}.get(values.get('ActiveState'), 'unknown')

    def check(self, args, failure='unknown'):
        result = self.command(*args)
        if result is None or result.returncode == 127:
            return 'unknown'
        return 'ok' if result.returncode == 0 else failure


def _exists(path):
    return path.exists() or path.is_symlink()


def _registry(path, limitations):
    if not _exists(path):
        return {}
    try:
        value = json.loads(read_file(path))
        if not isinstance(value, dict):
            raise ValueError('invalid registry')
        return value
    except (OSError, ValueError):
        limitations.append('已有网站登记无法读取，需核对后再修改')
        return {}


def _configuration_roots(cs_dir, host_root):
    return [cs_dir, host_root/'etc/nginx', host_root/'etc/openresty',
            host_root/'usr/share/nginx/modules-available',
            host_root/'usr/local/openresty/nginx/conf', host_root/'etc/V2bX',
            host_root/'usr/local/lib/crowdsec-v2bx-observer/config.json']


def _listener_identity(address):
    if not isinstance(address, str) or any(c in address for c in '\r\n\t'):
        raise ValueError('invalid AppSec listener')
    match = re.fullmatch(r'\[([^\]]+)\]:(\d+)', address)
    if match:
        host, port = match.groups()
    else:
        host, port = address.rsplit(':', 1)
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError('invalid AppSec listener port')
    host = str(ipaddress.ip_address(host)) if host not in ('', '*') else '*'
    return host, int(port)


def _parse_active_acquisitions(cs_dir, deadline=None):
    """Resolve the existing YAML setup without making YAML a fresh-host dependency."""
    result = dict(appsec=None, paths=[], appsec_files=[], listeners=[], guard_complete=False)
    config = cs_dir/'config.yaml'
    if not _exists(config):
        result.update(appsec=False, guard_complete=True)
        return result
    try:
        if deadline is not None and time.monotonic() >= deadline:
            raise ValueError('acquisition discovery budget expired')
        import yaml
        from crowdsec_config import acquisition_locations, appsec_sources, merged_config
        total = 0

        def preflight(path):
            nonlocal total
            if deadline is not None and time.monotonic() >= deadline:
                raise ValueError('acquisition discovery budget expired')
            path = Path(path)
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022):
                raise ValueError('unsafe acquisition configuration')
            data = read_file(path)
            total += len(data)
            if total > 8 * LIMIT:
                raise ValueError('acquisition byte budget exceeded')
            return data

        preflight(config)
        if _exists(Path(str(config)+'.local')):
            preflight(Path(str(config)+'.local'))
        data = merged_config(str(config))
        service = data.get('crowdsec_service', {})
        # Legacy minimal inventories have no explicit acquisition references.
        # Their file guard remains useful, but AppSec presence stays unknown.
        if isinstance(service, dict) and not service.get('acquisition_dir') and not service.get('acquisition_path'):
            result['guard_complete'] = True
            return result
        directory, single, _ = acquisition_locations(cs_dir, 'crowdsec-1key-appsec.yaml')
        directory = Path(directory)
        result['paths'] = [directory] + ([Path(single)] if single else [])
        if any('..' in path.parts for path in result['paths']):
            raise ValueError('unsafe acquisition parent traversal')
        if directory.is_symlink() or (_exists(directory) and not directory.is_dir()):
            raise ValueError('unsafe acquisition directory')
        files = ([Path(single)] if single and _exists(Path(single)) else [])
        if directory.exists():
            files.extend(sorted(path for path in directory.iterdir() if path.suffix in ('.yaml', '.yml')))
        files = list(dict.fromkeys(files))
        if len(files) > 512:
            raise ValueError('too many acquisition files')
        for path in files:
            documents = yaml.safe_load_all(preflight(path))
            if any(doc is not None and not isinstance(doc, dict) for doc in documents):
                raise ValueError('invalid acquisition document')
        documents = appsec_sources(cs_dir)
        listeners = sorted({_listener_identity(doc.get('listen_addr')) for _, doc in documents})
        if deadline is not None and time.monotonic() >= deadline:
            raise ValueError('acquisition discovery budget expired')
        result.update(appsec=bool(documents), appsec_files=sorted({Path(path) for path, _ in documents}),
                      listeners=listeners, guard_complete=True)
    except ImportError:
        pass
    except (OSError, TypeError, ValueError, RuntimeError):
        pass
    except yaml.YAMLError:
        pass
    return result


def _active_acquisitions(cs_dir, deadline=None):
    """Bound optional YAML parsing as well as system commands by the shared budget."""
    unknown = dict(appsec=None, paths=[], appsec_files=[], listeners=[], guard_complete=False)
    if not _exists(cs_dir/'config.yaml'):
        return dict(unknown, appsec=False, guard_complete=True)
    remaining = min(2.0, deadline-time.monotonic()) if deadline is not None else 2.0
    if remaining <= 0:
        return unknown
    parse_deadline = time.monotonic()+remaining
    script = ('import json,pathlib,sys;sys.path.insert(0,sys.argv[1]);'
              'from crowdbastion_flow_probe import _parse_active_acquisitions;'
              'print(json.dumps(_parse_active_acquisitions(pathlib.Path(sys.argv[2]),float(sys.argv[3])),default=str))')
    args = [sys.executable] + (['-S'] if sys.flags.no_site else [])
    args += ['-c', script, str(Path(__file__).parent), str(cs_dir), str(parse_deadline)]
    try:
        result = run_command(args, remaining)
        if result.returncode:
            return unknown
        data = json.loads(result.stdout)
        for key in ('paths', 'appsec_files'):
            data[key] = [Path(path) for path in data[key]]
        data['listeners'] = [tuple(listener) for listener in data['listeners']]
        return data
    except (OSError, TypeError, ValueError, subprocess.TimeoutExpired):
        return unknown


def _configuration_with_acquisitions(roots, acquisitions):
    return roots + [path for path in acquisitions['paths']
                    if not any(path.is_relative_to(root) for root in roots)]


def _stream_configuration(path, digest, remaining, deadline):
    """Hash regular trusted files without raising the text/JSON probe memory limit."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid())
                or before.st_mode & 0o022 or before.st_size > remaining):
            raise ValueError('unsafe or over-budget configuration')
        size = 0
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise ValueError('configuration budget expired')
            chunk = stream.read(min(65536, remaining-size+1))
            if not chunk:
                break
            size += len(chunk)
            if size > remaining:
                raise ValueError('configuration byte budget exceeded')
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('configuration changed while hashing')
        return size


def _fingerprint_paths(paths, allowed, deadline=None, excluded=()):
    digest = hashlib.sha256(b'crowdbastion-flow-validator-v1\0')
    complete = True
    count = 0
    total = 0
    for root in paths:
        if deadline is not None and time.monotonic() >= deadline:
            return digest.hexdigest(), False
        digest.update(str(root).encode())
        if not _exists(root):
            digest.update(b'absent\0')
            continue
        try:
            if root.is_dir() and not root.is_symlink():
                entries = os.walk(root, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e))
            else:
                entries = [(root.parent, [], [root.name])]
            for base, dirs, files in entries:
                if deadline is not None and time.monotonic() >= deadline:
                    return digest.hexdigest(), False
                dirs[:] = sorted(d for d in dirs if d != '__pycache__' and Path(base)/d not in excluded)
                for name in sorted(files + [d for d in dirs if (Path(base)/d).is_symlink()]):
                    count += 1
                    if count > 512 or total > 8 * LIMIT or (deadline is not None and time.monotonic() >= deadline):
                        return digest.hexdigest(), False
                    path = Path(base)/name
                    digest.update(str(path).encode() + b'\0')
                    try:
                        if path.is_symlink():
                            digest.update(os.fsencode(os.readlink(path)))
                            resolved = path.resolve(strict=True)
                            if not any(resolved.is_relative_to(parent) for parent in allowed):
                                raise ValueError('external config link')
                            source = resolved
                        else:
                            source = path
                        total += _stream_configuration(source, digest, 8 * LIMIT-total, deadline)
                    except (OSError, RuntimeError, ValueError):
                        complete = False
                    digest.update(b'\0')
        except (OSError, ValueError):
            complete = False
    return digest.hexdigest(), complete


def config_fingerprint(cs_dir, host_root=None, deadline=None, acquisitions=None):
    """Bounded active-config guard; Hub cache is rebuildable, enabled links are hashed."""
    cs_dir = Path(cs_dir)
    host_root = Path(host_root) if host_root is not None else cs_dir.parent.parent
    acquisitions = acquisitions if acquisitions is not None else _active_acquisitions(cs_dir, deadline)
    roots = _configuration_with_acquisitions(_configuration_roots(cs_dir, host_root), acquisitions)
    # Explicit acquisition inputs remain active even under the otherwise
    # rebuildable Hub tree, so the cache exclusion must not hide them.
    roots += [path for path in acquisitions['paths'] if path.is_relative_to(cs_dir/'hub') and path not in roots]
    # The downloaded Hub tree is not active configuration. Its enabled symlink
    # targets are still streamed by the traversal of parsers/scenarios/collections.
    if any(root.is_symlink() for root in roots):
        return hashlib.sha256(b'unsafe configuration root').hexdigest(), False
    modules = host_root/'usr/share/nginx/modules-available'
    if _exists(modules):
        from crowdbastion_ux import validate_private_destination
        try:
            validate_private_destination(modules/'.crowdbastion-probe')
        except (OSError, ValueError):
            return hashlib.sha256(b'unsafe module configuration directory').hexdigest(), False
    value, complete = _fingerprint_paths(roots, roots, deadline, excluded=(cs_dir/'hub',))
    return value, complete and acquisitions['guard_complete']


def _component_fingerprints(cs_dir, host_root, deadline, acquisitions=None):
    acquisitions = acquisitions if acquisitions is not None else _active_acquisitions(cs_dir, deadline)
    roots = _configuration_with_acquisitions(_configuration_roots(cs_dir, host_root), acquisitions)
    groups = {
        'core': [cs_dir/name for name in ('config.yaml', 'config.yaml.local', 'local_api_credentials.yaml',
                                         'online_api_credentials.yaml', 'simulation.yaml', 'contexts', 'patterns',
                                         'parsers', 'scenarios', 'postoverflows', 'collections', 'acquis.yaml', 'acquis.d')],
        'firewall': [cs_dir/'bouncers'/name for name in ('crowdsec-firewall-bouncer.yaml',
                    'crowdsec-firewall-bouncer.yaml.local', 'crowdsec-firewall-bouncer.yaml.remote.json')],
        'appsec': [cs_dir/name for name in ('appsec-configs', 'appsec-rules')],
        'proxy': [host_root/'etc/V2bX/config.json', host_root/'usr/local/lib/crowdsec-v2bx-observer/config.json'],
    }
    groups['core'] = _configuration_with_acquisitions(groups['core'], acquisitions)
    groups['appsec'] += acquisitions['appsec_files']
    result = {}
    for kind, paths in groups.items():
        if ((kind == 'appsec' and acquisitions['appsec'] is None)
                or (kind == 'core' and not acquisitions['guard_complete'])):
            result[kind] = None
            continue
        value, complete = _fingerprint_paths(paths, roots, deadline)
        if kind == 'appsec' and complete:
            locations = json.dumps([str(path) for path in acquisitions['paths']], separators=(',', ':'))
            value = hashlib.sha256((value+'\0'+locations).encode()).hexdigest()
        result[kind] = value if complete else None
    return result


def _target(identity, label, runtime, network, effective, owned=False, connected=False, transport=False):
    return dict(id=identity, label=label, runtime=runtime, network=network, owned=owned,
                connected=connected, transport=transport,
                config_hash=hashlib.sha256(effective.encode()).hexdigest(),
                realip='unknown', request_verification='pending', web_logs='unknown',
                server_names=[], integration_hash=None)


def _web_rules(probes):
    result = probes.command('cscli', 'collections', 'list', '-o', 'json')
    if result is None or result.returncode:
        return 'unknown'
    try:
        data = json.loads(result.stdout)
        items = data.get('collections') if isinstance(data, dict) else data
        if not isinstance(items, list) or any(not isinstance(item, dict) or not isinstance(item.get('name'), str) for item in items):
            return 'unknown'
        required = {'crowdsecurity/nginx', 'crowdsecurity/base-http-scenarios'}
        enabled = {item['name'] for item in items if isinstance(item.get('status'), str)
                   and item['status'].strip() == 'enabled'}
        return 'ok' if required <= enabled else 'missing'
    except (TypeError, ValueError):
        return 'unknown'


def _appsec_listener_state(listeners, probes):
    result = probes.command('ss', '-H', '-lnt')
    if result is None or result.returncode or not listeners:
        return 'unknown'
    observed = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            observed.add(_listener_identity(fields[3]))
        except ValueError:
            continue
    def present(listener):
        if listener in observed:
            return True
        host, port = listener
        return host == '*' and any(other_port == port and (other_host == '*' or ipaddress.ip_address(other_host).is_unspecified)
                                   for other_host, other_port in observed)
    return 'ok' if all(present(listener) for listener in listeners) else 'unknown'


def _web_evidence(target, effective, sources, mounts=None):
    from crowdsec_realip_diagnose import http_directives
    from crowdsec_web import mount_path
    paths, uncertain = set(), False
    names = set()
    for context, words, _ in http_directives(effective):
        if not words or 'stream' in context:
            continue
        if words[0] == 'server_name':
            names.update(words[1:])
        if words[0] != 'access_log' or len(words) < 2:
            continue
        path = words[1]
        if path == 'off':
            continue
        if not path.startswith('/') or '$' in path or path.startswith('/dev/') or '..' in Path(path).parts:
            uncertain = True
            continue
        if target['runtime'] == 'docker':
            try:
                # Reading metrics does not require a writable mount.
                path, _ = mount_path(path, [{**item, 'RW': True} for item in mounts or []])
            except (KeyError, TypeError, ValueError):
                uncertain = True
                continue
        paths.add(path)
    target['server_names'] = sorted(names)
    if sources is None or not paths:
        return target
    matched = {path: sources.get('file:'+path, sources.get(path)) for path in paths}
    available = {path: value for path, value in matched.items() if value is not None}
    state = acquisition_state(available) if available else 'pending'
    if state == 'fault':
        target['web_logs'] = 'fault'
    elif any(value is None for value in matched.values()):
        target['web_logs'] = 'missing'
    elif not uncertain:
        target['web_logs'] = state
    return target


def _integration_fingerprint(target, cs_dir, installs, transport, deadline, mounts=None):
    """Hash only this runtime's registration and Bouncer settings; never emit secrets."""
    roots = _configuration_roots(cs_dir, cs_dir.parent.parent)
    paths, registration = [], {}
    try:
        if target['runtime'] == 'docker':
            name = target['label']
            registration = {'install': installs.get(name), 'transport': transport.get(name)}
            for registry in ('crowdsec-1key-web-installs.json', 'crowdsec-1key-docker-endpoints.json'):
                if _exists(cs_dir/registry) and not isinstance(json.loads(read_file(cs_dir/registry)), dict):
                    return None
            entry = installs.get(name)
            if entry:
                from crowdsec_web import mount_path
                remote = entry['container_assets']+'/bouncer.conf'
                local, _ = mount_path(remote, [{**item, 'RW': True} for item in mounts or []])
                if Path(local) != Path(entry['host_assets'])/'bouncer.conf':
                    return None
                paths = [Path(local), Path(local+'.local')]
                roots.append(Path(entry['host_assets']))
        else:
            service = target['runtime']
            config = cs_dir/f'bouncers/crowdsec-{service}-bouncer.conf'
            paths = [config, Path(str(config)+'.local')]
            links = cs_dir/'crowdsec-1key-appsec-links.yaml'
            if _exists(links):
                import yaml
                try:
                    data = yaml.safe_load(read_file(links))
                except yaml.YAMLError:
                    return None
                if not isinstance(data, dict):
                    return None
                registration = {'appsec': data.get(str(config))}
        value, complete = _fingerprint_paths(paths, roots, deadline)
        if not complete:
            return None
        return hashlib.sha256((value+'\0'+json.dumps(registration, sort_keys=True, separators=(',', ':'))).encode()).hexdigest()
    except (ImportError, OSError, KeyError, TypeError, ValueError):
        return None


def _appsec_connected(target, cs_dir, mounts, acquisitions, appsec_state, installs, transport, deadline):
    """Request/IP audit proves the hook; AppSec additionally needs its actual endpoint."""
    if (time.monotonic() >= deadline or appsec_state != 'ok' or not acquisitions
            or acquisitions.get('appsec') is not True or not target.get('transport')):
        return False
    try:
        from urllib.parse import urlsplit
        from crowdsec_appsec import config
        from crowdsec_web import mount_path
        from crowdbastion_ux import validate_private_destination
        local_mount = None
        if target['runtime'] == 'docker':
            entry = (installs or {}).get(target['label'])
            if not isinstance(entry, dict) or entry.get('status') != 'installed':
                return False
            remote = entry['container_assets']+'/bouncer.conf'
            readable = [{**mount, 'RW': True} for mount in mounts or []]
            main, _ = mount_path(remote, readable)
            if Path(main) != Path(entry['host_assets'])/'bouncer.conf':
                return False
            local, local_mount = mount_path(remote+'.local', readable)
        else:
            main = cs_dir/f'bouncers/crowdsec-{target["runtime"]}-bouncer.conf'
            local = str(main)+'.local'
        def settings(path):
            if time.monotonic() >= deadline:
                raise ValueError('AppSec connection budget expired')
            validate_private_destination(Path(path))
            if len(read_file(path)) > LIMIT:
                raise ValueError('large Bouncer settings')
            return config(path)
        values = settings(main)
        if _exists(Path(local)):
            values.update(settings(local))
        elif local_mount and local_mount['Destination'].rstrip('/') == remote+'.local':
            return False
        def endpoint(value):
            parsed = urlsplit(value)
            if (parsed.scheme != 'http' or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ('', '/') or not parsed.port):
                raise ValueError('invalid AppSec URL')
            return str(ipaddress.ip_address(parsed.hostname or '')), parsed.port
        current = endpoint(values.get('APPSEC_URL', ''))
        listeners = acquisitions['listeners']
        if target['network'] != 'host':
            registered = (transport or {}).get(target['label'])
            return (isinstance(registered, dict) and current == endpoint(registered.get('appsec_url', ''))
                    and current in listeners)
        if current in listeners:
            return True
        address = ipaddress.ip_address(current[0])
        return address.is_loopback and any(port == current[1] and host != '*'
                    and ipaddress.ip_address(host).version == address.version
                    and ipaddress.ip_address(host).is_unspecified for host, port in listeners)
    except (OSError, TypeError, ValueError, KeyError):
        return False


def _audit_target(target, effective, cs_dir, probes, mounts=None, acquisitions=None,
                  appsec_state='unknown', installs=None, transport=None):
    if not target['owned']:
        return target
    with tempfile.TemporaryDirectory(prefix='crowdbastion-web-evidence-') as directory:
        work = Path(directory)
        (work/'effective').write_text(effective)
        (work/'mounts').write_text(json.dumps(mounts or []))
        (work/'events').touch(mode=0o600)
        helper = Path(__file__).with_name('crowdsec_request_audit.py')
        if target['runtime'] == 'docker':
            args = ['status', str(cs_dir/'crowdsec-1key-ip-verifications.json'), target['label'],
                    str(work/'effective'), str(cs_dir/'crowdsec-1key-web-installs.json'), str(work/'mounts')]
        else:
            service = target['runtime']
            args = ['status-host', str(cs_dir/'crowdsec-1key-ip-verifications.json'), target['id'],
                    str(work/'effective'), str(cs_dir/'crowdsec-1key-appsec-links.yaml'), str(work/'mounts'),
                    str(cs_dir/f'bouncers/crowdsec-{service}-bouncer.conf')]
        result = probes.command('env', 'CROWDBASTION_HEALTH_EVENTS='+str(work/'events'), sys.executable, str(helper), *args)
        records = (work/'events').read_text().splitlines()
        audited = result is not None and result.returncode in (0, 2) and 'web\tok' in records and 'web\tunknown' not in records
        if audited and result.returncode == 0:
            target['realip'] = 'verified'
        target['connected'] = audited and _appsec_connected(target, cs_dir, mounts, acquisitions, appsec_state,
                                                           installs, transport, probes.deadline)
    return target


def _audit_transport(item, name, registry, probes):
    if item.get('HostConfig', {}).get('NetworkMode') == 'host':
        return True
    if name not in registry:
        return False
    try:
        from crowdsec_transport import plan
        entry = registry[name]
        identities = sorted({n['NetworkID'] for n in item['NetworkSettings']['Networks'].values()})
        if not identities or any(not re.fullmatch(r'[0-9a-f]{64}', n) for n in identities):
            return False
        networks = probes.command('docker', 'network', 'inspect', *identities)
        if networks is None or networks.returncode:
            return False
        current = plan(item, json.loads(networks.stdout), entry['api_url'], entry['appsec_url'])
        if current != entry:
            return False
        sockets = probes.command('ss', '-H', '-lnt')
        if sockets is None or sockets.returncode:
            return False
        addresses = {line.split()[3] for line in sockets.stdout.splitlines() if len(line.split()) >= 4}
        if any(current[k].removeprefix('http://') not in addresses for k in ('api_url', 'appsec_url')):
            return False
        for key, suffix in (('api_url', '/v1/decisions'), ('appsec_url', '/')):
            result = probes.command('docker', 'exec', item['Id'], 'curl', '-sS', '--noproxy', '*',
                                    '--connect-timeout', '1', '--max-time', '2', '-o', '/dev/null', '-w', '%{http_code}',
                                    current[key].rstrip('/')+suffix)
            if result is None or result.returncode:
                return False
            code = result.stdout.strip()
            if (key == 'api_url' and code not in ('401', '403')) or (key == 'appsec_url' and not re.fullmatch(r'[234][0-9]{2}', code)):
                return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def _validated_timestamp(value):
    # Compare integers before any float conversion, including giant JSON ints.
    # This also rejects NaN/infinity and excludes bool's integer subclassing.
    if type(value) not in (int, float) or not 0 <= value <= 253402300799:
        raise ValueError('invalid timestamp')
    return value


def _pending_inventory(state_dir, deadline):
    """An incomplete recovery inventory must never authorize another change."""
    from crowdbastion_ux import validate_private_destination
    pending, complete = [], True

    def budget():
        if time.monotonic() >= deadline:
            raise ValueError('pending inventory budget expired')

    def directory(path):
        validate_private_destination(path/'scan', missing_parents=True)
        return _exists(path)

    total = 0
    def record(path):
        nonlocal total
        budget()
        validate_private_destination(path)
        data = read_file(path)
        total += len(data)
        if len(data) > LIMIT or total > 8 * LIMIT:
            raise ValueError('pending inventory byte budget exceeded')
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError('duplicate transaction field')
                value[key] = item
            return value
        def invalid_constant(_):
            raise ValueError('nonfinite transaction value')
        value = json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)
        if not isinstance(value, dict):
            raise ValueError('invalid transaction record')
        budget()
        return value

    migration = state_dir/'firewall-migration'
    try:
        if directory(migration):
            budget()
            terminal = False
            for name in ('committed', 'rolled-back'):
                marker = migration/name
                validate_private_destination(marker)
                terminal = _exists(marker) or terminal
            if not terminal:
                pending.append({'kind': 'firewall', 'state': 'migration_pending'})
            budget()
    except (OSError, ValueError, RuntimeError):
        complete = False

    tx_root = state_dir/'changes'
    try:
        if not directory(tx_root):
            return pending, complete
        budget()
        states = {'arming', 'applying', 'staged', 'verified', 'rolling_back',
                  'rollback_incomplete', 'committed', 'rolled_back'}
        transaction_count = 0
        with os.scandir(tx_root) as entries:
            for count, entry in enumerate(entries, 1):
                budget()
                if count > 130:  # 128 transactions plus the two engine metadata files.
                    raise ValueError('pending inventory entry budget exceeded')
                path = Path(entry.path)
                if entry.name == '.lock':
                    validate_private_destination(path)
                    continue
                if entry.name == '.crowdbastion-managed':
                    marker = record(path)
                    if (set(marker) != {'version'} or type(marker['version']) is not int or marker['version'] != 1
                            or tx_root.stat().st_mode & 0o077):
                        raise ValueError('invalid transaction ownership marker')
                    continue
                if not re.fullmatch(r'[0-9a-f]{32}', entry.name) or not entry.is_dir(follow_symlinks=False):
                    raise ValueError('unsafe transaction directory')
                transaction_count += 1
                if transaction_count > 128:
                    raise ValueError('pending transaction count exceeded')
                manifest = record(path/'manifest.json')
                journal = record(path/'journal.json')
                kind, state = manifest.get('kind'), journal.get('state')
                if kind not in ('network', 'port-policy') or not isinstance(state, str) or state not in states:
                    raise ValueError('invalid transaction kind or state')
                for value in (manifest, journal):
                    if 'version' in value and (type(value['version']) is not int or value['version'] != 1):
                        raise ValueError('invalid transaction version')
                if 'id' in manifest and manifest['id'] != entry.name:
                    raise ValueError('invalid transaction identity')
                if 'effects' in manifest and (not isinstance(manifest['effects'], list)
                        or any(not isinstance(effect, dict) or set(effect) != {'resource', 'before', 'after'}
                               for effect in manifest['effects'])):
                    raise ValueError('invalid transaction effects')
                if 'items' in journal and (not isinstance(journal['items'], list)
                        or any(not isinstance(item, str) or item not in ('planned', 'started', 'done', 'reverted')
                               for item in journal['items'])
                        or ('effects' in manifest and len(journal['items']) != len(manifest['effects']))):
                    raise ValueError('invalid transaction item states')
                if ('errors' in journal and not isinstance(journal['errors'], list)
                        or 'metadata' in manifest and not isinstance(manifest['metadata'], dict)
                        or 'runtime' in manifest and not isinstance(manifest['runtime'], dict)):
                    raise ValueError('invalid transaction metadata')
                expiry = _validated_timestamp(journal.get('deadline'))
                if 'manifest_sha256' in journal:
                    canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
                    if journal['manifest_sha256'] != hashlib.sha256(canonical).hexdigest():
                        raise ValueError('changed transaction manifest')
                if state not in ('committed', 'rolled_back'):
                    pending.append({'kind': kind, 'state': state, 'deadline': expiry})
        budget()
    except (OSError, ValueError, TypeError, RuntimeError):
        complete = False
    return pending, complete


def _parse_acceptance_history(cs_dir, path):
    """Worker body: one legacy content fingerprint serves summary and applicability."""
    unavailable = dict(valid=False, summary='历史验收记录无法完整核验，请重新验证具体入口。')
    try:
        from crowdbastion_ux import acceptance_summary, tree_fingerprint
        record = json.loads(read_file(path))
        if not isinstance(record, dict):
            raise ValueError('invalid acceptance record')
        stamp = _validated_timestamp(record.get('time'))
        current = tree_fingerprint(cs_dir)
        now = time.time()
        summary = acceptance_summary(path, cs_dir, now=now, fingerprint=current)
        return dict(valid=record['code'] == 0 and 0 <= now-stamp <= 86400 and record['fingerprint'] == current,
                    summary=summary)
    except (OSError, OverflowError, ValueError, TypeError, KeyError, RuntimeError):
        return unavailable


def _acceptance_history(cs_dir, path, deadline):
    remaining = min(2.0, deadline-time.monotonic())
    if remaining <= 0:
        return dict(valid=False, summary='历史验收：本次检查时间不足，历史记录尚未核验。')
    unavailable = dict(valid=False, summary='历史验收记录无法完整核验，请重新验证具体入口。')
    try:
        if not _exists(path):
            return dict(valid=False, summary='历史验收：尚无可用记录，实际拦截待验证。')
        script = ('import json,pathlib,sys;sys.path.insert(0,sys.argv[1]);'
                  'from crowdbastion_flow_probe import _parse_acceptance_history;'
                  'print(json.dumps(_parse_acceptance_history(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]))))')
        args = [sys.executable] + (['-S'] if sys.flags.no_site else [])
        args += ['-c', script, str(Path(__file__).parent), str(cs_dir), str(path)]
        result = run_command(args, remaining)
        if result.returncode:
            return unavailable
        report = json.loads(result.stdout)
        if (not isinstance(report, dict) or set(report) != {'valid', 'summary'}
                or type(report['valid']) is not bool or not isinstance(report['summary'], str)):
            return unavailable
        return report
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return unavailable


def discover(cs_dir, state_dir, budget=10.0, runner=None):
    cs_dir, state_dir = Path(cs_dir), Path(state_dir)
    host_root = cs_dir.parent.parent
    probes = Probes(budget, runner)
    pending, pending_complete = _pending_inventory(state_dir, probes.deadline)
    acquisitions = _active_acquisitions(cs_dir, probes.deadline)
    fingerprint, complete = config_fingerprint(cs_dir, host_root, probes.deadline, acquisitions)
    components = _component_fingerprints(cs_dir, host_root, probes.deadline, acquisitions)
    if acquisitions['appsec'] is None:
        probes.limitations.append('AppSec 有效采集配置无法完整解析，需核对已有配置和 YAML 解析依赖')
    checks, targets = {}, []
    sources = None
    inventory = dict(core=_exists(cs_dir/'config.yaml'),
                     bouncer=_exists(cs_dir/'bouncers/crowdsec-firewall-bouncer.yaml'),
                     remote=_exists(cs_dir/'bouncers/crowdsec-firewall-bouncer.yaml.remote.json'),
                     appsec=acquisitions['appsec'],
                     v2bx=_exists(host_root/'etc/V2bX/config.json'),
                     observer=_exists(host_root/'usr/local/lib/crowdsec-v2bx-observer/config.json'))
    checks['core'] = probes.service('crowdsec') if inventory['core'] else 'missing'
    if inventory['core']:
        checks['config'] = probes.check(('crowdsec', '-t'), 'fault')
        checks['api'] = probes.check(('cscli', 'lapi', 'status'))
        metrics = probes.command('cscli', 'metrics', 'show', 'acquisition', '-o', 'json')
        try:
            sources = parse_acquisition_metrics(metrics.stdout) if metrics is not None and metrics.returncode == 0 else None
            checks['logs'] = acquisition_state(sources) if sources is not None else 'unknown'
        except (TypeError, ValueError):
            checks['logs'] = 'unknown'
    checks['web_rules'] = _web_rules(probes) if inventory['core'] else 'missing'
    checks['bouncer'] = probes.service('crowdsec-firewall-bouncer') if inventory['bouncer'] or inventory['remote'] else 'missing'
    if inventory['remote']:
        # Registration alone is not proof of a working center or applied decisions.
        checks['remote'] = 'unknown'
    if inventory['v2bx']:
        checks['v2bx_service'] = probes.service('V2bX')
    if inventory['observer']:
        checks['observer'] = probes.service('crowdsec-v2bx-observer')
    if inventory['appsec'] is True:
        checks['appsec'] = _appsec_listener_state(acquisitions['listeners'], probes)
    elif inventory['appsec'] is None:
        checks['appsec'] = 'unknown'
    else:
        checks['appsec'] = 'missing'
    installs = _registry(cs_dir/'crowdsec-1key-web-installs.json', probes.limitations)
    transport = _registry(cs_dir/'crowdsec-1key-docker-endpoints.json', probes.limitations)
    for service in ('nginx', 'openresty'):
        result = probes.command(service, '-T')
        if result is not None and result.returncode == 0 and result.stdout.strip():
            configured = _exists(cs_dir/f'bouncers/crowdsec-{service}-bouncer.conf')
            effective = result.stdout
            # Hook presence is only connection evidence, never actual request verification.
            target = _target('host:'+service, '宿主机 '+service, service, 'host', effective, configured, False, True)
            _web_evidence(target, effective, sources)
            target['integration_hash'] = _integration_fingerprint(target, cs_dir, installs, transport, probes.deadline)
            targets.append(_audit_target(target, effective, cs_dir, probes,
                                         acquisitions=acquisitions, appsec_state=checks['appsec']))
    containers = probes.command('docker', 'ps', '--no-trunc', '--format', '{{json .}}')
    if containers is not None and containers.returncode == 0:
        try:
            rows = [json.loads(line) for line in containers.stdout.splitlines() if line.strip()]
            candidates, seen = [], set()
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get('ID'), str)
                        or not re.fullmatch(r'[a-f0-9]{12,64}', row['ID'])
                        or not isinstance(row.get('Image', ''), str) or not isinstance(row.get('Names', ''), str)):
                    probes.limitations.append('网站容器清单无法完整读取')
                    continue
                if row['ID'] not in seen:
                    candidates.append(row)
                    seen.add(row['ID'])
            def priority(row):
                name = row.get('Names', '').lstrip('/')
                if name in installs or name in transport:
                    return 0
                return 1 if re.search(r'nginx|openresty|npm|proxy.manager', row.get('Image', '')+' '+name, re.I) else 2
            candidates.sort(key=priority)
            if len(candidates) > 32:
                probes.limitations.append('网站容器扫描达到 32 个候选上限，部分容器尚未检查')
            for row in candidates[:32]:
                if time.monotonic() >= probes.deadline:
                    probes.limitations.append('网站容器扫描时间已用完，部分容器尚未检查')
                    break
                identity = row.get('ID', '')
                inspection = probes.command('docker', 'inspect', identity)
                if inspection is None or inspection.returncode:
                    continue
                item = json.loads(inspection.stdout)[0]
                full_id = item.get('Id', '')
                if not re.fullmatch(r'[a-f0-9]{12,64}', full_id):
                    raise ValueError('invalid container identity')
                effective = probes.command('docker', 'exec', full_id, 'nginx', '-T')
                if effective is None or effective.returncode or not effective.stdout.strip():
                    if priority(row) < 2:
                        probes.limitations.append('候选网站容器的有效配置无法读取')
                    continue
                name = item.get('Name', '').lstrip('/')
                network = item.get('HostConfig', {}).get('NetworkMode', 'unknown')
                owned = name in installs
                target = _target('docker:'+full_id, name, 'docker', network, effective.stdout,
                                 owned, False, _audit_transport(item, name, transport, probes))
                _web_evidence(target, effective.stdout, sources, item.get('Mounts', []))
                target['integration_hash'] = _integration_fingerprint(target, cs_dir, installs, transport, probes.deadline, item.get('Mounts', []))
                targets.append(_audit_target(target, effective.stdout, cs_dir, probes, item.get('Mounts', []),
                                             acquisitions, checks['appsec'], installs, transport))
        except (IndexError, KeyError, TypeError, ValueError):
            probes.limitations.append('网站容器清单无法完整读取')
    if not pending_complete:
        complete = False
        probes.limitations.append('未完成变更清单无法完整安全核对，请从高级工具核对后再修改')
    if not complete:
        probes.limitations.append('部分配置不能安全核对，直接修改需先完成专项检查')
    scope_issue, legacy_roles = '', []
    try:
        from crowdbastion_node import load
        legacy_roles = load(state_dir/'node-roles.json')
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        scope_issue = '节点用途配置无法安全读取；内容损坏可从菜单 [4] → [7] 重设，权限或路径异常请先修正。'
    acceptance = _acceptance_history(cs_dir, state_dir/'relay-acceptance.json', probes.deadline)
    return dict(version=1, checked_at=time.time(), fingerprint=fingerprint, fingerprint_complete=complete,
                component_fingerprints=components,
                inventory=inventory, checks=checks, targets=targets, pending=pending,
                pending_scan_complete=pending_complete,
                limitations=list(dict.fromkeys(probes.limitations)), scope_issue=scope_issue, legacy_roles=legacy_roles, acceptance=acceptance)

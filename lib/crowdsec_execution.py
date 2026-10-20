"""Read bounded tails of Nginx error logs; decisions are not execution evidence."""
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

CAUSES = {'lapi_ban': 'LAPI 封禁', 'lapi_failure': 'LAPI 故障策略拒绝', 'appsec_rule': 'AppSec 规则拒绝',
          'appsec_failure': 'AppSec 故障策略拒绝', 'appsec_body': 'AppSec 请求体策略拒绝'}
PREFIX = re.compile(r'^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[error\] \d+#\d+: '
                    r'\*\d+ \[lua\] execution\.lua:\d+: emit\(\): CB_EXEC_V1 ')
LOG_NAME = re.compile(r'[^/]*(?:error\.log|error_log)(?:\.1)?$')
TAIL_BYTES = 65536
MAX_FILES = 128


def parse_record(line, ip, since, now):
    match = PREFIX.match(line)
    if not match:
        return None
    try:
        item, end = json.JSONDecoder().raw_decode(line[match.end():])
        if not line[match.end()+end:].startswith(' while logging request, client: '):
            return None
        if (not isinstance(item, dict) or type(item.get('v')) is not int or item['v'] != 1
                or type(item.get('status')) is not int or not 400 <= item['status'] <= 599
                or item.get('upstream') != '' or item.get('cause') not in CAUSES
                or not re.fullmatch(r'[a-f0-9]{32}', item.get('request_id', ''))
                or type(item.get('time')) not in (int, float) or not math.isfinite(item['time'])
                or not since <= item['time'] <= now
                or str(ipaddress.ip_address(item.get('ip'))) != ip):
            return None
        return item
    except (ValueError, TypeError):
        return None


def query(log_dirs, ip, since, now=None):
    ip = str(ipaddress.ip_address(ip))
    now = time.time() if now is None else float(now)
    since = max(float(since), now-86400)
    result = dict(state='unavailable', count=0, causes={}, records=[], since=since,
                  logs_read=0, errors=0, truncated=False, truncated_files=0,
                  scan_limited=False, bytes_read=0)
    if not isinstance(log_dirs, list) or not 1 <= len(log_dirs) <= 4:
        return result
    files = []
    for directory in log_dirs:
        try:
            root = Path(directory)
            if not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents)):
                raise ValueError('unsafe log directory')
            with os.scandir(root) as entries:
                for number, entry in enumerate(entries):
                    if number >= 4096:
                        result['truncated'] = True
                        result['scan_limited'] = True
                        break
                    if LOG_NAME.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                        files.append((entry.stat(follow_symlinks=False).st_mtime, entry.path))
        except (OSError, ValueError, TypeError):
            result['errors'] += 1
    files.sort(reverse=True)
    result['truncated'] |= len(files) > MAX_FILES
    result['scan_limited'] |= len(files) > MAX_FILES
    seen = {}
    for _, path in files[:MAX_FILES]:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('not a regular log')
                offset = max(0, info.st_size-TAIL_BYTES)
                stream.seek(offset)
                data = stream.read(TAIL_BYTES)
            result['logs_read'] += 1
            result['bytes_read'] += len(data)
            result['truncated'] |= bool(offset)
            result['truncated_files'] += bool(offset)
            # Ignore an incomplete first/last record during rotation or active writes.
            lines = data.split(b'\n')
            for line in lines[1 if offset else 0:-1]:
                item = parse_record(line.decode('utf-8', errors='replace'), ip, since, now)
                if item:
                    seen[item['request_id']] = item
        except (OSError, ValueError):
            result['errors'] += 1
    for item in seen.values():
        cause = item['cause']
        result['causes'][cause] = result['causes'].get(cause, 0)+1
    result['count'] = len(seen)
    result['records'] = sorted(seen.values(), key=lambda r: r['time'], reverse=True)[:3]
    if result['logs_read']:
        result['state'] = 'observed' if seen else 'empty'
    return result


def firewall_membership(config, ip):
    """Read configured nft set membership only; this does not prove packet drops.

    Table metadata excludes elements, keeping large CAPI sets out of the reply.
    Missing elements count as negative only after rechecking the set metadata.
    Every command shares one five-second deadline and never mutates nft state.
    """
    unavailable = {'state': 'unavailable', 'sets': []}
    try:
        address = ipaddress.ip_address(ip)
        # nft parses its own command language even with shell=False. IPv6 scopes
        # are not valid remote sources and ipaddress leaves their text untouched.
        if getattr(address, 'scope_id', None) is not None:
            return unavailable
        if not isinstance(config, dict) or not config.get('mode'):
            return unavailable
        if config['mode'] != 'nftables':
            return {'state': 'unsupported', 'sets': []}
        family = 'ipv4' if address.version == 4 else 'ipv6'
        scope = config.get('nftables', {}).get(family, {})
        # Match the official bouncer: explicit enabled wins; only an unset
        # family option defaults to the inverse of disable_ipv4/disable_ipv6.
        enabled = scope.get('enabled')
        if enabled is None:
            disabled = config.get('disable_'+family, False)
            if type(disabled) is not bool:
                return unavailable
            enabled = not disabled
        if type(enabled) is not bool:
            return unavailable
        if not enabled:
            return {'state': 'unsupported', 'sets': []}
        nft_family = 'ip' if address.version == 4 else 'ip6'
        table = scope.get('table')
        if table is None or table == '':
            table = 'crowdsec' if address.version == 4 else 'crowdsec6'
        names = config.get('blacklists_'+family)
        if names is None or names == '':
            names = ['crowdsec-blacklists' if address.version == 4 else 'crowdsec6-blacklists']
        if isinstance(names, str):
            names = [names]
        set_only = scope.get('set-only')
        if set_only is None:
            set_only = False
        if type(set_only) is not bool:
            return unavailable
        def identifier(value):
            return isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}', value)
        if not identifier(table) or not isinstance(names, list) or not names or not all(map(identifier, names)):
            return unavailable
        deadline = time.monotonic()+5
        def run(args):
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('nft query deadline')
            return subprocess.run(['nft', *args], capture_output=True, text=True,
                                  timeout=remaining, env={'PATH': os.environ.get('PATH', os.defpath), 'LC_ALL': 'C'})
        def sets():
            reply = run(['-j', '-t', 'list', 'table', nft_family, table])
            if reply.returncode:
                raise ValueError('table query failed')
            objects = json.loads(reply.stdout)['nftables']
            if not isinstance(objects, list):
                raise ValueError('invalid table metadata')
            tables = [obj['table'] for obj in objects if obj.get('table', {}).get('family') == nft_family
                      and obj.get('table', {}).get('name') == table]
            table_handle = tables[0].get('handle') if len(tables) == 1 else None
            found = {}
            for obj in objects:
                item = obj.get('set', {})
                name = item.get('name', '')
                if (item.get('family') == nft_family and item.get('table') == table
                        and item.get('type') == family+'_addr' and identifier(name)
                        and any(name == prefix if set_only else
                                name.startswith(prefix+'-') and len(name) > len(prefix)+1
                                for prefix in names)):
                    found[name] = (table_handle, item.get('handle'))
            if not 1 <= len(found) <= 32:
                raise ValueError('configured sets unavailable or query limit exceeded')
            return found
        queried = sets()
        failed = False
        for name in sorted(queried):
            reply = run(['get', 'element', nft_family, table, name, '{', str(address), '}'])
            if reply.returncode == 0:
                # nft get element uses its native text printer even with -j on some releases.
                if re.search(r'\belements\s*=\s*\{\s*[^}\s]', reply.stdout):
                    return {'state': 'present', 'sets': [name]}
                failed = True
            elif (reply.returncode != 1 or
                  'Error: Could not process rule: No such file or directory' not in reply.stderr):
                failed = True
        # Names alone cannot detect deletion followed by same-name recreation.
        # A negative needs stable kernel identities for both table and sets.
        if (failed or sets() != queried or
                any(type(handle) is not int or handle <= 0
                    for handles in queried.values() for handle in handles)):
            return unavailable
        return {'state': 'absent', 'sets': sorted(queried)}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, TimeoutError, subprocess.TimeoutExpired):
        return unavailable

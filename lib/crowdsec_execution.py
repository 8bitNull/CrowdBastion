"""Read bounded tails of Nginx error logs; decisions are not execution evidence."""
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
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
                  logs_read=0, errors=0, truncated=False, bytes_read=0)
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
                        break
                    if LOG_NAME.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                        files.append((entry.stat(follow_symlinks=False).st_mtime, entry.path))
        except (OSError, ValueError, TypeError):
            result['errors'] += 1
    files.sort(reverse=True)
    result['truncated'] |= len(files) > MAX_FILES
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

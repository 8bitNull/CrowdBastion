"""Read-only follow-up for capacity, boot conflicts and final continuity."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import subprocess


def command(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=15,
                           env=dict(os.environ, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1'))
        return {'exit': p.returncode, 'stdout': p.stdout[:20000], 'stderr': p.stderr[-1000:]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'error': type(e).__name__}


r = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'commands': {}}
for key, argv in {
    'sysctl_unit': ['systemctl', 'show', 'systemd-sysctl', '-p', 'Result', '-p', 'ExecMainStatus', '-p', 'ActiveState'],
    'sysctl_journal': ['journalctl', '-u', 'systemd-sysctl', '-b', '-n', '40', '--no-pager'],
    'fail2ban': ['fail2ban-client', 'status'],
    'fail2ban_actions': ['fail2ban-client', 'get', 'sshd', 'actions'],
    'fail2ban_logpath': ['fail2ban-client', 'get', 'sshd', 'logpath'],
    'realm_version': ['/usr/local/bin/realm', '--version'],
    'ipset_module': ['modinfo', '-F', 'filename', 'ip_set'],
    'xt_set_module': ['modinfo', '-F', 'filename', 'xt_set'],
    'hash_net_module': ['modinfo', '-F', 'filename', 'ip_set_hash_net'],
    'sample_vmstat': ['vmstat', '1', '4'],
    'nstat': ['nstat', '-az'],
    'listeners': ['ss', '-H', '-lntup'],
    'dpkg_audit': ['dpkg', '--audit'],
}.items():
    r['commands'][key] = command(argv)
r['services'] = command(['systemctl', 'show', 'ssh', 'forwardx-agent', 'fail2ban', 'systemd-journald',
    *['forwardx-realm-both-' + str(port) for port in [53537,53541,53543,53544,53545,53546,53547,53548,53549,53551,53552,53553,53554]],
    '-p', 'Id', '-p', 'MainPID', '-p', 'NRestarts', '-p', 'ActiveState', '-p', 'ExecMainStartTimestamp'])
r['process_memory_kib'] = {}
for p in Path('/proc').glob('[0-9]*'):
    try:
        name = (p/'comm').read_text().strip()
        if name not in ['realm', 'forwardx-agent', 'fail2ban-server', 'systemd-journal', 'rsyslogd']:
            continue
        status = (p/'status').read_text()
        rss = re.search(r'^VmRSS:\s+(\d+)', status, re.M)
        r['process_memory_kib'].setdefault(name, []).append({'pid': int(p.name), 'rss': int(rss[1]) if rss else 0})
    except OSError:
        pass
r['startup_restore'] = []
for p in [Path('/etc/crontab'), Path('/var/spool/cron/crontabs/root'), *Path('/etc/cron.d').glob('*')]:
    if not p.is_file():
        continue
    for line in p.read_text(errors='replace').splitlines():
        match = re.search(r'(?:(?:ip6tables|iptables)-restore)\s*<\s*([/A-Za-z0-9_.-]+)', line)
        if match:
            r['startup_restore'].append({'file': str(p), 'disabled': line.lstrip().startswith('#'),
                                         'reboot': '@reboot' in line, 'snapshot': match[1]})
r['saved_rules'] = {}
for name in ['/etc/iptables/rules.v4', '/etc/iptables/rules.v6']:
    p = Path(name)
    if p.is_file():
        r['saved_rules'][name] = [line for line in p.read_text().splitlines() if line and not line.startswith('#')]
r['protected_hashes'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in [Path('/usr/local/bin/realm'), *Path('/etc/forwardx/realm').glob('*.toml')]}
r['module_files'] = {}
module_root = Path('/lib/modules') / os.uname().release
for p in module_root.rglob('*.ko*'):
    if re.match(r'^(ip_set(?:_hash_(?:ip|net))?|xt_set)\.ko', p.name):
        r['module_files'][p.name] = str(p)
status = Path('/proc/self/status').read_text()
caps = int(re.search(r'^CapEff:\s*([0-9a-f]+)', status, re.M)[1], 16)
r['capabilities'] = {'CAP_NET_ADMIN': bool(caps & (1 << 12)), 'CAP_SYS_MODULE': bool(caps & (1 << 16))}
print(json.dumps(r, ensure_ascii=False, indent=2))

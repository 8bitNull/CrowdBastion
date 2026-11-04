"""Read-only baseline for the targeted sysctl repair. No remote file writes."""
from pathlib import Path
import datetime
import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess


def cmd(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=20)
    return {'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr[-1500:]}


def meta(p):
    p = Path(p); s = p.lstat()
    return {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'uid': s.st_uid,
            'mode': oct(stat.S_IMODE(s.st_mode)), 'nlink': s.st_nlink,
            'is_symlink': p.is_symlink()}


ports = [53537,53541,53543,53544,53545,53546,53547,53548,53549,53551,53552,53553,53554]
units = ['forwardx-agent', 'fail2ban', 'ssh', 'systemd-journald', 'rsyslog'] + ['forwardx-realm-both-'+str(p) for p in ports]
source = Path('/etc/sysctl.d/99-network-optimize.conf')
r = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'target': str(source),
     'source_metadata': meta(source), 'commands': {}}
r['target_lines'] = [line for line in source.read_text().splitlines()
                     if re.match(r'^\s*net[./]core[./]netdev_budget_usecs\s*=', line)]
keys = {'net.core.netdev_budget_usecs', 'net.ipv4.tcp_congestion_control', 'net.core.default_qdisc'}
for p in [Path('/etc/sysctl.conf'), *Path('/etc/sysctl.d').glob('*.conf'), *Path('/usr/lib/sysctl.d').glob('*.conf')]:
    if not p.is_file():
        continue
    for line in p.read_text(errors='replace').splitlines():
        m = re.match(r'^\s*-?([A-Za-z0-9_.]+)\s*=', line)
        if m:
            keys.add(m[1])
r['sysctl_values'] = {}
for key in sorted(keys):
    p = Path('/proc/sys') / key.replace('.', '/')
    try:
        r['sysctl_values'][key] = p.read_text().strip()
    except OSError:
        pass
r['protected_hashes'] = {str(p): meta(p)['sha256'] for p in [Path('/usr/local/bin/realm'), *Path('/etc/forwardx/realm').glob('*.toml')]}
configuration = [Path('/etc/ssh/sshd_config'), Path('/usr/local/bin/forwardx-agent')]
for root in ['/etc/ssh/sshd_config.d', '/etc/fail2ban', '/etc/forwardx']:
    configuration.extend(p for p in Path(root).rglob('*') if p.is_file()
                         and p.suffix in ['.conf', '.local', '.yaml', '.yml', '.toml', '.json'])
r['other_protected_hashes'] = {str(p): meta(p)['sha256'] for p in configuration if p.is_file()}
cat = cmd(['/lib/systemd/systemd-sysctl', '--cat-config', '--no-pager'])
assert cat['exit'] == 0, cat
r['effective_config'] = {'exit': cat['exit'], 'sha256': hashlib.sha256(cat['stdout'].encode()).hexdigest(),
                         'files': [], 'target_matches': []}
current = None
for number, line in enumerate(cat['stdout'].splitlines(), 1):
    if line.startswith('# /'):
        current = line[2:].strip()
        r['effective_config']['files'].append(current)
    text = line.strip()
    if not text or text.startswith(('#', ';')):
        continue
    key = text.split('=', 1)[0].strip().lstrip('-').replace('.', '/')
    if fnmatch.fnmatchcase('net/core/netdev_budget_usecs', key):
        r['effective_config']['target_matches'].append({'source': current, 'cat_line': number, 'assignment': text})
for key, args in {
    'services': ['systemctl', 'show', *units, '-p', 'Id', '-p', 'MainPID', '-p', 'ActiveState', '-p', 'NRestarts', '-p', 'ExecMainStartTimestamp'],
    'failed_units': ['systemctl', '--failed', '--no-pager', '--no-legend'],
    'sysctl_unit': ['systemctl', 'show', 'systemd-sysctl', '-p', 'Result', '-p', 'ExecMainStatus', '-p', 'ActiveState'],
    'sysctl_journal': ['journalctl', '-u', 'systemd-sysctl', '-b', '-n', '20', '--no-pager'],
    'iptables': ['iptables-save'], 'ip6tables': ['ip6tables-save'], 'nft': ['nft', '-j', 'list', 'ruleset'],
    'listeners': ['ss', '-H', '-lntup'], 'nstat': ['nstat', '-az'],
    'sysctl_help': ['/lib/systemd/systemd-sysctl', '--help'],
    'sysctl_exec': ['systemctl', 'show', 'systemd-sysctl', '-p', 'ExecStart', '-p', 'FragmentPath', '-p', 'DropInPaths'],
    'namespaces': ['ip', 'netns', 'list'],
}.items():
    r['commands'][key] = cmd(args)
r['source_other_lines_sha256'] = hashlib.sha256('\n'.join(
    line for line in source.read_text().splitlines()
    if not re.match(r'^\s*net[./]core[./]netdev_budget_usecs\s*=', line)).encode()).hexdigest()
r['root_cron_sha256'] = hashlib.sha256(cmd(['crontab', '-l'])['stdout'].encode()).hexdigest()
r['saved_mangle_sha256'] = meta('/etc/iptables/rules.v4')['sha256']
r['memory'] = {k: v.strip() for line in Path('/proc/meminfo').read_text().splitlines()
               for k, v in [line.split(':', 1)] if k in ['MemTotal','MemAvailable','SwapTotal','SwapFree']}
kernel = Path('/boot/config-' + os.uname().release)
r['kernel_config'] = [line for line in kernel.read_text().splitlines()
                      if re.match(r'CONFIG_(HZ|HZ_\d+|PREEMPT|NET_RX_BUSY_POLL)', line)] if kernel.exists() else []
print(json.dumps(r, ensure_ascii=True, indent=2))

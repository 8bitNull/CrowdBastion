"""Read-only deployment assessment. Send via SSH stdin; writes no remote files."""
from pathlib import Path
import concurrent.futures
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import urllib.request
import urllib.error


def command(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1'))
        return {'exit': p.returncode, 'stdout': p.stdout[:70000], 'stderr': p.stderr[-1500:]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'error': type(error).__name__}


def read(path, limit=262144):
    try:
        with open(path) as stream:
            return stream.read(limit)
    except OSError:
        return None


def metadata(path):
    p = Path(path)
    try:
        info = p.lstat()
        result = {'exists': True, 'uid': info.st_uid, 'mode': oct(info.st_mode & 0o7777), 'size': info.st_size}
        if p.is_file() and info.st_size < 10000000:
            result['sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
        return result
    except OSError:
        return {'exists': False}


def service_state():
    result = command(['systemctl', 'show', 'ssh', 'crowdsec', 'crowdsec-firewall-bouncer',
                      'docker', 'nftables', 'netfilter-persistent', 'ufw', 'firewalld',
                      'rsyslog', 'systemd-journald', 'forwardx-agent',
                      '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState',
                      '-p', 'MainPID', '-p', 'NRestarts', '-p', 'UnitFileState'])
    units = {}
    for block in result.get('stdout', '').strip().split('\n\n'):
        item = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if 'Id' in item:
            units[item['Id']] = item
    return units


def firewall(binary):
    result = command([binary + '-save'])
    if 'stdout' not in result:
        return result
    rows = []
    for line in result['stdout'].splitlines():
        if not line or line.startswith('#'):
            continue
        words = shlex.split(line)
        while '--comment' in words:
            i = words.index('--comment'); del words[i:i+2]
        rows.append(shlex.join(words))
    return {'exit': result['exit'], 'rules': rows, 'stderr': result['stderr']}


def endpoint(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method='HEAD'), timeout=10) as response:
            return {'http_status': response.status, 'tls_http_reached': True}
    except urllib.error.HTTPError as error:
        return {'http_status': error.code, 'tls_http_reached': True}
    except Exception as error:
        return {'error': type(error).__name__, 'tls_http_reached': False}


r = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'uid': os.geteuid()}
r['os'] = {k: v.strip('"') for line in (read('/etc/os-release') or '').splitlines()
           if '=' in line for k, v in [line.split('=', 1)] if k in ['ID', 'VERSION_ID', 'PRETTY_NAME']}
r['commands'] = {}
checks = {
    'kernel': ['uname', '-srmo'], 'python': ['python3', '--version'], 'bash': ['bash', '--version'],
    'virtualization': ['systemd-detect-virt'], 'cpu': ['lscpu'], 'disk': ['df', '-hT', '/', '/var', '/tmp'],
    'inodes': ['df', '-i', '/'], 'mounts': ['findmnt', '-n', '-o', 'TARGET,FSTYPE,OPTIONS', '/'],
    'failed_units': ['systemctl', '--failed', '--no-pager', '--no-legend'],
    'unit_names': ['systemctl', 'list-units', '--all', '--type=service', '--no-legend', '--no-pager'],
    'listeners': ['ss', '-H', '-lntup'], 'addresses': ['ip', '-j', 'address', 'show'],
    'routes': ['ip', '-j', 'route', 'show'], 'qdisc': ['tc', '-s', 'qdisc', 'show'],
    'packages': ['dpkg-query', '-W', '-f=${Package} ${Status} ${Version}\n', 'crowdsec',
                 'crowdsec-firewall-bouncer-iptables', 'crowdsec-firewall-bouncer-nftables',
                 'iptables', 'ipset', 'nftables', 'python3', 'python3-yaml', 'git', 'curl', 'rsyslog'],
    'package_candidates': ['apt-cache', 'policy', 'crowdsec', 'crowdsec-firewall-bouncer-iptables', 'python3-yaml'],
    'dpkg_audit': ['dpkg', '--audit'], 'iptables_version': ['iptables', '--version'],
    'ip6tables_version': ['ip6tables', '--version'], 'ipset_version': ['ipset', '--version'],
    'journal_space': ['journalctl', '--disk-usage'],
    'ssh_journal_count': ['journalctl', '-u', 'ssh', '--since', '24 hours ago', '-n', '100', '-o', 'json', '--no-pager'],
    'kernel_counters': ['nstat', '-az'],
    'network_values': ['sysctl', 'net.ipv4.tcp_congestion_control', 'net.ipv4.tcp_available_congestion_control',
        'net.core.default_qdisc', 'net.core.rmem_max', 'net.core.wmem_max', 'net.ipv4.udp_rmem_min',
        'net.ipv4.udp_wmem_min', 'net.ipv4.tcp_mem', 'net.ipv4.tcp_syncookies',
        'net.ipv4.tcp_syn_retries', 'net.ipv4.tcp_synack_retries', 'net.ipv4.tcp_fin_timeout',
        'net.ipv4.ip_forward', 'net.ipv6.conf.all.disable_ipv6', 'net.netfilter.nf_conntrack_max'],
}
r['services_before'] = service_state()
for key, args in checks.items():
    result = command(args)
    if key == 'ssh_journal_count':
        rows = [line for line in result.get('stdout', '').splitlines() if line.strip()]
        r['ssh_journal'] = {'exit': result.get('exit'), 'sample_lines': len(rows),
                            'sample_cap': 100, 'has_journal': bool(rows)}
    elif key == 'unit_names':
        r['business_units'] = [line.strip() for line in result.get('stdout', '').splitlines()
                               if re.search(r'forwardx|realm|gost|v2bx|xray|sing-box|nginx|openresty|docker|crowdsec|fail2ban', line, re.I)]
    else:
        r['commands'][key] = result
r['memory'] = {k: int(v.split()[0]) for line in (read('/proc/meminfo') or '').splitlines()
               for k, v in [line.split(':', 1)] if k in ['MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree']}
r['loadavg'] = read('/proc/loadavg')
r['uptime_seconds'] = (read('/proc/uptime') or '').split()[0]
r['pressure'] = {k: read('/proc/pressure/' + k) for k in ['cpu', 'memory', 'io']}
r['yaml_available'] = importlib.util.find_spec('yaml') is not None
r['commands_available'] = {name: shutil.which(name) for name in ['git', 'curl', 'python3', 'bash', 'systemctl', 'iptables', 'ip6tables', 'ipset', 'nft', 'cscli', 'crowdsec', 'realm', 'docker']}
r['files'] = {name: metadata(name) for name in ['/var/log/auth.log', '/var/log/syslog', '/etc/crowdsec/config.yaml',
    '/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml', '/etc/iptables/rules.v4', '/etc/iptables/rules.v6',
    '/etc/nftables.conf', '/usr/local/bin/realm', '/usr/bin/realm', '/usr/local/bin/forwardx-agent',
    '/run/lock', '/run/lock/crowdsec-1key.lock']}
r['iptables'] = firewall('iptables'); r['ip6tables'] = firewall('ip6tables')
raw = command(['nft', '-j', 'list', 'ruleset'])
try:
    objects = json.loads(raw['stdout'])['nftables']
    r['nft'] = {'exit': raw['exit'], 'tables': [x['table'] for x in objects if 'table' in x],
                'chains': [{k: v for k, v in x['chain'].items() if k != 'comment'} for x in objects if 'chain' in x],
                'rule_count': sum('rule' in x for x in objects)}
except (KeyError, ValueError):
    r['nft'] = {'exit': raw.get('exit'), 'error': raw.get('error', 'not_readable')}
r['kernel_features'] = {}
config = read('/boot/config-' + os.uname().release)
for symbol in ['CONFIG_NETFILTER', 'CONFIG_NF_TABLES', 'CONFIG_NETFILTER_XTABLES', 'CONFIG_IP_SET',
               'CONFIG_IP_SET_HASH_IP', 'CONFIG_IP_SET_HASH_NET', 'CONFIG_NETFILTER_XT_SET',
               'CONFIG_NF_CONNTRACK', 'CONFIG_NET_SCH_FQ', 'CONFIG_TCP_CONG_BBR']:
    match = re.search(r'^' + symbol + r'=(\w+)$', config or '', re.M)
    r['kernel_features'][symbol] = match.group(1) if match else 'unknown'
r['loaded_modules'] = [line.split()[0] for line in (read('/proc/modules') or '').splitlines()
                        if re.match(r'(ip_set|xt_set|nf_tables|nf_conntrack|ip_tables|ip6_tables|tcp_bbr|sch_fq)', line)]
r['startup_restore_tasks'] = []
for path in [Path('/etc/crontab'), Path('/var/spool/cron/crontabs/root'), *Path('/etc/cron.d').glob('*')]:
    if not path.is_file():
        continue
    for line in (read(path) or '').splitlines():
        if re.search(r'iptables-restore|ip6tables-restore|nft\s+(-f|flush)|netfilter-persistent', line):
            r['startup_restore_tasks'].append({'file': str(path), 'disabled': line.lstrip().startswith('#'),
                'reboot': '@reboot' in line, 'line_sha256': hashlib.sha256(line.encode()).hexdigest()})
r['forwardx_configs'] = {str(p): metadata(str(p)) for p in Path('/etc/forwardx/realm').glob('*.toml')}
r['https_endpoints'] = {}
urls = ['https://install.crowdsec.net', 'https://packagecloud.io/crowdsec/crowdsec',
        'https://hub-data.crowdsec.net/', 'https://site-02.example.com/', 'https://github.com/']
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    for url, result in zip(urls, pool.map(endpoint, urls)):
        r['https_endpoints'][url] = result
r['services_after'] = service_state()
r['service_pid_continuity'] = {name: value.get('MainPID') == r['services_after'].get(name, {}).get('MainPID')
                               for name, value in r['services_before'].items()}
print(json.dumps(r, ensure_ascii=False, indent=2))

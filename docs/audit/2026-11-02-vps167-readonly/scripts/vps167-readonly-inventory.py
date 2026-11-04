import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time


def command(argv, timeout=15):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=dict(os.environ, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1'))
        return {'exit': result.returncode, 'output': result.stdout.strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'error': type(error).__name__}


def metadata(name):
    path = Path(name)
    if not path.exists() and not path.is_symlink():
        return {'exists': False}
    info = path.lstat()
    result = {'exists': True, 'mode': oct(stat.S_IMODE(info.st_mode)), 'uid': info.st_uid, 'gid': info.st_gid,
              'mtime': info.st_mtime, 'symlink': path.is_symlink()}
    if path.is_symlink():
        result['target'] = os.readlink(path)
    if path.is_file():
        result['size'] = path.stat().st_size
        result['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def source_manifest(name):
    root = Path(name)
    result = {'metadata': metadata(name), 'files': {}}
    if not root.is_dir():
        return result
    for path in sorted(root.iterdir()):
        if path.is_file() and (path.name in ('manager.sh', 'crowdbastion.sh', 'install-crowdsec-1panel.sh') or path.suffix in ('.py', '.lua')):
            result['files'][path.name] = metadata(path)
    library = root / 'lib'
    if library.is_dir():
        for path in sorted(library.iterdir()):
            if path.is_file() and path.suffix in ('.sh', '.py', '.lua'):
                result['files']['lib/'+path.name] = metadata(path)
    return result


def config_summary(name, allowed):
    result = {'metadata': metadata(name)}
    if not Path(name).is_file():
        return result
    try:
        if name.endswith('.json'):
            document = json.loads(Path(name).read_text())
        else:
            import yaml
            document = yaml.safe_load(Path(name).read_text())
        if isinstance(document, dict):
            result['keys'] = sorted(str(key) for key in document)
            result['values'] = {key: document[key] for key in allowed if key in document}
    except Exception as error:
        result['parse_error'] = type(error).__name__
    return result


report = {'checked_at': time.time(), 'uid': os.geteuid()}
report['os'] = {key: value.strip('"') for line in Path('/etc/os-release').read_text().splitlines() if '=' in line for key, value in [line.split('=', 1)] if key in ('ID', 'VERSION_ID', 'PRETTY_NAME')}
report['kernel'] = command(['uname', '-r'])
report['uptime'] = Path('/proc/uptime').read_text().split()[0]
report['memory_kib'] = {key: int(value.split()[0]) for line in Path('/proc/meminfo').read_text().splitlines() for key, value in [line.split(':', 1)] if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree')}
report['disk_root_bytes'] = dict(zip(('total', 'used', 'free'), shutil.disk_usage('/')))
units = ('crowdsec.service', 'crowdsec-firewall-bouncer.service', 'crowdsec-1key-bot.service', 'crowdbastion-notify.service', 'docker.service', 'nginx.service', 'crowdsec-v2bx-observer.service')
properties = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'NRestarts', 'ExecMainStartTimestamp', 'ExecMainStatus', 'Result', 'FragmentPath', 'After')
report['services'] = {}
for unit in units:
    raw = command(['systemctl', 'show', unit, '--no-pager', '--property='+','.join(properties)])
    report['services'][unit] = {line.split('=', 1)[0]: line.split('=', 1)[1] for line in raw.get('output', '').splitlines() if '=' in line}
report['source_roots'] = {root: source_manifest(root) for root in (
    '/root/crowdsec-1key', '/opt/crowdbastion/releases/review-20261030',
    '/usr/local/lib/crowdsec-1key/current', '/usr/local/lib/crowdsec-1key-bot',
    '/usr/local/lib/crowdsec-1key-bot/runtime/current', '/usr/local/lib/crowdbastion-notify')}
report['git'] = {'head': command(['git', '-C', '/root/crowdsec-1key', 'rev-parse', 'HEAD']),
    'status': command(['git', '--no-optional-locks', '-C', '/root/crowdsec-1key', 'status', '--porcelain'])}
report['releases'] = {root: sorted(path.name for path in Path(root).glob('*') if path.is_dir()) for root in ['/opt/crowdbastion/releases','/usr/local/lib/crowdsec-1key']}
report['manager_flags'] = {flag: flag in Path('/root/crowdsec-1key/crowdbastion.sh').read_text() for flag in ['--status-json','--status','--check-config']}
report['configs'] = {}
for name, fields in (
    ('/var/lib/crowdbastion/node-roles.json', ('roles',)),
    ('/etc/crowdsec/crowdsec-1key-bot.json', ('crowdsec_config', 'manager_script', 'maintenance_lock', 'migration_state', 'state_dir', 'whitelist_file', 'npm_log_dir', 'notification_callbacks')),
    ('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml', ('mode', 'iptables_chains', 'iptables_add_rule_comments', 'disable_ipv6')),
    ('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local', ('mode', 'iptables_chains', 'iptables_add_rule_comments', 'disable_ipv6')),
):
    report['configs'][name] = config_summary(name, fields)
for name in ('/etc/crowdsec/config.yaml', '/etc/crowdsec/config.yaml.local', '/var/lib/crowdbastion/firewall-migration', '/run/lock', '/run/lock/crowdsec-1key.lock', '/etc/crowdsec/crowdsec-1key-web-installs.json', '/etc/cron.d/crowdsec-autoupdate', '/var/spool/cron/crontabs/root'):
    report['configs'][name] = {'metadata': metadata(name)}
migration = Path('/var/lib/crowdbastion/firewall-migration')
report['migration_markers'] = {name: metadata(migration / name) for name in ('committed', 'rolled-back')}
report['crons'] = []
cron_files = [Path('/etc/crontab'), Path('/var/spool/cron/crontabs/root'), *Path('/etc/cron.d').glob('*')]
for file in cron_files:
    if not file.is_file():
        continue
    for line in file.read_text(errors='replace').splitlines():
        if not re.search('crowdsec|crowdbastion', line, re.I):
            continue
        text = line.lstrip('# ').strip()
        fields = text.split()
        report['crons'].append({'file': str(file), 'disabled': line.lstrip().startswith('#'),
            'schedule_fields': fields[:1] if fields and fields[0].startswith('@') else fields[:5] if len(fields) >= 5 and all(re.fullmatch(r'[0-9*/,\-]+', field) for field in fields[:5]) else [],
            'script_paths': re.findall(r'/[A-Za-z0-9_./-]+\.sh', text), 'line_sha256': hashlib.sha256(line.encode()).hexdigest()})
report['containers'] = []
container_ids = command(['docker', 'ps', '-aq']).get('output', '').splitlines()
for identifier in container_ids:
    inspected = command(['docker', 'inspect', identifier])
    try:
        item = json.loads(inspected['output'])[0]
        report['containers'].append({'name': item['Name'].lstrip('/'), 'image': item['Config']['Image'],
            'state': {key: item['State'].get(key) for key in ('Status', 'Running', 'Restarting', 'OOMKilled', 'ExitCode', 'StartedAt')},
            'health': item['State'].get('Health', {}).get('Status'), 'network': item['HostConfig']['NetworkMode'], 'restart_policy': item['HostConfig']['RestartPolicy'],
            'mounts': [{'source': entry['Source'], 'destination': entry['Destination'], 'rw': entry['RW']} for entry in item.get('Mounts', [])]})
    except (KeyError, ValueError, IndexError):
        report['containers'].append({'inspect_failed': identifier[:12]})
report['versions'] = {'crowdsec': command(['crowdsec', '-version']), 'cscli': command(['cscli', 'version']),
    'packages': command(['dpkg-query', '-W', '-f=${Package}\t${Version}\n', 'crowdsec', 'crowdsec-firewall-bouncer-iptables', 'ipset', 'iptables', 'docker-ce'])}
report['listeners'] = command(['ss', '-H', '-lntu'])
print(json.dumps(report, ensure_ascii=False, indent=2))

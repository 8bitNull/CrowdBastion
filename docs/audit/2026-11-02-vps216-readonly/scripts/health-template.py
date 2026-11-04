import contextlib
import hashlib
import importlib.abc
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def command(argv, timeout=20):
    started = time.monotonic()
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
            env=dict(os.environ, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1'))
        return {'exit': result.returncode, 'seconds': round(time.monotonic()-started, 3), 'stdout': result.stdout, 'stderr': result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'error': type(error).__name__, 'seconds': round(time.monotonic()-started, 3)}


def file_info(path):
    path = Path(path)
    if not path.is_file():
        return {'exists': False}
    data = path.read_bytes()
    info = path.stat()
    return {'exists': True, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': oct(info.st_mode & 0o7777), 'uid': info.st_uid}


def endpoint(value):
    try:
        parsed = urllib.parse.urlsplit(str(value))
        return {'scheme': parsed.scheme, 'host': parsed.hostname, 'port': parsed.port}
    except ValueError:
        return {'invalid': True}


report = {'checked_at': time.time()}
sys.path.insert(0, '/root/crowdsec-1key/lib')
import crowdsec_config
base = '/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml'
merged = crowdsec_config.merged_config(base)
report['effective_firewall'] = {key: merged.get(key) for key in ('mode', 'iptables_chains', 'iptables_v4_chains', 'iptables_v6_chains', 'disable_ipv4', 'disable_ipv6', 'iptables_chain', 'blacklists_ipv4', 'blacklists_ipv6', 'supported_decisions_types', 'update_frequency', 'origins', 'scopes', 'scenarios_containing', 'scenarios_not_containing')}
report['effective_firewall']['api_endpoint'] = endpoint(merged.get('api_url'))
for binary, family in (('iptables', 'ipv4'), ('ip6tables', 'ipv6')):
    result = command([binary, '-w', '5', '-S'])
    lines = result.get('stdout', '').splitlines()
    report['rules_'+family] = {'exit': result.get('exit'), 'sha256': hashlib.sha256(result.get('stdout', '').encode()).hexdigest(),
        'policies': [line for line in lines if line.startswith('-P ')],
        'first_rules': {chain: next((line for line in lines if line.startswith('-A '+chain+' ')), None) for chain in ('INPUT', 'FORWARD', 'DOCKER-USER', 'CROWDSEC_CHAIN')},
        'crowdsec_rule_count': sum('CROWDSEC' in line for line in lines)}

# These sources arrive through stdin and are loaded into memory only. Only the
# read-only audit/inspection entry points are called; no install/migration code.
class MemorySources(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        return importlib.util.spec_from_loader(fullname, self) if fullname in MEMORY_SOURCES else None
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        module.__file__ = '<in-memory-readonly-probe>/' + module.__name__ + '.py'
        exec(compile(MEMORY_SOURCES[module.__name__], module.__file__, 'exec'), module.__dict__)

loopback = False
try:
    loopback = ipaddress.ip_address(report['effective_firewall']['api_endpoint']['host']).is_loopback
except (KeyError, ValueError):
    pass
if loopback:
    for name in MEMORY_SOURCES:
        sys.modules.pop(name, None)
    sys.meta_path.insert(0, MemorySources())
    import crowdsec_firewall_runtime
    import crowdsec_firewall_evidence
    text = io.StringIO()
    try:
        with contextlib.redirect_stdout(text):
            status = crowdsec_firewall_runtime.audit(Path(base), decisions=False)
        report['latest_readonly_firewall_audit'] = {'exit': status, 'output': text.getvalue()}
        report['decision_membership'] = crowdsec_firewall_evidence.inspect(Path(base))
    except Exception as error:
        report['latest_readonly_firewall_audit'] = {'error': type(error).__name__}
else:
    report['decision_membership'] = {'state': 'unknown', 'reason': 'non-loopback endpoint; not queried'}

report['lapi_status'] = {key: value for key, value in command(['cscli', '-c', '/etc/crowdsec/config.yaml', 'lapi', 'status']).items() if key in ('exit', 'seconds', 'error')}
registry = command(['cscli', '-c', '/etc/crowdsec/config.yaml', 'bouncers', 'list', '-o', 'json'])
try:
    report['bouncer_registry'] = [{'name': entry.get('name'), 'revoked': entry.get('revoked'), 'last_pull': entry.get('last_pull'), 'type': entry.get('type'), 'version': entry.get('version')} for entry in json.loads(registry['stdout'])]
except Exception as error:
    report['bouncer_registry'] = {'error': type(error).__name__}
metrics = command(['cscli', '-c', '/etc/crowdsec/config.yaml', 'metrics', 'show', 'acquisition', '-o', 'json'])
try:
    import crowdbastion_health
    sources = crowdbastion_health.parse_acquisition_metrics(metrics['stdout'])
    report['acquisition'] = {'exit': metrics.get('exit'), 'state': crowdbastion_health.acquisition_state(sources), 'sources': sources}
except Exception as error:
    report['acquisition'] = {'exit': metrics.get('exit'), 'error': type(error).__name__}

report['web_registry_present'] = Path('/etc/crowdsec/crowdsec-1key-web-installs.json').is_file()
report['web_installs'] = {}
nginx = command(['docker', 'exec', 'nginx', 'nginx', '-T'])
text = nginx.get('stdout', '')
report['nginx_configuration'] = {'exit':nginx.get('exit'),'seconds':nginx.get('seconds'),'lua_access_hook_present':'access_by_lua' in text,'crowdsec_named_directive_present':'crowdsec' in text.lower()}

report['journal_error_counts_24h'] = {}
for unit in ('crowdsec.service', 'crowdsec-firewall-bouncer.service', 'crowdsec-1key-bot.service', 'crowdbastion-notify.service'):
    result = command(['journalctl', '-u', unit, '--since=-24h', '-p', 'err', '-o', 'json', '--no-pager'])
    messages = []
    for line in result.get('stdout', '').splitlines():
        try:
            messages.append(str(json.loads(line).get('MESSAGE', '')))
        except ValueError:
            pass
    report['journal_error_counts_24h'][unit] = {'records': len(messages), 'classes': {label: sum(bool(re.search(pattern, message, re.I)) for message in messages) for label, pattern in (
        ('out_of_memory', r'out of memory|oom'), ('network_timeout', r'timeout|timed out'), ('authentication', r'unauthorized|authentication|permission denied'), ('traceback', r'Traceback|ModuleNotFoundError'), ('rate_limit', r'rate.?limit|too many requests'))}}

report['listener_processes'] = command(['ss', '-H', '-lntup'])
report['firewall_binary_version'] = command(['/usr/bin/crowdsec-firewall-bouncer', '-version'])
report['system_restore_services'] = {unit: {key: value for key, value in command(['systemctl', 'show', unit, '--property=LoadState,ActiveState,UnitFileState', '--no-pager']).items() if key in ('exit', 'stdout', 'error')} for unit in ('netfilter-persistent.service', 'nftables.service', 'iptables.service', 'ip6tables.service')}
report['maintenance_paths'] = {name: file_info(name) for name in ('/opt/crowdsec-1key-maintenance/cron.sh', '/etc/cron.d/crowdsec-autoupdate', '/etc/systemd/system/crowdsec-firewall-bouncer.service.d/20-crowdbastion-docker-order.conf')}
# Preserve only the redacted status output in the client; no raw diagnostic is
# stored. This existing deployment's --status entry point performs inspection.
report['existing_manager_status'] = command(['bash', '/root/crowdsec-1key/crowdbastion.sh', '--status'], timeout=45)
report['existing_node_diagnosis'] = command(['bash', '/root/crowdsec-1key/crowdbastion.sh', '--diagnose-v2bx'], timeout=40)
report['finished_at'] = time.time()
# Only whitelisted summaries leave the server. Also mask exact credentials in
# diagnostic text in case an older status command includes one unexpectedly.
import yaml
secrets = set()
def find_secrets(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if re.search(r'(?:password|secret|token|api[_-]?key)', str(key), re.I) and isinstance(item, str) and len(item) >= 8:
                secrets.add(item)
            else:
                find_secrets(item)
    elif isinstance(value, list):
        for item in value: find_secrets(item)
for config_path in [Path(base), Path('/etc/crowdsec/local_api_credentials.yaml'), Path('/etc/crowdsec/online_api_credentials.yaml'), Path(base+'.local'), Path('/etc/V2bX/config.json')]:
    if config_path.is_file():
        try: find_secrets(yaml.safe_load(config_path.read_text()))
        except yaml.YAMLError: pass
for entry in report['web_installs'].values():
    conf = Path(entry['host_assets'])/'bouncer.conf'
    if conf.is_file():
        for line in conf.read_text().splitlines():
            if '=' in line:
                key, value = line.split('=',1)
                if re.search('KEY|TOKEN|SECRET|PASSWORD',key) and len(value.strip()) >= 8: secrets.add(value.strip())
encoded=json.dumps(report, ensure_ascii=False, indent=2)
report['exact_credential_matches_in_output'] = sum(value in encoded for value in secrets)
encoded=json.dumps(report, ensure_ascii=False, indent=2)
for value in sorted(secrets,key=len,reverse=True):
    encoded=encoded.replace(value,'<redacted>').replace(json.dumps(value,ensure_ascii=False)[1:-1],'<redacted>')
print(encoded)


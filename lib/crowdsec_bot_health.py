"""Bounded, read-only dashboard checks; standard library and shared health rules."""
import json
from pathlib import Path
import subprocess
import time

from crowdbastion_health import acquisition_state, parse_acquisition_metrics, summarize
from crowdbastion_node import load as load_roles


class HealthCollector:
    """Collect fixed observations and reuse them for thirty monotonic seconds."""

    def __init__(self, config_path: str, roles_path='/var/lib/crowdbastion/node-roles.json'):
        self.config_path = config_path
        self.roles_path = Path(roles_path)
        self._cached = None
        self._cached_at = None

    @staticmethod
    def _run(args, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL, check=False,
                                  timeout=min(5.0, remaining))
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
            return None

    def _service(self, unit, deadline):
        result = self._run(['systemctl', 'is-active', unit], deadline)
        if result is None:
            return 'unknown'
        output = result.stdout.strip()
        if result.returncode == 0 and output == 'active':
            return 'ok'
        if result.returncode != 0 and output in ('inactive', 'failed'):
            return 'fault'
        if result.returncode != 0 and output == 'unknown':
            return 'missing'
        return 'unknown'

    def _firewall(self, required, deadline):
        base = Path(self.config_path).parent / 'bouncers' / 'crowdsec-firewall-bouncer.yaml'
        try:
            configured = False
            for path in (base, Path(str(base) + '.local')):
                # A special file or linked configuration is insufficient evidence.
                if path.is_symlink() or (path.exists() and not path.is_file()):
                    return 'unknown'
                configured = path.is_file() or configured
        except OSError:
            return 'unknown'
        if not configured:
            return 'missing' if required else 'optional'
        return self._service('crowdsec-firewall-bouncer', deadline)

    def _cscli(self, args, deadline):
        return self._run(['cscli', '-c', self.config_path, *args], deadline)

    def _local(self, checks, roles, deadline):
        checks['core'] = self._service('crowdsec', deadline)
        try:
            configured = Path(self.config_path).is_file()
        except OSError:
            configured = False
        if configured:
            result = self._cscli(['lapi', 'status'], deadline)
            checks['api'] = 'unknown' if result is None else 'ok' if result.returncode == 0 else 'fault'
        else:
            checks['api'] = 'missing'
        checks['bouncer'] = self._firewall('relay' in roles, deadline)
        if not configured:
            return
        result = self._cscli(['bouncers', 'list', '-o', 'json'], deadline)
        if result is not None and result.returncode == 0:
            try:
                registry = json.loads(result.stdout)
                if not isinstance(registry, list) or any(
                        not isinstance(row, dict) or not isinstance(row.get('name'), str) or not row['name']
                        or type(row.get('revoked')) is not bool
                        for row in registry):
                    raise ValueError('invalid registry')
                checks['registry'] = ('missing' if not registry else 'fault'
                                      if any(row['revoked'] for row in registry) else 'ok')
            except (ValueError, TypeError, RecursionError):
                pass
        result = self._cscli(['metrics', 'show', 'acquisition', '-o', 'json'], deadline)
        if result is not None and result.returncode == 0:
            try:
                sources = parse_acquisition_metrics(result.stdout)
                checks['metrics'] = 'ok'
                checks['logs'] = acquisition_state(sources)
            except (ValueError, TypeError, RecursionError):
                pass

    def collect(self):
        now = time.monotonic()
        if self._cached is not None and now - self._cached_at < 30:
            return self._cached
        deadline = now + 20
        checks = dict.fromkeys(('core', 'api', 'bouncer', 'registry', 'metrics', 'logs', 'remote'), 'unknown')
        checks['traffic'] = 'pending'
        roles = []
        try:
            try:
                roles = load_roles(self.roles_path)
            except FileNotFoundError:
                roles = ['web']
        except (OSError, ValueError, UnicodeError, RecursionError):
            checks['check'] = 'unknown'
            scope = '节点用途配置无法确认，运行检查未完成'
        else:
            if 'remote' in roles:
                for key in ('core', 'api', 'registry', 'metrics', 'logs'):
                    checks[key] = 'optional'
                checks['bouncer'] = self._firewall(True, deadline)
                # Local service state cannot confirm remote authentication or delivery.
                scope = '远端执行节点：本机防火墙 Bouncer；远端连接与实际拦截待验证'
            else:
                checks['remote'] = 'optional'
                self._local(checks, roles, deadline)
                scope = '本地 CrowdSec、LAPI、已配置防火墙 Bouncer 与日志解析'
        records = [(key, 'required') for key, state in checks.items() if state != 'optional']
        summary = summarize([*records, *checks.items()], 2, 'overall', ' '.join(roles))
        self._cached = {'checked_at': time.time(), 'checks': checks, 'summary': summary, 'scope': scope}
        self._cached_at = time.monotonic()
        return self._cached

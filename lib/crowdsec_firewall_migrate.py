#!/usr/bin/env python3
"""Staged migration for the default official nftables bouncer on Docker hosts."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import uuid

import yaml
from crowdsec_config import merged_config, read_mapping
from crowdsec_firewall_runtime import DROPIN, ORDER, LEGACY_ORDER, UNIT, chain_coverage, cron_risks, restore_services, iptables_references, run

CONFIG = Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
STATE = Path('/var/lib/crowdbastion/firewall-migration')
TABLE = 'crowdbastion_migration'
TIMER = 'crowdbastion-firewall-rollback'
FLOW_UNIT = 'crowdbastion-firewall-flow'


class MigrationError(ValueError):
    """Only fixed, authored messages of this type may be shown to the user."""


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.cb-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise MigrationError('LAPI 重定向被拒绝。')


def _live(config):
    data = merged_config(config)
    url = urlsplit(data['api_url'])
    # This migration operates only on a local API, never a remote-only node.
    if url.scheme != 'http' or url.hostname not in ('127.0.0.1', '::1') or url.username or url.password:
        raise MigrationError('迁移仅支持本机 loopback HTTP LAPI。')
    request = urllib.request.Request(data['api_url'].rstrip('/')+'/v1/decisions',
                                     headers={'X-Api-Key': data['api_key']})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        rows = json.load(response)
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise MigrationError('无效决策响应。')
    return rows


def live(config=CONFIG):
    try:
        return _live(config)
    except MigrationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        # HTTP libraries may include raw header values in their exceptions.
        raise MigrationError('本机 LAPI 或有效配置无法读取；未输出凭据。') from None


def seconds(value):
    if not isinstance(value, str):
        raise MigrationError('决策时长无效。')
    if value.startswith('-'):
        return 0
    parts = re.findall(r'(\d+(?:\.\d+)?)(ns|us|µs|ms|h|m|s)', value)
    if ''.join(n+u for n, u in parts) != value:
        raise MigrationError('决策时长无效。')
    scale = {'h': 3600, 'm': 60, 's': 1, 'ms': .001, 'us': .000001, 'µs': .000001, 'ns': 1e-9}
    return sum(float(n)*scale[u] for n, u in parts)


def networks(rows, minleft=0):
    return {ipaddress.ip_network(row['value'], strict=False) for row in rows
            if row.get('type') == 'ban' and row.get('scope', '').lower() in ('ip', 'range')
            and seconds(row.get('duration', '0s')) > minleft}


def table_present():
    payload = json.loads(run(['nft', '-j', 'list', 'tables']).stdout)
    return any(record.get('table', {}).get('family') == 'inet'
               and record.get('table', {}).get('name') == TABLE for record in payload['nftables'])


def native_references(ruleset, config):
    """Bind native membership to direct source DROP references in each hook."""
    data = merged_config(config)
    records = ruleset['nftables']
    references = {}
    for version, protocol, label, table_default, base in (
            (4, 'ip', 'ipv4', 'crowdsec', 'crowdsec-blacklists'),
            (6, 'ip6', 'ipv6', 'crowdsec6', 'crowdsec6-blacklists')):
        table = data.get('nftables', {}).get(label, {}).get('table', table_default)
        sets = {(item['set'].get('family'), table, item['set']['name']): item['set']
                for item in records if 'set' in item and item['set'].get('table') == table
                and item['set'].get('family') in (protocol, 'inet')
                and re.fullmatch(re.escape(base)+r'(?:-.+)?', item['set'].get('name', ''))}
        for hook in ('input', 'forward'):
            selected = set()
            for item in records:
                chain = item.get('chain', {})
                if chain.get('table') != table or chain.get('family') not in (protocol, 'inet') or chain.get('hook') != hook:
                    continue
                for record in records:
                    rule = record.get('rule', {})
                    if (rule.get('family'), rule.get('table'), rule.get('chain')) != (chain['family'], table, chain['name']):
                        continue
                    exprs = [expr for expr in rule.get('expr', []) if 'counter' not in expr]
                    if not exprs:
                        continue
                    if len(exprs) != 2 or exprs[1] != {'drop': None}:
                        raise MigrationError('原 nftables 链包含无法确认的规则，保留临时保护。')
                    match = exprs[0].get('match', {})
                    target = match.get('right')
                    if match.get('op') not in ('==', 'in') or match.get('left') != {'payload': {'protocol': protocol, 'field': 'saddr'}} or not isinstance(target, str) or not target.startswith('@'):
                        raise MigrationError('原 nftables 规则不是直接来源集合封禁。')
                    key = (chain['family'], table, target[1:])
                    if key not in sets:
                        raise MigrationError('原 nftables 封禁集合引用无法确认。')
                    selected.add(key)
            if not selected:
                raise MigrationError('原 nftables 输入或转发封禁路径缺失。')
            references[(version, hook)] = [sets[key] for key in selected]
    return references


def ssh_identity():
    fields = os.environ.get('SSH_CONNECTION', '').split()
    if len(fields) != 4:
        raise MigrationError('必须通过 SSH 会话运行，才能保护当前来源并核验新连接。')
    for value in (fields[0], fields[2]):
        ipaddress.ip_address(value)
    if not all(p.isdecimal() and 0 < int(p) < 65536 for p in (fields[1], fields[3])):
        raise MigrationError('SSH 连接信息无效。')
    return fields


class Migration:
    def __init__(self, state=STATE, config=CONFIG, dropin=DROPIN):
        self.state, self.config, self.dropin = Path(state), Path(config), Path(dropin)
        self.local = Path(str(config)+'.local')
        self.paths = {'base': self.config, 'local': self.local, 'dropin': self.dropin}

    def marker(self, name):
        return (self.state/name).exists()

    def mark(self, name):
        atomic(self.state/name, b'yes\n')

    def metadata(self):
        return json.loads((self.state/'transaction.json').read_text())

    def preflight(self):
        if cron_risks() or restore_services():
            raise MigrationError('存在可能覆盖动态规则的开机任务或恢复服务；请先核对并停用冲突项。')
        config = merged_config(self.config)
        if config.get('mode') != 'nftables':
            raise MigrationError('只迁移当前原生 nftables 后端。')
        for option in ('iptables_chain', 'iptables_v4_chains', 'iptables_v6_chains', 'iptables_chains',
                       'disable_ipv4', 'disable_ipv6', 'blacklists_ipv4', 'blacklists_ipv6'):
            if option in config and config[option] not in (False, None, '', 'CROWDSEC_CHAIN', ['INPUT'], 'crowdsec-blacklists', 'crowdsec6-blacklists', ['crowdsec-blacklists'], ['crowdsec6-blacklists']):
                # Lists and custom set names require independent review.
                raise MigrationError('存在自定义防火墙路径或地址族配置，请人工规划迁移。')
        if config.get('deny_action', 'DROP') != 'DROP':
            raise MigrationError('自动迁移仅支持默认 DROP 策略。')
        if self.dropin.exists() and self.dropin.read_bytes() not in (ORDER, LEGACY_ORDER):
            raise MigrationError('启动顺序 drop-in 已有其他内容，拒绝覆盖。')
        for path in self.paths.values():
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise MigrationError('配置路径不是普通文件。')
        for command in ('nft', 'ipset', 'iptables', 'ip6tables', 'iptables-save', 'ip6tables-save',
                        'ip', 'ss', 'cscli', 'systemd-run'):
            if not shutil.which(command):
                raise MigrationError('请先安装迁移依赖：'+command+'；本操作不自动替换软件包。')
        user = run(['systemctl', 'show', UNIT, '--property=User', '--value']).stdout.strip()
        if user not in ('', 'root', '0'):
            raise MigrationError('自动迁移仅支持官方 root Bouncer 服务。')
        run(['systemctl', 'is-active', '--quiet', UNIT])
        run(['systemctl', 'is-active', '--quiet', 'docker.service'])
        native_references(json.loads(run(['nft', '-j', 'list', 'ruleset']).stdout), self.config)
        if chain_coverage(self.config, True) != 'unknown':
            raise MigrationError('原后端状态不符合迁移预期。')
        # Official service must read this configuration; no custom wrapper units.
        pid = run(['systemctl', 'show', UNIT, '--property=MainPID', '--value']).stdout.strip()
        if not pid.isdecimal() or int(pid) <= 0:
            raise MigrationError('无法定位运行中的 Bouncer。')
        argv = Path('/proc', pid, 'cmdline').read_bytes().decode().strip('\0').split('\0')
        if '-c' not in argv or argv[argv.index('-c')+1:] != [str(self.config)]:
            raise MigrationError('Bouncer 启动参数不是受支持的显式 -c 配置路径。')
        for binary in ('iptables', 'ip6tables'):
            run([binary, '-w', '5', '-S', 'DOCKER-USER'])
        if table_present():
            raise MigrationError('迁移保护表已存在，拒绝覆盖。')
        identity = ssh_identity()
        rows = live(self.config)
        source = ipaddress.ip_address(identity[0])
        if any(source.version == n.version and source in n for n in networks(rows)):
            raise MigrationError('当前 SSH 来源已有封禁决策，拒绝切换。')
        return identity, rows

    def snapshot(self, identity, rows):
        self.state.mkdir(mode=0o700)
        metadata = {}
        for name, path in self.paths.items():
            if path.exists():
                info = path.stat()
                metadata[name] = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
                atomic(self.state/(name+'.before'), path.read_bytes())
            else:
                metadata[name] = None
        atomic(self.state/'files.json', json.dumps(metadata).encode())
        local = read_mapping(self.local) if self.local.exists() else {}
        chains = ['INPUT', 'FORWARD', 'DOCKER-USER']
        local.update(mode='iptables', iptables_chains=chains, iptables_v4_chains=chains, iptables_v6_chains=chains)
        atomic(self.state/'local.applied', yaml.safe_dump(local, sort_keys=False).encode())
        atomic(self.state/'dropin.applied', self.dropin.read_bytes() if self.dropin.exists() else ORDER)
        atomic(self.state/'transaction.json', json.dumps({'ssh': identity, 'created': time.time(),
                                                        'id': uuid.uuid4().hex}).encode())
        atomic(self.state/'decisions-before.json', json.dumps(rows).encode())
        for binary in ('iptables', 'ip6tables'):
            atomic(self.state/(binary+'.before'), run([binary+'-save']).stdout.encode())
        # Timer uses a private immutable copy, independent of future repo updates.
        for name in ('crowdsec_firewall_migrate.py', 'crowdsec_firewall_runtime.py',
                     'crowdsec_firewall_flow.py', 'crowdsec_config.py', 'crowdbastion_health.py'):
            atomic(self.state/name, Path(__file__).with_name(name).read_bytes())
        self.mark('prepared')

    def hold(self):
        rows = live(self.config)
        nets = networks(rows)
        identity = self.metadata()['ssh']
        source = ipaddress.ip_address(identity[0])
        if any(source.version == n.version and source in n for n in nets):
            raise MigrationError('SSH 来源已有封禁，保留当前状态并要求人工恢复。')
        script = [f'table inet {TABLE} {{']
        for version, kind in ((4, 'ipv4_addr'), (6, 'ipv6_addr')):
            members = ', '.join(map(str, ipaddress.collapse_addresses(n for n in nets if n.version == version)))
            script.append(f'set ban{version} {{ type {kind}; flags interval; auto-merge; '
                          + (f'elements = {{ {members} }}; ' if members else '')+'}')
        for hook in ('input', 'forward'):
            script.extend([f'chain protect_{hook} {{ type filter hook {hook} priority -20; policy accept;',
                           'ip saddr @ban4 drop', 'ip6 saddr @ban6 drop', '}'])
        script.append('}')
        script = '\n'.join(script)+'\n'
        run(['nft', '-c', '-f', '-'], input=script)
        self.mark('hold-created')
        run(['nft', '-f', '-'], input=script)

    def admin(self, add):
        source, _, _, port = self.metadata()['ssh']
        binary = 'ip6tables' if ':' in source else 'iptables'
        rule = ['-s', source, '-p', 'tcp', '--dport', port, '-m', 'comment',
                '--comment', TABLE, '-j', 'ACCEPT']
        status = run([binary, '-w', '5', '-C', 'INPUT', *rule], check=False).returncode
        if status not in (0, 1):
            raise MigrationError('无法核查 SSH 保护规则；保留当前保护。')
        exists = status == 0
        if add and not exists:
            self.mark('admin-created')
            run([binary, '-w', '5', '-I', 'INPUT', '1', *rule])
        elif not add and exists and self.marker('admin-created'):
            run([binary, '-w', '5', '-D', 'INPUT', *rule])

    def drift(self):
        # Files may be either original or applied after an interrupted write.
        for name, path in self.paths.items():
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise MigrationError('配置路径类型发生漂移，拒绝覆盖。')
            current = path.read_bytes() if path.exists() else None
            allowed = []
            for suffix in (('before',) if name == 'base' else ('before', 'applied')):
                saved = self.state/(name+'.'+suffix)
                allowed.append(saved.read_bytes() if saved.exists() else None)
            if current not in allowed:
                raise MigrationError('配置发生漂移；保留保护规则和备份，需人工恢复。')

    def membership(self, native=False):
        expected = networks(live(self.config), 15)
        buckets = {}
        if native:
            ruleset = json.loads(run(['nft', '-j', 'list', 'ruleset']).stdout)
            for key, sets in native_references(ruleset, self.config).items():
                actual = set()
                for item in sets:
                    for value in item.get('elem', []):
                        if isinstance(value, dict) and 'elem' in value:
                            value = value['elem']['val']
                        if isinstance(value, str):
                            actual.add(ipaddress.ip_network(value, strict=False))
                        elif isinstance(value, dict) and 'prefix' in value:
                            prefix = value['prefix']
                            actual.add(ipaddress.ip_network(str(prefix['addr'])+'/'+str(prefix['len']), strict=False))
                        elif isinstance(value, dict) and 'range' in value:
                            actual.update(ipaddress.summarize_address_range(*map(ipaddress.ip_address, value['range'])))
                        else:
                            raise MigrationError('无法核查原 nftables 集合成员；保留临时保护。')
                buckets[key] = actual
        else:
            references = iptables_references(self.config, True)
            buckets = {(4, 'all'): set(), (6, 'all'): set()}
            for line in run(['ipset', 'save']).stdout.splitlines():
                tokens = line.split()
                if len(tokens) >= 3 and tokens[0] == 'add':
                    for version, names in references.items():
                        if tokens[1] in names:
                            net = ipaddress.ip_network(tokens[2], strict=False)
                            if net.version != version:
                                raise MigrationError('封禁集合地址族不匹配。')
                            buckets[(version, 'all')].add(net)
        from bisect import bisect_right
        for (version, _), actual in buckets.items():
            collapsed = list(ipaddress.collapse_addresses(actual))
            starts = [int(n.network_address) for n in collapsed]
            for net in (n for n in expected if n.version == version):
                index = bisect_right(starts, int(net.network_address))-1
                if index < 0 or not net.subnet_of(collapsed[index]):
                    raise MigrationError('有效封禁未完整进入实际引用的内核集合。')
        return {'expected': len(expected), 'kernel': len(set().union(*buckets.values())), 'missing': 0}

    def wait_coverage(self, native=False):
        deadline = time.monotonic()+60
        while True:
            try:
                return self.membership(native)
            except ValueError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    def rules(self):
        self.admin(False)
        if chain_coverage(self.config, True) != 'ok':
            raise MigrationError('双栈防火墙入口尚未完整接入。')
        for binary in ('iptables', 'ip6tables'):
            before = (self.state/(binary+'.before')).read_text().splitlines()
            after = run([binary+'-save']).stdout.splitlines()
            def normalize(rows, changed):
                table = None
                result = []
                for line in rows:
                    if line.startswith('*'):
                        table = line
                        result.append(line)
                    elif line == 'COMMIT':
                        result.append(line)
                    elif line.startswith(':'):
                        if changed and table == '*filter' and line.startswith(':CROWDSEC_CHAIN '):
                            continue
                        result.append(' '.join(line.split()[:2]))
                    elif line.startswith('-A '):
                        owned = table == '*filter' and (line.startswith('-A CROWDSEC_CHAIN ')
                            or re.fullmatch(r'-A (INPUT|FORWARD|DOCKER-USER) -j CROWDSEC_CHAIN', line))
                        if not (changed and owned):
                            result.append(line)
                return result
            if normalize(before, False) != normalize(after, True):
                raise MigrationError('非 CrowdSec 业务规则、链策略或顺序发生变化。')

    def start(self):
        if self.state.exists():
            raise MigrationError('已有迁移记录；请先完成或回退，再归档该私有目录。')
        identity, rows = self.preflight()
        try:
            self.snapshot(identity, rows)
            run(['systemd-run', '--collect', '--unit='+TIMER, '--on-active=8m', '--timer-property=AccuracySec=1s',
                 sys.executable, str(self.state/'crowdsec_firewall_migrate.py'), 'rollback',
                 '--state', str(self.state)])
            run(['systemctl', 'is-active', '--quiet', TIMER+'.timer'])
            self.mark('armed')
            self.hold()
            self.admin(True)
            self.mark('switch-started')
            run(['systemctl', 'stop', UNIT])
            atomic(self.local, (self.state/'local.applied').read_bytes())
            atomic(self.dropin, (self.state/'dropin.applied').read_bytes())
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'start', UNIT])
            run(['systemctl', 'is-active', '--quiet', UNIT])
            self.wait_coverage()
            self.rules()
            self.mark('awaiting-verification')
        except BaseException:
            if self.state.is_dir():
                self.rollback()
            raise
        print('已切换，8 分钟自动回退仍有效。请立即运行流量验收，并从新的独立 SSH 连接提交。')

    def pending(self):
        if not self.marker('awaiting-verification') or self.marker('committed') or self.marker('rolled-back'):
            raise MigrationError('没有待提交的迁移。')
        self.drift()
        if time.time() > self.metadata()['created']+420:
            raise MigrationError('已接近自动回退时间，拒绝继续验收或提交。')
        run(['systemctl', 'is-active', '--quiet', TIMER+'.timer'])

    def verify(self):
        self.pending()
        if time.time()+285 > self.metadata()['created']+420:
            raise MigrationError('剩余回退窗口不足以完成流量验收，请回退后重试。')
        if self.marker('flow-active') or self.marker('flow-after.json'):
            raise MigrationError('本事务已经运行过流量验收；请先核对结果或回退，不覆盖已有证据。')
        # Flow runner must complete under the migration timer, retaining cleanup
        # evidence even when the SSH process is interrupted.
        loaded = run(['systemctl', 'show', FLOW_UNIT, '--property=LoadState', '--value'], check=False).stdout.strip()
        if loaded != 'not-found':
            raise MigrationError('流量验收服务已存在或状态无法读取。')
        self.mark('flow-launching')
        try:
            result = subprocess.run(['systemd-run', '--collect', '--wait', '--pipe',
                                     '--service-type=exec', '--property=RuntimeMaxSec=180s',
                                     '--unit='+FLOW_UNIT, sys.executable,
                                     str(self.state/'crowdsec_firewall_flow.py'), 'after', str(self.state)], timeout=195)
        finally:
            self.clean_flow()
        if result.returncode:
            raise MigrationError('流量验收未通过；自动回退保持。')
        report = json.loads((self.state/'flow-after.json').read_text())
        if report.get('passed') is not True or report.get('cleanup') != 'done':
            raise MigrationError('流量验收或清理未完成。')
        self.pending()
        self.mark('flow-verified')
        print('本机双栈封禁、续封、删除、到期及正常对照通过；仍需独立 SSH 提交。')

    def clean_flow(self):
        if self.marker('flow-launching') or self.marker('flow-active'):
            loaded = run(['systemctl', 'show', FLOW_UNIT, '--property=LoadState', '--value'], check=False).stdout.strip()
            if loaded == 'loaded':
                run(['systemctl', 'stop', FLOW_UNIT])
            elif loaded != 'not-found':
                raise MigrationError('流量测试服务状态无法读取；保留保护。')
            result = subprocess.run([sys.executable, str(self.state/'crowdsec_firewall_flow.py'),
                                     'cleanup', str(self.state)], timeout=90, capture_output=True)
            if result.returncode or self.marker('flow-active'):
                raise MigrationError('流量测试资源尚未清理；保留保护和回退资料。')
            (self.state/'flow-launching').unlink(missing_ok=True)

    def cleanup(self):
        self.admin(False)
        if self.marker('hold-created') and table_present():
            run(['nft', 'delete', 'table', 'inet', TABLE])

    def rollback(self):
        if self.marker('committed') or self.marker('rolled-back'):
            return
        if not self.marker('prepared'):
            if any(self.marker(name) for name in ('armed', 'hold-created', 'admin-created', 'switch-started', 'flow-launching', 'flow-active')):
                raise MigrationError('事务备份不完整但已有变更标识，保留现场并要求人工恢复。')
            self.mark('rolled-back')
            print('准备阶段中止，未切换防火墙；私有备份已保留。')
            return
        self.drift()
        self.clean_flow()
        if self.marker('switch-started'):
            run(['systemctl', 'stop', UNIT])
            for name in ('local', 'dropin'):
                original = self.state/(name+'.before')
                if original.exists():
                    atomic(self.paths[name], original.read_bytes())
                    metadata = json.loads((self.state/'files.json').read_text())[name]
                    os.chown(self.paths[name], metadata['uid'], metadata['gid'])
                    os.chmod(self.paths[name], metadata['mode'])
                else:
                    self.paths[name].unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'start', UNIT])
            run(['systemctl', 'is-active', '--quiet', UNIT])
            self.wait_coverage(native=True)
        self.cleanup()
        self.mark('rolled-back')
        run(['systemctl', 'stop', TIMER+'.timer'], check=False)
        print('已恢复迁移前配置；旧后端的已知续封缺陷仍存在。')

    def commit(self):
        if self.marker('committed'):
            self.cleanup()
            run(['systemctl', 'stop', TIMER+'.timer'])
            print('迁移已提交，临时保护与定时器清理完成。')
            return
        self.pending()
        identity = ssh_identity()
        original = self.metadata()['ssh']
        if identity == original or identity[0] != original[0] or identity[2:] != original[2:]:
            raise MigrationError('请从同一管理员来源新建独立 SSH 连接后提交。')
        if not self.marker('flow-verified'):
            raise MigrationError('必须先运行本事务的完整流量验收。')
        for name in ('local', 'dropin'):
            if self.paths[name].read_bytes() != (self.state/(name+'.applied')).read_bytes():
                raise MigrationError('迁移配置已变化，拒绝提交。')
        self.clean_flow()
        self.membership()
        self.rules()
        run(['systemctl', 'is-active', '--quiet', UNIT])
        # Timer takes the same transaction flock. Mark intent only after all
        # validation; cleanup is retryable if interrupted, before timer removal.
        self.cleanup()
        self.mark('committed')
        run(['systemctl', 'stop', TIMER+'.timer'])
        print('迁移已提交，自动回退已解除。公网实际业务拦截仍需另行验收。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'verify', 'commit', 'rollback'])
    parser.add_argument('--state', type=Path, default=STATE)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise MigrationError('需要 root。')
    os.umask(0o077)
    # Sibling lock exists before the transaction directory, so failed preflight
    # leaves no half-created transaction. Timer and all actions share this lock.
    args.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (args.state.parent/(args.state.name+'.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda signum, frame: sys.exit(128+signum))
        getattr(Migration(args.state), args.action)()


if __name__ == '__main__':
    try:
        main()
    except (json.JSONDecodeError, UnicodeError):
        print('迁移数据无法读取；保留私有备份和保护规则。', file=sys.stderr)
        sys.exit(1)
    except MigrationError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, IndexError, yaml.YAMLError, subprocess.SubprocessError):
        print('迁移操作未完成；请查看私有事务目录。未确认恢复前保留保护规则及自动回退。', file=sys.stderr)
        sys.exit(1)

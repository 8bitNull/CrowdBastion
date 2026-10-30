#!/usr/bin/env python3
"""Firewall startup and live chain checks. Never restore saved rule tables."""
import argparse
import os
import tempfile
from pathlib import Path
import re
import shlex
import subprocess
import sys

import yaml
from crowdsec_config import merged_config, read_mapping, write
from crowdbastion_health import emit

UNIT = 'crowdsec-firewall-bouncer.service'
ORDER = b'# Managed by CrowdBastion\n[Unit]\nAfter=docker.service\n'
LEGACY_ORDER = b'[Unit]\nAfter=docker.service\n'
DROPIN = Path('/etc/systemd/system') / (UNIT+'.d/20-crowdbastion-docker-order.conf')


class IncompleteStartupError(ValueError):
    def __init__(self, risks):
        super().__init__('开机恢复检查未完成。')
        self.risks = list(risks)


def run(argv, check=True, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, **kwargs)
    if check and result.returncode:
        # Do not include command output, which may contain configuration secrets.
        raise ValueError('系统命令失败：'+argv[0])
    return result


def cron_risks(root=Path('/etc'), spool=Path('/var/spool/cron')):
    """Inspect system cron plus all per-user spool files, including root's."""
    files = [root/'crontab', root/'rc.local']
    for directory in (root/'cron.d', root/'cron.hourly', root/'cron.daily',
                      root/'cron.weekly', root/'cron.monthly'):
        if directory.exists():
            files.extend(p for p in directory.iterdir() if p.is_file())
    if spool.exists():
        files.extend(p for p in spool.rglob('*') if p.is_file())
    risks = []
    for file in files:
        if not file.exists():
            continue
        try:
            lines = file.read_text().splitlines()
        except (OSError, UnicodeError):
            if risks:
                raise IncompleteStartupError(risks) from None
            raise
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith('#'):
                continue
            # Report even --noflush: it can replace chains and does not establish
            # ordering with Docker. No attempt to execute/expand shell input.
            if re.search(r'(?<![\w-])(?:ip6tables|iptables|nftables|nft)-restore\b|\bnft\s+(?:-f|--file)\b', line):
                risks.append(f'{file}:{number}')
    return risks


def restore_services():
    risks = []
    for name in ('netfilter-persistent.service', 'iptables.service', 'ip6tables.service', 'nftables.service'):
        loaded = run(['systemctl', 'show', name, '--property=LoadState', '--value'], check=False).stdout.strip()
        if loaded == 'not-found':
            continue
        if loaded not in ('loaded', 'masked'):
            raise IncompleteStartupError(risks)
        state = run(['systemctl', 'is-enabled', name], check=False).stdout.strip()
        if state in ('enabled', 'enabled-runtime', 'linked', 'linked-runtime', 'alias', 'generated'):
            risks.append(name)
        elif state not in ('disabled', 'masked', 'masked-runtime', 'static', 'indirect'):
            raise IncompleteStartupError(risks)
    return risks


def docker_present():
    state = run(['systemctl', 'show', 'docker.service', '--property=LoadState', '--value']).stdout.strip()
    if state not in ('loaded', 'not-found', 'masked'):
        raise ValueError('无法确认 Docker unit 状态。')
    return state != 'not-found'


def expected_chains(config, docker):
    """Keep custom chains and honor family-specific overrides."""
    result = {}
    for family in ('v4', 'v6'):
        chains = config.get('iptables_'+family+'_chains', config.get('iptables_chains', ['INPUT']))
        if not isinstance(chains, list) or not all(isinstance(c, str) and re.fullmatch(r'[\w-]+', c) for c in chains):
            raise ValueError('防火墙链配置无效。')
        result['iptables_'+family+'_chains'] = list(dict.fromkeys(
            chains+['INPUT', 'FORWARD']+(['DOCKER-USER'] if docker else [])))
    return result


def write_startup(config, dropin=DROPIN):
    data = merged_config(config)
    if data.get('mode') != 'iptables':
        raise ValueError('启动修复只适用于 iptables 后端；其他后端请先检查或迁移。')
    docker = docker_present()
    local = Path(str(config)+'.local')
    overrides = read_mapping(local) if local.exists() else {}
    overrides.update(expected_chains(data, docker))
    if local.is_symlink() or dropin.is_symlink():
        raise ValueError('配置路径不能是符号链接。')
    if docker and dropin.exists() and dropin.read_bytes() not in (ORDER, LEGACY_ORDER):
        raise ValueError('Docker 启动顺序文件已由其他配置管理，拒绝覆盖。')
    write(local, overrides, private=True)
    if docker and not dropin.exists():
        dropin.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.crowdbastion-', dir=dropin.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(ORDER)
            os.replace(temporary, dropin)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class PathCoverageError(ValueError):
    """A readable ruleset has a confirmed missing or bypassed path."""


def iptables_references(config, docker):
    """Return only sets on unconditional source DROP paths in both families."""
    data = merged_config(config)
    chain = data.get('iptables_chain', 'CROWDSEC_CHAIN')
    if data.get('mode') != 'iptables' or not isinstance(chain, str) or not re.fullmatch(r'[\w-]+', chain):
        raise PathCoverageError('Bouncer 后端或链名称无效。')
    references = {}
    for binary, family in [('iptables', 'v4'), ('ip6tables', 'v6')]:
        if data.get('disable_ipv4' if family == 'v4' else 'disable_ipv6', False):
            raise PathCoverageError('无法确认被禁用地址族的双栈覆盖。')
        lines = [shlex.split(line) for line in run([binary, '-w', '5', '-S']).stdout.splitlines()]
        names = data.get('blacklists_ipv4' if family == 'v4' else 'blacklists_ipv6',
                         'crowdsec-blacklists' if family == 'v4' else 'crowdsec6-blacklists')
        names = [names] if isinstance(names, str) else names
        if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
            raise PathCoverageError('封禁集合名称配置无效。')
        drops = [t for t in lines if t[:2] == ['-A', chain]]
        # A preceding ACCEPT/RETURN, negation or protocol condition invalidates
        # coverage even when a later rule has the expected source-set DROP.
        if not drops or not all(len(t) == 9 and t[2:5] == ['-m', 'set', '--match-set']
                                and t[6:] == ['src', '-j', 'DROP']
                                and any(re.fullmatch(re.escape(name)+r'(?:-\d+)?', t[5]) for name in names)
                                for t in drops):
            raise PathCoverageError('CrowdSec 链含缺失或无法确认的来源封禁路径。')
        for entry in expected_chains(data, docker)['iptables_'+family+'_chains']:
            rules = [t for t in lines if t[:2] == ['-A', entry]]
            if not rules or rules[0] != ['-A', entry, '-j', chain]:
                raise PathCoverageError('入口未首先无条件跳转 CrowdSec。')
        references[4 if family == 'v4' else 6] = {t[5] for t in drops}
    return references


def chain_coverage(config, docker):
    data = merged_config(config)
    if data.get('mode') != 'iptables' or data.get('disable_ipv4') or data.get('disable_ipv6'):
        return 'unknown'
    try:
        iptables_references(config, docker)
    except PathCoverageError:
        return 'fault'
    return 'ok'


def audit(config):
    states = []
    for key in ('firewall_startup', 'firewall_paths'):
        emit(key, 'required')
    risks, uncertain, docker, ordered = [], False, None, None
    for probe in (cron_risks, restore_services):
        try:
            risks.extend(probe())
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            risks.extend(getattr(error, 'risks', []))
            uncertain = True
    try:
        docker = docker_present()
        ordered = not docker or 'docker.service' in run(
            ['systemctl', 'show', UNIT, '--property=After', '--value']).stdout.split()
    except (OSError, ValueError, subprocess.SubprocessError):
        uncertain = True
    state = 'fault' if risks or ordered is False else 'unknown' if uncertain or ordered is None else 'ok'
    emit('firewall_startup', state)
    states.append(state)
    print({'ok': '[已检查]', 'fault': '[异常]', 'unknown': '[尚未验证]'}[state],
          '开机规则覆盖与 Docker 启动顺序')
    for location in risks:
        print('  可能覆盖动态规则的任务：'+location+'（仅定位，未修改）')
    if ordered is False:
        print('  Bouncer 缺少 After=docker.service。')
    if uncertain:
        print('  部分开机任务或 systemd 依赖无法读取；已确认的问题仍保留。')
    try:
        state = chain_coverage(config, docker) if docker is not None else 'unknown'
    except (OSError, ValueError, TypeError, yaml.YAMLError, subprocess.SubprocessError):
        state = 'unknown'
    emit('firewall_paths', state)
    states.append(state)
    print({'ok': '[已检查]', 'fault': '[异常]', 'unknown': '[尚未验证]'}[state],
          'IPv4/IPv6 INPUT、FORWARD 与适用的 Docker 链入口；实际业务拦截仍需外部验收。')
    return 1 if 'fault' in states else 2 if 'unknown' in states else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['audit', 'write-startup'])
    parser.add_argument('config', type=Path)
    parser.add_argument('--dropin', type=Path, default=DROPIN)
    args = parser.parse_args()
    if args.action == 'audit':
        return audit(args.config)
    write_startup(args.config, args.dropin)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, yaml.YAMLError, subprocess.SubprocessError):
        print('防火墙启动检查或配置未完成；请核对备份，未输出凭据。', file=sys.stderr)
        sys.exit(1)

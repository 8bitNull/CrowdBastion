#!/usr/bin/env python3
"""Read-only repair plan and narrowly scoped root crontab transactions.

The parent owns confirmation and the maintenance lock. Supply a fresh, private
mktemp directory per disable attempt. No saved firewall rules are ever executed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import yaml
from crowdsec_config import merged_config
import crowdsec_firewall_runtime as runtime

BEFORE = 'root.crontab.before'
AFTER = 'root.crontab.after'
RECORD = 'cron.json'
PREFIX = b'# CrowdBastion disabled: '
# Deliberately exclude arguments, quoting, expansions, comments and shell lists.
RESTORE = re.compile(
    rb'[ \t]*@reboot[ \t]+(?P<binary>(?:/(?:[A-Za-z0-9_-]+/)*)?'
    rb'(?P<tool>ip6tables|iptables)-restore)[ \t]*<[ \t]*'
    rb'/etc/iptables/rules\.(?P<version>v4|v6)[ \t]*')


def _root_owned(info):
    return info.st_uid == 0


def _require_root():
    if os.geteuid() != 0:
        raise ValueError('Root privileges are required.')


def _backup_dir(path):
    """Follow runtime_preflight ownership rules, with a private leaf directory."""
    _require_root()
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Backup must be an absolute plain directory.')
    for item in [path, *path.parents]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            raise ValueError('Backup directory must already exist.') from None
        sticky_tmp = item == Path('/tmp') and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or not _root_owned(info)
                or (info.st_mode & 0o022 and not sticky_tmp)):
            raise ValueError('Unsafe backup directory or ancestor.')
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('Backup directory must have mode 0700.')
    return path


def _cron_read():
    _require_root()
    result = subprocess.run(['crontab', '-u', 'root', '-l'],
                            capture_output=True, timeout=30, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode == 1 and not result.stdout and result.stderr.strip() == b'no crontab for root':
        return b''
    if result.returncode != 0:
        raise ValueError('Cannot read root crontab; no changes made.')
    return result.stdout


def _cron_write(content):
    _require_root()
    result = subprocess.run(['crontab', '-u', 'root', '-'], input=content,
                            capture_output=True, timeout=30)
    if result.returncode != 0:
        raise ValueError('Root crontab installation failed; retain backup for review.')


def _family(line):
    match = RESTORE.fullmatch(line.removesuffix(b'\n'))
    if match is None:
        return None
    tool, version = match.group('tool', 'version')
    if (tool, version) == (b'iptables', b'v4'):
        return 'IPv4'
    if (tool, version) == (b'ip6tables', b'v6'):
        return 'IPv6'
    return None


def cron_list():
    """Return sanitized {index, family} rows; indexes are 1-based line numbers."""
    return [{'index': index, 'family': family}
            for index, line in enumerate(_cron_read().splitlines(keepends=True), 1)
            if (family := _family(line))]


def _disabled(before, index):
    lines = before.splitlines(keepends=True)
    if type(index) is not int or not 1 <= index <= len(lines) or not _family(lines[index-1]):
        raise ValueError('Index must identify an exact recognized root reboot restore entry.')
    lines[index-1] = PREFIX + lines[index-1]
    return b''.join(lines)


def _save(path, content):
    # O_EXCL makes retries and pre-existing symlinks fail without overwriting.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _load(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError('Backup file is missing or unsafe.') from None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or not _root_owned(info)
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError('Unsafe backup file.')
        return stream.read()


def cron_disable(backup, index):
    """Back up and comment precisely one recognized entry; never reuse an attempt."""
    backup = _backup_dir(backup)
    if any((backup/name).exists() or (backup/name).is_symlink()
           for name in (BEFORE, AFTER, RECORD)):
        raise ValueError('Backup attempt already contains crontab records.')
    before = _cron_read()
    after = _disabled(before, index)
    _save(backup/BEFORE, before)
    _save(backup/AFTER, after)
    _save(backup/RECORD, json.dumps({'version': 1, 'index': index,
                                   'mode': 0o600, 'uid': 0}).encode())
    if _cron_read() != before:
        raise ValueError('Root crontab changed during backup; no changes made.')
    _cron_write(after)


def cron_restore(backup):
    """Restore only our recorded transition, refusing intervening external edits."""
    backup = _backup_dir(backup)
    before = _load(backup/BEFORE)
    after = _load(backup/AFTER)
    record = json.loads(_load(backup/RECORD))
    if (not isinstance(record, dict) or record.get('version') != 1
            or record.get('uid') != 0 or record.get('mode') != 0o600
            or _disabled(before, record.get('index')) != after):
        raise ValueError('Invalid crontab backup record.')
    current = _cron_read()
    if current == before:
        return
    if current != after:
        raise ValueError('Root crontab differs from recorded after state; restore refused.')
    _cron_write(before)



def plan(config):
    """Return a credential-free, read-only scope for the parent repair workflow."""
    config = Path(config)
    data = merged_config(config)
    if data.get('mode') != 'iptables':
        raise ValueError('Existing deployment repair requires the iptables backend.')
    cron = runtime.cron_risks()
    services = runtime.restore_services()
    docker = runtime.docker_present()
    if type(docker) is not bool:
        raise ValueError('Docker state is unreadable; repair refused.')
    coverage = runtime.chain_coverage(config, docker)
    if coverage not in ('ok', 'fault'):
        raise ValueError('Chain coverage is unreadable; repair refused.')
    chains = runtime.expected_chains(data, docker)
    scope = [
        '保留自定义链，补齐 IPv4/IPv6 INPUT、FORWARD'
        + ('、DOCKER-USER，并设置 Docker 启动顺序。' if docker else '。'),
        '修改前备份配置覆盖文件和启动顺序文件。',
        '限时等待 Bouncer 决策同步，核对实际内核集合。',
        '仅逐项确认停用明确识别的 root 开机规则恢复任务。',
    ]
    if cron:
        scope.append('未知开机恢复任务必须人工核对。')
    if services:
        scope.append('规则恢复服务必须人工核对，不会自动停用。')
    return {'backend': 'iptables', 'cron_risks': cron, 'restore_services': services,
            'docker_present': docker, 'chain_coverage': coverage,
            'expected_chains': chains, 'scope': scope}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('plan').add_argument('config', type=Path)
    actions.add_parser('cron-list')
    disable = actions.add_parser('cron-disable')
    disable.add_argument('backup', type=Path)
    disable.add_argument('index', type=int)
    actions.add_parser('cron-restore').add_argument('backup', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'plan':
            print(json.dumps(plan(args.config), ensure_ascii=False))
        elif args.action == 'cron-list':
            print(json.dumps(cron_list()))
        elif args.action == 'cron-disable':
            cron_disable(args.backup, args.index)
        else:
            cron_restore(args.backup)
        return 0
    except (OSError, ValueError, TypeError, yaml.YAMLError, subprocess.SubprocessError):
        print('已有部署检查或修复未完成；请保留备份，核对配置、开机恢复冲突及权限。',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

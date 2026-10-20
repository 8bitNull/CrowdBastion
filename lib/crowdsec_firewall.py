#!/usr/bin/env python3
"""Read-only checks for the nftables decision-renewal defect found on VPSes."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import yaml

from crowdsec_config import merged_config
from crowdbastion_health import emit


def startup_binary():
    """Read systemd's effective ExecStart path, never its argv or shell syntax."""
    try:
        service = subprocess.run(['systemctl', 'show', '--property=ExecStart', '--value',
                                  'crowdsec-firewall-bouncer'], capture_output=True, text=True, timeout=10)
        if service.returncode != 0:
            return None
        # systemctl prints info.path verbatim, not a shell/C-escaped string.
        # Preserve spaces, quotes and backslashes, including trailing spaces;
        # only the formatter's exact field separator delimits the path.
        match = re.match(r'^\s*\{\s*path=(.*?) ; argv\[\]=',
                         service.stdout, re.S)
        if not match:
            return None
        path = match[1]
        return path if path.startswith('/') and '\0' not in path else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def binary_version(binary):
    if binary:
        try:
            result = subprocess.run([binary, '-version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                match = re.search(r'(?im)^\s*(?:version:\s*)?v?(\d+\.\d+\.\d+)(?:[-+\s]|$)',
                                  result.stdout+'\n'+result.stderr)
                return match[1] if match else None
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


def assess(path, check_startup=False):
    mode = merged_config(path).get('mode')
    if mode in ('iptables', 'ipset'):
        return 'ok', '当前后端未使用已知有续封缺陷的 nftables 实现；实际续封仍需流量验收。'
    if mode != 'nftables':
        raise ValueError('Firewall Bouncer mode 无效。')
    binary = shutil.which('crowdsec-firewall-bouncer')
    try:
        service = subprocess.run(['systemctl', 'show', '--property=MainPID', '--value',
                                  'crowdsec-firewall-bouncer'], capture_output=True, text=True, timeout=10)
        pid = service.stdout.strip()
        if service.returncode == 0 and pid.isdecimal() and int(pid) > 0:
            # Executing the proc inode also identifies a running binary that was
            # replaced on disk. Failure to read it must remain unknown.
            binary = '/proc/'+pid+'/exe'
    except (OSError, subprocess.TimeoutExpired):
        pass
    version = binary_version(binary)
    if check_startup and version not in ('0.0.36', '0.0.38'):
        version = binary_version(startup_binary())
    if version in ('0.0.36', '0.0.38'):
        return 'fault', ('Firewall Bouncer '+version+' 的 nftables 后端存在已确认的续封缺陷：'
                         '内核集合条目可能先于有效决策到期。请备份并规划迁移至 iptables/ipset，'
                         '再验收 IPv4/IPv6 续封、到期与撤销；本次未切换现有后端。')
    return 'unknown', 'nftables 后端的续封修复状态尚未验证；请核对实际二进制并执行续封对照验收。'


def main(args):
    action, path = args
    if action not in ('guard', 'audit'):
        raise ValueError('未知防火墙后端检查。')
    state, message = assess(Path(path), check_startup=action == 'guard')
    if action == 'audit':
        emit('renewal', 'required')
        emit('renewal', state)
    print({'ok': '[已检查] ', 'fault': '[异常] ', 'unknown': '[尚未验证] '}[state]+message,
          file=sys.stderr if action == 'guard' else sys.stdout)
    return 1 if state == 'fault' else 2 if state == 'unknown' and action == 'audit' else 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        print('防火墙后端检查未完成，请核对有效配置；未输出凭据。', file=sys.stderr)
        sys.exit(1)

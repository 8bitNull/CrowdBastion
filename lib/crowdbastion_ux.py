#!/usr/bin/env python3
"""Local UX artifacts; checks do not install components or change health verdicts."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
import tempfile
import time
import unicodedata

from crowdbastion_node import safe_path


def show_home_menu(role_label, roles_ok=True, banner=True):
    """Render navigation only; the shell owns prompts and operation dispatch."""
    columns = shutil.get_terminal_size().columns if sys.stdout.isatty() else 80
    boxed = columns >= 68
    color = (sys.stdout.isatty() and os.environ.get('TERM', 'dumb') != 'dumb'
             and 'NO_COLOR' not in os.environ)

    def paint(text, code):
        return f'\033[{code}m{text}\033[0m' if color else text

    def width(text):
        return sum(0 if unicodedata.combining(c) else
                   2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in text)

    def rule():
        print(paint('+' + '-' * 66 + '+' if boxed else '-' * max(1, columns), '90'))

    def row(text='', center=False):
        plain = re.sub(r'\033\[[0-9;]*m', '', text)
        if boxed:
            left = (66 - width(plain)) // 2 if center else 4
            print(paint('|', '90') + ' ' * left + text
                  + ' ' * (66 - left - width(plain)) + paint('|', '90'))
        else:
            # Count CJK characters as two columns; textwrap counts code points.
            indent = '  ' if columns > 4 else ''
            available = max(2, columns - len(indent))
            if width(plain) <= available:
                print(indent + text)
                return
            chunk = ''
            for char in plain:
                if width(chunk + char) > available:
                    print(indent + chunk)
                    chunk = ''
                chunk += char
            print(indent + chunk)

    print()
    rule()
    row()
    if banner:
        if boxed:
            for art in (r'''
  ____ ____   _____        ______
 / ___|  _ \ / _ \ \      / /  _ \
| |   | |_) | | | \ \ /\ / /| | | |
| |___|  _ <| |_| |\ V  V / | |_| |
 \____|_| \_\\___/  \_/\_/  |____/
''', r'''
 ____    _    ____ _____ ___ ___  _   _
| __ )  / \  / ___|_   _|_ _/ _ \| \ | |
|  _ \ / _ \ \___ \ | |  | | | | |  \| |
| |_) / ___ \ ___) || |  | | |_| | |\  |
|____/_/   \_\____/ |_| |___\___/|_| \_|
'''):
                lines = art.strip('\n').splitlines()
                offset = (66 - max(map(len, lines))) // 2
                for line in lines:
                    # Align each word as a block, retaining its letter spacing.
                    row(paint(line, '96') + ' ' * (66 - 2 * offset - len(line)), True)
                row()
            row(paint('S E R V E R   S E C U R I T Y   &   O P E R A T I O N S', '22;90'), True)
        else:
            row(paint('CrowdBastion', '96'))
        row(paint('服务器防护 · 运维管理', '22;37'), True)
        row()
        rule()

    if roles_ok:
        row(paint('节点用途：', '37') + paint(role_label.strip(), '92'))
    else:
        row(paint('用途配置无法读取，请在高级管理中重新设置。', '33'))
    row(paint('先了解当前情况，再按提示安装或处理问题。', '90'))
    rule()
    for number, label, note in (
            ('1', '检查防护情况', '建议先看这里'),
            ('2', '安装或调整防护', '按用途引导'),
            ('3', '管理封禁与放行', ''),
            ('4', '高级管理', '规则、通知、专项排查等'),
            ('5', '常用操作', '防火墙、验收、落地、维护副本')):
        row(paint(f'[{number}]', '96') + '  ' + paint(label, '37')
            + (paint(f'（{note}）', '90') if note else ''))
    row(paint('[0]', '96') + '  ' + paint('退出', '37'))
    rule()
    print(paint('  Ctrl+D 退出', '90'))


def read_regular(path, maximum=8 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError('not a bounded regular file')
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('file grew too large')
        return data


def validate_private_destination(path, missing_parents=False, *, allow_sticky_parent=False):
    safe_path(path)
    for parent in path.parents:
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if missing_parents:
                continue
            raise
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                info.st_mode & 0o022 and (not info.st_mode & stat.S_ISVTX or
                                         parent == path.parent and not allow_sticky_parent)):
            raise ValueError('unsafe destination directory or ancestor')
        if parent == path.parent and info.st_uid != os.geteuid():
            raise ValueError('destination directory must be owned')


def create_private(path, text):
    """Publish a complete 0600 file without replacing an existing destination."""
    path = Path(os.path.abspath(path))
    # Trust the entire directory chain; a writable ancestor permits replacing
    # an otherwise private parent. Root-owned sticky /tmp remains supported.
    validate_private_destination(path)
    fd, temporary = tempfile.mkstemp(prefix='.crowdbastion-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def _raise_walk_error(error):
    raise error


def tree_fingerprint(root):
    """Config content only. Links contribute their target spelling, never its content."""
    root = Path(root)
    digest = hashlib.sha256()
    if root.is_symlink():
        raise ValueError('unsafe config directory')
    if not root.exists():
        return 'absent'
    if not root.is_dir():
        raise ValueError('unsafe config directory')
    for base, dirs, files in os.walk(root, followlinks=False, onerror=_raise_walk_error):
        dirs[:] = sorted(name for name in dirs if name != '__pycache__')
        for name in sorted(files + [name for name in dirs if (Path(base)/name).is_symlink()]):
            path = Path(base)/name
            digest.update(str(path.relative_to(root)).encode() + b'\0')
            if path.is_symlink():
                digest.update(b'link:' + os.fsencode(os.readlink(path)))
            else:
                digest.update(read_regular(path))
            digest.update(b'\0')
    return digest.hexdigest()


def code_fingerprint(manager):
    # The supported legacy entry is a symlink to crowdbastion.sh.
    manager = Path(manager).resolve(strict=True)
    digest = hashlib.sha256(read_regular(manager))
    helpers = manager.parent/'lib'
    if not helpers.is_dir() or helpers.is_symlink():
        raise ValueError('missing helpers')
    # Path.rglob silently skips unreadable directories on supported Python
    # versions, which could make two incomplete copies appear identical.
    paths = []
    for base, dirs, files in os.walk(helpers, followlinks=False, onerror=_raise_walk_error):
        dirs[:] = [name for name in dirs if name != '__pycache__']
        paths.extend(Path(base)/name for name in dirs + files)
    for path in sorted(paths):
        if path.suffix not in ('.py', '.sh', '.lua'):
            continue
        digest.update(str(path.relative_to(helpers)).encode() + b'\0')
        digest.update(read_regular(path))
    return digest.hexdigest()


def runtime_cron_matches(path, manager):
    """Recognize an active managed job without evaluating any shell or cron text."""
    for line in read_regular(path, 65536).decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split(None, 2 if line.startswith('@') else 6)
        user_index = 1 if line.startswith('@') else 5
        if len(fields) != user_index + 2 or fields[user_index] != 'root':
            continue
        try:
            command = shlex.split(fields[-1], comments=True)
        except ValueError:
            continue
        if (len(command) >= 3 and command[0] in ('bash', '/bin/bash', '/usr/bin/bash')
                and command[1:3] == [str(manager), '--update-hub']):
            return True
    return False


def observer_config(path, core, filename, zone, networks, unit, write=False):
    from crowdsec_v2bx_service import validate_config
    source = dict(name=core, core=core, file=filename, relay_cidrs=networks, unit=unit)
    if zone:
        source['timezone'] = zone
    data = dict(poll_interval=1, sources=[source])
    validate_config(data)
    text = json.dumps(data, ensure_ascii=False, indent=2)+'\n'
    if write:
        create_private(path, text)
    return text


def redact(text):
    # Strip terminal controls; drop complete credential lines, including arbitrary values.
    text = re.sub(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\].*?(?:\x07|\x1b\\|$))', '', text, flags=re.S)
    # Normalize controls before recognizing field names, so split credential
    # labels cannot become readable only after the masking step has finished.
    text = ''.join(c for c in text if c in '\n\t' or ord(c) >= 32 and ord(c) != 127)
    # Anchor each attempt to a line: an unanchored greedy prefix rescans a long
    # credential-free line from every position and can stall report export.
    text = re.sub(r'^[^\n]*(?:api[ _-]*key|password|passwd|secret|token|authorization|credential|login|bot[_-]?id|cookie)[^\n]*$',
                  '[敏感字段已隐藏]', text, flags=re.I | re.M)
    text = re.sub(r'https?://[^\s<>"\']+', '[URL已隐藏]', text, flags=re.I)
    def hide_ip(match):
        value = match.group(0)
        try:
            ipaddress.ip_address(value.rstrip('.'))
            return '[IP已隐藏]'
        except ValueError:
            # An IPv4 endpoint may include a port; retain no address in that case.
            if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}:\d+', value):
                return '[IP及端口已隐藏]'
            return value
    text = re.sub(r'(?<![\w])(?:[0-9a-fA-F]*:[0-9a-fA-F:.]+(?:%[\w.-]+)?|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)(?![\w])', hide_ip, text)
    return text


def save_acceptance(path, root, scope, code, now=None, fingerprint=None):
    if scope is None:
        return
    path = Path(os.path.abspath(path))
    validate_private_destination(path, missing_parents=True)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    validate_private_destination(path)
    # Omit source and control addresses; they are unnecessary to identify the entry.
    data = dict(version=1, time=time.time() if now is None else now, code=code,
                scope={key: scope[key] for key in ('target', 'port', 'protocol', 'family', 'hook')},
                verification=scope.get('verification', 'basic'),
                fingerprint=fingerprint or tree_fingerprint(root), external_results='operator_confirmed')
    fd, temporary = tempfile.mkstemp(prefix='.relay-acceptance-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        safe_path(path)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def acceptance_summary(path, root, now=None, *, fingerprint=None):
    path = Path(os.path.abspath(path))
    if not path.exists() and not path.is_symlink():
        return '历史验收：尚无中转入口验收记录；使用 --verify-relay。'
    safe_path(path)
    data = json.loads(read_regular(path, 65536))
    scope = data['scope']
    if data['version'] != 1 or type(data['code']) is not int or data['code'] not in (0, 1, 2, 130):
        raise ValueError('invalid acceptance')
    target = str(ipaddress.ip_address(scope['target']))
    if (type(scope['port']) is not int or not 1 <= scope['port'] <= 65535 or
            scope['protocol'] not in ('TCP', 'UDP') or scope['family'] not in ('ip', 'ip6') or
            scope['hook'] not in ('input', 'forward')):
        raise ValueError('invalid scope')
    age = (time.time() if now is None else now) - data['time']
    freshness = '记录过期，请重验' if age < 0 or age > 24*3600 else '24 小时内的历史记录'
    if data['fingerprint'] != (tree_fingerprint(root) if fingerprint is None else fingerprint):
        freshness = '检测到配置变化，请重验'
    verdict = {0: '通过（人工确认）', 1: '未通过', 2: '未完成', 130: '已中断'}[data['code']]
    verification = data.get('verification', 'basic')
    if verification not in ('basic', 'lifecycle'):
        raise ValueError('invalid verification scope')
    coverage = '完整生命周期' if verification == 'lifecycle' else '基础连接对照'
    stamp = time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(data['time']))
    return (f'历史验收：{stamp} / {target}:{scope["port"]} / {scope["protocol"]} / '
            f'{"IPv4" if scope["family"] == "ip" else "IPv6"} / {scope["hook"].upper()} / 新连接 / {coverage} / {verdict}。\n'
            f'记录适用性：{freshness}；仅供该入口参考。网络、规则或业务变化也需重验，不改变当前健康结论。')


def change_summary(report, kind, action, code):
    """Fixed human outcomes from one trusted helper report; never echo errors."""
    if kind not in ('network', 'port-policy') or not isinstance(report, dict):
        raise ValueError('invalid result')
    label = 'TCP 配置' if kind == 'network' else '端口策略'
    state = report.get('state')
    error = report.get('error_code')
    followup = f'独立验收后运行 --{kind}-verify、--{kind}-commit，或 --{kind}-rollback。'
    if action == 'status' and any(row.get('state') not in ('committed', 'rolled_back', 'preparation_incomplete')
                                  for row in report.get('transactions', [])):
        return f'{label}存在未完成事务；请用 --{kind}-status 查看具体状态，核对后提交或回退。'
    if error == 'pending_change':
        pending = {'network': 'TCP 配置', 'port-policy': '端口策略'}.get(report.get('pending_kind'), '其他类型')
        return f'存在未完成的{pending}事务；先查看对应 status 并提交或回退，再继续。'
    if report.get('refusal_code') == 'transaction_expired':
        return '事务已过期，拒绝提交；请查看状态并回退，自动回退仍可继续。'
    if error == 'apply_failed':
        return ('应用失败，已恢复本次变更；请核对状态后重试。' if state == 'rolled_back' else
                '应用失败，回退尚未完成；请查看状态并重试 rollback，保留自动重试。')
    if state in ('unstable', 'unknown') and report.get('phase') == 'environment_sample':
        return '环境压力持续或无法确认稳定；暂缓修改，检查宿主机存储与内存后重试。'
    if code == 75:
        return '操作暂缓：管理锁忙或环境无法确认稳定；检查状态后重试。'
    if state == 'verification_failed':
        return '核验未通过，未提交；请检查配置、运行状态与期限，再核验或回退。'
    if state == 'rollback_incomplete':
        return '回退尚未完成；外部漂移保持不动，请核对 status 并重试 rollback。自动重试保留。'
    if code != 0:
        return f'{label}操作未完成；请用 --{kind}-status 和 --{kind}-plan 查看结构化证据，核对支持条件与权限。'
    if report.get('unchanged') is True:
        return f'{label}无需变更；已核验当前配置，未创建新事务。实际流量与吞吐需独立验收。'
    if action == 'plan' and state == 'ready':
        lines = [f'{label}计划可执行；应用后 15 分钟内须提交，否则自动回退。']
        if kind == 'network':
            for row in report.get('changes', []):
                key, before, after = row['key'], str(row['before']), str(row['after'])
                if not re.fullmatch(r'net\.ipv4\.tcp_[a-z_]+', key) or not before.isdigit() or not after.isdigit():
                    raise ValueError('invalid selection')
                lines.append(f'  {key}: {before} → {after}')
        else:
            for row in report.get('scope', {}).get('ingress', []):
                interface, protocol, port = row['interface'], row['protocol'], row['port']
                mode = {'public': '公网', 'local': '仅本机', 'sources': '指定来源'}[row['mode']]
                if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface) or protocol not in ('tcp', 'udp') or type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError('invalid selection')
                sources = ', '.join(str(ipaddress.ip_network(value)) for value in row['sources'])
                lines.append(f'  {interface} {protocol}/{port}: {mode}'+(f' ({sources})' if sources else ''))
            released = len(report.get('released_selectors', []))
            if released: lines.append(f'  将释放 {released} 个原有受管入口；详情先运行 --port-policy-plan。')
        lines.append(f'完整范围与归属见 --{kind}-plan；规则核验不代表实际流量或吞吐通过。')
        return '\n'.join(lines)
    if state == 'staged':
        return f'{label}已暂存；未提交将按原期限自动回退。'+followup
    if state == 'verified' and report.get('id'):
        return '未提交事务核验通过；仍须在原期限内提交。'+followup
    if state == 'committed': return f'{label}事务已提交；实际流量与吞吐仍需独立验收。'
    if state == 'rolled_back': return f'{label}事务已回退。'
    if state == 'verified': return f'{label}本地核验通过；实际流量与吞吐仍需独立验收。'
    if state == 'absent': return f'{label}尚无托管配置或事务。'
    if state == 'audited':
        return 'TCP 配置归属只读审计完成；动态配置、别名及加载顺序详情见 --network-status。此结果不表示可应用或吞吐通过。'
    raise ValueError('unexpected result')


def main(args):
    action, *values = args
    if action == 'home-menu':
        role_label, roles_status, banner = values
        show_home_menu(role_label, roles_ok=roles_status == '0', banner=banner == 'true')
    elif action == 'change-result':
        kind, operation, code = values
        print(change_summary(json.load(sys.stdin), kind, operation, int(code)))
    elif action == 'fingerprint':
        print(tree_fingerprint(values[0]))
    elif action == 'runtime':
        current = code_fingerprint(values[0])
        print('当前源码指纹：'+current[:12])
        try:
            deployed = code_fingerprint(values[1])
        except FileNotFoundError:
            print('定时任务副本：尚未安装；使用 --enable-cron。')
            return 2
        except (OSError, ValueError):
            print('定时任务副本：内容不完整或无法读取，请使用 --sync-runtime 修复托管副本。')
            return 2
        print('维护副本指纹：'+deployed[:12])
        print('定时任务副本：'+('与当前源码一致。' if current == deployed else '与当前源码不同，请使用 --sync-runtime 同步；git pull 不会自动更新副本。'))
        return 0 if current == deployed else 2
    elif action == 'runtime-cron':
        return 0 if runtime_cron_matches(*values) else 2
    elif action in ('observer-preview', 'observer-write'):
        print(observer_config(*values, write=action == 'observer-write'), end='')
    elif action == 'export':
        create_private(values[1], 'CrowdBastion 诊断报告（自动隐藏常见凭据、IP 和 URL；分享前请人工核对域名、路径及业务信息）\n'+redact(read_regular(values[0]).decode('utf-8', errors='replace')))
    elif action == 'acceptance':
        print(acceptance_summary(*values))
    else:
        raise ValueError('unknown action')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, TypeError, KeyError, ImportError, OverflowError):
        print('[ERROR] 无法读取或生成记录；请核对路径、权限、输入格式及文件是否已存在。未安装或重启服务。', file=sys.stderr)
        sys.exit(1)

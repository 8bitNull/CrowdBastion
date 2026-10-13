#!/usr/bin/env python3
"""Read-only relay path observations; never infer topology or read forwarder configs."""
import argparse
import ipaddress
import json
import re
import shlex
import shutil
import subprocess
import sys


class Cancelled(Exception):
    pass


def ask(label):
    try:
        answer = input(label).strip()
    except EOFError:
        raise Cancelled from None
    if answer.lower() in ('cancel', 'q'):
        raise Cancelled
    return answer


def ports(value):
    if not value.strip():
        return set()
    parts = value.split(',')
    if any(not re.fullmatch(r'[0-9]{1,5}', part.strip()) or
           not 1 <= int(part) <= 65535 for part in parts):
        raise ValueError('端口必须是 1-65535 的逗号分隔列表。')
    return {int(part) for part in parts}


def context(args):
    if args:
        parser = argparse.ArgumentParser(description='只读中转路径诊断')
        parser.add_argument('--role', required=True, choices=('entry', 'transit', 'exit', 'unknown'))
        parser.add_argument('--path', required=True, choices=('userspace', 'nat', 'bridge', 'unknown'))
        parser.add_argument('--tcp', default='')
        parser.add_argument('--udp', default='')
        try:
            options = parser.parse_args(args)
        except SystemExit as error:
            if error.code:
                raise ValueError('角色或路径选择无效。') from None
            raise
        return options.role, options.path, ports(options.tcp), ports(options.udp)
    print('中转角色/流量路径只读诊断；不读取 gost/realm 配置，不保存选择。输入 q 取消。')
    role = ask('声明本节点角色：1 入口(entry)，2 中间(transit)，3 出口(exit)，4 不确定(unknown)，0 返回: ')
    if role == '0':
        raise Cancelled
    role = {'1': 'entry', '2': 'transit', '3': 'exit', '4': 'unknown'}.get(role)
    if role is None:
        raise ValueError('角色选择无效。')
    path = ask('声明流量路径：1 用户态(userspace)，2 内核 NAT(nat)，3 Docker bridge，4 不确定(unknown)，0 返回: ')
    if path == '0':
        raise Cancelled
    path = {'1': 'userspace', '2': 'nat', '3': 'bridge', '4': 'unknown'}.get(path)
    if path is None:
        raise ValueError('路径选择无效。')
    tcp = ports(ask('TCP 本地入口端口（逗号分隔，留空不限定）: '))
    udp = ports(ask('UDP 本地入口端口（逗号分隔，留空不限定）: '))
    return role, path, tcp, udp


def read_command(args):
    if not shutil.which(args[0]):
        print('[尚未验证] 缺少 '+args[0]+'，对应本地证据不可读取。')
        return None
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError(args[0]+' 本地只读检查失败。') from None
    if result.returncode:
        raise ValueError(args[0]+' 本地只读检查失败，请核对权限。')
    return result.stdout


def endpoint(value):
    """Return only numeric socket addresses; process names/output are never echoed."""
    address, separator, port = value.rpartition(':')
    if not separator or (port != '*' and not re.fullmatch(r'[0-9]{1,5}', port)):
        return None
    address = address.strip('[]')
    if address != '*':
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return None
    if port != '*' and not 0 <= int(port) <= 65535:
        return None
    formatted = '['+address+']' if ':' in address else address
    return formatted+':'+port, int(port) if port != '*' else None


def sockets(tcp, udp):
    output = read_command(['ss', '-H', '-n', '-t', '-u', '-a'])
    count = 0
    for line in (output or '').splitlines():
        words = line.split()
        if len(words) < 6 or words[0] not in ('tcp', 'udp'):
            continue
        protocol, state = words[:2]
        if state not in ('LISTEN', 'UNCONN', 'ESTAB', 'SYN-RECV', 'SYN-SENT', 'TIME-WAIT', 'CLOSE-WAIT', 'FIN-WAIT-1', 'FIN-WAIT-2', 'LAST-ACK', 'CLOSING'):
            continue
        local, peer = endpoint(words[4]), endpoint(words[5])
        selected = tcp if protocol == 'tcp' else udp
        if not local or not peer or (selected and local[1] not in selected):
            continue
        print(f'[本地 socket 观察] {protocol} {state} local={local[0]} peer={peer[0]}')
        count += 1
    if not count:
        print('[尚未验证] 未发现可识别的所选 socket；端口不能证明进程身份或流量经过路径。')


def nat_value(value):
    if not isinstance(value, str):
        return None
    parsed = endpoint(value)
    if parsed:
        return parsed[0]
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def nat_iptables(output, family, tcp, udp):
    count = 0
    for line in output.splitlines():
        words = shlex.split(line)
        if len(words) < 3 or words[0] != '-A':
            continue
        # Do not turn inverted constraints into positive evidence.
        if '!' in words:
            print('[尚未验证] 跳过含否定条件的 iptables NAT 规则，未将其解释为正向匹配。')
            continue
        chain = words[1]
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', chain):
            continue
        def option(name):
            return next((words[i+1] for i, word in enumerate(words[:-1]) if word == name), None)
        action = option('-j')
        if action not in ('DNAT', 'SNAT', 'MASQUERADE', 'REDIRECT'):
            continue
        protocol, port = option('-p'), option('--dport')
        selected = tcp if protocol == 'tcp' else udp if protocol == 'udp' else set()
        # Source translation without dport remains relevant to source visibility.
        if port and (not port.isdigit() or (selected and int(port) not in selected)):
            continue
        evidence = [family, chain, action]
        if protocol in ('tcp', 'udp'):
            evidence.append(protocol)
        if port and port.isdigit():
            evidence.append('dport='+port)
        for flag in ('-s', '-d', '--to-destination', '--to-source'):
            value = nat_value(option(flag))
            if value:
                evidence.append(flag+'='+value)
        print('[本地 NAT 规则引用] '+' '.join(evidence))
        count += 1
    return count


def nat_nft(output, tcp, udp):
    data = json.loads(output)
    records = data.get('nftables')
    if not isinstance(records, list):
        raise ValueError('nft JSON 无效。')
    count = 0
    for item in records:
        rule = item.get('rule', {})
        expressions = rule.get('expr', [])
        actions = [name for expr in expressions for name in ('dnat', 'snat', 'masquerade', 'redirect') if name in expr]
        if not actions:
            continue
        protocol, port = None, None
        unsupported = False
        for expr in expressions:
            if 'match' not in expr:
                continue
            match = expr['match']
            payload = match.get('left', {}).get('payload', {}) if isinstance(match.get('left'), dict) else {}
            # Only a single positive scalar dport match is represented below.
            # Never erase !=, set/range, address or other unsupported constraints.
            if (match.get('op') != '==' or payload.get('field') != 'dport'
                    or payload.get('protocol') not in ('tcp', 'udp')
                    or type(match.get('right')) is not int or port is not None):
                unsupported = True
                break
            protocol = payload['protocol']
            port = match['right']
        if unsupported:
            print('[尚未验证] 跳过含未支持匹配条件的 nft NAT 规则，未将其解释为无条件转换。')
            continue
        selected = tcp if protocol == 'tcp' else udp if protocol == 'udp' else set()
        if port is not None and (type(port) is not int or not 1 <= port <= 65535 or (selected and port not in selected)):
            continue
        evidence = [name.upper() for name in actions]
        if protocol:
            evidence.append(protocol)
        if port is not None:
            evidence.append('dport='+str(port))
        for expr in expressions:
            for name in ('dnat', 'snat'):
                block = expr.get(name)
                if isinstance(block, dict):
                    address = nat_value(block.get('addr'))
                    if address:
                        evidence.append('addr='+address)
        print('[本地 nft NAT 规则引用] '+' '.join(evidence))
        count += 1
    return count


def inspect_nat(tcp, udp):
    count = 0
    for binary, family in (('iptables', 'IPv4'), ('ip6tables', 'IPv6')):
        output = read_command([binary, '-t', 'nat', '-S'])
        if output is not None:
            count += nat_iptables(output, family, tcp, udp)
    output = read_command(['nft', '-j', 'list', 'ruleset'])
    if output is not None:
        count += nat_nft(output, tcp, udp)
    if not count:
        print('[尚未验证] 未发现可识别的所选 NAT 规则引用；不能证明不存在转换。')


def main(args):
    try:
        role, path, tcp, udp = context(args)
    except Cancelled:
        print('已取消，未检查或修改系统。')
        return 0
    print(f'操作者声明（未由工具推断）：role={role} path={path}')
    print('TCP 入口端口：'+(','.join(map(str, sorted(tcp))) or '不限定'))
    print('UDP 入口端口：'+(','.join(map(str, sorted(udp))) or '不限定'))
    print('用户态监听通常经过 INPUT；内核 NAT 转发通常经过 FORWARD。Docker bridge 实际钩子/链顺序尚未验证。')
    sockets(tcp, udp)
    if path in ('nat', 'bridge', 'unknown'):
        inspect_nat(tcp, udp)
    print('socket peer 是本机实际网络对端；上游共享/多跳节点可能只显示上游 IP，不能当作最终用户 IP。')
    print('用户态转发通常向下游创建新连接，下游可能只看到本节点 IP；SNAT/MASQUERADE 也会改写来源。必须在每一跳核验真实来源。')
    print('PROXY protocol 中的用户 IP 不改变防火墙看到的真实对端；不自动信任上游或添加白名单。')
    print('[尚未验证] 端到端来源、正常/封禁/恢复及所有流量路径保护均需隔离实测；规则引用不证明实际阻断。')
    return 2


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, TypeError, KeyError, AttributeError):
        print('[ERROR] 中转路径输入无效或本地只读检查失败，请核对选择、工具与权限。', file=sys.stderr)
        sys.exit(1)

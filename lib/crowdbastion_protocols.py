#!/usr/bin/env python3
"""Bounded declaration-only transport guidance; source index: docs/protocol-capabilities.md.

No config discovery, network requests, logs, sysctls, or runtime version guesses.
"""
import argparse
import json
import sys

sys.dont_write_bytecode = True

PROTOCOLS = frozenset({'vmess', 'vless', 'shadowsocks', 'shadowsocks2022',
                       'trojan', 'hysteria1', 'hysteria2', 'tuic', 'anytls'})
TCP_TRANSPORTS = frozenset({'tcp', 'raw', 'ws', 'websocket', 'grpc', 'httpupgrade'})
# TLS is transport security; only a protocol's standard envelope can resolve it.
TRANSPORTS = TCP_TRANSPORTS | {'tls', 'udp', 'tcp+udp', 'quic', 'udp-over-tcp',
                              'wechat-video', 'faketcp', 'xhttp'}


def known(value, allowed):
    return value if isinstance(value, str) and value in allowed else 'unknown'


def profile(program='unknown', protocol='unknown', transport=None, *, version=None, topology='unknown'):
    """Only allowlisted declarations leave this function; version never verifies provenance."""
    program = known(program, {'v2bx', 'v2node'})
    protocol = 'hysteria1' if protocol == 'hysteria' else known(protocol, PROTOCOLS)
    selected = transport is not None and transport != ''
    transport = known(transport, TRANSPORTS)
    topology = known(topology, {'direct', 'shared-relay'})
    network, payload, sources = 'unknown', 'version_and_config_required', []
    if protocol in {'vmess', 'vless', 'trojan'}:
        sources = ['xray-transport', protocol]
        if transport in TCP_TRANSPORTS or (protocol == 'trojan' and (not selected or transport == 'tls')):
            network = 'tcp'
        if protocol == 'trojan':
            payload = 'over_tcp' if network == 'tcp' else 'version_and_config_required'
    elif protocol in {'shadowsocks', 'shadowsocks2022'}:
        sources = ['shadowsocks', 'singbox-shadowsocks']
        if transport in {'tcp', 'udp', 'tcp+udp'}:
            network = transport
        payload = 'native_if_udp_enabled'
    elif protocol == 'hysteria1':
        sources = ['hysteria1', 'singbox-hysteria']
        if transport in {'udp', 'wechat-video', 'quic'}:
            network = 'udp+quic'
        elif transport == 'faketcp':
            network = 'faketcp'
        payload = 'over_protocol'
    elif protocol == 'hysteria2':
        sources = ['hysteria2']
        if not selected or transport in {'quic', 'udp'}:
            network = 'udp+quic'
        elif transport == 'faketcp':
            network = 'faketcp'
        payload = 'over_protocol'
    elif protocol == 'tuic':
        sources = ['tuic-spec', 'singbox-tuic']
        if transport == 'quic':
            network = 'udp+quic'
        payload = 'over_protocol'
    elif protocol == 'anytls':
        sources = ['anytls']
        if not selected or transport in {'tcp', 'tls', 'udp-over-tcp'}:
            network = 'tcp'
        payload = 'over_tcp'
    tcp = network in {'tcp', 'tcp+udp'}
    userspace = network in {'udp+quic', 'faketcp'}
    guidance = [
        '声明画像不等于运行验证；需要确认实际 backend/core 版本、配置和传输。',
        '--network-status / --network-plan 仅审计所选宿主机 TCP 基线；不证明 QUIC 吞吐。',
        '内核 TCP BBR 不设置用户态 QUIC 拥塞控制；宿主机到目标站的 TCP 出口仍可受影响。',
        '独立网站按网站部署检查；缺少 HTTP/AppSec 不代表代理协议故障。',
        '日志认证失败、协议拒绝、完整性失败与普通 TLS/超时/reset 必须分别核验；协议名不验证日志解析。',
    ]
    if network == 'unknown':
        guidance.append('传输未知或组合不明确：提供脱敏的面板/运行传输证据，保持只读审计。')
    if network in {'udp', 'udp+quic', 'tcp+udp'}:
        guidance.append('先观察 UDP socket 错误、丢包和收发缓冲上限，再测量；不统一设置 UDP 内存。')
    if userspace:
        guidance.append('用户态拥塞控制取决于实现/版本/发送方向；Hysteria2 当前文档含 BBR/Reno/Brutal，TUIC 实现另有选择。')
    if network == 'faketcp':
        guidance.append('Hysteria1 faketcp 绕过系统 TCP 栈；Hysteria2 mimic 使用额外内核模块伪装 TCP。TCP 外观不证明 TCP BBR 生效，需专项审计。')
    if protocol == 'anytls':
        guidance.append('AnyTLS 的 UDP 载荷使用 UDP-over-TCP v2，外层 TLS/TCP；不能据此宣称原生 QUIC。')
    if protocol in {'shadowsocks', 'shadowsocks2022'}:
        guidance.append('Shadowsocks TCP/UDP 可独立启用；版本/密码算法和插件需要额外证据，不改密码或 cipher。')
    if program == 'v2node':
        guidance.append('V2Node 候选仓库 wyx2685/v2node；请确认实际仓库、提交/版本和脱敏 schema；当前不解析未知配置。')
    if topology == 'shared-relay':
        guidance.append('共享中转 socket 不能识别真实用户；保留观察器 relay CIDR 排除，不自动封禁中转地址。')
    return {'program': program, 'backend_status': 'candidate_repository_host_provenance_unknown' if program == 'v2node'
            else 'declared_v2bx_version_unverified' if program == 'v2bx' else 'unsupported_backend',
            'version_status': 'unverified', 'protocol': protocol, 'transport': transport,
            'network': network, 'udp_payload': payload, 'evidence': 'operator_declaration',
            'runtime_status': 'unverified', 'topology': topology, 'client_identity': 'unverified',
            'host_tcp_relevant': tcp,
            'congestion_control': 'userspace_version_and_direction_required' if userspace else 'host_tcp' if tcp else 'unknown',
            'automatic_tuning': False, 'automatic_ban': False,
            'log_detection': 'backend_version_and_sample_required', 'sources': sources, 'guidance': guidance}


def display(report):
    print('协议能力只读画像（声明；运行状态尚未验证）')
    print(f"程序={report['program']}；程序证据={report['backend_status']}；协议={report['protocol']}；传输={report['transport']}；网络={report['network']}")
    for line in report['guidance']:
        print(line)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def main(argv):
    parser = Parser(description='只读声明画像；程序名不是协议名。未知情况返回 2。')
    for name in ('program', 'protocol', 'transport', 'version', 'topology'):
        parser.add_argument('--'+name)
    parser.add_argument('--json', action='store_true')
    try:
        args = parser.parse_args(argv)
        report = profile(args.program, args.protocol, args.transport, version=args.version, topology=args.topology)
    except ValueError:
        print('invalid_arguments', file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        display(report)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

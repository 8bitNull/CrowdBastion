#!/usr/bin/env python3
"""Offline, source-backed V2bX log projection. Every event is observation-only."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True

from crowdsec_v2bx import InputError, Parser, read_regular

FAILURES = {'auth_failure', 'protocol_rejection'}
UUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
ADDRESS = r'(?:\[[0-9a-fA-F:.]+\]|[0-9.]+):[0-9]{1,5}'
SGR = re.compile(r'\x1b\[[0-9;]*m')


def offset_zone(value):
    if not isinstance(value, str) or not re.fullmatch(r'[+-][0-9]{2}:[0-9]{2}', value):
        raise ValueError('invalid_timezone')
    hours, minutes = int(value[1:3]), int(value[4:6])
    if hours > 14 or minutes > 59 or (hours == 14 and minutes):
        raise ValueError('invalid_timezone')
    return timezone(timedelta(minutes=(hours*60+minutes)*(1 if value[0] == '+' else -1)))


def timestamp(value):
    if value.tzinfo is None or not 2000 <= value.year <= 2200:
        raise ValueError('time_unverified')
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def source_address(value):
    if not isinstance(value, str) or not re.fullmatch(ADDRESS, value):
        return None
    address, _, port = value.rpartition(':')
    if not 1 <= int(port) <= 65535:
        return None
    try:
        source = ipaddress.ip_address(address.strip('[]'))
        if source.is_unspecified or source.is_multicast:
            return None
        if isinstance(source, ipaddress.IPv6Address) and source.ipv4_mapped:
            source = source.ipv4_mapped
        return str(source)
    except ValueError:
        return None


def event(core, protocol, kind, source, when, basis):
    if source is None or when is None:
        return None
    return {'schema_version': 1, 'timestamp': when, 'time_basis': basis,
            'core': core, 'protocol': protocol, 'event_type': kind,
            'source_ip': source, 'source_status': 'unverified',
            'observation_only': True}


def xray(line, offset, received):
    matched = re.fullmatch(r'(?:(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?) )?from ('+ADDRESS+r') (accepted|rejected) (.*)', line)
    if not matched:
        return None, 'unsupported_format'
    clock, source, action, reason = matched.groups()
    when, basis = received, 'journal_receipt'
    if clock and offset:
        zone = offset_zone(offset)
        when = timestamp(datetime.strptime(clock, '%Y/%m/%d %H:%M:%S.%f' if '.' in clock else '%Y/%m/%d %H:%M:%S').replace(tzinfo=zone))
        basis = 'explicit_offset'
    if when is None:
        return None, 'time_unverified'
    source = source_address(source)
    if source is None:
        return None, 'source_unverified'
    if action == 'accepted':
        return event('xray', 'unknown', 'connection_open', source, when, basis), 'parsed'
    reason = reason.lstrip()
    # v0.4.0 may prepend this precise drain/read-timeout chain to VMess
    # authentication rejection. A timeout alone remains unsupported.
    wrapped = re.fullmatch(r'common/drain: common/drain: unable to drain connection > read tcp ('+ADDRESS+r')->('+ADDRESS+r'): i/o timeout > (proxy/vmess/encoding: invalid user(?: > .*)?)', reason)
    if wrapped and all(source_address(endpoint) for endpoint in wrapped.groups()[:2]):
        reason = wrapped[3]
    patterns = [
        (r'proxy/vless/encoding: invalid request user id', 'vless', 'auth_failure'),
        (r'proxy/vmess/encoding: invalid user(?: > .*)?', 'vmess', 'auth_failure'),
        (r'proxy/trojan: not a valid user', 'trojan', 'fallback_candidate'),
        (r'proxy/trojan: not trojan protocol', 'trojan', 'fallback_candidate'),
    ]
    for pattern, protocol, kind in patterns:
        if re.fullmatch(pattern, reason):
            return event('xray', protocol, kind, source, when, basis), 'parsed'
    return None, 'unsupported_reason'


def sing(line, received):
    when, basis = received, 'journal_receipt'
    clock = re.match(r'^([+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ', line)
    if clock:
        when = timestamp(datetime.strptime(clock[1], '%z %Y-%m-%d %H:%M:%S'))
        basis = 'log_offset'
        line = line[clock.end():]
    quic_record = re.fullmatch(r'ERROR(?:\[\d+\])? (?:\[\d+ [0-9.ms]+\] )?v2bx-auth/(tuic|hysteria|hysteria2): v2bx-observation (\{.*\})', line)
    if quic_record:
        protocol, payload = quic_record.groups()
        data = json.loads(payload)
        if (not isinstance(data, dict) or type(data.get('schema_version')) is not int
                or data['schema_version'] != 1 or data.get('core') != 'sing'
                or data.get('protocol') != protocol or data.get('event_type') != 'auth_rejected'):
            return None, 'unsupported_reason'
        if when is None:
            return None, 'time_unverified'
        source = source_address(data.get('addr'))
        if source is None:
            return None, 'source_unverified'
        return event('sing', protocol, 'auth_failure', source, when, basis), 'parsed'
    matched = re.fullmatch(r'(ERROR|WARN|INFO|DEBUG)(?:\[\d+\])? (?:\[\d+ [0-9.ms]+\] )?inbound/(vless|vmess|trojan|anytls|shadowsocks)\[([^\r\n]{1,256})\]: process connection from ('+ADDRESS+r'): (.*)', line)
    if not matched:
        return None, 'unsupported_format'
    if when is None:
        return None, 'time_unverified'
    level, protocol, tag, source, reason = matched.groups()
    # V2bX labels embed a bracketed API address. Validate balanced nested
    # brackets so an embedded closing label cannot fabricate a source field.
    if not balanced_tag(tag):
        return None, 'unsupported_format'
    source = source_address(source)
    if source is None:
        return None, 'source_unverified'
    kind = None
    if level == 'ERROR' and protocol == 'vless' and re.fullmatch(r'unknown UUID: '+UUID, reason):
        kind = 'auth_failure'
    elif level == 'ERROR' and protocol == 'vmess' and reason == 'bad request':
        kind = 'protocol_rejection'
    elif level == 'ERROR' and protocol == 'trojan' and reason == 'bad request: fallback disabled':
        kind = 'protocol_rejection'
    elif level == 'ERROR' and protocol == 'anytls' and reason == 'unknown user password: fallback disabled':
        kind = 'auth_failure'
    elif level == 'ERROR' and protocol == 'shadowsocks':
        integrity = re.fullmatch(r'shadowsocks: serve TCP from ('+ADDRESS+r'): chacha20poly1305: message authentication failed', reason)
        if integrity and integrity[1] == matched[4]:
            kind = 'integrity_failure'
    elif reason.startswith('TLS handshake:') or reason in ('i/o timeout', 'EOF', 'connection reset by peer'):
        kind = 'network_error'
    if kind is None:
        return None, 'unsupported_reason'
    return event('sing', protocol, kind, source, when, basis), 'parsed'


def balanced_tag(tag):
    depth = 0
    for char in tag:
        if char == '[':
            depth += 1
        elif char == ']':
            depth -= 1
        if not 0 <= depth <= 8:
            return False
    return depth == 0


def hysteria(line, received):
    data = None
    when, basis = received, 'journal_receipt'
    if line.startswith('{'):
        data = json.loads(line)
        if not isinstance(data, dict):
            return None, 'unsupported_format'
        value = data.get('time')
        if type(value) in (int, float):
            when = timestamp(datetime.fromtimestamp(value/1000, timezone.utc))
            basis = 'log_epoch'
    else:
        matched = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2}))\t(INFO|DEBUG|ERROR|WARN)\t(client connected|client disconnected|v2bx authentication rejected)\t(\{.*\})', line)
        if not matched:
            return None, 'unsupported_format'
        when = timestamp(datetime.fromisoformat(matched[1].replace('Z', '+00:00')))
        basis = 'log_offset'
        data = json.loads(matched[4])
        if not isinstance(data, dict):
            return None, 'unsupported_format'
        data['msg'] = matched[3]
        data['level'] = matched[2].lower()
    msg = data.get('msg')
    if msg == 'v2bx authentication rejected':
        # Experimental v0.4.0 fork contract: accept only explicit rejection.
        # Masquerade/404, bandwidth policy and drop summaries are not failures.
        if (type(data.get('schema_version')) is not int or data['schema_version'] != 1
                or data.get('core') != 'hysteria2' or data.get('protocol') != 'hysteria2'
                or data.get('event_type') != 'auth_rejected' or data.get('level') != 'error'):
            return None, 'unsupported_reason'
        if when is None:
            return None, 'time_unverified'
        source = source_address(data.get('addr'))
        if source is None:
            return None, 'source_unverified'
        return event('hysteria2', 'hysteria2', 'auth_failure', source, when, basis), 'parsed'
    if msg not in ('client connected', 'client disconnected'):
        return None, 'unsupported_reason'
    if when is None:
        return None, 'time_unverified'
    source = source_address(data.get('addr'))
    if source is None:
        return None, 'source_unverified'
    kind = 'connection_open' if msg == 'client connected' else 'connection_close'
    return event('hysteria2', 'hysteria2', kind, source, when, basis), 'parsed'


def parse_line(line, core, timezone_offset=None, journal_unit='V2bX.service'):
    """Never return raw input or exception messages, even for malformed records."""
    if not isinstance(line, str) or len(line) > 8192:
        return None, 'oversized_line'
    line = SGR.sub('', line.rstrip('\r\n'))
    if any((ord(char) < 32 and char != '\t') or 127 <= ord(char) <= 159 or char in '\u2028\u2029' for char in line):
        return None, 'invalid_control'
    received = None
    try:
        if line.startswith('{'):
            data = json.loads(line)
            if isinstance(data, dict) and 'MESSAGE' in data:
                if data.get('_SYSTEMD_UNIT') != journal_unit:
                    return None, 'journal_unit_mismatch'
                message = data['MESSAGE']
                raw_time = data.get('__REALTIME_TIMESTAMP')
                if not isinstance(message, str) or not isinstance(raw_time, str) or not re.fullmatch(r'\d{1,17}', raw_time):
                    return None, 'invalid_journal'
                received = timestamp(datetime.fromtimestamp(int(raw_time)/1000000, timezone.utc))
                line = SGR.sub('', message)
                if any((ord(char) < 32 and char != '\t') or 127 <= ord(char) <= 159 or char in '\u2028\u2029' for char in line):
                    return None, 'invalid_control'
        if core == 'xray':
            return xray(line, timezone_offset, received)
        if core == 'sing':
            return sing(line, received)
        if core == 'hysteria2':
            return hysteria(line, received)
    except (ValueError, TypeError, OverflowError, RecursionError):
        return None, 'invalid_record'
    return None, 'unsupported_core'


def relay_networks(value):
    if not value:
        return []
    try:
        return [ipaddress.ip_network(part.strip(), strict=True) for part in value.split(',')]
    except ValueError:
        raise InputError('invalid_relay_cidrs') from None


def eligible(item):
    return item['event_type'] in FAILURES and item['source_status'] == 'unverified'


def inspect_file(path, core, timezone_offset=None, relay_cidrs='', journal_unit='V2bX.service'):
    if core not in ('xray', 'sing', 'hysteria2'):
        raise InputError('invalid_core')
    if timezone_offset:
        try:
            offset_zone(timezone_offset)
        except ValueError:
            raise InputError('invalid_timezone') from None
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service', journal_unit):
        raise InputError('invalid_unit')
    networks = relay_networks(relay_cidrs)
    text, state = read_regular(path, 1024*1024)
    if text is None:
        raise InputError(state)
    lines = text.split('\n')
    if lines[-1] == '':
        lines.pop()
    if len(lines) > 2000:
        raise InputError('too_many_lines')
    events, ignored, categories = [], {}, {}
    for line in lines:
        item, status = parse_line(line, core, timezone_offset, journal_unit)
        if item is None:
            ignored[status] = ignored.get(status, 0)+1
            continue
        if any(ipaddress.ip_address(item['source_ip']) in network for network in networks):
            item['source_status'] = 'relay_address'
        categories[item['event_type']] = categories.get(item['event_type'], 0)+1
        events.append(item)
    return {'sample_status': 'readable', 'core': core, 'lines': len(lines),
            'categories': categories, 'ignored': ignored, 'events': events,
            'failure_observations': sum(eligible(item) for item in events),
            'source_trust': 'unverified', 'production_validation': 'unverified',
            'observation_only': True}


def main(args):
    parser = Parser(description='只读检查 V2bX 日志样本，输出固定字段；不安装规则或创建封禁。')
    parser.add_argument('--file', required=True)
    parser.add_argument('--core', required=True)
    parser.add_argument('--timezone')
    parser.add_argument('--relay-cidrs', default='')
    parser.add_argument('--unit', default='V2bX.service')
    parser.add_argument('--events-only', action='store_true')
    try:
        options = parser.parse_args(args)
        report = inspect_file(options.file, options.core, options.timezone,
                              options.relay_cidrs, options.unit)
    except (InputError, OSError, ValueError, TypeError) as error:
        print(json.dumps({'sample_status': str(error) if isinstance(error, InputError) else 'read_failed',
                          'observation_only': True}))
        return 1
    if options.events_only:
        for item in report['events']:
            if eligible(item):
                print(json.dumps(item, ensure_ascii=False))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

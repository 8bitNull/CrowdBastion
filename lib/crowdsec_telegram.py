#!/usr/bin/env python3
"""Read-only Telegram diagnostics and official-plugin tests with API receipts."""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import yaml
from crowdsec_config import merged_config, notification_locations, read, read_mapping, telegram_routes, write
from crowdsec_notify import CONFIG_NAME, WEBHOOK_FORMAT, load_config
from crowdsec_notify_client import request as notify_request, worker_state

CHANNEL = 'crowdsec_1key_telegram'
EVIDENCE = 'crowdsec-1key-telegram-test.json'
CANDIDATE = re.compile(r'telegram|(?:^|[-_./])tg(?:[-_./]|$)|crowdsec.*bot|bot.*crowdsec', re.I)


def fingerprint(root):
    profiles, notification = notification_locations(root)
    digest = hashlib.sha256()
    for path in (Path(root)/'config.yaml', Path(root)/'config.yaml.local',
                 notification, profiles, Path(str(profiles)+'.local'), Path(root)/CONFIG_NAME):
        digest.update(str(path).encode()+b'\0')
        digest.update(path.read_bytes() if path.exists() else b'<absent>')
        digest.update(b'\0')
    return digest.hexdigest()


def smart_config(root, notification):
    path = Path(root)/CONFIG_NAME
    if not path.exists():
        return None
    config = load_config(path)
    if not config['enabled']:
        return None
    if (notification.get('url') != f'http://127.0.0.1:{config["port"]}/alerts'
            or (notification.get('headers') or {}).get('Authorization') != 'Bearer '+config['secret']
            or notification.get('format') != WEBHOOK_FORMAT):
        raise ValueError('分级通知配置与插件路由不一致')
    return config


def save_result(root, accepted, now=None, signature=None):
    target = Path(root)/EVIDENCE
    if target.is_symlink():
        raise ValueError('测试证据必须为普通文件')
    fd, temporary = tempfile.mkstemp(prefix='.telegram-test-', dir=root)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump({'accepted': accepted, 'checked_at': time.time() if now is None else now,
                       'fingerprint': fingerprint(root) if signature is None else signature}, stream)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command_output(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=8)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def external_candidates(units, cron_dir, crontab):
    services = sorted({line.split()[0] for line in (units or '').splitlines()
                       if line.split() and line.split()[0].endswith('.service')
                       and CANDIDATE.search(line.split()[0])})
    cron = []
    complete = units is not None
    directory = Path(cron_dir)
    if directory.exists():
        try:
            for path in sorted(directory.iterdir()):
                if path.is_file():
                    try:
                        # Report only the filename, never commands or credentials.
                        lines = [line for line in path.read_text().splitlines()
                                 if line.strip() and not line.lstrip().startswith('#')]
                        if CANDIDATE.search(path.name) or any(CANDIDATE.search(line) for line in lines):
                            cron.append(str(path))
                    except (OSError, UnicodeError):
                        complete = False
        except OSError:
            complete = False
    if crontab and any(CANDIDATE.search(line) for line in crontab.splitlines()
                       if line.strip() and not line.lstrip().startswith('#')):
        cron.append('root crontab')
    return {'services': services, 'cron': cron, 'complete': complete,
            'scope': '按服务名称及 cron 内容寻找候选，不能排除其他名称的独立推送进程；不会停止或删除。'}


def inspect_settings(root, units='', cron_dir='/etc/cron.d', crontab='', now=None):
    profiles_path, notification = notification_locations(root)
    report = {
        'configuration': {'state': 'unconfigured', 'path': str(notification)},
        'routing': {'state': 'unconfigured', 'profiles': []},
        'delivery': {'state': 'unknown', 'detail': '尚无当前配置的有效 API 测试回执'},
        'traffic': {'state': 'unknown', 'detail': '真实攻击取证尚未验证；插件测试不含真实攻击事件'},
        'duplicates': {'same_destination': [], 'repeated_profiles': [], 'continuing_profiles': [],
                       'co_routed_profiles': []},
        'external': external_candidates(units, cron_dir, crontab),
        'exit_code': 2,
    }
    if not notification.exists():
        return report
    config = read_mapping(notification)
    smart = smart_config(root, config)
    if config.get('type') != 'http' or config.get('name') != CHANNEL or not isinstance(config.get('format'), str):
        report['configuration']['state'] = 'abnormal'
        report['exit_code'] = 1
        return report
    report['configuration']['state'] = 'normal'
    threshold, wait = config.get('group_threshold', 1), config.get('group_wait', '1s')
    report['configuration']['mode'] = 'batch' if isinstance(threshold, int) and threshold > 1 else 'immediate'
    report['configuration']['group_threshold'] = threshold
    report['configuration']['group_wait'] = wait
    url = urlsplit(str(config.get('url', '')))
    token = re.search(r'/bot(\d+:[A-Za-z0-9_-]+)/sendMessage/?$', url.path)
    ids = re.findall(r'"chat_id"\s+"(-?\d+)"', config['format'])
    same = telegram_routes(root, token.group(1), ids[0]) if token and len(set(ids)) == 1 else []
    if smart:
        report['configuration']['mode'] = 'smart'
        same = telegram_routes(root, smart['bot_token'], str(smart['chat_id']))
        try:
            report['worker'] = notify_request(smart, 'status')
            state = worker_state(report['worker'], smart['policy']['health_interval_seconds'])
            report['worker']['state'] = state
            if state in ('sender_stale', 'health_stale', 'delivery_failed'):
                report['configuration']['state'] = 'abnormal'
                report['exit_code'] = 1
            elif state == 'health_pending':
                report['configuration']['state'] = 'unknown'
        except (OSError, ValueError, KeyError, TypeError):
            report['worker'] = {'state': 'unavailable'}
            report['configuration']['state'] = 'abnormal'
            report['exit_code'] = 1
    documents = []
    for path in (Path(str(profiles_path)+'.local'), profiles_path):
        if path.exists():
            for index, doc in enumerate(read(path, True), 1):
                if isinstance(doc, dict):
                    documents.append((path, index, doc))
    active = set()
    selected = report['routing']['profiles']
    for path, index, doc in documents:
        routes = doc.get('notifications') or []
        if not isinstance(routes, list) or not all(isinstance(x, str) for x in routes):
            raise ValueError('通知路由格式无效')
        active.update(routes)
        if CHANNEL not in routes:
            continue
        name = str(doc.get('name') or f'profile-{index}')
        selected.append({'name': name, 'path': str(path), 'document': index,
                         'on_success': doc.get('on_success', 'continue')})
        if routes.count(CHANNEL) > 1:
            report['duplicates']['repeated_profiles'].append(name)
        if set(routes).intersection(same):
            report['duplicates']['co_routed_profiles'].append(name)
    report['duplicates']['same_destination'] = sorted(active.intersection(same))
    # Multiple routes are normal with mutually exclusive filters. Continuing
    # profiles are candidates only: we do not evaluate arbitrary expressions.
    report['duplicates']['continuing_profiles'] = [p['name'] for p in selected[:-1]
                                                   if p['on_success'] != 'break']
    report['routing']['state'] = 'normal' if selected else 'abnormal'
    if not selected or report['duplicates']['repeated_profiles'] or report['duplicates']['co_routed_profiles']:
        report['exit_code'] = 1
    try:
        evidence = json.loads((Path(root)/EVIDENCE).read_text())
        current_time = time.time() if now is None else now
        if (evidence.get('fingerprint') == fingerprint(root)
                and 0 <= current_time-evidence['checked_at'] <= 86400):
            if evidence.get('accepted') is True:
                report['delivery'] = {'state': 'normal', 'detail': '24 小时内 Telegram API 已接受当前配置的测试消息'}
            elif evidence.get('accepted') is False:
                report['delivery'] = {'state': 'abnormal', 'detail': '当前配置最近一次 API 测试失败'}
                report['exit_code'] = 1
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return report


def print_report(report):
    labels = {'normal': '正常', 'abnormal': '异常', 'unknown': '尚未验证', 'unconfigured': '未配置'}
    config = report['configuration']
    print(f"[{labels[config['state']]}] 通知配置: {config['path']}")
    if config.get('mode'):
        mode = {'batch': '批量', 'smart': '分级降噪', 'immediate': '即时'}[config['mode']]
        print(f"通知模式: {mode}；group_wait={config['group_wait']}，group_threshold={config['group_threshold']}")
    if 'worker' in report:
        worker = report['worker']
        print(f'分级通知服务：待发 {worker.get("pending", "未知")} 条；未恢复紧急事件 {worker.get("open_critical", "未知")} 个')
        if worker.get('state') in ('health_stale', 'health_pending'):
            print('健康检查心跳已过期。' if worker['state'] == 'health_stale' else '健康检查尚未完成。')
        elif worker.get('state') == 'delivery_failed':
            print('仍有通知发送失败，队列将继续重试。')
    print(f"[{labels[report['routing']['state']]}] 通知路由（local 优先，仅匹配 profile 的告警会发送）")
    for profile in report['routing']['profiles']:
        print(f"  {profile['name']} / {profile['path']} / on_success={profile['on_success']}")
    print(f"[{labels[report['delivery']['state']]}] 测试投递: {report['delivery']['detail']}")
    print(f"[尚未验证] 真实攻击取证: {report['traffic']['detail']}")
    duplicates = report['duplicates']
    for field, title in [('same_destination', '同目标旧通道仍有路由'),
                         ('repeated_profiles', '本工具路由重复的 profile'),
                         ('co_routed_profiles', '同时路由本工具和旧通道的 profile'),
                         ('continuing_profiles', '继续匹配后续 profile，可能重复发送')]:
        if duplicates[field]:
            print(f"[待核对] {title}: {', '.join(duplicates[field])}")
    if not any(duplicates.values()):
        print('当前配置未发现上述重复来源；HTTP 重试仍可能重复投递，不能保证严格只发送一次。')
    external = report['external']
    for name in external['services']:
        print(f'[候选] 独立推送服务: {name}')
    for name in external['cron']:
        print(f'[候选] 独立推送 cron: {name}')
    if not external['complete']:
        print('[尚未验证] 独立服务/cron 信息读取不完整。')
    print(external['scope'])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def test_notification(root, cscli='cscli'):
    _, notification = notification_locations(root)
    if not notification.exists():
        print('请先配置 Telegram。', file=sys.stderr)
        return 1
    config = read_mapping(notification)
    smart = smart_config(root, config)
    url = urlsplit(str(config.get('url', '')))
    # Production endpoints use HTTPS; loopback HTTP is for isolated receivers.
    local_http = False
    try:
        local_http = url.scheme == 'http' and ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        pass
    if url.scheme != 'https' and not local_http:
        raise ValueError('API 端点必须使用 HTTPS')
    signature = fingerprint(root)
    nonce = '/'+secrets.token_urlsafe(24)
    receipt = {'accepted': None, 'reason': '未收到官方插件生成的通知'}
    receipt_event = threading.Event()
    opener = urllib.request.build_opener(NoRedirect())

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != nonce:
                self.send_error(404)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    raise ValueError('通知消息大小无效')
                body = self.rfile.read(length)
                payload = json.loads(body)
                if smart:
                    queued = notify_request(smart, 'test', payload)
                    deadline = time.monotonic()+20
                    accepted = False
                    while time.monotonic() < deadline:
                        accepted = notify_request(smart, 'receipt', {'id': queued['test_id']}).get('accepted') is True
                        if accepted:
                            break
                        time.sleep(0.5)
                    receipt['accepted'] = accepted
                    receipt['reason'] = '官方插件、持久化队列和 Telegram API 回执检查通过' if accepted else '测试已入队，尚未取得 API 成功回执'
                elif not isinstance(payload, dict) or not payload.get('chat_id') or not payload.get('text'):
                    raise ValueError('通知消息格式无效')
                else:
                    self.forward_direct(body, opener)
            except (ValueError, TypeError, KeyError, OSError, urllib.error.URLError):
                receipt['accepted'] = False
                receipt['reason'] = '官方插件通知或分级服务回执无效'
            receipt_event.set()
            self.send_response(200)
            self.end_headers()
            try:
                self.wfile.write(b'{"ok":true}')
            except OSError:
                pass

        def forward_direct(self, body, opener):
            request = urllib.request.Request(config['url'], data=body,
                       headers=config.get('headers') or {'Content-Type': 'application/json'}, method='POST')
            try:
                with opener.open(request, timeout=10) as response:
                    code = response.status
                    reply = json.loads(response.read(65536))
                receipt['accepted'] = 200 <= code < 300 and isinstance(reply, dict) and reply.get('ok') is True
                receipt['reason'] = 'API 已接受测试消息' if receipt['accepted'] else 'API 拒绝测试消息'
            except urllib.error.HTTPError as error:
                receipt['accepted'] = False
                receipt['reason'] = f'API 拒绝测试消息（HTTP {error.code}）'
            except (OSError, ValueError, urllib.error.URLError):
                receipt['accepted'] = False
                receipt['reason'] = 'API 回执读取失败（连接、超时或响应格式错误）'

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='crowdsec-telegram-test-') as temporary:
            stage = Path(temporary)
            staged = dict(config)
            staged.update(url=f'http://127.0.0.1:{server.server_port}{nonce}', log_level='info',
                          group_wait='1s', group_threshold=1, timeout='30s' if smart else '15s', max_retry=0)
            write(stage/'notifications/telegram.yaml', staged, private=True)
            effective = merged_config(str(Path(root)/'config.yaml'))
            effective.setdefault('config_paths', {})['notification_dir'] = str(stage/'notifications')
            write(stage/'config.yaml', effective, private=True)
            try:
                result = subprocess.run([cscli, 'notifications', 'test', CHANNEL, '-c', str(stage/'config.yaml')],
                                        capture_output=True, text=True, timeout=40)
                receipt_event.wait(1)
                if result.returncode:
                    receipt.update(accepted=False, reason='官方插件测试执行失败；请核对配置和插件版本')
            except (OSError, subprocess.TimeoutExpired):
                receipt.update(accepted=False, reason='官方插件测试无法执行或超时')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    save_result(root, receipt['accepted'], signature=signature)
    print(receipt['reason'])
    print('插件测试不验证实际攻击取证或 Bouncer 拦截；API 接受不代表使用者已读。')
    if receipt['accepted'] is not True:
        return 1 if receipt['accepted'] is False else 2
    if fingerprint(root) != signature:
        print('测试期间配置已变化，回执不作为当前配置的有效证据。')
        return 2
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'test'])
    parser.add_argument('root')
    parser.add_argument('--cscli', default='cscli')
    parser.add_argument('--units')
    parser.add_argument('--cron-dir', default='/etc/cron.d')
    parser.add_argument('--crontab')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'test':
            return test_notification(args.root, args.cscli)
        units = Path(args.units).read_text() if args.units else command_output(
            ['systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager'])
        crontab = Path(args.crontab).read_text() if args.crontab else command_output(['crontab', '-l'])
        report = inspect_settings(args.root, units, args.cron_dir, crontab)
        if args.json:
            print(json.dumps(report, ensure_ascii=False))
        else:
            print_report(report)
        return report['exit_code']
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        # YAML/HTTP exceptions may contain the endpoint and Bot Token.
        print('TG 操作失败：配置结构无效、文件不可读或测试证据无法保存。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

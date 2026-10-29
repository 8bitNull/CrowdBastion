#!/usr/bin/env python3
"""Prepare reversible notification configuration; shell owns systemd and rollback."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import tempfile
from urllib.parse import urlsplit

import yaml
from crowdsec_config import notification_locations, read, read_mapping, write
from crowdsec_notify import CONFIG_NAME, DEFAULT_POLICY, WEBHOOK_FORMAT, load_config, validate_config
from crowdsec_notify_client import request, worker_state


def save(path, config):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('配置不能为符号链接')
    fd, temporary = tempfile.mkstemp(prefix='.notify-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(config, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def enabled(root):
    path = Path(root)/CONFIG_NAME
    return path.exists() and load_config(path)['enabled']


def preflight(root, state_dir, code_dir, unit):
    _, notification = notification_locations(root)
    config_path = Path(root)/CONFIG_NAME
    files = [config_path, notification, Path(unit)]
    directories = [Path(state_dir), Path(code_dir)]
    for path in files+directories:
        if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('通知路径必须为无符号链接的绝对路径')
        if path.exists() and (not path.is_file() if path in files else not path.is_dir()):
            raise ValueError('通知路径类型无效')
    if config_path.exists():
        current = load_config(config_path)
        if current['state_dir'] != state_dir or current['crowdsec_config'] != str(Path(root)/'config.yaml'):
            raise ValueError('通知安装路径与保存配置不一致')


def plan(root, state_dir, bot_config):
    path = Path(root)/CONFIG_NAME
    profiles, notification = notification_locations(root)
    current = read_mapping(notification)
    config = load_config(path) if path.exists() else None
    if current.get('name') != 'crowdsec_1key_telegram' or current.get('type') != 'http':
        raise ValueError('请先设置官方 Telegram 通知')
    routed = False
    for profile in (Path(str(profiles)+'.local'), profiles):
        if not profile.exists():
            continue
        for doc in read(profile, True):
            if not isinstance(doc, dict):
                continue
            routes = doc.get('notifications') or []
            if not isinstance(routes, list) or any(not isinstance(route, str) for route in routes):
                raise ValueError('通知路由必须为名称列表')
            routed = routed or 'crowdsec_1key_telegram' in routes
    # Check configured routing on updates as well; arbitrary filters are not evaluated.
    if not routed:
        raise ValueError('请先启用官方通知路由')
    if not config or not config['enabled']:
        url = urlsplit(current.get('url', ''))
        match = re.fullmatch(r'(.*)/bot(\d+:[A-Za-z0-9_-]+)/sendMessage', url.path)
        template = current.get('format', '')
        if not isinstance(template, str):
            raise ValueError('通知模板无效')
        ids = re.findall(r'"chat_id"\s+"(-?\d+)"', template)
        if url.scheme != 'https' or not match or len(ids) != 1 or template.count('"chat_id"') != 1:
            raise ValueError('无法确定现有通知目标')
        config = {**(config or {}), 'version': 1, 'enabled': True, 'bot_token': match[2],
                  'chat_id': ids[0], 'api_endpoint': url._replace(path=match[1]).geturl(),
                  'secret': (config or {}).get('secret') or secrets.token_hex(32),
                  'port': (config or {}).get('port', 7423), 'node': clean_node(),
                  'state_dir': state_dir, 'crowdsec_config': str(Path(root)/'config.yaml'),
                  'bot_config': bot_config, 'policy': (config or {}).get('policy', DEFAULT_POLICY),
                  'direct_notification': current}
    config = validate_config(config)
    if len((json.dumps(config, ensure_ascii=False, indent=2)+'\n').encode()) > 65536:
        raise ValueError('通知配置过大')
    return config


def prepare(root, state_dir, bot_config):
    config = plan(root, state_dir, bot_config)
    path = Path(root)/CONFIG_NAME
    _, notification = notification_locations(root)
    save(path, config)
    webhook = {'type': 'http', 'name': 'crowdsec_1key_telegram', 'log_level': 'info',
               'format': WEBHOOK_FORMAT, 'url': f'http://127.0.0.1:{config["port"]}/alerts',
               'method': 'POST', 'headers': {'Content-Type': 'application/json', 'Authorization': 'Bearer '+config['secret']},
               'group_wait': '1s', 'group_threshold': 1, 'timeout': '10s', 'max_retry': 5}
    write(notification, webhook, private=True)


def clean_node():
    return socket.gethostname()[:120]


def restore(root):
    path = Path(root)/CONFIG_NAME
    config = load_config(path)
    _, notification = notification_locations(root)
    write(notification, config['direct_notification'], private=True)
    config['enabled'] = False
    save(path, config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'prepare', 'restore', 'enabled', 'preflight', 'status', 'ready', 'ack'))
    parser.add_argument('root')
    parser.add_argument('--state-dir')
    parser.add_argument('--bot-config')
    parser.add_argument('--code-dir')
    parser.add_argument('--unit')
    parser.add_argument('--id')
    args = parser.parse_args()
    try:
        if args.action == 'preflight':
            preflight(args.root, args.state_dir, args.code_dir, args.unit)
        elif args.action == 'plan':
            plan(args.root, args.state_dir, args.bot_config)
        elif args.action == 'prepare':
            prepare(args.root, args.state_dir, args.bot_config)
        elif args.action == 'restore':
            restore(args.root)
        elif args.action == 'enabled':
            return 0 if enabled(args.root) else 2
        else:
            config = load_config(Path(args.root)/CONFIG_NAME)
            if not config['enabled']:
                print('分级通知未启用。')
                return 2
            if args.action == 'ack':
                if not re.fullmatch(r'[a-f0-9]{24}', args.id or ''):
                    raise ValueError('事件编号无效')
                result = request(config, 'ack', {'id': args.id})
                print('已知晓；恢复和升级仍会通知。' if result['acknowledged'] else '事件不存在或已结束。')
                return 0 if result['acknowledged'] else 2
            result = request(config, 'status')
            state = worker_state(result, config['policy']['health_interval_seconds'])
            if args.action == 'ready':
                # Routing only requires a live queue; the first health probe may still be running.
                return 1 if state == 'sender_stale' else 0
            if args.action == 'status':
                print(f'待发通知：{result["pending"]} 条；未恢复紧急事件：{result["open_critical"]} 个')
                if result.get('retrying'):
                    print(f'发送失败、等待重试：{result["retrying"]} 条。')
                for key, title in (('heartbeat_age', '发送检查'), ('health_age', '组件健康检查')):
                    age = result[key]
                    print(f'{title}：'+('尚无记录' if age is None else f'{int(max(0, age))} 秒前'))
                for key, title in (('last_delivery', '最近 API 成功'), ('last_failure', '最近发送失败')):
                    stamp = datetime.fromtimestamp(result[key], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if result[key] else '暂无记录'
                    print(f'{title}：{stamp}')
                print({'ready': '通知服务与健康检查心跳正常。', 'health_pending': '健康检查尚未完成。',
                       'health_stale': '健康检查心跳已过期，请检查通知服务。',
                       'delivery_failed': '仍有通知发送失败，队列将继续重试；请检查 API 与网络。',
                       'sender_stale': '通知发送检查心跳已过期，请检查通知服务。'}[state])
            return 0 if state == 'ready' else 2 if state == 'health_pending' else 1
        return 0
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        print('分级通知操作失败：请检查现有 TG 配置、私有配置文件及本地服务。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

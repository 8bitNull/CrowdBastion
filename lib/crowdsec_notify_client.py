"""Authenticated loopback access shared by the manager and interactive bot."""
import json
import math
import os
import re
import stat
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def read_object(path):
    """Read a bounded regular configuration; optional files must not block sending."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
            raise ValueError('通知配置文件类型或大小无效')
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('通知配置过大')
    try:
        value = json.loads(raw)
    except RecursionError as error:
        raise ValueError('通知配置结构过深') from error
    if not isinstance(value, dict):
        raise ValueError('通知配置必须为对象')
    return value


def worker_state(report, health_interval=20):
    def fresh(value, limit):
        return (type(value) in (int, float) and math.isfinite(value)
                and 0 <= value < limit)
    if not fresh(report.get('heartbeat_age'), 90):
        return 'sender_stale'
    if report.get('health_age') is None:
        return 'health_pending'
    if not fresh(report['health_age'], max(90, 3*health_interval)):
        return 'health_stale'
    retrying = report.get('retrying')
    if retrying is None:
        retrying = report.get('pending', 0) > 0 and report.get('last_failure', 0) > report.get('last_delivery', 0)
    if retrying:
        return 'delivery_failed'
    return 'ready'


def request(config, action, data=None):
    if action not in ('status', 'ack', 'detail', 'test', 'receipt'):
        raise ValueError('未知通知操作')
    if type(config.get('port')) is not int or not 1024 <= config['port'] <= 65535:
        raise ValueError('无效通知端口')
    if not re.fullmatch(r'[a-f0-9]{64}', config.get('secret', '')):
        raise ValueError('无效通知认证')
    body = json.dumps({} if data is None else data).encode()
    message = urllib.request.Request(f'http://127.0.0.1:{config["port"]}/{action}', data=body,
                                    headers={'Content-Type': 'application/json', 'Authorization': 'Bearer '+config['secret']})
    # Ignore HTTP proxy environment variables for the local secret-bearing request.
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(message, timeout=5) as response:
        result = json.loads(response.read(65536))
    if not isinstance(result, dict):
        raise ValueError('通知服务响应无效')
    return result


def bot_request(config_path, token, chat, action, identifier):
    config = read_object(config_path)
    if not config.get('enabled') or config.get('bot_token') != token or str(config.get('chat_id')) != str(chat):
        raise ValueError('通知目标与当前机器人不一致')
    if not re.fullmatch(r'[a-f0-9]{24}', identifier):
        raise ValueError('事件编号无效')
    return request(config, action, {'id': identifier})

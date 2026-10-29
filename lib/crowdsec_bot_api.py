"""Single-attempt Telegram transport and private, read-only runtime diagnostics.

Only fixed labels and numeric metadata enter diagnostics. Telegram descriptions,
request bodies, endpoint URLs, tokens and exception messages are never recorded.
"""
import hashlib
import json
import math
import os
import re
import socket
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Optional


_RESPONSE_LIMIT = 1024 * 1024
_STATE_LIMIT = 64 * 1024
_STALE_AFTER = 90
_LABELS = {
    'identity': '身份认证失败（401）',
    'permissions': '权限不足（403）',
    'conflict': '同一 Token 存在其他轮询实例（409）',
    'rate_limit': '请求过于频繁（429）',
    'service': 'Telegram 服务暂时不可用（5xx）',
    'network': '网络连接失败',
    'timeout': '网络请求超时',
    'invalid_response': 'Telegram 响应格式无效',
    'invalid_request': '请求参数无效（400）',
    'redirect': 'API 端点返回重定向，已拒绝跟随',
}
_TIMES = ('checked_at', 'last_poll_at', 'last_poll_attempt_at',
          'last_send_at', 'last_send_attempt_at', 'next_retry_at')
_MESSAGE_METHODS = frozenset(('sendMessage', 'editMessageText'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _number(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            if math.isfinite(value) and value >= 0:
                return value
        except (ValueError, OverflowError):
            pass
    return None


def _error(category, retry_after=None):
    result = {'category': category, 'label': _LABELS[category]}
    if retry_after is not None:
        result['retry_after'] = retry_after
    return result


def _retry_after(value):
    # Telegram specifies an integer number of seconds; booleans are not integers.
    return value if type(value) is int and value > 0 and _number(value) is not None else None


def _empty_state():
    result = {key: None for key in _TIMES}
    result.update(version=1, poll_error=None, send_error=None, api_error=None,
                  poll_failures=0, instance=None)
    return result


def _basename(token):
    return 'runtime-' + hashlib.sha256(token.encode('utf-8')).hexdigest()[:24] + '.json'


def _directory_fd(state_dir, create=False):
    """Walk with directory descriptors so no path component follows a symlink."""
    parts = os.path.abspath(os.fspath(state_dir)).split(os.sep)
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in filter(None, parts):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid():
            raise ValueError('运行状态目录不可用')
        if create:
            os.fchmod(descriptor, 0o700)
        elif stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError('运行状态目录不可用')
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _regular_file(metadata):
    return stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()


def _sanitize_state(raw):
    if not isinstance(raw, dict) or type(raw.get('version')) is not int or raw['version'] != 1:
        return None
    if _number(raw.get('checked_at')) is None:
        return None
    result = _empty_state()
    for key in _TIMES:
        value = raw.get(key)
        if value is not None and _number(value) is None:
            return None
        result[key] = value
    for key in ('poll_error', 'send_error', 'api_error'):
        value = raw.get(key)
        if value is None:
            continue
        if not isinstance(value, dict) or value.get('category') not in _LABELS:
            return None
        result[key] = _error(value['category'], _retry_after(value.get('retry_after')))
    failures = raw.get('poll_failures', 0)
    if type(failures) is not int or not 0 <= failures <= 30:
        return None
    result['poll_failures'] = failures
    instance = raw.get('instance')
    if instance is not None:
        if (not isinstance(instance, dict) or type(instance.get('pid')) is not int
                or instance['pid'] <= 0 or not isinstance(instance.get('session'), str)
                or not re.fullmatch(r'[a-f0-9]{32}', instance['session'])):
            return None
        result['instance'] = {'pid': instance['pid'], 'session': instance['session']}
    return result


def _read_state(state_dir, token):
    directory = None
    try:
        directory = _directory_fd(state_dir)
        descriptor = os.open(_basename(token), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if (not _regular_file(metadata) or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size > _STATE_LIMIT):
                return None
            body = stream.read(_STATE_LIMIT + 1)
        if len(body) > _STATE_LIMIT:
            return None
        return _sanitize_state(json.loads(body))
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        return None
    finally:
        if directory is not None:
            os.close(directory)


def _write_state(state_dir, token, state):
    directory = _directory_fd(state_dir, create=True)
    temporary = '.runtime-' + uuid.uuid4().hex
    created = False
    try:
        name = _basename(token)
        try:
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not _regular_file(metadata):
                raise ValueError('运行状态文件不可用')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        created = True
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(state, stream, ensure_ascii=False, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        created = False
    finally:
        if created:
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def read_runtime(state_dir, token, now=None):
    """Read a safe snapshot without creating files, changing modes or networking.

    last_poll_at and last_send_at are successful operations. Poll-attempt time is
    the liveness heartbeat, including failures. A heartbeat older than 90 seconds
    is stale; a state file with no poll history cannot establish a healthy poller.
    """
    report = _read_state(state_dir, token) or _empty_state()
    checked = time.time() if now is None else now
    checked = _number(checked)
    heartbeat = report['last_poll_attempt_at']
    if heartbeat is None:
        heartbeat = report['last_poll_at']
    report['age_seconds'] = None if heartbeat is None or checked is None else max(0, checked - heartbeat)
    report['retry_in_seconds'] = (max(0, report['next_retry_at'] - checked)
                                  if report['next_retry_at'] is not None and checked is not None else None)
    if heartbeat is None or checked is None or heartbeat > checked + 5:
        report['status'] = 'unknown'
    elif report['age_seconds'] > _STALE_AFTER:
        report['status'] = 'stale'
    elif any(report[key] is not None for key in ('poll_error', 'send_error', 'api_error')):
        report['status'] = 'error'
    else:
        report['status'] = 'healthy'
    return report


def _format_time(value):
    if _number(value) is None:
        return '尚无记录'
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, OverflowError, OSError):
        return '未知'


def describe_runtime(report):
    """Render plain Chinese diagnostics using trusted labels, never stored text."""
    states = {'healthy': '正常', 'error': '异常', 'stale': '陈旧（不能确认当前运行）', 'unknown': '未知'}
    status = states.get(report.get('status'), '未知')
    age = _number(report.get('age_seconds'))
    age_text = '未知' if age is None else str(int(age)) + ' 秒'
    lines = ['Telegram 运行状态：' + status, '轮询记录距今：' + age_text,
             '最近成功轮询：' + _format_time(report.get('last_poll_at')),
             '最近发送成功：' + _format_time(report.get('last_send_at'))]
    errors = []
    for key, label in (('poll_error', '轮询'), ('send_error', '发送'), ('api_error', '其他 API')):
        value = report.get(key)
        if isinstance(value, dict) and isinstance(value.get('category'), str):
            category = value['category']
            if category in _LABELS:
                errors.append(label + '：' + _LABELS[category])
    lines.append('当前错误：' + ('；'.join(errors) if errors else '无已记录错误'))
    retry = _number(report.get('next_retry_at'))
    remaining = _number(report.get('retry_in_seconds'))
    retry_text = _format_time(retry) if retry is not None else '无待重试轮询'
    if remaining is not None:
        retry_text += '（' + str(int(math.ceil(remaining))) + ' 秒后）'
    lines.append('下次轮询重试：' + retry_text)
    return '\n'.join(lines)


def _classify(code, body):
    category = {400: 'invalid_request', 401: 'identity', 403: 'permissions',
                409: 'conflict', 429: 'rate_limit'}.get(code)
    if category is None:
        category = ('service' if 500 <= code <= 599 else
                    'redirect' if 300 <= code <= 399 else 'invalid_response')
    parameters = body.get('parameters') if isinstance(body, dict) else None
    delay = _retry_after(parameters.get('retry_after')) if isinstance(parameters, dict) else None
    return _error(category, delay if category == 'rate_limit' else None)


def _decode(stream):
    data = stream.read(_RESPONSE_LIMIT + 1)
    if len(data) > _RESPONSE_LIMIT:
        raise ValueError('Telegram 响应格式无效')
    return json.loads(data)


class TelegramClient:
    def __init__(self, base_url: str, state_dir: str, token: str):
        try:
            parsed = urllib.parse.urlsplit(base_url)
            valid = (parsed.scheme == 'https' and parsed.hostname and parsed.port != 0
                     and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment)
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise ValueError('API 端点必须为 HTTPS，不能含账号或查询参数')
        if not state_dir or os.path.abspath(os.fspath(state_dir)) == os.sep:
            raise ValueError('运行状态目录不可用')
        self._base_url = base_url.rstrip('/')
        self._state_dir = state_dir
        self._token = token
        self._state = _read_state(state_dir, token) or _empty_state()
        self._instance = {'pid': os.getpid(), 'session': uuid.uuid4().hex}
        self._lock = threading.Lock()

    def _record(self, method, succeeded, error):
        now = time.time()
        with self._lock:
            state = self._state
            state['checked_at'] = now
            state['instance'] = self._instance
            if method == 'getUpdates':
                state['last_poll_attempt_at'] = now
                state['poll_error'] = error
                if succeeded:
                    state['last_poll_at'] = now
                    state['poll_failures'] = 0
                    state['next_retry_at'] = None
                else:
                    count = min(state['poll_failures'] + 1, 30)
                    state['poll_failures'] = count
                    delay = min(2 ** min(count, 6), 60)
                    if error['category'] in ('identity', 'permissions', 'conflict'):
                        delay = 60
                    elif error['category'] == 'rate_limit' and error.get('retry_after') is not None:
                        delay = error['retry_after']
                    state['next_retry_at'] = now + delay
            elif method in _MESSAGE_METHODS:
                state['send_error'] = error
                state['last_send_attempt_at'] = now
                if succeeded:
                    state['last_send_at'] = now
            else:
                state['api_error'] = error
            try:
                _write_state(self._state_dir, self._token, state)
            except Exception:
                # Persistence failure must never cause a delivered message to replay.
                print('Telegram 运行状态记录失败，请检查状态目录。', file=sys.stderr)
        if error is not None:
            print('Telegram API：' + _LABELS[error['category']] + '。', file=sys.stderr)

    def retry_delay(self):
        """Remaining delay for the latest poll failure; this method never sleeps."""
        with self._lock:
            retry = self._state['next_retry_at']
            return max(0, retry - time.time()) if retry is not None else 0

    def last_send_error(self):
        """Return the latest safe send result even if diagnostic persistence failed."""
        with self._lock:
            error = self._state['send_error']
            return dict(error) if error is not None else None

    def request(self, endpoint: str, data: Optional[dict] = None) -> Optional[dict]:
        """Make exactly one HTTP attempt; callers decide when to poll again."""
        method = endpoint.split('?', 1)[0] if isinstance(endpoint, str) else ''
        result, error, body, code = None, None, None, 200
        try:
            if (not isinstance(endpoint, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*(?:\?[^#\r\n]*)?', endpoint)
                    or (data is not None and not isinstance(data, dict))):
                raise ValueError('请求参数无效')
            payload = json.dumps(data, allow_nan=False).encode('utf-8') if data is not None else None
            request = urllib.request.Request(self._base_url + '/' + endpoint, data=payload,
                                             headers={'Content-Type': 'application/json'})
        except (ValueError, TypeError, UnicodeError):
            error = _error('invalid_request')
        else:
            try:
                with urllib.request.build_opener(NoRedirect()).open(
                        request, timeout=35 if method == 'getUpdates' else 15) as response:
                    code = response.getcode()
                    body = _decode(response)
            except urllib.error.HTTPError as failure:
                code = failure.code
                try:
                    body = _decode(failure)
                except Exception:
                    body = None
                finally:
                    failure.close()
            except (TimeoutError, socket.timeout):
                error = _error('timeout')
            except urllib.error.URLError as failure:
                error = _error('timeout' if isinstance(failure.reason, (TimeoutError, socket.timeout)) else 'network')
            except (ValueError, TypeError, UnicodeError, RecursionError):
                error = _error('invalid_response')
            except Exception:
                error = _error('network')
            if error is None:
                if code != 200:
                    error = _classify(code, body)
                elif isinstance(body, dict) and body.get('ok') is False and type(body.get('error_code')) is int:
                    code = body['error_code']
                    error = _classify(code, body)
                elif isinstance(body, dict) and body.get('ok') is True and 'result' in body:
                    value = body['result']
                    valid = isinstance(value, (dict, list, bool))
                    if method == 'getUpdates':
                        valid = isinstance(value, list) and all(
                            isinstance(item, dict) and type(item.get('update_id')) is int
                            and item['update_id'] >= 0 for item in value)
                    elif method in _MESSAGE_METHODS:
                        valid = (isinstance(value, dict) and type(value.get('message_id')) is int
                                 and value['message_id'] >= 0)
                        if method == 'editMessageText' and value is True:
                            valid = True
                    if valid:
                        result = body
                    else:
                        error = _error('invalid_response')
                else:
                    error = _error('invalid_response')
                if (method == 'editMessageText' and code == 400 and isinstance(body, dict)
                        and isinstance(body.get('description'), str)
                        and 'message is not modified' in body['description'].lower()):
                    result, error = {'ok': True, 'result': True}, None
        self._record(method, result is not None, error)
        return result

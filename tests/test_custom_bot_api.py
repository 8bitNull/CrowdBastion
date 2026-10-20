"""Telegram transport tests use synthetic responses and private temporary state."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
import urllib.error
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'lib/crowdsec_bot_api.py'
if SOURCE.exists():
    spec = importlib.util.spec_from_file_location('tested_bot_api', SOURCE)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
else:
    api = None

TOKEN = '123456:SECRET_TOKEN_MARKER'
BASE = 'https://telegram.invalid/bot' + TOKEN
SECRET = 'sensitive_payload_marker'


class Response(io.BytesIO):
    def __init__(self, body, status=200):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        super().__init__(body)
        self.status = status

    def getcode(self):
        return self.status


class Opener:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class TelegramTransport(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(api, 'The isolated Telegram transport module is required')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'state'
        self.now = 1000.0
        self.clock = patch.object(api.time, 'time', side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stderr(self.output)
        self.capture.__enter__()
        self.addCleanup(self.capture.__exit__, None, None, None)
        self.client = api.TelegramClient(BASE, str(self.directory), TOKEN)

    def network(self, *outcomes):
        opener = Opener(outcomes)
        patched = patch.object(api.urllib.request, 'build_opener', return_value=opener)
        patched.start()
        self.addCleanup(patched.stop)
        return opener

    def report(self, token=TOKEN):
        return api.read_runtime(str(self.directory), token, now=self.now)

    def path(self, token=TOKEN):
        return self.directory / ('runtime-' + hashlib.sha256(token.encode()).hexdigest()[:24] + '.json')

    def failure(self, code, json_error=False, retry_after=None, endpoint='getUpdates'):
        body = {'ok': False, 'error_code': code, 'description': TOKEN + BASE + SECRET}
        if retry_after is not None:
            body['parameters'] = {'retry_after': retry_after}
        outcome = Response(body) if json_error else urllib.error.HTTPError(
            BASE, code, TOKEN + SECRET, {}, Response(body))
        opener = self.network(outcome)
        self.assertIsNone(self.client.request(endpoint, {'text': SECRET}))
        self.assertEqual(len(opener.calls), 1, 'A request must never replay an operation')
        return self.report()

    def test_success_preserves_response_and_poll_timeout(self):
        expected = {'ok': True, 'result': [{'update_id': 1}]}
        opener = self.network(Response(expected), Response({'ok': True, 'result': {'message_id': 2}}))
        self.assertEqual(self.client.request('getUpdates?offset=0&timeout=20'), expected)
        self.now += 1
        self.client.request('sendMessage', {'chat_id': 3, 'text': SECRET})
        self.assertEqual([entry[1] for entry in opener.calls], [35, 15])
        self.assertEqual(json.loads(opener.calls[1][0].data), {'chat_id': 3, 'text': SECRET})
        self.assertEqual(self.report()['last_poll_at'], 1000)
        self.assertEqual(self.report()['last_send_at'], 1001)
        self.assertEqual(self.report()['status'], 'healthy')

    def test_http_and_json_failures_have_safe_specific_categories(self):
        cases = [(400, 'invalid_request'), (401, 'identity'), (403, 'permissions'),
                 (409, 'conflict'), (429, 'rate_limit'), (500, 'service'), (503, 'service')]
        for as_json in (False, True):
            for code, category in cases:
                with self.subTest(as_json=as_json, code=code):
                    report = self.failure(code, json_error=as_json, retry_after=17)
                    self.assertEqual(report['poll_error']['category'], category)
                    self.assertEqual(report['status'], 'error')
                    if code in (401, 403, 409):
                        self.assertEqual(self.client.retry_delay(), 60)
                    if code == 429:
                        self.assertEqual(self.client.retry_delay(), 17)
                    visible = self.output.getvalue() + self.path().read_text() + api.describe_runtime(report)
                    for secret in (TOKEN, BASE, SECRET, 'sensitive_payload'):
                        self.assertNotIn(secret, visible)

    def test_network_and_timeout_errors_hide_exception_details(self):
        for error, category in [(urllib.error.URLError(TOKEN + SECRET), 'network'),
                                (socket.timeout(TOKEN), 'timeout'),
                                (urllib.error.URLError(socket.timeout(TOKEN)), 'timeout')]:
            with self.subTest(category=category):
                self.network(error)
                self.assertIsNone(self.client.request('getUpdates'))
                self.assertEqual(self.report()['poll_error']['category'], category)
        self.assertNotIn(TOKEN, self.output.getvalue() + self.path().read_text())

    def test_invalid_json_shape_and_oversize_are_rejected(self):
        bodies = [b'{', [], {'ok': 1, 'result': []}, {'ok': True},
                  {'ok': True, 'result': None}, {'ok': True, 'result': {}},
                  {'ok': True, 'result': [1]}, {'ok': True, 'result': [{}]},
                  {'ok': True, 'result': [{'update_id': True}]},
                  {'ok': True, 'result': [{'update_id': SECRET}]},
                  {'ok': False}, b'x' * (1024 * 1024 + 1)]
        for body in bodies:
            with self.subTest(kind=str(type(body))):
                self.network(Response(body))
                self.assertIsNone(self.client.request('getUpdates'))
                self.assertEqual(self.report()['poll_error']['category'], 'invalid_response')

    def test_poll_backoff_caps_resets_and_counts_down_without_retries(self):
        opener = self.network(*[urllib.error.URLError(SECRET) for _ in range(9)],
                              Response({'ok': True, 'result': []}), urllib.error.URLError(SECRET))
        for expected in [2, 4, 8, 16, 32, 60, 60, 60, 60]:
            self.assertIsNone(self.client.request('getUpdates'))
            self.assertEqual(self.client.retry_delay(), expected)
            self.now += 1
            self.assertEqual(self.client.retry_delay(), expected - 1)
        self.assertIsNotNone(self.client.request('getUpdates'))
        self.assertEqual(self.client.retry_delay(), 0)
        self.assertIsNone(self.report()['poll_error'])
        self.assertIsNone(self.report()['next_retry_at'])
        self.client.request('getUpdates')
        self.assertEqual(self.client.retry_delay(), 2)
        self.assertEqual(len(opener.calls), 11)

    def test_invalid_rate_limits_use_bounded_backoff(self):
        for value in [None, True, 0, -3, '999', {}, 1.5]:
            with self.subTest(value=value):
                self.failure(429, retry_after=value)
                self.assertGreaterEqual(self.client.retry_delay(), 2)
                self.assertLessEqual(self.client.retry_delay(), 60)
        self.failure(429, retry_after=120)
        self.assertEqual(self.client.retry_delay(), 120)

    def test_send_success_and_other_actions_do_not_clear_poll_failure(self):
        self.network(Response({'ok': True, 'result': []}),
                     urllib.error.URLError(SECRET),
                     Response({'ok': True, 'result': {'message_id': 1}}),
                     Response({'ok': True, 'result': True}),
                     Response({'ok': True, 'result': True}))
        self.client.request('getUpdates')
        self.now += 10
        self.client.request('getUpdates')
        self.now += 1
        self.client.request('sendMessage', {'text': SECRET})
        self.now += 1
        self.client.request('setMyCommands', {})
        self.client.request('answerCallbackQuery', {})
        report = self.report()
        self.assertEqual(report['last_poll_at'], 1000)
        self.assertEqual(report['last_poll_attempt_at'], 1010)
        self.assertEqual(report['last_send_at'], 1011)
        self.assertEqual(report['poll_error']['category'], 'network')
        self.assertEqual(self.client.retry_delay(), 0)

    def test_failed_send_is_never_replayed_and_keeps_successful_send_time(self):
        self.network(Response({'ok': True, 'result': {'message_id': 2}}))
        self.client.request('sendMessage', {'text': SECRET})
        self.now += 1
        report = self.failure(500, endpoint='sendMessage')
        self.assertEqual(report['send_error']['category'], 'service')
        self.assertEqual(report['last_send_at'], 1000)
        self.assertEqual(report['last_send_attempt_at'], 1001)
        self.assertIsNone(report['poll_error'])

    def test_callback_and_registration_results_preserve_delivery_error(self):
        self.network(Response({'ok': True, 'result': []}),
                     Response({'ok': False, 'error_code': 500}),
                     Response({'ok': True, 'result': True}),
                     Response({'ok': False, 'error_code': 400}),
                     Response({'ok': True, 'result': True}),
                     Response({'ok': True, 'result': {'message_id': 8}}))
        self.client.request('getUpdates')
        self.client.request('sendMessage', {'text': SECRET})
        self.client.request('setMyCommands', {})
        self.assertIsNotNone(self.report()['send_error'])
        self.assertEqual(self.report()['send_error']['category'], 'service')
        self.client.request('answerCallbackQuery', {})
        self.assertEqual(self.report()['send_error']['category'], 'service')
        self.assertEqual(self.report()['api_error']['category'], 'invalid_request')
        self.client.request('answerCallbackQuery', {})
        self.assertIsNone(self.report()['api_error'])
        self.assertEqual(self.report()['send_error']['category'], 'service')
        self.client.request('sendMessage', {'text': SECRET})
        self.assertIsNone(self.report()['send_error'])
        self.assertEqual(self.report()['status'], 'healthy')

    def test_uncertain_send_timeout_is_not_replayed(self):
        opener = self.network(socket.timeout(TOKEN + SECRET))
        self.assertIsNone(self.client.request('sendMessage', {'text': SECRET}))
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual(self.report()['send_error']['category'], 'timeout')
        self.assertIsNone(self.report()['last_send_at'])
        self.assertEqual(self.client.retry_delay(), 0)

    def test_message_result_requires_message_identifier(self):
        for method, result in [('sendMessage', {}), ('sendMessage', True),
                               ('sendMessage', {'message_id': SECRET}),
                               ('editMessageText', []), ('editMessageText', False),
                               ('editMessageText', {'message_id': True})]:
            with self.subTest(method=method, result=result):
                self.network(Response({'ok': True, 'result': result}))
                self.assertIsNone(self.client.request(method, {}))
                self.assertEqual(self.report()['send_error']['category'], 'invalid_response')

    def test_not_modified_is_success_only_for_edit_message_text(self):
        body = {'ok': False, 'error_code': 400,
                'description': 'Bad Request: message is not modified: ' + TOKEN}
        opener = self.network(Response(body), Response(body),
                              urllib.error.HTTPError(BASE, 400, SECRET, {}, Response(body)))
        self.assertEqual(self.client.request('editMessageText', {}), {'ok': True, 'result': True})
        self.assertIsNone(self.client.request('sendMessage', {}))
        self.assertEqual(self.client.request('editMessageText', {}), {'ok': True, 'result': True})
        self.assertEqual(len(opener.calls), 3)
        self.assertNotIn(TOKEN, self.path().read_text() + self.output.getvalue())

    def test_runtime_files_are_private_and_per_token(self):
        self.network(Response({'ok': True, 'result': []}), Response({'ok': True, 'result': []}))
        self.client.request('getUpdates')
        other = api.TelegramClient('https://telegram.invalid/botother', str(self.directory), 'other')
        self.now += 1
        other.request('getUpdates')
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path().stat().st_mode), 0o600)
        self.assertEqual(self.report()['last_poll_at'], 1000)
        self.assertEqual(self.report('other')['last_poll_at'], 1001)
        self.assertEqual(self.report()['instance']['pid'], os.getpid())
        self.assertNotEqual(self.report()['instance']['session'], self.report('other')['instance']['session'])
        self.assertEqual(len(list(self.directory.iterdir())), 2)

    def test_restart_preserves_history_but_uses_a_new_instance_marker(self):
        self.network(Response({'ok': True, 'result': []}),
                     Response({'ok': True, 'result': {'message_id': 1}}),
                     urllib.error.URLError(SECRET))
        self.client.request('getUpdates')
        self.client.request('sendMessage', {})
        old_session = self.report()['instance']['session']
        restarted = api.TelegramClient(BASE, str(self.directory), TOKEN)
        self.now += 10
        restarted.request('getUpdates')
        report = self.report()
        self.assertEqual(report['last_poll_at'], 1000)
        self.assertEqual(report['last_send_at'], 1000)
        self.assertEqual(report['last_poll_attempt_at'], 1010)
        self.assertNotEqual(report['instance']['session'], old_session)

    def test_existing_state_permissions_are_made_private_on_write(self):
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        self.path().write_text('{}')
        self.path().chmod(0o644)
        self.network(Response({'ok': True, 'result': []}))
        self.assertIsNotNone(self.client.request('getUpdates'))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path().stat().st_mode), 0o600)
        self.assertEqual(self.report()['status'], 'healthy')

    def test_read_runtime_is_read_only_and_preserves_stale_history(self):
        self.assertEqual(self.report()['status'], 'unknown')
        self.assertFalse(self.directory.exists())
        self.network(Response({'ok': True, 'result': []}),
                     Response({'ok': True, 'result': {'message_id': 1}}))
        self.client.request('getUpdates')
        self.client.request('sendMessage', {'text': SECRET})
        before = self.path().stat()
        self.now += 91
        report = self.report()
        after = self.path().stat()
        self.assertEqual(report['status'], 'stale')
        self.assertEqual(report['last_poll_at'], 1000)
        self.assertEqual(report['last_send_at'], 1000)
        self.assertEqual(report['age_seconds'], 91)
        self.assertEqual((before.st_mtime_ns, before.st_mode, before.st_size),
                         (after.st_mtime_ns, after.st_mode, after.st_size))
        text = api.describe_runtime(report)
        for phrase in ('最近成功轮询', '最近发送成功', '陈旧', '91'):
            self.assertIn(phrase, text)

    def test_live_poll_failure_and_send_only_state_are_not_healthy(self):
        self.network(Response({'ok': True, 'result': {'message_id': 1}}), urllib.error.URLError(SECRET))
        self.client.request('sendMessage', {})
        self.assertEqual(self.report()['status'], 'unknown')
        self.client.request('getUpdates')
        self.assertEqual(self.report()['status'], 'error')
        self.assertIsNone(self.report()['last_poll_at'])
        self.now += 91
        self.assertEqual(self.report()['status'], 'stale')

    def test_symlink_and_nonregular_state_paths_are_refused_without_losing_success(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        self.directory.symlink_to(outside, target_is_directory=True)
        self.network(Response({'ok': True, 'result': []}))
        self.assertIsNotNone(self.client.request('getUpdates'))
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.report()['status'], 'unknown')
        self.directory.unlink()
        self.directory.mkdir(mode=0o700)
        victim = outside / 'victim'
        victim.write_text(SECRET)
        for create in [lambda: self.path().symlink_to(victim), lambda: os.mkfifo(self.path()), lambda: self.path().mkdir()]:
            create()
            self.network(Response({'ok': True, 'result': []}))
            self.assertIsNotNone(self.client.request('getUpdates'))
            self.assertEqual(self.report()['status'], 'unknown')
            if self.path().is_dir():
                self.path().rmdir()
            else:
                self.path().unlink()
        self.assertEqual(victim.read_text(), SECRET)
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_runtime_write_error_cannot_turn_a_sent_message_into_failure(self):
        self.directory.write_text(SECRET)
        opener = self.network(Response({'ok': True, 'result': {'message_id': 7}}))
        self.assertEqual(self.client.request('sendMessage', {'text': SECRET})['result']['message_id'], 7)
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual(self.directory.read_text(), SECRET)
        self.assertIn('运行状态', self.output.getvalue())
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_corrupt_unreadable_and_untrusted_runtime_are_safe_and_read_only(self):
        self.directory.mkdir(mode=0o700)
        for raw in ('{', '[]', '{"version": 1}', json.dumps({'version': 1, 'poll_error': {'category': SECRET, 'label': TOKEN}})):
            self.path().write_text(raw)
            self.path().chmod(0o600)
            before = self.path().read_bytes()
            report = self.report()
            self.assertEqual(report['status'], 'unknown')
            self.assertNotIn(TOKEN, api.describe_runtime(report))
            self.assertNotIn(SECRET, json.dumps(report))
            self.assertEqual(self.path().read_bytes(), before)
        self.path().chmod(0)
        before = self.path().stat().st_mode
        self.assertEqual(self.report()['status'], 'unknown')
        self.assertEqual(self.path().stat().st_mode, before)

    def test_runtime_reader_discards_injected_error_text_and_extra_fields(self):
        self.failure(401)
        raw = json.loads(self.path().read_text())
        raw['poll_error']['label'] = TOKEN
        raw['poll_error']['description'] = SECRET
        raw['request'] = {'url': BASE, 'text': SECRET}
        self.path().write_text(json.dumps(raw))
        report = self.report()
        self.assertEqual(report['poll_error']['category'], 'identity')
        for secret in (TOKEN, SECRET, BASE):
            self.assertNotIn(secret, json.dumps(report) + api.describe_runtime(report))
        self.assertIn(SECRET, self.path().read_text(), 'The reader must not rewrite even invalid local text')

    def test_root_state_directory_is_refused_before_it_can_be_chmodded(self):
        with self.assertRaises(ValueError):
            api.TelegramClient(BASE, '/', TOKEN)

    def test_https_only_and_redirects_are_not_followed(self):
        for base in ['http://telegram.invalid/bot' + TOKEN,
                     'https://user:password@telegram.invalid/bot' + TOKEN,
                     'https://telegram.invalid/bot' + TOKEN + '?secret=' + SECRET]:
            with self.subTest(base=base):
                with self.assertRaises(ValueError) as caught:
                    api.TelegramClient(base, str(self.directory), TOKEN)
                self.assertNotIn(TOKEN, str(caught.exception))
                self.assertNotIn(SECRET, str(caught.exception))
        handler = api.NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, None, None, BASE))
        opener = self.network(urllib.error.HTTPError(BASE, 302, TOKEN, {}, Response(b'')))
        self.assertIsNone(self.client.request('sendMessage', {}))
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual(self.report()['send_error']['category'], 'redirect')

    def test_describe_runtime_uses_only_safe_labels_and_retry_time(self):
        report = self.failure(429, retry_after=45)
        text = api.describe_runtime(report)
        for phrase in ('当前错误', '429', '重试', '45', '最近成功轮询', '最近发送成功'):
            self.assertIn(phrase, text)
        report['poll_error']['label'] = TOKEN
        report['poll_error']['description'] = SECRET
        report['instance']['session'] = SECRET
        self.assertNotIn(TOKEN, api.describe_runtime(report))
        self.assertNotIn(SECRET, api.describe_runtime(report))


if __name__ == '__main__':
    unittest.main()

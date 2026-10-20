"""Exercise Telegram entrypoints without sending messages or changing the host."""
import importlib.util
import io
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))


class ConfirmedFlows(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('bot_flow', ROOT / 'lib/crowdsec_bot.py')
        self.bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bot)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bot.STATE_DIR = str(self.base / 'state')
        self.bot.BOT_TOKEN = '123:PRIVATE'
        self.bot.ADMIN_USER_ID, self.bot.ADMIN_CHAT_ID = 12, -34
        self.bot.CSCLI_CONFIG = str(self.base / 'config.yaml')
        self.sent = []
        self.tg = patch.object(self.bot, 'tg_request', side_effect=self.telegram)
        self.tg.start()
        self.addCleanup(self.tg.stop)

    def telegram(self, endpoint, payload=None):
        self.sent.append((endpoint, payload))
        return {'ok': True, 'result': {'message_id': 90}}

    def message(self, text):
        return {'message': {'from': {'id': 12}, 'chat': {'id': -34}, 'text': text}}

    def callback(self, data, user=12, chat=-34):
        return {'callback_query': {'id': 'callback', 'from': {'id': user}, 'data': data,
                                  'message': {'message_id': 90, 'chat': {'id': chat}}}}

    def request(self, update):
        self.assertTrue(hasattr(self.bot, 'handle_update'), 'missing unified update handler')
        self.bot.handle_update(update)
        payload = next(p for method, p in reversed(self.sent) if method == 'sendMessage')
        buttons = payload['reply_markup']['inline_keyboard'][0]
        return buttons[0]['callback_data'], buttons[1]['callback_data']

    def test_all_mutating_commands_and_old_buttons_require_confirmation(self):
        cases = [self.message('/ban 203.0.113.8 2h'), self.message('/unban 203.0.113.8'),
                 self.message('/white 203.0.113.8'), self.callback('unban:203.0.113.8'),
                 self.callback('white:203.0.113.8'), self.callback('em:reload_cs'),
                 self.callback('em:drop_caches')]
        with patch.object(self.bot, 'run_cmd') as run, patch.object(self.bot, 'drop_caches') as drop:
            for update in cases:
                with self.subTest(update=update):
                    yes, no = self.request(update)
                    self.assertLessEqual(len(yes.encode()), 64)
                    self.assertNotEqual(yes, no)
            run.assert_not_called()
            drop.assert_not_called()
        preview = '\n'.join(p['text'] for m, p in self.sent if m == 'sendMessage')
        self.assertIn('解封', preview)
        self.assertIn('白名单', preview)

    def test_confirmed_unban_executes_once_even_when_result_delivery_fails(self):
        yes, _ = self.request(self.message('/unban 203.0.113.8'))
        calls = []
        with patch.object(self.bot, 'run_cmd', side_effect=lambda args: calls.append(args) or ''), \
                patch.object(self.bot, 'tg_request', return_value=None):
            self.bot.handle_update(self.callback(yes))
            self.bot.handle_update(self.callback(yes))
        self.assertEqual(calls, [['cscli', 'decisions', 'delete', '--ip', '203.0.113.8']])
        audits = list((self.base / 'state').glob('bot-actions-*.jsonl'))
        self.assertEqual(len(audits), 1)
        content = audits[0].read_text()
        self.assertIn('success', content)
        self.assertNotIn('PRIVATE', content)

    def test_cancel_and_wrong_identity_do_not_execute_or_steal_confirmation(self):
        yes, no = self.request(self.message('/unban 203.0.113.8'))
        with patch.object(self.bot, 'run_cmd') as run:
            self.bot.handle_update(self.callback(yes, user=99))
            self.bot.handle_update(self.callback(yes, chat=-99))
            self.bot.handle_update(self.callback(no))
            self.bot.handle_update(self.callback(yes))
            run.assert_not_called()

    def test_audit_failure_refuses_operation(self):
        yes, _ = self.request(self.message('/unban 203.0.113.8'))
        self.bot.get_action_store().begin = lambda ticket: (_ for _ in ()).throw(OSError('PRIVATE'))
        with patch.object(self.bot, 'run_cmd') as run:
            self.bot.handle_update(self.callback(yes))
            run.assert_not_called()
        text = '\n'.join(p.get('text', '') for _, p in self.sent)
        self.assertIn('未执行', text)
        self.assertNotIn('PRIVATE', text)

    def test_action_exception_leaves_a_trace_without_exposing_details(self):
        yes, _ = self.request(self.callback('em:reload_cs'))
        with patch.object(self.bot, 'reload_engine', side_effect=RuntimeError('PRIVATE')):
            self.bot.handle_update(self.callback(yes))
        content = '\n'.join(p.get('text', '') for _, p in self.sent)
        self.assertIn('待核对', content)
        self.assertNotIn('PRIVATE', content)

    def test_actual_mutation_timeout_remains_pending_for_state_verification(self):
        yes, _ = self.request(self.message('/unban 203.0.113.8'))
        timeout = subprocess.TimeoutExpired(['cscli', 'PRIVATE'], 8)
        with patch.object(self.bot.subprocess, 'run', side_effect=timeout):
            self.bot.handle_update(self.callback(yes))
        content = '\n'.join(p.get('text', '') for _, p in self.sent)
        self.assertIn('待核对', content)
        self.assertNotIn('PRIVATE', content)
        self.assertEqual(len(self.bot.get_action_store().unfinished()), 1)

    def test_signal_interruption_keeps_mutation_outcome_pending(self):
        requests = [self.message('/ban 203.0.113.8'), self.message('/unban 203.0.113.8'),
                    self.callback('em:reload_cs')]
        for update in requests:
            with self.subTest(update=update):
                before = len(self.bot.get_action_store().unfinished())
                yes, _ = self.request(update)

                def interrupted(args, **kwargs):
                    if args == ['ip', '-j', 'address', 'show']:
                        return subprocess.CompletedProcess(args, 0, '[]', '')
                    validating = args[0] == 'crowdsec' and '-t' in args
                    return subprocess.CompletedProcess(args, 0 if validating else -15,
                                                       'PRIVATE', 'PRIVATE')

                with patch.object(self.bot.subprocess, 'run', side_effect=interrupted):
                    self.bot.handle_update(self.callback(yes))
                self.assertEqual(len(self.bot.get_action_store().unfinished()), before + 1)
                self.assertIn('待核对', self.sent[-1][1]['text'])
                self.assertNotIn('PRIVATE', self.sent[-1][1]['text'])

    def test_read_only_menu_responds_directly(self):
        self.assertTrue(hasattr(self.bot, 'handle_update'), 'missing unified update handler')
        self.bot.handle_update(self.message('/help'))
        self.assertTrue(any(m == 'sendMessage' for m, _ in self.sent))
        self.assertFalse(any('yes:' in json.dumps(p) for _, p in self.sent))

    def test_bad_update_does_not_discard_later_updates_in_same_poll(self):
        updates = {'ok': True, 'result': [
            {'update_id': 1, **self.message('/help')},
            {'update_id': 2, **self.message('/help')}]}
        processed = []
        def handle(update):
            processed.append(update['update_id'])
            if update['update_id'] == 1:
                raise ValueError('PRIVATE')
        self.assertTrue(hasattr(self.bot, 'handle_update'), 'missing unified update handler')
        with patch.object(self.bot, 'register_bot_commands'), \
                patch.object(self.bot, 'tg_request', side_effect=[updates, SystemExit]), \
                patch.object(self.bot, 'handle_update', side_effect=handle):
            with self.assertRaises(SystemExit):
                self.bot.main()
        self.assertEqual(processed, [1, 2])
        self.assertEqual(Path(self.bot.offset_path()).read_text(), '3')

    def test_database_failure_is_unknown_not_zero_or_malicious_ip_count(self):
        self.bot.DB_PATH = str(self.base / 'missing.sqlite')
        with patch.object(self.bot, 'module_health_status', return_value='健康摘要', create=True):
            text = self.bot.module_system_status()
        self.assertIn('未知', text)
        self.assertNotIn('0 个恶意 IP', text)
        self.assertNotIn('DMIT', text)


class PollingRestart(unittest.TestCase):
    def restart(self, error_code=None, retry_after=None, restart_at=1000):
        spec = importlib.util.spec_from_file_location('bot_restart', ROOT / 'lib/crowdsec_bot.py')
        bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bot)
        api = bot.sibling('crowdsec_bot_api')
        now, sleeps, requests = [1000.0], [], []

        class Response(io.BytesIO):
            def __init__(self, body):
                super().__init__(json.dumps(body).encode())

            def getcode(self):
                return 200

        responses = []
        if error_code is not None:
            responses.append(Response({'ok': False, 'error_code': error_code,
                                       'parameters': {'retry_after': retry_after}}))
        responses.extend([Response({'ok': True, 'result': True}),
                          Response({'ok': True, 'result': []}), SystemExit()])

        def respond(request, **kwargs):
            requests.append((now[0], request.full_url.rsplit('/', 1)[1]))
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        def sleep(delay):
            sleeps.append(delay)
            now[0] += delay

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(api.time, 'time', side_effect=lambda: now[0]), \
                patch.object(api.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(api.time, 'sleep', side_effect=sleep), \
                patch.object(api.urllib.request.OpenerDirector, 'open', side_effect=respond):
            bot.STATE_DIR = directory
            bot.BOT_TOKEN = '123:SYNTHETIC'
            bot.TG_API_BASE = 'https://telegram.invalid/bot' + bot.BOT_TOKEN
            if error_code is not None:
                bot.tg_request('getUpdates')
            # A restart discards the client but retains its private state files.
            bot._API_CLIENT = None
            now[0] = restart_at
            requests.clear()
            with self.assertRaises(SystemExit):
                bot.main()
        return requests, sleeps

    def test_restart_waits_for_remaining_rate_limit_before_any_request(self):
        requests, sleeps = self.restart(429, retry_after=120, restart_at=1010)
        self.assertEqual(requests[:2], [(1120, 'setMyCommands'),
                                       (1120, 'getUpdates?offset=0&timeout=20')])
        self.assertEqual(sleeps, [60, 50])

    def test_restart_preserves_remaining_exponential_backoff(self):
        requests, sleeps = self.restart(503, restart_at=1001)
        self.assertEqual(requests[:2], [(1002, 'setMyCommands'),
                                       (1002, 'getUpdates?offset=0&timeout=20')])
        self.assertEqual(sleeps, [1])

    def test_expired_retry_does_not_delay_startup(self):
        requests, sleeps = self.restart(429, retry_after=120, restart_at=1130)
        self.assertEqual(requests[:2], [(1130, 'setMyCommands'),
                                       (1130, 'getUpdates?offset=0&timeout=20')])
        self.assertEqual(sleeps, [])

    def test_first_start_polls_without_delay(self):
        requests, sleeps = self.restart()
        self.assertEqual(requests[:2], [(1000, 'setMyCommands'),
                                       (1000, 'getUpdates?offset=0&timeout=20')])
        self.assertEqual(sleeps, [])


if __name__ == '__main__':
    unittest.main()

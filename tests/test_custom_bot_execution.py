"""TG evidence cards read real logs; external cscli and Telegram stay isolated."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from test_execution_evidence import receipt

ROOT = Path(__file__).resolve().parents[1]


class ExecutionCards(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('bot_execution', os.environ.get('CROWDSEC_BOT_TEST_SOURCE', ROOT/'lib/crowdsec_bot.py'))
        self.bot = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.bot)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.bot.NPM_LOG_DIR = str(self.base)
        self.alert = dict(id=42, source={'value': '192.0.2.10'}, scenario='qa/<scan>',
                          start_at='2026-10-19T00:00:00Z', simulated=False, decisions=[])

    def command(self, args):
        if 'inspect' in args:
            return json.dumps([self.alert])
        return '[]'

    def card(self):
        with patch.object(self.bot, 'run_cmd', side_effect=self.command):
            return self.bot.module_execution(42)

    def test_forensic_button_and_same_source_not_exact_alert_claim(self):
        with patch.object(self.bot, 'run_cmd', side_effect=self.command):
            _, kb = self.bot.module_forensics(42)
        self.assertIn('exp:42', [b['callback_data'] for row in kb['inline_keyboard'] for b in row])
        (self.base/'proxy-host-1_error.log').write_text(receipt(time=time.time()-1, cause='appsec_failure'))
        text, kb = self.card()
        self.assertIn('已观测到同源 Web 拒绝', text)
        self.assertIn('AppSec 故障策略拒绝', text)
        self.assertIn('不能证明原触发请求', text)
        self.assertNotIn('本告警已拦截', text)
        self.assertIn('403', text)
        self.assertIn('exp:42', [b['callback_data'] for row in kb['inline_keyboard'] for b in row])

    def test_unavailable_and_zero_observations_have_distinct_messages(self):
        text, _ = self.card(); self.assertIn('日志不可用', text)
        (self.base/'proxy-host-1_error.log').write_text('business returned 403\n')
        text, _ = self.card(); self.assertIn('尚未观测到', text)
        self.assertNotIn('拦截失败', text)

    def test_simulated_alert_cannot_become_execution_claim(self):
        self.alert['simulated'] = True
        (self.base/'proxy-host-1_error.log').write_text(receipt(time=time.time()-1))
        text, _ = self.card()
        self.assertIn('模拟告警', text)
        self.assertIn('独立观测', text)
        self.assertNotIn('本告警已拦截', text)

    def test_ack_precedes_queries_and_refresh_edits_original_message(self):
        cq = dict(id='q', data='exp:42', **{'from': {'id': self.bot.ADMIN_USER_ID}},
                  message={'message_id': 90, 'chat': {'id': self.bot.ADMIN_CHAT_ID}})
        calls = []
        def command(args):
            calls.append(('command', args)); return self.command(args)
        def telegram(endpoint, data):
            calls.append((endpoint, data)); return {'ok': True}
        with patch.object(self.bot, 'run_cmd', side_effect=command), patch.object(self.bot, 'tg_request', side_effect=telegram):
            self.assertTrue(self.bot.handle_view_callback(cq))
        self.assertEqual(calls[0][0], 'answerCallbackQuery')
        payload = next(v for k,v in calls if k == 'editMessageText')
        self.assertEqual(payload['message_id'], 90)
        self.assertLess(len(payload['text']), 3900)
        cq['from']['id'] += 1
        with patch.object(self.bot, 'run_cmd') as run:
            self.assertFalse(self.bot.handle_view_callback(cq))
        self.assertFalse(run.called)

    def test_malformed_callback_does_not_query(self):
        for data in ['exp:0', 'exp:-1', 'exp:42;whoami', 'exp:'+'1'*20]:
            cq = dict(id='q', data=data, **{'from': {'id': self.bot.ADMIN_USER_ID}},
                      message={'message_id': 90, 'chat': {'id': self.bot.ADMIN_CHAT_ID}})
            with patch.object(self.bot, 'run_cmd') as run:
                self.assertFalse(self.bot.handle_view_callback(cq))
            self.assertFalse(run.called)


if __name__ == '__main__': unittest.main()

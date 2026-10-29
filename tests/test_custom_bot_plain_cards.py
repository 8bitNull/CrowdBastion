"""Short cards retain evidence, navigation context and authorization in details."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from test_execution_evidence import receipt

ROOT = Path(__file__).resolve().parents[1]


class PlainCards(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('plain_bot', os.environ.get('CROWDSEC_BOT_TEST_SOURCE', ROOT/'lib/crowdsec_bot.py'))
        self.bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bot)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bot.NPM_LOG_DIR = str(self.base)
        self.bot.CSCLI_CONFIG = str(self.base/'config.yaml')
        self.bot.ADMIN_USER_ID, self.bot.ADMIN_CHAT_ID = 12, -34
        self.alert = {'id': 42, 'source': {'value': '192.0.2.10'}, 'scenario': 'qa/<scan>',
                      'start_at': '2026-10-20T00:00:00Z', 'decisions': [], 'simulated': False,
                      'events': [{'meta': [{'key': 'uri', 'value': '/sample'},
                                            {'key': 'user_agent', 'value': 'PRIVATE-UA'}]}]}
        self.decisions = []
        self.sent, self.commands = [], []
        self.run_patch = patch.object(self.bot, 'run_cmd', side_effect=self.command)
        self.run_patch.start()
        self.addCleanup(self.run_patch.stop)
        self.tg_patch = patch.object(self.bot, 'tg_request', side_effect=self.telegram)
        self.tg_patch.start()
        self.addCleanup(self.tg_patch.stop)

    def command(self, args, **kwargs):
        self.commands.append(args)
        if args[:3] == ['cscli', 'alerts', 'inspect']:
            return json.dumps([self.alert])
        if args[:3] == ['cscli', 'decisions', 'list']:
            return json.dumps(self.decisions)
        raise AssertionError('unexpected command')

    def telegram(self, method, data=None):
        self.sent.append((method, data))
        return {'ok': True, 'result': True}

    def callback(self, data, user=12):
        self.sent.clear()
        result = self.bot.handle_view_callback({'id': 'q', 'data': data, 'from': {'id': user},
            'message': {'message_id': 90, 'chat': {'id': -34}}})
        edits = [value for method, value in self.sent if method == 'editMessageText']
        return result, edits

    def test_execution_detail_round_trip_keeps_evidence_and_message(self):
        (self.base/'proxy_error.log').write_text(receipt(time=time.time()-1))
        short, keyboard = self.bot.module_execution(42)
        self.assertIn('已记录 1 次', short)
        self.assertIn('尚未验证', short)
        self.assertNotIn('请求 ID', short)
        self.assertIn('more:exp:42', json.dumps(keyboard))
        handled, edits = self.callback('more:exp:42')
        self.assertTrue(handled)
        self.assertEqual(self.sent[0][0], 'answerCallbackQuery')
        self.assertEqual(len(edits), 1)
        self.assertEqual(edits[0]['message_id'], 90)
        self.assertIn('a'*32, edits[0]['text'])
        self.assertIn('HTTP 403', edits[0]['text'])
        self.assertIn('不能证明原触发请求', edits[0]['text'])
        self.assertIn('exp:42', json.dumps(edits[0]['reply_markup']))
        _, edits = self.callback('exp:42')
        self.assertNotIn('请求 ID', edits[0]['text'])

    def test_read_failure_and_empty_records_remain_distinct_in_short_card(self):
        short, _ = self.bot.module_execution(42)
        self.assertIn('网站拒绝：暂时无法查询', short)
        (self.base/'proxy_error.log').write_text('business 403\n')
        short, _ = self.bot.module_execution(42)
        self.assertIn('网站拒绝：本次未查到记录', short)
        self.assertNotIn('⏳', short)
        self.assertNotIn('实际拦截成功', short)

    def test_partial_logs_keep_visible_notice_and_counts_in_details(self):
        (self.base/'proxy_error.log').write_text('x'*70000+'\n'+receipt(time=time.time()-1))
        short, _ = self.bot.module_execution(42)
        self.assertIn('记录不完整', short)
        _, edits = self.callback('more:exp:42')
        self.assertIn('日志截尾：1', edits[0]['text'])
        self.assertIn('读取失败：0', edits[0]['text'])

    def test_forensic_detail_keeps_request_sample_and_current_decision_separate(self):
        self.alert['decisions'] = [{'type': 'ban', 'duration': '4h'}]
        short, _ = self.bot.module_forensics(42)
        self.assertIn('/sample', short)
        self.assertIn('告警处置', short)
        self.assertNotIn('PRIVATE-UA', short)
        self.assertNotIn('剩余', short)
        _, edits = self.callback('more:ins:42')
        self.assertIn('PRIVATE-UA', edits[0]['text'])
        self.assertIn('dip:192.0.2.10', json.dumps(edits[0]['reply_markup']))

    def test_more_callback_rejects_unauthorized_nested_and_mutating_routes(self):
        for data, user in [('more:exp:42', 99), ('more:more:exp:42', 12),
                           ('more:unban:192.0.2.10', 12), ('more:exp:0', 12)]:
            before = len(self.commands)
            handled, edits = self.callback(data, user=user)
            self.assertFalse(handled)
            self.assertFalse(edits)
            self.assertEqual(len(self.commands), before)

    def test_non_ban_current_decision_is_not_rendered_as_ban(self):
        self.decisions = [{'decisions': [{'type': 'captcha', 'duration': '59m12s'}]}]
        short, _ = self.bot.module_execution(42)
        self.assertIn('验证码', short)
        self.assertNotIn('封禁要求：', short)
        self.decisions.append({'decisions': [{'type': 'ban', 'duration': '2h'}]})
        short, _ = self.bot.module_execution(42)
        self.assertIn('2 条', short)

    def test_long_forensic_samples_fit_telegram_html_budget_in_details(self):
        self.alert['scenario'] = '<&>'*1000
        self.alert['source'].update(cn='<&>'*1000, as_name='<&>'*1000)
        self.alert['events'] = [{'meta': [{'key': 'uri', 'value': str(n)+'<&>'*1000},
                                         {'key': 'user_agent', 'value': '<&>'*1000},
                                         {'key': 'method', 'value': '<&>'*1000}]}
                                for n in range(3)]
        _, edits = self.callback('more:ins:42')
        self.assertLess(len(edits[0]['text']), 3900)

    def test_simulated_current_decision_stays_marked_even_for_real_alert(self):
        self.decisions = [{'simulated': True, 'decisions': [{'type': 'ban', 'duration': '4h'}]}]
        short, _ = self.bot.module_execution(42)
        self.assertIn('模拟处置', short)
        self.assertNotIn('封禁要求：', short)

    def test_send_error_does_not_mark_successful_polling_as_failed(self):
        api = self.bot.sibling('crowdsec_bot_api')
        self.bot.STATE_DIR = str(self.base/'state')
        state = api._empty_state()
        state.update(checked_at=time.time(), last_poll_at=time.time(), last_poll_attempt_at=time.time(),
                     send_error={'category': 'permissions'})
        api._write_state(self.bot.STATE_DIR, self.bot.BOT_TOKEN, state)
        text = self.bot.module_bot_status()
        self.assertIn('接收消息：正常', text)
        self.assertIn('发送', text)
        self.assertIn('权限', text)

    def test_mixed_real_and_simulated_decisions_do_not_label_all_as_simulated(self):
        self.decisions = [{'id': 42, 'scenario': 'qa/ban', 'simulated': False,
                           'decisions': [{'scope': 'Ip', 'value': '192.0.2.10', 'type': 'ban', 'duration': '4h'}]},
                          {'id': 43, 'scenario': 'qa/simulated', 'simulated': True,
                           'decisions': [{'scope': 'Ip', 'value': '192.0.2.10', 'type': 'captcha', 'duration': '1h'}]}]
        text, _ = self.bot.module_decisions()
        self.assertIn('含模拟', text)
        self.assertNotIn('192.0.2.10</code> · 模拟', text)

    def test_execution_decision_details_page_through_all_queried_requirements(self):
        self.decisions = [{'decisions': [{'type': 'ban', 'duration': str(n)+'h'} for n in range(1, 22)]}]
        _, edits = self.callback('more:exp:42')
        self.assertIn('exd:42:1', json.dumps(edits[0]['reply_markup']))
        handled, edits = self.callback('exd:42:4')
        self.assertTrue(handled)
        self.assertIn('21h', edits[0]['text'])
        self.assertIn('5/5', edits[0]['text'])
        self.assertIn('exp:42', json.dumps(edits[0]['reply_markup']))
        for bad in ['exd:0:0', 'exd:42:-1', 'exd:42:9999999']:
            self.assertFalse(self.callback(bad)[0])

    def test_recent_simulated_alert_and_historical_simulated_decision_are_marked(self):
        self.bot.DB_PATH = str(self.base/'db.sqlite')
        with sqlite3.connect(self.bot.DB_PATH) as conn:
            conn.execute('CREATE TABLE alerts(id INTEGER, source_ip TEXT, source_country TEXT, scenario TEXT, created_at TEXT, simulated BOOLEAN)')
            conn.execute("INSERT INTO alerts VALUES (42,'192.0.2.10','CN','qa/test','2026-10-20',1)")
        text, _ = self.bot.module_recent_alerts()
        self.assertIn('模拟', text)
        self.alert['decisions'] = [{'type': 'ban', 'duration': '4h', 'simulated': True}]
        text, _ = self.bot.module_forensics(42)
        self.assertIn('模拟', text)


if __name__ == '__main__':
    unittest.main()

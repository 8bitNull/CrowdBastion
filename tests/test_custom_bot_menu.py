"""Exercise menu navigation with real renderers and isolated data/command boundaries."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MENU_ROWS = [
    ['📊 防护概况', '🚨 最近告警', '🚫 封禁列表'],
    ['🔍 告警详情', '📈 访问分析', '📦 容器状态'],
    ['🤖 机器人状态', '🛠 管理工具', '❓ 使用帮助'],
]


class MenuNavigation(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('bot_menu', ROOT / 'lib/crowdsec_bot.py')
        self.bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bot)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bot.STATE_DIR = str(self.base / 'state')
        self.bot.DB_PATH = str(self.base / 'db.sqlite')
        self.bot.CSCLI_CONFIG = str(self.base / 'config.yaml')
        self.bot.WHITELIST_FILE = str(self.base / 'white.yaml')
        self.bot.NPM_LOG_DIR = str(self.base / 'logs')
        self.bot.BOT_TOKEN = '123:SYNTHETIC'
        self.bot.ADMIN_USER_ID, self.bot.ADMIN_CHAT_ID = 12, -34
        Path(self.bot.NPM_LOG_DIR).mkdir()
        (Path(self.bot.NPM_LOG_DIR) / 'proxy_access.log').write_text(
            '"GET /.env HTTP/1.1" 403 0 "-" "-" [Client 203.0.113.8]\n')
        with sqlite3.connect(self.bot.DB_PATH) as conn:
            conn.execute('CREATE TABLE alerts (id INTEGER, source_ip TEXT, source_country TEXT, '
                         'scenario TEXT, created_at TEXT, simulated BOOLEAN DEFAULT 0)')
            conn.execute("INSERT INTO alerts(id, source_ip, source_country, scenario, created_at) VALUES (42, '203.0.113.8', 'CN', 'qa/env', datetime('now'))")
            conn.execute('CREATE TABLE decisions (until TEXT)')
        self.alert = {'id': 42, 'scenario': 'qa/env', 'source': {'value': '203.0.113.8'},
                      'start_at': '2026-10-20T00:00:00Z', 'events': [], 'decisions': [
                          {'id': 8, 'scope': 'Ip', 'value': '203.0.113.8', 'type': 'ban',
                           'origin': 'cscli', 'duration': '1h'}]}
        self.current_decisions = [self.alert]
        self.sent, self.commands, self.mutations = [], [], []
        for name, replacement in [('tg_request', self.telegram), ('run_cmd', self.command),
                                  ('module_health_status', lambda details=False: '防护概况: 测试采样')]:
            mock = patch.object(self.bot, name, side_effect=replacement)
            mock.start()
            self.addCleanup(mock.stop)

    def telegram(self, endpoint, payload=None):
        self.sent.append((endpoint, payload))
        return {'ok': True, 'result': {'message_id': 90}}

    def command(self, args, **kwargs):
        self.commands.append(args)
        if args[:3] == ['cscli', 'alerts', 'list']:
            return json.dumps([self.alert])
        if args[:3] == ['cscli', 'alerts', 'inspect']:
            return json.dumps([self.alert] if args[3] == '42' else [])
        if args[:3] == ['cscli', 'decisions', 'list']:
            return json.dumps(self.current_decisions)
        if args[:3] == ['cscli', 'decisions', 'delete']:
            self.mutations.append(args)
            return ''
        if args[:2] == ['docker', 'ps']:
            return json.dumps({'ID': 'abc', 'Names': 'web', 'State': 'running', 'Status': 'Up 1h'})
        if args[:2] == ['docker', 'inspect']:
            return json.dumps({'StartedAt': '2026-10-20T00:00:00Z'})
        if args == ['cat', self.bot.WHITELIST_FILE]:
            return Path(self.bot.WHITELIST_FILE).read_text()
        raise AssertionError('Unexpected command: ' + repr(args))

    def message(self, text):
        self.sent.clear()
        self.bot.handle_update({'message': {'from': {'id': 12}, 'chat': {'id': -34}, 'text': text}})
        payloads = [p for method, p in self.sent if method == 'sendMessage']
        self.assertEqual(len(payloads), 1, 'menu entry must produce one card')
        return payloads[0]

    def callback(self, data, user=12, chat=-34):
        self.sent.clear()
        self.bot.handle_update({'callback_query': {'id': 'query', 'from': {'id': user}, 'data': data,
                               'message': {'message_id': 90, 'chat': {'id': chat}}}})

    def edited_card(self):
        edits = [p for method, p in self.sent if method == 'editMessageText']
        self.assertEqual(len(edits), 1, 'navigation must edit the existing card')
        self.assertEqual(edits[0]['message_id'], 90)
        self.assertEqual(self.sent[0][0], 'answerCallbackQuery')
        self.assertFalse(any(method == 'sendMessage' for method, _ in self.sent))
        return edits[0]

    def buttons(self, payload):
        return [button['callback_data'] for row in payload.get('reply_markup', {}).get('inline_keyboard', [])
                for button in row]

    def test_start_displays_the_approved_nine_entries(self):
        payload = self.message('/start')
        rows = [[b['text'] for b in row] for row in payload['reply_markup']['keyboard']]
        self.assertEqual(rows, MENU_ROWS)
        self.assertTrue(payload['reply_markup']['is_persistent'])

    def test_all_nine_entries_route_to_read_only_cards(self):
        cases = [('📊 防护概况', '防护概况'), ('🚨 最近告警', '#42'),
                 ('🚫 封禁列表', '203.0.113.8'), ('🔍 告警详情', '告警详情 · #42'),
                 ('📈 访问分析', '访问分析'), ('📦 容器状态', 'web'),
                 ('🤖 机器人状态', '接收消息'), ('🛠 管理工具', '管理工具'),
                 ('❓ 使用帮助', '/inspect')]
        for label, expected in cases:
            with self.subTest(label=label):
                payload = self.message(label)
                self.assertIn(expected, payload['text'])
                self.assertIn('nav:home', self.buttons(payload))
        self.assertEqual(self.mutations, [])

    def test_forensics_execution_round_trip_keeps_alert_and_navigation(self):
        self.callback('ins:42')
        card = self.edited_card()
        self.assertIn('exp:42', self.buttons(card))
        self.callback('exp:42')
        card = self.edited_card()
        self.assertIn('拦截记录 · #42', card['text'])
        self.assertIn('exp:42', self.buttons(card))
        self.assertIn('ins:42', self.buttons(card))
        self.assertIn('nav:home', self.buttons(card))
        self.callback('ins:42')
        self.assertIn('告警详情 · #42', self.edited_card()['text'])
        self.assertEqual(self.mutations, [])

    def test_old_labels_still_open_the_corresponding_cards(self):
        cases = [('📊 系统大屏', '防护概况'), ('🛡️ 攻击态势', '24'),
                 ('🚨 最新告警', '#42'), ('💀 黑客榜单', '可疑来源'),
                 ('🎯 漏洞靶心', '访问路径'), ('🔍 取证穿透', '告警详情 · #42'),
                 ('🚫 封禁名单', '203.0.113.8'), ('🌐 站点体检', 'web'),
                 ('⚡ 应急管家', '管理工具'), ('📊 防护总览', '防护概况'),
                 ('🚫 封禁决策', '203.0.113.8'), ('🔍 告警取证', '告警详情 · #42'),
                 ('📈 攻击分析', '访问分析'), ('🛠 运维工具', '管理工具')]
        for label, expected in cases:
            with self.subTest(label=label):
                self.assertIn(expected, self.message(label)['text'])

    def test_new_commands_are_registered_and_old_commands_are_retained(self):
        self.bot.register_bot_commands()
        commands = self.sent[-1][1]['commands']
        names = [item['command'] for item in commands]
        expected = {'start', 'status', 'inspect', 'ban', 'unban', 'white', 'top', 'help',
                    'overview', 'alerts', 'decisions', 'analysis', 'containers', 'bot', 'tools'}
        self.assertTrue(expected.issubset(names))
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('接收消息', self.message('/bot@example_bot')['text'])
        self.assertIn('防护概况', self.message('/status')['text'])
        self.assertIn('访问路径', self.message('/top')['text'])

    def test_analysis_subcards_refresh_and_return_without_new_messages(self):
        self.callback('nav:analysis')
        card = self.edited_card()
        self.assertTrue({'nav:posture', 'nav:sources', 'nav:paths'}.issubset(self.buttons(card)))
        for data, expected in [('nav:posture', '24'), ('nav:sources', '203.0.113.8'),
                               ('nav:paths', '/.env')]:
            with self.subTest(data=data):
                self.callback(data)
                card = self.edited_card()
                self.assertIn(expected, card['text'])
                self.assertIn(data, self.buttons(card))
                self.assertIn('nav:analysis', self.buttons(card))
                self.assertIn('nav:home', self.buttons(card))

    def test_return_home_edits_card_into_a_working_nine_button_menu(self):
        self.callback('nav:home')
        card = self.edited_card()
        keyboard = card['reply_markup']['inline_keyboard']
        self.assertEqual([[b['text'] for b in row] for row in keyboard], MENU_ROWS)
        for button in [b for row in keyboard for b in row]:
            self.callback(button['callback_data'])
            self.edited_card()

    def test_decision_and_container_pagination_keep_home_navigation(self):
        for data in ['dec:0', 'site:0']:
            with self.subTest(data=data):
                self.callback(data)
                buttons = self.buttons(self.edited_card())
                self.assertIn(data, buttons)
                self.assertIn('nav:home', buttons)

    def test_alert_to_forensics_to_current_decisions_requires_confirmation(self):
        card = self.message('🚨 最近告警')
        self.assertEqual(self.buttons(card)[0], 'ins:42')
        self.assertFalse(any(b.startswith(('unban:', 'white:')) for b in self.buttons(card)))
        self.callback('ins:42')
        card = self.edited_card()
        self.assertIn('dip:203.0.113.8', self.buttons(card))
        self.assertIn('ins:42', self.buttons(card), 'refresh must retain the selected alert')
        self.assertFalse(any(b.startswith(('unban:', 'white:')) for b in self.buttons(card)))
        self.callback('dip:203.0.113.8')
        card = self.edited_card()
        self.assertIn('处置要求', card['text'])
        self.assertIn('unban:203.0.113.8', self.buttons(card))
        self.assertIn('white:203.0.113.8', self.buttons(card))
        self.callback('unban:203.0.113.8')
        self.assertEqual(self.mutations, [])
        preview = next(p for method, p in self.sent if method == 'sendMessage')
        confirmation = next(b for b in self.buttons(preview) if b.startswith('yes:'))
        self.callback(confirmation)
        self.assertEqual(self.mutations, [['cscli', 'decisions', 'delete', '--ip', '203.0.113.8']])
        self.callback(confirmation)
        self.assertEqual(len(self.mutations), 1)

    def test_historical_alert_does_not_offer_actions_without_current_decisions(self):
        self.current_decisions = []
        self.callback('dip:203.0.113.8')
        card = self.edited_card()
        self.assertIn('本次未查到', card['text'])
        self.assertIn('203.0.113.8', card['text'])
        self.assertFalse(any(b.startswith(('unban:', 'white:')) for b in self.buttons(card)))
        self.assertIn('dip:203.0.113.8', self.buttons(card))

    def test_one_ip_with_multiple_decisions_has_one_set_of_actions(self):
        duplicate = json.loads(json.dumps(self.alert))
        duplicate['decisions'][0]['id'] = 9
        duplicate['decisions'][0]['duration'] = '2h'
        self.current_decisions.append(duplicate)
        self.callback('dip:203.0.113.8')
        card = self.edited_card()
        self.assertIn('剩余：1 小时', card['text'])
        self.assertIn('剩余：2 小时', card['text'])
        self.assertEqual(self.buttons(card).count('unban:203.0.113.8'), 1)
        self.assertEqual(self.buttons(card).count('white:203.0.113.8'), 1)

    def test_ipv6_current_decisions_accept_the_canonical_address(self):
        self.alert['decisions'][0]['value'] = '2001:0db8:0:0:0:0:0:8'
        self.callback('dip:2001:db8::8')
        card = self.edited_card()
        self.assertIn('处置要求', card['text'])
        self.assertIn('unban:2001:db8::8', self.buttons(card))
        for row in card['reply_markup']['inline_keyboard']:
            for button in row:
                self.assertLessEqual(len(button['callback_data'].encode()), 64)

    def test_range_decision_details_do_not_offer_ip_mutations(self):
        self.alert['decisions'][0].update(scope='Range', value='203.0.113.0/24')
        card = self.message('/decisions')
        detail = next(b for b in self.buttons(card) if b.startswith('dd:'))
        self.callback(detail)
        card = self.edited_card()
        self.assertIn('203.0.113.0/24', card['text'])
        self.assertFalse(any(b.startswith(('unban:', 'white:')) for b in self.buttons(card)))

    def test_query_failure_still_allows_refresh_and_return(self):
        with patch.object(self.bot, 'run_cmd', side_effect=RuntimeError('PRIVATE')):
            self.callback('site:0')
        card = self.edited_card()
        self.assertIn('暂时无法查询容器', card['text'])
        self.assertNotIn('PRIVATE', card['text'])
        self.assertIn('site:0', self.buttons(card))
        self.assertIn('nav:home', self.buttons(card))

    def test_old_whitelist_button_returns_to_tools_without_changing_file(self):
        path = Path(self.bot.WHITELIST_FILE)
        path.write_text('whitelist:\n  ip: [203.0.113.8]\n')
        before = path.read_bytes()
        self.callback('em:view_white')
        card = self.edited_card()
        self.assertIn('203.0.113.8', card['text'])
        self.assertIn('nav:tools', self.buttons(card))
        self.assertEqual(path.read_bytes(), before)

    def test_unknown_or_unauthorized_navigation_never_queries_or_edits(self):
        for data, user, chat in [('nav:__dict__', 12, -34), ('nav:tools;reboot', 12, -34),
                                 ('dip:203.0.113.8;reboot', 12, -34), ('ins:0', 12, -34),
                                 ('nav:overview', 99, -34), ('nav:tools', 12, -99)]:
            with self.subTest(data=data, user=user, chat=chat):
                self.commands.clear()
                self.callback(data, user=user, chat=chat)
                self.assertEqual(self.commands, [])
                self.assertEqual(self.sent, [])


if __name__ == '__main__':
    unittest.main()

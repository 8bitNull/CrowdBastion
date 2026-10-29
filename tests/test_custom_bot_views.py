"""Read-only query cards; commands and Telegram are isolated."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class QueryCards(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('bot_views', ROOT/'lib/crowdsec_bot.py')
        self.bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bot)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bot.CSCLI_CONFIG = str(self.base/'config.yaml')

    def alerts(self, count=7):
        return [{'id': n+1, 'scenario': 'qa/<scan>', 'simulated': False,
                 'decisions': [{'id': n+11, 'scope': 'Ip', 'value': f'203.0.113.{n+1}',
                                'type': 'ban', 'origin': 'cscli', 'duration': '59m12s'}]}
                for n in range(count)]

    def decisions(self, alerts, **kwargs):
        with patch.object(self.bot, 'run_cmd', return_value=json.dumps(alerts)):
            return self.bot.module_decisions(**kwargs)

    def test_group_retains_duplicate_rules_and_remaining_times(self):
        alerts = self.alerts(1)
        duplicate = self.alerts(1)[0]
        duplicate['id'] = 9
        duplicate['scenario'] = 'qa/second'
        duplicate['decisions'][0].update(id=99, duration='2h')
        text, kb = self.decisions(alerts+[duplicate])
        self.assertIn('1 个目标', text)
        self.assertIn('2 条处置要求', text)
        self.assertIn('其中一条：', text)
        target = kb['inline_keyboard'][0][0]['callback_data'].split(':')[1]
        detail, _ = self.decisions(alerts+[duplicate], target=target, details=True)
        for expected in ('59m12s', '2h', 'qa/second', 'qa/&lt;scan&gt;', '#9'):
            self.assertIn(expected, detail)
        self.assertIn('实际执行情况请查看拦截记录', detail)

    def test_pagination_has_five_cards_and_last_page_clamps(self):
        text, kb = self.decisions(self.alerts())
        self.assertIn('1/2', text)
        self.assertNotIn('203.0.113.6', text)
        self.assertTrue(any(b['callback_data'] == 'dec:1' for row in kb['inline_keyboard'] for b in row))
        text, _ = self.decisions(self.alerts(), page=999)
        self.assertIn('2/2', text)
        self.assertIn('203.0.113.7', text)
        self.assertNotIn('203.0.113.1</code>', text)

    def test_range_and_simulation_do_not_offer_ip_unban(self):
        alerts = self.alerts(1)
        alerts[0]['simulated'] = True
        alerts[0]['decisions'][0].update(scope='Range', value='203.0.113.0/24')
        text, kb = self.decisions(alerts)
        self.assertIn('203.0.113.0/24', text)
        self.assertIn('模拟', text)
        self.assertNotIn('unban:', json.dumps(kb))

    def test_empty_null_and_query_error_are_distinct(self):
        self.assertIn('未找到', self.decisions(None)[0])
        self.assertIn('未找到', self.decisions([])[0])
        with patch.object(self.bot, 'run_cmd', side_effect=RuntimeError('secret')):
            text, _ = self.bot.module_decisions()
        self.assertIn('暂时无法查询处置要求', text)
        self.assertNotIn('未找到有效处置要求', text)
        self.assertNotIn('secret', text)
        with patch.object(self.bot, 'run_cmd', return_value='{"unexpected": []}'):
            text, _ = self.bot.module_decisions()
        self.assertIn('暂时无法查询处置要求', text)

    def test_long_fields_fit_telegram_html_budget(self):
        alerts = self.alerts(5)
        for alert in alerts:
            alert['scenario'] = '<&>'*1000
            for field in ('origin', 'scope', 'value', 'type', 'duration'):
                alert['decisions'][0][field] = '<&>'+str(alert['id'])+'<&>'*1000
        text, kb = self.decisions(alerts)
        self.assertLess(len(text), 4096)
        self.assertTrue(all(len(b['callback_data'].encode()) <= 64 for r in kb['inline_keyboard'] for b in r))

    def docker(self, state='running', health=None):
        summary = json.dumps({'ID': 'a123', 'Names': 'web<&>', 'State': state, 'Status': 'Up 2 hours'})
        detail = {'Status': state, 'StartedAt': '2026-10-13T00:00:00Z'}
        if health:
            detail['Health'] = {'Status': health}
        return summary, json.dumps(detail)

    def test_site_card_distinguishes_container_health_and_http(self):
        with patch.object(self.bot, 'run_cmd', side_effect=self.docker(health='unhealthy')):
            text, _ = self.bot.module_sites()
        for expected in ('web&lt;&amp;&gt;', '运行：运行中', '健康检查：异常', '未检查网站访问和实际拦截', '无本工具安装记录'):
            self.assertIn(expected, text)
        self.assertNotIn('已拦截', text)

    def test_stopped_no_health_and_state_query_failure(self):
        with patch.object(self.bot, 'run_cmd', side_effect=self.docker(state='exited')):
            text, _ = self.bot.module_sites()
        self.assertIn('运行：已停止', text)
        self.assertIn('健康检查：未设置', text)
        with patch.object(self.bot, 'run_cmd', side_effect=[self.docker()[0], RuntimeError('no inspect')]):
            text, _ = self.bot.module_sites()
        self.assertIn('健康检查：暂时无法查询', text)
        self.assertNotIn('no inspect', text)

    def test_no_docker_empty_and_invalid_output(self):
        for output in ('', 'not json'):
            with patch.object(self.bot, 'run_cmd', return_value=output):
                text, _ = self.bot.module_sites()
            self.assertIn('未找到 Docker 容器' if not output else '暂时无法查询容器', text)
        with patch.object(self.bot, 'run_cmd', side_effect=RuntimeError('missing')):
            text, _ = self.bot.module_sites()
        self.assertIn('Docker', text)
        self.assertIn('暂时无法查询容器', text)

    def test_install_record_hash_is_not_execution_proof(self):
        import hashlib
        target = self.base/'web.conf'
        target.write_text('hook')
        records = {'web<&>': {'status': 'installed', 'host_target': str(target),
                             'installed_sha': hashlib.sha256(target.read_bytes()).hexdigest()}}
        (self.base/'crowdsec-1key-web-installs.json').write_text(json.dumps(records))
        with patch.object(self.bot, 'run_cmd', side_effect=self.docker()):
            text, _ = self.bot.module_sites()
        self.assertIn('主配置：与安装记录一致', text)
        self.assertIn('未检查网站访问和实际拦截', text)
        target.write_text('changed')
        with patch.object(self.bot, 'run_cmd', side_effect=self.docker()):
            text, _ = self.bot.module_sites()
        self.assertIn('与安装记录不同', text)

    def test_invalid_view_callbacks_do_not_execute_commands(self):
        with patch.object(self.bot, 'run_cmd') as run:
            for data in ('dec:-1', 'site:;reboot', 'dd:bad:0', 'dec:9999999',
                         'more:site:;reboot', 'more:dd:bad:0', 'more:more:dec:0'):
                self.assertFalse(self.bot.handle_view_callback({
                    'data': data, 'from': {'id': self.bot.ADMIN_USER_ID},
                    'message': {'message_id': 90, 'chat': {'id': self.bot.ADMIN_CHAT_ID}}}))
        self.assertFalse(run.called)

    def test_detail_pagination_keeps_all_decisions(self):
        alerts = self.alerts()
        for alert in alerts:
            alert['decisions'][0]['value'] = '203.0.113.1'
        _, kb = self.decisions(alerts)
        key = kb['inline_keyboard'][0][0]['callback_data'].split(':')[1]
        first, kb = self.decisions(alerts, target=key)
        last, _ = self.decisions(alerts, target=key, page=1)
        self.assertIn('1/2', first)
        self.assertIn('2/2', last)
        self.assertIn('7 条要求', first)
        self.assertNotIn('告警 #6 ', first)
        self.assertIn('告警 #6 ', last)
        self.assertTrue(any(b['callback_data'] == 'dd:'+key+':1' for row in kb['inline_keyboard'] for b in row))

    def test_site_pagination_inspects_only_selected_containers(self):
        containers = [{'ID': str(n), 'Names': f'web{n}', 'State': 'running'} for n in range(1, 8)]
        inspected = []
        def command(args):
            if args[1] == 'ps':
                return '\n'.join(json.dumps(c) for c in containers)
            inspected.append(args[-1])
            return json.dumps({'StartedAt': '2026-10-13'})
        with patch.object(self.bot, 'run_cmd', side_effect=command):
            first, _ = self.bot.module_sites()
            self.assertEqual(inspected, ['1', '2', '3', '4', '5'])
            inspected.clear()
            last, _ = self.bot.module_sites(page=999)
        self.assertEqual(inspected, ['6', '7'])
        self.assertIn('1/2', first)
        self.assertIn('2/2', last)
        self.assertNotIn('<b>web6</b>', first)
        self.assertIn('<b>web6</b>', last)

    def callback_card(self, data):
        cq = {'id': 'q', 'data': data, 'from': {'id': self.bot.ADMIN_USER_ID},
              'message': {'message_id': 90, 'chat': {'id': self.bot.ADMIN_CHAT_ID}}}
        with patch.object(self.bot, 'tg_request', return_value={'ok': True}) as tg:
            self.assertTrue(self.bot.handle_view_callback(cq))
        self.assertEqual(tg.call_args_list[0].args[0], 'answerCallbackQuery')
        payload = next(c.args[1] for c in tg.call_args_list if c.args[0] == 'editMessageText')
        self.assertEqual(payload['message_id'], 90)
        buttons = [b['callback_data'] for row in payload['reply_markup']['inline_keyboard'] for b in row]
        return payload['text'], buttons

    def test_more_decision_list_keeps_selected_page_and_returns_to_same_page(self):
        with patch.object(self.bot, 'run_cmd', return_value=json.dumps(self.alerts())) as run:
            plain, plain_buttons = self.callback_card('dec:1')
            detail, detail_buttons = self.callback_card('more:dec:1')
            returned, _ = self.callback_card('dec:1')
        self.assertTrue(all(c.args[0][:3] == ['cscli', 'decisions', 'list'] for c in run.call_args_list))
        self.assertIn('more:dec:1', plain_buttons)
        self.assertIn('2/2', detail)
        self.assertIn('203.0.113.6', detail)
        self.assertNotIn('203.0.113.1</code>', detail)
        self.assertIn('来源：cscli', detail)
        self.assertIn('more:dec:0', detail_buttons)
        self.assertIn('more:dec:1', detail_buttons)
        self.assertIn('dec:1', detail_buttons)
        self.assertEqual(plain, returned)

    def test_more_decision_requirements_keep_target_and_requirement_page(self):
        alerts = self.alerts()
        for alert in alerts:
            alert['decisions'][0]['value'] = '203.0.113.1'
        _, kb = self.decisions(alerts)
        target = kb['inline_keyboard'][0][0]['callback_data'].split(':')[1]
        base = 'dd:'+target+':1'
        with patch.object(self.bot, 'run_cmd', return_value=json.dumps(alerts)) as run:
            plain, plain_buttons = self.callback_card(base)
            detail, detail_buttons = self.callback_card('more:'+base)
        self.assertTrue(all(c.args[0][:3] == ['cscli', 'decisions', 'list'] for c in run.call_args_list))
        self.assertIn('more:'+base, plain_buttons)
        self.assertNotIn('原始时长', plain)
        self.assertIn('原始时长：59m12s', detail)
        self.assertIn('2/2', detail)
        self.assertIn('告警 #6 ', detail)
        self.assertNotIn('告警 #1 ', detail)
        self.assertIn('more:dd:'+target+':0', detail_buttons)
        self.assertIn('more:'+base, detail_buttons)
        self.assertIn(base, detail_buttons)

    def test_more_container_card_keeps_page_and_selected_container_inspections(self):
        containers = [{'ID': str(n), 'Names': f'web{n}', 'State': 'running', 'Status': 'Up 2 hours'}
                      for n in range(1, 8)]
        inspected = []
        def command(args):
            if args[1] == 'ps':
                return '\n'.join(json.dumps(c) for c in containers)
            self.assertEqual(args[:2], ['docker', 'inspect'])
            inspected.append(args[-1])
            return json.dumps({'StartedAt': '2026-10-13T00:00:00Z'})
        with patch.object(self.bot, 'run_cmd', side_effect=command):
            detail, buttons = self.callback_card('more:site:1')
            self.assertEqual(inspected, ['6', '7'])
            inspected.clear()
            plain, plain_buttons = self.callback_card('site:1')
        self.assertEqual(inspected, ['6', '7'])
        self.assertIn('2/2', detail)
        self.assertIn('Docker 摘要：Up 2 hours', detail)
        self.assertIn('原始状态：running', detail)
        self.assertIn('UTC', detail)
        self.assertNotIn('<b>web1</b>', detail)
        self.assertNotIn('Docker 摘要', plain)
        self.assertIn('more:site:0', buttons)
        self.assertIn('more:site:1', buttons)
        self.assertIn('site:1', buttons)
        self.assertIn('more:site:1', plain_buttons)

    def test_callback_acknowledged_before_slow_docker_query(self):
        cq = {'id': 'q', 'data': 'site:0', 'from': {'id': self.bot.ADMIN_USER_ID},
              'message': {'message_id': 90, 'chat': {'id': self.bot.ADMIN_CHAT_ID}}}
        calls = []
        def command(args):
            calls.append('command')
            return ''
        def telegram(endpoint, data):
            calls.append(endpoint)
            return {'ok': True}
        with patch.object(self.bot, 'run_cmd', side_effect=command), patch.object(self.bot, 'tg_request', side_effect=telegram):
            self.bot.handle_view_callback(cq)
        self.assertEqual(calls[0], 'answerCallbackQuery')

    def test_view_callback_edits_original_authorized_message(self):
        cq = {'id': 'q', 'data': 'dec:1', 'from': {'id': self.bot.ADMIN_USER_ID},
              'message': {'message_id': 90, 'chat': {'id': self.bot.ADMIN_CHAT_ID}}}
        with patch.object(self.bot, 'run_cmd', return_value=json.dumps(self.alerts())), patch.object(self.bot, 'tg_request', return_value={'ok': True}) as tg:
            self.assertTrue(self.bot.handle_view_callback(cq))
        payload = next(c.args[1] for c in tg.call_args_list if c.args[0] == 'editMessageText')
        self.assertEqual(payload['message_id'], 90)
        self.assertIn('2/2', payload['text'])
        cq['from']['id'] += 1
        with patch.object(self.bot, 'run_cmd') as run:
            self.assertFalse(self.bot.handle_view_callback(cq))
        self.assertFalse(run.called)


if __name__ == '__main__':
    unittest.main()

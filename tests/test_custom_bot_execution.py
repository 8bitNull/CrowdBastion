"""TG evidence cards read real logs; external cscli and Telegram stay isolated."""
import importlib.util
from datetime import datetime, timezone
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
        self.bot.CSCLI_CONFIG = str(self.base/'config.yaml')
        self.alert = dict(id=42, source={'value': '192.0.2.10'}, scenario='qa/<scan>',
                          start_at='2026-10-19T00:00:00Z', simulated=False, decisions=[])

    def command(self, args):
        if 'inspect' in args:
            return json.dumps([self.alert])
        return '[]'

    def card(self, details=False):
        with patch.object(self.bot, 'run_cmd', side_effect=self.command):
            return self.bot.module_execution(42, details=details)

    def test_forensic_button_and_same_source_not_exact_alert_claim(self):
        with patch.object(self.bot, 'run_cmd', side_effect=self.command):
            _, kb = self.bot.module_forensics(42)
        self.assertIn('exp:42', [b['callback_data'] for row in kb['inline_keyboard'] for b in row])
        (self.base/'proxy-host-1_error.log').write_text(receipt(time=time.time()-1, cause='appsec_failure'))
        text, kb = self.card()
        self.assertIn('网站拒绝：已记录 1 次（抽样）', text)
        self.assertIn('范围：该来源', text)
        self.assertNotIn('本告警已拦截', text)
        self.assertNotIn('HTTP 403', text)
        self.assertNotIn('请求 ID', text)
        self.assertIn('exp:42', [b['callback_data'] for row in kb['inline_keyboard'] for b in row])
        self.assertIn('more:exp:42', [b['callback_data'] for row in kb['inline_keyboard'] for b in row])
        text, _ = self.card(details=True)
        self.assertIn('网站检查故障，按策略拒绝', text)
        self.assertIn('不能证明原触发请求', text)
        self.assertIn('HTTP 403', text)
        self.assertIn('请求 ID', text)

    def test_unavailable_and_zero_observations_have_distinct_messages(self):
        text, _ = self.card(); self.assertIn('网站拒绝：暂时无法查询', text)
        self.assertNotIn('网站拒绝：本次未查到记录', text)
        (self.base/'proxy-host-1_error.log').write_text('business returned 403\n')
        text, _ = self.card(); self.assertIn('网站拒绝：本次未查到记录', text)
        self.assertNotIn('日志截尾', text)
        self.assertNotIn('链路未接入', text)
        self.assertIn('防火墙名单：暂时无法查询', text)
        self.assertIn('防火墙实际拦截：尚未验证', text)
        self.assertNotIn('拦截失败', text)
        detail, _ = self.card(details=True)
        self.assertIn('日志截尾：0 个 · 读取失败：0', detail)

    def test_firewall_local_override_is_loaded_without_claiming_packet_drops(self):
        folder = self.base/'bouncers'; folder.mkdir()
        config = folder/'crowdsec-firewall-bouncer.yaml'
        config.write_text('mode: nftables\nnftables:\n  ipv4:\n    enabled: true\n')
        Path(str(config)+'.local').write_text('mode: iptables\n')
        text, _ = self.card()
        self.assertIn('防火墙名单：当前方式暂不支持查询', text)
        self.assertIn('防火墙实际拦截：尚未验证', text)
        detail, _ = self.card(details=True)
        self.assertIn('集合成员状态不能证明实际丢包', detail)

    def test_real_nft_reply_renders_membership_as_sync_evidence_only(self):
        import subprocess
        folder = self.base/'bouncers'; folder.mkdir()
        (folder/'crowdsec-firewall-bouncer.yaml').write_text('mode: nftables\n')
        metadata = json.dumps({'nftables': [{'set': {'family': 'ip', 'table': 'crowdsec',
            'name': 'crowdsec-blacklists-cscli', 'type': 'ipv4_addr'}}]})
        replies = [subprocess.CompletedProcess([], 0, metadata, ''),
                   subprocess.CompletedProcess([], 0, 'elements = { 192.0.2.10 timeout 4h }', '')]
        with patch('subprocess.run', side_effect=replies):
            text, _ = self.card()
        self.assertIn('防火墙名单：已加入', text)
        self.assertIn('防火墙实际拦截：尚未验证', text)
        self.assertNotIn('已成功拦截', text)

    def test_simulated_alert_cannot_become_execution_claim(self):
        self.alert['simulated'] = True
        (self.base/'proxy-host-1_error.log').write_text(receipt(time=time.time()-1))
        text, _ = self.card()
        self.assertIn('模拟告警', text)
        self.assertIn('以下记录按来源单独查询', text)
        self.assertNotIn('本告警已拦截', text)

    def test_plain_and_detail_cards_share_bounded_utc_query_scope(self):
        self.alert['start_at'] = '2026-10-17T01:02:03Z'
        (self.base/'proxy-host-1_error.log').write_text('business returned 403\n')
        now = datetime(2026, 10, 20, 12, 34, 56, tzinfo=timezone.utc).timestamp()
        with patch.object(self.bot.time, 'time', return_value=now):
            plain, _ = self.card()
            detail, _ = self.card(details=True)
        for text in (plain, detail):
            self.assertIn('10-19 12:34', text)
            self.assertIn('UTC', text)
            self.assertNotIn('10-17 01:02', text)
        self.assertNotIn('10-20 12:34:56', plain)
        self.assertIn('10-20 12:34:56 UTC', detail)

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

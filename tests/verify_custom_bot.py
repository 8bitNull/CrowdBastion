#!/usr/bin/env python3
"""Official LAPI/CLI JSON integration for the user bot; never calls Telegram.

Usage: python3 tests/verify_custom_bot.py /path/to/crowdsec-v1.8.1
Temporary engine/DB and loopback only; Hub collection download required.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import urllib.request

from verify_web import real_engine

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
import crowdsec_bot as bot
import crowdsec_config as config


def verify(release):
    release = Path(release).resolve()
    os.environ['PATH'] = str(release/'cmd/crowdsec-cli')+os.pathsep+str(release/'cmd/crowdsec')+os.pathsep+os.environ['PATH']
    with tempfile.TemporaryDirectory(prefix='custom-bot-engine-') as temporary:
        base = Path(temporary)/'engine'
        with real_engine(release, base) as engine:
            bot.CSCLI_CONFIG = str(base/'etc/config.yaml')
            bot.DB_PATH = str(base/'data/crowdsec.db')
            credentials = config.read(base/'etc/local_api_credentials.yaml')
            login = urllib.request.Request(engine['api_url']+'/v1/watchers/login',
                data=json.dumps({'machine_id': credentials['login'], 'password': credentials['password']}).encode(),
                headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(login, timeout=10) as response:
                token = json.load(response)['token']
            timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            alert = {'capacity': 1, 'events_count': 1, 'leakspeed': '0', 'message': 'custom bot QA',
                     'scenario': 'qa/custom-bot-http', 'scenario_hash': 'qa', 'scenario_version': '1',
                     'simulated': False, 'remediation': False,
                     'source': {'scope': 'Ip', 'value': '203.0.113.20', 'ip': '203.0.113.20'},
                     'start_at': timestamp, 'stop_at': timestamp,
                     'events': [{'timestamp': timestamp, 'meta': [
                         {'key': 'http_path', 'value': '/.env?qa=custom-bot'},
                         {'key': 'http_user_agent', 'value': 'Custom-Bot-Real-JSON <probe>'},
                         {'key': 'http_verb', 'value': 'GET'}]}]}
            request = urllib.request.Request(engine['api_url']+'/v1/alerts', data=json.dumps([alert]).encode(),
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer '+token})
            with urllib.request.urlopen(request, timeout=10) as response:
                assert response.status == 201
            alerts = json.loads(engine['cli']('alerts', 'list', '-o', 'json'))
            aid = next(a['id'] for a in alerts if a['scenario'] == alert['scenario'])
            text, keyboard = bot.module_forensics(aid, details=True)
            assert '/.env?qa=custom-bot' in text and 'Custom-Bot-Real-JSON &lt;probe&gt;' in text, text
            assert '203.0.113.20' in text and keyboard, (text, keyboard)
            assert 'DROP' not in text and '模拟告警' not in text, text
            latest, _ = bot.module_forensics()
            assert '/.env?qa=custom-bot' in latest, latest
            print('Official 1.8.1 alerts inspect --details -o json -> user bot path/UA/source/buttons: PASS.', flush=True)
            print('Latest-alert query and false simulation/no-decision semantics: PASS.', flush=True)
            recent, _ = bot.module_recent_alerts()
            assert '#'+str(aid) in recent, recent
            assert '查询异常' not in bot.module_attack_posture()
            print('Official SQLite schema -> retained recent-alerts/posture menus: PASS.', flush=True)
            engine['cli']('decisions', 'add', '--ip', '203.0.113.29', '--duration', '1h', '--reason', 'qa/bot-card')
            engine['cli']('decisions', 'add', '--range', '198.51.100.0/24', '--duration', '2h', '--reason', 'qa/bot-range')
            card, buttons = bot.module_decisions(details=True)
            assert '203.0.113.29' in card and '198.51.100.0/24' in card, card
            assert 'qa/bot-card' in card and '查询失败' not in card, card
            groups = bot.decision_groups()
            group = next(g for g in groups if g['value'] == '203.0.113.29')
            detail, _ = bot.module_decisions(target=group['key'])
            assert 'qa/bot-card' in detail and '剩余：' in detail and '告警 #' in detail, detail
            range_group = next(g for g in groups if g['value'] == '198.51.100.0/24')
            assert all(not b['callback_data'].startswith('unban:') for b in bot.decision_buttons(range_group, range_group['decisions']))
            print('Official decision-list alert array -> IP/Range cards and decision details: PASS.', flush=True)
            bot.WHITELIST_FILE = str(base/'etc/parsers/s02-enrich/qa-custom-bot.yaml')
            original = bot.run_cmd
            calls = []
            def only_reload_stub(args, **kwargs):
                if args[0] == 'systemctl':
                    calls.append(args)
                    return ''
                return original(args, **kwargs)
            bot.run_cmd = only_reload_stub
            try:
                result = bot.action_whitelist('203.0.113.21')
                assert '已更新日志白名单' in result, result
                assert calls == [['systemctl', 'reload', 'crowdsec']], calls
                print('Generated whitelist accepted by official crowdsec -t; reload simulated, decision delete real: PASS.', flush=True)
            finally:
                bot.run_cmd = original


if __name__ == '__main__':
    verify(sys.argv[1])

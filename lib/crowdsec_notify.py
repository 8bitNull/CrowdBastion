#!/usr/bin/env python3
"""Persistent notification policy. Receiving an alert never changes a decision."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import threading
import time
import unicodedata

from crowdsec_bot_api import TelegramClient, _directory_fd
from crowdsec_bot_health import HealthCollector
from crowdsec_notify_client import read_object, worker_state


CONFIG_NAME = 'crowdbastion-notify.json'
DEFAULT_POLICY = {
    'digest_seconds': 3600, 'cooldown_seconds': 1800,
    'attention_interval_seconds': 60, 'fault_seconds': 60,
    'recovery_seconds': 120, 'health_interval_seconds': 20,
    'surge_window_seconds': 300, 'surge_count': 100,
    'surge_minutes': 3, 'retention_days': 7,
    'routine_scenarios': [
        'crowdsecurity/http-probing', 'crowdsecurity/http-crawl-non_statics',
        'crowdsecurity/http-bad-user-agent', 'crowdsecurity/http-sensitive-files',
        'crowdsecurity/http-404-scan', 'crowdsecurity/ssh-bf',
        'crowdsecurity/ssh-slow-bf', 'crowdsec-1key/v2bx-failure-observation',
    ],
    # Only explicitly trusted scenario names may declare a critical incident.
    'critical_scenarios': [],
}
LABELS = {'core': 'CrowdSec 服务', 'api': '本地 API', 'bouncer': '防火墙 Bouncer'}
WEBHOOK_FORMAT = ('{{- $alerts := list -}}{{- range . -}}'
                  '{{- $a := . | toJson | fromJson -}}'
                  '{{- $alerts = append $alerts (pick $a "id" "scenario" "simulated" "source" "start_at") -}}'
                  '{{- end -}}{{- $alerts | toJson -}}')


def clean(value, limit=120):
    return ''.join(c for c in str(value) if not unicodedata.category(c).startswith('C'))[:limit]


def load_config(path):
    return validate_config(read_object(path))


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('通知配置必须为对象')
    config = dict(config)
    if type(config.get('version')) is not int or config['version'] != 1 or type(config.get('enabled')) is not bool:
        raise ValueError('通知配置版本无效')
    if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', config.get('bot_token', '')):
        raise ValueError('Token 无效')
    if not re.fullmatch(r'-?[1-9]\d*', str(config.get('chat_id', ''))):
        raise ValueError('Chat ID 无效')
    if not re.fullmatch(r'[a-f0-9]{64}', config.get('secret', '')):
        raise ValueError('本地认证密钥无效')
    if type(config.get('port')) is not int or not 1024 <= config['port'] <= 65535:
        raise ValueError('监听端口无效')
    for key in ('state_dir', 'crowdsec_config', 'bot_config'):
        if not isinstance(config.get(key), str) or not Path(config[key]).is_absolute():
            raise ValueError('通知路径无效')
    if not isinstance(config.get('policy', {}), dict):
        raise ValueError('通知策略必须为对象')
    policy = {**DEFAULT_POLICY, **config.get('policy', {})}
    if set(policy) != set(DEFAULT_POLICY):
        raise ValueError('未知通知策略字段')
    for key, default in DEFAULT_POLICY.items():
        value = policy[key]
        if isinstance(default, list):
            if not isinstance(value, list) or any(not isinstance(v, str) or not 1 <= len(v) <= 200 for v in value):
                raise ValueError('规则名称无效')
        elif type(value) is not int or not 1 <= value <= 604800:
            raise ValueError('策略时间或计数无效')
    if policy['retention_days'] > 90 or policy['surge_minutes'] * 60 > policy['surge_window_seconds']:
        raise ValueError('策略窗口无效')
    config['policy'] = policy
    if not isinstance(config.get('node'), str) or not config['node']:
        raise ValueError('节点名称无效')
    services = config.get('scenario_services', {})
    if not isinstance(services, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                            or not 1 <= len(k) <= 200 or not 1 <= len(v) <= 80
                                            for k, v in services.items()):
        raise ValueError('规则与服务映射无效')
    # Reuse the transport's strict HTTPS validation; construction does not send.
    if not isinstance(config.get('api_endpoint'), str):
        raise ValueError('API 端点无效')
    TelegramClient(config['api_endpoint'].rstrip('/')+'/bot'+config['bot_token'],
                   str(Path(config['state_dir'])/'transport'), config['bot_token'])
    return config


class Store:
    def __init__(self, config, now=None):
        self.config = config
        self.policy = {**DEFAULT_POLICY, **config.get('policy', {})}
        self.lock = threading.RLock()
        destination = hashlib.sha256(json.dumps([config['bot_token'], str(config['chat_id'])]).encode()).hexdigest()[:24]
        database = 'queue-'+destination+'.sqlite3'
        self.database_path = Path(config['state_dir'])/database
        directory = _directory_fd(config['state_dir'], create=True)
        try:
            for name in (database, database+'-wal', database+'-shm'):
                path = Path(config['state_dir'])/name
                if path.is_symlink() or (path.exists() and not path.is_file()):
                    raise ValueError('队列文件类型无效')
            fd = os.open(database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            os.fchmod(fd, 0o600)
            os.close(fd)
        finally:
            os.close(directory)
        self.db = sqlite3.connect(str(self.database_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, kind TEXT NOT NULL,
                title TEXT NOT NULL, level INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'open',
                first REAL NOT NULL, last REAL NOT NULL, count INTEGER NOT NULL DEFAULT 0,
                reported INTEGER NOT NULL DEFAULT 0, notified INTEGER NOT NULL DEFAULT 0,
                ack INTEGER NOT NULL DEFAULT 0, next_notice REAL NOT NULL DEFAULT 0,
                reminder INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 1,
                alert_id INTEGER, detail TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS incident_key ON incidents(fingerprint, state);
            CREATE TABLE IF NOT EXISTS events (
                fingerprint TEXT PRIMARY KEY, incident TEXT NOT NULL, at REAL NOT NULL, source TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS event_window ON events(incident, at);
            CREATE TABLE IF NOT EXISTS rates (
                incident TEXT NOT NULL, second INTEGER NOT NULL, count INTEGER NOT NULL,
                PRIMARY KEY (incident, second));
            CREATE TABLE IF NOT EXISTS observations (
                name TEXT PRIMARY KEY, state TEXT NOT NULL, since REAL NOT NULL, checked REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox (
                slot TEXT PRIMARY KEY, priority INTEGER NOT NULL, payload TEXT NOT NULL,
                snapshot TEXT NOT NULL, due REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
        ''')
        with self.transaction():
            self.db.execute('INSERT OR IGNORE INTO meta VALUES (?, ?)', ('digest', time.time() if now is None else now))

    @contextmanager
    def transaction(self):
        with self.lock, self.db:
            yield

    def close(self):
        self.db.close()

    def _get(self, key, default=0):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return row[0] if row else default

    def _set(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?, ?)', (key, value))

    def _incident(self, fingerprint, kind, title, level, now, detail='', alert_id=None):
        row = self.db.execute("SELECT * FROM incidents WHERE fingerprint=? AND state='open'", (fingerprint,)).fetchone()
        if (row and kind == 'alert' and now-row['last'] > self.policy['cooldown_seconds']
                and (row['level'] < 2 or row['notified'])):
            self.db.execute("UPDATE incidents SET state='closed' WHERE id=?", (row['id'],))
            row = None
        if row is None:
            if kind == 'health':
                # A later confirmed problem supersedes an undelivered recovery/scope change.
                self.db.execute('''DELETE FROM outbox WHERE slot IN
                    (SELECT 'recovery:'||id FROM incidents WHERE fingerprint=?)''', (fingerprint,))
            identifier = secrets.token_hex(12)
            self.db.execute('''INSERT INTO incidents
                (id,fingerprint,kind,title,level,first,last,detail,alert_id) VALUES (?,?,?,?,?,?,?,?,?)''',
                (identifier, fingerprint, kind, clean(title), level, now, now, detail, alert_id))
        else:
            identifier = row['id']
            if level > row['level']:
                self.db.execute('''UPDATE incidents SET level=?, ack=0, notified=0,
                    next_notice=0, reminder=0, generation=generation+1 WHERE id=?''', (level, identifier))
                self.db.execute('DELETE FROM outbox WHERE slot=?', ('incident:'+identifier,))
            self.db.execute('UPDATE incidents SET last=?,detail=?,alert_id=COALESCE(?,alert_id) WHERE id=?',
                            (now, detail, alert_id, identifier))
        return identifier

    @staticmethod
    def validate_alerts(alerts):
        if not isinstance(alerts, list) or not 1 <= len(alerts) <= 1000:
            raise ValueError('告警批次格式无效')
        for alert in alerts:
            if (not isinstance(alert, dict) or not isinstance(alert.get('scenario'), str)
                    or not 1 <= len(alert['scenario']) <= 200
                    or not isinstance(alert.get('source') or {}, dict)
                    or ('simulated' in alert and type(alert['simulated']) is not bool)):
                raise ValueError('告警格式无效')

    def ingest(self, alerts, now):
        self.validate_alerts(alerts)
        accepted = 0
        with self.transaction():
            for alert in alerts:
                scenario = alert['scenario']
                # IDs may be reused after a CrowdSec database replacement.
                identity = [alert.get('id'), alert.get('start_at'), scenario, alert.get('source')]
                if not alert.get('id'):
                    identity = alert
                fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
                if self.db.execute('SELECT 1 FROM events WHERE fingerprint=?', (fingerprint,)).fetchone():
                    continue
                simulated = alert.get('simulated') is True
                level = 0 if simulated or scenario in self.policy['routine_scenarios'] else 1
                if not simulated and scenario in self.policy['critical_scenarios']:
                    level = 2
                # Service is administratively assigned by exact scenario mapping, never attacker Meta.
                service = self.config.get('scenario_services', {}).get(scenario, '')
                key = json.dumps(['simulation' if simulated else 'alert', service, scenario])
                aid = alert.get('id')
                aid = int(aid) if re.fullmatch(r'[1-9]\d{0,17}', str(aid)) else None
                title = ('模拟 · ' if simulated else '')+(service+' · ' if service else '')+scenario
                identifier = self._incident(key, 'alert', title,
                                            level, now, '命中检测规则；处置执行情况需另行核验。', aid)
                source = clean((alert.get('source') or {}).get('value') or '', 80)
                self.db.execute('INSERT INTO events VALUES (?,?,?,?)', (fingerprint, identifier, now, source))
                self.db.execute('UPDATE incidents SET count=count+1 WHERE id=?', (identifier,))
                if (level == 0 and not simulated and self.db.execute(
                        'SELECT level FROM incidents WHERE id=?', (identifier,)).fetchone()[0] == 0):
                    # Bound a rate query by seconds in the window, not by attack volume.
                    self.db.execute('''INSERT INTO rates VALUES (?,?,1)
                        ON CONFLICT(incident,second) DO UPDATE SET count=count+1''', (identifier, int(now)))
                    rate = self.db.execute('''SELECT COALESCE(SUM(count),0),COUNT(DISTINCT CAST(second/60 AS INTEGER))
                        FROM rates WHERE incident=? AND second>=?''',
                        (identifier, now-self.policy['surge_window_seconds'])).fetchone()
                    if rate[0] >= self.policy['surge_count'] and rate[1] >= self.policy['surge_minutes']:
                        self._incident(key, 'alert', title, 1, now,
                                       '告警量持续超过配置阈值；请检查业务与防护状态。', aid)
                accepted += 1
            self._set('last_ingress', now)
        return accepted

    def observe(self, checks, now):
        """Debounce independently of alert arrival; an unknown check is never recovery."""
        with self.transaction():
            for name, state in checks.items():
                if name not in LABELS:
                    continue
                state = state if state in ('ok', 'fault', 'missing', 'optional') else 'unknown'
                old = self.db.execute('SELECT * FROM observations WHERE name=?', (name,)).fetchone()
                # A gap in checking does not prove continuous failure/recovery.
                since = old['since'] if old and old['state'] == state and now-old['checked'] <= max(90, 3*self.policy['health_interval_seconds']) else now
                self.db.execute('INSERT OR REPLACE INTO observations VALUES (?,?,?,?)', (name, state, since, now))
                key = 'health:'+name
                if old and old['state'] == 'optional' and state != 'optional':
                    self.db.execute('''DELETE FROM outbox WHERE slot IN
                        (SELECT 'recovery:'||id FROM incidents WHERE fingerprint=? AND state='closed')''', (key,))
                row = self.db.execute("SELECT * FROM incidents WHERE fingerprint=? AND state='open'", (key,)).fetchone()
                if state == 'optional':
                    if row:
                        self.db.execute("UPDATE incidents SET state='closed',last=?,reported=count,detail=? WHERE id=?",
                                        (now, '组件已不在当前监测范围，停止提醒；不代表故障已恢复。', row['id']))
                        self.db.execute('DELETE FROM outbox WHERE slot=?', ('incident:'+row['id'],))
                        self._queue_recovery(row['id'], now)
                elif state == 'ok':
                    if row and now-since >= self.policy['recovery_seconds']:
                        self.db.execute("UPDATE incidents SET state='recovered',last=?,detail=? WHERE id=?",
                                        (now, '连续检查已恢复正常。', row['id']))
                        self.db.execute('DELETE FROM outbox WHERE slot=?', ('incident:'+row['id'],))
                        self._queue_recovery(row['id'], now)
                elif now-since >= self.policy['fault_seconds']:
                    level = 1 if state == 'unknown' else 2
                    identifier = self._incident(key, 'health', LABELS[name], level, now,
                                                '状态无法确认，请检查采集与组件。' if state == 'unknown' else '连续检查异常，请检查防护组件。')
                    self.db.execute('UPDATE incidents SET count=MAX(count,1) WHERE id=?', (identifier,))
            self._set('last_health', now)

    def _buttons(self, identifier):
        try:
            bot = read_object(self.config['bot_config'])
            if (bot.get('notification_callbacks') == 1 and bot.get('bot_token') == self.config['bot_token']
                    and str(bot.get('chat_id')) == str(self.config['chat_id'])):
                return {'inline_keyboard': [[{'text': '已知晓', 'callback_data': 'na:'+identifier},
                                              {'text': '查看详情', 'callback_data': 'nd:'+identifier}]]}
        except (OSError, ValueError, TypeError):
            pass
        return None

    def _payload(self, text, quiet=False, identifier=None):
        # Telegram counts UTF-16 code units, including surrogate pairs.
        text = text.encode('utf-16-le')[:7600].decode('utf-16-le', errors='ignore')
        result = {'chat_id': self.config['chat_id'], 'text': text, 'disable_notification': quiet}
        buttons = self._buttons(identifier) if identifier else None
        if buttons:
            result['reply_markup'] = buttons
        return result

    def _enqueue(self, slot, priority, payload, snapshot, now):
        self.db.execute('''INSERT INTO outbox VALUES (?,?,?,?,?,0)
            ON CONFLICT(slot) DO UPDATE SET payload=excluded.payload,snapshot=excluded.snapshot''',
                        (slot, priority, json.dumps(payload), json.dumps(snapshot), now))

    def _queue_recovery(self, identifier, now):
        row = self.db.execute('SELECT * FROM incidents WHERE id=?', (identifier,)).fetchone()
        title = '✅ 故障恢复' if row['state'] == 'recovered' else 'ℹ️ 停止监测'
        note = '' if row['notified'] else '\n异常期间的通知尚未确认送达。'
        text = f'{title} · {clean(self.config["node"])}\n{row["title"]}\n{row["detail"]}{note}'
        self._enqueue('recovery:'+identifier, 1, self._payload(text), {'kind': 'recovery', 'items': []}, now)

    def schedule(self, now):
        with self.transaction():
            self.db.execute("""UPDATE incidents SET state='closed' WHERE kind='alert' AND state='open'
                AND notified=1 AND count<=reported AND last<?""", (now-self.policy['cooldown_seconds'],))
            self.db.execute("""DELETE FROM outbox WHERE slot IN
                (SELECT 'incident:'||id FROM incidents WHERE state='closed' AND notified=1)""")
            critical = self.db.execute("SELECT * FROM incidents WHERE level=2 AND state='open'").fetchall()
            for row in critical:
                if row['notified'] and (row['ack'] or now < row['next_notice']):
                    continue
                prefix = '🚨 紧急告警' if not row['notified'] else '🚨 故障仍待处理'
                text = f'{prefix} · {clean(self.config["node"])}\n{row["title"]}\n{row["detail"]}\n事件：{row["id"]}'
                if row['alert_id']:
                    text += f'\n告警详情：/inspect {row["alert_id"]}'
                self._enqueue('incident:'+row['id'], 2, self._payload(text, identifier=row['id']),
                              {'kind': 'critical', 'items': [[row['id'], row['count'], row['generation']]]}, now)
            attention = self.db.execute('''SELECT * FROM incidents WHERE level=1
                AND (state='open' OR (kind='alert' AND state='closed'))
                AND ((notified=0) OR (count>reported AND next_notice<=?)) ORDER BY first''', (now,)).fetchall()
            if attention and now >= self._get('attention'):
                self._aggregate('attention', attention, now)
            elif not attention:
                self.db.execute("DELETE FROM outbox WHERE slot='attention'")
            if now >= self._get('digest')+self.policy['digest_seconds']:
                ordinary = self.db.execute('''SELECT * FROM incidents WHERE level=0 AND count>reported
                    ORDER BY count-reported DESC''').fetchall()
                if ordinary:
                    self._aggregate('digest', ordinary, now)
                else:
                    self._set('digest', now)
                    self.db.execute("DELETE FROM outbox WHERE slot='digest'")
            if now >= self._get('cleanup')+3600:
                cutoff = now-self.policy['retention_days']*86400
                self.db.execute('DELETE FROM events WHERE at<?', (cutoff,))
                self.db.execute('DELETE FROM rates WHERE second<?', (now-self.policy['surge_window_seconds'],))
                self.db.execute('''DELETE FROM incidents WHERE last<? AND count<=reported
                    AND (kind='alert' OR state!='open')
                    AND NOT EXISTS(SELECT 1 FROM outbox WHERE slot LIKE '%'||incidents.id)''', (cutoff,))
                self._set('cleanup', now)
                self.db.execute("DELETE FROM meta WHERE key LIKE 'test:%' AND value<?", (cutoff,))
            self._set('heartbeat', now)

    def _aggregate(self, kind, rows, now):
        total = sum(row['count']-row['reported'] for row in rows)
        title = '📋 普通告警汇总' if kind == 'digest' else '⚠️ 需要关注'
        lines = [f'{title} · {clean(self.config["node"])}', f'新增 {total} 条告警，涉及 {len(rows)} 类事件。']
        for row in rows[:6]:
            sources = self.db.execute("SELECT COUNT(DISTINCT source) FROM events WHERE incident=? AND source!=''", (row['id'],)).fetchone()[0]
            lines.append(f'• {row["title"]}：新增 {row["count"]-row["reported"]} 条；留存记录来源 {sources} 个')
            if row['kind'] == 'health':
                lines.append(row['detail'])
            if row['alert_id']:
                lines.append(f'  /inspect {row["alert_id"]}')
        if len(rows) > 6:
            lines.append(f'另有 {len(rows)-6} 类事件，详情在本机告警中查询。')
        lines.append('告警数量不等于实际拦截次数。')
        self._enqueue(kind, 0 if kind == 'digest' else 1, self._payload('\n'.join(lines), kind == 'digest'),
                      {'kind': kind, 'items': [[r['id'], r['count'], r['generation']] for r in rows]}, now)

    def acknowledge(self, identifier):
        with self.transaction():
            row = self.db.execute("SELECT * FROM incidents WHERE id=? AND state='open'", (identifier,)).fetchone()
            if row is None:
                return False
            self.db.execute('UPDATE incidents SET ack=1 WHERE id=?', (identifier,))
            if row['notified']:
                self.db.execute('DELETE FROM outbox WHERE slot=?', ('incident:'+identifier,))
            return True

    def detail(self, identifier):
        with self.lock:
            row = self.db.execute('SELECT * FROM incidents WHERE id=?', (identifier,)).fetchone()
            if row is None:
                return '事件不存在或已超过保留期。'
            status = '已恢复' if row['state'] == 'recovered' else '已结束' if row['state'] == 'closed' else '待处理'
            return (f'{row["title"]}\n状态：{status}；'+('已知晓' if row['ack'] else '未确认')+
                    f'\n累计告警：{row["count"]}\n{row["detail"]}\n事件：{identifier}')

    def deliver_one(self, send, now):
        with self.transaction():
            if now < self._get('api_retry'):
                return False
            row = self.db.execute('SELECT * FROM outbox WHERE due<=? ORDER BY priority DESC,due,slot LIMIT 1', (now,)).fetchone()
            if row is None:
                return False
        # Network access must never hold the ingress/database lock.
        started = time.monotonic()
        accepted, retry_after = send(json.loads(row['payload']))
        now += time.monotonic()-started
        with self.transaction():
            if not accepted:
                delay = retry_after or min(300, 5 * 2**min(row['attempts'], 6))
                self.db.execute('UPDATE outbox SET attempts=attempts+1,due=? WHERE slot=? AND snapshot=?',
                                (now+delay, row['slot'], row['snapshot']))
                if retry_after:
                    self._set('api_retry', now+retry_after)
                self._set('last_failure', now)
                return False
            snapshot = json.loads(row['snapshot'])
            for identifier, count, generation in snapshot['items']:
                current = self.db.execute('SELECT * FROM incidents WHERE id=?', (identifier,)).fetchone()
                if current is None or current['generation'] != generation:
                    continue
                delay = self.policy['cooldown_seconds']
                reminder = current['reminder']
                if snapshot['kind'] == 'critical':
                    # Relative to the first successful send: 5, 15, 30 minutes, then hourly.
                    delay = (300, 600, 900, 3600)[min(reminder, 3)]
                    reminder += 1
                self.db.execute('''UPDATE incidents SET reported=MAX(reported,?),notified=1,
                    next_notice=?,reminder=? WHERE id=?''', (count, now+delay, reminder, identifier))
            if snapshot['kind'] == 'digest':
                self._set('digest', now)
            if snapshot['kind'] == 'attention':
                self._set('attention', now+self.policy['attention_interval_seconds'])
            if snapshot['kind'] == 'test':
                self._set('test:'+snapshot['test_id'], now)
            # A recovery/upgrade may have removed or replaced this slot during sending.
            self.db.execute('DELETE FROM outbox WHERE slot=? AND snapshot=?', (row['slot'], row['snapshot']))
            self._set('last_delivery', now)
        return True

    def test_message(self, now):
        identifier = secrets.token_hex(12)
        with self.transaction():
            self._enqueue('test:'+identifier, 2, self._payload('🔔 分级通知测试\n官方插件已接入降噪服务；此消息用于验证 Telegram 投递。'),
                          {'kind': 'test', 'test_id': identifier, 'items': []}, now)
        return identifier

    def status(self, now):
        with self.lock:
            report = {'pending': self.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],
                    'retrying': self.db.execute('SELECT COUNT(*) FROM outbox WHERE attempts>0').fetchone()[0],
                    'open_critical': self.db.execute("SELECT COUNT(*) FROM incidents WHERE state='open' AND level=2").fetchone()[0],
                    'heartbeat_age': now-self._get('heartbeat') if self._get('heartbeat') else None,
                    'last_delivery': self._get('last_delivery'), 'last_failure': self._get('last_failure'),
                    'health_age': now-self._get('last_health') if self._get('last_health') else None}
            report['state'] = worker_state(report, self.policy['health_interval_seconds'])
            return report


class NotificationServer(http.server.ThreadingHTTPServer):
    """Keep stalled local clients from creating an unbounded number of threads."""
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, connection, address):
        if not self.slots.acquire(blocking=False):
            try:
                connection.settimeout(1)
                connection.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n'
                                   b'Connection: close\r\nRetry-After: 1\r\n\r\n')
            except OSError:
                pass
            finally:
                self.shutdown_request(connection)
            return
        try:
            super().process_request(connection, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, connection, address):
        try:
            super().process_request_thread(connection, address)
        finally:
            self.slots.release()


def make_server(config, store):
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def do_POST(self):
            if not hmac.compare_digest(self.headers.get('Authorization', '').encode(), ('Bearer '+config['secret']).encode()):
                self.send_error(403)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 2*1024*1024:
                    raise ValueError('invalid length')
                data = json.loads(self.rfile.read(length))
                now = time.time()
                if self.path == '/alerts':
                    result = {'accepted': store.ingest(data, now)}
                elif self.path == '/status':
                    result = store.status(now)
                elif self.path in ('/ack', '/detail'):
                    identifier = data['id']
                    if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{24}', identifier):
                        raise ValueError('invalid id')
                    result = {'acknowledged': store.acknowledge(identifier)} if self.path == '/ack' else {'text': store.detail(identifier)}
                elif self.path == '/test':
                    store.validate_alerts(data)
                    result = {'test_id': store.test_message(now)}
                elif self.path == '/receipt':
                    identifier = data['id']
                    if not re.fullmatch(r'[a-f0-9]{24}', identifier):
                        raise ValueError('invalid id')
                    with store.lock:
                        result = {'accepted': bool(store._get('test:'+identifier))}
                else:
                    self.send_error(404)
                    return
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (ValueError, KeyError, TypeError, RecursionError):
                self.send_error(400)
            except (OSError, sqlite3.Error):
                # A failed disk commit must not acknowledge receipt to CrowdSec.
                self.send_error(503)

        def log_message(self, *args):
            pass

    return NotificationServer(('127.0.0.1', config['port']), Handler)


def run(config):
    if not config['enabled']:
        raise ValueError('分级通知未启用')
    directory = _directory_fd(config['state_dir'], create=True)
    try:
        lock = os.open('service.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = Store(config)
        client = TelegramClient(config['api_endpoint'].rstrip('/')+'/bot'+config['bot_token'],
                                str(Path(config['state_dir'])/'transport'), config['bot_token'])
        server = make_server(config, store)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        collector = HealthCollector(config['crowdsec_config'])

        def health():
            while True:
                try:
                    # The dashboard cache is useful for queries, but monitoring needs a fresh observation.
                    collector._cached = None
                    store.observe(collector.collect()['checks'], time.time())
                except Exception:
                    print('通知健康检查失败；状态无法确认。', file=sys.stderr)
                    store.observe(dict.fromkeys(LABELS, 'unknown'), time.time())
                time.sleep(config['policy']['health_interval_seconds'])

        def send(payload):
            accepted = client.request('sendMessage', payload) is not None
            error = client.last_send_error() or {}
            return accepted, error.get('retry_after') if error.get('category') == 'rate_limit' else None

        health_thread = threading.Thread(target=health, daemon=True)
        health_thread.start()
        started = time.monotonic()
        while True:
            if not health_thread.is_alive() or not server_thread.is_alive():
                raise ValueError('通知接收或健康检查线程已停止')
            now = time.time()
            if (time.monotonic()-started >= max(90, 3*config['policy']['health_interval_seconds'])
                    and store.status(now)['state'] in ('health_stale', 'health_pending')):
                raise ValueError('健康检查未按时完成')
            store.schedule(now)
            store.deliver_one(send, now)
            time.sleep(1)
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'check'))
    parser.add_argument('config')
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.action == 'run':
            run(config)
        else:
            print('分级通知配置有效。')
        return 0
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        print('分级通知启动或配置检查失败；请检查配置、端口和私有状态目录。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram WAF & Threat Intelligence Bot 3.1
- Queries use Python 3 standard library; ban guard also requires PyYAML
- Multi-Source Fusion: CrowdSec SQLite DB + NPM Stream Access Logs
- Real-time Forensic Drill-Down & Interactive Inline Actions
- Strictly filters out CAPI/system updates (+15000/-0 IPs) to prevent notification spam
"""

import os
import argparse
import importlib.util
import fcntl
import hashlib
import ipaddress
import shlex
import tempfile
from pathlib import Path
import sys
import time
import json
import sqlite3
import subprocess
import urllib.request
import urllib.parse
import html
import re
from datetime import datetime, timezone, timedelta
from collections import Counter, namedtuple
from threading import Thread

# ==================== 用户配置区 ====================
BOT_TOKEN = "你的_BOT_TOKEN"           # 替换为 @BotFather 获取的 Token
ADMIN_CHAT_ID = 123456789             # 替换为你的 Telegram 数字 ID
DB_PATH = "/var/lib/crowdsec/data/crowdsec.db"
NPM_LOG_DIR = "/home/docker/npm/data/logs"
WHITELIST_FILE = "/etc/crowdsec/parsers/s02-enrich/tg-whitelist.yaml"

ADMIN_USER_ID = ADMIN_CHAT_ID
CSCLI_CONFIG = "/etc/crowdsec/config.yaml"
AUTO_NOTIFY = False
STATE_DIR = "/var/lib/crowdsec-1key-bot"
EXECUTION_LOG_DIRS = None  # None follows NPM_LOG_DIR; custom deployments may supply 1–4 directories.
TG_API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"
_INSTANCE_LOCK = None
_API_CLIENT = None
_ACTION_STORE = None
_HEALTH_COLLECTOR = None


def sibling(name):
    """Resolve installed helpers even when an audit tool imports this script."""
    target = Path(__file__).resolve().with_name(name+'.py')
    module = sys.modules.get(name)
    if module is None or Path(module.__file__).resolve() != target:
        spec = importlib.util.spec_from_file_location(name, target)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def get_api_client():
    global _API_CLIENT
    key = (TG_API_BASE, STATE_DIR, BOT_TOKEN)
    if _API_CLIENT is None or _API_CLIENT[0] != key:
        _API_CLIENT = (key, sibling('crowdsec_bot_api').TelegramClient(*key))
    return _API_CLIENT[1]


def get_action_store():
    global _ACTION_STORE
    key = (STATE_DIR, BOT_TOKEN)
    if _ACTION_STORE is None or _ACTION_STORE[0] != key:
        _ACTION_STORE = (key, sibling('crowdsec_bot_actions').ActionStore(*key))
    return _ACTION_STORE[1]


def load_settings(path):
    global BOT_TOKEN, ADMIN_CHAT_ID, ADMIN_USER_ID, DB_PATH, NPM_LOG_DIR, CSCLI_CONFIG, WHITELIST_FILE, STATE_DIR, TG_API_BASE, EXECUTION_LOG_DIRS
    config = json.loads(Path(path).read_text(encoding='utf-8'))
    BOT_TOKEN = config['bot_token']
    ADMIN_CHAT_ID = int(config['chat_id'])
    ADMIN_USER_ID = int(config['admin_user_id'])
    if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', BOT_TOKEN) or not ADMIN_CHAT_ID or ADMIN_USER_ID <= 0:
        raise ValueError('Token、Chat ID 或管理员用户 ID 无效')
    DB_PATH = config.get('db_path', DB_PATH)
    NPM_LOG_DIR = config.get('npm_log_dir', NPM_LOG_DIR)
    EXECUTION_LOG_DIRS = config.get('execution_log_dirs')
    if EXECUTION_LOG_DIRS is not None and (not isinstance(EXECUTION_LOG_DIRS, list)
            or not 1 <= len(EXECUTION_LOG_DIRS) <= 4
            or any(not isinstance(p, str) or not Path(p).is_absolute() for p in EXECUTION_LOG_DIRS)):
        raise ValueError('执行证据日志目录需为 1–4 个绝对目录')
    CSCLI_CONFIG = config.get('crowdsec_config', CSCLI_CONFIG)
    WHITELIST_FILE = config.get('whitelist_file', WHITELIST_FILE)
    STATE_DIR = config.get('state_dir', STATE_DIR)
    endpoint = config.get('api_endpoint', 'https://api.telegram.org').rstrip('/')
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('API 端点必须为 HTTPS，不能含账号或查询参数')
    TG_API_BASE = endpoint+'/bot'+BOT_TOKEN
    return config


def acquire_instance_lock():
    global _INSTANCE_LOCK
    # Same-token instances share a lock even if their configuration paths differ.
    signature = hashlib.sha256(BOT_TOKEN.encode()).hexdigest()[:24]
    path = '/run/crowdsec-tg-'+signature+'.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    stream = os.fdopen(fd, 'w')
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        stream.close()
        raise RuntimeError('同一 Token 已有本工具机器人实例运行')
    _INSTANCE_LOCK = stream


def authorized(update):
    if update.get('from', {}).get('id') != ADMIN_USER_ID:
        return False
    message = update.get('message', update)
    return message.get('chat', {}).get('id') == ADMIN_CHAT_ID


def save_offset(value):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.offset-', dir=STATE_DIR)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(str(value))
        os.replace(temporary, offset_path())
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def offset_path():
    signature = hashlib.sha256(BOT_TOKEN.encode()).hexdigest()[:24]
    return os.path.join(STATE_DIR, 'offset-'+signature)


# Labels, commands, legacy aliases and navigation share stable view identifiers.
MenuView = namedtuple('MenuView', 'label renderer command description aliases parent refresh usage',
                      defaults=(None, '', (), 'home', True, ''))
VIEWS = {
    'overview': MenuView('📊 防护概况', 'module_system_status', 'overview', '服务状态与系统资源', ('📊 系统大屏', '📊 防护总览')),
    'alerts': MenuView('🚨 最近告警', 'module_recent_alerts', 'alerts', '查看最近告警', ('🚨 最新告警',)),
    'decisions': MenuView('🚫 封禁列表', 'module_decisions', 'decisions', '查看当前处置要求', ('🚫 封禁名单', '🚫 封禁决策'), refresh=False),
    'forensics': MenuView('🔍 告警详情', 'module_forensics', 'inspect', '查看指定或最新告警', ('🔍 取证穿透', '🔍 告警取证'),
                          parent='alerts', usage=' [ID]'),
    'analysis': MenuView('📈 访问分析', 'module_analysis', 'analysis', '告警与访问日志统计', ('📈 攻击分析',), refresh=False),
    'sites': MenuView('📦 容器状态', 'module_sites', 'containers', '容器健康与接入配置', ('🌐 站点体检',), refresh=False),
    'runtime': MenuView('🤖 机器人状态', 'module_bot_status', 'bot', '轮询、投递与待核对操作'),
    'tools': MenuView('🛠 管理工具', 'module_emergency_manager', 'tools', '白名单、重载与缓存', ('⚡ 应急管家', '🛠 运维工具'), refresh=False),
    'help': MenuView('❓ 使用帮助', 'module_help', 'help', '查看命令与操作说明', ('帮助',), refresh=False),
    'posture': MenuView('📈 24 小时告警', 'module_attack_posture', aliases=('🛡️ 攻击态势', '🛡️ 告警统计'), parent='analysis'),
    'sources': MenuView('🔎 可疑来源', 'module_top_hackers', aliases=('💀 黑客榜单',), parent='analysis'),
    'paths': MenuView('🎯 访问路径', 'module_top_targets', aliases=('🎯 漏洞靶心', '🎯 请求路径'), parent='analysis'),
    'whitelist': MenuView('📋 日志白名单', 'module_whitelist', aliases=('📋 日志解析白名单',), parent='tools'),
    'status': MenuView('🩺 综合状态', 'module_status', 'status', '防护健康与机器人运行状态'),
    'top': MenuView('📈 日志抽样排行', 'module_top', 'top', '可疑来源与请求路径排行', parent='analysis'),
}
MAIN_MENU = (('overview', 'alerts', 'decisions'), ('forensics', 'analysis', 'sites'),
             ('runtime', 'tools', 'help'))
ACTION_COMMANDS = (('ban', ' IP [时长]', '手动封禁 IP（需确认）'),
                   ('unban', ' IP', '提交 IP 解封（需确认）'),
                   ('white', ' IP', '加入日志白名单（需确认）'))
MAIN_KEYBOARD = {
    "keyboard": [[{"text": VIEWS[key].label} for key in row] for row in MAIN_MENU],
    "resize_keyboard": True,
    "is_persistent": True
}
MENU_ROUTES = {}
for _key, _view in VIEWS.items():
    for _label in (_view.label, *_view.aliases):
        MENU_ROUTES[_label] = _key
    if _view.command:
        MENU_ROUTES['/'+_view.command] = _key

# ==================== 网络与 Telegram API ====================
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def tg_request(endpoint, data=None):
    return get_api_client().request(endpoint, data)


def register_bot_commands():
    """注入 Telegram 聊天框原生斜杠命令联想菜单"""
    commands = [{'command': 'start', 'description': '📱 唤出 3×3 九宫格主菜单'}]
    commands.extend({'command': view.command, 'description': view.description}
                    for view in VIEWS.values() if view.command)
    commands.extend({'command': command, 'description': description}
                    for command, _, description in ACTION_COMMANDS)
    tg_request("setMyCommands", {"commands": commands})

def send_message(text, reply_markup=None, chat_id=None):
    chat_id = ADMIN_CHAT_ID if chat_id is None else chat_id
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return tg_request("sendMessage", payload)

def answer_callback(callback_id, text=None, alert=False):
    payload = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text
        payload["show_alert"] = alert
    tg_request("answerCallbackQuery", payload)

class CommandUncertain(RuntimeError):
    """The subprocess timed out after a mutation may already have reached its target."""


def run_cmd(cmd, timeout=8):
    args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    # This service runs with its own permissions; avoid sudo and shell expansion.
    if args and args[0] == 'sudo':
        args.pop(0)
    if args and args[0] == 'cscli':
        args[1:1] = ['-c', CSCLI_CONFIG]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise CommandUncertain('命令超时，执行结果待核对') from error
    except OSError as error:
        raise RuntimeError('命令无法执行或超时') from error
    if result.returncode < 0:
        raise CommandUncertain('命令被信号中断，执行结果待核对')
    if result.returncode:
        raise RuntimeError('命令执行失败（退出码 '+str(result.returncode)+'）')
    return result.stdout.strip()


def get_db_conn():
    """以只读无锁模式连接 CrowdSec 本地 SQLite 数据库"""
    if os.path.exists(DB_PATH):
        try:
            return sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        except Exception:
            return None
    return None

def read_log_tail_chunks():
    """
    轻量反向游标读取 NPM 日志末尾切片（防 OOM 核心）
    最多 8 个 access.log，各读取末尾 512KB；统计为有限抽样，不代表全部日志
    """
    chunks = []
    if not os.path.exists(NPM_LOG_DIR):
        return ""
    for fname in sorted(name for name in os.listdir(NPM_LOG_DIR) if name.endswith('_access.log'))[:8]:
        if fname.endswith("_access.log"):
            fpath = os.path.join(NPM_LOG_DIR, fname)
            try:
                size = os.path.getsize(fpath)
                with open(fpath, "rb") as f:
                    read_len = min(size, 512 * 1024)
                    if size > read_len:
                        f.seek(size - read_len)
                    raw = f.read().decode("utf-8", errors="ignore")
                    chunks.append(raw)
            except Exception:
                continue
    return "\n".join(chunks)

# ==================== 业务模块实现 ====================
def display_duration(value):
    raw = str(value or '')
    if len(raw) > 48:
        return esc(raw, 40)
    parts = re.findall(r'(\d+(?:\.\d+)?)([hms])', raw)
    if not parts or ''.join(n+u for n, u in parts) != raw:
        return esc(raw or '未记录', 40)
    seconds = sum(float(n)*{'h': 3600, 'm': 60, 's': 1}[u] for n, u in parts)
    if seconds >= 3600:
        return f'{int(seconds//3600)} 小时'+(f' {int(seconds%3600//60)} 分' if seconds%3600 >= 60 else '')
    return f'{int(seconds//60)} 分 {int(seconds%60)} 秒' if seconds >= 60 else f'{int(seconds)} 秒'


def display_time(value):
    try:
        date = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return date.replace(tzinfo=date.tzinfo or timezone.utc).astimezone(timezone.utc).strftime('%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError, OverflowError):
        return '未记录'


def disposition(value):
    return {'ban': '封禁', 'captcha': '验证码'}.get(str(value), esc(value or '未记录', 20))


def detail_button(data, details):
    return {'text': '⬅️ 返回简洁版' if details else '📄 查看详情',
            'callback_data': data if details else 'more:'+data}


def module_system_status(details=False):
    with open('/proc/meminfo', 'r') as stream:
        memory = {line.split(':')[0]: int(line.split(':')[1].split()[0]) for line in stream if ':' in line}
    total = memory.get('MemTotal', 1)/1024
    used = total-memory.get('MemAvailable', 1)/1024
    disk = os.statvfs('/')
    disk_total = disk.f_blocks*disk.f_frsize/(1024**3)
    disk_used = disk_total-disk.f_bavail*disk.f_frsize/(1024**3)
    count = None
    conn = get_db_conn()
    if conn:
        try:
            count = conn.execute("SELECT count(*) FROM decisions WHERE until > datetime('now')").fetchone()[0]
        except sqlite3.Error:
            pass
        finally:
            conn.close()
    count_text = str(count)+' 条' if count is not None else '暂时无法查询（未知）'
    text = f'📊 <b>防护概况 · {esc(os.uname().nodename, 60)}</b>\n'
    text += module_health_status(details=details)+'\n'
    text += f'当前处置要求：{count_text}\n内存：{used:.0f}/{total:.0f} MB · 磁盘：{disk_used:.1f}/{disk_total:.1f} GB'
    if details:
        load = os.getloadavg()
        hours = int(float(Path('/proc/uptime').read_text().split()[0])//3600)
        text += f'\n系统负载：{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}\n持续运行：{hours} 小时'
    return text


def module_health_status(details=False):
    global _HEALTH_COLLECTOR
    try:
        sibling('crowdbastion_health')
        sibling('crowdbastion_node')
        if _HEALTH_COLLECTOR is None or _HEALTH_COLLECTOR[0] != CSCLI_CONFIG:
            _HEALTH_COLLECTOR = (CSCLI_CONFIG, sibling('crowdsec_bot_health').HealthCollector(CSCLI_CONFIG))
        report = _HEALTH_COLLECTOR[1].collect()
        labels = {'ok': '正常', 'fault': '异常', 'missing': '尚未配置', 'unknown': '暂时无法确认',
                  'pending': '样本不足', 'optional': '未启用（可选）', 'verified': '已验证'}
        names = {'core': '检测服务', 'api': '检测接口', 'bouncer': '防火墙服务',
                 'registry': '组件登记', 'metrics': '运行指标', 'logs': '日志解析', 'remote': '远端连接'}
        checks, summary = report['checks'], report['summary']
        lines = ['🩺 <b>服务检查</b>']
        if any(state in ('fault', 'missing', 'unknown') for state in checks.values()):
            lines.append('⚠️ '+esc(summary.get('attention') or summary['verdict'], 140))
            if summary.get('next'):
                lines.append('建议：'+esc(summary['next'], 180))
        selected = names if details else ('core', 'bouncer', 'logs', 'remote')
        for key in selected:
            state = checks.get(key)
            if state is None or (not details and state == 'optional'):
                continue
            label = '运行中' if state == 'ok' and key in ('core', 'bouncer') else labels.get(state, '暂时无法确认')
            lines.append(names[key]+'：'+label)
        if details:
            lines.extend(['范围：'+esc(report['scope'], 120), '检查结论：'+esc(summary['verdict'], 120)])
            if summary.get('impact'):
                lines.append('影响：'+esc(summary['impact'], 160))
            lines.append('本页检查服务与配置；实际拦截请查看具体来源的拦截记录。')
        lines.append('更新：'+datetime.fromtimestamp(report['checked_at'], timezone.utc).strftime('%m-%d %H:%M:%S UTC'))
        return '\n'.join(lines)
    except (OSError, ValueError, RuntimeError, ImportError, KeyError, TypeError):
        return '🩺 服务检查：暂时无法查询，请检查依赖或权限。'


def runtime_status_text(details=True):
    api = sibling('crowdsec_bot_api')
    report = api.read_runtime(STATE_DIR, BOT_TOKEN)
    if details:
        text = api.describe_runtime(report)
    else:
        labels = {'healthy': '正常', 'error': '异常', 'stale': '状态记录已过期', 'unknown': '暂时无法确认'}
        poll_status = report.get('status')
        if poll_status in ('healthy', 'error'):
            poll_status = 'error' if report.get('poll_error') is not None else ('healthy' if report.get('last_poll_at') is not None else 'unknown')
        text = '接收消息：'+labels.get(poll_status, '暂时无法确认')
        text += '\n最近成功收取：'+api._format_time(report.get('last_poll_at'))
        text += '\n最近发送成功：'+api._format_time(report.get('last_send_at'))
        # The API renderer uses only fixed, trusted error categories.
        diagnostic = api.describe_runtime(report)
        error_line = next((line for line in diagnostic.splitlines() if line.startswith('当前错误：')), '')
        if error_line and error_line != '当前错误：无已记录错误':
            text += '\n⚠️ '+error_line
        if report.get('next_retry_at') is not None:
            text += '\n下次重试：'+api._format_time(report['next_retry_at'])
    try:
        pending = get_action_store().unfinished()
        text += f'\n待核对操作：最近 {len(pending)} 项（最多显示 5 项）' if pending else '\n待核对操作：0 项'
        if pending:
            text += '\n请先核对操作结果，再决定是否重试。'
            if details:
                for item in pending:
                    text += '\n'+item['action']+' '+' '.join(item['params'])+' / '+item['id']
    except (OSError, ValueError):
        text += '\n⚠️ 操作记录暂时无法读取，请在服务器核对。'
    return text


def module_status(details=False):
    return module_health_status(details=details)+'\n\n'+module_bot_status(details=details)


def module_bot_status(details=False):
    return '🤖 <b>机器人状态</b>\n'+esc(runtime_status_text(details=details), 2500)


def module_analysis():
    return ('📈 <b>访问分析</b>\n选择要查看的统计。',
            {'inline_keyboard': [[{'text': VIEWS[key].label, 'callback_data': 'nav:'+key}]
                                 for key in ('posture', 'sources', 'paths')]})


def module_top(details=False):
    return module_top_hackers(details=details)+'\n\n'+module_top_targets(details=details)


def module_attack_posture(details=False):
    conn = get_db_conn()
    if not conn:
        return '暂时无法查询告警统计，请稍后刷新。'
    day_ago = (datetime.now(timezone.utc)-timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        rows = conn.execute("""SELECT scenario, source_ip FROM alerts
            WHERE created_at >= ? AND scenario NOT LIKE '%update%'
            AND source_ip IS NOT NULL AND source_ip != ''""", (day_ago,)).fetchall()
    except sqlite3.Error:
        return '暂时无法查询告警统计，请稍后刷新。'
    finally:
        conn.close()
    rules = Counter(row[0] for row in rows)
    sources = {row[1] for row in rows}
    text = f'📈 <b>24 小时告警</b>\n告警：{len(rows)} 条\n来源 IP：{len(sources)} 个\n'
    if rows:
        text += '常见类型：\n'+'\n'.join(f'{i}. {esc(rule.split("/")[-1], 60)} · {count} 条'
                                         for i, (rule, count) in enumerate(rules.most_common(3), 1))
    else:
        text += '近 24 小时未查到告警。'
    text += '\n范围：本机告警记录。'
    if details:
        text += '\n统计告警数量，不代表实际拦截次数。'
    return text


def module_recent_alerts():
    conn = get_db_conn()
    if not conn:
        return '暂时无法查询告警，请稍后刷新。', None
    try:
        alerts = conn.execute("""SELECT id, source_ip, source_country, scenario, created_at, simulated
            FROM alerts WHERE scenario NOT LIKE '%update%' AND source_ip IS NOT NULL
            AND source_ip != '' ORDER BY id DESC LIMIT 5""").fetchall()
    except sqlite3.Error:
        return '暂时无法查询告警，请稍后刷新。', None
    finally:
        conn.close()
    if not alerts:
        return '🚨 最近告警\n本次查询未找到告警。', None
    text, keyboard = '🚨 <b>最近告警 · 最近 5 条</b>\n', []
    for aid, ip, country, rule, created, simulated in alerts:
        text += f'\n<b>#{esc(aid)}</b> · <code>{esc(ip, 60)}</code> · {esc(country or "未记录", 20)}'+(' · 模拟' if simulated else '')+'\n'
        text += '类型：'+esc(str(rule).split('/')[-1], 65)+'\n时间：'+display_time(created)+'\n'
        keyboard.append([{'text': f'🔍 查看 #{aid}', 'callback_data': f'ins:{aid}'}])
    return text.strip(), {'inline_keyboard': keyboard}


def module_top_hackers(details=False):
    raw = read_log_tail_chunks()
    if not raw:
        return '🔎 可疑来源\n暂时没有可读取的网站日志。'
    matches = re.findall(r'(?:GET|POST|HEAD) [^\"]*(?:\.env|\.\./|phpmyadmin|actuator|pearcmd|\.git|wp-login|\.bak)[^\"]* [^\[]*\[Client ([a-fA-F0-9:.]+)\]', raw, re.I) or re.findall(r' (?:404|403) [^\[]*\[Client ([a-fA-F0-9:.]+)\]', raw)
    counts = Counter(matches).most_common(10)
    text = '🔎 <b>可疑来源 · 前 10 名</b>\n'
    text += '\n'.join(f'{i}. <code>{esc(ip)}</code> · {count} 次匹配' for i, (ip, count) in enumerate(counts, 1)) if counts else '本次抽样未匹配到可疑请求。'
    text += '\n范围：最近可读取的网站日志抽样。'
    if details:
        text += '\n按请求路径或响应状态匹配，不能据此确定恶意身份或实际拦截。'
    return text


def module_top_targets(details=False):
    raw = read_log_tail_chunks()
    if not raw:
        return '🎯 访问路径\n暂时没有可读取的网站日志。'
    paths = re.findall(r'(?:GET|POST|HEAD) (/[^ \"?]+)', raw, re.I)
    sensitive = [p for p in paths if any(k in p.lower() for k in ['.env', '..', 'phpmyadmin', 'actuator', 'pearcmd', '.git', 'wp-', '.bak', 'api/', 'login'])]
    counts = Counter(sensitive).most_common(10) or Counter(paths).most_common(10)
    text = '🎯 <b>访问路径 · 前 10 名</b>\n'
    text += '\n'.join(f'{i}. <code>{esc(path, 100 if details else 32)}</code> · {count} 次' for i, (path, count) in enumerate(counts, 1)) if counts else '本次抽样未找到请求路径。'
    text += '\n范围：最近可读取的网站日志抽样。'
    if details:
        text += '\n优先统计敏感路径；请求频率不能单独证明攻击或已拦截。'
    return text


def meta_values(meta):
    if isinstance(meta, dict):
        return meta
    if isinstance(meta, list):
        return {item['key']: item.get('value', '') for item in meta
                if isinstance(item, dict) and isinstance(item.get('key'), str)}
    return {}


def context_value(value):
    if isinstance(value, str) and value.lstrip().startswith('['):
        try:
            value = json.loads(value)
        except ValueError:
            return [value]
    return value if isinstance(value, list) else [value]


def request_samples(alert):
    context = meta_values(alert.get('meta'))
    context_paths = context_value(context.get('http_path', context.get('target_uri', '')))
    context_uas = context_value(context.get('http_user_agent', context.get('user_agent', '')))
    context_methods = context_value(context.get('http_verb', context.get('method', '')))
    single = all(len(values) == 1 for values in (context_paths, context_uas, context_methods))
    samples = []
    for event in alert.get('events') or []:
        if not isinstance(event, dict):
            continue
        meta = meta_values(event.get('meta'))
        path = meta.get('http_path', meta.get('uri', meta.get('target_uri')))
        if path is None:
            continue
        ua = meta.get('http_user_agent', meta.get('user_agent'))
        method = meta.get('http_verb', meta.get('method', ''))
        if alert.get('kind') == 'appsec' and single and context_paths[0] == path:
            if ua is None and ('http_user_agent' in context or 'user_agent' in context):
                ua = context_uas[0]
            method = method or context_methods[0]
        sample = (str(path), None if ua is None else str(ua), str(method))
        if sample not in samples:
            samples.append(sample)
        if len(samples) == 3:
            break
    if not samples and any(context_paths):
        # Arrays are independent context sets, not proven request/UA pairs.
        paths = ' | '.join(map(str, context_paths[:3]))
        ua = str(context_uas[0]) if single and ('http_user_agent' in context or 'user_agent' in context) else None
        samples.append((paths, ua, str(context_methods[0]) if single else ''))
    return samples


def read_alert(alert_id=None):
    if alert_id is None:
        alerts = json.loads(run_cmd(['cscli', 'alerts', 'list', '-l', '20', '-o', 'json']))
        if not isinstance(alerts, list):
            raise ValueError('告警列表格式无效')
        candidates = [a for a in alerts if isinstance(a, dict) and (a.get('source') or {}).get('value')
                      and not any(x in str(a.get('scenario', '')).lower() for x in ('update', 'capi'))]
        if not candidates:
            return None
        alert_id = max(candidates, key=lambda a: int(a['id']))['id']
    if isinstance(alert_id, bool) or not str(alert_id).isdigit() or int(alert_id) <= 0:
        raise ValueError('告警 ID 无效')
    data = json.loads(run_cmd(['cscli', 'alerts', 'inspect', str(alert_id), '--details', '-o', 'json']))
    alerts = data if isinstance(data, list) else [data]
    return next((a for a in alerts if isinstance(a, dict) and str(a.get('id')) == str(alert_id)), None)


def esc(value, limit=160):
    return html.escape(str(value or '')[:limit])


def module_forensics(alert_id=None, details=False):
    try:
        alert = read_alert(alert_id)
        if alert is None:
            return '未找到这条告警，请返回列表刷新。', None
        source = alert.get('source') or {}
        aid, ip = alert.get('id'), source.get('value', source.get('ip', ''))
        text = f'🔍 <b>告警详情 · #{card_esc(aid)}</b>\n'
        if alert.get('simulated') is True:
            text += 'ℹ️ 模拟告警\n'
        text += f'来源：<code>{card_esc(ip, 60)}</code> · {card_esc(source.get("cn") or "地区未记录", 30)}\n'
        text += '类型：'+card_esc(alert.get('scenario'), 100)+'\n时间：'+display_time(alert.get('start_at'))+'\n'
        decisions = alert.get('decisions') or []
        text += '告警处置：'+('、'.join(disposition(d.get('type'))+' '+display_duration(d.get('duration'))+('（模拟）' if d.get('simulated') is True else '')
                                          for d in decisions[:3]) if decisions else '未附带处置要求')+'\n'
        if len(decisions) > 3:
            text += f'另有 {len(decisions)-3} 条未展开。\n'
        samples = request_samples(alert)
        if details:
            text += '网络归属：'+card_esc(source.get('as_name') or '未记录', 100)+'\n'
            text += '告警附带的处置是历史记录；当前状态请查看“当前封禁要求”。\n'
            for index, (path, ua, method) in enumerate(samples, 1):
                description = '未记录 UA' if ua is None else ('请求未提供 UA' if not ua else ua)
                text += f'\n请求样本 {index}：<code>{card_esc(method, 12)} {card_esc(path, 180)}</code>\n客户端：<code>{card_esc(description, 100)}</code>\n'
            text += '\n拦截记录按来源查询，不等同于原告警请求已被拦截。'
        elif samples:
            path, _, method = samples[0]
            text += f'请求样本：<code>{card_esc(method, 12)} {card_esc(path, 180)}</code>\n'
        else:
            text += '未记录网站请求详情。\n'
        rows = []
        try:
            parsed_ip = str(ipaddress.ip_address(ip))
            if type(aid) is int and aid > 0:
                rows.append([{'text': '🔎 拦截记录', 'callback_data': f'exp:{aid}'}])
            rows.append([{'text': '📋 当前封禁要求', 'callback_data': 'dip:'+parsed_ip}])
        except ValueError:
            pass
        if type(aid) is int and aid > 0:
            rows.append([detail_button(f'ins:{aid}', details)])
        return text.strip(), {'inline_keyboard': rows}
    except (RuntimeError, ValueError, TypeError, KeyError):
        return '暂时无法查询告警，请稍后刷新。', None


# Read-only mobile views. Limits are alert/container samples, not global totals.
VIEW_SIZE = 5
DECISION_ALERT_LIMIT = 50


def card_esc(value, limit=60):
    # Bound serialized HTML without cutting entities or tags.
    result = ''
    for char in str(value or '')[:limit]:
        escaped = html.escape(char)
        if len(result)+len(escaped) > limit:
            break
        result += escaped
    return result


def module_execution(alert_id, details=False, decision_page=0):
    base = f'exp:{alert_id}'
    keyboard = {'inline_keyboard': [[{'text': '🔄 刷新', 'callback_data': ('more:' if details else '')+base},
                                    detail_button(base, details)],
        [{'text': '⬅️ 返回告警', 'callback_data': f'ins:{alert_id}'}],
        [{'text': '🏠 主菜单', 'callback_data': 'nav:home'}]]}
    try:
        alert = read_alert(alert_id)
        if alert is None:
            return '未找到这条告警，请返回列表刷新。', keyboard
        ip = str(ipaddress.ip_address((alert.get('source') or {}).get('value', '')))
    except (RuntimeError, ValueError, TypeError):
        return '暂时无法查询拦截记录，请核对告警及来源 IP。', keyboard
    lines = [f'🔎 <b>{"拦截详情" if details else "拦截记录"} · #{card_esc(alert_id)}</b>']
    if alert.get('simulated') is True:
        lines.append('ℹ️ 模拟告警；以下记录按来源单独查询。')
    lines.append(f'来源：<code>{card_esc(ip)}</code>')
    decisions = []
    try:
        data = json.loads(run_cmd(['cscli', 'decisions', 'list', '--ip', ip, '-l', '20', '-o', 'json']))
        if data is None:
            data = []
        if not isinstance(data, list) or any(not isinstance(a, dict) or
                not isinstance(a.get('decisions', []), list) for a in data):
            raise ValueError('Invalid decisions')
        decisions = [dict(d, simulated=d.get('simulated') is True or a.get('simulated') is True)
                     for a in data for d in (a.get('decisions') or []) if isinstance(d, dict)]
        if not decisions:
            lines.append('当前处置：本次未查到')
        elif len(decisions) == 1 and decisions[0]['simulated']:
            lines.append('模拟处置：'+disposition(decisions[0].get('type'))+' · '+display_duration(decisions[0].get('duration')))
        elif len(decisions) == 1 and decisions[0].get('type') == 'ban':
            lines.append('封禁要求：剩余 '+display_duration(decisions[0].get('duration')))
        elif len(decisions) == 1:
            lines.append('当前处置：'+disposition(decisions[0].get('type'))+' · 剩余 '+display_duration(decisions[0].get('duration')))
        else:
            lines.append(f'当前处置：{len(decisions)} 条要求'+('（含模拟）' if any(d['simulated'] for d in decisions) else '')+'，详见详情')
    except (RuntimeError, ValueError, TypeError):
        lines.append('当前处置：暂时无法查询')
    now = time.time()
    since = now-86400
    fallback_time = False
    try:
        date = datetime.fromisoformat(str(alert.get('start_at', '')).replace('Z', '+00:00'))
        since = date.replace(tzinfo=date.tzinfo or timezone.utc).timestamp()
    except (ValueError, TypeError, OverflowError):
        fallback_time = True
    evidence = None
    try:
        reader = sibling('crowdsec_execution')
        evidence = reader.query(EXECUTION_LOG_DIRS or [NPM_LOG_DIR], ip, since, now=now)
        if evidence['state'] == 'observed':
            lines.append(f"网站拒绝：已记录 {evidence['count']} 次（抽样）")
        elif evidence['state'] == 'empty':
            lines.append('网站拒绝：本次未查到记录')
        else:
            lines.append('网站拒绝：暂时无法查询')
    except (OSError, ValueError, TypeError, ImportError, KeyError, OverflowError):
        lines.append('网站拒绝：暂时无法查询')
        evidence = None
    try:
        config_path = Path(CSCLI_CONFIG).parent/'bouncers/crowdsec-firewall-bouncer.yaml'
        firewall = sibling('crowdsec_execution').firewall_membership(sibling('crowdsec_safety').load(config_path), ip)
        labels = {'present': '已加入', 'absent': '本次未查到',
                  'unavailable': '暂时无法查询', 'unsupported': '当前方式暂不支持查询'}
        lines.append('防火墙名单：'+labels[firewall['state']])
    except Exception:
        lines.append('防火墙名单：暂时无法查询')
    lines.append('防火墙实际拦截：尚未验证')
    start = max(since, now-86400) if evidence is None else evidence['since']
    lines.append('范围：该来源，自 '+datetime.fromtimestamp(start, timezone.utc).strftime('%m-%d %H:%M UTC')+' 起')
    if evidence and (evidence['truncated'] or evidence['errors']):
        lines.append('ℹ️ 记录不完整，详见详情。')
    if details:
        if fallback_time:
            lines.append('告警时间未记录，按最近 24 小时查询。')
        lines.append('查询结束：'+datetime.fromtimestamp(now, timezone.utc).strftime('%m-%d %H:%M:%S UTC'))
        lines.append('当前处置按 IP 查询，最多 20 条告警；处置要求不等于已执行。')
        entries, decision_page, decision_pages = page_slice(decisions, decision_page)
        lines.append(f'处置要求：{decision_page+1}/{decision_pages} 页')
        for decision in entries:
            lines.append('• '+disposition(decision.get('type'))+' / '+card_esc(decision.get('duration'), 30)+(' · 模拟' if decision['simulated'] else ''))
        keyboard['inline_keyboard'][0][0]['callback_data'] = f'exd:{alert_id}:{decision_page}'
        if decision_pages > 1:
            keyboard['inline_keyboard'].insert(1, page_controls(f'exd:{alert_id}', decision_page, decision_pages))
        if evidence:
            lines.append(f"读取日志：{evidence['logs_read']} 个\n日志截尾：{evidence['truncated_files']} 个 · 读取失败：{evidence['errors']}")
            lines.append('扫描上限：'+('已达到' if evidence['scan_limited'] else '未达到'))
            causes = {'lapi_ban': '命中封禁要求', 'lapi_failure': '封禁查询故障，按策略拒绝',
                      'appsec_rule': '命中网站安全规则', 'appsec_failure': '网站检查故障，按策略拒绝',
                      'appsec_body': '请求体检查未完成，按策略拒绝'}
            if evidence['state'] == 'observed':
                lines.append('拒绝原因：'+'；'.join(causes[k]+f' {v} 次' for k, v in evidence['causes'].items()))
                last = evidence['records'][0]
                lines.append('最近拒绝：'+datetime.fromtimestamp(last['time'], timezone.utc).strftime('%m-%d %H:%M:%S UTC'))
                lines.append(f"HTTP {last['status']} · 未访问业务上游\n请求 ID：<code>{last['request_id']}</code>")
        lines.extend(['网站记录按来源 IP 和时间查询，不能证明原触发请求或某条告警决策已执行。',
                      '未查到网站记录时，可能没有新访问、请求先被防火墙拦住，或日志记录不完整。',
                      '加入防火墙名单仅表示配置集合中存在该 IP，集合成员状态不能证明实际丢包。'])
    return '\n'.join(lines), keyboard


def page_controls(prefix, page, pages):
    row = []
    if page:
        row.append({'text': '⬅️ 上一页', 'callback_data': f'{prefix}:{page-1}'})
    row.append({'text': '🔄 刷新', 'callback_data': f'{prefix}:{page}'})
    if page+1 < pages:
        row.append({'text': '下一页 ➡️', 'callback_data': f'{prefix}:{page+1}'})
    return row


def page_slice(items, page):
    pages = max(1, (len(items)+VIEW_SIZE-1)//VIEW_SIZE)
    page = min(max(0, int(page)), pages-1)
    return items[page*VIEW_SIZE:(page+1)*VIEW_SIZE], page, pages


def decision_groups():
    alerts = json.loads(run_cmd(['cscli', 'decisions', 'list', '-l', str(DECISION_ALERT_LIMIT), '-o', 'json']))
    if alerts is None:
        alerts = []
    if not isinstance(alerts, list):
        raise ValueError('Invalid decisions JSON')
    groups = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError('Invalid alert')
        for decision in alert.get('decisions') or []:
            if not isinstance(decision, dict):
                raise ValueError('Invalid decision')
            scope, value = str(decision.get('scope', '')), str(decision.get('value', ''))
            key = (scope, value)
            if key not in groups:
                digest = hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16]
                groups[key] = {'scope': scope, 'value': value, 'key': digest, 'decisions': []}
            groups[key]['decisions'].append(dict(decision, alert_id=alert.get('id'),
                scenario=decision.get('scenario') or alert.get('scenario'),
                simulated=decision.get('simulated') is True or alert.get('simulated') is True))
    return sorted(groups.values(), key=lambda g: (g['scope'], g['value']))


def decision_buttons(group, decisions, detail=False):
    if not detail:
        return [{'text': '📋 查看要求', 'callback_data': 'dd:'+group['key']+':0'}]
    aids = list(dict.fromkeys(str(d['alert_id']) for d in decisions if re.fullmatch(r'[1-9][0-9]{0,17}', str(d['alert_id']))))
    return [{'text': '🔍 查看告警 #'+aid, 'callback_data': 'ins:'+aid} for aid in aids[:2]]


def decision_actions(group):
    if group['scope'].lower() == 'ip':
        try:
            value = str(ipaddress.ip_address(group['value']))
            return [{'text': '🔓 解封此 IP', 'callback_data': 'unban:'+value},
                    {'text': '🛡️ 加入日志白名单', 'callback_data': 'white:'+value}]
        except ValueError:
            pass
    return []


def module_decisions(page=0, target=None, ip=None, details=False):
    refresh = {'inline_keyboard': [page_controls('dec', 0, 1)]}
    try:
        groups = decision_groups()
        intro = '范围：本地及手动来源，最多 50 条告警；不含云端情报。'
        if ip is not None:
            ip = validated_ip(ip)
            refresh = {'inline_keyboard': [[{'text': '🔄 刷新', 'callback_data': 'dip:'+ip}],
                                           [{'text': '⬅️ 返回列表', 'callback_data': 'dec:0'}]]}
            group = next((g for g in groups if g['scope'].lower() == 'ip'
                          and str(ipaddress.ip_address(g['value'])) == ip), None)
            if group is None:
                return ('本次未查到 IP <code>'+esc(ip)+'</code> 的处置要求。\n可能已到期或不在查询范围内。\n'+intro, refresh)
            target = group['key']
        keyboard = []
        if target is not None:
            group = next((g for g in groups if g['key'] == target), None)
            if group is None:
                return '此目标已不在本次查询结果中，可能已到期或超出范围。', refresh
            entries, page, pages = page_slice(group['decisions'], page)
            base = 'dd:'+target+':'+str(page)
            text = f'📋 <b>处置要求 · {page+1}/{pages}</b>\n目标：<code>{card_esc(group["value"], 64)}</code>\n共 {len(group["decisions"])} 条要求\n'
            for d in entries:
                text += f'\n告警 #{card_esc(d["alert_id"], 12)} · '+disposition(d.get('type'))+'\n'
                text += '剩余：'+display_duration(d.get('duration'))+(' · 模拟' if d['simulated'] else '')+'\n'
                text += '规则：<code>'+card_esc(d.get('scenario'), 55)+'</code>\n'
                if details:
                    text += '来源：'+card_esc(d.get('origin'), 16)+' · 决策 #'+card_esc(d.get('id'), 12)+'\n'
                    text += '原始时长：'+card_esc(d.get('duration'), 24)+'\n'
                row = decision_buttons(group, [d], detail=True)
                if row:
                    keyboard.append(row)
            actions = decision_actions(group)
            if actions:
                keyboard.append(actions)
            prefix = ('more:' if details else '')+'dd:'+target
        else:
            entries, page, pages = page_slice(groups, page)
            base = 'dec:'+str(page)
            total = sum(len(g['decisions']) for g in groups)
            text = f'🚫 <b>封禁列表 · {page+1}/{pages}</b>\n本次查到：{len(groups)} 个目标 · {total} 条处置要求\n'
            if not entries:
                text += '\n本次查询未找到有效处置要求。\n'
            for group in entries:
                ds, d = group['decisions'], group['decisions'][0]
                simulation = ' · 模拟' if all(x['simulated'] for x in ds) else (' · 含模拟' if any(x['simulated'] for x in ds) else '')
                text += f'\n<code>{card_esc(group["value"], 64)}</code>'+simulation+'\n'
                text += ('其中一条：' if len(ds)>1 else '')+disposition(d.get('type'))+' · 剩余 '+display_duration(d.get('duration'))+'\n'
                text += f'{len(ds)} 条要求 · 查看要求\n'
                if details:
                    text += '规则：'+card_esc(d.get('scenario'), 55)+' · 来源：'+card_esc(d.get('origin'), 16)+'\n'
                keyboard.append(decision_buttons(group, ds))
            prefix = ('more:' if details else '')+'dec'
        text += '\n'+intro
        if details:
            text += '\n这里显示处置要求；实际执行情况请查看拦截记录。刷新后列表可能变化。'
        keyboard.append(page_controls(prefix, page, pages))
        keyboard.append([detail_button(base, details)])
        if target is not None:
            keyboard.append([{'text': '⬅️ 返回列表', 'callback_data': 'dec:0'}])
        return text, {'inline_keyboard': keyboard}
    except (RuntimeError, ValueError, TypeError, KeyError):
        return '暂时无法查询处置要求，请稍后刷新。', refresh


def web_install_records():
    path = Path(CSCLI_CONFIG).parent/'crowdsec-1key-web-installs.json'
    if not path.exists():
        return {}, None
    try:
        # Installation records contain credentials: never display their contents.
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise ValueError('Invalid record')
        return data, None
    except (OSError, ValueError):
        return {}, '安装记录不可读或格式无效'


def web_config_status(name, records, error):
    if error:
        return '暂时无法核对'
    if name not in records:
        return '无本工具安装记录'
    entry = records[name]
    if not isinstance(entry, dict):
        return '安装记录格式无效'
    if entry.get('status') != 'installed':
        return '安装记录状态: '+card_esc(entry.get('status', '未知'), 24)
    try:
        actual = hashlib.sha256(Path(entry['host_target']).read_bytes()).hexdigest()
        return '与安装记录一致' if actual == entry['installed_sha'] else '⚠️ 与安装记录不同'
    except (OSError, ValueError, TypeError, KeyError):
        return '暂时无法核对'


def module_sites(page=0, details=False):
    refresh = {'inline_keyboard': [page_controls('site', 0, 1)]}
    try:
        raw = run_cmd(['docker', 'ps', '-a', '--format', '{{json .}}'])
        containers = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if any(not isinstance(c, dict) or not c.get('ID') or not c.get('Names') for c in containers):
            raise ValueError('Invalid container summary')
        containers.sort(key=lambda c: c['Names'])
        entries, page, pages = page_slice(containers, page)
        records, error = web_install_records()
        text = f'📦 <b>容器状态 · {page+1}/{pages}</b>\n共 {len(containers)} 个，包含已停止的容器\n'
        if not entries:
            text += '\n未找到 Docker 容器。\n'
        status_names = {'running': '运行中', 'exited': '已停止', 'restarting': '重启中',
                        'paused': '已暂停', 'created': '已创建', 'dead': '异常'}
        health_names = {'healthy': '正常', 'unhealthy': '异常', 'starting': '检查中'}
        for container in entries:
            state_value = container.get('State', '未记录')
            text += f'\n<b>{card_esc(container["Names"], 48)}</b>\n运行：'+card_esc(status_names.get(state_value, state_value), 24)+'\n'
            try:
                state = json.loads(run_cmd(['docker', 'inspect', '--format', '{{json .State}}', container['ID']]))
                if not isinstance(state, dict):
                    raise ValueError('Invalid state')
                health = (state.get('Health') or {}).get('Status', '未设置')
                text += '健康检查：'+card_esc(health_names.get(health, health), 28)+'\n'
                if details:
                    text += '启动时间：'+display_time(state.get('StartedAt'))+'\n'
            except (RuntimeError, ValueError, TypeError, AttributeError):
                text += '健康检查：暂时无法查询\n'
            status = web_config_status(container['Names'], records, error)
            text += '主配置：'+status+'\n'
            if details:
                text += 'Docker 摘要：'+card_esc(container.get('Status'), 60)+'\n'
                text += '原始状态：'+card_esc(state_value, 20)+'\n'
        if error and not entries:
            text += '主配置：暂时无法核对\n'
        text += '\n本页未检查网站访问和实际拦截。'
        if details:
            text += '\n仅核对主配置文件；未检查挂载、资源文件或运行时加载。其他接入方式未检查。'
        prefix = ('more:' if details else '')+'site'
        return text, {'inline_keyboard': [page_controls(prefix, page, pages), [detail_button('site:'+str(page), details)]]}
    except (RuntimeError, ValueError, TypeError, KeyError):
        return '暂时无法查询容器，请检查 Docker 服务或权限。', refresh


def home_card():
    return ('📱 <b>主菜单</b>\n选择下方功能。\n封禁、解封等操作会先请你确认。',
            {'inline_keyboard': [[{'text': VIEWS[key].label, 'callback_data': 'nav:'+key}
                                  for key in row] for row in MAIN_MENU]})


DETAIL_VIEWS = {'overview', 'forensics', 'runtime', 'posture', 'sources', 'paths',
                'status', 'top', 'decisions', 'sites'}


def render_view(view_id, *args, refresh_data=None, details=False, **kwargs):
    """Normalize existing renderers into cards with the same navigation rules."""
    if view_id == 'home':
        return home_card()
    view = VIEWS[view_id]
    if view_id in DETAIL_VIEWS:
        kwargs['details'] = details
    result = globals()[view.renderer](*args, **kwargs)
    text, markup = result if isinstance(result, tuple) else (result, None)
    rows = [[dict(button) for button in row] for row in (markup or {}).get('inline_keyboard', [])]
    navigation = []
    base = refresh_data or 'nav:'+view_id
    if view.refresh:
        navigation.append({'text': '🔄 刷新', 'callback_data': ('more:' if details else '')+base})
    if view_id in DETAIL_VIEWS-{'forensics', 'decisions', 'sites'}:
        rows.append([detail_button(base, details)])
    if view.parent != 'home':
        navigation.append({'text': '⬅️ 返回'+VIEWS[view.parent].label, 'callback_data': 'nav:'+view.parent})
    if navigation:
        rows.append(navigation)
    rows.append([{'text': '🏠 主菜单', 'callback_data': 'nav:home'}])
    return text, {'inline_keyboard': rows}


def send_view(view_id, *args, **kwargs):
    text, keyboard = render_view(view_id, *args, **kwargs)
    return send_message(text, reply_markup=keyboard)


def handle_view_callback(callback):
    if not authorized(callback):
        return False
    data = callback.get('data', '')
    message_id = callback.get('message', {}).get('message_id')
    if not isinstance(data, str) or not message_id:
        return False
    details = data.startswith('more:')
    if details:
        data = data[5:]
    view_id, kwargs = None, {}
    match = re.fullmatch(r'(dec|site):(\d{1,6})', data)
    detail = re.fullmatch(r'dd:([a-f0-9]{16}):(\d{1,6})', data)
    inspect = re.fullmatch(r'ins:([1-9]\d{0,17})', data)
    execution = re.fullmatch(r'exp:([1-9]\d{0,11})', data)
    execution_detail = re.fullmatch(r'exd:([1-9]\d{0,11}):(\d{1,6})', data)
    if data.startswith('nav:') and data[4:] in (*VIEWS, 'home'):
        view_id = data[4:]
    elif match:
        view_id = 'decisions' if match[1] == 'dec' else 'sites'
        kwargs = {'page': int(match[2])}
    elif detail:
        view_id, kwargs = 'decisions', {'page': int(detail[2]), 'target': detail[1]}
    elif inspect:
        view_id, kwargs = 'forensics', {'alert_id': int(inspect[1]), 'refresh_data': data}
    elif data.startswith('dip:'):
        try:
            kwargs = {'ip': validated_ip(data[4:])}
        except ValueError:
            return False
        view_id = 'decisions'
    elif execution:
        view_id = 'execution'
        kwargs = {'alert_id': int(execution[1])}
    elif execution_detail:
        view_id, details = 'execution', True
        kwargs = {'alert_id': int(execution_detail[1]), 'decision_page': int(execution_detail[2])}
    elif data == 'em:view_white':
        view_id = 'whitelist'
    if view_id is None:
        return False
    if details and view_id not in DETAIL_VIEWS | {'execution'}:
        return False
    answer_callback(callback['id'], '正在查询…')
    if view_id == 'execution':
        text, keyboard = module_execution(details=details, **kwargs)
    else:
        text, keyboard = render_view(view_id, details=details, **kwargs)
    tg_request('editMessageText', {'chat_id': ADMIN_CHAT_ID, 'message_id': message_id,
        'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True, 'reply_markup': keyboard})
    return True


def module_emergency_manager():
    return ('🛠 <b>管理工具</b>\n选择操作，执行前会再次确认。', {'inline_keyboard': [
        [{'text': '📋 查看日志白名单', 'callback_data': 'nav:whitelist'}],
        [{'text': '🔄 重载检测服务', 'callback_data': 'em:reload_cs'}],
        [{'text': '🧹 释放文件缓存', 'callback_data': 'em:drop_caches'}]]})


def module_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return '📋 日志白名单\n未找到本工具管理的日志白名单。'
    return module_command(['cat', WHITELIST_FILE], '日志白名单')+'\n作用：在日志检测流程中加白。网站检查和云端封禁可能仍然生效。'


def module_help():
    lines = ['❓ <b>使用帮助</b>', '查告警：最近告警 → 告警详情', '查拦截：告警详情 → 拦截记录',
             '查封禁：封禁列表', '做操作：管理工具，或使用下方命令', '', '<code>/start</code> — 打开主菜单']
    lines.extend('<code>/'+view.command+esc(view.usage)+'</code> — '+view.description
                 for view in VIEWS.values() if view.command)
    lines.extend('<code>/'+command+esc(usage)+'</code> — '+description
                 for command, usage, description in ACTION_COMMANDS)
    lines.extend(['', '网站拒绝记录：查询该来源的网站请求拒绝记录。',
                  '防火墙名单：查询该 IP 是否进入封禁集合，实际丢包尚未验证。',
                  '未查到网站记录可能是没有新访问、先被防火墙拦住，或记录不完整。',
                  '操作需在 60 秒内确认；结果待核对时，请先查询实际状态。'])
    return '\n'.join(lines)


def validated_ip(value):
    return str(ipaddress.ip_address(value.strip()))


def action_ban(ip, dur='4h'):
    try:
        ip = validated_ip(ip)
        if not re.fullmatch(r'(?:[1-9][0-9]*[smh])+', dur):
            raise ValueError('时长无效')
    except ValueError:
        return '❌ IP 或封禁时长无效。'
    try:
        from crowdsec_safety import guard
        interfaces = run_cmd(['ip', '-j', 'address', 'show'])
        guard(ip, Path(CSCLI_CONFIG).parent, '', interfaces)
    except Exception:
        # Invalid YAML and command errors may contain private configuration.
        return '❌ 封禁安全检查未通过，未添加封禁。请核对本机与管理员地址保护。'
    try:
        run_cmd(['cscli', 'decisions', 'add', '--ip', ip, '--duration', dur, '--reason', 'manual_tg'])
        return f'✅ 已添加封禁要求\nIP：<code>{esc(ip)}</code> · 时长：{display_duration(dur)}\n实际执行情况请查看拦截记录。'
    except CommandUncertain:
        raise
    except RuntimeError:
        return '❌ 添加封禁要求失败。'


def action_unban(ip):
    try:
        ip = validated_ip(ip)
        run_cmd(['cscli', 'decisions', 'delete', '--ip', ip])
        return f'✅ 已提交解封\nIP：<code>{esc(ip)}</code>\n防护组件同步后生效。'
    except CommandUncertain:
        raise
    except ValueError:
        return '❌ IP 无效。'
    except RuntimeError:
        return '❌ 解封失败。'


def replace_private(path, content):
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.bot-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def action_whitelist(ip):
    previous = None
    changed = False
    loaded = False
    try:
        ip = validated_ip(ip)
        if os.path.islink(WHITELIST_FILE):
            raise ValueError('不接受符号链接')
        if os.path.exists(WHITELIST_FILE):
            previous = Path(WHITELIST_FILE).read_text(encoding='utf-8')
            # Only modify our own stable YAML format; preserve unknown files.
            if not previous.startswith('name: custom/tg-whitelist\n'):
                return '❌ 白名单文件归属/格式未知，未修改；请先迁移原文件。'
            ips = re.findall(r'^    - "([^"\n]+)"$', previous, re.M)
            ips = [validated_ip(item) for item in ips]
            expected = 'name: custom/tg-whitelist\ndescription: Telegram managed whitelist\nwhitelist:\n  reason: Telegram administrator\n  ip:\n'+''.join('    - '+json.dumps(item)+'\n' for item in ips)
            if previous != expected:
                return '❌ 白名单文件包含非本工具字段或格式，未修改。'
        else:
            ips = []
        if ip not in ips:
            ips.append(ip)
        content = 'name: custom/tg-whitelist\ndescription: Telegram managed whitelist\nwhitelist:\n  reason: Telegram administrator\n  ip:\n'+''.join('    - '+json.dumps(item)+'\n' for item in ips)
        replace_private(WHITELIST_FILE, content)
        changed = True
        run_cmd(['crowdsec', '-c', CSCLI_CONFIG, '-t'], timeout=30)
        run_cmd(['systemctl', 'reload', 'crowdsec'])
        loaded = True
        changed = False
        run_cmd(['cscli', 'decisions', 'delete', '--ip', ip])
        return f'✅ 已更新日志白名单并提交解封\nIP：<code>{esc(ip)}</code>\n网站检查和云端封禁仍可能阻止访问。'
    except ValueError:
        return '❌ IP 或白名单文件格式无效。'
    except (RuntimeError, OSError) as error:
        if changed:
            try:
                if previous is None:
                    os.unlink(WHITELIST_FILE)
                else:
                    replace_private(WHITELIST_FILE, previous)
                run_cmd(['systemctl', 'reload', 'crowdsec'])
            except (RuntimeError, OSError):
                raise CommandUncertain('白名单恢复或重载未完成，结果待核对') from None
            if isinstance(error, CommandUncertain):
                raise error
            return '❌ 加白失败，已恢复原白名单文件。'
        if isinstance(error, CommandUncertain):
            raise error
        return '❌ 白名单已加载，但解封失败，请核对现有决策。' if loaded else '❌ 白名单读取或写入失败，未加载新配置。'


def module_command(args, label):
    try:
        output = run_cmd(args)
        return '<b>'+esc(label)+'</b>\n<pre>'+esc(output, 2500)+'</pre>'
    except RuntimeError:
        return '暂时无法查询'+esc(label)+'，请检查服务或权限。'


def reload_engine():
    try:
        run_cmd(['crowdsec', '-c', CSCLI_CONFIG, '-t'], timeout=30)
    except RuntimeError:
        return '❌ 配置校验失败或超时，未提交重载。'
    try:
        run_cmd(['systemctl', 'reload', 'crowdsec'])
        return '✅ CrowdSec 已重载。'
    except CommandUncertain:
        raise
    except RuntimeError:
        return '❌ 校验或重载失败。'


def drop_caches():
    try:
        os.sync()
        with open('/proc/sys/vm/drop_caches', 'w') as stream:
            stream.write('3\n')
        return '✅ 已请求释放文件缓存。\n应用占用的内存不一定减少。'
    except OSError:
        return '❌ 缓存释放失败或权限不足。'


# ==================== 后台监听与严密过滤 ====================
def background_alert_watcher():
    """实时监听新增告警并主动推卡片到 TG（严密过滤云端情报同步）"""
    last_id = 0
    conn = get_db_conn()
    if conn:
        try:
            r = conn.execute("SELECT max(id) FROM alerts").fetchone()
            if r and r[0]:
                last_id = r[0]
        except Exception:
            pass
        conn.close()

    while True:
        time.sleep(3)
        conn = get_db_conn()
        if not conn:
            continue
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, scenario, source_ip FROM alerts WHERE id > ? ORDER BY id ASC", (last_id,))
            alerts = cur.fetchall()
            for aid, sc, ip in alerts:
                last_id = max(last_id, aid)
                sc_str = str(sc or "").strip().lower()
                ip_str = str(ip or "").strip()

                # 核心防骚扰过滤：若是云端情报同步 (+15000/-0 IPs) 或无 IP，静默忽略
                if "update" in sc_str or not ip_str or "capi" in sc_str:
                    continue

                # 只有真正外部黑客来犯才报警！
                txt, kb = module_forensics(aid)
                send_message(f"🚨 <b>新告警</b>\n\n{txt}", reply_markup=kb)
        except Exception:
            pass
        finally:
            conn.close()

def request_action(action, params):
    """Both commands and legacy buttons enter this preview, never execute directly."""
    labels = {'ban': '封禁', 'unban': '解封', 'white': '加入日志白名单',
              'reload': '重载 CrowdSec', 'drop_caches': '释放文件缓存'}
    try:
        if action not in labels:
            raise ValueError('unknown action')
        if action in ('ban', 'unban', 'white'):
            params = [validated_ip(params[0]), *params[1:]]
        if action == 'ban' and (len(params) != 2 or not re.fullmatch(r'(?:[1-9][0-9]*[smh])+', params[1])):
            raise ValueError('invalid duration')
        nonce = get_action_store().offer(action, params, ADMIN_USER_ID, ADMIN_CHAT_ID)
    except (ValueError, IndexError, TypeError):
        send_message('❌ 参数格式不正确，本次未执行。')
        return
    text = '⚠️ <b>确认'+labels[action]+'？</b>\n'
    if params:
        text += 'IP：<code>'+esc(params[0])+'</code>\n'
    if action == 'ban':
        text += '时长：'+display_duration(params[1])+'\n将添加封禁要求，执行前会检查管理地址保护。\n'
    elif action == 'unban':
        text += '将删除该 IP 的全部处置要求。防护组件同步后生效。\n'
    elif action == 'white':
        text += '将更新白名单、重载检测服务，并删除该 IP 的全部处置要求。\n网站检查和云端封禁仍可能阻止访问。\n'
    elif action == 'reload':
        text += '先检查配置，再重载检测服务。\n'
    else:
        text += '将先写回数据，再释放系统文件缓存。应用占用的内存不一定减少。\n'
    text += '请在 60 秒内确认。'
    send_message(text, {'inline_keyboard': [[
        {'text': '确认执行', 'callback_data': 'yes:'+nonce},
        {'text': '取消', 'callback_data': 'no:'+nonce}]]})


def execute_confirmed(ticket):
    store = get_action_store()
    try:
        store.begin(ticket)
    except (OSError, ValueError):
        return '❌ 无法保存操作记录，未执行；请核对状态目录后重新发起。'
    try:
        actions = {'ban': action_ban, 'unban': action_unban, 'white': action_whitelist,
                   'reload': reload_engine, 'drop_caches': drop_caches}
        result = actions[ticket['action']](*ticket['params'])
        outcome = 'success' if result.startswith('✅') else 'failed'
    except Exception:
        # A command may have completed before its caller failed. Never replay it.
        outcome, result = 'unknown', '⚠️ 操作结果待核对\n请先查询实际状态，再决定是否重试。'
    try:
        store.finish(ticket, outcome, result)
    except (OSError, ValueError):
        result += '\n⚠️ 操作记录未保存完整，请先核对实际结果。'
    return result+'\n操作 ID: <code>'+esc(ticket['id'])+'</code>'


def handle_action_callback(callback):
    data = callback.get('data', '')
    notice = re.fullmatch(r'(na|nd):([a-f0-9]{24})', data)
    if notice:
        try:
            result = sibling('crowdsec_notify_client').bot_request(
                Path(CSCLI_CONFIG).parent/'crowdbastion-notify.json', BOT_TOKEN, ADMIN_CHAT_ID,
                'ack' if notice[1] == 'na' else 'detail', notice[2])
            if notice[1] == 'na':
                answer_callback(callback['id'], '已知晓；恢复和升级仍会通知' if result.get('acknowledged') else '事件已结束或不存在')
            else:
                answer_callback(callback['id'])
                send_message(esc(result['text']))
        except (OSError, ValueError, TypeError, KeyError):
            answer_callback(callback['id'], '通知服务暂不可用，请检查服务状态', alert=True)
        return True
    match = re.fullmatch(r'(yes|no):([A-Za-z0-9_-]{16,64})', data)
    if match:
        store = get_action_store()
        if match[1] == 'no':
            cancelled = store.cancel(match[2], ADMIN_USER_ID, ADMIN_CHAT_ID)
            answer_callback(callback['id'], '已取消，本次未执行' if cancelled else '此确认已失效或已处理，请先核对结果')
            return True
        ticket = store.take(match[2], ADMIN_USER_ID, ADMIN_CHAT_ID)
        if ticket is None:
            answer_callback(callback['id'], '确认已失效或已处理，请先核对结果', alert=True)
            return True
        answer_callback(callback['id'], '正在执行，请稍候…')
        result = execute_confirmed(ticket)
        message_id = callback.get('message', {}).get('message_id')
        if message_id:
            tg_request('editMessageText', {'chat_id': ADMIN_CHAT_ID, 'message_id': message_id,
                       'text': result, 'parse_mode': 'HTML', 'reply_markup': {'inline_keyboard': []}})
        else:
            send_message(result)
        return True
    for prefix, action in (('unban:', 'unban'), ('white:', 'white')):
        if data.startswith(prefix):
            answer_callback(callback['id'], '请核对操作影响并确认')
            request_action(action, [data[len(prefix):]])
            return True
    emergency = {'em:drop_caches': 'drop_caches', 'em:reload_cs': 'reload'}
    if data in emergency:
        answer_callback(callback['id'], '请核对操作影响并确认')
        request_action(emergency[data], [])
        return True
    return False


def handle_update(update):
    if 'callback_query' in update:
        callback = update['callback_query']
        if not authorized(callback):
            return
        if handle_action_callback(callback) or handle_view_callback(callback):
            return
        return
    message = update.get('message', {})
    if not authorized(message):
        return
    text = message.get('text', '').strip()
    parts = text.split()
    cmd = parts[0].lower().split('@')[0] if parts else ''
    if cmd in ('/start', '菜单'):
        send_message(home_card()[0], reply_markup=MAIN_KEYBOARD)
    elif cmd in ('/ban', '/unban', '/white'):
        if len(parts) < 2 or len(parts) > (3 if cmd == '/ban' else 2):
            send_message('❌ 用法: '+esc(cmd)+' IP'+(' [时长]' if cmd == '/ban' else ''))
            return
        params = [parts[1], parts[2] if len(parts) == 3 else '4h'] if cmd == '/ban' else [parts[1]]
        request_action(cmd[1:], params)
    elif cmd == '/inspect':
        if len(parts) > 2 or (len(parts) == 2 and not re.fullmatch(r'[1-9]\d{0,17}', parts[1])):
            send_message('❌ 用法: <code>/inspect [ID]</code>；ID 为正整数。')
            return
        aid = int(parts[1]) if len(parts) == 2 else None
        send_view('forensics', alert_id=aid, refresh_data='ins:'+str(aid) if aid is not None else None)
    else:
        view_id = MENU_ROUTES.get(cmd if text.startswith('/') else text)
        if view_id is not None:
            send_view(view_id)


def wait_for_retry(delay):
    # Long Telegram retry_after values remain observable and interruptible.
    deadline = time.monotonic()+max(0, delay)
    while True:
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 60))


def main():
    # Honor saved polling backoff before startup makes any Telegram requests.
    wait_for_retry(get_api_client().retry_delay())
    register_bot_commands()
    if AUTO_NOTIFY:
        Thread(target=background_alert_watcher, daemon=True).start()
    try:
        offset = max(0, int(Path(offset_path()).read_text()))
    except (OSError, ValueError):
        offset = 0
    while True:
        try:
            updates = tg_request(f'getUpdates?offset={offset}&timeout=20')
            if not updates or not updates.get('ok'):
                wait_for_retry(get_api_client().retry_delay())
                continue
            for update in updates.get('result', []):
                try:
                    update_id = update.get('update_id')
                    if type(update_id) is not int or update_id < offset:
                        continue
                    # Claim before handling; crashes can lose a request but cannot replay a mutation.
                    offset = update_id+1
                    save_offset(offset)
                    handle_update(update)
                except Exception:
                    print('Telegram 单条更新处理失败；请查询状态后重新发起。', file=sys.stderr)
        except Exception:
            print('Telegram 轮询处理失败；稍后重试。', file=sys.stderr)
            wait_for_retry(2)

def cli():
    parser = argparse.ArgumentParser(description='CrowdBastion 交互机器人；CrowdSec 官方通道负责自动告警')
    parser.add_argument('--config', default='/etc/crowdsec/crowdsec-1key-bot.json')
    parser.add_argument('--check-config', action='store_true')
    parser.add_argument('--runtime-status', action='store_true', help='只读显示轮询、投递和待核对操作记录')
    args = parser.parse_args()
    if args.runtime_status or args.check_config:
        sys.dont_write_bytecode = True
    try:
        load_settings(args.config)
        if args.check_config:
            print('机器人配置格式有效；未连接 Telegram，也未验证运行状态。')
            return 0
        if args.runtime_status:
            print(runtime_status_text())
            report = sibling('crowdsec_bot_api').read_runtime(STATE_DIR, BOT_TOKEN)
            if report['status'] == 'error':
                return 1
            if report['status'] != 'healthy' or get_action_store().unfinished():
                return 2
            return 0
        acquire_instance_lock()
        main()
    except (OSError, ValueError, KeyError, RuntimeError):
        print('机器人启动失败：配置无效、文件不可读或存在重复实例。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(cli())

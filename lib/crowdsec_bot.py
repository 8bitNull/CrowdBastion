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
    'overview': MenuView('📊 防护总览', 'module_system_status', 'overview', '防护健康与系统资源', ('📊 系统大屏',)),
    'alerts': MenuView('🚨 最近告警', 'module_recent_alerts', 'alerts', '查看最近告警', ('🚨 最新告警',)),
    'decisions': MenuView('🚫 封禁决策', 'module_decisions', 'decisions', '查看当前封禁决策', ('🚫 封禁名单',), refresh=False),
    'forensics': MenuView('🔍 告警取证', 'module_forensics', 'inspect', '调阅指定或最新告警', ('🔍 取证穿透',),
                          parent='alerts', usage=' [ID]'),
    'analysis': MenuView('📈 攻击分析', 'module_analysis', 'analysis', '告警统计与日志抽样分析', refresh=False),
    'sites': MenuView('📦 容器状态', 'module_sites', 'containers', '容器健康与接入配置', ('🌐 站点体检',), refresh=False),
    'runtime': MenuView('🤖 机器人状态', 'module_bot_status', 'bot', '轮询、投递与待核对操作'),
    'tools': MenuView('🛠 运维工具', 'module_emergency_manager', 'tools', '查看白名单与运维操作', ('⚡ 应急管家',), refresh=False),
    'help': MenuView('❓ 使用帮助', 'module_help', 'help', '查看命令与操作说明', ('帮助',), refresh=False),
    'posture': MenuView('🛡️ 告警统计', 'module_attack_posture', aliases=('🛡️ 攻击态势',), parent='analysis'),
    'sources': MenuView('🔎 可疑来源', 'module_top_hackers', aliases=('💀 黑客榜单',), parent='analysis'),
    'paths': MenuView('🎯 请求路径', 'module_top_targets', aliases=('🎯 漏洞靶心',), parent='analysis'),
    'whitelist': MenuView('📋 日志解析白名单', 'module_whitelist', parent='tools'),
    'status': MenuView('🩺 综合状态', 'module_status', 'status', '防护健康与机器人运行状态'),
    'top': MenuView('📈 日志抽样排行', 'module_top', 'top', '可疑来源与请求路径排行', parent='analysis'),
}
MAIN_MENU = (('overview', 'alerts', 'decisions'), ('forensics', 'analysis', 'sites'),
             ('runtime', 'tools', 'help'))
ACTION_COMMANDS = (('ban', ' IP [时长]', '手动封禁 IP（需确认）'),
                   ('unban', ' IP', '删除此 IP 全部决策（需确认）'),
                   ('white', ' IP', '永久加入日志解析白名单（需确认）'))
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
def module_system_status():
    """📊 系统大屏"""
    load = os.getloadavg()
    with open('/proc/meminfo', 'r') as f:
        m = {line.split(':')[0].strip(): int(line.split(':')[1].split()[0]) for line in f if ':' in line}
    mem_total = m.get('MemTotal', 1) / 1024
    mem_used = mem_total - (m.get('MemAvailable', 1) / 1024)
    mem_pct = (mem_used / mem_total) * 100
    st = os.statvfs('/')
    d_total = (st.f_blocks * st.f_frsize) / (1024**3)
    d_used = d_total - ((st.f_bavail * st.f_frsize) / (1024**3))
    uptime_h = int(float(Path('/proc/uptime').read_text().split()[0]) // 3600)
    ban_cnt = None
    conn = get_db_conn()
    if conn:
        try:
            ban_cnt = conn.execute("SELECT count(*) FROM decisions WHERE until > datetime('now')").fetchone()[0]
        except Exception:
            pass
        conn.close()
    count_text = '未知（数据库不可读或查询失败）' if ban_cnt is None else str(ban_cnt)+' 条'
    return f"""📊 <b>【{esc(os.uname().nodename, 80)} 防护总览】</b>
━━━━━━━━━━━━━━━━━━
⏱️ <b>持续运行</b>: <code>{uptime_h} 小时</code>
⚙️ <b>系统负载</b>: <code>{load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}</code>
🧠 <b>内存状态</b>: <code>{mem_used:.0f}M / {mem_total:.0f}M ({mem_pct:.1f}%)</code>
💾 <b>系统磁盘</b>: <code>{d_used:.1f}G / {d_total:.1f}G</code>
🛡️ <b>有效决策总数</b>: <code>{count_text}</code>
━━━━━━━━━━━━━━━━━━
<i>资源为当前采样，不代表内存容量验收。</i>

{module_health_status()}"""


def module_health_status():
    global _HEALTH_COLLECTOR
    try:
        # The collector imports only these installed, shared standard-library helpers.
        sibling('crowdbastion_health')
        sibling('crowdbastion_node')
        if _HEALTH_COLLECTOR is None or _HEALTH_COLLECTOR[0] != CSCLI_CONFIG:
            _HEALTH_COLLECTOR = (CSCLI_CONFIG, sibling('crowdsec_bot_health').HealthCollector(CSCLI_CONFIG))
        report = _HEALTH_COLLECTOR[1].collect()
        labels = {'ok': '正常', 'fault': '异常', 'missing': '未配置', 'unknown': '未知',
                  'pending': '待确认', 'optional': '未配置（可选）', 'verified': '已验证'}
        names = {'core': 'CrowdSec', 'api': 'LAPI', 'bouncer': 'Firewall Bouncer',
                 'registry': 'Bouncer 登记', 'metrics': '指标读取', 'logs': '日志解析', 'remote': '远端连接'}
        lines = ['🩺 <b>防护健康摘要</b>', '范围: '+esc(report['scope'], 100)]
        for key, name in names.items():
            if key in report['checks']:
                lines.append(name+': '+labels.get(report['checks'][key], '未知'))
        summary = report['summary']
        lines.append('结论: '+esc(summary['verdict'], 100))
        if summary.get('attention'):
            lines.append('需要关注: '+esc(summary['attention'], 160))
        if summary.get('impact'):
            lines.append('影响: '+esc(summary['impact'], 160))
        lines.append('下一步: '+esc(summary['next'], 220))
        lines.append('实际拦截: 待独立核验；组件状态不证明具体请求已被拦截。')
        lines.append('采样: '+datetime.fromtimestamp(report['checked_at'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
        return '\n'.join(lines)
    except (OSError, ValueError, RuntimeError, ImportError, KeyError, TypeError):
        return '🩺 防护健康摘要: 未知，检查未完成；请核对诊断依赖与运行权限。'


def runtime_status_text():
    api = sibling('crowdsec_bot_api')
    text = api.describe_runtime(api.read_runtime(STATE_DIR, BOT_TOKEN))
    try:
        pending = get_action_store().unfinished()
        if pending:
            text += '\n操作结果待核对（不会自动重放）:'
            for item in pending:
                text += '\n'+item['action']+' '+ ' '.join(item['params'])+' / '+item['id']
    except (OSError, ValueError):
        text += '\n操作记录不可读，请在本机核对。'
    return text


def module_status():
    return module_health_status()+'\n\n<b>Telegram 与操作状态</b>\n<pre>'+esc(runtime_status_text(), 2000)+'</pre>'


def module_bot_status():
    return '🤖 <b>机器人状态</b>\n<pre>'+esc(runtime_status_text(), 2000)+'</pre>'


def module_analysis():
    return ('📈 <b>攻击分析</b>\n告警统计读取近 24 小时 CrowdSec 告警；'
            '可疑来源和请求路径来自 NPM 日志有限抽样。\n请选择要查看的分析。',
            {'inline_keyboard': [[{'text': VIEWS[key].label, 'callback_data': 'nav:'+key}]
                                 for key in ('posture', 'sources', 'paths')]})


def module_top():
    return module_top_hackers()+'\n\n'+module_top_targets()


def module_attack_posture():
    """🛡️ 攻击态势（24小时战报，严密排除云端同步更新）"""
    conn = get_db_conn()
    if not conn:
        return "❌ 无法读取数据库"
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    sc_cnt, ip_cnt = Counter(), Counter()
    try:
        cur = conn.cursor()
        rows = cur.execute("""
            SELECT scenario, source_ip
            FROM alerts
            WHERE created_at >= ?
              AND scenario NOT LIKE '%update%'
              AND source_ip IS NOT NULL
              AND source_ip != ''
        """, (day_ago,)).fetchall()
        for r in rows:
            sc_cnt[r[0]] += 1
            ip_cnt[r[1]] += 1
    except Exception as e:
        conn.close()
        return f"❌ 查询异常: {html.escape(str(e))}"
    conn.close()
    rules_txt = "".join([f"• <code>{html.escape(k.split('/')[-1])}</code>: {v} 次\n" for k, v in sc_cnt.most_common(3)]) or "• <i>近24小时内未产生新增威胁</i>\n"
    return f"""🛡️ <b>【24小时全网防御态势战报】</b>
━━━━━━━━━━━━━━━━━━
📈 <b>24H 告警</b>: <b>{len(rows)}</b> 次
👾 <b>告警来源 IP</b>: <b>{len(ip_cnt)}</b> 个
🔥 <b>主流攻击类型</b>:
{rules_txt}━━━━━━━━━━━━━━━━━━
💡 <i>提示：告警统计不证明 Bouncer 已实际拦截。</i>"""

def module_recent_alerts():
    """🚨 最新告警（只呈现真实外部黑客）"""
    conn = get_db_conn()
    if not conn:
        return "❌ 数据库离线", None
    try:
        alerts = conn.execute("""
            SELECT id, source_ip, source_country, scenario, created_at
            FROM alerts
            WHERE scenario NOT LIKE '%update%'
              AND source_ip IS NOT NULL
              AND source_ip != ''
            ORDER BY id DESC LIMIT 5
        """).fetchall()
    except Exception as e:
        conn.close()
        return f"❌ 查询失败: {e}", None
    conn.close()
    if not alerts:
        return "✅ 当前查询未找到告警；不代表防护已验证。", None
    txt = "🚨 <b>【最近告警 (Top 5)】</b>\n━━━━━━━━━━━━━━━━━━\n"
    kb = []
    for a in alerts:
        aid, ip, country, sc, created = a
        txt += f"<b>#{aid}</b> | <code>{html.escape(ip)}</code> ({html.escape(country or '未知')})\n   └ 规则: <code>{html.escape(sc.split('/')[-1])}</code>\n   └ 时间: <code>{created}</code>\n\n"
        kb.append([{"text": f"🔍 取证 #{aid}", "callback_data": f"ins:{aid}"}])
    return txt.strip(), {"inline_keyboard": kb}

def module_top_hackers():
    """💀 黑客榜单（Top 10 恶意扫描 IP 排行）"""
    raw = read_log_tail_chunks()
    if not raw:
        return "⚠️ 可疑来源: 暂无可读取的 NPM 日志抽样。"
    m = re.findall(r'(?:GET|POST|HEAD) [^\"]*(?:\.env|\.\./|phpmyadmin|actuator|pearcmd|\.git|wp-login|\.bak)[^\"]* [^\[]*\[Client ([a-fA-F0-9:.]+)\]', raw, re.I) or re.findall(r' (?:404|403) [^\[]*\[Client ([a-fA-F0-9:.]+)\]', raw)
    counts = Counter(m).most_common(10)
    if not counts:
        return "可疑来源: 本次日志抽样未匹配到可疑请求；不代表没有攻击。"
    txt = "🔎 <b>【可疑来源 IP (Top 10)】</b>\n━━━━━━━━━━━━━━━━━━\n"
    for idx, (ip, cnt) in enumerate(counts, 1):
        txt += f"<b>{idx}.</b> <code>{html.escape(ip)}</code> ➔ <b>{cnt}</b> 次探测\n"
    return txt + "━━━━━━━━━━━━━━━━━━\n<i>NPM 日志有限抽样，按路径/状态码启发式统计，不作为恶意身份或实际拦截的证明。</i>"

def module_top_targets():
    """🎯 漏洞靶心（Top 10 被嗅探敏感路径）"""
    raw = read_log_tail_chunks()
    if not raw:
        return "⚠️ 请求路径: 暂无可读取的 NPM 日志抽样。"
    paths = re.findall(r'(?:GET|POST|HEAD) (/[^ \"?]+)', raw, re.I)
    sensitive = [p for p in paths if any(k in p.lower() for k in ['.env', '..', 'phpmyadmin', 'actuator', 'pearcmd', '.git', 'wp-', '.bak', 'api/', 'login'])]
    counts = Counter(sensitive).most_common(10) or Counter(paths).most_common(10)
    txt = "🎯 <b>【请求路径抽样 (Top 10)】</b>\n━━━━━━━━━━━━━━━━━━\n"
    for idx, (p, cnt) in enumerate(counts, 1):
        disp = p if len(p) <= 32 else p[:29] + "..."
        txt += f"<b>{idx}.</b> <code>{html.escape(disp)}</code> ➔ <b>{cnt}</b> 次\n"
    return txt + "━━━━━━━━━━━━━━━━━━\n<i>NPM 日志有限抽样；请求频率不能单独证明攻击或已拦截。</i>"

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


def module_forensics(alert_id=None):
    try:
        alert = read_alert(alert_id)
        if alert is None:
            return '⚠️ 未找到对应的告警。', None
        source = alert.get('source') or {}
        aid, ip = alert.get('id'), source.get('value', source.get('ip', ''))
        txt = f"🔍 <b>【Alert #{esc(aid)} 告警取证】</b>\n来源: <code>{esc(ip)}</code>\n归属地: {esc(source.get('cn'))} | {esc(source.get('as_name'))}\n规则: <code>{esc(alert.get('scenario'), 100)}</code>\n告警时间: {esc(alert.get('start_at'), 50)}\n"
        if alert.get('simulated') is True:
            txt += '模式: 模拟告警（不代表实际封禁）\n'
        decisions = alert.get('decisions') or []
        if decisions:
            txt += '决策: '+', '.join(esc(d.get('type'), 20)+' / '+esc(d.get('duration'), 20) for d in decisions[:3])+'\n'
        else:
            txt += '决策: 本告警未附带处置决策\n'
        txt += '执行回执: 本页未查询；点击下方“执行核验”查看 Web 拒绝记录和防火墙集合同步状态。\n'
        samples = request_samples(alert)
        for index, (path, ua, method) in enumerate(samples, 1):
            description = '未记录 UA' if ua is None else ('请求未提供 UA' if not ua else ua)
            txt += f"\n请求样本 {index}\n🎯 刺探目标: <code>{esc(method, 12)} {esc(path, 180)}</code>\n🤖 客户端指纹: <code>{esc(description, 100)}</code>\n"
        if not samples:
            txt += '取证: 未记录 HTTP 元数据；非 HTTP 告警不适用路径/UA。\n'
        kb = None
        try:
            parsed_ip = str(ipaddress.ip_address(ip))
            kb = {'inline_keyboard': [[{'text': '📋 查看此 IP 当前决策', 'callback_data': 'dip:'+parsed_ip}]]}
            if type(aid) is int and aid > 0:
                kb['inline_keyboard'].insert(0, [{'text': '🔎 执行核验', 'callback_data': f'exp:{aid}'}])
        except ValueError:
            pass
        return txt, kb
    except (RuntimeError, ValueError, TypeError, KeyError):
        return '❌ 告警查询失败，请检查 cscli 权限、配置和 JSON 输出。', None


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


def module_execution(alert_id):
    keyboard = {'inline_keyboard': [[{'text': '🔄 刷新执行核验', 'callback_data': f'exp:{alert_id}'}],
        [{'text': '⬅️ 返回告警取证', 'callback_data': f'ins:{alert_id}'}],
        [{'text': '🏠 主菜单', 'callback_data': 'nav:home'}]]}
    try:
        alert = read_alert(alert_id)
        if alert is None:
            return '⚠️ 未找到对应的告警。', keyboard
        ip = str(ipaddress.ip_address((alert.get('source') or {}).get('value', '')))
    except (RuntimeError, ValueError, TypeError):
        return '⚠️ 执行核验无法读取告警或来源不是单个 IP。', keyboard
    text = f'🔎 <b>【Alert #{card_esc(alert_id)} 执行核验 · Web】</b>\n来源: <code>{card_esc(ip)}</code>\n'
    if alert.get('simulated') is True:
        text += '模式: 模拟告警；以下为该来源的独立观测，不代表模拟告警产生了封禁。\n'
    try:
        data = json.loads(run_cmd(['cscli', 'decisions', 'list', '--ip', ip, '-l', '20', '-o', 'json']))
        if data is None:
            data = []
        if not isinstance(data, list) or any(not isinstance(a, dict) or
                not isinstance(a.get('decisions', []), list) for a in data):
            raise ValueError('Invalid decisions')
        decisions = [d for a in data for d in (a.get('decisions') or []) if isinstance(d, dict)]
        text += '当前决策（按 IP 查询，最多20条告警）: '
        text += ('、'.join(card_esc(d.get('type'), 20)+' / '+card_esc(d.get('duration'), 20)
                          for d in decisions[:3]) if decisions else '未查到')+'\n'
    except (RuntimeError, ValueError, TypeError):
        text += '当前决策: 查询不可用\n'
    text += '决策存在只表示处置要求。\n'
    now = time.time()
    since = now-86400
    try:
        date = datetime.fromisoformat(str(alert.get('start_at', '')).replace('Z', '+00:00'))
        since = date.replace(tzinfo=date.tzinfo or timezone.utc).timestamp()
    except (ValueError, TypeError, OverflowError):
        text += '告警时间不可用，按最近24小时查询。\n'
    try:
        # Load the installed sibling even when this bot is imported by an audit tool.
        import importlib.util
        spec = importlib.util.spec_from_file_location('crowdbastion_execution', Path(__file__).with_name('crowdsec_execution.py'))
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        evidence = reader.query(EXECUTION_LOG_DIRS or [NPM_LOG_DIR], ip, since, now=now)
        if evidence['state'] == 'observed':
            text += f"✅ 已记录同源 Web 拒绝: {evidence['count']} 条（日志抽样）\n"
            text += '原因: '+'、'.join(reader.CAUSES[k]+f' {v} 条' for k,v in evidence['causes'].items())+'\n'
            last = evidence['records'][0]
            date = datetime.fromtimestamp(last['time'], timezone.utc).strftime('%m-%d %H:%M:%S UTC')
            text += f"最后记录: {date} / HTTP {last['status']} / 未访问业务上游\n请求 ID: <code>{last['request_id']}</code>\n"
        elif evidence['state'] == 'empty':
            text += '⏳ Web 回执: 本次未找到该来源的拒绝记录，不能据此判断拦截成功或漏防。\n'
        else:
            text += '⚠️ Web 回执查询不可用，本次结果未知。\n'
        start = datetime.fromtimestamp(evidence['since'], timezone.utc).strftime('%m-%d %H:%M UTC')
        text += f"查询窗口: {start} 至今（最多24小时）；读取 {evidence['logs_read']} 个日志尾部。\n"
        text += f"读取情况: 截尾 {evidence['truncated_files']} 个文件；读取错误 {evidence['errors']}。\n"
        if evidence['scan_limited']:
            text += '扫描达到文件或目录条目上限。\n'
        if evidence['truncated'] or evidence['errors']:
            text += '覆盖有限: 以上条数仅为本次抽样，不代表全量；扫描范围不是拦截次数。\n'
    except (OSError, ValueError, TypeError, ImportError, KeyError, OverflowError):
        text += '⚠️ Web 回执查询不可用（日志或核验模块异常），本次结果未知。\n'
    try:
        config_path = Path(CSCLI_CONFIG).parent/'bouncers/crowdsec-firewall-bouncer.yaml'
        firewall = sibling('crowdsec_execution').firewall_membership(sibling('crowdsec_safety').load(config_path), ip)
        labels = {'present': '已进入配置的封禁集合', 'absent': '本次未在配置的封禁集合中查到',
                  'unavailable': '查询不可用，本次结果未知', 'unsupported': '未核验（当前后端或地址族不支持）'}
        text += '防火墙集合同步: '+labels[firewall['state']]+'。\n'
    except Exception:
        # Optional evidence must not hide the independent Web receipt result.
        text += '防火墙集合同步: 查询不可用，本次结果未知。\n'
    text += '防火墙实际丢包: 本卡未核验；集合成员状态不能证明实际丢包。\n'
    text += '关联范围: 来源 IP 与时间窗；不能证明原触发请求或本告警某条决策已执行。'
    return text, keyboard



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
    row = []
    if not detail:
        row.append({'text': '📋 决策详情', 'callback_data': 'dd:'+group['key']+':0'})
    else:
        aids = list(dict.fromkeys(str(d['alert_id']) for d in decisions if re.fullmatch(r'[1-9][0-9]{0,17}', str(d['alert_id']))))
        row.extend({'text': '🔍 取证 #'+aid, 'callback_data': 'ins:'+aid} for aid in aids[:2])
    return row


def decision_actions(group):
    if group['scope'].lower() == 'ip':
        try:
            value = str(ipaddress.ip_address(group['value']))
            return [{'text': '🔓 解封此 IP 全部决策', 'callback_data': 'unban:'+value},
                    {'text': '🛡️ 加入日志解析白名单', 'callback_data': 'white:'+value}]
        except ValueError:
            pass
    return []


def module_decisions(page=0, target=None, ip=None):
    refresh = {'inline_keyboard': [page_controls('dec', 0, 1)]}
    try:
        groups = decision_groups()
        intro = '范围: 本地/手动等默认来源，不含 CAPI；最多查询 50 条告警所附决策。\n'
        if ip is not None:
            ip = validated_ip(ip)
            refresh = {'inline_keyboard': [[{'text': '🔄 刷新', 'callback_data': 'dip:'+ip}],
                                           [{'text': '⬅️ 返回决策列表', 'callback_data': 'dec:0'}]]}
            group = next((g for g in groups if g['scope'].lower() == 'ip'
                          and str(ipaddress.ip_address(g['value'])) == ip), None)
            if group is None:
                return ('⚠️ 本次查询未找到 IP <code>'+esc(ip)+'</code> 的当前决策。\n'+intro+
                        '可能已过期或超出查询范围，请先核对实际状态。', refresh)
            target = group['key']
        if target is not None:
            group = next((g for g in groups if g['key'] == target), None)
            if group is None:
                return '⚠️ 此目标已不在本次查询结果中，可能已过期或超出查询范围。', refresh
            entries, page, pages = page_slice(group['decisions'], page)
            text = f"📋 <b>决策详情 {page+1}/{pages}</b>\n目标: <code>{card_esc(group['value'], 64)}</code> ({card_esc(group['scope'], 12)})\n共 {len(group['decisions'])} 条决策\n"+intro
            keyboard = []
            for d in entries:
                text += (f"\n告警 #{card_esc(d['alert_id'], 12)} · 决策 #{card_esc(d.get('id'), 12)}\n"
                         f"规则: <code>{card_esc(d.get('scenario'), 55)}</code>\n"
                         f"来源: {card_esc(d.get('origin'), 16)} · {card_esc(d.get('type'), 12)}\n"
                         f"剩余: {card_esc(d.get('duration'), 24)} · {'模拟' if d['simulated'] else '非模拟'}\n")
                row = decision_buttons(group, [d], detail=True)
                if row:
                    keyboard.append(row)
            actions = decision_actions(group)
            if actions:
                keyboard.append(actions)
            keyboard.append(page_controls('dd:'+target, page, pages))
            keyboard.append([{'text': '⬅️ 返回决策列表', 'callback_data': 'dec:0'}])
        else:
            entries, page, pages = page_slice(groups, page)
            total = sum(len(g['decisions']) for g in groups)
            text = f'🚫 <b>封禁决策 {page+1}/{pages}</b>\n本次结果: {len(groups)} 个目标 · {total} 条决策\n'+intro
            keyboard = []
            if not entries:
                text += '\n未找到有效决策。\n'
            for g in entries:
                decisions = g['decisions']
                d = decisions[0]
                text += (f"\n<code>{card_esc(g['value'], 64)}</code> ({card_esc(g['scope'], 12)})\n"
                         f"{len(decisions)} 条决策 · {'含模拟决策' if any(x['simulated'] for x in decisions) else '非模拟'}\n"
                         f"规则: <code>{card_esc(d.get('scenario'), 55)}</code>\n"
                         f"来源: {card_esc(d.get('origin'), 16)} · {card_esc(d.get('type'), 12)} · 剩余: {card_esc(d.get('duration'), 24)}\n"
                         f"告警 #{card_esc(d['alert_id'], 12)}"+(' · 更多规则/时长见详情' if len(decisions)>1 else '')+'\n')
                keyboard.append(decision_buttons(g, decisions))
            keyboard.append(page_controls('dec', page, pages))
        text += '\n决策存在不证明 Bouncer 已实际拦截。刷新会重新查询，排序及页数可能变化。'
        return text, {'inline_keyboard': keyboard}
    except (RuntimeError, ValueError, TypeError, KeyError):
        return '❌ 决策查询失败，请检查 cscli 权限、配置和 JSON 输出。', refresh


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
        return error
    if name not in records:
        return '无本工具安装记录（不排除外部安装）'
    entry = records[name]
    if not isinstance(entry, dict):
        return '安装记录格式无效'
    if entry.get('status') != 'installed':
        return '安装记录状态: '+card_esc(entry.get('status', '未知'), 24)
    try:
        actual = hashlib.sha256(Path(entry['host_target']).read_bytes()).hexdigest()
        return '配置指纹一致（仅主配置文件）' if actual == entry['installed_sha'] else '配置已变化，请核对'
    except (OSError, ValueError, TypeError, KeyError):
        return '配置不可读或记录不完整'


def module_sites(page=0):
    refresh = {'inline_keyboard': [page_controls('site', 0, 1)]}
    try:
        raw = run_cmd(['docker', 'ps', '-a', '--format', '{{json .}}'])
        containers = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if any(not isinstance(c, dict) or not c.get('ID') or not c.get('Names') for c in containers):
            raise ValueError('Invalid container summary')
        containers.sort(key=lambda c: c['Names'])
        entries, page, pages = page_slice(containers, page)
        records, error = web_install_records()
        text = f'📦 <b>容器状态 {page+1}/{pages}</b>\nDocker 容器: {len(containers)} 个（包括停止的容器）\n'
        if not entries:
            text += '\n未找到容器。\n'
        for container in entries:
            text += f"\n<b>{card_esc(container['Names'], 48)}</b>\n容器: {card_esc(container.get('State', '未知'), 16)} · {card_esc(container.get('Status'), 45)}\n"
            try:
                # State only: full inspect can expose passwords/environment variables.
                state = json.loads(run_cmd(['docker', 'inspect', '--format', '{{json .State}}', container['ID']]))
                if not isinstance(state, dict):
                    raise ValueError('Invalid state')
                health = (state.get('Health') or {}).get('Status', '未配置 HEALTHCHECK')
                text += f"健康: {card_esc(health, 28)}\n启动时间: {card_esc(state.get('StartedAt', '未知'), 35)}\n"
            except (RuntimeError, ValueError, TypeError, AttributeError):
                text += '健康/启动时间: 状态查询失败\n'
            text += 'Bouncer: '+web_config_status(container['Names'], records, error)+'\n'
        if error and not entries:
            text += error+'\n'
        text += '\nHTTP 可用性: 尚未验证（本页不主动探测）。\n配置指纹不证明挂载、资源文件、运行时加载或实际拦截；其他接入方式尚未核验。'
        return text, {'inline_keyboard': [page_controls('site', page, pages)]}
    except (RuntimeError, ValueError, TypeError, KeyError):
        return '❌ Docker 容器查询失败，请检查 Docker 是否安装、守护进程、权限和 JSON 输出。', refresh


def home_card():
    return ('📱 <b>主菜单</b>\n请选择要查看的状态或告警；修改操作会先展示影响并请求确认。',
            {'inline_keyboard': [[{'text': VIEWS[key].label, 'callback_data': 'nav:'+key}
                                  for key in row] for row in MAIN_MENU]})


def render_view(view_id, *args, refresh_data=None, **kwargs):
    """Normalize existing renderers into cards with the same navigation rules."""
    if view_id == 'home':
        return home_card()
    view = VIEWS[view_id]
    result = globals()[view.renderer](*args, **kwargs)
    text, markup = result if isinstance(result, tuple) else (result, None)
    rows = [[dict(button) for button in row] for row in (markup or {}).get('inline_keyboard', [])]
    navigation = []
    if view.refresh:
        navigation.append({'text': '🔄 刷新', 'callback_data': refresh_data or 'nav:'+view_id})
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
    view_id, kwargs = None, {}
    match = re.fullmatch(r'(dec|site):(\d{1,6})', data)
    detail = re.fullmatch(r'dd:([a-f0-9]{16}):(\d{1,6})', data)
    inspect = re.fullmatch(r'ins:([1-9]\d{0,17})', data)
    execution = re.fullmatch(r'exp:([1-9]\d{0,11})', data)
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
    elif data == 'em:view_white':
        view_id = 'whitelist'
    if view_id is None:
        return False
    answer_callback(callback['id'], '正在查询…')
    if view_id == 'execution':
        text, keyboard = module_execution(**kwargs)
    else:
        text, keyboard = render_view(view_id, **kwargs)
    tg_request('editMessageText', {'chat_id': ADMIN_CHAT_ID, 'message_id': message_id,
        'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True, 'reply_markup': keyboard})
    return True


def module_emergency_manager():
    """运维工具：查询直接响应，修改经既有确认与审计流程执行。"""
    txt = """🛠 <b>运维工具</b>
━━━━━━━━━━━━━━━━━━
• <b>查看日志解析白名单</b>：只读展示本工具白名单文件
• <b>重载 CrowdSec</b>：校验配置后重载
• <b>释放文件缓存</b>：不保证降低应用内存
修改操作会展示具体影响，确认后才执行。"""
    kb = {"inline_keyboard": [
        [{"text": VIEWS['whitelist'].label, "callback_data": "nav:whitelist"}],
        [{"text": "🔄 重载 CrowdSec", "callback_data": "em:reload_cs"}],
        [{"text": "🧹 释放文件缓存", "callback_data": "em:drop_caches"}]
    ]}
    return txt, kb


def module_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return '📋 日志解析白名单\n无本工具白名单文件。'
    return module_command(['cat', WHITELIST_FILE], '日志解析白名单')


def module_help():
    lines = ['❓ <b>使用帮助</b>', '• <code>/start</code> - 唤出 3×3 九宫格主键盘']
    lines.extend('• <code>/'+view.command+esc(view.usage)+'</code> - '+view.description
                 for view in VIEWS.values() if view.command)
    lines.extend('• <code>/'+command+esc(usage)+'</code> - '+description
                 for command, usage, description in ACTION_COMMANDS)
    lines.append('流程：最近告警 → 告警取证 → 当前决策 → 操作确认。')
    lines.append('<i>修改操作需在 60 秒内点击确认；查询直接响应。'
                 '操作结果待核对时请先查询实际状态。</i>')
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
        return '❌ 封禁安全检查失败，请核对本机和管理员地址及检查依赖；未添加封禁。'
    try:
        run_cmd(['cscli', 'decisions', 'add', '--ip', ip, '--duration', dur, '--reason', 'manual_tg'])
        return f'✅ 封禁决策已添加: <code>{esc(ip)}</code> / {esc(dur)}；实际拦截需核验 Bouncer。'
    except CommandUncertain:
        raise
    except RuntimeError:
        return '❌ 添加封禁决策失败。'


def action_unban(ip):
    try:
        ip = validated_ip(ip)
        run_cmd(['cscli', 'decisions', 'delete', '--ip', ip])
        return f'✅ 已提交解封: <code>{esc(ip)}</code>；Bouncer 同步后生效。'
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
        return f'✅ 已加入日志解析白名单并提交解封: <code>{esc(ip)}</code>。不保证 AppSec/CAPI 或其他防护组件放行。'
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
        return '❌ '+esc(label)+'查询失败，请检查命令和权限。'


def reload_engine():
    try:
        run_cmd(['crowdsec', '-c', CSCLI_CONFIG, '-t'], timeout=30)
    except RuntimeError:
        return '❌ 配置校验失败或超时，未提交重载。'
    try:
        run_cmd(['systemctl', 'reload', 'crowdsec'])
        return '✅ 引擎重载完成。'
    except CommandUncertain:
        raise
    except RuntimeError:
        return '❌ 校验或重载失败。'


def drop_caches():
    try:
        os.sync()
        with open('/proc/sys/vm/drop_caches', 'w') as stream:
            stream.write('3\n')
        return '✅ 已请求释放文件缓存；不保证降低应用内存。'
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
                send_message(f"🚨 <b>【CrowdSec 突发威胁阻断】</b>\n\n{txt}", reply_markup=kb)
        except Exception:
            pass
        finally:
            conn.close()

def request_action(action, params):
    """Both commands and legacy buttons enter this preview, never execute directly."""
    labels = {'ban': '封禁', 'unban': '解封', 'white': '永久加入日志解析白名单',
              'reload': '重载 CrowdSec', 'drop_caches': '释放系统文件缓存'}
    try:
        if action not in labels:
            raise ValueError('unknown action')
        if action in ('ban', 'unban', 'white'):
            params = [validated_ip(params[0]), *params[1:]]
        if action == 'ban' and (len(params) != 2 or not re.fullmatch(r'(?:[1-9][0-9]*[smh])+', params[1])):
            raise ValueError('invalid duration')
        nonce = get_action_store().offer(action, params, ADMIN_USER_ID, ADMIN_CHAT_ID)
    except (ValueError, IndexError, TypeError):
        send_message('❌ 操作参数无效，未执行。')
        return
    text = '⚠️ <b>确认操作：'+labels[action]+'</b>\n'
    if params:
        text += '目标: <code>'+esc(params[0])+'</code>\n'
    if action == 'ban':
        text += '时长: '+esc(params[1])+'；提交决策前仍会核对本机与管理员地址。\n'
    elif action == 'unban':
        text += '影响: 删除此 IP 的全部决策，Bouncer 同步后生效。\n'
    elif action == 'white':
        text += '影响: 修改日志解析白名单、重载 CrowdSec，并删除此 IP 的全部决策以提交解封。此白名单不保证 AppSec/CAPI 放行。\n'
    elif action == 'reload':
        text += '影响: 校验配置后重载 CrowdSec。\n'
    else:
        text += '影响: 同步写入并释放文件缓存，不保证降低应用内存。\n'
    text += '60 秒内确认有效；取消或服务重启后需重新发起。'
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
        outcome, result = 'unknown', '⚠️ 操作结果待核对，请先查询实际状态后再决定是否重新发起。'
    try:
        store.finish(ticket, outcome, result)
    except (OSError, ValueError):
        result += '\n⚠️ 操作记录写入未完成，结果待核对；不会自动重放。'
    return result+'\n操作 ID: <code>'+esc(ticket['id'])+'</code>'


def handle_action_callback(callback):
    data = callback.get('data', '')
    match = re.fullmatch(r'(yes|no):([A-Za-z0-9_-]{16,64})', data)
    if match:
        store = get_action_store()
        if match[1] == 'no':
            cancelled = store.cancel(match[2], ADMIN_USER_ID, ADMIN_CHAT_ID)
            answer_callback(callback['id'], '已取消' if cancelled else '确认已过期或已处理')
            return True
        ticket = store.take(match[2], ADMIN_USER_ID, ADMIN_CHAT_ID)
        if ticket is None:
            answer_callback(callback['id'], '确认已过期或已处理，请重新发起', alert=True)
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

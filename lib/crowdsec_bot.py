#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram WAF & Threat Intelligence Bot 3.1
- Python 3 Standard Library; runtime memory depends on data
- Multi-Source Fusion: CrowdSec SQLite DB + NPM Stream Access Logs
- Real-time Forensic Drill-Down & Interactive Inline Actions
- Strictly filters out CAPI/system updates (+15000/-0 IPs) to prevent notification spam
"""

import os
import argparse
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
from collections import Counter
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
TG_API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"
_INSTANCE_LOCK = None


def load_settings(path):
    global BOT_TOKEN, ADMIN_CHAT_ID, ADMIN_USER_ID, DB_PATH, NPM_LOG_DIR, CSCLI_CONFIG, WHITELIST_FILE, STATE_DIR, TG_API_BASE
    config = json.loads(Path(path).read_text(encoding='utf-8'))
    BOT_TOKEN = config['bot_token']
    ADMIN_CHAT_ID = int(config['chat_id'])
    ADMIN_USER_ID = int(config['admin_user_id'])
    if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', BOT_TOKEN) or not ADMIN_CHAT_ID or ADMIN_USER_ID <= 0:
        raise ValueError('Token、Chat ID 或管理员用户 ID 无效')
    DB_PATH = config.get('db_path', DB_PATH)
    NPM_LOG_DIR = config.get('npm_log_dir', NPM_LOG_DIR)
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


# 3×3 九宫格主菜单常驻键盘
MAIN_KEYBOARD = {
    "keyboard": [
        [{"text": "📊 系统大屏"}, {"text": "🛡️ 攻击态势"}, {"text": "🚨 最新告警"}],
        [{"text": "💀 黑客榜单"}, {"text": "🎯 漏洞靶心"}, {"text": "🔍 取证穿透"}],
        [{"text": "🚫 封禁名单"}, {"text": "🌐 站点体检"}, {"text": "⚡ 应急管家"}]
    ],
    "resize_keyboard": True,
    "is_persistent": True
}

# ==================== 网络与 Telegram API ====================
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def tg_request(endpoint, data=None):
    url = f"{TG_API_BASE}/{endpoint}"
    body = json.dumps(data).encode('utf-8') if data is not None else None
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=35 if endpoint.startswith('getUpdates') else 15) as resp:
            result = json.loads(resp.read(1024*1024))
            return result if isinstance(result, dict) and result.get('ok') is True else None
    except Exception:
        # HTTP exceptions can contain Bot Token: never print them.
        print('Telegram API 调用失败，请检查连接和配置。', file=sys.stderr)
        return None


def register_bot_commands():
    """注入 Telegram 聊天框原生斜杠命令联想菜单"""
    commands = [
        {"command": "start", "description": "📱 唤出 3×3 九宫格主菜单"},
        {"command": "inspect", "description": "🔍 调阅真实攻击报文 (/inspect ID)"},
        {"command": "ban", "description": "🚫 手动封禁 IP (/ban IP [时长])"},
        {"command": "unban", "description": "🔓 解除 IP 封禁 (/unban IP)"},
        {"command": "white", "description": "🛡️ 永久加白 IP (/white IP)"},
        {"command": "top", "description": "💀 查看 Top 10 黑客与漏洞靶心"},
        {"command": "help", "description": "❓ 查看全部指令使用指南"}
    ]
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

def run_cmd(cmd, timeout=8):
    args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    # This service runs with its own permissions; avoid sudo and shell expansion.
    if args and args[0] == 'sudo':
        args.pop(0)
    if args and args[0] == 'cscli':
        args[1:1] = ['-c', CSCLI_CONFIG]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError('命令无法执行或超时') from error
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
    ban_cnt = 0
    conn = get_db_conn()
    if conn:
        try:
            ban_cnt = conn.execute("SELECT count(*) FROM decisions WHERE until > datetime('now')").fetchone()[0]
        except Exception:
            pass
        conn.close()
    return f"""📊 <b>【DMIT 节点系统大屏】</b>
━━━━━━━━━━━━━━━━━━
⏱️ <b>持续运行</b>: <code>{uptime_h} 小时</code>
⚙️ <b>系统负载</b>: <code>{load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}</code>
🧠 <b>内存状态</b>: <code>{mem_used:.0f}M / {mem_total:.0f}M ({mem_pct:.1f}%)</code>
💾 <b>系统磁盘</b>: <code>{d_used:.1f}G / {d_total:.1f}G</code>
🛡️ <b>有效决策总数</b>: <code>{ban_cnt} 个恶意 IP</code>
━━━━━━━━━━━━━━━━━━
<i>状态：仅显示当前资源采样，不代表防护或内存容量验收</i>"""

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
    txt = "🚨 <b>【最新告警动态 (Top 5)】</b>\n━━━━━━━━━━━━━━━━━━\n"
    kb = []
    for a in alerts:
        aid, ip, country, sc, created = a
        txt += f"<b>#{aid}</b> | <code>{html.escape(ip)}</code> ({html.escape(country or '未知')})\n   └ 规则: <code>{html.escape(sc.split('/')[-1])}</code>\n   └ 时间: <code>{created}</code>\n\n"
        kb.append([{"text": f"🔍 取证 #{aid}", "callback_data": f"ins:{aid}"}, {"text": f"🔓 解封", "callback_data": f"unban:{ip}"}])
    return txt.strip(), {"inline_keyboard": kb}

def module_top_hackers():
    """💀 黑客榜单（Top 10 恶意扫描 IP 排行）"""
    raw = read_log_tail_chunks()
    if not raw:
        return "⚠️ 暂无黑客统计。"
    m = re.findall(r'(?:GET|POST|HEAD) [^\"]*(?:\.env|\.\./|phpmyadmin|actuator|pearcmd|\.git|wp-login|\.bak)[^\"]* [^\[]*\[Client ([a-fA-F0-9:.]+)\]', raw, re.I) or re.findall(r' (?:404|403) [^\[]*\[Client ([a-fA-F0-9:.]+)\]', raw)
    counts = Counter(m).most_common(10)
    if not counts:
        return "✅ 近期未发现集中嗅探黑客。"
    txt = "💀 <b>【扫描最凶黑客 IP 排行榜 (Top 10)】</b>\n━━━━━━━━━━━━━━━━━━\n"
    for idx, (ip, cnt) in enumerate(counts, 1):
        txt += f"<b>{idx}.</b> <code>{html.escape(ip)}</code> ➔ <b>{cnt}</b> 次探测\n"
    return txt + "━━━━━━━━━━━━━━━━━━\n<i>数据来源：全站 NPM 实时日志反向抽样</i>"

def module_top_targets():
    """🎯 漏洞靶心（Top 10 被嗅探敏感路径）"""
    raw = read_log_tail_chunks()
    if not raw:
        return "⚠️ 暂无靶心统计。"
    paths = re.findall(r'(?:GET|POST|HEAD) (/[^ \"?]+)', raw, re.I)
    sensitive = [p for p in paths if any(k in p.lower() for k in ['.env', '..', 'phpmyadmin', 'actuator', 'pearcmd', '.git', 'wp-', '.bak', 'api/', 'login'])]
    counts = Counter(sensitive).most_common(10) or Counter(paths).most_common(10)
    txt = "🎯 <b>【黑客集中刺探路径排行榜 (Top 10)】</b>\n━━━━━━━━━━━━━━━━━━\n"
    for idx, (p, cnt) in enumerate(counts, 1):
        disp = p if len(p) <= 32 else p[:29] + "..."
        txt += f"<b>{idx}.</b> <code>{html.escape(disp)}</code> ➔ <b>{cnt}</b> 次\n"
    return txt + "━━━━━━━━━━━━━━━━━━\n<i>建议：对高频命中路径实施即时熔断</i>"

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
        txt += '执行状态: 本通知未验证 Bouncer 实际拦截\n'
        samples = request_samples(alert)
        for index, (path, ua, method) in enumerate(samples, 1):
            description = '未记录 UA' if ua is None else ('请求未提供 UA' if not ua else ua)
            txt += f"\n请求样本 {index}\n🎯 刺探目标: <code>{esc(method, 12)} {esc(path, 180)}</code>\n🤖 客户端指纹: <code>{esc(description, 100)}</code>\n"
        if not samples:
            txt += '取证: 未记录 HTTP 元数据；非 HTTP 告警不适用路径/UA。\n'
        kb = None
        try:
            parsed_ip = str(ipaddress.ip_address(ip))
            kb = {'inline_keyboard': [[{'text': '🔓 解封此 IP', 'callback_data': 'unban:'+parsed_ip},
                                        {'text': '🛡️ 加入白名单', 'callback_data': 'white:'+parsed_ip}]]}
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
    if group['scope'].lower() == 'ip':
        try:
            value = str(ipaddress.ip_address(group['value']))
            row.append({'text': '🔓 解封此 IP 全部决策', 'callback_data': 'unban:'+value})
        except ValueError:
            pass
    return row


def module_decisions(page=0, target=None):
    refresh = {'inline_keyboard': [page_controls('dec', 0, 1)]}
    try:
        groups = decision_groups()
        intro = '范围: 本地/手动等默认来源，不含 CAPI；最多查询 50 条告警所附决策。\n'
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
        text = f'🌐 <b>站点体检 {page+1}/{pages}</b>\nDocker 容器: {len(containers)} 个（包括停止的容器）\n'
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


def handle_view_callback(callback):
    if not authorized(callback):
        return False
    data = callback.get('data', '')
    match = re.fullmatch(r'(dec|site):(\d{1,6})', data)
    detail = re.fullmatch(r'dd:([a-f0-9]{16}):(\d{1,6})', data)
    if not (match or detail):
        return False
    message = callback.get('message', {})
    if not message.get('message_id'):
        return False
    answer_callback(callback['id'], '正在查询…')
    if match:
        view = module_decisions if match[1] == 'dec' else module_sites
        text, keyboard = view(int(match[2]))
    elif detail:
        text, keyboard = module_decisions(int(detail[2]), target=detail[1])
    tg_request('editMessageText', {'chat_id': ADMIN_CHAT_ID, 'message_id': message['message_id'],
        'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True, 'reply_markup': keyboard})
    return True


def module_emergency_manager():
    """⚡ 应急管家"""
    txt = """⚡ <b>【应急处置与系统调优管家】</b>
━━━━━━━━━━━━━━━━━━
请点击下方快捷指令进行现场急救：
• <b>内存急救</b>：请求释放文件缓存，不保证降低应用内存
• <b>重载防御</b>：热重载 CrowdSec 规则库，免重启生效
• <b>查看白名单</b>：检查当前放行的特权 IP 列表"""
    kb = {"inline_keyboard": [
        [{"text": "🧹 立即释放系统缓存 (内存急救)", "callback_data": "em:drop_caches"}],
        [{"text": "🔄 热重载 CrowdSec 引擎", "callback_data": "em:reload_cs"}],
        [{"text": "📋 查看当前特权白名单", "callback_data": "em:view_white"}]
    ]}
    return txt, kb

def module_help():
    return """❓ <b>【WAF 机器人全部快捷指令指南】</b>
━━━━━━━━━━━━━━━━━━
• <code>/start</code> - 唤出 3×3 九宫格主键盘
• <code>/inspect &lt;ID&gt;</code> - 调阅指定告警报文 (如: /inspect 108)
• <code>/ban &lt;IP&gt; [时长]</code> - 手动封禁 IP (如: /ban 1.2.3.4 24h)
• <code>/unban &lt;IP&gt;</code> - 解除封禁 (如: /unban 1.2.3.4)
• <code>/white &lt;IP&gt;</code> - 永久加入白名单 (如: /white 1.2.3.4)
• <code>/top</code> - 一键查看黑客 Top 10 与敏感路径 Top 10
━━━━━━━━━━━━━━━━━━
<i>提示：点击屏幕下方的九宫格按键即可直接操作。</i>"""

def validated_ip(value):
    return str(ipaddress.ip_address(value.strip()))


def action_ban(ip, dur='4h'):
    try:
        ip = validated_ip(ip)
        if not re.fullmatch(r'(?:[1-9][0-9]*[smh])+', dur):
            raise ValueError('时长无效')
        run_cmd(['cscli', 'decisions', 'add', '--ip', ip, '--duration', dur, '--reason', 'manual_tg'])
        return f'✅ 封禁决策已添加: <code>{esc(ip)}</code> / {esc(dur)}；实际拦截需核验 Bouncer。'
    except ValueError:
        return '❌ IP 或封禁时长无效。'
    except RuntimeError:
        return '❌ 添加封禁决策失败。'


def action_unban(ip):
    try:
        ip = validated_ip(ip)
        run_cmd(['cscli', 'decisions', 'delete', '--ip', ip])
        return f'✅ 已提交解封: <code>{esc(ip)}</code>；Bouncer 同步后生效。'
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
    except (RuntimeError, OSError):
        if changed:
            try:
                if previous is None:
                    os.unlink(WHITELIST_FILE)
                else:
                    replace_private(WHITELIST_FILE, previous)
                run_cmd(['systemctl', 'reload', 'crowdsec'])
            except (RuntimeError, OSError):
                return '❌ 加白失败，恢复或重载未完成，请手工核验白名单配置。'
            return '❌ 加白失败，已恢复原白名单文件。'
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
        run_cmd(['systemctl', 'reload', 'crowdsec'])
        return '✅ 引擎重载完成。'
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

def main():
    register_bot_commands()
    send_message("🚀 <b>【WAF 威胁情报中心 3.1 已上线】</b>", reply_markup=MAIN_KEYBOARD)
    if AUTO_NOTIFY:
        Thread(target=background_alert_watcher, daemon=True).start()
    try:
        offset = int(Path(offset_path()).read_text())
    except (OSError, ValueError):
        offset = 0
    while True:
        try:
            updates = tg_request(f"getUpdates?offset={offset}&timeout=20")
            if not updates or not updates.get("ok"):
                time.sleep(2)
                continue
            for u in updates.get("result", []):
                offset = u["update_id"] + 1
                save_offset(offset)
                if "callback_query" in u:
                    cq = u["callback_query"]
                    cid, data = cq["id"], cq.get("data", "")
                    if not authorized(cq):
                        continue
                    if handle_view_callback(cq):
                        continue
                    if data.startswith("ins:"):
                        txt, kb = module_forensics(int(data.split(":")[1]))
                        send_message(txt, reply_markup=kb)
                        answer_callback(cid, "已调阅取证")
                    elif data.startswith("unban:"):
                        send_message(action_unban(data.split(":", 1)[1]), reply_markup=MAIN_KEYBOARD)
                        answer_callback(cid, "已处理请求")
                    elif data.startswith("white:"):
                        send_message(action_whitelist(data.split(":", 1)[1]), reply_markup=MAIN_KEYBOARD)
                        answer_callback(cid, "已处理请求")
                    elif data == "em:drop_caches":
                        send_message(drop_caches(), reply_markup=MAIN_KEYBOARD)
                        answer_callback(cid, "已处理请求")
                    elif data == "em:reload_cs":
                        send_message(reload_engine(), reply_markup=MAIN_KEYBOARD)
                        answer_callback(cid, "已处理请求")
                    elif data == "em:view_white":
                        send_message(module_command(['cat', WHITELIST_FILE], '白名单') if os.path.exists(WHITELIST_FILE) else '无白名单文件', reply_markup=MAIN_KEYBOARD)
                        answer_callback(cid, "已展示")
                elif "message" in u:
                    msg = u["message"]
                    text = msg.get("text", "").strip()
                    if not authorized(msg):
                        continue
                    parts = text.split()
                    cmd = parts[0].lower().split("@")[0] if parts else ""
                    if cmd in ["/start", "菜单"]:
                        send_message("📱 <b>【主菜单】</b>", reply_markup=MAIN_KEYBOARD)
                    elif cmd in ["/help", "帮助"]:
                        send_message(module_help(), reply_markup=MAIN_KEYBOARD)
                    elif text == "📊 系统大屏":
                        send_message(module_system_status(), reply_markup=MAIN_KEYBOARD)
                    elif text == "🛡️ 攻击态势":
                        send_message(module_attack_posture(), reply_markup=MAIN_KEYBOARD)
                    elif text == "🚨 最新告警":
                        txt, kb = module_recent_alerts()
                        send_message(txt, reply_markup=kb or MAIN_KEYBOARD)
                    elif text == "💀 黑客榜单":
                        send_message(module_top_hackers(), reply_markup=MAIN_KEYBOARD)
                    elif text == "🎯 漏洞靶心":
                        send_message(module_top_targets(), reply_markup=MAIN_KEYBOARD)
                    elif text == "🔍 取证穿透":
                        txt, kb = module_forensics()
                        send_message(txt, reply_markup=kb or MAIN_KEYBOARD)
                    elif text == "🚫 封禁名单":
                        txt, kb = module_decisions()
                        send_message(txt, reply_markup=kb)
                    elif text == "🌐 站点体检":
                        txt, kb = module_sites()
                        send_message(txt, reply_markup=kb)
                    elif text == "⚡ 应急管家":
                        txt, kb = module_emergency_manager()
                        send_message(txt, reply_markup=kb)
                    elif cmd == "/inspect":
                        aid = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                        txt, kb = module_forensics(aid)
                        send_message(txt, reply_markup=kb)
                    elif cmd == "/ban" and len(parts) >= 2:
                        dur = parts[2] if len(parts) >= 3 else "4h"
                        send_message(action_ban(parts[1], dur), reply_markup=MAIN_KEYBOARD)
                    elif cmd == "/unban" and len(parts) >= 2:
                        send_message(action_unban(parts[1]), reply_markup=MAIN_KEYBOARD)
                    elif cmd == "/white" and len(parts) >= 2:
                        send_message(action_whitelist(parts[1]), reply_markup=MAIN_KEYBOARD)
                    elif cmd == "/top":
                        send_message(f"{module_top_hackers()}\n\n{module_top_targets()}", reply_markup=MAIN_KEYBOARD)
        except Exception:
            time.sleep(2)

def cli():
    parser = argparse.ArgumentParser(description='CrowdBastion 交互机器人；CrowdSec 官方通道负责自动告警')
    parser.add_argument('--config', default='/etc/crowdsec/crowdsec-1key-bot.json')
    parser.add_argument('--check-config', action='store_true')
    args = parser.parse_args()
    try:
        load_settings(args.config)
        if args.check_config:
            print('机器人配置格式有效；未连接 Telegram，也未验证运行状态。')
            return 0
        acquire_instance_lock()
        main()
    except (OSError, ValueError, KeyError, RuntimeError):
        print('机器人启动失败：配置无效、文件不可读或存在重复实例。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(cli())

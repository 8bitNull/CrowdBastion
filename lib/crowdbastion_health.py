#!/usr/bin/env python3
"""Fixed, user-facing conclusions from typed observations; no runtime probes."""
import os
import json
import math
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True

# label, missing, fault, unknown, impact, recommended action
CATALOG = {
    'core': ('本地检测服务运行', '本地检测服务尚未安装', '本地检测服务没有运行', '无法确认本地检测服务状态', '当前无法正常检测本机日志中的攻击。', 'core_logs'),
    'bouncer': ('防火墙防护服务运行', '防火墙防护尚未部署', '防火墙防护服务没有运行', '无法确认防火墙防护服务状态', '当前无法正常执行 IP 封禁。', 'bouncer_logs'),
    'api': ('本地检测接口可用', '本地检测接口未配置', '本地检测接口连接失败', '无法读取本地检测接口状态', '检测服务与防护组件的通信需要核查。', 'core_logs'),
    'config': ('检测配置校验通过', '检测配置缺失', '检测配置校验未通过', '检测配置未完成校验', '检测服务可能无法按当前配置运行。', 'core_logs'),
    'registry': ('组件登记可读取', '组件尚未登记', '组件登记检查未通过', '无法读取组件登记', '暂时无法确认防护组件接入情况。', 'details'),
    'metrics': ('运行指标可读取', '运行指标未启用', '运行指标检查未通过', '无法读取运行指标', '暂时无法判断日志处理情况。', 'details'),
    'logs': ('日志读取与解析正常', '日志采集尚未配置', '日志已读取，但没有成功解析', '日志解析证据不足', '相关日志中的攻击可能无法被识别。', 'log_help'),
    'acquisition': ('日志采集配置检查通过', '日志采集尚未配置', '日志采集配置存在问题', '无法核查日志采集配置', '可能遗漏或重复处理日志事件。', 'log_help'),
    'rules': ('已发现来源 IP 封禁规则', '封禁规则尚未接入', '封禁规则检查未通过', '封禁规则或适用的流量路径尚未确认', '暂时无法确认业务流量会经过封禁规则。', 'path_help'),
    'renewal': ('未命中已知的 nftables 续封缺陷', '封禁续期检查未配置', '防火墙后端存在已知续封缺陷', '防火墙后端续封修复状态尚未验证', '封禁决策仍有效时，流量可能已经恢复通行。', 'details'),
    'remote': ('远端连接配置检查通过', '远端检测中心连接尚未配置', '远端连接配置检查未通过', '无法读取远端连接配置', '当前节点可能无法接收检测中心的封禁决策。', 'details'),
    'appsec': ('网站检查配置的 AppSec 地址有监听', '网站检查引擎尚未接入', '网站检查引擎没有在配置地址监听', '网站检查引擎状态未能确认', '网站请求可能无法经过 AppSec 检查。', 'details'),
    'web': ('网站接入配置检查通过', '网站防护尚未接入', '网站接入检查未通过', '网站接入检查未完成', '暂时无法确认网站防护接入情况。', 'details'),
    'web_container': ('已部署的网站容器运行', '网站容器尚未部署', '已登记的网站容器没有运行', '网站容器状态无法读取', '相关网站可能无法访问或执行请求检查。', 'details'),
    'webui': ('管理界面可用', '管理界面尚未部署', '管理界面检查未通过', '管理界面检查未完成', '管理界面可能暂时不可用。', 'details'),
    'v2bx': ('V2bX 配置可读取', 'V2bX 配置尚未发现', 'V2bX 配置无效', 'V2bX 配置未完成核查', '暂时无法检查落地节点配置。', 'details'),
    'v2bx_service': ('V2bX 服务运行', 'V2bX 服务尚未安装', 'V2bX 服务没有运行', 'V2bX 服务状态无法读取', '落地节点可能无法提供连接服务。', 'v2bx_logs'),
    'v2bx_logs': ('落地日志可读取', '落地日志尚未配置', '落地日志检查未通过', '配置的落地日志无法完整读取', '暂时无法检查相关落地节点的运行日志。', 'details'),
    'sockets': ('落地监听信息可读取', '落地监听尚未发现', '落地监听检查未通过', '落地监听信息无法读取', '暂时无法确认落地连接入口。', 'details'),
    'check': ('', '', '', '部分检查没有取得完整结果', '本次检查不足以判断整体运行情况。', 'details'),
    'traffic': ('实际拦截验证通过', '', '', '实际拦截待验证', '', 'verify'),
}
STATES = {'required', 'ok', 'optional', 'pending', 'unknown', 'missing', 'fault', 'verified'}
RANK = {'optional': 0, 'ok': 1, 'verified': 1, 'pending': 2, 'unknown': 3, 'missing': 4, 'fault': 5}
LABELS = {'web': '网站', 'relay': '本地中转', 'remote': '远端执行', 'node': 'V2bX 落地'}
ACTIONS = {
    'verify': ('查看如何验证实际拦截', '按实际流量路径完成一次外部拦截验证。'),
    'core_logs': ('查看检测服务日志', '查看检测服务日志：journalctl -u crowdsec -n 50 --no-pager'),
    'bouncer_logs': ('查看防火墙防护服务日志', '查看启动失败原因：journalctl -u crowdsec-firewall-bouncer -n 50 --no-pager'),
    'v2bx_logs': ('查看 V2bX 服务日志', '查看落地服务日志：journalctl -u V2bX.service -n 50 --no-pager'),
    'install_web': ('安装网站基础防护', '安装网站基础防护：[1] → [1]，或 --install-core。'),
    'install_relay': ('安装本机系统/SSH 基础防护', '安装本机系统/SSH 基础防护：[1] → [5]，或 --install-relay。'),
    'install_remote': ('配置远端检测中心连接', '配置远端检测中心连接：[1] → [6]。'),
    'details': ('查看检查详情和未完成原因', '查看检查详情，先解决依赖、权限或读取失败。'),
    'log_help': ('查看日志解析排查方法', '核对日志格式、采集标签与解析器；详见检查详情。'),
    'path_help': ('查看封禁路径核验方法', '核对连接来源和转发路径：--relay-path。'),
}


def parse_acquisition_metrics(payload):
    """Validate cscli acquisition counters without exposing source names or output."""
    metrics = json.loads(payload)
    if not isinstance(metrics, dict):
        raise ValueError('invalid acquisition metrics')
    sources = metrics.get('acquisition', {})
    if not isinstance(sources, dict):
        raise ValueError('invalid acquisition metrics')
    for name, source in sources.items():
        if not isinstance(name, str) or not isinstance(source, dict):
            raise ValueError('invalid acquisition source')
        for key in ('reads', 'parsed', 'unparsed'):
            value = source.get(key, 0)
            if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)) or value < 0:
                raise ValueError('invalid acquisition count')
    return sources


def acquisition_state(sources):
    """Classify already validated sources; a busy unparsable source wins."""
    if any(source.get('reads', 0) and not source.get('parsed', 0) for source in sources.values()):
        return 'fault'
    if not sources or any(not source.get('reads', 0) for source in sources.values()):
        return 'pending'
    return 'ok'


def emit(key, state):
    """Append only fixed tokens to the private report created by the shell wrapper."""
    path = os.environ.get('CROWDBASTION_HEALTH_EVENTS')
    if not path:
        return
    if key not in CATALOG or state not in STATES:
        raise ValueError('invalid health observation')
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('unsafe health report')
        os.write(fd, f'{key}\t{state}\n'.encode())
    finally:
        os.close(fd)


def summarize(records, status, scope, roles):
    expected, states = {}, {}
    for key, state in records:
        if key not in CATALOG or state not in STATES:
            raise ValueError('invalid health observation')
        if state == 'required':
            expected.setdefault(key, None)
        elif RANK[state] >= RANK.get(states.get(key), -1):
            states[key] = state
    for key in expected:
        states.setdefault(key, 'unknown')
    # A return code alone never supplies proof of a healthy or broken component.
    if not (set(expected) - {'traffic'}) or (status == 1 and not any(s in ('fault', 'missing', 'unknown') for s in states.values())):
        states['check'] = 'unknown'
    faults = [k for k, s in states.items() if s == 'fault']
    missing = [k for k, s in states.items() if s == 'missing']
    unknown = [k for k, s in states.items() if s == 'unknown' and k != 'traffic'] + [k for k, s in states.items() if s == 'pending' and k != 'traffic']
    issue = (faults or missing or unknown or [None])[0]
    action = 'verify'
    if faults:
        verdict, status = '发现问题，需要处理', 1
    elif missing:
        verdict = '部署尚未完成'
    elif unknown:
        verdict = '检查未完成，暂时无法判断'
    elif states.get('traffic') == 'verified':
        verdict = '运行与防护验证通过'
    else:
        verdict = '运行检查通过，实际拦截待验证'
    attention, impact = '', ''
    if issue:
        row = CATALOG[issue]
        state = states[issue]
        attention = row[2 if state == 'fault' else 1 if state == 'missing' else 3]
        impact, action = row[4], row[5] if state in ('fault', 'missing') else 'details'
        if state == 'missing' and issue in ('core', 'bouncer', 'remote'):
            action = 'details' if roles == 'node' else 'install_remote' if 'remote' in roles.split() else 'install_web' if 'web' in roles.split() or not roles else 'install_relay'
        if state == 'pending' and issue == 'logs':
            attention = '日志暂时没有足够的解析样本，可能空闲或刚重启'
            impact = '需要产生正常访问或登录日志后再检查。'
    confirmed = [CATALOG[k][0] for k, s in states.items() if s == 'ok' and CATALOG[k][0]]
    # Keep a short summary; details retain every individual result.
    important = [CATALOG[k][0] for k in ('core', 'bouncer', 'logs', 'rules', 'remote', 'v2bx', 'v2bx_service', 'appsec') if states.get(k) == 'ok']
    return {'verdict': verdict, 'status': 1 if status == 1 else 0 if verdict == '运行与防护验证通过' else 2,
            'confirmed': '、'.join((important or confirmed)[:4]), 'attention': attention,
            'additional': max(0, len(faults or missing or unknown) - 1), 'impact': impact,
            'action': action, 'action_label': ACTIONS[action][0], 'next': ACTIONS[action][1]}


def main(args):
    if args[0] == 'event':
        emit(args[1], args[2])
        return 0
    path, status, scope, roles, action_path = args
    records = [line.split('\t') for line in Path(path).read_text().splitlines()]
    report = summarize(records, int(status), scope, roles)
    print('检查结论：'+report['verdict'])
    label = '、'.join(LABELS[r] for r in roles.split() if r in LABELS)
    print('检查范围：'+({'relay': '中转防火墙', 'node': 'V2bX 落地'}.get(scope, label or '网站（尚未选择用途）')))
    if report['confirmed']:
        print('已确认：'+report['confirmed']+'。')
    if report['attention']:
        print('需要关注：'+report['attention']+'。')
        print('影响：'+report['impact'])
        if report['additional']:
            print(f"另有 {report['additional']} 项需要关注，可在详情中查看。")
    elif report['status'] == 2:
        print('待确认：'+('专用攻击检测与外部连接拦截效果。' if scope == 'node' or roles == 'node' else '外部连接是否确实被拦截。'))
        print('本次未发现需要修复的问题。')
    else:
        print('本次适用的运行与防护验证已通过。')
    print('下一步：'+report['next'])
    Path(action_path).write_text(report['action']+'\n'+report['action_label']+'\n')
    return report['status']


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        print('检查结论：检查未完成，暂时无法判断\n下一步：查看详情，核对报告工具与运行权限。')
        sys.exit(1)

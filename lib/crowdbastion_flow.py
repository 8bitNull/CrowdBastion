#!/usr/bin/env python3
"""Business intent and evidence-driven tasks; never executes system commands."""
import json
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import tempfile

from crowdbastion_ux import validate_private_destination

GOALS = ('system', 'web', 'proxy', 'remote')
GOAL_LABELS = {'system': '系统与登录安全', 'web': '网站防护',
               'proxy': '代理/中转检查', 'remote': '接收中心封禁结果'}
STATE_KEYS = {'version', 'goals', 'online_requests', 'program', 'selected_targets',
              'deferred', 'outcomes', 'last_task', 'deployment_scope'}
TOKEN = re.compile(r'[a-zA-Z0-9:._-]{1,160}\Z')
TARGET = re.compile(r'(?:host:(?:nginx|openresty)|docker:[0-9a-f]{12,64})\Z')


def normalize_goals(goals):
    if (not isinstance(goals, list) or any(not isinstance(g, str) or g not in GOALS for g in goals)
            or len(goals) != len(set(goals))):
        raise ValueError('防护目标无效或重复')
    if 'remote' in goals and ({'system', 'web'} & set(goals)):
        raise ValueError('请先选择本机检测或只接收中心结果，不能混合保存这两种方式')
    return [g for g in GOALS if g in goals]


def project_roles(goals, program='unknown'):
    goals = normalize_goals(goals)
    roles = ['remote'] if 'remote' in goals else ['web'] if 'web' in goals else ['relay'] if 'system' in goals else []
    if 'proxy' in goals and program == 'v2bx':
        roles.append('node')
    return roles


def new_state(goals, *, online_requests=False, program='unknown'):
    value = dict(version=1, goals=normalize_goals(goals), online_requests=online_requests,
                 program=program, selected_targets=[], deferred={}, outcomes={}, last_task='', deployment_scope=None)
    return validate_state(value)


def _stamp(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def validate_state(value):
    if not isinstance(value, dict) or set(value) != STATE_KEYS or type(value['version']) is not int or value['version'] != 1:
        raise ValueError('流程记录格式无效；可重新设置防护目标')
    goals = normalize_goals(value['goals'])
    if goals != value['goals'] or type(value['online_requests']) is not bool or value['program'] not in ('unknown', 'v2bx', 'other'):
        raise ValueError('流程偏好无效')
    targets = value['selected_targets']
    if (not isinstance(targets, list) or len(targets) > 128 or
            any(not isinstance(t, str) or not TARGET.fullmatch(t) for t in targets) or len(set(targets)) != len(targets)):
        raise ValueError('网站实例选择无效')
    if not isinstance(value['last_task'], str) or (value['last_task'] and not TOKEN.fullmatch(value['last_task'])):
        raise ValueError('任务标识无效')
    scope = value['deployment_scope']
    if scope is not None and (not isinstance(scope, dict) or set(scope) != {'choice', 'fingerprint'}
                              or scope['choice'] not in ('local', 'remote')
                              or not isinstance(scope['fingerprint'], str)
                              or not re.fullmatch(r'[0-9a-f]{64}', scope['fingerprint'])):
        raise ValueError('维护范围确认无效')
    for field, status_key, allowed in (('deferred', 'reason', {'later', 'cancelled'}),
                                       ('outcomes', 'state', {'failed', 'cancelled', 'returned', 'running', 'observed'})):
        records = value[field]
        if not isinstance(records, dict) or len(records) > 256:
            raise ValueError('流程历史无效')
        for key, row in records.items():
            if (not isinstance(key, str) or not TOKEN.fullmatch(key) or not isinstance(row, dict)
                    or set(row) != {'fingerprint', status_key, 'at'} or not isinstance(row[status_key], str) or row[status_key] not in allowed
                    or not isinstance(row['fingerprint'], str)
                    or not re.fullmatch(r'(?:[0-9a-f]{64}|absent)', row['fingerprint']) or not _stamp(row['at'])):
                raise ValueError('流程历史包含无效字段')
    return value


def intent_fingerprint(state):
    if state is None:
        return 'absent'
    validate_state(state)
    intent = {k: state[k] for k in ('goals', 'online_requests', 'program', 'selected_targets', 'deployment_scope')}
    return hashlib.sha256(json.dumps(intent, sort_keys=True).encode()).hexdigest()


def _state_path(path):
    path = Path(os.path.abspath(path))
    validate_private_destination(path, missing_parents=True)
    if path.exists() and path.stat().st_mode & 0o077:
        raise ValueError('流程记录必须仅允许当前管理员读取和写入')
    return path


def load_state(path):
    path = _state_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 262144 or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise ValueError('流程记录不安全或过大')
        return validate_state(json.load(stream))


def save_state(path, value):
    """Caller acquires the existing management lock before publishing intent."""
    validate_state(value)
    path = _state_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _state_path(path)
    fd, temporary = tempfile.mkstemp(prefix='.user-flow-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        _state_path(path)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


ACTIONS = frozenset({'choose_goals', 'choose_targets', 'choose_scope', 'inspect', 'core_diagnose',
                     'bouncer_diagnose', 'v2bx_diagnose', 'logs_diagnose', 'diagnose_log_realip',
                     'install_core_system', 'install_core_web', 'connect_remote',
                     'check_remote', 'check_firewall', 'configure_appsec',
                     'verify_realip', 'configure_transport', 'connect_website',
                     'verify_website', 'verify_entry', 'inspect_proxy',
                     'observer_manage', 'observer_diagnose', 'check_proxy', 'configure_web_logs', 'maintain_firewall', 'maintain_network',
                     'maintain_ports'})

MODIFYING_ACTIONS = frozenset({'install_core_system', 'install_core_web', 'connect_remote',
                              'configure_web_logs', 'configure_appsec', 'configure_transport',
                              'connect_website', 'verify_realip', 'verify_entry'})


def blocking_tasks(tasks):
    return [t['id'] for t in tasks if t['state'] != 'done' and
            (t['id'] in ('deployment.conflict', 'goals.scope') or t['id'].startswith('pending.'))]


def build_tasks(snapshot, state):
    """Derive work from current evidence, never from previous button presses."""
    if state is not None:
        validate_state(state)
    inv, checks = snapshot['inventory'], snapshot['checks']
    goals = state['goals'] if state else []
    scope = state.get('deployment_scope') if state else None
    scope_choice = scope['choice'] if scope and scope['fingerprint'] == snapshot['fingerprint'] else None
    tasks = []

    def add(ident, title, reason, action, *, target='', priority=40, deps=(), done=False, impact='', blocked=False):
        if action not in ACTIONS or not TOKEN.fullmatch(ident):
            raise ValueError('unsupported task')
        family = ident.split('.', 1)[0]
        component = {'bouncer': 'firewall', 'entry': 'firewall', 'remote': 'firewall', 'web': 'appsec', 'proxy': 'proxy'}.get(family, 'core')
        if ident.startswith('web.logs:'):
            component = 'core'
        relevant = {
            'core': ('core', 'config', 'api', 'logs', 'acquisition'),
            'bouncer': ('bouncer', 'config', 'remote'),
            'firewall': ('bouncer', 'rules', 'firewall_startup', 'firewall_paths', 'decisions', 'renewal'),
            'entry': ('bouncer', 'remote', 'rules', 'firewall_startup', 'firewall_paths', 'decisions', 'renewal', 'traffic'),
            'remote': ('remote', 'bouncer'),
            'web': ('core', 'config', 'api', 'appsec', 'web_rules'),
            'proxy': ('v2bx', 'v2bx_service', 'sockets', 'observer'),
        }.get(family, ())
        evidence = {'config': snapshot.get('component_fingerprints', {}).get(component, snapshot['fingerprint']),
                    'checks': {k: checks[k] for k in relevant if k in checks},
                    'target': next((t for t in snapshot['targets'] if t['id'] == target), None),
                    'pending': [p for p in snapshot['pending'] if ident == 'pending.'+p['kind']] if priority == 0 else []}
        if ident == 'web.targets':
            evidence['candidates'] = sorted(t['id'] for t in snapshot['targets'])
        fingerprint = hashlib.sha256(json.dumps(evidence, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        task = dict(id=ident, title=title, reason=reason, action=action, target=target,
                    priority=priority, dependencies=list(deps), state='done' if done else 'blocked' if blocked else 'ready',
                    evidence_fingerprint=fingerprint, impact=impact)
        task['completion_kind'] = 'auxiliary' if action == 'verify_website' else 'information' if action == 'inspect_proxy' else 'evidence'
        tasks.append(task)
        return ident

    if snapshot.get('pending_scan_complete') is False:
        add('pending.unknown', '先核验未完成变更记录',
            '变更记录不完整或无法读取；核验后才能安排新的修改。', 'inspect', priority=0)
    for item in sorted(snapshot['pending'], key=lambda t: t['kind']):
        kind = item['kind']
        action = {'firewall': 'maintain_firewall', 'network': 'maintain_network', 'port-policy': 'maintain_ports'}.get(kind)
        if action:
            add('pending.'+kind, '先处理未完成的'+{'firewall': '防火墙迁移', 'network': 'TCP 配置变更', 'port-policy': '端口策略变更'}[kind],
                '提交或回退入口仍可使用；退出不会取消原回退期限。', action, priority=0)
    if inv.get('core') and (inv.get('remote') or 'remote' in goals) and not scope_choice:
        add('deployment.conflict', '核对本机检测与远端执行配置',
            '已有本地核心，而当前配置或目标涉及远端执行；先确认本次方式，不自动迁移。',
            'choose_scope' if inv.get('remote') and state is not None else 'choose_goals', priority=10)
    if snapshot.get('scope_issue') or (state and project_roles(goals, state['program']) and
                                     snapshot.get('legacy_roles') is not None and
                                     not set(project_roles(goals, state['program'])) <= set(snapshot.get('legacy_roles', []))):
        add('goals.scope', '重新确认防护目标与用途范围',
            '保存的用途与目标不一致或用途记录无法读取；先确认范围，再安排修改。', 'choose_goals', priority=11)

    core_needed = (bool({'system', 'web'} & set(goals)) or inv.get('core')) and scope_choice != 'remote'
    core_dep = []
    if core_needed:
        if not inv.get('core'):
            action = 'install_core_web' if 'web' in goals else 'install_core_system'
            core_dep = [add('core.install', '安装'+('网站基础防护' if 'web' in goals else '系统与登录基础防护'),
                            '先安装系统检测与封禁基础；网站日志将在选定实例并核验来源后单独接入。' if 'web' in goals else
                            '当前目标需要本机检测服务和防火墙封禁，尚未发现完整配置。', action, priority=40)]
        else:
            config = add('core.config', '核对检测服务配置',
                         '配置校验有问题或尚未取得结果；先处理配置，再考虑启动服务。', 'core_diagnose',
                         priority=20, done=checks.get('config') == 'ok')
            running = add('core.service', '排查检测服务运行情况',
                          '服务没有运行或状态未知；先查看配置与日志，再选择是否启动。', 'core_diagnose',
                          priority=21, deps=[config], done=checks.get('core') == 'ok')
            api = add('core.api', '检查检测服务与组件的连接',
                      '本机检测接口尚未确认可用，先核对连接与服务日志。', 'inspect',
                      priority=22, deps=[config, running], done=checks.get('api') == 'ok')
            core_dep = [config, running, api]
            add('core.logs', '核对日志读取与解析',
                '日志暂时没有足够样本，产生正常访问或登录日志后再检查。' if checks.get('logs') == 'pending'
                else '需要确认日志采集与解析证据；没有样本和解析失败不能混为一谈。',
                'logs_diagnose', priority=23 if checks.get('logs') == 'fault' else 43,
                deps=core_dep, done=checks.get('logs') == 'ok')
    if 'remote' in goals and not inv.get('remote'):
        add('remote.connect', '连接已有检测中心', '先确认中心已经就绪，再预览本机接入范围。', 'connect_remote', priority=40)
    if inv.get('remote'):
        add('remote.check', '核对远端连接与决策接收',
            '发现远端配置；登记存在不能证明通信和本机执行正常。', 'check_remote',
            priority=24, done=checks.get('remote') == 'ok')
    bouncer_needed = core_needed or 'remote' in goals or inv.get('bouncer') or inv.get('remote')
    if bouncer_needed:
        add('bouncer.service', '核对防火墙封禁服务', '防火墙执行组件缺失或尚未正常运行。',
            'bouncer_diagnose' if inv.get('bouncer') or inv.get('remote') else 'connect_remote' if 'remote' in goals else 'install_core_web' if 'web' in goals else 'install_core_system',
            priority=25 if inv.get('bouncer') else 41, deps=core_dep, done=checks.get('bouncer') == 'ok')
        add('firewall.check', '核对防火墙规则与适用入口',
            '服务运行不等于流量经过封禁规则；需要完整的防火墙检查证据。', 'check_firewall',
            priority=44, deps=['bouncer.service'], done=checks.get('rules') == 'ok' and
            all(checks.get(k, 'ok') == 'ok' for k in ('firewall_startup', 'firewall_paths', 'decisions', 'renewal')))
    # Existing optional components remain visible even if the saved goal changes.
    if inv.get('appsec') and checks.get('appsec') in ('fault', 'unknown'):
        add('web.existing', '检查已有网站请求检测服务', '已部署的网站组件需要核查，当前目标不会隐藏它的故障。', 'inspect', priority=26)
    if inv.get('appsec') is None:
        add('appsec.unknown', '核对现有网站请求检测配置', '有效采集路径或配置无法读取，不能当成未安装；先补充只读检查证据。', 'inspect', priority=26)
    from crowdbastion_health import CATALOG
    handled = {'core', 'config', 'api', 'bouncer', 'logs', 'appsec', 'remote', 'v2bx_service', 'traffic'}
    if scope_choice == 'remote':
        handled -= {'core', 'config', 'api', 'logs'}
    for key, value in sorted(checks.items()):
        if value == 'fault' and key not in handled and key in CATALOG:
            add('component.'+key, '排查已部署组件：'+CATALOG[key][2],
                CATALOG[key][4]+' 本次目标不会隐藏现有组件故障。', 'inspect', priority=26)
    if inv.get('v2bx') and checks.get('v2bx_service') in ('fault', 'unknown', 'missing'):
        add('proxy.service', '排查已有 V2bX 服务', '当前目标不会隐藏已部署代理服务的故障；本项只排查。', 'v2bx_diagnose', priority=27)
    if inv.get('observer') and checks.get('observer') in ('fault', 'unknown', 'missing'):
        add('proxy.observer', '排查已有日志观察服务', '观察服务没有正常运行或尚未取得状态；先只读查看服务和日志。', 'observer_diagnose', priority=27)

    if not goals:
        if state is None:
            add('goals.confirm', '确认想保护什么', '已有配置先保留；选择目标只保存偏好，不安装或迁移组件。', 'choose_goals', priority=35)
        else:
            add('goals.inspect', '先检查当前配置与支持范围', '目标暂不确定时只读检查；以后可从首页 3 调整，不重复要求选择。', 'inspect', priority=35)

    web_prerequisites = []
    if 'web' in goals and scope_choice != 'remote':
        available = {t['id']: t for t in snapshot['targets']}
        selected = state['selected_targets']
        selection_ok = bool(selected) and all(t in available for t in selected)
        selection = add('web.targets', '选择要处理的网站实例',
                        '一个实例可能承载多个域名；先明确本次实际修改范围。' if available else
                        '尚未发现可核验的网站实例；先准备或检查网站运行环境，再重新选择。',
                        'choose_targets', priority=39, done=selection_ok, blocked=not available and not inv.get('core'))
        if not available and inv.get('core'):
            tasks[-1]['state'] = 'needs_input'
        web_prerequisites.append(selection)
        if selection_ok:
            for ident in selected:
                target = available[ident]
                source_dependencies = []
                if not state['online_requests']:
                    source = add('web.source:'+ident, '核对 '+target['label']+' 的日志访客来源',
                                 '先用外部正常请求对照访问日志中的访客 IP；代理信任配置或日志解析成功不能代替来源核验。只读诊断不会自动标为通过，证据不足时需人工核验。',
                                 'diagnose_log_realip', target=ident, priority=41,
                                 deps=core_dep+[selection], done=target.get('realip') == 'verified')
                    if target.get('realip') != 'verified':
                        tasks[-1]['state'] = 'needs_input'
                    source_dependencies.append(source)
                    web_prerequisites.append(source)
                else:
                    source_dependencies.append('web.realip:'+ident)
                ready = target.get('web_logs') == 'ok' and checks.get('web_rules') == 'ok'
                ready = ready and target.get('realip') == 'verified'
                connect_logs = target.get('web_logs') == 'missing' or checks.get('web_rules') == 'missing'
                add('web.logs:'+ident, '核对 '+target['label']+' 的网站日志防护',
                    '需要本实例的网站访问日志与适用规则证据；SSH 日志成功不能代替网站采集和解析。',
                    'configure_web_logs' if connect_logs else 'logs_diagnose',
                    target=ident, priority=42, deps=core_dep+[selection]+source_dependencies, done=ready)
        if state['online_requests']:
            engine = add('web.engine', '配置网站请求检测引擎',
                         '你选择了在线请求检查；先准备检测引擎，再接入网站。', 'configure_appsec',
                         priority=45, deps=core_dep+[selection]+(['appsec.unknown'] if inv.get('appsec') is None else []), done=checks.get('appsec') == 'ok')
            if selection_ok:
                for ident in selected:
                    target = available[ident]
                    dependencies = [engine, selection]
                    if target['runtime'] == 'docker' and target['network'] != 'host':
                        transport = add('web.transport:'+ident, '核对 '+target['label']+' 的私有连接',
                                        '需先准备可达的私有地址；登记不会创建网关或修改容器网络。',
                                        'configure_transport', target=ident, priority=46, deps=dependencies,
                                        done=target.get('transport') is True)
                        dependencies.append(transport)
                    connect = add('web.connect:'+ident, '接入 '+target['label']+' 的请求检查',
                                  '先预检现有配置，复用已有组件或安装兼容组件；实例内网站可能一同受影响。',
                                  'connect_website', target=ident, priority=47, deps=dependencies,
                                  done=target.get('connected') is True)
                    realip = add('web.realip:'+ident, '核验 '+target['label']+' 的真实访客 IP',
                                 '结合一次正常请求核对代理信任和来源，避免把共享代理出口当访客。',
                                 'verify_realip', target=ident, priority=48, deps=[connect],
                                 done=target.get('realip') == 'verified')
                    web_prerequisites.append(realip)
                    add('web.verify:'+ident, '运行 '+target['label']+' 的网站辅助测试',
                        '记录本实例的辅助测试结果；仍需关联外部请求的唯一标识、真实 IP 与规则日志，实际防护保持待验证。',
                        'verify_website', target=ident, priority=60, deps=[connect, realip],
                        done=target.get('request_verification') == 'verified')
    if 'proxy' in goals:
        if state['program'] == 'v2bx':
            add('proxy.inspect', '检查 V2bX 配置、运行与入口',
                '根据实际配置和运行证据检查；日志观察不等于业务攻击自动封禁。', 'check_proxy', priority=49,
                done=all(checks.get(k) == 'ok' for k in ('v2bx', 'v2bx_service', 'sockets')))
        else:
            add('proxy.inspect', '查看代理/中转适用范围',
                '本项只完成能力说明；程序实际运行与专项检测仍需另外核查。', 'inspect_proxy', priority=49)
    if bouncer_needed:
        add('entry.verify', '验证实际入口拦截', '需要独立测试设备和正常对照来源；仅针对选定入口、协议及地址族。',
            'verify_entry', priority=60, deps=[t['id'] for t in tasks if t['id'].startswith(('core.', 'bouncer.', 'firewall.', 'remote.', 'web.logs:'))]+web_prerequisites,
            done=(checks.get('traffic') == 'verified' or snapshot.get('acceptance', {}).get('valid') is True)
                 and all(t['state'] == 'done' for t in tasks if t['id'] in web_prerequisites))

    premises = blocking_tasks(tasks)
    for task in tasks:
        if task['action'] in MODIFYING_ACTIONS:
            task['dependencies'] = list(dict.fromkeys(task['dependencies'] + premises))
    by_id = {t['id']: t for t in tasks}
    for task in tasks:
        if task['state'] in ('done', 'blocked'):
            continue
        if any(by_id[d]['state'] != 'done' for d in task['dependencies']):
            task['state'] = 'blocked'
            continue
        previous = state['outcomes'].get(task['id'], {}) if state else {}
        deferred = state['deferred'].get(task['id'], {}) if state else {}
        if (previous.get('fingerprint') == task['evidence_fingerprint'] and previous.get('state') == 'observed'
                and task['action'] in ('verify_website', 'inspect_proxy')):
            task['state'] = 'done'
        elif deferred.get('fingerprint') == task['evidence_fingerprint']:
            task['state'] = 'deferred'
        elif previous.get('fingerprint') == task['evidence_fingerprint'] and previous.get('state') in ('failed', 'running'):
            task['state'] = 'failed'
    return sorted(tasks, key=lambda t: (t['priority'], t['id']))


def report(snapshot, state):
    tasks = build_tasks(snapshot, state)
    candidates = [t for t in tasks if t['state'] in ('ready', 'failed', 'needs_input')]
    recommended = candidates[0] if candidates else dict(id='inspect', title='查看当前运行情况', reason='可继续检查或在待办中恢复暂缓项目。',
                                                       action='inspect', target='', state='ready', dependencies=[],
                                                       priority=99, evidence_fingerprint=snapshot['fingerprint'], impact='')
    faults = any(s == 'fault' for s in snapshot['checks'].values())
    conclusion = '发现问题，需要处理' if faults else '有待完成或暂缓的防护设置，实际拦截待验证' if any(t['state'] != 'done' and t['priority'] < 60 for t in tasks) else '运行检查已完成，实际拦截待验证'
    if not snapshot.get('fingerprint_complete', False) or any(s == 'unknown' for s in snapshot['checks'].values()):
        conclusion = '部分检查未完成；'+('已发现的问题仍需处理' if faults else '暂时无法判断完整运行状态')
    goals = state['goals'] if state else []
    if goals == ['proxy'] and state['program'] != 'v2bx' and not snapshot['inventory'].get('core') and not snapshot['inventory'].get('remote'):
        conclusion = '已提供适用范围说明；程序运行与实际防护待验证'
    scope_label = '、'.join(GOAL_LABELS[g] for g in goals) or '现有部署（目标尚未确认）'
    scope = state.get('deployment_scope') if state else None
    if scope and scope['fingerprint'] == snapshot['fingerprint']:
        scope_label += '（本次维护'+('本机检测' if scope['choice'] == 'local' else '远端执行')+'）'
    return dict(conclusion=conclusion, scope=scope_label,
                checked_at=snapshot['checked_at'], tasks=tasks, recommended=recommended,
                deferred_count=sum(t['state'] == 'deferred' for t in tasks))

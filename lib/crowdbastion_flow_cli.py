#!/usr/bin/env python3
"""Private flow protocol: JSON data in, fixed tokens out; no shell evaluation."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
import re
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

import crowdbastion_flow as flow
from crowdbastion_flow_probe import discover, read_file


def read_json(path):
    return json.loads(read_file(path))


def token(path):
    # Check safety even when resetting corrupt JSON after explicit confirmation.
    path = flow._state_path(path)
    return hashlib.sha256(read_file(path)).hexdigest() if path.exists() else 'absent'


def current(snapshot, path):
    issue = ''
    try:
        state = flow.load_state(path)
    except (OSError, ValueError):
        state, issue = None, '流程记录无法安全读取；可从调整防护目标重新设置，权限或路径异常须先修正。'
    result = flow.report(snapshot, state)
    result['state_issue'] = issue
    return result, state


def dump(value):
    print(json.dumps(value, ensure_ascii=False, allow_nan=False))


def test_url(snapshot, target_id, url):
    target = next((t for t in snapshot['targets'] if t['id'] == target_id), None)
    parsed = urlsplit(url)
    if (target is None or parsed.scheme not in ('http', 'https') or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError('辅助请求必须属于所选网站实例')
    hostname = parsed.hostname.lower()
    if not any(fnmatchcase(hostname, str(name).lower()) for name in target.get('server_names', []) if name and name != '_' and '$' not in name):
        raise ValueError('网站地址未匹配所选实例的有效 server_name；请核对目标后再测试')


def render_home(result, snapshot):
    stamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(snapshot['checked_at']))
    print('\nCrowdBastion · 服务器防护')
    print('本次范围：'+result['scope'])
    print('检查时间：'+stamp)
    print('当前情况：'+result['conclusion'])
    labels = {'core': '检测服务运行', 'config': '检测配置有效', 'api': '检测接口可用',
              'logs': '日志读取与解析正常', 'bouncer': '封禁服务运行', 'remote': '远端连接检查通过'}
    confirmed = [label for key, label in labels.items() if snapshot['checks'].get(key) == 'ok']
    if confirmed:
        print('已确认：'+'、'.join(confirmed[:4]))
    print('实际拦截：需按入口、协议与地址族单独验证；历史记录不代表所有流量。')
    if snapshot.get('acceptance'):
        print(snapshot['acceptance']['summary'])
    if result['state_issue']:
        print(result['state_issue'])
    if snapshot.get('scope_issue'):
        print(snapshot['scope_issue'], file=sys.stderr)
    if snapshot['limitations']:
        print(f'检查说明：有 {len(snapshot["limitations"])} 项未完整核实，可查看详情。')
    if result['deferred_count']:
        print(f'保留待办：{result["deferred_count"]} 项已暂缓，可在任务列表恢复。')
    print('\n[1] '+result['recommended']['title']+'（推荐）')
    print('    '+result['recommended']['reason'])
    print('[2] 日常管理\n[3] 调整防护目标\n[4] 高级工具与检查详情\n[0] 退出')


def main(args):
    command, *values = args
    if command == 'snapshot':
        snapshot = dict(discover(Path(values[0]), Path(values[1])))
        try:
            snapshot['intent_token'] = flow.intent_fingerprint(flow.load_state(Path(values[1])/'user-flow.json'))
        except (OSError, ValueError):
            snapshot['intent_token'] = 'invalid'
        dump(snapshot)
    elif command == 'state':
        dump(flow.load_state(values[0]))
    elif command == 'token':
        print(token(values[0]))
    elif command == 'core-plan':
        path, profile, admin_ip = values
        if profile not in ('web', 'relay'):
            raise ValueError('invalid installation profile')
        if admin_ip:
            ipaddress.ip_address(admin_ip)
        flow._state_path(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(dict(version=1, profile=profile, admin_ip=admin_ip), stream)
    elif command == 'core-plan-read':
        path, profile = values
        flow._state_path(path)
        plan = read_json(path)
        if set(plan) != {'version', 'profile', 'admin_ip'} or plan['version'] != 1 or plan['profile'] != profile:
            raise ValueError('installation plan changed')
        if plan['admin_ip']:
            ipaddress.ip_address(plan['admin_ip'])
        print(plan['admin_ip'])
    elif command == 'prepare-goals':
        current_path, output, numbers, online, program = values
        mapping = {'1': 'system', '2': 'web', '3': 'proxy', '4': 'remote', '5': None}
        parts = numbers.split()
        if not parts or any(n not in mapping for n in parts) or ('5' in parts and len(parts) != 1):
            raise ValueError('请选择列出的业务目标，不能混合“不确定”和其他目标')
        state = flow.new_state([mapping[n] for n in parts if mapping[n]], online_requests=online == 'true', program=program)
        previous = None
        try:
            previous = flow.load_state(current_path)
        except (ValueError, OSError):
            pass
        if previous and previous['goals'] == state['goals'] and previous['program'] == state['program']:
            state['selected_targets'] = previous['selected_targets']
        flow.save_state(output, state)
        print('将保存目标：'+('、'.join(flow.GOAL_LABELS[g] for g in state['goals']) or '尚未确定，先检查现有配置'))
        print('网站请求检查：'+('按网站引导接入' if state['online_requests'] else '未选择；不自动安装'))
        print('本次只保存偏好，不安装、迁移或卸载组件。')
    elif command == 'save-goals':
        path, candidate, roles_path, expected = values
        if token(path) != expected:
            raise ValueError('目标记录已变化，请重新检查并确认')
        state = flow.validate_state(read_json(candidate))
        roles = flow.project_roles(state['goals'], state['program'])
        # Preflight both destinations before publishing either file.
        flow._state_path(path)
        if roles:
            from crowdbastion_node import save, safe_path
            safe_path(Path(roles_path))
            save(Path(roles_path), roles)
        flow.save_state(path, state)
    elif command in ('home', 'report', 'next', 'tasks', 'step', 'roles'):
        snapshot, path = read_json(values[0]), values[1]
        result, state = current(snapshot, path)
        if command == 'home':
            render_home(result, snapshot)
        elif command == 'report':
            dump(result)
        elif command == 'next':
            task = result['recommended']
            print('\t'.join((task['action'], task['target'] or '-', task['id'], task['evidence_fingerprint'])))
        elif command == 'tasks':
            names = {'done': '本项检查通过', 'blocked': '前提未完成', 'needs_input': '需要补充条件', 'ready': '可继续', 'failed': '上次未完成', 'deferred': '已暂缓'}
            for index, task in enumerate(result['tasks'], 1):
                label = names.get(task['state'], task['state'])
                if task['state'] == 'done' and task.get('completion_kind') in ('auxiliary', 'information'):
                    label = '辅助测试已完成，实际防护待验证' if task['completion_kind'] == 'auxiliary' else '适用说明已查看，运行待验证'
                print(f'{index}. {task["title"]} [{label}]')
                if task['state'] == 'blocked':
                    print('   先完成：'+'、'.join(d for d in task['dependencies'] if next(t for t in result['tasks'] if t['id'] == d)['state'] != 'done'))
        elif command == 'step':
            task = result['recommended']
            print('\n当前任务：'+task['title'])
            print('原因：'+task['reason'])
            if task['state'] == 'failed':
                print('上次尝试未完成或被中断；先核对错误和已生效的变更，不会自动重试。')
            print('1. 开始 / 明确重试\n2. 查看检查详情\n3. 查看全部待办与恢复暂缓项\n4. 暂时不处理\n5. 重新检查\n0. 返回首页')
        else:
            roles = flow.project_roles(state['goals'], state['program']) if state else []
            inv = snapshot['inventory']
            scope = state.get('deployment_scope') if state else None
            if scope and scope['fingerprint'] == snapshot['fingerprint']:
                roles = ['remote'] if scope['choice'] == 'remote' else ['web'] if 'web' in state['goals'] else ['relay']
            if not roles:
                roles = ['remote'] if inv['remote'] and not inv['core'] else ['web'] if inv['core'] and (snapshot['targets'] or inv['appsec']) else ['relay'] if inv['core'] else ['node'] if inv['v2bx'] else []
            if inv['v2bx'] and 'node' not in roles:
                roles.append('node')
            print(' '.join(roles))
    elif command == 'targets':
        for index, target in enumerate(read_json(values[0])['targets'], 1):
            print(f'{index}. {target["label"]}（{target["network"]}；作用于该运行实例内的适用网站）')
    elif command == 'target-count':
        print(len(read_json(values[0])['targets']))
    elif command == 'choose-scope':
        path, snapshot_path, choice = values
        state = flow.load_state(path)
        snapshot = read_json(snapshot_path)
        if state is None or choice not in ('local', 'remote') or not (snapshot['inventory']['core'] and snapshot['inventory']['remote']):
            raise ValueError('先确认目标及两类部署事实')
        state['deployment_scope'] = {'choice': choice, 'fingerprint': snapshot['fingerprint']}
        flow.save_state(path, state)
    elif command == 'check-test-url':
        snapshot_path, target_id, url = values
        test_url(read_json(snapshot_path), target_id, url)
    elif command == 'write-observation':
        path, kind, *scope = values
        data = dict(version=1, kind=kind, checked_at=time.time())
        if kind == 'web_auxiliary':
            target, site, request_id = scope
            if not flow.TARGET.fullmatch(target) or not re.fullmatch(r'[0-9a-f]{12,64}', request_id):
                raise ValueError('辅助请求记录无效')
            data.update(target=target, site=site, request_id=request_id)
        elif kind != 'proxy_guidance' or scope:
            raise ValueError('未支持的观察记录')
        flow._state_path(path)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
    elif command == 'record-observed':
        path, snapshot_path, ident, observation_path = values
        state = flow.load_state(path)
        snapshot = read_json(snapshot_path)
        if state is None or snapshot.get('intent_token') != flow.intent_fingerprint(state):
            raise ValueError('防护目标已变化，未记录过时的观察')
        task = next((t for t in flow.build_tasks(snapshot, state) if t['id'] == ident), None)
        flow._state_path(observation_path)
        data = read_json(observation_path)
        expected = 'web_auxiliary' if task and task['action'] == 'verify_website' else 'proxy_guidance' if task and task['action'] == 'inspect_proxy' else None
        if (expected is None or data.get('kind') != expected or type(data.get('version')) is not int or data['version'] != 1 or
                type(data.get('checked_at')) not in (int, float) or not 0 <= time.time()-data['checked_at'] <= 300):
            raise ValueError('观察证据无效或过期')
        if expected == 'web_auxiliary':
            if data.get('target') != task['target'] or not re.fullmatch(r'[0-9a-f]{12,64}', data.get('request_id', '')):
                raise ValueError('辅助请求与目标不匹配')
            test_url(snapshot, task['target'], data['site'])
        state['outcomes'][ident] = dict(fingerprint=task['evidence_fingerprint'], state='observed', at=data['checked_at'])
        flow.save_state(path, state)
    elif command == 'select-targets':
        path, snapshot_path, numbers, expected = values
        if token(path) != expected:
            raise ValueError('目标记录已变化，请重新选择')
        state = flow.load_state(path)
        if state is None or 'web' not in state['goals']:
            raise ValueError('请先保存网站防护目标')
        targets = read_json(snapshot_path)['targets']
        parts = numbers.split()
        if not parts or any(not p.isdecimal() or not 1 <= int(p) <= len(targets) for p in parts):
            raise ValueError('请选择列表中的网站实例编号')
        state['selected_targets'] = [targets[int(n)-1]['id'] for n in parts]
        flow.save_state(path, state)
    elif command in ('defer', 'record', 'resume'):
        path, snapshot_path, ident, *extra = values
        state = flow.load_state(path)
        if state is None:
            raise ValueError('请先保存防护目标，才能记录或暂缓任务')
        result = flow.report(read_json(snapshot_path), state)
        task = next((t for t in result['tasks'] if t['id'] == ident), None)
        if task is None:
            raise ValueError('任务已变化，请重新检查')
        if command == 'defer':
            state['deferred'][ident] = dict(fingerprint=task['evidence_fingerprint'], reason='later', at=time.time())
        elif command == 'resume':
            state['deferred'].pop(ident, None)
            state['outcomes'].pop(ident, None)
        else:
            if extra[0] not in ('running', 'returned', 'failed', 'cancelled'):
                raise ValueError('无效操作结果')
            state['outcomes'][ident] = dict(fingerprint=task['evidence_fingerprint'], state=extra[0], at=time.time())
            state['last_task'] = ident
        flow.save_state(path, state)
    elif command == 'resume-number':
        path, snapshot_path, number = values
        result, _ = current(read_json(snapshot_path), path)
        if not number.isdecimal() or not 1 <= int(number) <= len(result['tasks']):
            raise ValueError('请选择待办编号')
        task = result['tasks'][int(number)-1]
        if task['state'] != 'deferred':
            raise ValueError('该项目未被暂缓；请按推荐顺序处理其前提')
        return main(['resume', path, snapshot_path, task['id']])
    elif command == 'guard':
        snapshot_path, cs_dir, state_dir, target = values[:4]
        action = values[4] if len(values) > 4 else None
        previous = read_json(snapshot_path)
        state = flow.load_state(Path(state_dir)/'user-flow.json')
        if state is None or previous.get('intent_token') != flow.intent_fingerprint(state):
            raise ValueError('防护目标或流程记录已变化，请重新检查并预览')
        fresh = discover(Path(cs_dir), Path(state_dir))
        tasks = flow.build_tasks(fresh, state)
        if flow.blocking_tasks(tasks):
            raise ValueError('存在未处理变更或未确认的维护范围；暂缓不能解除修改前提')
        if not previous.get('fingerprint_complete') or not fresh['fingerprint_complete'] or previous['fingerprint'] != fresh['fingerprint']:
            raise ValueError('配置或检查前提已变化，请重新检查并预览')
        if target != '-':
            old = next((t for t in previous['targets'] if t['id'] == target), None)
            new = next((t for t in fresh['targets'] if t['id'] == target), None)
            if old is None or new is None or old['config_hash'] != new['config_hash'] or old['network'] != new['network']:
                raise ValueError('网站实例配置或网络已变化，请重新检查并选择')
            old_integration, new_integration = old.get('integration_hash'), new.get('integration_hash')
            if (not isinstance(old_integration, str) or not re.fullmatch(r'[0-9a-f]{64}', old_integration)
                    or old_integration != new_integration):
                raise ValueError('网站接入配置无法完整核对或已变化，请重新检查并预览')
        if action and not any(t['action'] == action and t['state'] in ('ready', 'failed') and (target == '-' or t['target'] == target)
                              for t in tasks):
            raise ValueError('当前目标或任务前提不再允许本次修改，请重新检查')
    elif command == 'merge-health':
        snapshot_path, health_path = values
        snapshot, health = read_json(snapshot_path), read_json(health_path)
        allowed = {'ok', 'fault', 'missing', 'unknown', 'pending', 'optional', 'verified'}
        for key, value in health.get('checks', {}).items():
            if key in __import__('crowdbastion_health').CATALOG and value in allowed:
                snapshot['checks'][key] = value
        # Legacy JSON keeps synthetic summary failures outside its check map.
        # Preserve that missing evidence in the new flow without changing CLI v1.
        if health.get('summary', {}).get('status') == 1 and not any(
                value in ('fault', 'missing', 'unknown') for value in health.get('checks', {}).values()):
            snapshot['checks']['check'] = 'unknown'
        dump(snapshot)
    else:
        raise ValueError('未知流程操作')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        print('[WARN] 流程记录、配置或输入无法安全核对，请重新检查；目标冲突时不能混合本机检测与远端执行。', file=sys.stderr)
        sys.exit(1)

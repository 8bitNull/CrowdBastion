#!/usr/bin/env python3
"""Operator-guided relay acceptance; every local command is read-only."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True


class Incomplete(ValueError):
    pass


class Cancelled(Exception):
    pass


def contains(value, address):
    if isinstance(value, dict) and 'elem' in value:
        value = value['elem']
    if isinstance(value, dict) and 'val' in value:
        value = value['val']
    if isinstance(value, str):
        return address in ipaddress.ip_network(value, strict=False)
    if isinstance(value, dict) and set(value) == {'prefix'}:
        prefix = value['prefix']
        return address in ipaddress.ip_network(str(prefix['addr'])+'/'+str(prefix['len']), strict=False)
    if isinstance(value, dict) and set(value) == {'range'}:
        start, end = (ipaddress.ip_address(item) for item in value['range'])
        return start.version == address.version == end.version and start <= address <= end
    raise Incomplete('无法识别封禁集合元素，不能判断测试来源是否已经入集。')


def nft_evidence(ruleset, family, table, names, hook, source):
    records = ruleset.get('nftables')
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise Incomplete('防火墙返回的规则格式无法识别。')
    address = ipaddress.ip_address(source)
    namespace = {family, 'inet'}
    sets, chains, named = {}, {}, {}
    for item in records:
        block = item.get('set', {})
        name = block.get('name')
        if block.get('family') in namespace and block.get('table') == table and isinstance(name, str):
            if any(name == base or name.startswith(base+'-') and len(name) > len(base)+1 for base in names):
                elements = block.get('elem', [])
                if not isinstance(elements, list):
                    raise Incomplete('封禁集合元素无法读取。')
                sets[(block['family'], '@'+name)] = any(contains(elem, address) for elem in elements)
        block = item.get('chain', {})
        if block.get('family') in namespace and block.get('table') == table:
            chains[(block.get('family'), block.get('name'))] = block.get('hook')
        block = item.get('counter', {})
        packets = block.get('packets')
        if block.get('table') == table and type(packets) is int and packets >= 0:
            named[(block.get('family'), block.get('name'))] = packets
    result = {'matched': False, 'present': False, 'rule_counters': {}, 'source_counters': {}}
    for item in records:
        rule = item.get('rule', {})
        version = rule.get('family')
        if version not in namespace or rule.get('table') != table or chains.get((version, rule.get('chain'))) != hook:
            continue
        expressions = rule.get('expr', [])
        if not isinstance(expressions, list) or any(not isinstance(expr, dict) for expr in expressions):
            raise Incomplete('封禁规则表达式无法读取。')
        # The standard bouncer source-set rule applies across all ports. Extra
        # predicates may refer to another entry, interface, state or source set.
        if (len(expressions) < 2 or set(expressions[0]) != {'match'} or
                set(expressions[-1]) not in ({'drop'}, {'reject'}) or
                any(set(expr) != {'counter'} for expr in expressions[1:-1])):
            continue
        references = []
        for expr in expressions:
            match = expr.get('match', {})
            right = match.get('right')
            if (match.get('op') in ('==', 'in') and
                    match.get('left') == {'payload': {'protocol': family, 'field': 'saddr'}} and
                    isinstance(right, str) and (version, right) in sets):
                references.append(right)
        if not references or not any('drop' in expr or 'reject' in expr for expr in expressions):
            continue
        result['matched'] = True
        present = any(sets[(version, name)] for name in references)
        result['present'] |= present
        # Counters reset or replacement rules must not appear as an increase.
        stable = [{key: {} if key == 'counter' and isinstance(value, dict) else value
                   for key, value in expr.items()} for expr in expressions]
        fingerprint = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()
        for index, expr in enumerate(expressions):
            counter = expr.get('counter')
            packets = named.get((version, counter)) if isinstance(counter, str) else counter.get('packets') if isinstance(counter, dict) else None
            if type(packets) is not int or packets < 0 or type(rule.get('handle')) is not int:
                continue
            key = (version, table, rule.get('chain'), rule['handle'], fingerprint, index)
            result['rule_counters'][key] = packets
            if present:
                result['source_counters'][key] = packets
    return result


def read_snapshot(root, scope):
    # Import existing YAML helpers only for the configuration read.
    from crowdsec_config import merged_config
    from crowdsec_relay import set_names
    try:
        data = merged_config(Path(root)/'bouncers/crowdsec-firewall-bouncer.yaml')
    except Exception:
        # YAML scanner errors can contain the credential line being parsed.
        raise Incomplete('无法读取 Bouncer 配置，请查看 --relay-status-details。') from None
    if data.get('mode') != 'nftables':
        raise Incomplete('本轮向导只支持 nftables；其他后端请按中转部署文档进行人工验收。')
    family = 'ipv4' if scope['family'] == 'ip' else 'ipv6'
    options = data.get('nftables', {}).get(family, {})
    if options.get('enabled', True) is not True or family == 'ipv6' and data.get('disable_ipv6') is True:
        raise Incomplete('所选地址族未启用防火墙防护。')
    table = options.get('table', 'crowdsec' if family == 'ipv4' else 'crowdsec6')
    try:
        process = subprocess.run(['nft', '-j', 'list', 'ruleset'], capture_output=True, text=True, timeout=15)
        if process.returncode:
            raise Incomplete('无法读取防火墙规则，请核对 nftables 权限和运行状态。')
        ruleset = json.loads(process.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        raise Incomplete('无法取得完整防火墙规则，请查看 --relay-status-details。') from None
    return nft_evidence(ruleset, scope['family'], table, set_names(data, family), scope['hook'], scope['source'])


def counter_increased(before, after):
    left, right = before['source_counters'], after['source_counters']
    if not left or left.keys() != right.keys() or any(right[key] < value for key, value in left.items()):
        return False
    return any(right[key] > value for key, value in left.items())


def single_ip(value, public=False):
    try:
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or '%' in value:
            raise ValueError
        if public and not address.is_global:
            raise ValueError
        return str(address)
    except ValueError:
        raise Incomplete('请输入单个可用 IP；测试与对照来源需使用实际公网 IP，不使用网段或示例地址。') from None


def verify(root, remote=False, ask=None, snapshot=None, env=None):
    ask = ask or input
    snapshot = snapshot or (lambda scope: read_snapshot(root, scope))
    env = os.environ if env is None else env
    scope = None
    failures, pending = [], []
    ban_shown, recovered, interrupted = False, False, False
    reason = 'crowdbastion-verify-'+uuid.uuid4().hex

    def answer(label):
        try:
            value = ask(label).strip()
        except EOFError:
            raise Cancelled from None
        if value.lower() in ('q', 'cancel'):
            raise Cancelled
        return value

    def result(label, fault):
        value = answer(label+' [1 成功 / 2 失败 / 0 不确定]: ')
        if value not in ('0', '1', '2'):
            raise Incomplete('测试结果只能选择 1、2 或 0。')
        if value == '0':
            pending.append('有外部连接测试尚未确认。')
        elif value == '2':
            failures.append(fault)
        return value == '1' if value != '0' else None

    print('中转入口验证向导 — 输入 q 取消。')
    print('准备独立测试设备和另一公网来源的正常对照设备，用同一个入口、同一种协议测试新连接。')
    print('外部连接结果由操作者确认；脚本只读本机规则，不发送请求、不创建或删除封禁。')
    try:
        target = single_ip(answer('目标中转入口 IP: '))
        port = answer('入口端口 [1-65535]: ')
        if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise Incomplete('入口端口必须是 1-65535 的整数。')
        protocol = {'1': 'TCP', '2': 'UDP'}.get(answer('测试协议 [1 TCP / 2 UDP]: '))
        hook = {'1': 'input', '2': 'forward'}.get(answer('已核对的流量路径 [1 用户态 INPUT / 2 NAT FORWARD / 3 Docker bridge / 0 不确定]: '))
        if not protocol or not hook:
            raise Incomplete('本轮只验证已核对的 INPUT/FORWARD；先用 --relay-path 核对来源和路径。')
        source = single_ip(answer('本机实际看到的独立测试来源公网 IP: '), public=True)
        control = single_ip(answer('正常对照来源公网 IP（须与测试来源不同）: '), public=True)
        detected = (env.get('SSH_CLIENT') or env.get('SSH_CONNECTION') or '').split()
        default_admin = detected[0] if detected else ''
        admin = answer('当前管理来源 IP'+('（回车使用 '+default_admin+'）' if default_admin else '（必须填写）')+': ')
        admin = single_ip(admin or default_admin)
        family = ipaddress.ip_address(target).version
        protected = {admin}
        for variable in ('SSH_CLIENT', 'SSH_CONNECTION'):
            fields = env.get(variable, '').split()
            if fields:
                try:
                    protected.add(str(ipaddress.ip_address(fields[0])))
                except ValueError:
                    pass
        if source in {control, target} | protected:
            raise Incomplete('测试来源不能是管理来源、正常对照来源或目标服务器；请换用独立设备。')
        if control == target:
            raise Incomplete('正常对照来源不能是目标服务器，请使用另一台外部设备。')
        if any(ipaddress.ip_address(item).version != family for item in (source, control)):
            raise Incomplete('目标、测试与对照来源的 IPv4/IPv6 必须一致。')
        if answer('确认来源已核对，测试 IP 不承载共享中转且设备／入口由你管理？[y/N]: ').lower() != 'y':
            raise Cancelled
        scope = {'target': target, 'port': int(port), 'protocol': protocol, 'hook': hook,
                 'family': 'ip' if family == 4 else 'ip6', 'source': source, 'control': control}
        initial = snapshot(scope)
        if initial['present']:
            raise Incomplete('测试来源已经在封禁集合中，请换用未被封禁的独立来源。')
        if not initial['matched'] or not initial['rule_counters']:
            raise Incomplete('所选链缺少可识别的封禁规则或计数，请先查看 --relay-status-details。')
        print('\n步骤 1/4：确认封禁前正常可达。')
        if protocol == 'UDP':
            print('UDP 必须用现有业务客户端确认应用响应；发送成功或无响应不能证明连接正常。')
        else:
            print('使用现有业务客户端建立新的 TCP 连接并确认业务响应，不复用已有长连接。')
        result('测试来源正常访问同一入口', '封禁前测试来源就无法连接，请先排查业务服务与转发路径。')
        result('正常对照来源访问同一入口', '封禁前正常对照来源就无法连接，请先排查业务服务与转发路径。')
        if failures or pending:
            raise Incomplete('封禁前的连接对照没有完成，未生成测试封禁命令。')
        print('\n步骤 2/4：短时封禁独立测试来源。')
        print('以下命令'+('仅在远端检测中心执行' if remote else '在本地 CrowdSec 核心执行')+'：')
        print('sudo cscli decisions add --ip '+source+' --duration 2m --reason '+reason+' --type ban')
        ban_shown = True
        print('该测试决策 2 分钟后到期；保持当前管理连接。等待 Bouncer 同步后继续。')
        if answer('已提交上述测试决策并等待同步？[y/N]: ').lower() != 'y':
            raise Cancelled
        before = snapshot(scope)
        if not before['present'] or not before['source_counters']:
            raise Incomplete('测试来源尚未同步到所选链的封禁集合，或对应计数无法读取。')
        print('\n步骤 3/4：对比封禁期间的新连接。')
        value = answer('测试来源的新连接 [1 仍成功 / 2 已失败 / 0 不确定]: ')
        if value not in ('0', '1', '2'):
            raise Incomplete('测试结果只能选择 1、2 或 0。')
        if value == '1':
            failures.append('测试来源仍能建立新连接，请核对看到的来源、转发路径和决策执行。')
        elif value == '0':
            pending.append('封禁期间的测试连接结果尚未确认。')
        result('正常对照来源仍可访问', '正常对照来源也无法连接，请排查共享来源、业务服务与转发路径。')
        after = snapshot(scope)
        if not after['present']:
            pending.append('测试期间来源已不在封禁集合，可能决策到期或来源发生变化。')
        if not counter_increased(before, after):
            pending.append('所选链对应封禁规则的计数未确认增加，或规则／计数发生重置。')
        print('\n步骤 4/4：等待测试决策到期并确认恢复。')
        print('等待这条 2 分钟决策到期；如需提前撤销，只删除本次原因对应的决策 ID。')
        print('本次原因：'+reason)
        if answer('测试决策已到期或已按本次 ID 撤销？[y/N]: ').lower() != 'y':
            raise Cancelled
        final = snapshot(scope)
        if final['present']:
            raise Incomplete('测试来源仍在封禁集合中，先等待同步并核查是否还有其他决策。')
        if not final['matched'] or not final['rule_counters']:
            raise Incomplete('恢复阶段无法确认防护规则仍然存在，请先核查防火墙状态。')
        recovered = True
        result('测试来源恢复访问同一入口', '测试来源未恢复连接，请查看业务状态、剩余决策与转发路径。')
        result('正常对照来源仍可访问同一入口', '正常对照来源未恢复连接，请查看业务状态与转发路径。')
    except Cancelled:
        pending.append('本次验证已取消或输入结束，尚未完成全部对照。')
    except KeyboardInterrupt:
        interrupted = True
        pending.append('本次验证已中断，尚未完成全部对照。')
    except Incomplete as error:
        pending.append(str(error))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError):
        # Configuration parser errors may contain secrets. Never echo them.
        pending.append('无法读取完整的配置或防火墙证据，请查看 --relay-status-details。')
    if ban_shown and not recovered:
        print('\n恢复提示：如已执行测试命令，让本次 2 分钟决策到期，再核对集合退出与业务恢复。')
        print('本次原因：'+reason+'；不要按 IP 删除其他封禁决策。')
    code = 1 if failures else 2 if pending else 0
    print('\n验收结论：'+{0: '本次入口验证通过（人工确认）', 1: '本次入口验证未通过', 2: '验证未完成'}[code])
    if scope:
        target = '['+scope['target']+']' if scope['family'] == 'ip6' else scope['target']
        print('验证范围：'+target+':'+str(scope['port'])+' / '+scope['protocol']+' / '+
              ('IPv4' if scope['family'] == 'ip' else 'IPv6')+' / '+scope['hook'].upper()+' / 新连接。')
        print('来源对照：测试 '+scope['source']+' / 正常 '+scope['control']+'。')
    if code:
        print('原因：'+(failures or pending)[0])
        print('下一步：先处理上述原因，再运行 --verify-relay；技术排查用 --relay-status-details 或 --relay-path。')
    else:
        print('已确认：外部连接对照、来源入集与退出、对应封禁规则计数增加。')
        print('证据说明：外部连接结果由操作者确认；集合计数也可能包含其他流量。')
        print('下一步：如还有其他入口、协议或地址族，分别验证；静态健康检查仍保留实际拦截待验证。')
    return 130 if interrupted else code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='/etc/crowdsec')
    parser.add_argument('--remote', action='store_true')
    options = parser.parse_args()
    return verify(options.root, remote=options.remote)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\n验收结论：验证未完成\n恢复提示：如已创建测试决策，等待其 2 分钟到期并确认恢复。')
        sys.exit(130)

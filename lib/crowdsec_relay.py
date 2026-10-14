#!/usr/bin/env python3
"""Minimal system acquisition and conservative, local-only firewall evidence."""
import glob
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import yaml
from crowdsec_config import acquisition_locations, go_escape, go_glob, merged_config, read, write


SSH_FILTERS = ['_SYSTEMD_UNIT=ssh.service', '_SYSTEMD_UNIT=sshd.service']


def stage_system_logs(root, destination, candidates):
    directory, single, target = acquisition_locations(root, 'crowdsec-1key-relay.yaml')
    paths = ([single] if single else []) + sorted(glob.glob(glob.escape(directory)+'/*.yaml')) + sorted(glob.glob(glob.escape(directory)+'/*.yml'))
    docs = [doc for doc in read(target, True) if doc] if target.exists() else []
    acquired = {}
    journal_ssh = False
    for path in dict.fromkeys(paths):
        if not Path(path).exists():
            continue
        for doc in read(path, True):
            if not doc:
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get('labels', {}), dict):
                raise ValueError('已有日志采集格式无效，请先核对配置。')
            kind = doc.get('labels', {}).get('type')
            if doc.get('source') == 'journalctl':
                filters = doc.get('journalctl_filter', [])
                if not isinstance(filters, list) or any(not isinstance(item, str) for item in filters):
                    raise ValueError('已有 journalctl_filter 必须为列表。')
                # Same-field journal matches are OR alternatives, not AND.
                # Even a constrained source can overlap SSH; never add another
                # source to "repair" it and accidentally count events twice.
                if not filters or set(filters) & set(SSH_FILTERS):
                    journal_ssh = True
                    if any(not item.startswith('_SYSTEMD_UNIT=') for item in filters):
                        print('[WARN] 已有 SSH journalctl 源含额外过滤条件，未新增重复采集；请人工核对完整覆盖。', file=sys.stderr)
                    if kind != 'syslog':
                        print('[WARN] SSH journalctl 源已有非 syslog 标签，未重复添加；请人工核对。', file=sys.stderr)
            if doc.get('source', 'file') != 'file':
                continue
            filenames = doc.get('filenames', [])
            if isinstance(filenames, str):
                filenames = [filenames]
            if not isinstance(filenames, list):
                raise ValueError('已有 filenames 必须为列表或字符串。')
            if doc.get('filename'):
                filenames = [*filenames, doc['filename']]
            for pattern in filenames:
                if not isinstance(pattern, str):
                    raise ValueError('已有日志路径必须为字符串。')
                for filename in go_glob(pattern):
                    acquired[os.path.realpath(filename)] = kind

    additions = []
    existing = [Path(path) for path in candidates if Path(path).is_file()]
    if not journal_ssh:
        pending = []
        for path in existing:
            canonical = os.path.realpath(path)
            if canonical in acquired:
                if acquired[canonical] != 'syslog':
                    print('[WARN] SSH 日志已有非 syslog 标签采集，未重复添加；请人工核对。', file=sys.stderr)
                continue
            pending.append(go_escape(str(path)))
            acquired[canonical] = 'syslog'
        if pending:
            additions.append({'filenames': pending, 'labels': {'type': 'syslog'}})
        elif not existing:
            if not shutil.which('journalctl'):
                raise ValueError('未发现认证日志且缺少 journalctl，请先准备 SSH 日志采集。')
            additions.append({'source': 'journalctl', 'journalctl_filter': SSH_FILTERS,
                              'labels': {'type': 'syslog'}})
            print('[INFO] 未发现认证文件，使用标准 SSH systemd unit 的 journalctl 采集；请用 cscli metrics 核验。', file=sys.stderr)
    write(destination, docs+additions, multiple=True)
    print(len(additions))


def command(args):
    if not shutil.which(args[0]):
        print('[尚未验证] 缺少 '+args[0]+'，无法读取对应规则。')
        return None
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        raise ValueError(args[0]+' 读取超时。') from None
    if result.returncode:
        raise ValueError(args[0]+' 读取失败，请检查权限与防火墙后端。')
    return result.stdout


def set_names(data, family):
    names = data.get('blacklists_'+family, ['crowdsec-blacklists' if family == 'ipv4' else 'crowdsec6-blacklists'])
    if isinstance(names, str):
        names = [names]
    if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
        raise ValueError('Bouncer blacklist 配置无效。')
    return set(names)


def iptables_paths(output, names):
    """Discover references only; preceding accepts/conditions still need live validation."""
    rules = {}
    for line in output.splitlines():
        words = shlex.split(line)
        if len(words) >= 3 and words[0] == '-A':
            rules.setdefault(words[1], []).append(words[2:])

    def reaches(chain, seen):
        if chain in seen:
            return False
        seen = seen | {chain}
        for words in rules.get(chain, []):
            verdict = next((words[i+1] for i, word in enumerate(words[:-1]) if word in ('-j', '-g')), None)
            for i, word in enumerate(words):
                if (word == '--match-set' and i+2 < len(words)
                        and words[i+1] in names and words[i+2] == 'src'
                        and '!' not in words[:i] and verdict in ('DROP', 'REJECT')):
                    return True
            if verdict in rules and reaches(verdict, seen):
                return True
        return False

    return {chain for chain in ('INPUT', 'FORWARD', 'DOCKER-USER') if reaches(chain, set())}


def nft_paths(ruleset, table, name, protocol):
    """Only count source-address drops in a matching, directly hooked chain."""
    records = ruleset.get('nftables')
    if not isinstance(records, list):
        raise ValueError('nft JSON 规则格式无效。')
    families = {protocol, 'inet'}
    sets = {}
    for entry in records:
        candidate = entry.get('set', {})
        actual = candidate.get('name')
        # Official nftables sets use <configured blacklist>-<decision origin>.
        # Keep exact names for older layouts and manually managed set-only rules.
        if isinstance(actual, str) and (actual == name or
                (actual.startswith(name+'-') and len(actual) > len(name)+1)):
            key = (candidate.get('family'), candidate.get('table'))
            sets.setdefault(key, set()).add('@'+actual)
    hooks = {(entry['chain'].get('family'), entry['chain'].get('table'), entry['chain'].get('name')):
             entry['chain'].get('hook') for entry in records if 'chain' in entry}
    found = set()
    for entry in records:
        rule = entry.get('rule', {})
        family = rule.get('family')
        references = sets.get((family, table), set())
        if family not in families or rule.get('table') != table or not references:
            continue
        hook = hooks.get((family, table, rule.get('chain')))
        if hook not in ('input', 'forward'):
            continue
        expressions = rule.get('expr', [])
        source_match = any(expr.get('match', {}).get('op') in ('==', 'in')
                           and expr.get('match', {}).get('left') == {'payload': {'protocol': protocol, 'field': 'saddr'}}
                           and isinstance(expr.get('match', {}).get('right'), str)
                           and expr['match']['right'] in references
                           for expr in expressions)
        drop = any('drop' in expr or 'reject' in expr for expr in expressions)
        if source_match and drop:
            found.add(hook.upper())
    return found


def report_paths(label, found):
    for chain in ('INPUT', 'FORWARD'):
        print(f'{label} {chain}: '+('已发现来源 IP 集合封禁规则引用' if chain in found else '尚未发现可识别的来源 IP 集合封禁规则引用'))
    if 'DOCKER-USER' in found:
        print(f'{label} DOCKER-USER: 已发现规则引用，需另核对 FORWARD 跳转顺序。')


def audit(root, core_required=True):
    print('中转防护只读检查：未发送请求、未创建封禁、未修改防火墙。')
    print('用户态监听通常检查 INPUT；内核 NAT 检查 FORWARD；Docker bridge 需另核对实际路径。')
    path = Path(root)/'bouncers/crowdsec-firewall-bouncer.yaml'
    if not path.exists():
        print('[尚未验证] Firewall Bouncer 未安装或配置缺失。')
        return 2
    data = merged_config(path)
    mode = data.get('mode')
    if mode not in ('iptables', 'nftables', 'ipset'):
        raise ValueError('Firewall Bouncer mode 无效。')
    error = False
    services = ('crowdsec', 'crowdsec-firewall-bouncer') if core_required else ('crowdsec-firewall-bouncer',)
    for service in services:
        if not shutil.which('systemctl'):
            print('[尚未验证] 缺少 systemctl，无法检查服务。')
            break
        result = subprocess.run(['systemctl', 'is-active', '--quiet', service], capture_output=True, timeout=15)
        if result.returncode:
            print('[异常] '+service+' 未运行或无法读取状态。')
            error = True
        else:
            print('[已发现] '+service+' 运行。')
    print('Bouncer 后端：'+mode)
    if mode in ('iptables', 'ipset'):
        output = command(['ipset', 'list', '-name'])
        present = set(output.splitlines()) if output is not None else set()
        if mode == 'ipset':
            print('[尚未验证] ipset 模式仅管理集合，过滤规则由部署者接入。')
        for family, label, binary in (('ipv4', 'IPv4', 'iptables'), ('ipv6', 'IPv6', 'ip6tables')):
            if family == 'ipv6' and data.get('disable_ipv6') is True:
                print('IPv6: 配置未启用（disable_ipv6）。')
                report_paths(label, set())
                continue
            names = set_names(data, family)
            print(label+' 封禁集合：'+('已发现' if names & present else '尚未发现'))
            if mode == 'iptables':
                chains = data.get('iptables_v4_chains' if family == 'ipv4' else 'iptables_v6_chains', data.get('iptables_chains', ['INPUT']))
                if not isinstance(chains, list) or any(not isinstance(chain, str) for chain in chains):
                    raise ValueError('Bouncer iptables chains 配置无效。')
                print(label+' 配置链：'+', '.join(chains))
                rules = command([binary, '-S'])
                report_paths(label, iptables_paths(rules, names & present) if rules is not None else set())
    else:
        output = command(['nft', '-j', 'list', 'ruleset'])
        ruleset = json.loads(output) if output is not None else {'nftables': []}
        for family, label, protocol in (('ipv4', 'IPv4', 'ip'), ('ipv6', 'IPv6', 'ip6')):
            block = data.get('nftables', {}).get(family, {})
            if not isinstance(block, dict):
                raise ValueError('Bouncer nftables 配置无效。')
            if block.get('enabled', False) is not True or (family == 'ipv6' and data.get('disable_ipv6') is True):
                print(label+': 配置未启用 nftables 防护。')
                report_paths(label, set())
                continue
            table = block.get('table', 'crowdsec' if family == 'ipv4' else 'crowdsec6')
            names = set_names(data, family)
            if not isinstance(table, str):
                raise ValueError('Bouncer nftables table/set 配置无效。')
            if block.get('set-only') is True:
                print(label+' set-only：仅管理集合，过滤规则由部署者接入。')
            print(label+' 配置表/集合：'+table+'/'+', '.join(sorted(names)))
            print(label+' 配置钩子：'+', '.join(data.get('nftables_hooks', ['input', 'forward'])))
            found = set()
            for name in names:
                found.update(nft_paths(ruleset, table, name, protocol))
            report_paths(label, found)
    print('[尚未验证] 实际业务阻断尚未验证；规则引用不证明顺序、匹配范围、LAPI 决策同步或已建立连接被阻断。')
    print('多跳/隧道节点可能只看到上游 IP；先核对来源，避免封禁整条链路。')
    print('此模式不提供 gost/realm 专用行为检测、连接限速或带宽型 DDoS 清洗。')
    return 1 if error else 2


def main(args):
    if len(args) >= 1 and args[0] == 'stage' and len(args) == 5:
        stage_system_logs(args[1], args[2], args[3:])
        return 0
    if len(args) == 2 and args[0] == 'audit':
        return audit(args[1])
    if len(args) == 2 and args[0] == 'audit-remote':
        return audit(args[1], core_required=False)
    raise ValueError('未知中转操作。')


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, TypeError, KeyError, AttributeError, yaml.YAMLError, subprocess.TimeoutExpired):
        # Never echo config values or untrusted tool output (including API keys).
        print('[ERROR] 中转采集配置无效或本地服务/防火墙读取失败，请核对配置、工具与权限。', file=sys.stderr)
        sys.exit(1)

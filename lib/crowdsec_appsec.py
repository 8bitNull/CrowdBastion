#!/usr/bin/env python3
"""Read effective Web Bouncer policies and assess bounded AppSec evidence."""
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

DEFAULTS = {'APPSEC_URL': '', 'APPSEC_DROP_UNREADABLE_BODY': 'false',
            'APPSEC_FAILURE_ACTION': 'passthrough', 'LAPI_FAILURE_ACTION': 'passthrough'}

def config(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*', line)
        if not match:
            raise ValueError('无法解释 Web Bouncer 配置行，请手动核对')
        key, value = match.groups()
        if key in result and (key.startswith('APPSEC_') or key == 'LAPI_FAILURE_ACTION'):
            raise ValueError('重复 Web Bouncer 配置键: '+key)
        result[key] = value.split(' #', 1)[0].strip()
    return result

def guard(path):
    if Path(path).exists():
        config(path)
        for line in Path(path).read_text().splitlines():
            if re.match(r'\s*APPSEC_URL\s*=', line) and not line.startswith('APPSEC_URL='):
                raise ValueError('非规范 APPSEC_URL 赋值，请先手动规范为 APPSEC_URL=，避免覆盖恢复记录')
    local = Path(str(path)+'.local')
    if local.exists() and config(local):
        raise ValueError(str(local)+' 存在有效覆盖，请先手动评估；未修改配置')

def effective(path):
    values = dict(DEFAULTS)
    values.update(config(path))
    local = Path(str(path)+'.local')
    if local.exists():
        values.update(config(local))
    for key in ('APPSEC_FAILURE_ACTION', 'LAPI_FAILURE_ACTION'):
        if values[key] not in ('deny', 'passthrough'):
            raise ValueError(key+' 需 deny/passthrough')
    return {key: values[key] for key in DEFAULTS}

def set_policy(path, body, failure, lapi=None):
    if (body not in ('true', 'false') or failure not in ('deny', 'passthrough')
            or lapi is not None and lapi not in ('deny', 'passthrough')):
        raise ValueError('正文策略需 true/false，AppSec/LAPI 故障策略需 deny/passthrough')
    guard(path)
    text = Path(path).read_text()
    choices = [('APPSEC_DROP_UNREADABLE_BODY', body), ('APPSEC_FAILURE_ACTION', failure)]
    if lapi is not None:
        choices.append(('LAPI_FAILURE_ACTION', lapi))
    for key, value in choices:
        text = re.sub(r'^\s*'+key+r'\s*=.*\n?', '', text, flags=re.M)
        text = text.rstrip('\n')+'\n'+key+'='+value+'\n'
    Path(path).write_text(text)

def counters(text):
    result = {'processed': 0, 'blocked': 0, 'rules': 0}
    recognized = False
    for line in text.splitlines():
        match = re.match(r'(cs_appsec_[a-z_]+)(?:\{.*\})?\s+([0-9.eE+-]+)(?:\s+\d+)?$', line)
        if not match:
            continue
        name, value = match.groups()
        value = float(value)
        if name == 'cs_appsec_reqs_total':
            result['processed'] += value
            recognized = True
        elif name == 'cs_appsec_block_total':
            result['blocked'] += value
        elif name == 'cs_appsec_rule_hits' and re.search(r'\brule_name="crowdsecurity/vpatch-env-access"', line):
            result['rules'] += value
    # No series before the first request is valid, if the endpoint is Prometheus.
    if not recognized and not any(line.startswith('# HELP ') for line in text.splitlines()):
        raise ValueError('无法读取 AppSec Prometheus 计数')
    return result

def verdict(http, before, after):
    if not before or not after or any(after[k] < before[k] for k in before):
        return 'inconclusive'
    delta = {k: after[k]-before[k] for k in before}
    if http == '403' and all(delta[k] > 0 for k in ('processed', 'blocked', 'rules')):
        return 'passed'
    if http.isdigit() and http != '000' and http != '403' and not any(delta.values()):
        return 'failed'
    return 'inconclusive'

def main():
    action, *args = sys.argv[1:]
    if action == 'validate-url':
        target = args[0]
        url = urlsplit(target)
        if (url.scheme not in ('http', 'https') or not url.hostname or url.username is not None
                or url.password is not None or url.path not in ('', '/')
                or '?' in target or '#' in target or any(c.isspace() or ord(c) < 32 for c in target)):
            raise ValueError('请输入无凭据、查询、片段或子路径的 HTTP(S) 网站根地址')
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError('网站端口无效')
    elif action == 'guard':
        guard(args[0])
    elif action == 'show':
        for key, value in effective(args[0]).items():
            print(key+'='+value)
    elif action == 'record-policy':
        state_path, name, config_path = args
        state = json.loads(Path(state_path).read_text())
        entry = state[name]
        if Path(config_path) != Path(entry['host_assets'])/'bouncer.conf':
            raise ValueError('原生 Web Bouncer 策略路径与记录不匹配')
        from crowdsec_web import resource_hashes
        entry['resource_hashes']['bouncer.conf'] = resource_hashes(entry['host_assets'])['bouncer.conf']
        Path(state_path).write_text(json.dumps(state, indent=2)+'\n')
    elif action == 'policy':
        set_policy(*args)
    elif action == 'snapshot':
        print(json.dumps(counters(Path(args[0]).read_text())))
    elif action == 'verdict':
        before, after = [json.loads(Path(p).read_text()) if Path(p).stat().st_size else None for p in args[1:]]
        result = verdict(args[0], before, after)
        print(result)
        return {'passed':0, 'failed':1, 'inconclusive':2}[result]
    else:
        raise ValueError('未知 AppSec 操作')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)

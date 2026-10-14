"""Correlate one normal HTTP request with the IP passed to a managed Lua Bouncer."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlencode, urlsplit, urlunsplit

from crowdsec_realip_diagnose import client_address, http_directives
from crowdsec_web import check_install, directives, mount_path, read_state, save_state
from crowdbastion_health import emit

HOST_APPSEC_URL = 'http://127.0.0.1:7422'


def config_digest(text):
    return hashlib.sha256('\n'.join(line for line in text.splitlines() if not line.startswith('nginx:')).encode()).hexdigest()


def host_hook(effective, links, service, config):
    from crowdsec_config import read
    from crowdsec_realip import sections
    if service not in ('nginx', 'openresty') or config not in (read(links) if Path(links).is_file() else {}):
        raise ValueError('宿主机官方 Bouncer 尚未由本工具接入 AppSec')
    settings = Path(config).read_text()
    if re.findall(r'^APPSEC_URL=(.*)$', settings, re.M) != [HOST_APPSEC_URL]:
        raise ValueError('宿主机 AppSec 地址已变化，请先核对接入')
    local = Path(config+'.local')
    if local.exists() and re.search(r'^\s*APPSEC_URL\s*=', local.read_text(), re.M):
        raise ValueError('本地覆盖文件改变 AppSec 地址，未插入诊断钩子')
    parsed = list(directives(effective))
    hooks = [words for _, words, _ in parsed if words and words[0].startswith('access_by_lua')]
    if hooks != [['access_by_lua_block']] or any(words == ['satisfy', 'any'] for _, words, _ in parsed):
        raise ValueError('宿主机需使用单一官方 inline 访问钩子，且不能被站点钩子或 satisfy any 绕过')
    candidates = [(path, text) for path, text in sections(effective) if 'cs.Allow(ngx.var.remote_addr)' in text]
    if len(candidates) != 1:
        raise ValueError('无法唯一定位官方 Bouncer 的访问钩子')
    target, dumped = candidates[0]
    if not target.endswith('/crowdsec_'+service+'.conf') or not Path(target).is_file() or Path(target).is_symlink():
        raise ValueError('官方钩子文件路径不符合已验证布局')
    original = Path(target).read_text()
    if original.strip() != dumped.strip() or config not in effective or original.count('cs.Allow(ngx.var.remote_addr)') != 1:
        raise ValueError('官方钩子文件与有效配置不一致')
    return target


def plan(effective_file, mounts_file, installs, name, url, expected, token, destination, host_config=None):
    effective = Path(effective_file).read_text()
    mounts = json.loads(Path(mounts_file).read_text())
    if host_config:
        target = host_hook(effective, installs, name, host_config)
    else:
        entry = check_install(installs, name, mounts)
        if entry['status'] != 'installed':
            raise ValueError('只支持已完整安装的本工具 Web Bouncer')
        remote = entry['container_assets']+'/access.lua'
        target, _ = mount_path(remote, mounts)
        if target != str(Path(entry['host_assets'])/'access.lua'):
            raise ValueError('Lua 钩子挂载已变化')
        hooks = [words for _, words, _ in directives(effective) if words and words[0].startswith('access_by_lua')]
        if hooks != [['access_by_lua_file', remote]] or any(words == ['satisfy', 'any'] for _, words, _ in directives(effective)):
            raise ValueError('只支持所有站点使用同一个受管理访问钩子且无 satisfy any 的环境')
    parsed = urlsplit(url)
    names = {value for _, words, _ in directives(effective) if words and words[0] == 'server_name' for value in words[1:]}
    if (parsed.scheme not in ('http', 'https') or parsed.hostname not in names or parsed.username
            or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('请输入所选 Web 服务中明确配置的站点根地址，不含凭据、查询参数或路径')
    expected = str(ipaddress.ip_address(expected))
    if not re.fullmatch(r'[a-f0-9]{24}', token):
        raise ValueError('请求标记无效')
    original = Path(target).read_text()
    if original.count('cs.Allow(ngx.var.remote_addr)') != 1:
        raise ValueError('访问钩子已变化，未插入诊断代码')
    paths = []
    wait_seconds = 25
    for context, words, _ in http_directives(effective):
        if len(words) < 2 or words[0] not in ('access_log', 'error_log') or 'stream' in context:
            continue
        if not words[1].startswith('/') or '$' in words[1] or words[1].startswith('/dev/'):
            continue
        if words[0] == 'access_log' and any(value.startswith('buffer=') for value in words[2:]):
            flushing = [value.removeprefix('flush=') for value in words[2:] if value.startswith('flush=')]
            if len(flushing) != 1 or not re.fullmatch(r'\d+(?:ms|s|m)?', flushing[0]):
                raise ValueError('访问日志有 buffer 但缺少可核对的 flush 时间，无法进行有界请求核验')
            duration = re.fullmatch(r'(\d+)(ms|s|m)?', flushing[0])
            seconds = int(duration[1])*{'ms': .001, 's': 1, 'm': 60, None: 1}[duration[2]]
            if seconds > 115:
                raise ValueError('访问日志 flush 超过 115 秒，请先人工调整或等待日志后手动核对')
            wait_seconds = max(wait_seconds, int(seconds)+5)
        try:
            local, _ = mount_path(words[1], [{**mount, 'RW': True} for mount in mounts])
            if Path(local).is_file():
                paths.append({'path': local, 'kind': words[0]})
        except ValueError:
            continue
    if not {item['kind'] for item in paths} >= {'access_log', 'error_log'}:
        raise ValueError('缺少可读取的持久化访问/错误日志')
    diagnostic = ('local crowdsec_checked_ip = ngx.var.remote_addr\n'
                  'if ngx.var.arg_crowdsec_ip_check == '+json.dumps(token)+' then\n'
                  '    local json = require "cjson.safe"\n'
                  '    ngx.log(ngx.ERR, "crowdsec-1key-ip|'+token+'|", json.encode({client=ngx.var.remote_addr, bouncer=crowdsec_checked_ip, peer=ngx.var.realip_remote_addr, cf=ngx.var.http_cf_connecting_ip, xff=ngx.var.http_x_forwarded_for, real=ngx.var.http_x_real_ip, host=ngx.var.host}))\n'
                  'end\ncs.Allow(crowdsec_checked_ip)')
    request_url = urlunsplit((parsed.scheme, parsed.netloc, '/', urlencode({'crowdsec_ip_check': token}), ''))
    save_state(destination, {'target': target, 'before': hashlib.sha256(original.encode()).hexdigest(),
                            'instrumented': original.replace('cs.Allow(ngx.var.remote_addr)', diagnostic),
                            'url': request_url, 'site': parsed.hostname, 'expected': expected,
                            'token': token, 'logs': paths, 'config_sha': config_digest(effective),
                            'wait_seconds': wait_seconds,
                            'settings_sha': host_settings_digest(host_config) if host_config else None})


def host_settings_digest(config):
    target = Path(config)
    local = Path(config+'.local')
    return hashlib.sha256(target.read_bytes()+b'\0'+(local.read_bytes() if local.exists() else b'')).hexdigest()


def stage(plan_file):
    data = read_state(plan_file)
    target = Path(data['target'])
    if hashlib.sha256(target.read_bytes()).hexdigest() != data['before']:
        raise ValueError('Lua 文件在预检后变化，未覆盖')
    target.write_text(data['instrumented'])


def tail(path):
    with Path(path).open('rb') as stream:
        stream.seek(0, 2)
        start = max(0, stream.tell()-131072)
        stream.seek(start)
        lines = stream.read(131072).decode(errors='replace').splitlines()
        return lines[1:] if start else lines


def verify(plan_file, result_file):
    data = read_state(plan_file)
    traces, clients = [], []
    for entry in data['logs']:
        for line in tail(entry['path']):
            if entry['kind'] == 'error_log':
                marker = 'crowdsec-1key-ip|'+data['token']+'|'
                if marker in line:
                    trace, _ = json.JSONDecoder().raw_decode(line.split(marker, 1)[1])
                    if trace.get('host') == data['site']:
                        traces.append(trace)
            elif 'crowdsec_ip_check='+data['token'] in line:
                address = client_address(line)
                if address:
                    clients.append(address)
    if not traces or not clients:
        raise ValueError('未找到同一请求的 Bouncer 诊断与访问日志；请求可能被 CDN/原 WAF 提前拦截')
    trace = traces[-1]
    print('连接对端：'+str(trace.get('peer', trace.get('client'))))
    print('CF-Connecting-IP：'+str(trace.get('cf', '缺失')))
    print('X-Forwarded-For：'+str(trace.get('xff', '缺失')))
    print('访问日志 IP：'+clients[-1]+'；Bouncer IP：'+str(trace.get('bouncer'))+'；预期 IP：'+data['expected'])
    addresses = [trace.get('client'), trace.get('bouncer'), clients[-1]]
    if any(str(ipaddress.ip_address(address)) != data['expected'] for address in addresses):
        if not trace.get('cf') and trace.get('xff', '').split(',')[-1].strip() == data['expected']:
            print('CF 访客头缺失，但 XFF 最右地址符合预期；核对上游后，可选择 --repair-real-ip 的 Cloudflare XFF 模式。')
        raise ValueError('同一请求的访客 IP 不一致，请核对上游 Header 和信任范围；未扩大代理信任')
    save_state(result_file, {'site': data['site'], 'client': data['expected'], 'peer': trace.get('peer'),
                             'config_sha': data['config_sha'], 'bouncer_sha': data['before'],
                             'settings_sha': data.get('settings_sha'),
                             'verified_at': datetime.now(timezone.utc).isoformat()})


def status(state_file, name, effective_file, installs, mounts_file, host_config=None):
    effective = Path(effective_file).read_text()
    names = {value for _, words, _ in directives(effective) if words and words[0] == 'server_name'
             for value in words[1:] if '.' in value and '$' not in value}
    for value in list(names):
        try:
            ipaddress.ip_address(value)
            names.remove(value)
        except ValueError:
            pass
    records = read_state(state_file).get(name, {})
    try:
        if host_config:
            target = host_hook(effective, installs, name.removeprefix('host:'), host_config)
            hook_sha = hashlib.sha256(Path(target).read_bytes()).hexdigest()
        else:
            entry = check_install(installs, name, json.loads(Path(mounts_file).read_text()))
            remote = entry['container_assets']+'/access.lua'
            hooks = [words for _, words, _ in directives(effective) if words and words[0].startswith('access_by_lua')]
            if hooks != [['access_by_lua_file', remote]] or any(words == ['satisfy', 'any'] for _, words, _ in directives(effective)):
                raise ValueError('有效请求钩子已变化')
            hook_sha = hashlib.sha256((Path(entry['host_assets'])/'access.lua').read_bytes()).hexdigest()
    except (ValueError, OSError, KeyError):
        hook_sha = None
    registered = read_state(installs).get(name, {}) if not host_config else {}
    deployed = (bool(registered) or
                bool(host_config and (Path(host_config).exists() or Path(host_config).is_symlink())) or
                any(words and words[0].startswith('access_by_lua') and any('crowdsec' in word.lower() or 'cs.Allow' in word for word in words) for _, words, _ in directives(effective)))
    if deployed:
        emit('web', 'required')
        emit('web', 'ok' if hook_sha and names else 'unknown')
    else:
        emit('web', 'optional')
    unknown = False
    for site in sorted(names):
        record = records.get(site, {})
        try:
            age = (datetime.now(timezone.utc)-datetime.fromisoformat(record['verified_at'])).total_seconds()
            valid = (0 <= age < 86400 and record['config_sha'] == config_digest(effective)
                     and hook_sha and record['bouncer_sha'] == hook_sha)
            if host_config:
                valid = valid and record.get('settings_sha') == host_settings_digest(host_config)
        except (KeyError, ValueError):
            valid = False
        if valid:
            print('[正常] 真实 IP 最近已核验：'+site)
        else:
            command = '--verify-host-real-ip' if host_config else '--verify-real-ip'
            print('[尚未验证] 真实 IP：'+site+'；运行 '+command+' 关联一次正常请求。')
            unknown = True
    return 2 if unknown or not names else 0


def main(args):
    action, *args = args
    if action in ('plan', 'plan-host'):
        plan(*args)
    elif action == 'stage':
        stage(*args)
    elif action == 'verify':
        verify(*args)
    elif action == 'record':
        state_file, name, result_file = args
        state = read_state(state_file)
        result = read_state(result_file)
        state.setdefault(name, {})[result['site']] = result
        save_state(state_file, state)
    elif action in ('status', 'status-host'):
        return status(*args)
    else:
        raise ValueError('未知请求核验操作')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('请求核验失败：'+str(error), file=sys.stderr)
        sys.exit(1)

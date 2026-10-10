#!/usr/bin/env python3
"""Persistent native Web Bouncer installation; never execute a vendor installer."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile

BOUNCER_SHA = '2a3dceeb166b3fabb450c1c9a5ccd960d1493f5aa52677a9be2be36d6014a0bf'
HTTP_SHA = 'f52a0538b20a2d45025f318c18a138b78f6f88f07713dd0ed502183cb3d16f17'
WAF_PATH = '/usr/local/openresty/1pwaf/data/conf/waf.conf'
PHASES = {'init': 'init_by_lua_file', 'access': 'access_by_lua_file',
          'worker': 'init_worker_by_lua_file'}
ORIGINAL = {'init': '/usr/local/openresty/1pwaf/init.lua',
            'access': '/usr/local/openresty/1pwaf/waf.lua',
            'worker': '/usr/local/openresty/1pwaf/worker.lua',
            'log': '/usr/local/openresty/1pwaf/log_and_traffic.lua'}


def safe_path(path):
    if not re.fullmatch(r'/[a-zA-Z0-9_./ -]+', str(path)) or '..' in Path(path).parts:
        raise ValueError('路径含不支持的字符或父目录引用')
    return str(path)


def mount_path(target, mounts):
    safe_path(target)
    matches = [m for m in mounts if target == m['Destination'].rstrip('/')
               or target.startswith(m['Destination'].rstrip('/')+'/')]
    if not matches:
        raise ValueError('配置和资源必须位于持久化挂载中')
    mount = max(matches, key=lambda m: len(m['Destination'].rstrip('/')))
    if mount.get('Type') not in ('bind', 'volume') or not mount.get('RW', True):
        raise ValueError('配置被只读或非持久化挂载遮住')
    source = Path(safe_path(mount['Source']))
    result = source/target[len(mount['Destination'].rstrip('/')):].lstrip('/')
    for ancestor in [result, *result.parents]:
        if ancestor.is_symlink():
            raise ValueError('安装路径不能经过符号链接')
    return str(result), mount


def directives(text):
    """Tokenize nginx directives with their local context (nginx -T is not expanded)."""
    tokens = re.findall(r'#[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};#]+', text)
    stack, words = [], []
    for token in tokens:
        if token.startswith('#'):
            continue
        if token == '{':
            stack.append(words[0] if words else '?')
            yield tuple(stack[:-1]), words, True
            words = []
        elif token == '}':
            if stack:
                stack.pop()
            words = []
        elif token == ';':
            yield tuple(stack), words, False
            words = []
        else:
            words.append(token.strip('"\''))


def plan_install(effective, mounts, image, network, version):
    if network != 'host':
        raise ValueError('自动安装仅支持 host 网络；bridge 需私有可达的 LAPI/AppSec 地址')
    if not ('openresty/' in version.lower() or 'ngx_http_lua' in version
            or re.search(r'load_module\s+[^;]*ngx_http_lua[^;]*;', effective)):
        raise ValueError('缺少 Lua 模块；科技lion 默认 nginx:alpine 不能直接加载 OpenResty Bouncer，请先部署兼容 Lua 的 Web 服务')
    parsed = list(directives(effective))
    if any(words == ['satisfy', 'any'] for _, words, _ in parsed):
        raise ValueError('satisfy any 可能绕过 Lua 请求检查；请先核对并调整访问控制')
    hooks = [words for _, words, _ in parsed if words and
             re.match(r'(init|init_worker|access|log)_by_lua', words[0])]
    packages = [words for _, words, _ in parsed if words and words[0] == 'lua_package_path']
    is_waf = ('# configuration file '+WAF_PATH+':') in effective
    if is_waf:
        expected = [[directive, ORIGINAL[phase]] for phase, directive in PHASES.items()]
        expected.append(['log_by_lua_file', ORIGINAL['log']])
        if sorted(hooks) != sorted(expected) or len(packages) != 1:
            raise ValueError('现有 Lua 钩子不符合已验证的 1Panel WAF 布局，未覆盖原逻辑')
        target = WAF_PATH
        host, mount = mount_path(target, mounts)
        original = Path(host).read_text()
        # Do not combine stale host files with the running container config.
        if sorted([w for _, w, _ in directives(original) if w and
                   re.match(r'(init|init_worker|access|log)_by_lua', w[0])]) != sorted(expected):
            raise ValueError('挂载配置与有效 Lua 钩子不一致')
        assets = '/usr/local/openresty/1pwaf/data/crowdsec-1key'
        mode = '1panel'
    else:
        if hooks or packages:
            raise ValueError('发现已有 Lua 钩子/搜索路径，请人工合并以保留现有防护')
        includes = [w[1] for ctx, w, block in parsed
                    if ctx == ('http',) and not block and len(w) == 2 and w[0] == 'include']
        if '/data/nginx/custom/http_top[.]conf' in includes or '/data/nginx/custom/http_top.conf' in includes:
            target = '/data/nginx/custom/http_top.conf'
            assets = '/data/crowdsec-1key'
            mode = 'npm'
        elif '/etc/nginx/conf.d/*.conf' in includes:
            target = '/etc/nginx/conf.d/crowdsec-1key.conf'
            assets = '/etc/nginx/conf.d/crowdsec-1key'
            mode = 'nginx'
        else:
            raise ValueError('未找到已启用的 HTTP 层持久化配置入口')
        host, mount = mount_path(target, mounts)
        original = Path(host).read_text() if Path(host).exists() else None
        if original and 'crowdsec-1key' in original:
            raise ValueError('已有安装文件，请先核对安装记录')
    host_assets, _ = mount_path(assets, mounts)
    if Path(host_assets).exists():
        raise ValueError('资源目录已经存在，请先核对或撤销旧安装')
    if re.search(r'\bcrowdsec_cache\b', effective):
        raise ValueError('已有 CrowdSec 字典，请使用已有 Bouncer 接入')
    return dict(mode=mode, image=image, host_target=host, container_target=target,
                host_assets=host_assets, container_assets=assets, original=original,
                original_mode=Path(host).stat().st_mode & 0o777 if Path(host).exists() else 0o644)


def render_hooks(plan):
    assets = safe_path(plan['container_assets'])
    text = plan['original'] or ''
    if plan['mode'] == '1panel':
        for phase, directive in PHASES.items():
            text = re.sub(r'\b'+directive+r'\s+[^;]+;',
                          directive+' "'+assets+'/'+phase+'.lua";', text)
        text = re.sub(r'(lua_package_path\s+["\'])([^"\']+)(["\']\s*;)',
                      lambda m: m[1]+m[2]+';'+assets+'/lib/?.lua'+m[3], text)
    else:
        text += '\n# crowdsec-1key managed Web Bouncer\n'
        text += 'lua_package_path "'+assets+'/lib/?.lua;;";\n'
        text += ''.join(directive+' "'+assets+'/'+phase+'.lua";\n'
                        for phase, directive in PHASES.items())
    text += '\nlua_shared_dict crowdsec_cache 50m;\n'
    files = {'target': text}
    for phase in PHASES:
        body = '-- crowdsec-1key: original WAF runs first\n'
        if plan['mode'] == '1panel':
            # dofile is a C-call boundary and breaks yielding ngx.exit/cosocket calls.
            body += 'assert(loadfile('+json.dumps(ORIGINAL[phase])+'))()\n'
        body += 'local cs = require "crowdsec_1key.crowdsec"\n'
        if phase == 'init':
            body += 'local ok, err = cs.init('+json.dumps(assets+'/bouncer.conf')+', "crowdsec-openresty-bouncer/v1.2.3")\nif ok == nil then error(err) end\n'
        elif phase == 'access':
            body += 'cs.Allow(ngx.var.remote_addr)\n'
        else:
            body += 'if string.lower(cs.get_mode()) == "stream" then cs.SetupStream() end\nif ngx.worker.id() == 0 then cs.SetupMetrics() end\n'
        files[phase+'.lua'] = body
    return files


def verify_archive(path, expected_sha256):
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected_sha256:
        raise ValueError('官方资源 SHA256 校验失败，未安装')


def stage_assets(plan, bouncer_archive, http_archive, stage, key, api_url):
    verify_archive(bouncer_archive, BOUNCER_SHA)
    verify_archive(http_archive, HTTP_SHA)
    if not re.fullmatch(r'[a-zA-Z0-9_+/=-]{16,}', key.strip()):
        raise ValueError('Bouncer API Key 无效')
    if not re.fullmatch(r'http://(?:127\.0\.0\.1|localhost):[0-9]+/?', api_url):
        raise ValueError('自动安装仅使用 loopback LAPI；请核对 local_api_credentials.yaml')
    stage = Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    def namespace(text):
        # Keep proprietary WAF dependencies in their original namespace.
        return re.sub(r'(["\'])(plugins\.crowdsec(?:\.[a-zA-Z_]+)*|resty\.http(?:_[a-zA-Z_]+)?)(["\'])',
                      lambda m: m[1]+'crowdsec_1key.'+m[2]+m[3], text)
    for archive, prefix in [(bouncer_archive, 'crowdsec-openresty-bouncer-v1.2.3/'),
                            (http_archive, 'lua-resty-http-0.17.1/')]:
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                name = member.name
                if not member.isfile() or not name.startswith(prefix):
                    continue
                rel = name[len(prefix):]
                if '..' in Path(rel).parts:
                    raise ValueError('资源归档路径无效')
                if rel.startswith('lua/lib/'):
                    dest = stage/'lib/crowdsec_1key'/rel[len('lua/lib/'):]
                elif rel.startswith('lib/resty/') and rel.endswith('.lua'):
                    dest = stage/'lib/crowdsec_1key'/rel[len('lib/'):]
                elif rel.startswith('templates/') or rel in ('LICENSE', 'LICENSE.md'):
                    dest = stage/rel if rel.startswith('templates/') else stage/(prefix.rstrip('/')+'-LICENSE')
                elif rel == 'config/config_example.conf':
                    dest = stage/'bouncer.conf'
                else:
                    continue
                content = tar.extractfile(member).read().decode()
                if dest.suffix == '.lua':
                    content = namespace(content)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
                dest.chmod(0o644)
    conf = stage/'bouncer.conf'
    content = conf.read_text().replace('${CROWDSEC_LAPI_URL}', api_url.replace('localhost', '127.0.0.1').rstrip('/')+'/').replace('${API_KEY}', key.strip())
    content = content.replace('/var/lib/crowdsec/lua/templates/', plan['container_assets']+'/templates/')
    conf.write_text(content)
    conf.chmod(0o600)
    for name, text in render_hooks(plan).items():
        if name != 'target':
            (stage/name).write_text(text)
    (stage/'target.conf').write_text(render_hooks(plan)['target'])


def read_state(path):
    return json.loads(Path(path).read_text()) if Path(path).exists() else {}


def save_state(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def resource_hashes(assets):
    hashes = {}
    if not Path(assets).exists():
        return hashes
    for path in Path(assets).rglob('*'):
        if path.is_symlink():
            raise ValueError('资源中出现符号链接，未清理')
        if path.is_file():
            data = path.read_bytes()
            if path.name == 'bouncer.conf':
                data = re.sub(rb'^APPSEC_URL=.*$', b'APPSEC_URL=', data, flags=re.M)
            hashes[str(path.relative_to(assets))] = hashlib.sha256(data).hexdigest()
    return hashes


def apply_install(plan, stage, state_path, name, account):
    state = read_state(state_path)
    if name in state or Path(plan['host_assets']).exists():
        raise ValueError('安装记录或资源已存在，未覆盖')
    target = Path(plan['host_target'])
    actual = target.read_text() if target.exists() else None
    if actual != plan['original']:
        raise ValueError('原配置已变化，请重新生成计划')
    shutil.copytree(stage, plan['host_assets'])
    # Temporary download directory is private; installed modules must be worker-readable.
    for directory, _, _ in os.walk(plan['host_assets']):
        Path(directory).chmod(0o755)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = render_hooks(plan)['target']
    target.write_text(text)
    target.chmod(plan['original_mode'])
    state[name] = dict(plan, account=account, installed_sha=hashlib.sha256(text.encode()).hexdigest(),
                       resource_hashes=resource_hashes(plan['host_assets']), status='installed')
    save_state(state_path, state)


def check_install(state_path, name, mounts):
    entry = read_state(state_path)[name]
    for remote, local in [('container_target', 'host_target'), ('container_assets', 'host_assets')]:
        resolved, _ = mount_path(entry[remote], mounts)
        if resolved != entry[local]:
            raise ValueError('容器挂载已经变化，未覆盖安装')
    if entry['status'] == 'installed':
        if hashlib.sha256(Path(entry['host_target']).read_bytes()).hexdigest() != entry['installed_sha']:
            raise ValueError('安装配置已被手工修改，请先人工合并/撤销')
    else:
        target = Path(entry['host_target'])
        actual = target.read_text() if target.exists() else None
        if actual != entry['original'] and not (entry['status'] == 'recovery-required'
                and actual == render_hooks(entry)['target']):
            raise ValueError('恢复后的网站配置已变化，未继续清理')
    current = resource_hashes(entry['host_assets'])
    expected = entry.get('resource_hashes', {})
    if entry['status'] != 'cleanup-pending' and current != expected:
        raise ValueError('安装资源已被手工修改，未清理')
    if entry['status'] == 'cleanup-pending' and any(expected.get(k) != v for k, v in current.items()):
        raise ValueError('待清理资源已变化，请人工核对')
    conf = Path(entry['host_assets'])/'bouncer.conf'
    if Path(str(conf)+'.local').exists():
        raise ValueError('存在 .local 覆盖配置，请先人工核对')
    return entry


def restore_install(entry):
    target = Path(entry['host_target'])
    if entry['original'] is None:
        target.unlink(missing_ok=True)
    else:
        target.write_text(entry['original'])
        target.chmod(entry['original_mode'])


def main(args):
    action, *args = args
    if action == 'plan':
        effective, mounts, image, network, version, destination = args
        plan = plan_install(Path(effective).read_text(), json.loads(Path(mounts).read_text()), image, network, Path(version).read_text())
        save_state(destination, plan)
    elif action == 'verify':
        verify_archive(args[0], BOUNCER_SHA)
        verify_archive(args[1], HTTP_SHA)
    elif action == 'credentials':
        from crowdsec_config import merged_config
        print(merged_config(args[0])['api']['client']['credentials_path'])
    elif action == 'get':
        print(read_state(args[0])[args[1]])
    elif action == 'stage':
        plan, bouncer, http, stage, key_file, api_url = args
        stage_assets(read_state(plan), bouncer, http, stage, Path(key_file).read_text(), api_url)
    elif action == 'apply':
        plan, stage, state, name, account = args
        apply_install(read_state(plan), stage, state, name, account)
    elif action in ('list', 'targets'):
        for name, entry in read_state(args[0]).items():
            if action == 'list':
                print(name+'\t'+entry['status'])
            elif entry['status'] == 'installed' and name == args[1]:
                print(entry['container_assets']+'/bouncer.conf')
    elif action == 'check':
        state, name, mounts, destination = args
        save_state(destination, check_install(state, name, json.loads(Path(mounts).read_text())))
    elif action == 'active-hooks':
        state, name, mounts, effective = args
        entry = check_install(state, name, json.loads(Path(mounts).read_text()))
        text = Path(effective).read_text()
        if entry['status'] != 'installed' or '# configuration file '+entry['container_target']+':' not in text:
            raise ValueError('安装配置未进入有效配置')
        access = [words for _, words, _ in directives(text) if words and words[0].startswith('access_by_lua')]
        if access != [['access_by_lua_file', entry['container_assets']+'/access.lua']]:
            raise ValueError('有效请求钩子与受管理安装不一致')
        if any(words == ['satisfy', 'any'] for _, words, _ in directives(text)):
            raise ValueError('访问控制可能绕过请求钩子')
        print('crowdsec')
    elif action == 'restore':
        restore_install(read_state(args[0]))
    elif action == 'pending':
        state = read_state(args[0])
        state[args[1]]['status'] = 'cleanup-pending'
        save_state(args[0], state)
    elif action == 'recovery':
        plan, state_path, name, account = args
        entry = read_state(plan)
        state = read_state(state_path)
        text = render_hooks(entry)['target']
        state[name] = dict(entry, account=account, status='recovery-required',
                           installed_sha=hashlib.sha256(text.encode()).hexdigest(),
                           resource_hashes=resource_hashes(entry['host_assets']))
        save_state(state_path, state)
    elif action == 'forget':
        state = read_state(args[0])
        entry = state[args[1]]
        if entry['status'] != 'cleanup-pending':
            raise ValueError('必须先恢复并重载网站配置')
        if Path(entry['host_assets']).exists():
            shutil.rmtree(entry['host_assets'])
        del state[args[1]]
        save_state(args[0], state)
    elif action == 'unlink-record':
        import yaml
        path, config = args
        if Path(path).exists():
            links = yaml.safe_load(Path(path).read_text()) or {}
            links.pop(config, None)
            if links:
                Path(path).write_text(yaml.safe_dump(links))
            else:
                Path(path).unlink()
    elif action == 'account-absent':
        account, path = args
        data = json.loads(Path(path).read_text())
        if not isinstance(data, list) or any(not isinstance(item, dict) or not isinstance(item.get('name'), str) for item in data):
            raise ValueError('Bouncer 列表格式无效，未继续清理')
        if any(item['name'] == account for item in data):
            raise ValueError('Bouncer 账号仍然存在，待下次清理')
    else:
        raise ValueError('未知 Web 安装操作')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, KeyError, tarfile.TarError) as error:
        print('[ERROR] '+str(error), file=sys.stderr)
        sys.exit(1)

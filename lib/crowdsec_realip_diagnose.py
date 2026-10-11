"""Bounded, read-only log evidence; observations never create proxy trust."""
from collections import Counter
import fnmatch
import ipaddress
from pathlib import Path
import posixpath
import re
import secrets
import shlex

from crowdsec_web import directives, mount_path

TIMESTAMP = r'\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}'
NPM_CLIENT = re.compile(r'^\['+TIMESTAMP+r'\] +(?:[A-Za-z0-9_,:.-]+ +)*\d{3} - '
                        r'\S+ https? [^\s"]+ "(?:[^"\\]|\\.)*" '
                        r'\[Client ([^\]\s]+)\] \[Length \d+\] \[Gzip [^\]\r\n]*\]')


def http_directives(effective):
    """Follow dumped include sections; exclude files used in stream or unknown context."""
    parts = re.split(r'(?m)^# configuration file ([^\n]+):\n', effective)
    if len(parts) == 1:
        yield from directives(effective)
        return
    contents = dict(zip(parts[1::2], parts[2::2]))
    root = parts[1]
    prefix = posixpath.dirname(root)
    contexts = {path: set() for path in contents}
    pending = [(root, False)]
    while pending:
        path, stream = pending.pop()
        if stream in contexts[path]:
            continue
        contexts[path].add(stream)
        for context, words, _ in directives(contents[path]):
            if len(words) == 2 and words[0] == 'include' and '$' not in words[1]:
                pattern = words[1] if words[1].startswith('/') else posixpath.join(prefix, words[1])
                pattern = posixpath.normpath(pattern)
                pending.extend((child, stream or 'stream' in context) for child in contents
                               if fnmatch.fnmatchcase(child, pattern))
    for path, content in contents.items():
        if contexts[path] == {False}:
            yield from directives(content)


def client_address(line):
    # Standard IP-first layouts take priority over request-controlled text.
    first = line.split()[0] if line.split() else ''
    try:
        return str(ipaddress.ip_address(first))
    except ValueError:
        match = NPM_CLIENT.match(line)
        if match:
            try:
                return str(ipaddress.ip_address(match[1]))
            except ValueError:
                pass
    return None


def log_evidence(effective, mounts, limit=12):
    reports, seen = [], set()
    for context, words, _ in http_directives(effective):
        if len(words) < 2 or words[0] != 'access_log':
            continue
        remote = words[1]
        if ('stream' in context or 'stream' in Path(remote).name.lower() or
                not remote.startswith('/') or '$' in remote or remote.startswith('/dev/')):
            continue
        try:
            # Read-only mounts are valid evidence sources; never write through them.
            local, _ = mount_path(remote, [{**mount, 'RW': True} for mount in mounts])
            path = Path(local)
            if local in seen or not path.is_file():
                continue
            seen.add(local)
            with path.open('rb') as stream:
                stream.seek(0, 2)
                end = stream.tell()
                start = max(0, end-65536)
                stream.seek(start)
                lines = stream.read(65536).decode(errors='replace').splitlines()
                if start and lines:
                    lines = lines[1:]  # first line may have been cut mid-record
                lines = lines[-20:]
        except (OSError, ValueError):
            continue
        ips, latest = [], None
        for line in lines:
            client = client_address(line)
            if client:
                ips.append(client)
            timestamp = re.search(r'\[('+TIMESTAMP+r')\]', line)
            if timestamp:
                latest = timestamp[1]
        reports.append(dict(path=local, ips=Counter(ips).most_common(5), latest=latest, sampled=len(lines)))
        if len(reports) >= limit:
            break
    return reports


def report_evidence(effective, mounts, owned=None):
    names = sorted({name for _, words, _ in directives(effective)
                    if words and words[0] == 'server_name' for name in words[1:]
                    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z][A-Za-z0-9-]*', name)})
    print('只读上游诊断：上游仍未确认，不生成可信网段或选择 Header。')
    if names:
        print('已配置站点（最多 12 个）：'+', '.join(names[:12]))
    if owned:
        print('已有本工具管理记录；记录存在不代表当前链路已验证。改变接入方式前核对原配置，可用 --restore-real-ip 撤销。')
    token = 'crowdsec_ip_check='+secrets.token_hex(6)
    print('请在另一台设备访问实际站点的正常页面，附加唯一查询参数：?'+token)
    print('记下该设备的公网 IP，并核对同一请求的时间与日志 IP；本诊断不发送请求。')
    reports = log_evidence(effective, mounts)
    print('最多展示 12 份可读 HTTP 日志；其他站点请按实际 access_log 路径核对。')
    for entry in reports:
        print('\n日志：'+entry['path'])
        print('最近日志时间：'+(entry['latest'] or '无法从此格式读取；也可能为空'))
        print('已采样最近 '+str(entry['sampled'])+' 条（最多 64KiB / 20 条）。')
        if not entry['ips']:
            print('此格式未识别客户端 IP；需核对 log_format，不据此判断直连或 CDN。')
        for address, count in entry['ips']:
            kind = '公网' if ipaddress.ip_address(address).is_global else '非公网/保留地址'
            print('日志客户端 IP '+address+'：'+str(count)+' 条，'+kind)
        print('在新增访问后关联请求：rg -F -- '+shlex.quote(token)+' '+shlex.quote(entry['path']))
    if not reports:
        print('未找到可读取的持久化 HTTP 访问日志；请核对 access_log、挂载、权限和实际日志格式。')
    print('\n上述客户端字段可能已被 real-IP 配置改写，不能当作原始 TCP 对端；配置默认网段、DNS 或 Header 名称不能单独证明 CDN 接入。')
    print('若 IP 与设备公网地址不同，核对 DNS/CDN 面板、反向代理和 Tunnel 部署；必要时在你控制的代理处核对连接对端及请求头。')
    print('确认直连：无需新增真实 IP 配置；确认 Cloudflare 公网节点接入：选 1；确认其他代理及其 Header/网段：选 2。未确认时保持只读。')
    print('诊断完成；配置、管理记录、白名单及运行服务均未修改。')

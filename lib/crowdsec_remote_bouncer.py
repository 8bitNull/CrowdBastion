#!/usr/bin/env python3
"""Private remote credentials overlay. Secrets are accepted only on stdin."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.request
from urllib.parse import urlsplit
import yaml

class RemoteError(ValueError):
    pass

def validate(url, key):
    if not isinstance(url,str) or not isinstance(key,str) or not key or len(key)>4096 or re.search(r'[\s\x00-\x1f\x7f]',key):
        raise RemoteError('URL 或密钥格式无效。')
    if re.search(r'[\s\x00-\x1f\x7f]',url):
        raise RemoteError('URL 格式无效。')
    parts=urlsplit(url)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise RemoteError('URL 必须为无用户信息、查询或片段的 HTTP(S) 地址。')
    try:
        parts.port
    except ValueError:
        raise RemoteError('URL 端口无效。') from None
    try:
        address=ipaddress.ip_address(parts.hostname)
    except ValueError:
        address=None
    if parts.scheme=='http':
        # Names (including .local) do not prove transport is private; use a
        # literal RFC1918/ULA/loopback address, or verified TLS instead.
        networks=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','::1/128','fc00::/7']
        if address is None or not any(address in ipaddress.ip_network(n) for n in networks):
            raise RemoteError('明文 HTTP 仅允许环回、RFC1918 或 ULA 地址；其他地址必须使用 HTTPS。')
    return url.rstrip('/')+'/'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise RemoteError('预检拒绝重定向。')

def preflight(url,key):
    request=urllib.request.Request(url+'v1/decisions/stream?startup=true',headers={'X-Api-Key':key})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    try:
        with opener.open(request,timeout=5) as response:
            if response.status!=200:
                raise RemoteError('远端认证预检失败。')
            payload=response.read(1024*1024+1)
            if len(payload)>1024*1024:
                raise RemoteError('预检响应过大。')
            content=json.loads(payload)
            if not isinstance(content,dict) or not all(k in content and (content[k] is None or isinstance(content[k],list)) for k in ('new','deleted')):
                raise RemoteError('预检响应不是决策流。')
    except Exception:
        raise RemoteError('远端认证预检失败（认证、TLS 或连接错误），原配置未改变。') from None

def paths(base):
    base=Path(base)
    return base,Path(str(base)+'.local'),Path(str(base)+'.remote.json')

def check_paths(base):
    for path in paths(base):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise RemoteError('拒绝符号链接或非普通配置文件。')
    for parent in Path(base).parents:
        if parent.is_symlink():
            raise RemoteError('拒绝符号链接配置目录。')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def owned(base):
    check_paths(base)
    _,local,state=paths(base)
    try:
        record=json.loads(state.read_text())
        if record.get('manager')!='crowdsec-1key-remote-v1' or record.get('sha256')!=digest(local):
            raise RemoteError('托管配置已被外部修改，拒绝操作。')
    except (OSError,ValueError,TypeError):
        raise RemoteError('未发现完整且未修改的托管配置，拒绝操作。') from None
    return record

def atomic(path,data):
    fd,name=tempfile.mkstemp(prefix='.remote-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def apply(base,data):
    url=validate(data.get('url'),data.get('key'))
    check_paths(base)
    base,local,state=paths(base)
    if local.exists() or state.exists(): owned(base)
    if not base.is_file(): raise RemoteError('缺少官方 Bouncer 基础配置，请先安装软件包。')
    config=yaml.safe_load(base.read_text())
    if not isinstance(config,dict) or config.get('mode') not in ('nftables','iptables','ipset'):
        raise RemoteError('基础 Bouncer 配置或防火墙后端无效。')
    preflight(url,data['key'])
    old={p:(p.read_bytes(),p.stat().st_mode & 0o777) if p.exists() else None for p in (local,state)}
    try:
        atomic(local,yaml.safe_dump({'api_url':url,'api_key':data['key'], 'insecure_skip_verify':False, 'cert_path':'', 'key_path':'', 'iptables_chains':['INPUT','FORWARD'], 'nftables_hooks':['input','forward']}).encode())
        atomic(state,json.dumps({'manager':'crowdsec-1key-remote-v1','sha256':digest(local)}).encode())
    except Exception:
        for path,previous in old.items():
            if previous is None: path.unlink(missing_ok=True)
            else: atomic(path,previous[0]); path.chmod(previous[1])
        raise

def main():
    action,base=sys.argv[1:]
    if action=='apply': apply(base,json.load(sys.stdin))
    elif action=='guard':
        check_paths(base)
        _,local,state=paths(base)
        if local.exists() or state.exists(): owned(base)
    elif action=='owned': owned(base)
    elif action=='remove':
        owned(base)
        _,local,state=paths(base)
        local.unlink(); state.unlink()
    elif action=='status':
        record=owned(base)
        _,local,_=paths(base)
        config=yaml.safe_load(local.read_text())
        print('托管远端 LAPI: '+config['api_url'])
        print('密钥: 已配置（不显示）；认证与实际业务阻断需另行验证。')
    elif action=='preflight':
        data=json.load(sys.stdin); preflight(validate(data.get('url'),data.get('key')),data['key'])
    else: raise RemoteError('未知操作。')

if __name__=='__main__':
    try: main()
    except Exception as error:
        print(str(error) if isinstance(error,RemoteError) else '远端配置操作失败，未输出敏感详情。',file=sys.stderr)
        sys.exit(1)

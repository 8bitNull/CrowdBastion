"""Explicit private Docker endpoints; never publish or rebind the host engine."""
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

from crowdsec_web import read_state, save_state

PRIVATE_V4 = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]


def endpoint(value):
    parsed = urlsplit(value)
    address = ipaddress.ip_address(parsed.hostname or '')
    if (parsed.scheme != 'http' or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ('', '/') or not parsed.port or address.version != 4
            or not any(address in network for network in PRIVATE_V4)):
        raise ValueError('私有接入仅接受 Docker bridge 网关的明确 IPv4 HTTP 地址和端口')
    return 'http://'+str(address)+':'+str(parsed.port), str(address)


def plan(inspection, networks, api_url, appsec_url):
    api_url, gateway = endpoint(api_url)
    appsec_url, appsec_gateway = endpoint(appsec_url)
    if gateway != appsec_gateway or api_url == appsec_url:
        raise ValueError('LAPI/AppSec 必须使用同一私有网关的不同端口')
    mode = inspection['HostConfig']['NetworkMode']
    if mode in ('host', 'none') or mode.startswith('container:'):
        raise ValueError('此入口仅用于独立 Docker bridge 网络')
    connected = inspection['NetworkSettings']['Networks']
    matches = []
    for network in networks:
        connection = connected.get(network['Name'], {})
        if network.get('Driver') != 'bridge' or connection.get('NetworkID') != network['Id']:
            continue
        subnets = [ipaddress.ip_network(item['Subnet']) for item in network.get('IPAM', {}).get('Config', [])
                   if item.get('Gateway') == gateway]
        subnets = [subnet for subnet in subnets if ipaddress.ip_address(gateway) in subnet]
        if connection.get('Gateway') != gateway:
            if network.get('Internal') is not True or connection.get('Gateway') or not connection.get('IPAddress'):
                continue
            container_address = ipaddress.ip_address(connection['IPAddress'])
            subnets = [subnet for subnet in subnets if container_address in subnet]
        if subnets:
            matches.append(network['Id'])
    if len(matches) != 1:
        raise ValueError('地址未唯一匹配容器当前连接的 Docker bridge 私有网关')
    return {'api_url': api_url, 'appsec_url': appsec_url, 'network_id': matches[0], 'gateway': gateway}


def main(args):
    action, *args = args
    if action == 'plan':
        inspection, networks, api_url, appsec_url, destination = args
        save_state(destination, plan(json.loads(Path(inspection).read_text())[0],
                                     json.loads(Path(networks).read_text()), api_url, appsec_url))
    elif action == 'check':
        state, name, inspection, networks, destination = args
        entry = read_state(state)[name]
        current = plan(json.loads(Path(inspection).read_text())[0], json.loads(Path(networks).read_text()),
                       entry['api_url'], entry['appsec_url'])
        if current != entry:
            raise ValueError('私有接入的 Docker 网络已变化，请重新核对并配置端点')
        save_state(destination, entry)
    elif action == 'record':
        state, name, planned = args
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', name):
            raise ValueError('容器名称无效')
        data = read_state(state)
        data[name] = read_state(planned)
        save_state(state, data)
    elif action == 'registered':
        state, name = args
        data = read_state(state)
        if not isinstance(data, dict):
            raise ValueError('私有端点登记必须为容器名称映射')
        if name not in data:
            sys.exit(2)
    elif action == 'listeners':
        planned, listeners = args
        data = read_state(planned)
        addresses = {line.split()[3] for line in Path(listeners).read_text().splitlines() if len(line.split()) >= 4}
        if any(url.removeprefix('http://') not in addresses for url in (data['api_url'], data['appsec_url'])):
            raise ValueError('宿主机尚未在这两个私有地址精确监听；不接受公网/通配监听作为自动接入依据')
    elif action == 'config-api':
        settings, planned = args
        matches = re.findall(r'^API_URL=(.*)$', Path(settings).read_text(), re.M)
        if len(matches) != 1 or matches[0].rstrip('/') != read_state(planned)['api_url']:
            raise ValueError('已有 Bouncer 的 API_URL 与核验的私有 LAPI 不一致，请先手动核对凭据和端点')
    elif action == 'installed-current':
        installed, planned = args
        if read_state(installed).get('transport') != read_state(planned):
            raise ValueError('私有端点与原安装不一致，请先撤销并重新安装，不会覆盖已有账号或配置')
    elif action in ('check-install', 'check-link'):
        if action == 'check-link':
            from crowdsec_config import read
            installed, config, inspection, networks = args
            entry = read(installed)[config]['transport']
        else:
            installed, inspection, networks = args
            entry = read_state(installed)['transport']
        current = plan(json.loads(Path(inspection).read_text())[0], json.loads(Path(networks).read_text()),
                       entry['api_url'], entry['appsec_url'])
        if current != entry:
            raise ValueError('安装后 Docker bridge 网络已变化，未撤销网站配置')
    elif action in ('probe-config', 'probe-settings'):
        key, planned, destination = args
        if action == 'probe-settings':
            matches = re.findall(r'^API_KEY=(.*)$', Path(key).read_text(), re.M)
            if len(matches) != 1:
                raise ValueError('已有 Bouncer 密钥配置无效')
            value = matches[0]
        else:
            value = Path(key).read_text().strip()
        if not re.fullmatch(r'[a-zA-Z0-9_+/=-]{16,}', value):
            raise ValueError('Bouncer API Key 无效')
        target = Path(destination)
        target.touch(mode=0o600)
        target.chmod(0o600)
        target.write_text('url = '+json.dumps(read_state(planned)['api_url']+'/v1/decisions')+'\nheader = '+json.dumps('X-Api-Key: '+value)+'\n')
    elif action == 'probe-response':
        data = json.loads(Path(args[0]).read_text())
        if data is not None and not isinstance(data, list):
            raise ValueError('私有 LAPI 的认证响应结构不符')
    else:
        raise ValueError('未知私有接入操作')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, KeyError, TypeError, IndexError) as error:
        print('私有接入失败：'+str(error), file=sys.stderr)
        sys.exit(1)

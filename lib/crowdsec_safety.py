#!/usr/bin/env python3
"""Local-only safety evidence; no network discovery or automatic exemptions."""
import ipaddress
import json
import re
import sys
from pathlib import Path
import yaml


def load(path):
    result = {}
    for item in (Path(path), Path(str(path)+'.local')):
        if item.exists() or item.is_symlink():
            data = yaml.safe_load(item.read_text())
            if data is None:
                data = {}
            if not isinstance(data, dict):
                raise ValueError(f'{item}: expected mapping')
            def merge(a, b):
                for key, value in b.items():
                    if isinstance(value, dict) and isinstance(a.get(key), dict):
                        merge(a[key], value)
                    else:
                        a[key] = value
            merge(result, data)
    return result


def firewall_spec(path):
    data = load(path)
    mode = data.get('mode', '')
    if mode not in ('', 'nftables', 'iptables', 'ipset'):
        raise ValueError('unknown firewall backend')
    names = ['crowdsec']
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key in ('table', 'set', 'set_name') or key.startswith('blacklists_')):
                    items = item if isinstance(item, list) else [item]
                    names.extend(x for x in items if isinstance(x, str) and x)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(data)
    print(mode or 'auto')
    print('|'.join(re.escape(x) for x in names))


def guard(target, directory, current, interfaces):
    def canonical(value):
        if not isinstance(value, str):
            raise ValueError('address records must contain IP strings')
        parsed = ipaddress.ip_address(value)
        return getattr(parsed, 'ipv4_mapped', None) or parsed
    address = canonical(target)
    if address.is_loopback or address.is_unspecified:
        raise ValueError('不能封禁 loopback 或 unspecified 地址')
    protected = []
    if current:
        protected.append(current)
    records = json.loads(interfaces)
    if not isinstance(records, list):
        raise ValueError('interface records must be a list')
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get('addr_info'), list):
            raise ValueError('invalid interface addresses')
        for item in record['addr_info']:
            if not isinstance(item, dict) or not isinstance(item.get('local'), str):
                raise ValueError('invalid interface address')
            protected.append(item['local'])
    admin = load(Path(directory)/'parsers/s02-enrich/99-admin-whitelist.yaml')
    rules = admin.get('whitelist', {})
    if not isinstance(rules, dict) or not isinstance(rules.get('ip', []), list):
        raise ValueError('invalid administrator whitelist')
    protected.extend(rules.get('ip', []))
    # Optional explicit own-address records, never inferred from external probes.
    records = Path(directory)/'crowdsec-1key-own-addresses.json'
    if records.exists() or records.is_symlink():
        data = json.loads(records.read_text())
        if not isinstance(data, list):
            raise ValueError('own-address records must be a list')
        protected.extend(data)
    admin_records = Path(directory)/'crowdsec-1key-admin-addresses.json'
    if admin_records.exists() or admin_records.is_symlink():
        data = json.loads(admin_records.read_text())
        if not isinstance(data, list):
            raise ValueError('administrator address records must be a list')
        protected.extend(data)
    if any(address == canonical(item) for item in protected):
        raise ValueError('不能封禁已知本机或管理员地址')


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'firewall-spec':
            firewall_spec(sys.argv[2])
        elif sys.argv[1] == 'known-addresses':
            directory, interfaces = sys.argv[2:]
            addresses = ['127.0.0.1', '::1']
            for record in json.loads(interfaces):
                addresses.extend(x['local'] for x in record.get('addr_info', []) if 'local' in x)
            for name in ('crowdsec-1key-own-addresses.json', 'crowdsec-1key-admin-addresses.json'):
                path = Path(directory)/name
                if path.exists():
                    records = json.loads(path.read_text())
                    if not isinstance(records, list):
                        raise ValueError('address records must be lists')
                    addresses.extend(records)
            print('\n'.join(sorted(set(str(ipaddress.ip_address(x)) for x in addresses))))
        elif sys.argv[1] == 'record-admin':
            directory, action, address = sys.argv[2:]
            path = Path(directory)/'crowdsec-1key-admin-addresses.json'
            records = json.loads(path.read_text()) if path.exists() else []
            address = str(ipaddress.ip_address(address))
            records = [item for item in records if str(ipaddress.ip_address(item)) != address]
            if action == 'add':
                records.append(address)
            elif action != 'remove':
                raise ValueError('invalid record action')
            stage = path.with_suffix('.json.tmp')
            stage.write_text(json.dumps(records))
            stage.chmod(0o600)
            stage.replace(path)
        elif sys.argv[1] == 'guard-ban':
            guard(*sys.argv[2:])
        else:
            raise ValueError('unknown operation')
    except (ValueError, OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

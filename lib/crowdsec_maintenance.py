"""Structured maintenance, health summaries and rule snapshots."""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import sys
import yaml

from crowdsec_realip_diagnose import http_directives
from crowdsec_web import mount_path

from crowdsec_config import acquisition_locations, go_glob, merged_config, read, write

RULE_DIRS = ('hub', 'collections', 'parsers', 'scenarios', 'postoverflows',
             'contexts', 'appsec-configs', 'appsec-rules')


def require_plain_path(path):
    path = Path(path)
    if not path.is_absolute() or any(item.is_symlink() for item in [path, *path.parents]):
        raise ValueError('路径必须为非符号链接的绝对路径：'+str(path))


def runtime_preflight(path):
    path = Path(path)
    require_plain_path(path)
    for item in [path, *path.parents]:
        if not item.exists():
            continue
        metadata = item.stat()
        if not item.is_dir() or metadata.st_uid != 0 or (
                metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX):
            raise ValueError('维护目录及祖先必须归 root 所有且不可由其他用户写入：'+str(item))
    if path.exists():
        marker = path/'.crowdsec-1key-managed'
        if not marker.is_file() or marker.is_symlink():
            raise ValueError('维护目录不属于本工具，未覆盖：'+str(path))


def fingerprint(path):
    path = Path(path)
    if path.is_symlink():
        return ['link', os.readlink(path)]
    if path.is_file():
        return ['file', hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode & 0o777]
    if path.is_dir():
        return ['dir', {item.name: fingerprint(item) for item in sorted(path.iterdir())}]
    if path.exists():
        raise ValueError('快照不支持特殊文件：'+str(path))
    return None


def preserve_ownership(source, destination):
    if os.geteuid() == 0:
        metadata = Path(source).lstat()
        os.chown(destination, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
    if Path(source).is_dir() and not Path(source).is_symlink():
        for item in Path(source).iterdir():
            preserve_ownership(item, Path(destination)/item.name)


def rule_data_file(path, database):
    if not path.is_file() or path.suffix in ('.db', '.sqlite', '.sqlite3') or path.name.endswith(('-wal', '-shm', '-journal')):
        return False
    if database and path.resolve() == Path(database).resolve():
        return False
    return True


def snapshot(config, destination):
    effective = merged_config(config)
    config_dir = Path(effective.get('config_paths', {}).get('config_dir', Path(config).parent))
    require_plain_path(config_dir)
    paths = [config_dir/name for name in RULE_DIRS]
    for key in ('hub_dir', 'index_path'):
        value = effective.get('config_paths', {}).get(key)
        if value:
            require_plain_path(value)
        if value and not any(Path(value) == path or path in Path(value).parents for path in paths):
            paths.append(Path(value))
    data = effective.get('config_paths', {}).get('data_dir')
    database = effective.get('db_config', {}).get('db_path', '')
    if data:
        data_path = Path(data)
        require_plain_path(data_path)
        paths.extend(path for path in data_path.iterdir() if rule_data_file(path, database))
    paths = list(dict.fromkeys(paths))
    for path in paths:
        require_plain_path(path)
    hub_roots = [config_dir/'hub']
    configured_hub = effective.get('config_paths', {}).get('hub_dir')
    if configured_hub:
        hub_roots.append(Path(configured_hub))
    for hub in hub_roots:
        require_plain_path(hub)
        if hub.is_dir() and any(item.is_symlink() for item in hub.rglob('*')):
            raise ValueError('Hub 内部不能包含符号链接：'+str(hub))
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = {'config': str(Path(config).resolve()), 'paths': []}
    for index, path in enumerate(paths):
        if not path.is_absolute() or len(path.parts) < 3:
            raise ValueError('拒绝备份无效规则路径：'+str(path))
        copy = destination/str(index)
        before = fingerprint(path)
        if before is not None:
            if path.is_dir() and not path.is_symlink():
                shutil.copytree(path, copy, symlinks=True)
            else:
                shutil.copy2(path, copy, follow_symlinks=False)
            preserve_ownership(path, copy)
        manifest['paths'].append({'path': str(path), 'copy': str(copy), 'before': before})
    manifest['data_dir'] = data
    manifest['database'] = database
    manifest['data_files'] = [str(path) for path in Path(data).iterdir() if path.is_file()] if data else []
    write(destination/'manifest.yaml', manifest)


def changed(destination):
    manifest = read(Path(destination)/'manifest.yaml')
    if any(fingerprint(entry['path']) != entry['before'] for entry in manifest['paths']):
        return True
    if manifest['data_dir']:
        return any(str(path) not in manifest['data_files'] for path in Path(manifest['data_dir']).iterdir()
                   if rule_data_file(path, manifest.get('database', '')))
    return False


def restore(destination):
    manifest = read(Path(destination)/'manifest.yaml')
    for entry in manifest['paths']:
        if entry['before'] is not None and fingerprint(entry['copy']) != entry['before']:
            raise ValueError('快照内容已变化，拒绝恢复：'+entry['copy'])
    for entry in manifest['paths']:
        copy, path = Path(entry['copy']), Path(entry['path'])
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            if not path.is_dir() or path.is_mount():
                raise ValueError('拒绝替换特殊文件或挂载点：'+str(path))
            shutil.rmtree(path)
        if entry['before'] is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            if copy.is_dir() and not copy.is_symlink():
                shutil.copytree(copy, path, symlinks=True)
            else:
                shutil.copy2(copy, path, follow_symlinks=False)
            preserve_ownership(copy, path)
    data = manifest['data_dir']
    if data:
        for path in Path(data).iterdir():
            if rule_data_file(path, manifest.get('database', '')) and str(path) not in manifest['data_files']:
                path.unlink()


def health_metrics(acquisition, appsec):
    metrics = json.loads(Path(acquisition).read_text())
    sources = metrics.get('acquisition', {})
    reads = sum(source.get('reads', 0) for source in sources.values())
    web = [source for name, source in sources.items() if 'access' in name or 'nginx' in name or '/sites/' in name]
    parsed = sum(source.get('parsed', 0) for source in web)
    if reads:
        print(f'[正常] 日志采集：已读 {reads} 行；HTTP 已解析 {parsed} 行。')
    else:
        print('[尚未验证] 日志采集：没有新行指标，可能空闲或刚重启。')
    if any(source.get('reads', 0) and not source.get('parsed', 0) for name, source in sources.items() if 'access' in name):
        print('[异常] HTTP 日志有读取但无解析，请核对格式和标签。')
        return 1
    data = json.loads(Path(appsec).read_text()) if Path(appsec).is_file() else {}
    engines = data.get('appsec-engine', {})
    processed = sum(engine.get('processed', 0) for engine in engines.values())
    blocked = sum(engine.get('blocked', 0) for engine in engines.values())
    if processed:
        print(f'[正常] AppSec 请求处理：Processed={processed}，Blocked={blocked}。')
    else:
        print('[尚未验证] AppSec 网站接入：未观察到处理计数。')
    print('[尚未验证] 公网阻断：累计计数和服务状态不能证明每个站点的实际阻断。')
    return 0


def audit_acquisition(root):
    directory, single, _ = acquisition_locations(root)
    sources = ([Path(single)] if single else []) + list(Path(directory).glob('*.yaml')) + list(Path(directory).glob('*.yml'))
    files = {}
    for path in sources:
        if not path.exists():
            continue
        for doc in read(path, True):
            if not doc or doc.get('source', 'file') != 'file':
                continue
            patterns = doc.get('filenames', [])
            if isinstance(patterns, str):
                patterns = [patterns]
            if doc.get('filename'):
                patterns = [*patterns, doc['filename']]
            for pattern in patterns:
                for filename in go_glob(pattern):
                    files.setdefault(str(Path(filename).resolve()), []).append(str(path))
    duplicate = {name: configs for name, configs in files.items() if len(configs) > 1}
    for name in duplicate:
        print('[异常] 重复采集：'+name)
    print(f'已配置现存文件 {len(files)} 个，重复 {len(duplicate)} 个。')
    return bool(duplicate)


def main(args):
    action, *args = args
    if action == 'snapshot':
        snapshot(*args)
    elif action == 'runtime-preflight':
        runtime_preflight(args[0])
    elif action == 'changed':
        return 0 if changed(args[0]) else 1
    elif action == 'restore':
        restore(args[0])
    elif action == 'health-metrics':
        return health_metrics(*args)
    elif action == 'audit-acquisition':
        return int(audit_acquisition(args[0]))
    elif action == 'prune-snapshots':
        snapshots = sorted((path for path in Path(args[0]).glob('hub.*')
                            if path.is_dir() and not path.is_symlink() and (path/'.successful').is_file()),
                           key=lambda path: (path/'.successful').stat().st_mtime, reverse=True)
        for path in snapshots[14:]:
            if (path/'manifest.yaml').is_file():
                shutil.rmtree(path)
    elif action == 'collections-missing':
        data = json.loads(Path(args[0]).read_text())
        items = data.get('collections', []) if isinstance(data, dict) else data
        names = {item['name'] for item in items if 'enabled' in str(item.get('status', 'enabled'))}
        print('\n'.join(name for name in args[1:] if name not in names))
    elif action == 'metrics-port':
        port = merged_config(args[0]).get('prometheus', {}).get('listen_port', 6060)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError('指标端口无效')
        print(port)
    elif action == 'metrics-url':
        port = merged_config(args[0]).get('prometheus', {}).get('listen_port', 6060)
        print(f'http://127.0.0.1:{port}/metrics')
    elif action == 'webui-image':
        data = json.loads(Path(args[0]).read_text())
        candidates = [value for value in data if re.fullmatch(r'ghcr\.io/theduffman85/crowdsec-web-ui@sha256:[a-f0-9]{64}', value)]
        if not candidates:
            raise ValueError('没有可固定的官方 WebUI 镜像摘要')
        print(candidates[0])
    elif action == 'webui-health':
        if json.loads(Path(args[0]).read_text()).get('status') != 'ok':
            raise ValueError('WebUI HTTP 健康响应异常')
    elif action == 'webui-port':
        data = read(args[0])
        print(data['services']['crowdsec-web-ui'].get('environment', {}).get('CONFIG_SERVER_PORT', 3000))
    elif action == 'runtime-logs':
        kind, mounts_file, effective_file, destination = args
        mounts = json.loads(Path(mounts_file).read_text())
        paths = set()
        for context, words, _ in http_directives(Path(effective_file).read_text()):
            if len(words) < 2 or words[0] not in ('access_log', 'error_log') or 'stream' in context:
                continue
            if not words[1].startswith('/') or '$' in words[1] or words[1].startswith('/dev/'):
                continue
            try:
                path, _ = mount_path(words[1], [{**mount, 'RW': True} for mount in mounts])
                if Path(path).is_file() and 'stream' not in Path(path).name:
                    paths.add(path)
            except ValueError:
                continue
        with Path(destination).open('a') as stream:
            for path in sorted(paths):
                stream.write(json.dumps({'path': path, 'kind': kind})+'\n')
    else:
        raise ValueError('未知维护操作：'+action)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, KeyError, TypeError, yaml.YAMLError) as error:
        print('维护操作失败：'+str(error), file=sys.stderr)
        sys.exit(2)

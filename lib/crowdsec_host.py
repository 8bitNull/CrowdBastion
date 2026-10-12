"""Map effective host HTTP paths without pretending a host is a container."""
import json
from pathlib import Path
import sys

from crowdsec_realip_diagnose import http_directives
from crowdsec_web import save_state, safe_path


def identity_mounts(effective):
    parents = set()
    for _, words, _ in http_directives(effective):
        if len(words) < 2 or words[0] not in ('include', 'access_log', 'error_log', 'access_by_lua_file'):
            continue
        value = words[1]
        if not value.startswith('/') or '$' in value or value.startswith('/dev/'):
            continue
        parent = Path(value).parent
        if not parent.is_dir() or str(parent) == '/':
            continue
        safe_path(str(parent))
        if any(path.is_symlink() for path in [parent, *parent.parents]):
            continue
        parents.add(str(parent))
    return [{'Type': 'bind', 'RW': True, 'Source': path, 'Destination': path} for path in sorted(parents)]


if __name__ == '__main__':
    try:
        effective, destination = sys.argv[1:]
        save_state(destination, identity_mounts(Path(effective).read_text()))
    except (OSError, ValueError) as error:
        print('宿主机路径发现失败：'+str(error), file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Private configuration and read-only conflict checks for the optional user bot."""
import ast
import json
import os
from pathlib import Path
import re
import sys
import yaml

from crowdsec_config import merged_config
from crowdsec_bot import load_settings, replace_private


def legacy_settings(path):
    values = {}
    if not Path(path).is_file():
        return values
    for statement in ast.parse(Path(path).read_text()).body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            try:
                values[statement.targets[0].id] = ast.literal_eval(statement.value)
            except (ValueError, TypeError):
                pass
    return values


def configure(target, root, state_dir, legacy):
    config = json.loads(Path(target).read_text()) if Path(target).exists() else {}
    if Path(target).is_symlink():
        raise ValueError('不接受符号链接配置')
    prior = legacy_settings(legacy) if not config else {}
    fields = sys.stdin.read().splitlines()
    if len(fields) != 5:
        raise ValueError('输入不完整')
    token, chat, admin, npm, endpoint = fields
    default_chat = prior.get('ADMIN_CHAT_ID')
    config.update(bot_token=token or config.get('bot_token', prior.get('BOT_TOKEN', '')),
                  chat_id=int(chat or config.get('chat_id', default_chat) or 0),
                  admin_user_id=int(admin or config.get('admin_user_id', default_chat if isinstance(default_chat, int) and default_chat > 0 else 0)),
                  npm_log_dir=npm or config.get('npm_log_dir', prior.get('NPM_LOG_DIR', '/home/docker/npm/data/logs')),
                  api_endpoint=endpoint or config.get('api_endpoint', 'https://api.telegram.org'),
                  crowdsec_config=str(Path(root)/'config.yaml'), state_dir=state_dir,
                  whitelist_file=str(Path(root)/'parsers/s02-enrich/crowdsec-1key-tg-whitelist.yaml'))
    effective = merged_config(str(Path(root)/'config.yaml'))
    config['db_path'] = effective.get('db_config', {}).get('db_path') or prior.get('DB_PATH', '/var/lib/crowdsec/data/crowdsec.db')
    # Validate before replacing the production config.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='bot-config-') as temporary:
        check = str(Path(temporary)/'config.json')
        replace_private(check, json.dumps(config))
        load_settings(check)
    replace_private(target, json.dumps(config, ensure_ascii=False, indent=2)+'\n')


def conflicts(managed_script, cron_dir):
    candidates = set()
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry/'cmdline').read_bytes().decode(errors='replace').split('\0')
            if args and re.search(r'python', Path(args[0]).name):
                for arg in args[1:]:
                    if Path(arg).name == 'crowdsec_bot.py' and os.path.realpath(arg) != os.path.realpath(managed_script):
                        candidates.add('独立 crowdsec_bot.py 进程 PID '+entry.name)
        except (OSError, ValueError):
            continue
    directory = Path(cron_dir)
    if directory.exists():
        for path in directory.iterdir():
            if not path.is_file():
                continue
            lines = path.read_text().splitlines()
            if any('crowdsec_bot.py' in line and not line.lstrip().startswith('#') for line in lines):
                candidates.add('cron 文件 '+path.name)
    print('\n'.join(sorted(candidates)))
    return 1 if candidates else 0


def main():
    try:
        if sys.argv[1] == 'configure':
            configure(*sys.argv[2:])
        elif sys.argv[1] == 'conflicts':
            return conflicts(*sys.argv[2:])
        else:
            raise ValueError('未知操作')
        return 0
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, yaml.YAMLError):
        print('机器人配置/检查失败；未输出 Token。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

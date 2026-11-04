"""Record/check real shell behavior across incremental refactors, without host writes.

Uses the workflow fixture's injected host commands. Only fixture directory paths
are normalized; stdout/stderr, exits, command order and business files are hashed.
Piped stdin suppresses Bash read -p prompts; terminal confirmation coverage lives
in test_protocol_navigation. Transaction helpers here are injected, so business
file snapshots establish shell side effects, not real transaction enforcement.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import stat

import unittest
from workflow_fixture import WorkflowFixtureMixin


class Fixture(WorkflowFixtureMixin, unittest.TestCase):
    """Standalone fixture with TestCase cleanup support and no test methods."""



def digest(value):
    return hashlib.sha256(value).hexdigest()


def observe(action, answers='', overrides=''):
    fixture = Fixture()
    fixture.setUp()
    try:
        result = fixture.run_shell(action, answers, overrides, timeout=20)
        marker = str(fixture.base).encode()
        normalize = lambda value: value.replace(marker, b'{FIXTURE_ROOT}')
        files = {}
        for folder in ('etc', 'var', 'run', 'usr/local'):
            parent = fixture.base/folder
            if not parent.exists():
                continue
            for path in sorted(parent.rglob('*')):
                info = path.lstat()
                row = {'mode': stat.S_IMODE(info.st_mode)}
                if path.is_symlink():
                    row['link'] = normalize(str(path.readlink()).encode()).decode()
                elif path.is_file():
                    row['sha256'] = digest(normalize(path.read_bytes()))
                elif path.is_dir():
                    row['directory'] = True
                else:
                    raise AssertionError('unexpected fixture file type')
                files[str(path.relative_to(fixture.base))] = row
        return {'exit': result.returncode,
                'stdout_sha256': digest(normalize(result.stdout.encode())),
                'stderr_sha256': digest(normalize(result.stderr.encode())),
                'commands': normalize(fixture.commands().encode()).decode(),
                'files': files}
    finally:
        fixture.doCleanups()


def scenarios():
    yield 'help', 'show_help', '', ''
    choices = {
        'anytls': '2\n1\n4\n3\n', 'vmess-ws': '1\n2\n4\n2\n',
        'vless-tls': '1\n3\n10\n1\n', 'shadowsocks-dual': '3\n4\n4\n1\n',
        'ss2022-udp': '3\n5\n3\n1\n', 'trojan-tls': '3\n6\n3\n1\n',
        'hy1-faketcp': '3\n7\n5\n1\n', 'hy2-quic': '3\n8\n2\n1\n',
        'tuic-quic': '3\n9\n2\n1\n', 'unknown': '3\n10\n1\n1\n',
    }
    for name, answers in choices.items():
        yield name, 'guided_protocol_status', answers, ''
    for index, answers in enumerate(('0\n', '', '1\n0\n', '1\n', '1\n1\n0\n',
                                     '1\n1\n', '1\n1\n2\n0\n', '1\n1\n2\n')):
        yield f'cancel-{index}', 'guided_protocol_status', answers, ''
    yield 'invalid-choice', 'guided_protocol_status', '$(false)\n01\n3\n9\n2\n1\n', ''
    yield 'full-home', 'show_main_menu', '4\n11\n1\n3\n1\n4\n3\n0\n0\n0\n', 'pause() { :; }'
    plan = {'version': 1, 'state': 'ready', 'changes': [], 'scope': {'ingress': []}}
    cases = [
        ('status', '', {'version': 1, 'state': 'absent'}, 0, 0),
        ('plan', '', plan, 0, 0),
        ('apply', 'y\n', {'version': 1, 'state': 'staged'}, 0, 0),
        ('apply', 'y\n', {'version': 1, 'state': 'verified', 'unchanged': True}, 0, 0),
        ('apply', 'n\n', {'version': 1, 'state': 'staged'}, 0, 0),
        ('apply', 'y\n', {'version': 1, 'state': 'rolled_back', 'error_code': 'apply_failed'}, 1, 0),
        ('apply', 'y\n', {'version': 1, 'state': 'refused'}, 75, 0),
        ('apply', 'y\n', {'version': 1, 'state': 'staged'}, 0, 1),
        ('verify', '', {'version': 1, 'state': 'verification_failed'}, 1, 0),
        ('commit', '', {'version': 1, 'state': 'verification_failed', 'refusal_code': 'transaction_expired'}, 1, 0),
        ('rollback', '', {'version': 1, 'state': 'rollback_incomplete'}, 1, 0),
    ]
    for kind in ('network', 'port-policy'):
        tool = 'network_tool' if kind == 'network' else 'port_policy_tool'
        for index, (action, answers, report, code, plan_code) in enumerate(cases):
            override = f'''{tool}() {{
 record "{kind}-tool $*"
 if [[ "$1" == plan ]]; then
  printf '%s\\n' {shlex.quote(json.dumps(plan))}; return {plan_code}
 fi
 printf '%s\\n' {shlex.quote(json.dumps(report))}; return {code}
}}
'''
            yield f'{kind}-{action}-{index}', f'main --{kind}-{action}', answers, override


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('record', 'check'))
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    observed = {name: observe(action, answers, overrides)
                for name, action, answers, overrides in scenarios()}
    if args.action == 'record':
        with args.path.open('x') as stream:
            json.dump(observed, stream, sort_keys=True, indent=2)
    else:
        expected = json.loads(args.path.read_text())
        failures = sorted(name for name in expected.keys() | observed.keys()
                          if expected.get(name) != observed.get(name))
        if failures:
            raise SystemExit('behavior changed: '+', '.join(failures))
    print(f'{args.action}: {len(observed)} behavior scenarios match')


if __name__ == '__main__':
    main()

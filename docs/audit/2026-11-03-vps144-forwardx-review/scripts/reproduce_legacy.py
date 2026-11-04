import ast
import json
import runpy
import subprocess
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[4]
source = root / 'docs/audit/2026-11-03-vps144-forwardx/scripts/vps144-prepare-host.py'
tree = ast.parse(source.read_text())
program = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'program' for t in n.targets))
preflight = json.loads((Path(__file__).resolve().parent.parent / 'preflight.json').read_text())
rules_text = preflight['files']['/usr/local/lib/crowdbastion-static-policy/rules.json']['text']
rules = json.loads(rules_text)
assert preflight['files']['/usr/local/lib/crowdbastion-static-policy/apply.py']['text'] == program
applied = []
calls = []

def execute(argv, capture_output=False, check=False):
    calls.append(argv)
    operation = argv[5]
    if operation == '-C':
        # A transient xtables lock/command failure on the sixth rule.
        result = subprocess.CompletedProcess(argv, 4 if len(applied) == 5 else 1, b'', b'xtables lock failure' if len(applied) == 5 else b'')
    else:
        assert operation == '-A'
        applied.append(argv)
        result = subprocess.CompletedProcess(argv, 0, b'', b'')
    if check:
        result.check_returncode()
    return result

with patch.object(Path, 'read_text', return_value=rules_text), patch.object(subprocess, 'run', side_effect=execute):
    try:
        exec(compile(program, str(source), 'exec'), {})
    except RuntimeError as error:
        failure = str(error)
    else:
        raise AssertionError('expected lookup failure')

assert len(applied) == 5
assert len(calls) == 11
assert all('-D' not in argv for argv in calls)
print(json.dumps({'status': 'reproduced', 'failure': failure, 'total_rules': len(rules), 'rules_left_applied': len(applied), 'rollback_commands': 0, 'calls': len(calls)}, indent=2))

"""Isolated file-backed command/fault tests; never invokes host iptables."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
RULES = [
    {'binary': 'iptables', 'table': table, 'rule': rule.split()}
    for table, rule in [
        ('mangle', '-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'),
        ('mangle', '-A OUTPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1448'),
        ('mangle', '-A OUTPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'),
        ('mangle', '-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1448'),
        ('filter', '-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT'),
        ('filter', '-A INPUT -i lo -j ACCEPT'),
        ('filter', '-A INPUT -p tcp -m tcp --dport 53322 -j ACCEPT'),
        ('filter', '-A FORWARD -i lo -j ACCEPT'),
        ('filter', '-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT'),
    ]
]


def load_candidate():
    spec = importlib.util.spec_from_file_location('static_policy', HERE / 'static_policy.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def key(item):
    return [item['binary'], item['table'], item['rule'][1:]]


def fake_command(state_path, control_path, argv):
    state_path = Path(state_path)
    state = json.loads(state_path.read_text())
    control = json.loads(Path(control_path).read_text())
    binary, _, _, _, table, operation, *rule = argv
    identity = [Path(binary).name, table, rule]
    state['calls'].append([operation, identity])
    count = sum(call[0] == operation for call in state['calls'])
    failure = control.get('operation') == operation and count == control.get('nth')
    code = 0
    if operation == '-C':
        code = 4 if failure else (0 if identity in state['rules'] else 1)
    elif operation == '-A':
        if not failure or control.get('side_effect'):
            state['rules'].append(identity)
        if failure:
            code = 4
    elif operation == '-D':
        if failure:
            code = 4
        elif identity in state['rules']:
            state['rules'].remove(identity)
        else:
            code = 1
    else:
        raise AssertionError(argv)
    state_path.write_text(json.dumps(state))
    if operation == '-D' and control.get('cancel_cleanup'):
        os.kill(os.getppid(), signal.SIGTERM)
        os.kill(os.getppid(), signal.SIGINT)
    if failure and control.get('signal'):
        os.kill(os.getppid(), control['signal'])
    if failure and control.get('timeout'):
        time.sleep(10)
    raise SystemExit(code)


def runner(state, control):
    def execute(argv):
        return subprocess.run([sys.executable, str(Path(__file__).resolve()), '--fake', str(state), str(control), *argv],
                              capture_output=True, text=True, timeout=0.5)
    return execute


def legacy_apply(rules, execute):
    """Run the original archived program, changing only file/command boundaries."""
    source = HERE.parent.parent / '2026-11-03-vps144-forwardx/scripts/vps144-prepare-host.py'
    tree = ast.parse(source.read_text())
    program = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'program' for t in n.targets))
    def legacy_run(argv, **kwargs):
        result = execute(argv)
        if kwargs.get('check'):
            result.check_returncode()
        return result
    with patch.object(Path, 'read_text', return_value=json.dumps(rules)), patch.object(subprocess, 'run', side_effect=legacy_run):
        # execute uses a saved subprocess.run below to avoid patch recursion.
        exec(compile(program, 'legacy-apply.py', 'exec'), {})


class StaticPolicyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'state.json'
        self.control = Path(self.temp.name) / 'control.json'
        self.initial = [['iptables', 'filter', ['INPUT', '-j', 'CROWDSEC_CHAIN']], key(RULES[0]), key(RULES[5])]
        self.state.write_text(json.dumps({'rules': self.initial, 'calls': []}))
        self.control.write_text('{}')
        self.policy = load_candidate() if '--legacy' not in sys.argv else None
        self.run_command = runner(self.state, self.control)

    def apply(self, rules=None):
        rules = RULES if rules is None else rules
        if self.policy is None:
            # Preserve the actual subprocess implementation below the patch.
            real_run = subprocess.run
            def execute(argv):
                return real_run([sys.executable, str(Path(__file__).resolve()), '--fake', str(self.state), str(self.control), *argv],
                                capture_output=True, text=True, timeout=0.5)
            return legacy_apply(rules, execute)
        return self.policy.apply(rules, runner=self.run_command)

    def snapshot(self):
        return json.loads(self.state.read_text())

    def fault(self, **control):
        self.control.write_text(json.dumps(control))

    def test_intact_is_idempotent_and_preserves_first_bouncer_jump(self):
        self.apply()
        expected = self.initial + [key(item) for item in RULES if key(item) not in self.initial]
        self.assertEqual(self.snapshot()['rules'], expected)
        self.state.write_text(json.dumps({'rules': expected, 'calls': []}))
        self.apply()
        self.assertEqual(self.snapshot()['rules'], expected)
        self.assertTrue(all(call[0] == '-C' for call in self.snapshot()['calls']))

    def test_late_lookup_failure_does_not_append(self):
        self.fault(operation='-C', nth=9)
        with self.assertRaises(Exception):
            self.apply()
        self.assertEqual(self.snapshot()['rules'], self.initial)
        self.assertFalse(any(call[0] == '-A' for call in self.snapshot()['calls']))

    def test_invalid_late_manifest_is_rejected_without_commands(self):
        bad = json.loads(json.dumps(RULES))
        bad[-1]['rule'] = ['-A', 'CROWDSEC_CHAIN', '-j', 'DROP']
        with self.assertRaises(Exception):
            self.apply(bad)
        self.assertEqual(self.snapshot()['rules'], self.initial)
        self.assertEqual(self.snapshot()['calls'], [])

    def test_late_append_failure_rolls_back_only_new_rules(self):
        self.fault(operation='-A', nth=4)
        with self.assertRaises(Exception):
            self.apply()
        self.assertEqual(self.snapshot()['rules'], self.initial)

    def test_final_verification_failure_rolls_back_new_rules(self):
        if self.policy is None:
            self.skipTest('legacy has no final verification')
        self.fault(operation='-C', nth=18)
        with self.assertRaises(Exception):
            self.apply()
        self.assertEqual(self.snapshot()['rules'], self.initial)

    def test_side_effect_then_timeout_is_owned_and_removed(self):
        self.fault(operation='-A', nth=4, side_effect=True, timeout=True)
        with self.assertRaises(Exception):
            self.apply()
        self.assertEqual(self.snapshot()['rules'], self.initial)

    def test_rollback_failure_continues_and_reports_incomplete(self):
        # Invalid result on fifth append triggers rollback, then first deletion fails.
        original = self.run_command
        def execute(argv):
            if argv[5] == '-A' and sum(c[0] == '-A' for c in self.snapshot()['calls']) == 4:
                self.fault(operation='-D', nth=1)
                raise RuntimeError('injected append failure')
            return original(argv)
        if self.policy is None:
            self.skipTest('candidate reporting contract')
        with self.assertRaisesRegex(Exception, 'rollback incomplete'):
            self.policy.apply(RULES, runner=execute)
        self.assertEqual(self.snapshot()['rules'][:len(self.initial)], self.initial)
        self.assertEqual(len(self.snapshot()['rules']), len(self.initial) + 1)
        self.assertGreaterEqual(sum(c[0] == '-D' for c in self.snapshot()['calls']), 4)

    def test_real_cancellation_and_repeated_cleanup_signals(self):
        if self.policy is None:
            self.skipTest('legacy SIGTERM would terminate test harness')
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signum=signum):
                self.state.write_text(json.dumps({'rules': self.initial, 'calls': []}))
                self.fault(operation='-A', nth=4, side_effect=True, signal=signum, cancel_cleanup=True)
                child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--signal-child', str(self.state), str(self.control)],
                                       capture_output=True, text=True, timeout=10)
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(self.snapshot()['rules'], self.initial)
                self.assertEqual(sum(c[0] == '-A' for c in self.snapshot()['calls']), 4)
                self.assertEqual(sum(c[0] == '-D' for c in self.snapshot()['calls']), 4)

    def test_repeat_signal_during_first_ignore_installation_cannot_skip_cleanup(self):
        if self.policy is None:
            self.skipTest('candidate signal transition contract')
        self.fault(operation='-A', nth=4, side_effect=True, signal=signal.SIGTERM)
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--transition-child', str(self.state), str(self.control)],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(self.snapshot()['rules'], self.initial)
        self.assertEqual(sum(c[0] == '-D' for c in self.snapshot()['calls']), 4)

    @unittest.skipUnless(os.geteuid() == 0, 'production lock owner is root')
    def test_sticky_lock_parent_and_busy_lock_preserve_existing_file(self):
        if self.policy is None:
            self.skipTest('candidate lock contract')
        lock = Path(self.temp.name) / 'maintenance.lock'
        lock.write_text('preserve lock bytes')
        lock.chmod(0o600)
        Path(self.temp.name).chmod(0o1777)
        with patch.object(self.policy, 'LOCK', lock):
            with self.policy.maintenance_lock():
                with self.assertRaises(BlockingIOError):
                    with self.policy.maintenance_lock():
                        self.fail('second lock acquired')
            with self.policy.maintenance_lock():
                self.assertEqual(lock.read_text(), 'preserve lock bytes')

    @unittest.skipUnless(os.geteuid() == 0, 'production lock owner is root')
    def test_unsafe_lock_link_and_writable_file_are_rejected(self):
        if self.policy is None:
            self.skipTest('candidate lock contract')
        lock = Path(self.temp.name) / 'maintenance.lock'
        target = Path(self.temp.name) / 'victim'
        target.write_text('untouched')
        target.chmod(0o600)
        lock.symlink_to(target)
        with patch.object(self.policy, 'LOCK', lock):
            with self.assertRaises(OSError):
                with self.policy.maintenance_lock():
                    self.fail('symlink accepted')
            lock.unlink()
            lock.write_text('unsafe')
            lock.chmod(0o666)
            with self.assertRaises(RuntimeError):
                with self.policy.maintenance_lock():
                    self.fail('writable lock accepted')
        self.assertEqual(target.read_text(), 'untouched')

    def test_executable_rejects_path_override_arguments(self):
        if self.policy is None:
            self.skipTest('candidate CLI contract')
        child = subprocess.run([sys.executable, str(HERE / 'static_policy.py'), '--rules', str(self.state)],
                               capture_output=True, text=True, timeout=5)
        self.assertEqual(child.returncode, 1)
        self.assertIn('accepts no arguments', child.stderr)
        self.assertEqual(self.snapshot()['rules'], self.initial)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--fake':
        fake_command(sys.argv[2], sys.argv[3], sys.argv[4:])
    elif len(sys.argv) > 1 and sys.argv[1] == '--signal-child':
        try:
            load_candidate().apply(RULES, runner=runner(sys.argv[2], sys.argv[3]))
        except Exception:
            raise SystemExit(0)
        raise SystemExit(2)
    elif len(sys.argv) > 1 and sys.argv[1] == '--transition-child':
        real_install = signal.signal
        injected = False
        def install(number, handler):
            global injected
            if handler == signal.SIG_IGN and not injected:
                injected = True
                # Deliver a different real signal before the first IGN takes
                # effect, while all cancellation handlers are still installed.
                os.kill(os.getpid(), signal.SIGHUP)
            return real_install(number, handler)
        with patch.object(signal, 'signal', side_effect=install):
            try:
                load_candidate().apply(RULES, runner=runner(sys.argv[2], sys.argv[3]))
            except Exception:
                raise SystemExit(0 if injected else 3)
        raise SystemExit(2)
    else:
        unittest.main(argv=[sys.argv[0], *[arg for arg in sys.argv[1:] if arg != '--legacy']])

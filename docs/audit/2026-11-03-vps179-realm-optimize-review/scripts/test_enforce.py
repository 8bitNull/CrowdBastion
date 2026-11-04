"""Run locally; --legacy demonstrates failures in the untouched prior script.

Commands are replaced with filesystem-backed network doubles. Cancellation uses
real OS signals and a real owned child process; no root/network access is used.
"""
import ast
import contextlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
LEGACY = '--legacy' in sys.argv
if LEGACY:
    sys.argv.remove('--legacy')
OLD = HERE.parents[1] / '2026-11-03-vps179-realm-optimize/scripts/realm179-enforce-test.py'


def load_new():
    spec = importlib.util.spec_from_file_location('review_enforce', HERE / 'enforce.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeCommands:
    def __init__(self, root, fault=None, slow_cleanup=False):
        self.root, self.fault, self.slow_cleanup = root, fault, slow_cleanup

    def __call__(self, args, timeout=20, check=True):
        output = ''
        if args[:4] == ['ip', '-j', 'route', 'show']:
            output = '[]'
        elif args[:4] == ['ip', '-j', 'link', 'show']:
            output = json.dumps([{'ifname': p.name[5:]} for p in self.root.glob('link-*')])
        elif args[:3] == ['ip', 'netns', 'list']:
            output = '\n'.join(p.name[3:] for p in self.root.glob('ns-*'))
        elif args[:3] == ['ip', 'netns', 'add']:
            path = self.root / ('ns-' + args[3])
            if path.exists():
                raise RuntimeError('namespace already exists')
            path.write_text('owned')
            (self.root / 'creation-attempted').write_text('yes')
            if self.fault == 'namespace':
                raise subprocess.TimeoutExpired(args, timeout)
        elif args[:3] == ['ip', 'link', 'add']:
            path = self.root / ('link-' + args[3])
            if path.exists():
                raise RuntimeError('link already exists')
            path.write_text('owned')
            (self.root / 'creation-attempted').write_text('yes')
            if self.fault == 'veth':
                raise subprocess.TimeoutExpired(args, timeout)
        elif args[:3] == ['ip', 'link', 'delete']:
            if self.slow_cleanup:
                (self.root / 'cleanup-ready').write_text('yes')
                time.sleep(.35)
            (self.root / ('link-' + args[3])).unlink(missing_ok=True)
        elif args[:3] == ['ip', 'netns', 'delete']:
            (self.root / ('ns-' + args[3])).unlink(missing_ok=True)
        elif args[:3] == ['ip', 'link', 'show']:
            return types.SimpleNamespace(stdout='', stderr='', returncode=0 if (self.root / ('link-' + args[3])).exists() else 1)
        elif args[:3] == ['cscli', 'decisions', 'list']:
            output = '[]'
        return types.SimpleNamespace(stdout=output, stderr='', returncode=0)


def exercise(root, fault=None, signal_wait=False, slow_cleanup=False):
    commands = FakeCommands(root, fault, slow_cleanup)
    echo = None

    def start_echo(owner=None):
        nonlocal echo
        echo = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        (root / 'echo-pid').write_text(str(echo.pid))
        if owner is not None:
            owner.echo = echo
        return echo

    def matrix(*args):
        if signal_wait:
            (root / 'ready').write_text('yes')
            while True:
                time.sleep(.02)
        raise RuntimeError('stop before any decision')

    if LEGACY:
        tree = ast.parse(OLD.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.Try))
        fake_subprocess = types.SimpleNamespace(Popen=lambda *a, **kw: start_echo(), PIPE=None, TimeoutExpired=subprocess.TimeoutExpired)
        # Old echo readiness expects a text pipe; a separate proxy retains the real PID.
        class EchoProxy:
            stdout = types.SimpleNamespace(readline=lambda: 'ready')
            def terminate(self): echo.terminate()
            def kill(self): echo.kill()
            def wait(self, timeout): return echo.wait(timeout=timeout)
            def poll(self): return echo.poll()
        def popen(*a, **kw):
            start_echo()
            return EchoProxy()
        fake_subprocess.Popen = popen
        env = dict(cmd=commands, json=json, ipaddress=ipaddress, subnet=ipaddress.ip_network('203.0.113.240/29'), test='203.0.113.242', control='203.0.113.243', memberships=lambda _: [], ns='owned', vh='owned-h', vn='owned-n', host='203.0.113.241', created_ns=False, created_veth=False, decision_attempted=False, echo=None, subprocess=fake_subprocess, select=types.SimpleNamespace(select=lambda *a: ([True], [], [])), matrix=matrix, r={'cleanup': {}}, base=root)
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(ast.Module(body=[node], type_ignores=[]), 'legacy-main', 'exec'), env)
        result = env['r']
    else:
        module = load_new()
        owner = module.Enforcement(base=root, result_path=root / 'enforcement-result.json', command=commands, token='12345678')
        owner.ns, owner.vh, owner.vn = 'owned', 'owned-h', 'owned-n'
        owner.memberships = lambda ip: []
        owner.start_echo = lambda: start_echo(owner)
        owner.matrix = matrix
        result = owner.run()
    (root / 'done').write_text(json.dumps(result))
    return result


class EnforcementFailureTests(unittest.TestCase):
    def test_namespace_creation_side_effect_then_timeout_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exercise(root, 'namespace')
            self.assertFalse((root / 'ns-owned').exists(), 'namespace leaked after creation timeout')

    def test_veth_creation_side_effect_then_timeout_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exercise(root, 'veth')
            self.assertFalse((root / 'link-owned-h').exists(), 'veth leaked after creation timeout')
            self.assertFalse((root / 'ns-owned').exists())

    def test_preexisting_link_prevents_any_owned_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'link-owned-h').write_text('administrator-owned')
            exercise(root)
            self.assertEqual((root / 'link-owned-h').read_text(), 'administrator-owned')
            self.assertFalse((root / 'ns-owned').exists())
            self.assertFalse((root / 'creation-attempted').exists(), 'collision preflight ran after network mutation')

    def test_preexisting_namespace_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'ns-owned').write_text('administrator-owned')
            exercise(root)
            self.assertEqual((root / 'ns-owned').read_text(), 'administrator-owned')
            self.assertFalse((root / 'creation-attempted').exists())

    def test_preexisting_peer_link_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'link-owned-n').write_text('administrator-owned')
            exercise(root)
            self.assertEqual((root / 'link-owned-n').read_text(), 'administrator-owned')
            self.assertFalse((root / 'creation-attempted').exists())

    def check_signal(self, signum):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = [sys.executable, __file__]
            if LEGACY:
                args.append('--legacy')
            args += ['--child', tmp]
            proc = subprocess.Popen(args)
            try:
                self.wait_file(root / 'ready', proc)
                proc.send_signal(signum)
                if not LEGACY:
                    self.wait_file(root / 'cleanup-ready', proc)
                    proc.send_signal(signal.SIGTERM)
                    proc.send_signal(signal.SIGHUP)
                proc.wait(timeout=8)
                self.assertEqual(proc.returncode, 0, 'signal skipped the managed cleanup path')
                self.assertFalse((root / 'ns-owned').exists())
                self.assertFalse((root / 'link-owned-h').exists())
                self.assertTrue((root / 'done').exists(), 'cleanup did not finish after repeated cancellation')
                pid = int((root / 'echo-pid').read_text())
                self.assertFalse(Path('/proc', str(pid)).exists(), 'owned echo process survived cleanup')
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)
                if (root / 'echo-pid').exists():
                    try:
                        os.kill(int((root / 'echo-pid').read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @staticmethod
    def wait_file(path, proc):
        deadline = time.monotonic() + 5
        while not path.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        if not path.exists():
            raise AssertionError('child did not reach ' + path.name)

    def test_sigterm_and_repeated_signals_finish_cleanup(self):
        self.check_signal(signal.SIGTERM)

    def test_sighup_and_repeated_signals_finish_cleanup(self):
        self.check_signal(signal.SIGHUP)


    @unittest.skipIf(LEGACY, 'new exact-rule evidence helper')
    def test_input_evidence_retains_exact_drop_rule_counters(self):
        module = load_new()
        fixture = "*filter\n[20:2000] -A INPUT -j CROWDSEC_CHAIN\n[3:180] -A CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists-2 src -m comment --comment 'CrowdSec: crowdsec' -j DROP\nCOMMIT\n*nat\n[999:999] -A CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists-2 src -j DROP\n"
        evidence = module.input_evidence(fixture, ['crowdsec-blacklists-2'])
        self.assertEqual(evidence['drop_rules'][0]['packets'], 3)
        self.assertEqual(evidence['drop_rules'][0]['bytes'], 180)
        self.assertEqual(len(evidence['drop_rules']), 1)
        self.assertIn('-A INPUT -j CROWDSEC_CHAIN', evidence['input_jump'])
        with self.assertRaises(RuntimeError):
            module.input_evidence(fixture.replace('[20:2000] -A INPUT', '[1:1] -A INPUT -j ACCEPT\n[20:2000] -A INPUT'), ['crowdsec-blacklists-2'])
        with self.assertRaises(RuntimeError):
            module.input_evidence(fixture.replace('-j DROP', '-j ACCEPT'), ['crowdsec-blacklists-2'])

    @unittest.skipIf(LEGACY, 'new independently callable cleanup')
    def test_cleanup_continues_after_delete_timeout_and_accepts_null_decision_list(self):
        module = load_new()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = FakeCommands(root)
            def commands(args, **kw):
                if args[:3] == ['cscli', 'decisions', 'delete']:
                    raise subprocess.TimeoutExpired(args, kw['timeout'])
                if args[:3] == ['cscli', 'decisions', 'list']:
                    return types.SimpleNamespace(stdout='null', stderr='', returncode=0)
                return fake(args, **kw)
            owner = module.Enforcement(base=root, command=commands, token='12345678')
            owner.ns, owner.vh = 'owned', 'owned-h'
            owner.ns_attempted = owner.veth_attempted = owner.decision_attempted = True
            (root / 'ns-owned').write_text('owned')
            (root / 'link-owned-h').write_text('owned')
            owner.memberships = lambda ip: []
            owner.echo = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'])
            previous = {sig: signal.getsignal(sig) for sig in module.SIGNALS}
            try:
                owner.cleanup()
                owner.cleanup()  # Repeated cleanup must remain harmless.
                self.assertIsNotNone(owner.echo.poll())
                self.assertFalse((root / 'ns-owned').exists())
                self.assertFalse((root / 'link-owned-h').exists())
                self.assertTrue(owner.r['cleanup']['no_test_decision'])
                self.assertIn('decision_delete_error', owner.r['cleanup'])
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
                if owner.echo.poll() is None:
                    owner.echo.kill()
                    owner.echo.wait(timeout=3)


if __name__ == '__main__':
    if '--child' in sys.argv:
        exercise(Path(sys.argv[sys.argv.index('--child') + 1]), signal_wait=True, slow_cleanup=True)
    else:
        unittest.main(verbosity=2)

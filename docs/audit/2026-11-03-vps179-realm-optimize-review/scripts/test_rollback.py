"""Subprocess/file-effect regressions; no production paths or commands are used.

Run with unittest, or set ROLLBACK_HELPER to the historical helper to reproduce
the regressions. Root is needed for the disposable chroot and ownership checks.
All path and service fault injection lives in this harness, not the helper.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


OWNED = (
    '/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml',
    '/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml',
    '/etc/systemd/journald.conf.d/60-crowdbastion-storage-cap.conf',
)
BACKUP = '/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z'
HELPER = Path(os.environ.get('ROLLBACK_HELPER', Path(__file__).with_name('rollback.py'))).resolve()


def worker(helper, root, scenario):
    """Run the actual helper, redirecting absolute paths and external services."""
    import fcntl
    import stat
    import time

    original_open = os.open
    original_unlink = os.unlink
    original_fdopen = os.fdopen
    original_sleep = time.sleep
    source = compile(Path(helper).read_bytes(), helper, 'exec')
    os.chroot(root)
    os.chdir('/')
    root_path = Path('/')
    events = root_path / 'events.jsonl'
    restored_fds = set()

    def checkpoint(stage):
        (root_path / ('checkpoint-' + stage)).touch()
        while not (root_path / ('release-' + stage)).exists():
            original_sleep(0.01)

    def command(args, **kwargs):
        with events.open('a') as out:
            out.write(json.dumps(args) + '\n')
        if scenario in ('restore_error', 'partial_write', 'recreated_file', 'signal_recovery') and args == ['crowdsec', '-t']:
            if scenario == 'recreated_file':
                target = root_path / OWNED[0].lstrip('/')
                target.symlink_to(root_path / 'unrelated')
            return subprocess.CompletedProcess(args, 1, '', 'injected invalid configuration')
        if scenario == 'inactive' and args[:2] == ['systemctl', 'is-active']:
            return subprocess.CompletedProcess(args, 3, 'inactive\n', '')
        if scenario == 'lapi_down' and args[:3] == ['cscli', 'lapi', 'status']:
            return subprocess.CompletedProcess(args, 1, '', 'injected unavailable LAPI')
        if scenario == 'restart_failure' and args == ['systemctl', 'restart', 'systemd-journald']:
            raise OSError('injected persistent restart failure')
        if scenario == 'restart_timeout' and args == ['systemctl', 'restart', 'systemd-journald']:
            if not (root_path / 'timeout-fired').exists():
                (root_path / 'timeout-fired').touch()
                raise subprocess.TimeoutExpired(args, 55)
        return subprocess.CompletedProcess(args, 0, 'active\n', '')

    def opened(path, flags, *args, **kwargs):
        if flags & os.O_CREAT and str(path).endswith(Path(OWNED[0]).name):
            if scenario == 'restore_error':
                raise PermissionError('injected first restore open failure')
            fd = original_open(path, flags, *args, **kwargs)
            restored_fds.add(fd)
            if scenario in ('signal_recovery', 'signal_partial_then_recovery'):
                checkpoint('recovery')
            return fd
        return original_open(path, flags, *args, **kwargs)

    class BrokenWrite:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            self.file.__enter__()
            return self

        def write(self, data):
            self.file.write(data[:3])
            raise OSError('injected partial restore write failure')

        def __exit__(self, *args):
            return self.file.__exit__(*args)

    def fdopened(fd, *args, **kwargs):
        out = original_fdopen(fd, *args, **kwargs)
        if scenario == 'partial_write' and fd in restored_fds:
            restored_fds.discard(fd)
            return BrokenWrite(out)
        return out

    first_unlinked = False

    def unlinked(path, *args, **kwargs):
        nonlocal first_unlinked
        result = original_unlink(path, *args, **kwargs)
        if scenario in ('signal_partial', 'signal_partial_then_recovery') and not first_unlinked:
            first_unlinked = True
            checkpoint('partial')
        if scenario in ('changed_after_preflight', 'parent_changed_after_preflight') and not first_unlinked:
            first_unlinked = True
            target = root_path / OWNED[1].lstrip('/')
            if scenario == 'parent_changed_after_preflight':
                target.parent.rename(target.parent.with_name('parked'))
                target.parent.mkdir()
            target.write_bytes(b'external replacement')
        return result

    subprocess.run = command
    os.open = opened
    os.fdopen = fdopened
    os.unlink = unlinked
    # Deadline advancement keeps service fault tests fast without changing code.
    ticks = iter(range(100000))
    time.monotonic = lambda: next(ticks)
    time.sleep = lambda duration: None
    sys.argv = [helper, BACKUP]
    exec(source, {'__name__': '__main__', '__file__': helper})


@unittest.skipUnless(os.geteuid() == 0, 'root-owned fixture validation requires root')
class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='realm179-rollback-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backup = self.root / BACKUP.lstrip('/')
        self.backup.mkdir(parents=True, mode=0o700)
        (self.root / 'run/lock').mkdir(parents=True)
        self.content = {}
        for index, name in enumerate(OWNED):
            path = self.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.content[name] = ('owned deployment %s\n' % index).encode()
            path.write_bytes(self.content[name])
            path.chmod(0o644)
        self.manifest = {'status': 'applied', 'new_files': {
            name: hashlib.sha256(data).hexdigest() for name, data in self.content.items()
        }}
        self.write_manifest()
        (self.root / 'unrelated').write_bytes(b'unrelated sentinel')

    def path(self, name):
        return self.root / name.lstrip('/')

    def write_manifest(self):
        (self.backup / 'apply-result.json').write_text(json.dumps(self.manifest))

    def run_helper(self, scenario='normal', timeout=10, signal_steps=()):
        command = [sys.executable, str(Path(__file__).resolve()), '--worker',
                   str(HELPER), str(self.root), scenario]
        if signal_steps:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True) as process:
                try:
                    for stage, signals in signal_steps:
                        deadline = time.monotonic() + timeout
                        while not (self.root / ('checkpoint-' + stage)).exists():
                            if process.poll() is not None:
                                self.fail('helper exited before signal checkpoint: ' + process.communicate()[1])
                            if time.monotonic() >= deadline:
                                self.fail('helper did not reach signal checkpoint: ' + stage)
                            time.sleep(0.01)
                        for signum in signals:
                            process.send_signal(signum)
                        (self.root / ('release-' + stage)).touch()
                    stdout, stderr = process.communicate(timeout=timeout)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        else:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        events = self.root / 'events.jsonl'
        self.commands = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
        self.assertEqual((self.root / 'unrelated').read_bytes(), b'unrelated sentinel')
        # No command is allowed to mutate firewall state, decisions, or ForwardX.
        for cmd in self.commands:
            self.assertIn(cmd[0], ('systemctl', 'crowdsec', 'cscli'))
            if cmd[0] == 'systemctl':
                self.assertIn(cmd, [['systemctl', verb, unit]
                                   for verb in ('restart', 'is-active')
                                   for unit in ('systemd-journald', 'crowdsec')])
            elif cmd[0] == 'cscli':
                self.assertEqual(cmd, ['cscli', 'lapi', 'status'])
            else:
                self.assertEqual(cmd, ['crowdsec', '-t'])
        return result

    def assert_original(self, names=OWNED):
        for name in names:
            self.assertTrue(self.path(name).exists(), 'not restored: ' + name)
            self.assertEqual(self.path(name).read_bytes(), self.content[name], name)

    def assert_recovery_attempted(self):
        for unit in ('systemd-journald', 'crowdsec'):
            self.assertIn(['systemctl', 'restart', unit], self.commands)
            self.assertIn(['systemctl', 'is-active', unit], self.commands)

    def test_success_removes_only_owned_files_and_checks_service_readiness(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(not self.path(name).exists() for name in OWNED))
        self.assert_recovery_attempted()
        self.assertIn(['cscli', 'lapi', 'status'], self.commands)

    def test_manifest_cannot_add_an_unrelated_file(self):
        target = '/etc/unrelated.conf'
        self.path(target).write_bytes(b'foreign')
        self.manifest['new_files'][target] = hashlib.sha256(b'foreign').hexdigest()
        self.write_manifest()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path(target).read_bytes(), b'foreign')
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_manifest_cannot_omit_an_owned_file(self):
        del self.manifest['new_files'][OWNED[1]]
        self.write_manifest()
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_modified_file_refuses_all_changes(self):
        self.path(OWNED[1]).write_bytes(b'admin edit')
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertEqual(self.path(OWNED[1]).read_bytes(), b'admin edit')
        self.assert_original((OWNED[0], OWNED[2]))
        self.assertEqual(self.commands, [])

    def test_file_symlink_refuses_all_changes(self):
        path = self.path(OWNED[1])
        parked = path.with_name('original')
        path.rename(parked)
        path.symlink_to(parked.name)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertTrue(path.is_symlink())
        self.assert_original()

    def test_parent_symlink_refuses_all_changes(self):
        parent = self.path(OWNED[1]).parent
        parked = parent.with_name('parked')
        parent.rename(parked)
        parent.symlink_to(parked.name, target_is_directory=True)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_backup_must_be_root_private(self):
        self.backup.chmod(0o755)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_manifest_symlink_refuses_all_changes(self):
        manifest = self.backup / 'apply-result.json'
        parked = self.backup / 'foreign-manifest.json'
        manifest.rename(parked)
        manifest.symlink_to(parked.name)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()

    def test_writable_manifest_refuses_all_changes(self):
        (self.backup / 'apply-result.json').chmod(0o666)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()

    def test_changed_file_mode_refuses_all_changes(self):
        self.path(OWNED[1]).chmod(0o600)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_hardlinked_deployment_file_refuses_all_changes(self):
        os.link(self.path(OWNED[1]), self.root / 'foreign-hardlink')
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_sticky_root_lock_directory_is_supported(self):
        (self.root / 'run/lock').chmod(0o1777)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(not self.path(name).exists() for name in OWNED))

    def test_nonsticky_writable_lock_directory_is_refused(self):
        (self.root / 'run/lock').chmod(0o777)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_foreign_lock_file_is_refused(self):
        lock = self.root / 'run/lock/crowdsec-1key.lock'
        lock.touch(mode=0o600)
        os.chown(lock, 65534, 65534)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assert_original()
        self.assertEqual(self.commands, [])

    def test_fifo_deployment_file_is_refused_without_blocking(self):
        path = self.path(OWNED[1])
        path.unlink()
        os.mkfifo(path)
        try:
            result = self.run_helper(timeout=2)
        except subprocess.TimeoutExpired:
            self.fail('rollback blocked while opening a non-regular deployment file')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(path.is_fifo())
        self.assert_original((OWNED[0], OWNED[2]))
        self.assertEqual(self.commands, [])

    def test_restore_open_failure_does_not_skip_other_files_or_services(self):
        result = self.run_helper('restore_error')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.path(OWNED[0]).exists())
        self.assert_original(OWNED[1:])
        self.assert_recovery_attempted()
        self.assertIn('restore_errors', result.stderr)

    def test_partial_restore_write_is_cleaned_and_other_files_recover(self):
        result = self.run_helper('partial_write')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.path(OWNED[0]).exists())
        self.assert_original(OWNED[1:])
        self.assert_recovery_attempted()

    def test_external_recreation_is_preserved_and_recovery_continues(self):
        result = self.run_helper('recreated_file')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.path(OWNED[0]).is_symlink())
        self.assert_original(OWNED[1:])
        self.assert_recovery_attempted()

    def test_change_after_preflight_is_not_deleted(self):
        result = self.run_helper('changed_after_preflight')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path(OWNED[1]).read_bytes(), b'external replacement')
        self.assert_original((OWNED[0], OWNED[2]))
        self.assert_recovery_attempted()

    def test_restart_timeout_restores_files_and_attempts_both_services(self):
        result = self.run_helper('restart_timeout')
        self.assertNotEqual(result.returncode, 0)
        self.assert_original()
        self.assert_recovery_attempted()

    def test_recovery_restart_error_does_not_skip_other_service(self):
        result = self.run_helper('restart_failure')
        self.assertNotEqual(result.returncode, 0)
        self.assert_original()
        self.assert_recovery_attempted()
        self.assertIn('injected persistent restart failure', result.stderr)

    def test_changed_parent_after_preflight_is_not_followed(self):
        result = self.run_helper('parent_changed_after_preflight')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path(OWNED[1]).read_bytes(), b'external replacement')
        self.assertEqual((self.path(OWNED[1]).parent.with_name('parked') /
                          self.path(OWNED[1]).name).read_bytes(), self.content[OWNED[1]])
        self.assert_original((OWNED[0], OWNED[2]))
        self.assert_recovery_attempted()

    def test_inactive_service_cannot_report_success(self):
        self.assertNotEqual(self.run_helper('inactive').returncode, 0)
        self.assert_original()
        self.assert_recovery_attempted()

    def test_unavailable_lapi_cannot_report_success(self):
        self.assertNotEqual(self.run_helper('lapi_down').returncode, 0)
        self.assert_original()
        self.assert_recovery_attempted()

    def test_sigterm_after_unlink_restores_files_and_services(self):
        result = self.run_helper('signal_partial', signal_steps=(('partial', (signal.SIGTERM,)),))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assert_original()
        self.assert_recovery_attempted()
        self.assertIn('rollback_failed', result.stderr)

    def test_sighup_after_unlink_restores_files_and_services(self):
        result = self.run_helper('signal_partial', signal_steps=(('partial', (signal.SIGHUP,)),))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assert_original()
        self.assert_recovery_attempted()

    def test_repeated_signals_cannot_interrupt_cancellation_recovery(self):
        result = self.run_helper('signal_partial_then_recovery', signal_steps=(
            ('partial', (signal.SIGTERM,)),
            ('recovery', (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)),
        ))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assert_original()
        self.assert_recovery_attempted()
        self.assertIn('rollback_failed', result.stderr)

    def test_termination_cannot_interrupt_error_recovery(self):
        result = self.run_helper('signal_recovery', signal_steps=(
            ('recovery', (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)),
        ))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assert_original()
        self.assert_recovery_attempted()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        worker(*sys.argv[2:])
    else:
        unittest.main()

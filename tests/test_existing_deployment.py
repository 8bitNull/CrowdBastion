"""Focused safety tests; all host commands are mocked."""
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

try:
    helper = importlib.import_module('crowdsec_existing_deployment')
except ModuleNotFoundError:
    helper = None


class ExistingDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(helper, 'existing deployment helper is not implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backup = self.root / 'attempt'
        self.backup.mkdir(mode=0o700)
        self.config = self.root / 'bouncer.yaml'
        self.config.write_text('mode: iptables\napi_key: secret-canary\n')
        self.enter(patch.object(helper.os, 'geteuid', return_value=0))
        # Only fixture ownership is relaxed; production still requires root.
        self.enter(patch.object(helper, '_root_owned', side_effect=lambda info: info.st_uid in (0, self.root.stat().st_uid)))
        self.command = self.enter(patch.object(helper.subprocess, 'run'))
        self.current = b'MAILTO=private@example.test\n# keep\n@reboot /sbin/iptables-restore < /etc/iptables/rules.v4\n0 * * * * echo private\n@reboot ip6tables-restore < /etc/iptables/rules.v6\n'
        self.writes = []
        self.command.side_effect = self.crontab

    def enter(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def crontab(self, argv, **kwargs):
        self.assertEqual(argv[:3], ['crontab', '-u', 'root'])
        self.assertNotIn('shell', kwargs)
        self.assertEqual(kwargs['timeout'], 30)
        if argv[3:] == ['-l']:
            return subprocess.CompletedProcess(argv, 0, self.current, b'')
        self.assertEqual(argv[3:], ['-'])
        self.current = kwargs['input']
        self.writes.append(self.current)
        return subprocess.CompletedProcess(argv, 0, b'', b'')

    def test_exact_recognition_and_sanitized_line_indexes(self):
        self.current += b'@reboot /usr/sbin/ip6tables-restore </etc/iptables/rules.v6\n'
        rows = helper.cron_list()
        self.assertEqual([r['index'] for r in rows], [3, 5, 6])
        self.assertEqual([r['family'] for r in rows], ['IPv4', 'IPv6', 'IPv6'])
        self.assertNotIn('private', json.dumps(rows))
        self.assertEqual(self.writes, [])

    def test_unknown_commands_are_never_recognized(self):
        commands = ['iptables-restore --noflush < /etc/iptables/rules.v4',
                    'iptables-restore < /etc/iptables/rules.v6',
                    'iptables-restore < /etc/iptables/rules.v4; echo secret',
                    'iptables-restore < /etc/iptables/rules.v4 # note',
                    'env iptables-restore < /etc/iptables/rules.v4',
                    './iptables-restore < /etc/iptables/rules.v4',
                    '/tmp/../sbin/iptables-restore < /etc/iptables/rules.v4',
                    'iptables-restore < /etc/iptables/rules.v4 > /tmp/out']
        self.current = ''.join('@reboot '+c+'\n' for c in commands).encode()
        self.assertEqual(helper.cron_list(), [])
        with self.assertRaises(ValueError):
            helper.cron_disable(self.backup, 1)
        self.assertEqual(list(self.backup.iterdir()), [])
        self.assertEqual(self.writes, [])

    def test_disable_and_restore_preserve_all_other_bytes_and_private_backups(self):
        original = self.current
        helper.cron_disable(self.backup, 3)
        after = original.replace(b'@reboot /sbin/', b'# CrowdBastion disabled: @reboot /sbin/', 1)
        self.assertEqual(self.current, after)
        self.assertEqual((self.backup/'root.crontab.before').read_bytes(), original)
        self.assertEqual((self.backup/'root.crontab.after').read_bytes(), after)
        for path in self.backup.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads((self.backup/'cron.json').read_text())['index'], 3)
        helper.cron_restore(self.backup)
        self.assertEqual(self.current, original)
        self.assertEqual(self.writes, [after, original])

    def test_restore_refuses_external_changes(self):
        helper.cron_disable(self.backup, 3)
        self.current += b'# external edit\n'
        with self.assertRaises(ValueError):
            helper.cron_restore(self.backup)
        self.assertEqual(len(self.writes), 1)

    def test_disable_rereads_and_refuses_concurrent_changes(self):
        reads = 0
        def changed(argv, **kwargs):
            nonlocal reads
            if argv[-1] == '-l':
                reads += 1
                if reads == 2:
                    self.current += b'# concurrent\n'
            return self.crontab(argv, **kwargs)
        self.command.side_effect = changed
        with self.assertRaises(ValueError):
            helper.cron_disable(self.backup, 3)
        self.assertEqual(reads, 2)
        self.assertEqual(self.writes, [])

    def test_unreadable_crontab_is_an_error(self):
        for code, stderr in [(1, b'permission denied secret'), (2, b'error')]:
            with self.subTest(code=code, stderr=stderr):
                self.command.return_value = subprocess.CompletedProcess([], code, b'', stderr)
                self.command.side_effect = None
                with self.assertRaises(ValueError) as caught:
                    helper.cron_list()
                self.assertNotIn('secret', str(caught.exception))
                with self.assertRaises(ValueError):
                    helper.cron_disable(self.backup, 1)
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_confirmed_absent_root_crontab_has_no_candidates(self):
        self.command.side_effect = None
        self.command.return_value = subprocess.CompletedProcess([], 1, b'', b'no crontab for root\n')
        self.assertEqual(helper.cron_list(), [])

    def test_invalid_indexes_never_write(self):
        for index in (0, -1, 1, 2, 4, 6, True):
            with self.subTest(index=index), self.assertRaises(ValueError):
                helper.cron_disable(self.backup, index)
        self.assertEqual(self.writes, [])
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_backup_reuse_is_refused_without_overwriting(self):
        helper.cron_disable(self.backup, 3)
        saved = {p.name: p.read_bytes() for p in self.backup.iterdir()}
        with self.assertRaises(ValueError):
            helper.cron_disable(self.backup, 5)
        self.assertEqual(saved, {p.name: p.read_bytes() for p in self.backup.iterdir()})
        self.assertEqual(len(self.writes), 1)

    def test_unsafe_backup_paths_refused(self):
        link = self.root/'link'
        link.symlink_to(self.backup, target_is_directory=True)
        for path in (Path('relative'), link, link/'child', self.root/'missing'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                helper.cron_disable(path, 3)
        self.backup.chmod(0o755)
        with self.assertRaises(ValueError):
            helper.cron_disable(self.backup, 3)
        self.assertEqual(self.writes, [])

    def test_untrusted_ancestor_and_nonroot_refused(self):
        with patch.object(helper, '_root_owned', return_value=False):
            with self.assertRaises(ValueError):
                helper.cron_disable(self.backup, 3)
        with patch.object(helper.os, 'geteuid', return_value=1000):
            with self.assertRaises(ValueError):
                helper.cron_list()
        self.assertEqual(self.writes, [])

    def test_restore_rejects_symlink_or_public_backup(self):
        helper.cron_disable(self.backup, 3)
        before = self.backup/'root.crontab.before'
        before.chmod(0o644)
        with self.assertRaises(ValueError):
            helper.cron_restore(self.backup)
        before.unlink()
        before.symlink_to(self.config)
        with self.assertRaises(ValueError):
            helper.cron_restore(self.backup)
        self.assertEqual(len(self.writes), 1)

    def test_install_failure_keeps_recovery_records(self):
        original = self.crontab
        def fail(argv, **kwargs):
            if argv[-1] == '-':
                return subprocess.CompletedProcess(argv, 1, b'', b'secret')
            return original(argv, **kwargs)
        self.command.side_effect = fail
        with self.assertRaises(ValueError) as caught:
            helper.cron_disable(self.backup, 3)
        self.assertNotIn('secret', str(caught.exception))
        self.assertTrue((self.backup/'root.crontab.before').is_file())

    def test_timeout_after_install_can_restore_without_overwriting_others(self):
        original = self.current
        original_command = self.crontab
        def interrupted(argv, **kwargs):
            result = original_command(argv, **kwargs)
            if argv[-1] == '-':
                raise subprocess.TimeoutExpired(argv, 30)
            return result
        self.command.side_effect = interrupted
        with self.assertRaises(subprocess.TimeoutExpired):
            helper.cron_disable(self.backup, 3)
        self.command.side_effect = original_command
        helper.cron_restore(self.backup)
        self.assertEqual(self.current, original)


    def test_absolute_binary_at_root_and_unterminated_line(self):
        self.current = b'@reboot /iptables-restore < /etc/iptables/rules.v4'
        self.assertEqual(helper.cron_list(), [{'index': 1, 'family': 'IPv4'}])
        before = self.current
        helper.cron_disable(self.backup, 1)
        helper.cron_restore(self.backup)
        self.assertEqual(self.current, before)

    def test_carriage_return_is_not_a_crontab_line_boundary(self):
        self.current = b'@reboot iptables-restore < /etc/iptables/rules.v4\rmalicious\n'
        self.assertEqual(helper.cron_list(), [])
        with self.assertRaises(ValueError):
            helper.cron_disable(self.backup, 1)
        self.assertEqual(self.writes, [])

    def test_unrelated_snapshots_are_untouched(self):
        snapshot = self.backup/'rules.v4'
        snapshot.write_bytes(b'snapshot-canary')
        snapshot.chmod(0o640)
        helper.cron_disable(self.backup, 3)
        helper.cron_restore(self.backup)
        self.assertEqual(snapshot.read_bytes(), b'snapshot-canary')
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o640)

    def test_writable_nonsticky_ancestor_is_refused(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            helper.cron_disable(self.backup, 3)
        self.assertEqual(self.writes, [])

    def test_restore_rejects_tampered_transition(self):
        helper.cron_disable(self.backup, 3)
        (self.backup/'root.crontab.before').write_bytes(b'@reboot echo attacker\n')
        with self.assertRaises(ValueError):
            helper.cron_restore(self.backup)
        self.assertEqual(len(self.writes), 1)

    def test_empty_read_success_is_empty_but_read_failure_never_is(self):
        self.current = b''
        self.assertEqual(helper.cron_list(), [])
        with self.assertRaises(ValueError):
            helper.cron_disable(self.backup, 1)
        self.assertEqual(self.writes, [])

    def probes(self, coverage='fault'):
        self.enter(patch.object(helper.runtime, 'cron_risks', return_value=['/etc/rc.local:2']))
        self.enter(patch.object(helper.runtime, 'restore_services', return_value=['iptables.service']))
        docker = self.enter(patch.object(helper.runtime, 'docker_present', return_value=True))
        chains = self.enter(patch.object(helper.runtime, 'chain_coverage', return_value=coverage))
        return docker, chains

    def test_plan_uses_merged_config_and_runtime_with_actionable_scope(self):
        self.config.write_text('mode: nftables\napi_key: secret-canary\n')
        Path(str(self.config)+'.local').write_text('mode: iptables\n')
        docker, chains = self.probes()
        report = helper.plan(self.config)
        self.assertEqual(report['chain_coverage'], 'fault')
        self.assertTrue(report['docker_present'])
        self.assertEqual(report['cron_risks'], ['/etc/rc.local:2'])
        self.assertEqual(report['restore_services'], ['iptables.service'])
        self.assertIn('DOCKER-USER', json.dumps(report))
        self.assertIn('FORWARD', json.dumps(report))
        self.assertNotIn('secret-canary', json.dumps(report))
        docker.assert_called_once_with()
        chains.assert_called_once_with(self.config, True)
        self.assertEqual(self.writes, [])

    def test_plan_refuses_unsupported_unreadable_or_unknown(self):
        self.probes('unknown')
        with self.assertRaises(ValueError):
            helper.plan(self.config)
        self.config.write_text('mode: nftables\n')
        with self.assertRaises(ValueError):
            helper.plan(self.config)
        self.config.unlink()
        with self.assertRaises((ValueError, OSError)):
            helper.plan(self.config)

    def test_plan_probe_errors_fail_closed(self):
        self.probes()
        with patch.object(helper.runtime, 'cron_risks', side_effect=PermissionError('secret')):
            with self.assertRaises((ValueError, OSError)):
                helper.plan(self.config)

    def test_cli_dispatch_and_sanitized_errors(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(helper.main(['cron-list']), 0)
        self.assertEqual(json.loads(output.getvalue())[0]['index'], 3)
        self.assertNotIn('private', output.getvalue())
        self.assertEqual(helper.main(['cron-disable', str(self.backup), '3']), 0)
        self.assertEqual(helper.main(['cron-restore', str(self.backup)]), 0)
        self.probes()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(helper.main(['plan', str(self.config)]), 0)
        self.assertIn('scope', json.loads(output.getvalue()))
        self.command.side_effect = PermissionError('private-canary')
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(helper.main(['cron-list']), 1)
        self.assertNotIn('private-canary', errors.getvalue())


if __name__ == '__main__':
    unittest.main()

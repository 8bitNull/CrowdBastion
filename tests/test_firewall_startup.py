"""Startup checks use effective systemd metadata without evaluating shell text."""
import contextlib
import io
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import crowdsec_firewall as firewall
import test_workflows


class FirewallStartup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = self.base/'bouncer.yaml'
        self.config.write_text('mode: nftables\napi_key: private-canary\n')
        self.startup = self.binary('effective startup/bouncer', 'v0.0.36')
        self.fallback = self.binary('path/bouncer', 'v0.0.38')
        self.runtime = 'v9.9.9'
        self.pid = '42\n'
        self.execstart = self.property(str(self.startup))
        self.metadata_code = 0
        self.metadata_error = None
        self.calls = []
        self.real_run = subprocess.run
        self.addCleanup(patch.stopall)
        patch.object(firewall.shutil, 'which', return_value=str(self.fallback)).start()
        patch.object(firewall.subprocess, 'run', side_effect=self.process).start()

    def binary(self, name, version):
        binary = self.base/name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text('#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = -version ] || exit 71\n'
                          'printf "%s\\n" '+shlex.quote('version: '+version)+'\n')
        binary.chmod(0o755)
        return binary

    @staticmethod
    def property(path):
        return ('{ path='+path+' ; argv[]=/wrong/argv --api-key=private-canary ; '
                'ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; '
                'pid=42 ; code=(null) ; status=0/0 }\n')

    def process(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == 'systemctl':
            if '--property=MainPID' in argv:
                return subprocess.CompletedProcess(argv, 0, self.pid, '')
            if '--property=ExecStart' in argv:
                if self.metadata_error:
                    raise self.metadata_error
                return subprocess.CompletedProcess(argv, self.metadata_code, self.execstart, '')
            self.fail('Unexpected systemctl arguments: '+repr(argv))
        if argv[0] == '/proc/42/exe':
            return subprocess.CompletedProcess(argv, 0, 'version: '+self.runtime+'\n', '')
        kwargs.setdefault('cwd', str(self.base))
        return self.real_run(argv, **kwargs)

    def check(self, action='guard'):
        output = io.StringIO()
        before = self.config.read_bytes()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = firewall.main([action, str(self.config)])
        self.assertEqual(self.config.read_bytes(), before)
        self.assertNotIn('private-canary', output.getvalue())
        return code, output.getvalue()

    def test_guard_blocks_bad_startup_despite_unknown_running_version(self):
        for version in ['v0.0.36', 'v0.0.38-debian-pragmatic-amd64']:
            with self.subTest(version=version):
                self.binary('effective startup/bouncer', version)
                code, output = self.check()
                self.assertEqual(code, 1, output)
                self.assertIn('续封', output)

    def test_guard_blocks_bad_running_version_despite_unknown_startup(self):
        self.runtime = 'v0.0.38'
        self.binary('effective startup/bouncer', 'v9.9.9')
        self.assertEqual(self.check()[0], 1)

    def test_audit_keeps_running_binary_precedence(self):
        code, output = self.check('audit')
        self.assertEqual(code, 2, output)
        self.assertIn('尚未验证', output)
        self.assertNotIn([str(self.startup), '-version'], self.calls)
        self.runtime = 'v0.0.36'
        self.assertEqual(self.check('audit')[0], 1)

    def test_effective_path_preserves_spaces_and_literal_quotes(self):
        for name in ['effective startup/bouncer', 'quoted "name"/bouncer',
                     "quoted 'name'/bouncer", 'trailing-spaces/bouncer  ']:
            with self.subTest(name=name):
                binary = self.binary(name, 'v0.0.36')
                self.execstart = self.property(str(binary))
                self.assertEqual(self.check()[0], 1)

    def test_raw_systemd_path_preserves_literal_backslashes(self):
        for name in [r'bouncer\release', r'bouncer\x20release', r'bouncer\040release',
                     r'double-bouncer\\release', 'bouncer\\']:
            with self.subTest(name=name):
                binary = self.binary(name, 'v0.0.36')
                self.execstart = self.property(str(binary))
                self.assertEqual(self.check()[0], 1)

    def test_raw_path_handles_literal_quotes_and_backslashes(self):
        binary = self.binary('quoted "name"/bouncer\\release', 'v0.0.38')
        self.execstart = self.property(str(binary))
        self.assertEqual(self.check()[0], 1)

    def test_shell_metacharacters_in_executable_are_literal(self):
        marker = self.base/'executed-shell'
        # Backticks and $() both resolve to this marker if a shell evaluates
        # the property. The executable itself has these literal characters.
        binary = self.binary('literal$(touch executed-shell)`touch executed-shell`/bouncer', 'v0.0.36')
        self.execstart = self.property(str(binary))
        self.assertEqual(self.check()[0], 1)
        self.assertFalse(marker.exists())

    def test_argv_and_other_properties_are_never_executed(self):
        marker = self.base/'injection'
        self.binary('effective startup/bouncer', 'unverified-build')
        self.execstart = (self.property(str(self.startup)).replace(
            '/wrong/argv --api-key=private-canary', '/bin/sh -c "touch '+str(marker)+'"'))
        self.assertEqual(self.check()[0], 0)
        self.assertFalse(marker.exists())

    def test_unknown_or_missing_startup_metadata_remains_unverified_allowed(self):
        values = ['', '{}', 'ExecStart=', '42\n', '{ argv[]=/bin/false ; }',
                  self.property('/missing/bouncer'), self.property('relative/bouncer'),
                  self.property('"/unterminated/bouncer'), self.property('/bad\\q/bouncer')]
        for value in values:
            with self.subTest(value=value):
                self.execstart = value
                code, output = self.check()
                self.assertEqual(code, 0, output)
                self.assertIn('尚未验证', output)

    def test_metadata_failure_does_not_execute_its_stdout(self):
        self.metadata_code = 1
        self.assertEqual(self.check()[0], 0)
        self.assertNotIn([str(self.startup), '-version'], self.calls)
        for error in [OSError('unavailable'), subprocess.TimeoutExpired('systemctl', 10)]:
            with self.subTest(error=error):
                self.metadata_error = error
                self.assertEqual(self.check()[0], 0)

    def test_unknown_versions_remain_unverified(self):
        for version in ['v9.9.9', 'v0.0.37', 'development-build']:
            with self.subTest(version=version):
                self.binary('effective startup/bouncer', version)
                code, output = self.check()
                self.assertEqual(code, 0, output)
                self.assertIn('尚未验证', output)

    def test_non_nftables_backends_do_not_probe_binaries_or_systemd(self):
        for mode in ['iptables', 'ipset']:
            with self.subTest(mode=mode):
                self.config.write_text('mode: '+mode+'\n')
                self.assertEqual(self.check()[0], 0)
                self.assertEqual(self.calls, [])

    def test_inactive_service_keeps_path_fallback(self):
        self.pid = '0\n'
        self.binary('effective startup/bouncer', 'v9.9.9')
        self.assertEqual(self.check()[0], 1)


class FirewallStartupCallers(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_startup_defect_blocks_remote_and_repair_before_mutation(self):
        config = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        config.parent.mkdir(exist_ok=True)
        config.write_text('mode: nftables\napi_key: private-canary\n')
        binaries = self.base/'bin'
        binaries.mkdir()
        for name, version in [('crowdsec-firewall-bouncer', 'v9.9.9'), ('startup bouncer', 'v0.0.36')]:
            binary = binaries/name
            binary.write_text('#!/bin/sh\necho '+shlex.quote('version: '+version)+'\n')
            binary.chmod(0o755)
        systemctl = binaries/'systemctl'
        systemctl.write_text('#!/bin/sh\ncase "$*" in\n'
                            '*--property=MainPID*) echo 0 ;;\n'
                            '*--property=ExecStart*) printf "%s\\n" '+
                            shlex.quote(FirewallStartup.property(str(binaries/'startup bouncer')).strip())+' ;;\nesac\n')
        systemctl.chmod(0o755)
        overrides = ('export PATH='+shlex.quote(str(binaries))+':"$PATH"\n'
                     'remote_bouncer_tool() { return 0; }\n')
        before = config.read_bytes()
        for action in ['remote_bouncer_change configure', 'repair_firewall_bouncer']:
            with self.subTest(action=action):
                self.trace.write_text('')
                result = self.run_shell(action, overrides=overrides)
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertIn('[异常]', result.stderr)
                self.assertIn('0.0.36', result.stderr)
                self.assertEqual(config.read_bytes(), before)
                self.assertFalse(Path(str(config)+'.local').exists())
                self.assertNotIn('restart', self.commands())
                self.assertNotIn('bouncers add', self.commands())
                self.assertNotIn('private-canary', result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()

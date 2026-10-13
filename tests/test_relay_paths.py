"""Relay diagnostics exercise real helpers with isolated read-only command fixtures."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import test_workflows

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'lib/crowdsec_relay_paths.py'


class RelayPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.trace = self.base / 'trace'
        self.trace.touch()
        self.env = {**os.environ, 'PATH': str(self.bin), 'TRACE': str(self.trace)}

    def binary(self, name, output='', status=0):
        file = self.bin / name
        file.write_text('#!/bin/bash\nprintf "%s\\n" "$0 $*" >> "$TRACE"\nprintf "%s\\n" '+shlex.quote(output)+'\nexit '+str(status)+'\n')
        file.chmod(0o755)

    def run_helper(self, *args, user_input=''):
        return subprocess.run([sys.executable, str(HELPER), *args], input=user_input,
                              text=True, capture_output=True, env=self.env, timeout=5)

    def test_explicit_context_and_selected_listener_peer_evidence(self):
        self.binary('ss', 'tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*\ntcp ESTAB 0 0 192.0.2.10:8443 198.51.100.8:53000\ntcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\nudp UNCONN 0 0 [::]:5353 [::]:*')
        p = self.run_helper('--role', 'transit', '--path', 'userspace', '--tcp', '8443', '--udp', '5353')
        self.assertEqual(p.returncode, 2, p.stderr)
        for text in ('transit', 'userspace', '8443', '5353', '198.51.100.8', 'INPUT', 'PROXY', 'SNAT', '新连接', '尚未验证'):
            self.assertIn(text, p.stdout)
        self.assertNotIn('127.0.0.1:22', p.stdout)
        self.assertNotIn('已全面保护', p.stdout)
        self.assertNotIn('-p', self.trace.read_text())

    def test_nat_selectors_hide_unrelated_rules_and_comments(self):
        self.binary('iptables', '-A PREROUTING -p tcp --dport 8443 -m comment --comment SECRET -j DNAT --to-destination 192.0.2.20:443\n-A POSTROUTING -s 198.51.100.0/24 -j MASQUERADE\n-A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 192.0.2.21:22')
        p = self.run_helper('--role', 'entry', '--path', 'nat', '--tcp', '8443')
        self.assertEqual(p.returncode, 2)
        for text in ('DNAT', '192.0.2.20:443', 'FORWARD', 'MASQUERADE'):
            self.assertIn(text, p.stdout)
        self.assertNotIn('SECRET', p.stdout)
        self.assertNotIn('192.0.2.21', p.stdout)
        self.assertIn('-t nat -S', self.trace.read_text())

    def test_nft_nat_reports_only_selected_sanitized_evidence(self):
        rules = {'nftables': [
            {'rule': {'family': 'ip', 'table': 'nat', 'chain': 'prerouting',
                      'comment': 'SECRET', 'expr': [
                          {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': 5353}},
                          {'dnat': {'addr': '192.0.2.30', 'port': 53}}]}},
            {'rule': {'expr': [
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': 53}},
                {'dnat': {'addr': '192.0.2.99'}}]}}]}
        self.binary('nft', json.dumps(rules))
        p = self.run_helper('--role', 'exit', '--path', 'nat', '--udp', '5353')
        self.assertEqual(p.returncode, 2)
        self.assertIn('192.0.2.30', p.stdout)
        self.assertNotIn('192.0.2.99', p.stdout)
        self.assertNotIn('SECRET', p.stdout)

    def test_iptables_inverted_matches_are_not_reported_as_positive(self):
        for constraint in ('-p tcp ! --dport 8443',
                           '! -p tcp --dport 8443',
                           '-p tcp --dport 8443 ! -s 198.51.100.0/24',
                           '-p tcp --dport 8443 ! -d 192.0.2.10',
                           '-p tcp --dport ! 8443'):
            with self.subTest(constraint=constraint):
                self.binary('iptables', '-A PREROUTING '+constraint+
                            ' -j DNAT --to-destination 192.0.2.77:443')
                p = self.run_helper('--role', 'entry', '--path', 'nat', '--tcp', '8443')
                self.assertEqual(p.returncode, 2)
                self.assertNotIn('192.0.2.77', p.stdout)
                self.assertNotIn('dport=8443', p.stdout)
                self.assertIn('尚未验证', p.stdout)

    def test_nft_unsupported_constraints_are_not_reported_as_unconstrained(self):
        cases = [('tcp', 'dport', '!=', 8443),
                 ('tcp', 'dport', 'in', {'set': [8443, 8444]}),
                 ('ip', 'saddr', '!=', '198.51.100.0/24'),
                 ('ip', 'daddr', '!=', '192.0.2.10')]
        for protocol, field, operator, value in cases:
            with self.subTest(field=field, operator=operator):
                rules = {'nftables': [{'rule': {'expr': [
                    {'match': {'op': operator, 'left': {'payload': {'protocol': protocol, 'field': field}}, 'right': value}},
                    {'dnat': {'addr': '192.0.2.77'}}]}}]}
                self.binary('nft', json.dumps(rules))
                p = self.run_helper('--role', 'entry', '--path', 'nat', '--tcp', '8443')
                self.assertEqual(p.returncode, 2)
                self.assertNotIn('192.0.2.77', p.stdout)
                self.assertNotIn('dport=8443', p.stdout)
                self.assertIn('尚未验证', p.stdout)

    def test_malformed_nat_evidence_is_error_and_does_not_echo_secrets(self):
        self.binary('nft', 'SECRET invalid JSON')
        p = self.run_helper('--role', 'unknown', '--path', 'unknown')
        self.assertEqual(p.returncode, 1)
        self.assertNotIn('SECRET', p.stdout+p.stderr)

    def test_missing_tools_remain_unverified(self):
        p = self.run_helper('--role', 'unknown', '--path', 'bridge')
        self.assertEqual(p.returncode, 2)
        self.assertIn('缺少 ss', p.stdout)
        self.assertIn('Docker', p.stdout)
        self.assertIn('上游', p.stdout)
        self.assertEqual(self.trace.read_text(), '')

    def test_read_errors_are_errors_without_raw_output(self):
        self.binary('ss', 'API_KEY=secret', 1)
        p = self.run_helper('--role', 'exit', '--path', 'unknown')
        self.assertEqual(p.returncode, 1)
        self.assertNotIn('secret', p.stdout+p.stderr)

    def test_invalid_selector_does_not_inspect_system(self):
        self.binary('ss')
        for selector in ('0', '65536', '8443;touch /tmp/unsafe', '1-9'):
            p = self.run_helper('--role', 'entry', '--path', 'nat', '--tcp', selector)
            self.assertEqual(p.returncode, 1, p.stderr)
        self.assertEqual(self.trace.read_text(), '')

    def test_interactive_selection_and_eof_cancel_are_read_only(self):
        self.binary('ss', 'tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*')
        p = self.run_helper(user_input='2\n1\n8443\n\n')
        self.assertEqual(p.returncode, 2)
        self.assertIn('transit', p.stdout)
        for user_input in ('', '0\n', '1\n', '1\n1\n'):
            self.trace.write_text('')
            p = self.run_helper(user_input=user_input)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(self.trace.read_text(), '')


class RelayPathRouting(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_cli_bypasses_lock_and_cancellation_does_not_run_audit(self):
        p = self.run_shell('main --relay-path', '0\n', overrides='locked_operation() { record LOCK; return 99; }; check_relay_status() { record AUDIT; return 2; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands(), '')

    def test_cli_combines_path_and_bouncer_evidence_without_lock(self):
        # A subprocess fixture hides host ss/firewall binaries; existing audit is stubbed.
        fixture_bin = self.base/'bin'
        fixture_bin.mkdir()
        (fixture_bin/'python3').symlink_to(sys.executable)
        p = self.run_shell('main --relay-path', '1\n2\n8443\n\n', overrides=
                           'detect_os() { :; }; PATH='+shlex.quote(str(fixture_bin))+'; '
                           'locked_operation() { record LOCK; return 99; }; '
                           'check_relay_status() { record AUDIT; return 2; }')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertEqual(self.commands(), 'AUDIT\n')
        self.assertIn('entry', p.stdout)
        self.assertIn('FORWARD', p.stdout)

    def test_menu_routes_to_read_only_diagnostic(self):
        p = self.run_shell('manage_diagnostics', '3\n2\n0\n0\n', overrides='check_relay_path() { record PATH_DIAGNOSTIC; }; locked_operation() { record LOCK; return 99; }')
        self.assertEqual(p.returncode, 0)
        self.assertIn('PATH_DIAGNOSTIC', self.commands())
        self.assertNotIn('LOCK', self.commands())

"""Declared transport guidance must not become runtime or attack-detection claims."""
import importlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))


class Capabilities(unittest.TestCase):
    def setUp(self):
        try:
            self.mod = importlib.import_module('crowdbastion_protocols')
        except ModuleNotFoundError:
            self.fail('shipped protocol capability module is missing')

    def test_transport_evidence_controls_tcp_and_quic_guidance(self):
        cases = [
            ('vmess', None, 'unknown', False), ('vless', None, 'unknown', False),
            ('vmess', 'ws', 'tcp', True), ('vless', 'grpc', 'tcp', True),
            ('vless', 'httpupgrade', 'tcp', True), ('vless', 'xhttp', 'unknown', False), ('vless', 'tcp,tls', 'unknown', False),
            ('vmess', 'quic', 'unknown', False),
            ('shadowsocks', 'tcp', 'tcp', True), ('shadowsocks2022', 'udp', 'udp', False),
            ('shadowsocks', 'tcp+udp', 'tcp+udp', True),
            ('shadowsocks', None, 'unknown', False),
            ('trojan', None, 'tcp', True), ('trojan', 'grpc', 'tcp', True),
            ('hysteria1', None, 'unknown', False), ('hysteria1', 'udp', 'udp+quic', False),
            ('hysteria1', 'wechat-video', 'udp+quic', False),
            ('hysteria1', 'faketcp', 'faketcp', False),
            ('hysteria2', None, 'udp+quic', False), ('hysteria2', 'faketcp', 'faketcp', False), ('tuic', 'quic', 'udp+quic', False),
            ('tuic', None, 'unknown', False), ('anytls', None, 'tcp', True),
            ('anytls', 'udp-over-tcp', 'tcp', True), ('anytls', 'quic', 'unknown', False)]
        for protocol, transport, network, tcp in cases:
            with self.subTest(protocol=protocol, transport=transport):
                report = self.mod.profile('v2bx', protocol, transport)
                self.assertEqual(report['network'], network)
                self.assertEqual(report['host_tcp_relevant'], tcp)
                self.assertEqual(report['runtime_status'], 'unverified')
                self.assertFalse(report['automatic_tuning'])
        anytls = self.mod.profile('v2bx', 'anytls')
        self.assertEqual(anytls['udp_payload'], 'over_tcp')
        for protocol, transport in [('hysteria1', 'udp'), ('hysteria2', None), ('tuic', 'quic')]:
            r = self.mod.profile('v2bx', protocol, transport)
            self.assertEqual(r['congestion_control'], 'userspace_version_and_direction_required')
            self.assertIn('UDP', ' '.join(r['guidance']))
            self.assertIn('--network-plan', ' '.join(r['guidance']))

    def test_tls_security_alone_does_not_establish_vmess_or_vless_transport(self):
        for protocol in ('vmess', 'vless'):
            with self.subTest(protocol=protocol):
                report = self.mod.profile('v2bx', protocol, 'tls')
                self.assertEqual(report['network'], 'unknown')
                self.assertFalse(report['host_tcp_relevant'])
                self.assertEqual(report['congestion_control'], 'unknown')
                self.assertEqual(report['runtime_status'], 'unverified')
        # These protocols' standard envelopes provide the additional evidence.
        for protocol in ('anytls', 'trojan'):
            with self.subTest(protocol=protocol):
                report = self.mod.profile('v2bx', protocol, 'tls')
                self.assertEqual(report['network'], 'tcp')
                self.assertTrue(report['host_tcp_relevant'])
                self.assertEqual(report['runtime_status'], 'unverified')

    def test_backend_is_never_a_protocol_or_verified_by_a_version_string(self):
        for name in ['v2node', 'v2bx', 'TOKEN_CANARY']:
            report = self.mod.profile('v2node', name, 'PASSWORD_CANARY', version='SECRET_CANARY')
            self.assertEqual(report['protocol'], 'unknown')
            self.assertEqual(report['backend_status'], 'candidate_repository_host_provenance_unknown')
            self.assertEqual(report['network'], 'unknown')
            self.assertNotIn('CANARY', json.dumps(report))
        report = self.mod.profile('OTHER_CANARY', 'vless', 'tcp', version='9.99')
        self.assertEqual(report['program'], 'unknown')
        self.assertEqual(report['backend_status'], 'unsupported_backend')

    def test_relay_declaration_never_authorizes_client_identity_or_a_ban(self):
        r = self.mod.profile('v2bx', 'hysteria2', topology='shared-relay')
        self.assertEqual(r['topology'], 'shared-relay')
        self.assertEqual(r['client_identity'], 'unverified')
        self.assertEqual(r['automatic_ban'], False)
        self.assertEqual(r['log_detection'], 'backend_version_and_sample_required')
        self.assertIn('relay CIDR', ' '.join(r['guidance']))

    def test_cli_is_bounded_redacted_and_readonly(self):
        r = subprocess.run([sys.executable, str(ROOT/'lib/crowdbastion_protocols.py'),
                            '--program', 'v2node', '--protocol', 'TOKEN_CANARY',
                            '--transport', 'SECRET_CANARY', '--version', 'PASSWORD_CANARY', '--json'],
                           text=True, capture_output=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data['evidence'], 'operator_declaration')
        self.assertNotIn('CANARY', r.stdout+r.stderr)

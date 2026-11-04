"""Private operator profiles refuse readable-by-others or replaced descriptors."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import crowdbastion_change as change
import crowdbastion_network as network
import crowdbastion_port_policy as policy


class PrivateOperatorProfiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.base.chmod(0o700)
        self.network_data = {'version': 1, 'loader': 'systemd',
                             'keys': ['net.ipv4.tcp_syn_retries'], 'sources': []}
        self.policy_data = {'version': 1, 'topology': {'kind': 'direct', 'relay_sources': []},
                            'ingress': [{'interface': 'eth0', 'protocol': 'tcp', 'port': 443,
                                         'mode': 'public', 'sources': []}]}
        self.profiles = {}
        for name, data in (('network', self.network_data), ('port-policy', self.policy_data)):
            path = self.base/(name+'.json')
            path.write_text(json.dumps(data))
            path.chmod(0o600)
            self.profiles[name] = path

    def invoke(self, module, action, path):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(policy.Backend, 'interfaces', return_value=['eth0']):
            code = module.cli([action, '--config', str(path), '--root', str(self.base/'changes')])
        return code, json.loads(output.getvalue())

    def test_private_0600_profiles_reach_plan_and_apply_with_validated_values(self):
        self.assertEqual(policy.load_policy(self.profiles['port-policy']), self.policy_data)
        for module, name, plan, apply in ((network, 'network', 'make_plan', 'apply_network'),
                                           (policy, 'port-policy', 'plan', 'apply_policy')):
            for action, operation in (('plan', plan), ('apply', apply)):
                with self.subTest(name=name, action=action), patch.object(module, operation, return_value={'version': 1, 'state': 'ready' if action == 'plan' else 'staged', 'effects': [], 'managed': {}}):
                    code, result = self.invoke(module, action, self.profiles[name])
                self.assertEqual(code, 0)
                self.assertIn(result['state'], ('ready', 'staged'))

    def test_0644_and_0640_profiles_refuse_before_plan_or_apply_and_do_not_write(self):
        for module, name, plan, apply in ((network, 'network', 'make_plan', 'apply_network'),
                                           (policy, 'port-policy', 'plan', 'apply_policy')):
            path = self.profiles[name]
            original = path.read_bytes()
            for mode in (0o644, 0o640):
                path.chmod(mode)
                for action, operation in (('plan', plan), ('apply', apply)):
                    with self.subTest(name=name, mode=oct(mode), action=action), patch.object(module, operation, return_value={'version': 1, 'state': 'ready' if action == 'plan' else 'staged', 'effects': [], 'managed': {}}) as mutation:
                        code, result = self.invoke(module, action, path)
                        self.assertEqual(code, 1)
                        self.assertEqual(result['state'], 'refused')
                        mutation.assert_not_called()
                        self.assertEqual(path.read_bytes(), original)
                        self.assertFalse((self.base/'changes').exists())

    def test_hardlinked_private_profile_is_refused(self):
        path = self.profiles['port-policy']
        os.link(path, self.base/'second-name.json')
        with self.assertRaises(ValueError): policy.load_policy(path)

    def test_descriptor_permissions_are_rechecked_after_safe_path_validation(self):
        path = self.profiles['port-policy']
        real_open = os.open
        def changed_open(target, flags, *args, **kwargs):
            fd = real_open(target, flags, *args, **kwargs)
            os.fchmod(fd, 0o644)
            return fd
        with patch.object(change.os, 'open', side_effect=changed_open):
            with self.assertRaises(ValueError): policy.load_policy(path)

    @unittest.skipUnless(os.geteuid() == 0, 'temporary descriptor ownership fixture needs root')
    def test_descriptor_owner_is_rechecked_after_safe_path_validation(self):
        path = self.profiles['port-policy']
        real_open = os.open
        def changed_open(target, flags, *args, **kwargs):
            fd = real_open(target, flags, *args, **kwargs)
            os.fchown(fd, 1, -1)
            return fd
        with patch.object(change.os, 'open', side_effect=changed_open):
            with self.assertRaises(ValueError): policy.load_policy(path)

    def test_status_does_not_load_operator_profile_and_generic_public_json_stays_supported(self):
        for path in self.profiles.values(): path.chmod(0o644)
        self.assertEqual(change.json_read(self.profiles['network']), self.network_data)
        self.assertEqual(change.json_read(self.profiles['port-policy']), self.policy_data)
        with patch.object(network.Backend, 'audit', return_value={'version': 1, 'state': 'audited'}):
            code, result = self.invoke(network, 'status', self.profiles['network'])
        self.assertEqual((code, result['state']), (0, 'audited'))
        code, result = self.invoke(policy, 'status', self.profiles['port-policy'])
        self.assertEqual((code, result['state']), (0, 'absent'))
        self.assertFalse((self.base/'changes').exists())

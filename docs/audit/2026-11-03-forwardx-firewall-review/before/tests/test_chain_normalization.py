"""Catch duplicated official common+family jumps and lost custom paths."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
import crowdsec_firewall_runtime as runtime
import crowdsec_remote_bouncer as remote


class ChainNormalization(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root/'bouncer.yaml'
        self.data = {'mode': 'iptables', 'api_key': 'keep-secret',
                     'iptables_chains': ['INPUT', 'COMMON', 'INPUT'],
                     'iptables_v4_chains': ['V4', 'INPUT'],
                     'iptables_v6_chains': ['V6']}
        self.base.write_text(yaml.safe_dump(self.data))
        self.local = Path(str(self.base)+'.local')

    def effective(self, overrides):
        merged = self.data | overrides
        # Official Bouncer appends its common list to the per-family list.
        return {family: merged.get('iptables_chains', []) + merged.get('iptables_'+family+'_chains', [])
                for family in ['v4', 'v6']}

    def test_startup_keeps_common_and_family_paths_once_and_is_idempotent(self):
        with patch.object(runtime, 'docker_present', return_value=False):
            runtime.write_startup(self.base, self.root/'dropin')
            first = self.local.read_bytes()
            runtime.write_startup(self.base, self.root/'dropin')
        self.assertEqual(first, self.local.read_bytes())
        data = yaml.safe_load(first)
        self.assertEqual(self.effective(data), {
            'v4': ['INPUT', 'COMMON', 'V4', 'FORWARD'],
            'v6': ['INPUT', 'COMMON', 'V6', 'FORWARD']})
        self.assertEqual(yaml.safe_load(self.base.read_text()), self.data)

    def test_local_credential_setup_normalizes_and_keeps_docker_ipv4_only(self):
        helper = Path(runtime.__file__).with_name('crowdsec_config.py')
        result = subprocess.run([sys.executable, str(helper), 'bouncer', str(self.base),
                                 'http://127.0.0.1:8080/', 'new-secret', 'true'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        data = yaml.safe_load(self.local.read_text())
        self.assertEqual(self.effective(data), {
            'v4': ['INPUT', 'COMMON', 'V4', 'DOCKER-USER'],
            'v6': ['INPUT', 'COMMON', 'V6']})
        self.assertEqual(data['api_key'], 'new-secret')
        self.assertNotIn('new-secret', result.stdout+result.stderr)

    def test_remote_setup_preserves_effective_custom_paths_and_package_bytes(self):
        original = self.base.read_bytes()
        with patch.object(remote, 'preflight'):
            remote.apply(self.base, {'url': 'http://127.0.0.1:8080/', 'key': 'new-secret'})
        data = yaml.safe_load(self.local.read_text())
        self.assertEqual(self.effective(data), {
            'v4': ['INPUT', 'COMMON', 'V4', 'FORWARD'],
            'v6': ['INPUT', 'COMMON', 'V6', 'FORWARD']})
        self.assertEqual(self.base.read_bytes(), original)
        self.assertEqual(data['api_key'], 'new-secret')
        remote.owned(self.base)

    def test_invalid_common_or_family_list_is_rejected_before_write(self):
        for field, value in [('iptables_chains', 'INPUT'), ('iptables_chains', [42]),
                             ('iptables_v4_chains', ['INPUT;echo']), ('iptables_v6_chains', None)]:
            with self.subTest(field=field, value=value):
                bad = self.data | {field: value}
                self.base.write_text(yaml.safe_dump(bad))
                with patch.object(runtime, 'docker_present', return_value=False), self.assertRaises(ValueError):
                    runtime.write_startup(self.base, self.root/'dropin')
                self.assertFalse(self.local.exists())

    def test_valid_custom_chain_with_period_is_preserved(self):
        self.data['iptables_chains'] = ['INPUT', 'CUSTOM.INPUT']
        self.base.write_text(yaml.safe_dump(self.data))
        with patch.object(runtime, 'docker_present', return_value=False):
            runtime.write_startup(self.base, self.root/'dropin')
        data = yaml.safe_load(self.local.read_text())
        self.assertIn('CUSTOM.INPUT', self.effective(data)['v4'])
        self.assertIn('CUSTOM.INPUT', self.effective(data)['v6'])


if __name__ == '__main__':
    unittest.main()

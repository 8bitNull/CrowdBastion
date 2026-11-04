"""Re-review failures reproduced without host firewall or service changes."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml
import test_workflows
import crowdsec_config as config
import crowdsec_firewall_runtime as runtime
import crowdsec_remote_bouncer as remote
import crowdbastion_relay_verify as verify
from test_relay_verification import fixture


class ChainReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root/'bouncer.yaml'
        self.base.write_text('mode: iptables\niptables_chains: [INPUT, CUSTOM]\n')
        self.local = Path(str(self.base)+'.local')
        self.state = Path(str(self.base)+'.remote.json')

    def apply(self):
        with patch.object(remote, 'preflight'):
            remote.apply(self.base, {'url':'http://127.0.0.1:8080/', 'key':'new-secret'})

    def test_missing_common_does_not_invent_input_for_family_only_scope(self):
        result = config.canonical_iptables_chains({'iptables_v4_chains':['CUSTOM4'], 'iptables_v6_chains':['CUSTOM6']})
        self.assertEqual(result, {'iptables_chains':[], 'iptables_v4_chains':['CUSTOM4'], 'iptables_v6_chains':['CUSTOM6']})

    def test_explicit_null_lists_have_official_empty_slice_semantics(self):
        result = config.canonical_iptables_chains({'iptables_chains':None, 'iptables_v4_chains':None, 'iptables_v6_chains':None})
        self.assertEqual(result, {'iptables_chains':[], 'iptables_v4_chains':[], 'iptables_v6_chains':[]})

    def test_reapply_keeps_active_custom_chains_after_package_base_changes(self):
        self.apply()
        self.base.write_text('mode: iptables\niptables_chains: [INPUT]\n')
        self.apply()
        effective = config.merged_config(self.base)
        self.assertEqual(effective['iptables_v4_chains'], ['INPUT','CUSTOM','FORWARD'])
        self.assertEqual(effective['iptables_v6_chains'], ['INPUT','CUSTOM','FORWARD'])
        remote.owned(self.base)

    def test_startup_docker_normalization_keeps_ownership_valid_and_idempotent(self):
        self.apply()
        dropin = self.root/'order.conf'
        with patch.object(runtime, 'docker_present', return_value=True):
            runtime.write_startup(self.base, dropin)
            try:
                remote.owned(self.base)
            except remote.RemoteError as error:
                self.fail('our startup writer invalidated remote ownership: '+str(error))
            first = {p:p.read_bytes() for p in [self.local,self.state,dropin]}
            runtime.write_startup(self.base, dropin)
        self.assertEqual(first, {p:p.read_bytes() for p in first})
        self.assertIn('DOCKER-USER', config.merged_config(self.base)['iptables_v4_chains'])

    def test_startup_refuses_preexisting_owned_overlay_drift_before_write(self):
        self.apply()
        self.local.write_text(self.local.read_text()+'unknown_external: keep\n')
        before = self.local.read_bytes()
        with patch.object(runtime, 'docker_present', return_value=True), self.assertRaises(ValueError):
            runtime.write_startup(self.base, self.root/'order.conf')
        self.assertEqual(self.local.read_bytes(), before)
        self.assertFalse((self.root/'order.conf').exists())

    def test_startup_does_not_bless_an_external_edit_during_write(self):
        self.apply()
        old_marker = self.state.read_bytes()
        real_write = runtime.write
        def changed(path, data, **options):
            real_write(path, data, **options)
            self.local.write_text(self.local.read_text()+'external_edit: keep\n')
        with patch.object(runtime, 'docker_present', return_value=True), patch.object(runtime, 'write', side_effect=changed):
            with self.assertRaises(remote.RemoteError):
                runtime.write_startup(self.base, self.root/'order.conf')
        self.assertEqual(self.state.read_bytes(), old_marker)
        self.assertIn('external_edit', self.local.read_text())

    def test_startup_does_not_bless_false_changed_to_integer_zero(self):
        self.apply()
        old_marker = self.state.read_bytes()
        real_write = runtime.write
        def changed(path, data, **options):
            real_write(path, data, **options)
            self.local.write_text(self.local.read_text().replace('insecure_skip_verify: false', 'insecure_skip_verify: 0'))
        with patch.object(runtime, 'docker_present', return_value=True), patch.object(runtime, 'write', side_effect=changed):
            with self.assertRaises(remote.RemoteError):
                runtime.write_startup(self.base, self.root/'order.conf')
        self.assertEqual(self.state.read_bytes(), old_marker)


class NftReviewRegressions(unittest.TestCase):
    def evidence(self, payload):
        return verify.nft_evidence(payload, 'ip', 'crowdsec', {'crowdsec-blacklists'}, 'input', '1.1.1.1')

    def test_new_accept_before_drop_is_not_counter_growth(self):
        before = self.evidence(fixture(source=True,packets=10))
        payload = fixture(source=True,packets=14)
        payload['nftables'].insert(-1, {'rule':{'family':'ip','table':'crowdsec','chain':'ban','handle':8,'expr':[{'accept':None}]}})
        after = self.evidence(payload)
        self.assertFalse(after['matched'])
        self.assertFalse(verify.counter_increased(before, after))

    def test_named_counter_replacement_is_not_growth(self):
        first = fixture(source=True,packets=10); second = fixture(source=True,packets=14)
        first['nftables'][2]['counter']['handle'] = 44
        second['nftables'][2]['counter']['handle'] = 45
        self.assertFalse(verify.counter_increased(self.evidence(first), self.evidence(second)))


class ManagedStartupRollback(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_restart_failure_restores_managed_overlay_and_marker_together(self):
        import hashlib
        directory = self.config/'bouncers'; directory.mkdir()
        base = directory/'crowdsec-firewall-bouncer.yaml'
        base.write_text('mode: iptables\n')
        local = Path(str(base)+'.local'); local.write_text('api_key: keep-secret\n')
        marker = Path(str(base)+'.remote.json')
        marker.write_text(json.dumps({'manager':'crowdsec-1key-remote-v1','sha256':hashlib.sha256(local.read_bytes()).hexdigest()}))
        before = {p:p.read_bytes() for p in [local,marker]}
        overrides = '''
source "$SCRIPT_DIR/lib/firewall.sh"
FIREWALL_DROPIN="$TRACE.order"
firewall_write_startup() {
 command python3 - "$1" "$FIREWALL_DROPIN" "$SCRIPT_DIR/lib" <<'PYTHON'
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
import crowdsec_firewall_runtime as runtime
runtime.docker_present=lambda:True
runtime.write_startup(Path(sys.argv[1]),Path(sys.argv[2]))
PYTHON
}
check_firewall_runtime() { return 0; }
wait_firewall_decisions() { return 0; }
systemctl() {
 record systemctl "$@"
 if [[ "$1" == restart && ! -f "$TRACE.first-restart" ]]; then touch "$TRACE.first-restart"; return 1; fi
 return 0
}
'''
        result = self.run_shell('repair_firewall_startup', overrides=overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(Path(str(self.trace)+'.first-restart').exists(), result.stdout+result.stderr)
        self.assertEqual(self.commands().count('restart crowdsec-firewall-bouncer'), 2)
        self.assertEqual(before, {p:p.read_bytes() for p in before})
        remote.owned(base)
        self.assertFalse(Path(str(self.trace)+'.order').exists())
        self.assertNotIn('keep-secret', result.stdout+result.stderr+self.commands())


if __name__ == '__main__':
    unittest.main()

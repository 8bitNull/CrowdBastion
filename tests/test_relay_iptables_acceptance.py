"""Read-only save-output evidence: never changes the test host firewall."""
import contextlib
import importlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def fixture(present=False, packets=10, family='ip', hook='input'):
    name = 'crowdsec-blacklists-0' if family == 'ip' else 'crowdsec6-blacklists-0'
    address = '1.1.1.1' if family == 'ip' else '2606:4700:4700::1111'
    rules = ('*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n'
             ':CROWDSEC_CHAIN - [0:0]\n[100:6000] -A '+hook.upper()+' -j CROWDSEC_CHAIN\n'
             '['+str(packets)+':600] -A CROWDSEC_CHAIN -m set --match-set '+name+
             ' src -m comment --comment "CrowdSec: cscli" -j DROP\nCOMMIT\n')
    sets = 'create '+name+' hash:net family '+('inet' if family == 'ip' else 'inet6')+' hashsize 1024 maxelem 65536 timeout 300\n'
    if present:
        sets += 'add '+name+' '+address+' timeout 42\n'
    return rules, sets


class IptablesAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = importlib.import_module('crowdbastion_relay_verify')

    def evidence(self, present=False, packets=10, family='ip', hook='input', rules=None, sets=None):
        a, b = fixture(present, packets, family, hook)
        return self.tool.iptables_evidence(a if rules is None else rules, b if sets is None else sets,
            family, hook, '1.1.1.1' if family == 'ip' else '2606:4700:4700::1111',
            'CROWDSEC_CHAIN', {'crowdsec-blacklists' if family == 'ip' else 'crowdsec6-blacklists'})

    def test_both_families_and_hooks_bind_membership_and_counter_to_source(self):
        for family in ['ip', 'ip6']:
            for hook in ['input', 'forward']:
                with self.subTest(family=family, hook=hook):
                    initial = self.evidence(family=family, hook=hook)
                    banned = self.evidence(True, family=family, hook=hook)
                    self.assertTrue(initial['matched'])
                    self.assertFalse(initial['present'])
                    self.assertTrue(banned['present'])
                    self.assertEqual(list(banned['source_counters'].values()), [10])
                    self.assertTrue(self.tool.counter_increased(banned, self.evidence(True, 14, family, hook)))

    def test_network_membership_and_unrelated_sets_do_not_supply_counters(self):
        rules, sets = fixture(True)
        sets = sets.replace('1.1.1.1 timeout', '1.1.1.0/24 timeout')
        sets += 'create unrelated hash:net family inet\nadd unrelated 1.1.1.1\n'
        item = self.evidence(rules=rules, sets=sets)
        self.assertTrue(item['present'])
        self.assertEqual(list(item['source_counters'].values()), [10])
        item = self.evidence(sets=sets.replace('add crowdsec-blacklists-0 1.1.1.0/24 timeout 42\n', ''))
        self.assertFalse(item['present'])

    def test_bypasses_predicates_foreign_sets_and_non_filter_rules_cannot_pass(self):
        base, sets = fixture(True)
        cases = [base.replace('[100:6000]', '[1:60] -A INPUT -j ACCEPT\n[100:6000]'),
                 base.replace('-A INPUT -j', '-A INPUT -p tcp -j'),
                 base.replace(' src -m comment', ' dst -m comment'),
                 base.replace('--match-set ', '! --match-set '),
                 base.replace(' src -m comment', ' src -p tcp -m comment'),
                 base.replace('-j DROP', '-j ACCEPT'),
                 base.replace('crowdsec-blacklists-0 src', 'unrelated src'),
                 base.replace('*filter', '*mangle')]
        for rules in cases:
            with self.subTest(rules=rules):
                result = self.evidence(rules=rules, sets=sets)
                self.assertFalse(result['matched'])
                self.assertFalse(result['source_counters'])

    def test_missing_or_wrong_family_or_excluded_or_unsupported_set_is_incomplete(self):
        rules, sets = fixture(True)
        cases = ['', sets.replace('family inet ', 'family inet6 '),
                 sets.replace(' timeout 42', ' nomatch timeout 42'),
                 sets.replace('hash:net', 'list:set'),
                 sets.replace('family inet ', 'family inet netmask 24 ')]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(self.tool.Incomplete):
                self.evidence(rules=rules, sets=payload)

    def test_reset_or_rule_position_change_does_not_count_as_growth(self):
        before = self.evidence(True, 20)
        self.assertFalse(self.tool.counter_increased(before, self.evidence(True, 2)))
        rules, sets = fixture(True, 25)
        extra = '[0:0] -A CROWDSEC_CHAIN -m set --match-set crowdsec-blacklists-1 src -j DROP\n'
        rules = rules.replace('[25:600]', extra+'[25:600]')
        sets += 'create crowdsec-blacklists-1 hash:net family inet\n'
        self.assertFalse(self.tool.counter_increased(before, self.evidence(rules=rules, sets=sets)))

    def test_default_reject_verdict_is_recognized_with_explicit_reject_type(self):
        rules, sets = fixture(True)
        item = self.evidence(rules=rules.replace('-j DROP', '-j REJECT --reject-with icmp-port-unreachable'), sets=sets)
        self.assertTrue(item['matched'])
        self.assertTrue(item['present'])

    def test_missing_filter_commit_does_not_become_valid_at_next_table(self):
        rules, sets = fixture(True)
        payload = rules.replace('COMMIT\n', '*mangle\nCOMMIT\n')
        with self.assertRaises(self.tool.Incomplete):
            self.evidence(rules=payload, sets=sets)

    def test_snapshot_reads_only_selected_family_filter_and_referenced_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'bouncers').mkdir()
            config = root/'bouncers/crowdsec-firewall-bouncer.yaml'
            config.write_text('mode: iptables\napi_key: private-canary\n')
            original = config.read_bytes(); rules, sets = fixture(True)
            calls = []
            def execute(args, **kwargs):
                calls.append(args)
                if args == ['iptables-save', '-c', '-t', 'filter']:
                    return subprocess.CompletedProcess(args, 0, rules, '')
                if args == ['ipset', 'save', 'crowdsec-blacklists-0']:
                    return subprocess.CompletedProcess(args, 0, sets, '')
                raise AssertionError('unexpected or mutating command: '+str(args))
            with patch.object(self.tool.subprocess, 'run', side_effect=execute):
                item = self.tool.read_snapshot(root, {'family':'ip','hook':'input','source':'1.1.1.1'})
            self.assertTrue(item['present'])
            self.assertEqual(len(calls), 2)
            self.assertEqual(config.read_bytes(), original)

    def test_command_failure_is_sanitized_and_ipset_only_still_requires_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'bouncers').mkdir()
            config = root/'bouncers/crowdsec-firewall-bouncer.yaml'
            config.write_text('mode: ipset\napi_key: private-canary\n')
            with patch.object(self.tool.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'private-canary')):
                with self.assertRaises(self.tool.Incomplete) as caught:
                    self.tool.read_snapshot(root, {'family':'ip','hook':'input','source':'1.1.1.1'})
            self.assertNotIn('private-canary', str(caught.exception))


if __name__ == '__main__':
    unittest.main()

"""Legacy iptables evidence parsing; no host firewall operations."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).parent))

class IptablesEvidence(unittest.TestCase):
    def test_counts_only_source_blacklist_drop_rules(self):
        from verify_relay_iptables import drop_packets
        data='''*filter
[7:420] -A INPUT -m set --match-set crowdsec-blacklists src -j DROP
[3:180] -A FORWARD -m set --match-set crowdsec-blacklists src -j DROP
[90:5400] -A INPUT -j DROP
[5:300] -A INPUT -m set --match-set crowdsec-blacklists dst -j DROP
[9:540] -A INPUT -m set --match-set other src -j DROP
[40:2400] -A INPUT -m set --match-set crowdsec-blacklists src -j ACCEPT
[21:1260] -A INPUT -m set ! --match-set crowdsec-blacklists src -j DROP
COMMIT
'''
        self.assertEqual(drop_packets(data),10)
        self.assertEqual(drop_packets('[2:120] -A INPUT -m set --match-set crowdsec6-blacklists src -j DROP'),2)
        self.assertEqual(drop_packets('[4:240] -A INPUT -m set --match-set crowdsec-blacklists-0 src -j DROP'),4)
        self.assertEqual(drop_packets('[4:240] -A INPUT -m set --match-set crowdsec-blacklists-other src -j DROP'),0)
    def test_exact_ipset_membership_does_not_use_substring(self):
        from verify_relay_iptables import has_address
        data='create crowdsec-blacklists hash:net family inet\nadd crowdsec-blacklists 10.231.1.20 timeout 90\nadd crowdsec6-blacklists fd42:231:1::2 timeout 90\n'
        self.assertFalse(has_address(data,'10.231.1.2'))
        self.assertTrue(has_address(data,'fd42:0231:1:0:0:0:0:2'))
        self.assertFalse(has_address('add other 10.231.1.2','10.231.1.2'))
        self.assertTrue(has_address('add crowdsec-blacklists-0 10.231.1.2/32 timeout 90','10.231.1.2'))

if __name__=='__main__': unittest.main()

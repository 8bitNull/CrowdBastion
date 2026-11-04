import importlib.util
from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'docs/audit/2026-11-02-vps45-repair/scripts/static-policy.py'

class StaticPolicyTests(unittest.TestCase):
    def module(self):
        spec=importlib.util.spec_from_file_location('vps45_static',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_existing_rules_are_not_changed(self):
        m=self.module();calls=[]
        def command(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv,0,'')
        m.apply(command)
        self.assertFalse(any('-A' in a or '-N' in a or '-D' in a for a in calls))

    def test_cold_start_creates_both_families_without_restore_or_flush(self):
        m=self.module();calls=[]
        def command(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv,1 if '-S' in argv or '-C' in argv else 0,'')
        m.apply(command)
        for binary in ('iptables','ip6tables'):
            actual=[a for a in calls if a[0]==binary and '-A' in a]
            self.assertEqual(len(actual),len(m.RULES)+1)
            self.assertEqual(actual[-1][-4:],['-A','INPUT','-j',m.CHAIN])
            self.assertIn(['-p','tcp','-m','tcp','--dport','53322','-j','ACCEPT'],m.RULES)
            self.assertIn(['-p','tcp','-m','tcp','--dport','29726','-j','ACCEPT'],m.RULES)
        self.assertFalse(any('-F' in a or 'restore' in a[0] for a in calls))

    def test_failure_removes_only_added_rules_in_reverse_order(self):
        m=self.module();calls=[];adds=[];deletes=[]
        def command(argv):
            calls.append(argv)
            if '-A' in argv:
                if argv[0]=='ip6tables':return subprocess.CompletedProcess(argv,2,'')
                adds.append(argv)
            if '-D' in argv:deletes.append(argv)
            return subprocess.CompletedProcess(argv,1 if '-S' in argv or '-C' in argv else 0,'')
        with self.assertRaises(RuntimeError):m.apply(command)
        expected=[]
        for argv in reversed(adds):
            argv=list(argv);argv[argv.index('-A')]='-D';expected.append(argv)
        self.assertEqual(deletes,expected)

    def test_unreadable_checks_refuse_mutation(self):
        m=self.module();calls=[]
        def command(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv,2,'')
        with self.assertRaises(RuntimeError):m.apply(command)
        self.assertEqual(len(calls),1)

if __name__=='__main__':unittest.main()

"""Full lifecycle requires elapsed time, kernel evidence and external results."""
import contextlib
import importlib
import inspect
import io
import unittest


def evidence(present=False, packets=10):
    return {'matched': True, 'present': present,
            'rule_counters': {'stable-rule': packets},
            'source_counters': {'stable-rule': packets} if present else {}}


class Lifecycle(unittest.TestCase):
    def run_flow(self, early_renew=False, early_expiry=False, cancel_renew=False, snapshots=None,
                 initial_delay=0, renewal_delay=0, deletion_delay=0):
        tool = importlib.import_module('crowdbastion_relay_verify')
        self.assertIn('lifecycle', inspect.signature(tool.verify).parameters,
                      'guided verifier does not expose the required lifecycle mode')
        now = [1000.0]
        answers = iter(['9.9.9.9','8443','1','1','1.1.1.1','8.8.8.8','','y',
                        '1','1','y','2','1',                 # baseline and initial ban
                        'y','y','2','1',                   # renewal and post-original-expiry test
                        'y','1','1',                       # exact deletion and recovery
                        'y','2','1','y','1','1'])           # fresh short ban and natural expiry
        reads = iter(snapshots or [evidence(), evidence(True), evidence(True,14),
                     evidence(True,14), evidence(True,14), evidence(True,18),
                     evidence(False,18), evidence(True,18), evidence(True,22), evidence(False,22)])
        output = io.StringIO()
        def ask(prompt):
            output.write(prompt+'\n')
            if prompt.startswith('已提交上述'):
                now[0] += initial_delay
            if prompt.startswith('确认在原决策'):
                now[0] += renewal_delay
            if prompt.startswith('已执行上述精确删除'):
                now[0] += deletion_delay
            if '原期限' in prompt:
                if cancel_renew:
                    return 'q'
                if not early_renew:
                    now[0] += 121
            if '自然到期' in prompt:
                if not early_expiry:
                    now[0] += 61
            try:
                return next(answers)
            except StopIteration:
                raise EOFError from None
        with contextlib.redirect_stdout(output):
            code = tool.verify('/unused', ask=ask, snapshot=lambda scope: next(reads),
                               env={'SSH_CONNECTION':'4.2.2.2 1234 9.9.9.9 53322'},
                               lifecycle=True, clock=lambda: now[0])
        return code, output.getvalue()

    def test_complete_lifecycle_has_renewal_exact_delete_and_natural_expiry(self):
        code, text = self.run_flow()
        self.assertEqual(code, 0, text)
        self.assertIn('--duration 4m', text)
        self.assertIn('--duration 1m', text)
        self.assertIn('decisions delete --scenario crowdbastion-verify-', text)
        self.assertIn('--ip 1.1.1.1', text)
        self.assertIn('生命周期', text)

    def test_early_renewal_confirmation_cannot_pass(self):
        code, text = self.run_flow(early_renew=True)
        self.assertEqual(code, 2, text)
        self.assertIn('尚未', text)
        self.assertNotIn('本次入口验证通过', text)
        self.assertIn('4 分钟', text)

    def test_early_natural_expiry_confirmation_cannot_pass(self):
        code, text = self.run_flow(early_expiry=True)
        self.assertEqual(code, 2, text)
        self.assertNotIn('本次入口验证通过', text)

    def test_cancellation_after_renewal_retains_precise_recovery_reason(self):
        code, text = self.run_flow(cancel_renew=True)
        self.assertEqual(code, 2, text)
        self.assertIn('crowdbastion-verify-', text)
        self.assertIn('4 分钟', text)
        self.assertNotIn('本次入口验证通过', text)

    def test_missing_renewed_membership_cannot_pass(self):
        reads = [evidence(),evidence(True),evidence(True,14),evidence(True,14),evidence(False,14)]
        code, text = self.run_flow(snapshots=reads)
        self.assertEqual(code, 2, text)
        self.assertNotIn('本次入口验证通过', text)

    def test_delayed_initial_confirmation_cannot_extend_renewal_window(self):
        code, text = self.run_flow(initial_delay=90, renewal_delay=40)
        self.assertEqual(code, 2, text)
        self.assertNotIn('本次入口验证通过', text)

    def test_late_delete_cannot_credit_natural_expiry_as_explicit_delete(self):
        code, text = self.run_flow(deletion_delay=120)
        self.assertEqual(code, 2, text)
        self.assertNotIn('本次入口验证通过', text)

    def test_expiry_that_leaves_source_banned_cannot_pass(self):
        reads = [evidence(),evidence(True),evidence(True,14),evidence(True,14),evidence(True,14),
                 evidence(True,18),evidence(False,18),evidence(True,18),evidence(True,22),evidence(True,22)]
        code, text = self.run_flow(snapshots=reads)
        self.assertEqual(code, 2, text)
        self.assertNotIn('本次入口验证通过', text)


if __name__ == '__main__':
    unittest.main()

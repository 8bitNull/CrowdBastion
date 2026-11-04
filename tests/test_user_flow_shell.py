"""Real shell flow with host effects confined to the workflow fixture."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
import contextlib
import io
from unittest.mock import patch

import test_user_flow
import workflow_fixture

ROOT = Path(__file__).resolve().parents[1]


class UserFlowShell(workflow_fixture.WorkflowFixtureMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.facts = self.base/'facts.json'
        self.facts.write_text(json.dumps(test_user_flow.snapshot()))
        self.state = self.base/'var/lib/crowdbastion/user-flow.json'

    def run_flow(self, action='show_main_menu', answers='', overrides=''):
        setup = 'flow_collect() { cp '+shlex.quote(str(self.facts))+' "$1"; }\n'
        return self.run_shell(action, answers, setup+overrides, timeout=12)

    def save(self, goals):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text(json.dumps(test_user_flow.flow.new_state(goals)))
        self.state.chmod(0o600)

    def test_eof_and_exit_only_inspect_without_saving_or_installing(self):
        for answer in ('', '0\n'):
            result = self.run_flow(answers=answer)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('现有部署', result.stdout)
            self.assertIn('确认想保护什么', result.stdout)
            self.assertFalse(self.state.exists())
        self.assertEqual(self.commands(), '')

    def test_home_routes_daily_goals_and_original_advanced_menu(self):
        result = self.run_flow(answers='2\n3\n4\n0\n', overrides='''
flow_daily() { record daily; }
flow_choose_goals() { record goals; }
flow_advanced() { record advanced; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands().splitlines(), ['daily', 'goals', 'advanced'])

    def test_goal_confirmation_saves_intent_and_projection_without_install(self):
        result = self.run_flow('flow_choose_goals', '1\ny\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(json.loads(self.state.read_text())['goals'], ['system'])
        self.assertEqual(json.loads((self.state.parent/'node-roles.json').read_text())['roles'], ['relay'])
        self.assertNotRegex(self.commands(), r'install|restart|reload|enable')

    def test_declining_goal_confirmation_does_not_save_preferences(self):
        result = self.run_flow('flow_choose_goals', '1\nn\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.state.exists())

    def test_conflicting_goals_are_rejected_before_any_state_write(self):
        result = self.run_flow('flow_choose_goals', '1 4\n0\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('不能', result.stdout+result.stderr)
        self.assertFalse(self.state.exists())

    def test_corrupt_state_keeps_readonly_home_and_explicit_recovery(self):
        self.save(['system'])
        self.state.write_text('{')
        result = self.run_flow(answers='0\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('流程记录', result.stdout+result.stderr)
        self.assertEqual(self.state.read_text(), '{')

    def test_selected_task_is_deferred_and_not_replayed_on_next_launch(self):
        self.save(['system'])
        result = self.run_flow(answers='1\n4\n0\n0\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        data = json.loads(self.state.read_text())
        self.assertIn('entry.verify', data['deferred'])
        again = self.run_flow(answers='0\n')
        self.assertIn('暂缓', again.stdout)
        self.assertNotIn('verify-relay', self.commands())

    def test_returning_zero_without_changed_evidence_does_not_complete_install(self):
        self.save(['system'])
        self.facts.write_text(json.dumps(test_user_flow.snapshot(False)))
        result = self.run_flow(answers='1\n1\n0\n0\n', overrides='''
flow_dispatch() { record cancelled-operation; return 0; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('以复查证据', result.stdout)
        self.assertGreaterEqual(result.stdout.count('安装系统与登录基础防护'), 2)
        self.assertEqual(self.commands().count('cancelled-operation'), 1)

    def test_failed_operation_rechecks_without_automatic_retry(self):
        self.save(['system'])
        self.facts.write_text(json.dumps(test_user_flow.snapshot(False)))
        result = self.run_flow(answers='1\n1\n0\n0\n', overrides='''
flow_dispatch() { record failed-operation; return 1; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands().count('failed-operation'), 1)
        self.assertIn('未完成', result.stdout+result.stderr)

    def test_stale_direct_plan_is_refused_under_real_lock(self):
        result = self.run_flow('locked_operation flow_apply '+shlex.quote(str(self.facts))+' configure_appsec ""', overrides='''
setup_appsec() { record unexpected-mutation; }
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('unexpected-mutation', self.commands())
        self.assertIn('重新检查', result.stdout+result.stderr)

    def test_pending_migration_recommendation_reaches_original_maintenance(self):
        facts = test_user_flow.snapshot()
        facts['pending'] = [{'kind': 'firewall', 'state': 'migration_pending'}]
        self.facts.write_text(json.dumps(facts))
        result = self.run_flow(answers='1\n1\n0\n0\n', overrides='''
manage_firewall_maintenance() { record maintenance-reached; }
firewall_migration_pending() { return 0; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands().count('maintenance-reached'), 1)

    def test_unknown_action_is_not_executed(self):
        result = self.run_flow('flow_dispatch "$(printf arbitrary)" "" '+shlex.quote(str(self.facts)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.commands(), '')

    def test_chosen_container_is_reused_without_asking_for_its_name_again(self):
        result = self.run_flow('''
CROWDBASTION_FLOW_TARGET=docker:abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcdef
select_native_container
code=$?
printf 'RESULT=%s/%s/%s' "$code" "$NATIVE_ID" "$NATIVE_NAME"
''', overrides='''
appsec_containers() { printf 'abcdef123456 nginx:alpine selected-edge\\n'; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('RESULT=0/abcdef123456/selected-edge', result.stdout)

    def test_chosen_host_runtime_is_reused_without_another_service_prompt(self):
        result = self.run_flow('''
CROWDBASTION_FLOW_TARGET=host:openresty
real_ip_select_runtime host
code=$?
printf 'RESULT=%s/%s' "$code" "$NATIVE_NAME"
''', overrides='require_commands() { return 0; }')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('RESULT=0/host:openresty', result.stdout)

    def test_declining_core_plan_does_not_hold_lock_or_install_packages(self):
        result = self.run_flow('flow_install_core relay '+shlex.quote(str(self.facts)), '203.0.113.2\nn\n', '''
locked_operation() { record unexpected-lock; return 1; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('本次变更预览', result.stdout)
        self.assertNotRegex(self.commands(), r'unexpected-lock|apt-get|restart|enable|curl')

    def test_corrupt_progress_cannot_block_readonly_service_diagnosis(self):
        self.save(['system'])
        self.state.write_text('{')
        facts = test_user_flow.snapshot()
        facts['checks']['core'] = 'fault'
        self.facts.write_text(json.dumps(facts))
        result = self.run_flow(answers='1\n1\n0\n0\n', overrides='''
health_service_diagnose() { record diagnostic "$@"; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands().splitlines(), ['diagnostic core readonly'])
        self.assertEqual(self.state.read_text(), '{')

    def test_readonly_diagnosis_never_offers_service_start(self):
        result = self.run_flow('health_service_diagnose core readonly', 'y\n', '''
health_service_state() { printf inactive; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('最近启动日志', result.stdout)
        self.assertNotIn('systemctl start', self.commands())


class FlowCLI(unittest.TestCase):
    def test_missing_state_read_is_json_null_without_creating_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)/'new/state.json'
            result = subprocess.run([sys.executable, str(ROOT/'lib/crowdbastion_flow_cli.py'), 'state', str(state)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIsNone(json.loads(result.stdout))
            self.assertFalse(state.parent.exists())

    def test_locked_guard_rejects_changed_corrupt_or_unsafe_intent(self):
        import tempfile
        import crowdbastion_flow_cli as cli
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'state/user-flow.json'
            facts = test_user_flow.snapshot(False)
            test_user_flow.flow.save_state(path, test_user_flow.flow.new_state(['system']))
            with patch.object(cli, 'discover', return_value=facts), contextlib.redirect_stdout(io.StringIO()) as output:
                cli.main(['snapshot', str(root/'etc/crowdsec'), str(path.parent)])
            snap = root/'snapshot.json'
            snap.write_text(output.getvalue())
            for mutation in ('target', 'corrupt', 'permission'):
                test_user_flow.flow.save_state(path, test_user_flow.flow.new_state(['system']))
                if mutation == 'target':
                    test_user_flow.flow.save_state(path, test_user_flow.flow.new_state(['remote']))
                elif mutation == 'corrupt':
                    path.write_text('{')
                else:
                    path.chmod(0o666)
                with self.subTest(mutation=mutation), patch.object(cli, 'discover', return_value=facts):
                    with self.assertRaises((ValueError, OSError)):
                        cli.main(['guard', str(snap), str(root/'etc/crowdsec'), str(path.parent), '-'])
                path.chmod(0o600)


if __name__ == '__main__':
    unittest.main()

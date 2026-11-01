"""Common paths stay understandable and keep host mutations explicit."""
import shlex
import unittest

import test_node_guidance
import test_workflows


class GuidedInteraction(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    roles = test_node_guidance.Guidance.roles
    run_terminal = test_node_guidance.Guidance.run_terminal

    def test_home_dispatches_common_tasks_and_advanced_menu(self):
        self.roles('relay')
        names = ('interactive_health_check', 'guided_setup', 'manage_firewall_ops', 'manage_advanced')
        overrides = '\n'.join(f'{name}() {{ record invoked {name}; }}' for name in names)
        p = self.run_shell('show_main_menu', '1\n2\n3\n4\n0\n', overrides)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().splitlines(), ['invoked '+name for name in names])
        self.assertIn('1. 检查防护情况', p.stdout)
        self.assertNotIn('Next-Gen', p.stdout)

    def test_setup_dispatches_role_specific_steps_and_recheck(self):
        for role, operation in [('web', 'install_crowdsec_core web'),
                                ('relay', 'install_crowdsec_core relay'),
                                ('remote', 'manage_remote_bouncer'),
                                ('node', 'manage_v2bx_node')]:
            with self.subTest(role=role):
                self.roles(role)
                self.trace.write_text('')
                p = self.run_shell('guided_setup', '1\n9\n0\n', '''
locked_operation() { record lock "$@"; "$@"; }
install_crowdsec_core() { record install_crowdsec_core "$@"; }
manage_remote_bouncer() { record manage_remote_bouncer; }
manage_v2bx_node() { record manage_v2bx_node; }
interactive_health_check() { record recheck; }
''')
                self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
                self.assertIn(operation, self.commands())
                self.assertIn('recheck', self.commands())
                if role == 'node':
                    self.assertNotIn('install_crowdsec_core', self.commands())

    def test_setup_cancel_and_eof_are_read_only(self):
        self.roles('relay', 'node')
        for inputs in ('0\n', ''):
            p = self.run_shell('guided_setup', inputs)
            self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
            self.assertTrue(all(line == 'systemctl is-active crowdsec' for line in self.commands().splitlines()))

    def test_first_selection_enters_setup_with_real_lock(self):
        p = self.run_terminal('show_main_menu', '2\n0\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn('1. 安装中转基础防护', p.stdout)
        self.assertEqual(self.commands(), 'systemctl is-active crowdsec\n')

    def test_setup_reloads_new_selection_after_real_lock(self):
        p = self.run_shell('guided_setup', '4\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('1. 管理 V2bX', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_corrupt_roles_hint_leads_to_working_recovery_menu(self):
        self.roles('web')
        path = self.base/'var/lib/crowdbastion/node-roles.json'
        path.write_text('{')
        p = self.run_shell('show_main_menu', '4\n7\n2\n0\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('菜单 [4] → [7] 重设', p.stderr)
        self.assertNotIn('无效选项', p.stderr)
        self.assertIn('本地中转', p.stdout)
        import json
        self.assertEqual(json.loads(path.read_text())['roles'], ['relay'])
        self.assertEqual(self.commands(), '')

    def test_service_diagnosis_rejects_invalid_config_without_start(self):
        p = self.run_shell('health_service_diagnose core', 'y\n', '''
systemctl() { record systemctl "$@"; if [[ "$1" == show ]]; then echo loaded; else echo inactive; return 3; fi; }
crowdsec() { record crowdsec "$@"; return 1; }
''')
        self.assertIn('配置校验未通过', p.stdout+p.stderr)
        self.assertNotIn('systemctl start', self.commands())

    def test_service_start_rechecks_under_lock_and_requires_confirmation(self):
        p = self.run_shell('health_service_diagnose core', 'y\n', '''
systemctl() {
 record systemctl "$@"
 case "$1" in
  show) echo loaded ;;
  start) touch "$TRACE.started" ;;
  is-active) if [[ -f "$TRACE.started" ]]; then echo active; else echo inactive; return 3; fi ;;
 esac
}
locked_operation() { record lock "$@"; "$@"; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('服务已启动', p.stdout)
        self.assertIn('lock health_start_service core', self.commands())
        self.assertIn('systemctl start crowdsec', self.commands())
        self.assertGreaterEqual(self.commands().count('crowdsec -t'), 2)

    def test_start_reports_failure_when_service_stays_inactive(self):
        p = self.run_shell('health_service_diagnose core', 'y\n', '''
systemctl() {
 record systemctl "$@"
 case "$1" in show) echo loaded ;; is-active) echo inactive; return 3 ;; esac
}
''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('启动后服务仍未运行', p.stderr)
        self.assertNotIn('服务已启动', p.stdout)

    def test_failed_start_displays_latest_attempt_logs(self):
        for start_status in (0, 1):
            with self.subTest(start_status=start_status):
                self.trace.write_text('')
                marker = self.base/'trace.latest'
                marker.unlink(missing_ok=True)
                p = self.run_shell('health_service_diagnose core', 'y\n', '''
systemctl() {
 record systemctl "$@"
 case "$1" in
  show) echo loaded ;;
  start) printf 'CURRENT_ATTEMPT_ERROR: port already in use\\n' > "$TRACE.latest"; return START_STATUS ;;
  is-active) echo inactive; return 3 ;;
 esac
}
journalctl() {
 record journalctl "$@"
 if [[ -f "$TRACE.latest" ]]; then cat "$TRACE.latest"; else echo OLD_ATTEMPT_ERROR; fi
}
'''.replace('START_STATUS', str(start_status)))
                self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
                self.assertIn('CURRENT_ATTEMPT_ERROR: port already in use', p.stdout)
                self.assertEqual(self.commands().count('journalctl -u crowdsec '), 2)

    def test_website_guide_exposes_private_endpoint_configuration(self):
        self.roles('web')
        p = self.run_shell('guided_setup', '2\n3\n2\n0\n0\n', '''
locked_operation() { record lock "$@"; "$@"; }
configure_docker_endpoints() { record configure_docker_endpoints; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('Docker bridge', p.stdout)
        self.assertIn('lock configure_docker_endpoints', self.commands())

    def test_website_submenu_exposes_private_endpoints_before_bouncer(self):
        p = self.run_shell('manage_website_protection', '8\n2\n0\n', '''
configure_docker_endpoints() { record configure-endpoints; }
install_web_bouncer() { record install-bouncer; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().splitlines(), ['configure-endpoints', 'install-bouncer'])
        self.assertIn('已准备', p.stdout)

    def test_missing_service_never_offers_start(self):
        p = self.run_shell('health_service_diagnose bouncer', 'y\n', '''
systemctl() {
 record systemctl "$@"
 case "$1" in show) echo not-found ;; is-active) echo inactive; return 4 ;; esac
}
''')
        self.assertNotIn('systemctl start', self.commands())
        self.assertNotIn('现在尝试启动', p.stdout)
        self.assertIn('未安装或无法读取', p.stdout)

    def test_start_guard_rejects_service_removed_after_diagnosis(self):
        p = self.run_shell('health_start_service core', overrides='''
systemctl() {
 record systemctl "$@"
 case "$1" in show) echo not-found ;; is-active) echo inactive; return 3 ;; esac
}
''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertNotIn('systemctl start', self.commands())

    def test_is_active_query_error_never_offers_start(self):
        p = self.run_shell('health_service_diagnose bouncer', 'y\n', '''
systemctl() {
 record systemctl "$@"
 case "$1" in show) echo loaded ;; is-active) echo inactive; return 4 ;; esac
}
''')
        self.assertNotIn('systemctl start', self.commands())
        self.assertNotIn('现在尝试启动', p.stdout)

    def test_bouncer_start_blocks_known_bad_effective_binary(self):
        import test_firewall_startup
        config = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        config.parent.mkdir(exist_ok=True)
        config.write_text('mode: nftables\napi_key: private-canary\n')
        binaries = self.base/'bin'
        binaries.mkdir()
        binary = binaries/'startup bouncer'
        binary.write_text('#!/bin/sh\necho "version: v0.0.36"\n')
        binary.chmod(0o755)
        tool = binaries/'systemctl'
        prop = test_firewall_startup.FirewallStartup.property(str(binary)).strip()
        tool.write_text('#!/bin/sh\ncase "$*" in\n'
                        '*--property=MainPID*) echo 0 ;;\n'
                        '*--property=ExecStart*) printf "%s\\n" '+shlex.quote(prop)+' ;;\nesac\n')
        tool.chmod(0o755)
        overrides = 'export PATH='+shlex.quote(str(binaries))+':"$PATH"\n'+'''
systemctl() {
 record systemctl "$@"
 case "$1" in show) echo loaded ;; is-active) echo inactive; return 3 ;; esac
}
'''
        p = self.run_shell('health_service_diagnose bouncer', 'y\n', overrides)
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('0.0.36', p.stderr)
        self.assertNotIn('systemctl start', self.commands())
        self.assertNotIn('private-canary', p.stdout+p.stderr)

    def test_log_help_keeps_parsing_evidence_and_checks_inventory(self):
        details = self.base/'details'
        details.write_text('HTTP 日志有读取但无解析，请核对格式和标签。\n')
        p = self.run_shell('health_recommended_action log_help '+shlex.quote(str(details)), overrides='''
check_log_inventory() { record inventory; printf '采集路径已覆盖。\n'; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('HTTP 日志有读取但无解析', p.stdout)
        self.assertIn('cscli parsers list', p.stdout)
        self.assertIn('采集路径已覆盖', p.stdout)

    def test_service_start_cancel_is_read_only(self):
        p = self.run_shell('health_service_diagnose bouncer', 'n\n', '''
systemctl() { record systemctl "$@"; if [[ "$1" == show ]]; then echo loaded; else echo inactive; return 3; fi; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('systemctl start', self.commands())
        self.assertIn('防火墙封禁服务', p.stdout)
        self.assertIn('可以尝试启动', p.stdout)

    def test_unknown_service_state_never_offers_start(self):
        p = self.run_shell('health_service_diagnose bouncer', 'y\n', '''
systemctl() { record systemctl "$@"; echo unknown; return 4; }
''')
        self.assertNotIn('systemctl start', self.commands())
        self.assertNotIn('现在尝试启动', p.stdout)
        self.assertIn('暂时无法确定', p.stdout)

    def test_start_guard_rejects_changed_state(self):
        p = self.run_shell('health_start_service core', overrides='''
systemctl() { record systemctl "$@"; if [[ "$1" == show ]]; then echo loaded; else echo active; fi; }
''')
        self.assertEqual(p.returncode, 1)
        self.assertNotIn('systemctl start', self.commands())
        self.assertIn('服务状态已变化', p.stderr)

    def test_bouncer_can_start_after_backend_guard(self):
        config = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        config.parent.mkdir(exist_ok=True)
        config.write_text('mode: iptables\n')
        p = self.run_shell('health_service_diagnose bouncer', 'y\n', '''
systemctl() {
 record systemctl "$@"
 case "$1" in
  show) echo loaded ;;
  start) touch "$TRACE.started" ;;
  is-active) if [[ -f "$TRACE.started" ]]; then echo active; else echo inactive; return 3; fi ;;
 esac
}
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('服务已启动', p.stdout)
        self.assertIn('当前后端未使用已知有续封缺陷', p.stderr)
        self.assertIn('systemctl start crowdsec-firewall-bouncer', self.commands())

    def test_service_start_eof_is_cancelled(self):
        p = self.run_shell('health_service_diagnose core', overrides='''
systemctl() { record systemctl "$@"; if [[ "$1" == show ]]; then echo loaded; else echo failed; return 3; fi; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('可以尝试启动', p.stdout)
        self.assertNotIn('systemctl start', self.commands())

    def test_combined_roles_have_both_sets_of_steps(self):
        self.roles('relay', 'node')
        p = self.run_shell('guided_setup', '0\n')
        self.assertIn('1. 安装中转基础防护', p.stdout)
        self.assertIn('3. 管理 V2bX', p.stdout)
        self.assertEqual(self.commands(), 'systemctl is-active crowdsec\n')

    def test_interactive_report_can_recheck_after_action(self):
        self.roles('relay')
        p = self.run_terminal('interactive_health_check', '1\n3\n0\n', '''
check_health_status_raw() { record check; health_expect core; health_event core fault; return 1; }
health_service_diagnose() { record diagnose "$@"; }
''')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(self.commands().splitlines(), ['check', 'diagnose core', 'check'])
        self.assertIn('3. 重新检查', p.stdout)


if __name__ == '__main__':
    unittest.main()